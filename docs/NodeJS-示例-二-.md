# NodeJS 示例（二）

> 原文：[`zh.annas-archive.org/md5/59094B51B116DA7DDAC7E4359313EBB3`](https://zh.annas-archive.org/md5/59094B51B116DA7DDAC7E4359313EBB3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章： 管理用户

在第四章中，*开发模型-视图-控制器层*，我们使用了模型-视图-控制器模式并编写了我们社交网络的基础。我们将应用程序分成了后端和前端目录。第一个文件夹中的代码用于提供资产并生成主页。除此之外，我们还建立了后端 API 的基础。项目的客户端由 Ractive.js 框架驱动。这是我们存储控制器、模型和视图的地方。有了这些元素，我们将继续管理用户。在本书的这一部分，我们将涵盖以下主题：

+   使用 MongoDB 数据库

+   注册新用户

+   使用会话进行用户认证

+   管理用户的个人资料

# 使用 MongoDB 数据库

现在，几乎每个网络应用程序都会从数据库中存储和检索数据。其中一个与 Node.js 兼容性很好的最流行的数据库是 MongoDB ([`www.mongodb.org/`](http://www.mongodb.org/))。这就是我们要使用的。MongoDB 的主要特点是它是一个具有不同数据格式和查询语言的 NoSQL 数据库。

## 安装 MongoDB

与其他流行软件一样，MongoDB 适用于所有操作系统。如果您是 Windows 用户，可以从官方页面[`www.mongodb.org/downloads`](http://www.mongodb.org/downloads)下载安装程序。对于 Linux 或 OS X 开发人员，MongoDB 可以通过大多数流行的软件包管理系统获得。我们不会详细介绍安装过程，但您可以在[`docs.mongodb.org/manual/installation/`](http://docs.mongodb.org/manual/installation/)找到详细的说明。

## 运行 MongoDB

安装成功后，我们将有一个`mongod`命令可用。通过在终端中运行它，我们启动一个默认监听端口`27017`的 MongoDB 服务器。我们的 Node.js 后端将连接到这个端口并执行数据库查询。以下是在执行`mongod`命令后我们控制台的样子：

![运行 MongoDB](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00177.jpeg)

## 连接到数据库服务器

Node.js 的一个好处是存在成千上万的模块。由于社区不断增长，我们几乎可以为遇到的每个任务找到一个模块。我们已经使用了几个 Gulp 插件。现在，我们将在`package.json`文件中添加官方的 MongoDB 驱动程序：

```js
"dependencies": {
  "mongodb": "1.4.25",
  ..
}
```

我们必须运行`npm install`将模块安装到`node_modules`目录中。一旦过程完成，我们可以使用以下代码连接到服务器：

```js
var MongoClient = require('mongodb').MongoClient;
MongoClient.connect('mongodb://127.0.0.1:27017/nodejs-by-example',  function(err, db) {
  // ...
});
```

在这段代码中，`nodejs-by-example`是我们的数据库名称。调用的回调函数使我们能够访问驱动程序的 API。我们可以使用`db`对象来操作数据库中的集合，换句话说，创建、更新、检索或删除文档。以下是一个示例：

```js
var collection = db.collection('users');
collection.insert({
  name: 'John',
  email: 'john@test.com'
}, function(err, result) {
  // ...
});
```

现在我们知道如何管理系统中的数据了。让我们继续到下一节并扩展我们的客户端代码。

# 扩展上一章的代码

向已有的代码库添加新功能意味着重构和扩展已经编写的代码。为了开发用户管理，我们需要更新`models/Base.js`文件。到目前为止，我们有一个简单的`Version`模型，我们将需要一个新的`User`模型。我们需要改进我们的导航和路由，以便用户有页面来创建、编辑和管理他们的账户。

本章附带的代码有很多 CSS 样式的添加。我们不会讨论它们，因为我们更想专注于 JavaScript 部分。它们为应用程序提供了稍微更好的外观。如果您对最终的 CSS 是如何生成感兴趣，请查看本书的代码包。

## 更新我们的基础模型类

到目前为止，`models/Base.js`只有两种方法。第一个方法`fetch`执行一个带有给定 URL 的`GET`请求。在第二章中，*项目架构*，我们谈到了 REST API；为了完全支持这种架构，我们必须添加用于创建、更新和删除记录的方法。实际上，所有这些方法都将接近我们已经拥有的方法。这是`create`函数：

```js
create: function(callback) {
  var self = this;
  ajax.request({
    url: self.get('url'),
    method: 'POST',
    data: this.get('value'),
    json: true
  })
  .done(function(result) {
    if(callback) {
      callback(null, result);
    }
  })
  .fail(function(xhr) {
    if(callback) {
      callback(JSON.parse(xhr.responseText));
    }
  });
  return this;
}
```

我们运行模型的方法，该方法从其`value`属性获取数据并执行`POST`请求。最后，我们触发一个回调。如果出现问题，我们将错误作为第一个参数发送。如果没有问题，那么第一个参数（表示错误状态）为`null`，第二个参数包含服务器的响应。

我们将遵循相同的方法来更新和删除代码：

```js
save: function(callback) {
  var self = this;
  ajax.request({
    url: self.get('url'),
    method: 'PUT',
    data: this.get('value'),
    json: true
  })
  .done(function(result) { // ...  })
  .fail(function(xhr) { // ... });
  return this;
},
del: function(callback) {
  var self = this;
  ajax.request({
    url: self.get('url'),
    method: 'DELETE',
    json: true
  })
  .done(function(result) { ...  })
  .fail(function(xhr) { ... });
  return this;
}
```

不同之处在于`request`方法。对于`save`操作，我们使用`PUT`，而要删除数据，我们使用`DELETE`。请注意，在删除过程中，我们不必发送模型的数据，因为我们只是执行一个简单的操作，从数据库中删除特定的数据对象，而不是进行像`create`和`save`请求中所见的更复杂的更改。

## 更新页面导航和路由

来自第四章的代码，*开发模型-视图-控制器层*，在其导航中只包含两个链接。我们需要为其添加更多内容——链接到注册、登录和注销，以及个人资料管理访问。`frontend/tpl/navigation.html`模板片段如下所示：

```js
<nav>
  <ul>
    <li><a on-click="goto:home">Home</a></li>
    {{#if !isLogged }}
      <li><a on-click="goto:register">Register</a></li>
      <li><a on-click="goto:login">Login</a></li>
    {{else}}
      <li class="right"><a on-click="goto:logout">Logout</a></li>
      <li class="right"><a on-click="goto:profile">Profile</a></li>
    {{/if}}
  </ul>
</nav>
```

除了新的`<a>`标签，我们还进行了以下两个有趣的添加：

+   有一个`{{#if}}`表达式。在我们的 Ractive.js 组件中，我们需要注册一个`isLogged`变量。它将通过隐藏和显示适当的按钮来控制导航的状态。当用户未登录时，我们将显示**注册**和**登录**按钮。否则，我们的应用程序将显示**注销**和**个人资料**链接。关于`isLogged`变量的更多信息将在本章末讨论，当我们涵盖会话支持时。

+   我们有`on-click`属性。请注意，这些属性不是有效的 HTML，但它们被 Ractive.js 解释为产生期望的结果。导航中的每个链接都将分派一个带有特定参数的`goto`事件，并且当用户触发链接时，这将发生。

在应用程序的主文件（`frontend/js/app.js`）中，我们有一个`showPage`函数。该方法可以访问当前页面，是监听`goto`事件的理想位置。这也是一个很好的选择，因为在同一个文件中，我们有一个对路由器的引用。因此，我们能够更改当前站点的页面。对这个函数进行一点改变，我们就完成了页面的切换：

```js
var showPage = function(newPage) {
  if(currentPage) currentPage.teardown();
  currentPage = newPage;
  body.innerHTML = '';
  currentPage.render(body);
  currentPage.on('navigation.goto', function(e, route) {
    Router.navigate(route);
  });
}
```

在下一节中，我们将继续编写代码，以在我们的系统中注册新用户。

# 注册新用户

为了处理用户的注册，我们需要更新前端和后端代码。应用程序的客户端部分将收集数据，后端将其存储在数据库中。

## 更新前端

我们更新了导航，现在，如果用户点击**注册**链接，应用程序将将他们转发到`/register`路由。我们必须调整我们的路由器，并以以下方式注册处理程序：

```js
var Register = require('./controllers/Register');
Router
.add('register', function() {
  var p = new Register();
  showPage(p);
})
```

与主页一样，我们将创建一个位于`frontend/js/controllers/Register.js`中的新控制器，如下所示：

```js
module.exports = Ractive.extend({
  template: require('../../tpl/register'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  onrender: function() {
    var self = this;
    this.observe('firstName',  userModel.setter('value.firstName'));
    this.observe('lastName', userModel.setter('value.lastName'));
    this.observe('email', userModel.setter('value.email'));
    this.observe('password', userModel.setter('value.password'));
    this.on('register', function() {
      userModel.create(function(error, result) {
        if(error) {
          self.set('error', error.error);
        } else {
          self.set('error', false);
          self.set('success', 'Registration successful.  Click <a href="/login">here</a> to login.');
        }
      });
    });
  }
});
```

该控制器附加的模板包含一个带有几个字段的表单——名字、姓氏、电子邮件和密码：

```js
<header>
  <navigation></navigation>
</header>
<div class="hero">
  <h1>Register</h1>
</div>
<form>
  {{#if error && error != ''}}
    <div class="error">{{error}}</div>
  {{/if}}
  {{#if success && success != ''}}
    <div class="success">{{{success}}}</div>
  {{else}}
    <label for="first-name">First name</label>
    <input type="text" id="first-name" value="{{firstName}}"/>
    <label for="last-name">Last name</label>
    <input type="text" id="last-name" value="{{lastName}}" />
    <label for="email">Email</label>
    <input type="text" id="email" value="{{email}}" />
    <label for="password">Password</label>
    <input type="password" id="password" value="{{password}}" />
    <input type="button" value="register" on-click="register" />
  {{/if}}
</form>
<appfooter />
```

值得一提的是，我们有错误和成功消息的占位符。它们受`{{#if}}`表达式保护，并且默认情况下是隐藏的。如果我们在控制器中为`error`或`success`变量设置值，这些隐藏的`div`元素将变为可见。为了获取输入字段的值，我们将使用 Ractive.js 绑定。通过设置`value="{{firstName}}"`，我们将创建一个新变量，该变量将在我们的控制器中可用。我们甚至可以监听此变量的更改，如下所示：

```js
this.observe('firstName', function(value) {
   userModel.set('value.firstName', value);
});
```

输入字段中的数据应发送到与后端通信的`model`类。由于我们有几个表单字段，创建一个辅助程序可以节省一些代码：

```js
this.observe('firstName', userModel.setter('value.firstName'));
```

`setter`方法返回了我们在前面代码中使用的相同闭包：

```js
// frontend/js/models/Base.js
setter: function(key) {
  var self = this;
  return function(v) {
    self.set(key, v);
  }
}
```

如果我们回头检查`controllers/Register.js`，我们将看到注册表单中的所有字段。在此表单中，我们有一个按钮触发`register`事件。控制器订阅了该事件，并触发模型的`create`函数。根据结果，我们要么显示错误消息，要么显示注册成功消息。

在前面的代码中，我们使用了一个`userModel`对象。这是`User`类的一个实例，它扩展了`models/Base.js`文件中的内容。以下是存储在`frontend/js/models/User.js`中的代码：

```js
var Base = require('./Base');
module.exports = Base.extend({
  data: {
    url: '/api/user'
  }
});
```

我们扩展了基本模型。因此，我们自动获得了`create`和`setter`函数。对于注册过程，我们不需要任何其他自定义方法。但是，为了登录和退出，我们将添加更多函数。

我们的系统的几个部分将需要这个模型。因此，我们将创建其全局`userModel`实例。这样做的合适位置是`frontend/js/app.js`文件。`window.onload`事件的监听器是这样的代码的良好宿主：

```js
window.onload = function() {
  ...
  userModel = new UserModel();
  ...
};
```

请注意，我们在变量定义前面漏掉了`var`关键字。这是我们使`userModel`在全局范围内可用的方法。

## 更新后端 API

我们的客户端代码向后端发出`POST`请求，携带新用户的数据。为了闭环，我们必须在后端 API 中处理请求，并将信息记录在数据库中。让我们首先在`backend/API.js`中添加一些辅助函数和变量：

```js
var MongoClient = require('mongodb').MongoClient;
var database;
var getDatabaseConnection = function(callback) {
  if(database) {
    callback(database);
    return;
  } else {
    MongoClient.connect('mongodb://127.0.0.1:27017/nodejs-by-example',  function(err, db) {
      if(err) {
        throw err;
      };
      database = db;
      callback(database);
    });
  }
};
```

在本章的开头，我们学习了如何向 MongoDB 数据库发出查询。我们需要访问驱动程序的 API。有一段代码我们会经常使用。因此，将其包装在一个辅助方法中是一个好主意。`getDatabaseConnection`函数正是可以用来实现这一点的函数。它只在第一次执行时连接到数据库。之后的每次调用都会返回缓存的`database`对象。

Node.js 请求处理的另一个常见任务是获取`POST`数据。`GET`参数可在每个路由处理程序中的`request`对象中使用。但是，对于`POST`数据，我们需要一个特殊的辅助程序：

```js
var querystring = require('querystring');
var processPOSTRequest = function(req, callback) {
  var body = '';
  req.on('data', function (data) {
    body += data;
  });
  req.on('end', function () {
    callback(querystring.parse(body));
  });
};
```

我们使用`request`对象作为流，并订阅其`data`事件。一旦我们接收到所有信息，我们就使用`querystring.parse`将其格式化为可用的哈希映射（`POST`参数的键/值）对象，并触发回调。

最后，我们将添加一个电子邮件验证函数。我们在注册和更新用户资料时会用到它。实际的验证是通过正则表达式完成的：

```js
var validEmail = function(value) {
  var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@( (\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0- 9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(value);
};
```

现在让我们继续编写代码，接受`POST`请求并在数据库中注册新用户。到目前为止，我们只向 API 添加了两个路由—`/api/version`和默认路由。我们将再添加一个`/api/user`，如下所示：

```js
Router.add('api/user', function(req, res) {
  switch(req.method) {
    case 'GET':
      // ...
    break;
    case 'PUT':
      // ...
    break;
    case 'POST':
      processPOSTRequest(req, function(data) {
        if(!data.firstName || data.firstName === '') {
          error('Please fill your first name.', res);
        } else if(!data.lastName || data.lastName === '') {
          error('Please fill your last name.', res);
        } else if(!data.email || data.email === '' ||  !validEmail(data.email)) {
          error('Invalid or missing email.', res);
        } else if(!data.password || data.password === '') {
          error('Please fill your password.', res);
        } else {
          getDatabaseConnection(function(db) {
            var collection = db.collection('users');
            data.password = sha1(data.password);
            collection.insert(data, function(err, docs) {
              response({
                success: 'OK'
              }, res);
            });
          });
        }
      });
    break;
    case 'DELETE':
      // ...
    break;
  };
});
```

同一路由将承载不同的操作。为了区分它们，我们将依赖`request`方法，正如 REST API 概念中所描述的那样。

在`POST`情况下，我们将首先使用`processPOSTRequest`助手获取数据。之后，我们将运行一系列检查，以确保发送的数据是正确的。如果不正确，我们将用适当的错误消息进行响应。如果一切正常，我们将使用另一个`getDatabaseConnection`助手，在数据库中创建一个新记录。将用户密码以明文形式存储并不是一个好的做法。因此，在将它们发送到 MongoDB 之前，我们将使用`sha1`模块对它们进行加密。这是一个在 Node.js 包管理器注册表中可用的模块。在`backend/API.js`的顶部，我们将添加以下内容：

```js
var sha1 = require('sha1');
```

为了使这一行起作用，我们必须更新`package.json`文件，并在控制台中运行`npm install`。

在下一节中，我们将实现`GET`、`PUT`和`DELETE`情况。除此之外，我们还将向您介绍一个新的登录路由。

# 用户身份验证与会话

我们实现了在系统中注册新用户的功能。下一步是对这些用户进行身份验证。让我们首先提供一个输入用户名和密码的界面。我们需要在`frontend/js/app.js`中添加一个新的路由处理程序：

```js
Router
.add('login', function() {
    var p = new Login();
    showPage(p);
})
```

到目前为止，所有其他页面都使用了相同的思路。我们将初始化一个新的控制器并将其传递给`showPage`助手。这里使用的模板如下：

```js
// frontend/tpl/login.html
<header>
  <navigation></navigation>
</header>
<div class="hero">
  <h1>Login</h1>
</div>
<form>
  {{#if error && error != ''}}
    <div class="error">{{error}}</div>
  {{/if}}
  {{#if success && success != ''}}
    <div class="success">{{{success}}}</div>
  {{else}}
    <label for="email">Email</label>
    <input type="text" id="email" value="{{email}}" />
    <label for="password">Password</label>
    <input type="password" id="password" value="{{password}}" />
    <input type="button" value="login" on-click="login" />
  {{/if}}
</form>
<appfooter />
```

在注册过程中，我们使用了类似的占位符来显示错误和成功消息。同样，我们有一个 HTML 表单。但是这次，表单包含了用户名和密码的输入字段。我们还将绑定两个变量，并确保按钮分派`login`事件。这是我们控制器的代码：

```js
// frontend/js/controllers/Login.js
module.exports = Ractive.extend({
  template: require('../../tpl/login'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  onrender: function() {
    var self = this;
    this.observe('email', userModel.setter('email'));
    this.observe('password', userModel.setter('password'));
    this.on('login', function() {
      userModel.login(function(error, result) {
        if(error) {
          self.set('error', error.error);
        } else {
          self.set('error', false);
          // redirecting the user to the home page
          window.location.href = '/';
        }
      });
    });
  }
});
```

通过使用相同的`setter`函数，我们存储了填入我们模型的值。有一个`userModel.login`方法，类似于`userModel.create`。它触发一个带有给定数据的`POST`请求到服务器。在这种情况下，数据是用户名和密码。这次，我们不会使用基本模型中的函数。我们将在`/frontend/js/models/User.js`文件中注册一个新的模型：

```js
var ajax = require('../lib/Ajax');
var Base = require('./Base');
module.exports = Base.extend({
  data: {
    url: '/api/user'
  },
  login: function(callback) {
    var self = this;
    ajax.request({
      url: this.get('url') + '/login',
      method: 'POST',
      data: {
        email: this.get('email'),
        password: this.get('password')
      },
      json: true
    })
    .done(function(result) {
      callback(null, result);
    })
    .fail(function(xhr) {
      callback(JSON.parse(xhr.responseText));
    });
  }
});
```

再次，我们使用 Ajax 助手将信息发送到后端 API。请求发送到`/api/user/login` URL。目前，我们不会处理这样的路由。以下代码放在`/backend/API.js`中，就在`/api/user`处理程序的上面：

```js
.add('api/user/login', function(req, res) {
  processPOSTRequest(req, function(data) {
    if(!data.email || data.email === '' ||  !validEmail(data.email)) {
      error('Invalid or missing email.', res);
    } else if(!data.password || data.password === '') {
      error('Please enter your password.', res);
    } else {
      getDatabaseConnection(function(db) {
        var collection = db.collection('users');
        collection.find({ 
          email: data.email,
          password: sha1(data.password)
        }).toArray(function(err, result) {
          if(result.length === 0) {
            error('Wrong email or password', res);
          } else {
            var user = result[0];
            delete user._id;
            delete user.password;
            req.session.user = user;
            response({
              success: 'OK',
              user: user
            }, res);
          }
        });
      });
    }
  });
})
```

`processPOSTRequest`函数传递了前端发送的`POST`数据。我们将保持相同的电子邮件和密码验证机制。如果一切正常，我们将检查提供的凭据是否与数据库中的某些帐户匹配。正确的电子邮件和密码的结果是包含用户详细信息的对象。将 ID 和用户密码返回给用户并不是一个好主意。因此，我们将它们从返回的用户对象中删除。到目前为止，还有一件事我们还没有谈论：

```js
req.session.user = user;
```

这就是我们存储会话的方式。默认情况下，我们没有可用的`session`对象。有一个模块提供了这个功能。它被称为`cookie-session`。我们必须将其添加到`package.json`并在终端中运行`npm install`命令。安装成功后，我们必须调整`server.js`文件：

```js
Router
.add('static', Assets)
.add('api', API)
.add(Default);

var session = require('cookie-session');
var checkSession = function(req, res) {
  session({
    keys: ['nodejs-by-example']
  })(req, res, function() {
    process(req, res);
  });
}
var process = function(req, res) {
  Router.check(req.url, [req, res]);
}
var app = http.createServer(checkSession).listen(port,  '127.0.0.1');
console.log("Listening on 127.0.0.1:" + port);
```

在将应用程序的流程传递给路由之前，我们运行`checkSession`函数。该方法使用新添加的模块，并通过附加`session`对象来修补`request`对象。所有 API 方法都可以访问当前用户的会话。这意味着我们可以通过简单地检查用户是否经过身份验证来保护对后端的每个请求。

你可能还记得，在本章的开头，我们创建了一个全局的`userModel`对象。它的初始化发生在`window.onload`处理程序中，这实际上是我们前端的引导点。我们可以在显示 UI 之前向后端询问当前用户是否已登录。这将帮助我们显示适当的导航按钮。因此，这是`frontend/js/app.js`的更改方式：

```js
window.onload = function() {
  userModel = new UserModel();
  userModel.fetch(function(error, result) {
    // ... router setting
  });
}
```

`userModel`函数扩展了基本模型，其中`fetch`方法将服务器的响应放入模型的`value`属性中。从前端获取数据意味着发出`GET`请求，在这种情况下，是对`/api/user` URL 的`GET`请求。让我们看看`backend/API.js`如何处理这个查询：

```js
.add('api/user', function(req, res) {
  switch(req.method) {
    case 'GET':
      if(req.session && req.session.user) {
        response(req.session.user, res);
      } else {
        response({}, res);
      }
    break;
    …
```

如果用户已登录，我们返回存储在`session`对象中的内容。如果没有，后端将返回一个空对象。对于客户端来说，这意味着`userModel`对象的`value`属性可能根据当前用户的状态有信息，也可能没有。因此，在`frontend/js/models/User.js`文件中添加一个新的`isLogin`方法是有意义的：

```js
isLogged: function() {
  return this.get('value.firstName') &&  this.get('value.lastName');
}
```

添加了前面的函数后，我们可以在客户端代码的任何地方使用`userModel.isLogged()`调用，从而知道用户是否已登录。这将起作用，因为我们在应用程序的最开始执行了数据获取。例如，导航(`frontend/js/views/Navigation.js`)需要这些信息以便显示正确的链接：

```js
module.exports = Ractive.extend({
  template: require('../../tpl/navigation'),
  onconstruct: function() {
    this.data.isLogged = userModel.isLogged();
  }
});
```

# 管理用户的个人资料

本章的前几节给了我们足够的知识来更新数据库中保存的信息。同样，我们需要在前端创建一个包含 HTML 表单的页面。这里的区别在于，表单的输入字段应该默认填充当前用户的数据。因此，让我们从为`/profile` URL 添加路由处理程序开始：

```js
Route
.add('profile', function() {
  if(userModel.isLogged()) {
    var p = new Profile();
    showPage(p);
  } else {
    Router.navigate('login');
  }      
})
```

如果用户未登录，没有理由允许访问此页面。在调用`showPage`助手之前进行简单的身份验证检查，如果需要，将用户转发到登录页面。

我们需要为`Profile`控制器准备的模板与我们用于注册的模板相同。我们只需要更改两件事情——我们需要删除`email`字段，并将按钮的标签从**注册**更改为**更新**。删除`email`字段并不是绝对必要的，但防止用户更改并将其保留为注册时输入的内容是一个好的做法。控制器的样子如下：

```js
module.exports = Ractive.extend({
  template: require('../../tpl/profile'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  onrender: function() {
    var self = this;
    this.set(userModel.get('value'));
    this.on('updateProfile', function() {
      userModel.set('value.firstName', this.get('firstName'));
      userModel.set('value.lastName', this.get('lastName'));
      if(this.get('password') != '') {
        userModel.set('value.password', this.get('password'));
      }
      userModel.save(function(error, result) {
        if(error) {
          self.set('error', error.error);
        } else {
          self.set('error', false);
          self.set('success', 'Profile updated successfully.');
        }
      });
    });
  }
});
```

`updateProfile`事件是页面上按钮触发的事件。我们使用表单中的值更新`model`字段。只有用户在字段中输入了内容，密码才会更改。否则，后端将保留旧值。

我们将调用`userModel.save`，它执行对 API 的`PUT`请求。以下是我们在`backend/API.js`中处理请求的方式：

```js
.add('api/user', function(req, res) {
  switch(req.method) {
    case 'PUT':
      processPOSTRequest(req, function(data) {
        if(!data.firstName || data.firstName === '') {
          error('Please fill your first name.', res);
        } else if(!data.lastName || data.lastName === '') {
          error('Please fill your last name.', res);
        } else {
          getDatabaseConnection(function(db) {
            var collection = db.collection('users');
            if(data.password) {
              data.password = sha1(data.password);
            }
            collection.update(
              { email: req.session.user.email },
              { $set: data }, 
              function(err, result) {
                if(err) {
                  err('Error updating the data.');
                } else {
                  if(data.password) delete data.password;
                  for(var key in data) {
                    req.session.user[key] = data[key];
                  }
                  response({
                    success: 'OK'
                  }, res);
                }
              }
            );
          });
        }
      });
    break;
```

通常的字段验证又出现了。我们将检查用户是否已输入了名字和姓氏。只有在有相应数据时才会更新密码。重要的是要注意，我们需要用户的电子邮件来更新个人资料。这是我们在 MongoDB 数据库中引用确切记录的方式。由于我们将电子邮件存储在用户的会话中，因此很容易从那里获取。如果一切顺利，我们将更新`session`对象中的信息。这是必要的，因为前端从那里获取用户的详细信息，如果我们忘记进行这个更改，我们的 UI 将显示旧数据。

# 摘要

在本章中，我们取得了很大的进展。我们构建了社交网络的核心功能之一——用户管理。我们学会了如何将数据存储在 MongoDB 数据库中，并使用会话对用户进行身份验证。

在下一章中，我们将实现好友管理的功能。任何社交网络的用户都会熟悉这个功能。在下一章的结束时，用户将能够使用我们的应用程序添加好友。


# 第六章：添加友谊功能

在第五章*管理用户*中，我们实现了用户注册和登录系统。现在我们在数据库中有用户信息，我们可以继续社交网络中最重要的特征之一——友谊。在本章中，我们将添加以下逻辑：

+   查找朋友

+   标记用户为朋友

+   在**个人资料**页面上显示已连接的用户

# 查找朋友

查找朋友的过程涉及对我们当前代码库的一系列更改。以下各节将指导我们完成搜索和显示朋友资料。我们将对我们的 REST API 进行一些改进，并定义一个新的控制器和模型。

## 添加搜索页面

到目前为止，我们已经有了注册、登录和个人资料管理页面。我们将在导航栏中添加一个新链接——`查找朋友`。为了做到这一点，我们必须按照以下方式更新`frontend/tpl/navigation.html`文件：

```js
<li class="right"><a on-click="goto:logout">Logout</a></li>
<li class="right"><a on-click="goto:profile">Profile</a></li>
<li class="right"><a on-click="goto:find-friends">Find  friends</a></li>
```

我们在最后添加的链接将把用户转发到一个新的路由。与其他页面一样，我们的路由器将捕获 URL 更改并触发处理程序。以下是`app.js`文件的小更新：

```js
Router
.add('find-friends', function() {
  if(userModel.isLogged()) {
    var p = new FindFriends();
    showPage(p);
  } else {
    Router.navigate('login');
  }
})
```

如果用户未经身份验证，则不应该能够添加新的朋友。我们将在前端应用一个简单的检查，但我们也将保护 API 调用。必须创建一个新的`FindFriends`控制器。该控制器的作用是显示一个带有输入字段和按钮的表单。用户提交表单后，我们查询数据库，然后显示与输入字符串匹配的用户。以下是控制器的开始部分：

```js
// frontend/js/controllers/FindFriends.js
module.exports = Ractive.extend({
  template: require('../../tpl/find-friends'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  data: {
    loading: false,
    message: '',
    searchFor: '',
    foundFriends: null
  },
  onrender: function() {
    // ...
  }
});
```

我们保留了相同的`Navigation`和`Footer`组件。有几个变量及其默认值。`loading`关键字将用作指示我们正在向 API 发出请求的标志。查找符合某些条件的朋友可能是一个复杂的操作。因此，向用户显示我们正在处理他/她的查询将是一个很好的做法。`message`属性将用于显示一切正常的确认或报告错误。最后两个变量保留数据。`searchFor`变量将承载用户输入的字符串，`foundFriends`将承载后端返回的用户。

让我们检查一下我们需要的 HTML 标记。`frontend/tpl/find-friends.html`文件包含以下内容：

```js
<header>
  <navigation></navigation>
</header>
<div class="hero">
  <h1>Find friends</h1>
</div>
<form onsubmit="return false;">
  {{#if loading}}
    <p>Loading. Please wait.</p>
  {{else}}
    <label for="friend-name">
      Please, type the name of your friend:
    </label>
    <input type="text" id="friend-name" value="{{friendName}}"/>
    <input type="button" value="Find" on-click="find" />
  {{/if}}
</form>
{{#if foundFriends !== null}}
  <div class="friends-list">
    {{#each foundFriends}}
      <div class="friend-list-item">
        <h2>{{firstName}} {{lastName}}</h2>
        <input type="button" value="Add as a friend"
         on-click="add:{{id}}"/>
      </div>
    {{/each}}
  </div>
{{/if}}
{{#if message !== ''}}
  <div class="friends-list">
    <p>{{{message}}}</p>
  </div>
{{/if}}
<appfooter />
```

`header`和`navigation`部分保持不变。顶部有一个很好放置的标题，后面是我们提到的表单。如果`loading`标志的值为`true`，我们将显示**加载中，请稍候**消息。如果我们没有在查询后端的过程中，那么我们会显示输入字段和按钮。以下截图展示了这在实践中的样子：

![添加搜索页面](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00178.jpeg)

模板的下一部分呈现了后端发送的用户。它显示他们的姓名和一个**添加为朋友**按钮。我们将在接下来的页面中看到这个视图的截图。

HTML 标记的最后部分是用于条件显示消息。如果我们为`message`变量设置了一个值，那么 Ractive.js 将显示`div`元素并使我们的文本可见。

## 编写模型

我们有一个用户界面，可以接受用户的输入。现在，我们需要与后端通信，并检索与表单字段值匹配的用户。在我们的系统中，我们通过模型向 API 发出请求。

因此，让我们创建一个新的`frontend/js/models/Friends.js`模型：

```js
var ajax = require('../lib/Ajax');
var Base = require('./Base');

module.exports = Base.extend({
  data: {
    url: '/api/friends'
  },
  find: function(searchFor, callback) {
    ajax.request({
      url: this.get('url') + '/find',
      method: 'POST',
      data: {
        searchFor: searchFor
      },
      json: true
    })
    .done(function(result) {
      callback(null, result);
    })
    .fail(function(xhr) {
      callback(JSON.parse(xhr.responseText));
    });
  }
});
```

`friendship`功能的端点将是`/api/friends`。要在用户中进行搜索，我们在 URL 后面添加`/find`。我们将使用`POST`请求和`searchFor`变量的值进行搜索。处理结果的代码再次使用`lib/Ajax`模块，如果一切正常，它将触发指定的回调。

让我们更新调用新创建的模型及其`find`函数的控制器。在`controllers/FindFriends.js`文件的顶部，我们将添加一个`require`语句：

```js
var Friends = require('../models/Friends');
```

然后，在控制器的`render`处理程序中，我们将放置以下片段：

```js
onrender: function() {

  var model = new Friends();
  var self = this;

  this.on('find', function(e) {
    self.set('loading', true);
    self.set('message', '');
    var searchFor = this.get('friendName');
    model.find(searchFor, function(err, res) {

      if(res.friends && res.friends.length > 0) {
        self.set('foundFriends', res.friends);
      } else {
        self.set('foundFriends', null);
        self.set('message', 'Sorry, there is no friends matching <strong>' + searchFor + '<strong>');
      }
      self.set('loading', false);
    });
  });

}
```

`find`事件由表单中的按钮触发。一旦我们注册了按钮的点击，我们显示`loading`字符串并清除任何先前显示的消息。我们获取输入字段的值，并要求模型匹配用户。如果有任何潜在的朋友，我们通过为`foundFriends`变量设置一个值来呈现它们。如果没有，我们会显示一条消息，说明没有符合条件的用户。一旦我们完成了 API 方法的实现，屏幕将如下所示：

![编写模型](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00179.jpeg)

## 从数据库中获取朋友

我们需要在`backend/API.js`中进行的更改是添加一些新路由。但是，在继续查询用户之前，我们将添加一个辅助函数来获取当前用户的配置文件。我们将保留当前用户的姓名和电子邮件在一个`session`变量中，但这还不够，因为我们想显示更多的用户信息。因此，以下函数从数据库中获取完整的配置文件：

```js
var getCurrentUser = function(callback, req, res) {
  getDatabaseConnection(function(db) {
    var collection = db.collection('users');
    collection.find({ 
      email: req.session.user.email
    }).toArray(function(err, result) {
      if(result.length === 0) {
        error('No such user', res);
      } else {
        callback(result[0]);
      }
    });
  });
};
```

我们使用用户的电子邮件作为请求的标准。包含配置文件数据的对象作为回调的参数返回。

由于我们已经拥有关于当前用户的所有信息，我们可以继续实现用户搜索。应该回答这类查询的路由如下：

```js
Router
.add('api/friends/find', function(req, res) {
  if(req.session && req.session.user) {
    if(req.method === 'POST') {      
      processPOSTRequest(req, function(data) {
        getDatabaseConnection(function(db) {
          getCurrentUser(function(user) {
            findFriends(db, data.searchFor, user.friends || []);
          }, req, res);          
        });
      });
    } else {
      error('This method accepts only POST requests.', res);
    }
  } else {
    error('You must be logged in to use this method.', res);
  }
})
```

第一个`if`子句确保此路由仅对已注册并已登录的用户可访问。此方法仅接受`POST`请求。其余部分获取`searchFor`变量并调用`findFriends`函数，可以实现如下：

```js
var findFriends = function(db, searchFor, currentFriends) {
  var collection = db.collection('users');
  var regExp = new RegExp(searchFor, 'gi');
  var excludeEmails = [req.session.user.email];
  currentFriends.forEach(function(value, index, arr) {
    arr[index] = ObjectId(value);
  });
  collection.find({
    $and: [
      {
        $or: [
          { firstName: regExp },
          { lastName: regExp }
        ]
      },
      { email: { $nin: excludeEmails } },
      { _id: { $nin: currentFriends } }
    ]
  }).toArray(function(err, result) {
    var foundFriends = [];
    for(var i=0; i<result.length; i++) {
      foundFriends.push({
        id: result[i]._id,
        firstName: result[i].firstName,
        lastName: result[i].lastName
      });
    };
    response({
      friends: foundFriends
    }, res);
  });
}
```

我们系统中的用户将他们的名字分成两个变量——`firstName`和`lastName`。当用户在搜索表单字段中输入时，我们无法确定用户可能指的是哪一个。因此，我们将在数据库中搜索这两个属性。我们还将使用正则表达式来确保我们的搜索不区分大小写。

MongoDB 数据库提供了执行复杂查询的语法。在我们的情况下，我们想获取以下内容：

+   其名字的第一个或最后一个与客户端发送的条件匹配的用户。

+   与当前用户已添加的朋友不同的用户。

+   与当前用户不同的用户。我们不希望向用户提供与他们自己的配置文件的友谊。

`$nin`变量表示*值不在提供的数组中*。我们将排除当前用户的电子邮件地址。值得一提的一个小细节是，MongoDB 将用户的 ID 存储在 12 字节的 BSON 类型中。它们不是明文。因此，在发送查询之前，我们需要使用`ObjectID`函数。该方法可以通过相同的`mongodb`模块访问——`var ObjectId = require('mongodb').ObjectID`。

当数据库驱动程序返回满足我们条件的记录时，我们会过滤信息并用适当的 JSON 文件进行响应。我们不会发送用户的整个配置文件，因为我们不会使用所有数据。姓名和 ID 就足够了。

将该新路由添加到 API 将使朋友搜索起作用。现在，让我们添加逻辑，将配置文件附加到当前用户。

# 将用户标记为朋友

如果我们检查新页面的 HTML 模板，我们会发现每个呈现的用户都有一个按钮，可以触发`add`事件。让我们在我们的控制器中处理这个，并在我们的模型中运行一个类似于查找朋友的过程的函数：

```js
this.on('add', function(e, id) {
  this.set('loading', true);
  model.add(id, function(err, res) {
    self.set('foundFriends', null);
    if(err) {
      self.set('message', 'Operation failed.');
    } else if(res.success === 'OK') {
      self.set('message', 'Operation successful.');
    }
    self.set('loading', false);
  });
});
```

我们使用相同的技术来处理`loading`标志。我们将在下面的代码中介绍的模型方法接受用户的`id`值，并报告链接是否成功。我们需要清除`foundFriends`数组。否则，当前用户可能会点击同一个个人资料两次。另一个选项是只删除被点击的项目，但这涉及更多的代码。

在`models/Friends.js`中的添加如下：

```js
add: function(id, callback) {
  ajax.request({
    url: this.get('url') + '/add',
    method: 'POST',
    data: {
      id: id
    },
    json: true
  })
  .done(function(result) {
    callback(null, result);
  })
  .fail(function(xhr) {
    callback(JSON.parse(xhr.responseText));
  });
}
```

`add`和`find`方法之间的唯一区别在于，在第一个方法中，我们发送了`searchFor`，而在第二个方法中，我们发送了`id`参数。错误处理和结果响应是相同的。当然，端点也经过了调整。

我们展示个人资料，用户点击其中一些，我们的模型向后端发送`POST`请求。现在是时候实现标记用户为朋友的 API 路由了。为此，我们将通过添加一个名为`friends`的新数组来更新当前用户的个人资料，其中包含对朋友个人资料的引用：

```js
.add('api/friends/add', function(req, res) {
  if(req.session && req.session.user) {
    if(req.method === 'POST') {
      var friendId;
      var updateUserData = function(db, friendId) {
        var collection = db.collection('users');
        collection.update(
          { email: req.session.user.email },
          { $push: { friends: friendId } }, 
          done
        );
      };
      var done = function(err, result) {
        if(err) {
          error('Error updating the data.', res);
        } else {                
          response({
            success: 'OK'
          }, res);
        }
      };
      processPOSTRequest(req, function(data) {
        getDatabaseConnection(function(db) {
          updateUserData(db, data.id);
        });
      });
    } else {
      error('This method accepts only POST requests.', res);
    }
  } else {
    error('You must be logged in to use this method.', res);
  }
})
```

前面的方法再次受到保护。我们需要一个经过身份验证的用户和进行`POST`请求。在获取朋友的 ID 之后，我们使用`$push`运算符来创建（如果不存在）并填充`friends`数组。`done`函数的唯一工作是向浏览器发送响应。

本章的下一步是在用户的**个人资料**页面上显示添加的朋友。

# 在个人资料页面显示链接的用户

同样，我们将从更新我们的模板开始。在上一章中，我们创建了`frontend/tpl/profile.html`。它包含一个我们用于个人资料更新的表单。让我们在它之后添加以下代码：

```js
{{#if friends.length > 0}}
  <div class="hero">
    <h1>Friends</h1>
  </div>
  <div class="friends-list">
    {{#each friends:index}}
      <div class="friend-list-item">
        <h2>{{friends[index].firstName}}  {{friends[index].lastName}}</h2>
      </div>
    {{/each}}
  </div>
{{/if}}
```

如果 Ractive 组件有一个`friends`属性，那么我们将渲染一个用户列表。页面将显示用户的名称，看起来像下一个截图：

![在个人资料页面显示链接的用户](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00180.jpeg)

渲染页面的控制器也应该更新。我们应该使用在前几节中开发的相同的`models/Friends`模型。这就是为什么我们需要在顶部添加`var Friends = require('../models/Friends');`。另外三行代码将使记录的获取工作。我们将在控制器的`onrender`处理程序中添加它们，如下所示：

```js
// controllers/Profile.js
onrender: function() {

  ...

  var friends = new Friends();
  friends.fetch(function(err, result) {
    self.set('friends', result.friends);   });
}
```

我们在控制器中还需要做的另一个小的添加是定义`friends`变量的默认值，如下所示：

```js
  data: {
    friends: []
  },
  onrender: function() {
  ...
  }
```

这一次，我们不打算更新模型。我们将使用默认的`fetch`方法，向`/api/friends`端点发送`GET`请求。唯一需要做的是在`backend/API.js`文件中进行添加。我们需要一个路由来找到当前用户的朋友并返回它们：

```js
.add('api/friends', function(req, res) {
  if(req.session && req.session.user) {
    getCurrentUser(function(user) {
      if(!user.friends || user.friends.length === 0) {
        return response({ friends: [] }, res);
      }
      user.friends.forEach(function(value, index, arr) {
        arr[index] = ObjectId(value);
      });
      getDatabaseConnection(function(db) {
        var collection = db.collection('users');
        collection.find({ 
          _id: { $in: user.friends }
        }).toArray(function(err, result) {
          result.forEach(function(value, index, arr) {
            arr[index].id = value.id;
            delete arr[index].password;
            delete arr[index].email;
            delete arr[index]._id;
          });
          response({
            friends: result
          }, res);
        });
      });
    }, req, res);
  } else {
    error('You must be logged in to use this method.', res);
  }
})
```

这是我们使用`getCurrentUser`辅助函数的第二个地方。我们没有用户的个人资料。因此，我们需要向 MongoDB 服务器发出一个额外的请求。在这种情况下，`$in`运算符对我们有帮助。再次，在将它们与查询一起发送之前，我们需要将 ID 转换为适当的格式。最后，在向浏览器响应之前，我们删除敏感信息，如 ID、密码和电子邮件。前端将收到一个包含当前登录用户的所有朋友的漂亮数组。

# 总结

在本章中，我们使得用户之间创建链接成为可能。我们加强了对前端控制器和模型的了解。我们通过一些复杂的数据库查询扩展了项目的 API，添加了一些新的方法。

在下一章中，我们将学习如何使用 Node.js 上传内容。与其他流行的社交网络一样，发布的信息将显示为用户的动态。


# 第七章：发布内容

第六章，“添加友谊功能”，是关于添加友谊功能的。在社交网络中与其他用户建立联系的能力很重要。然而，更重要的是提供一个生成内容的接口。在本章中，我们将实现内容创建背后的逻辑。我们将涵盖以下主题：

+   发布和存储文本

+   显示用户的动态

+   发布文件

# 发布和存储文本

与前几章一样，我们有一个需要在应用程序的前端和后端部分都进行更改的功能。我们需要一个 HTML 表单，接受用户的文本，一个处理与后端通信的新模型，当然，还有 API 的更改。让我们从更新我们的主页开始。

## 添加一个发布文本消息的表单

我们有一个显示简单标题的主页。让我们使用它，并添加一个`<textarea>`标签来将内容发送到 API。在本章的后面，我们将使用同一个页面来显示用户的动态。让我们用以下标记替换孤独的`<h1>`标签：

```js
{{#if posting === true}}
  <form enctype="multipart/form-data" method="post">
    <h3>What is on your mind?</h3>
    {{#if error && error != ''}}
      <div class="error">{{{error}}}</div>
    {{/if}}
    {{#if success && success != ''}}
      <div class="success">{{{success}}}</div>
    {{/if}}
    <label for="text">Text</label>
    <textarea value="{{text}}"></textarea>
    <input type="file" name="file" />
    <input type="button" value="Post" on-click="post" />
  </form>
{{else}}
  <h1>Node.js by example</h1>
{{/if}}
```

我们仍然有标题，但只有当`posting`变量等于`false`时才显示。在接下来的部分中，我们将更新主页的控制器，我们将使用`posting`来保护内容的表单。在某些情况下，我们不希望使`<textarea>`可见。

请注意，我们有两个块来显示消息。如果在发布过程中出现错误，第一个块将可见，当一切顺利时，第二个块将可见。表单的其余部分是所需的用户界面——文本区域、输入文件字段和一个按钮。按钮会触发一个发布事件，我们将在控制器中捕获到。

## 介绍内容模型

我们肯定需要一个模型来管理与 API 的通信。让我们创建一个新的`models/Content.js`文件，并将以下代码放在那里：

```js
var ajax = require('../lib/Ajax');
var Base = require('./Base');

module.exports = Base.extend({
  data: {
    url: '/api/content'
  },
  create: function(content, callback) {
    var self = this;
    ajax.request({
      url: this.get('url'),
      method: 'POST',
      data: {
        text: content.text
      },
      json: true
    })
    .done(function(result) {
      callback(null, result);
    })
    .fail(function(xhr) {
      callback(JSON.parse(xhr.responseText));
    });
  }
});
```

该模块扩展了相同的`models/Base.js`类，它类似于我们系统中的其他模型。需要`lib/Ajax.js`模块，因为我们将进行 HTTP 请求。我们应该熟悉其余的代码。通过将文本作为参数传递给`create`函数，向`/api/content`发出`POST`请求。

当我们到达文件发布时，该模块将被更新。要创建仅基于文本的记录，这就足够了。

## 更新主页的控制器

现在我们有了一个合适的模型和形式，我们准备调整主页的控制器。如前所述，`posting`变量控制表单的可见性。它的值将默认设置为`true`，如果用户未登录，我们将把它改为`false`。每个 Ractive.js 组件都可以有一个`data`属性。它表示所有内部变量的初始状态：

```js
// controllers/Home.js
module.exports = Ractive.extend({
  template: require('../../tpl/home'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  data: {
    posting: true
  }
});
```

现在，让我们向`onrender`处理程序添加一些逻辑。这是我们组件的入口点。我们将首先检查当前用户是否已登录：

```js
onrender: function() {
  if(userModel.isLogged()) {
    // ...
  } else {
    this.set('posting', false);
  }
}
```

从第五章，“管理用户”中，我们知道`userModel`是一个全局对象，我们可以用它来检查当前用户的状态。如前所述，如果我们有一个未经授权的访问者，我们必须将`posting`设置为`false`。

下一个逻辑步骤是处理表单中的内容并向 API 提交请求。我们将使用新创建的`ContentModel`类，如下所示：

```js
var ContentModel = require('../models/Content');
var model = new ContentModel();
var self = this;
this.on('post', function() {
  model.create({
    text: this.get('text')
  }, function(error, result) {
    self.set('text', '');
    if(error) {
      self.set('error', error.error);
    } else {
      self.set('error', false);
      self.set('success', 'The post is saved successfully.<br />What about adding another one?');
    }
  });
});
```

一旦用户在表单中按下按钮，我们的组件就会触发一个`post`事件。然后我们将捕获事件并调用模型的`create`方法。给用户一个合适的响应很重要，所以我们用`self.set('text', '')`清除文本字段，并使用本地的`error`和`success`变量来指示请求的状态。

## 在数据库中存储内容

到目前为止，我们有一个 HTML 表单，它向 API 提交 HTTP 请求。在本节中，我们将更新我们的 API，以便我们可以在数据库中存储文本内容。我们模型的端点是`/api/content`。我们将添加一个新的路由，并通过允许只有授权用户访问来保护它：

```js
// backend/API.js
.add('api/content', function(req, res) {
  var user;
  if(req.session && req.session.user) {
    user = req.session.user;
  } else {
    error('You must be logged in in order to use this method.', res);
  }
})
```

我们将创建一个包含访客会话数据的`user`本地变量。发送到数据库的每个帖子都应该有一个所有者。因此，有一个快捷方式到用户的个人资料是很好的。

同样的`/api/content`目录也将用于获取帖子。同样，我们将使用`req.method`属性来查找请求的类型。如果是`GET`，我们需要从数据库中获取帖子并将它们发送到浏览器。如果是`POST`，我们需要创建一个新的条目。以下是将用户的文本发送到数据库的代码：

```js
switch(req.method) {
  case 'POST':
    processPOSTRequest(req, function(data) {
      if(!data.text || data.text === '') {
        error('Please add some text.', res);
      } else {
        getDatabaseConnection(function(db) {
          getCurrentUser(function(user) {
            var collection = db.collection('content');
            data.userId = user._id.toString();
            data.userName = user.firstName + ' ' + user.lastName;
            data.date = new Date();
            collection.insert(data, function(err, docs) {
              response({
                success: 'OK'
              }, res);
            });
          }, req, res);
        });
      }
    });
  break;
};
```

浏览器发送的数据作为`POST`变量传递。同样，我们需要`processPOSTRequest`的帮助来访问它。如果没有`.text`或者它是空的，API 将返回一个错误。如果一切正常并且文本消息可用，我们将继续建立数据库连接。我们还会获取当前用户的整个个人资料。我们的社交网络中的帖子将与以下附加属性一起保存：

+   `userId`：这代表了记录的创建者。我们将在生成动态时使用这个属性。

+   `userName`：我们不想为我们显示的每一篇帖子都调用`getCurrentUser`。因此，所有者的名称直接与文本一起存储。值得一提的是，在某些情况下，这样的调用是必要的。例如，在更改用户的名称时，将需要这些调用。

+   `date`：我们应该知道数据的创建日期。这对于数据的排序或过滤是有用的。

最后，我们调用`collection.insert`，这实际上将条目存储在数据库中。

在下一节中，我们将看到如何检索创建的内容并将其显示给用户。

# 显示用户的动态

现在，每个用户都能够在我们的数据库中存储消息。让我们继续通过在浏览器中显示记录来展示。我们将首先向获取帖子的 API 添加逻辑。这将很有趣，因为你不仅应该获取特定用户发送的消息，还应该获取他/她的朋友发送的消息。我们使用`POST`方法来创建内容。接下来的行将处理`GET`请求。

首先，我们将以以下方式获取用户的朋友的 ID：

```js
case 'GET':
  getCurrentUser(function(user) {
    if(!user.friends) {
      user.friends = [];
    }
    // ...
break;
```

在上一章中，我们实现了友谊功能，并直接在用户的个人资料中保留了用户的朋友的 ID。`friends`数组正是我们需要的，因为我们的社交网络中的帖子是通过它们的 ID 与用户的个人资料相关联的。

下一步是建立与数据库的连接，并仅查询与特定 ID 匹配的记录，如下所示：

```js
case 'GET':
  getCurrentUser(function(user) {
    if(!user.friends) {
      user.friends = [];
    }
    getDatabaseConnection(function(db) {
      var collection = db.collection('content');
      collection.find({ 
        $query: {
          userId: { $in: [user._id.toString()].concat(user.friends) }
        },
        $orderby: {
          date: -1
        }
      }).toArray(function(err, result) {
        result.forEach(function(value, index, arr) {
          arr[index].id = ObjectId(value.id);
          delete arr[index].userId;
        });
        response({
          posts: result
        }, res);
      });
    });
  }, req, res);
break;
```

我们将从`content`集合中读取记录。`find`方法接受一个具有`$query`和`$orderby`属性的对象。在第一个属性中，我们将放入我们的条件。在这种特殊情况下，我们想要获取所有属于`friends`数组的记录的 ID。为了创建这样的查询，我们需要`$in`运算符。它接受一个数组。除了用户的朋友的帖子，我们还需要显示用户的帖子。因此，我们将创建一个数组，其中包含一个项目——当前用户的 ID，并将其与`friends`连接起来，如下所示：

```js
[user._id.toString()].concat(user.friends)
```

成功查询后，`userId`属性将被删除，因为它不再需要。在`content`集合中，我们保留消息的文本和所有者的名称。最后，记录将附加到`posts`属性上发送。

通过在前面的代码中添加的内容，我们的后端返回了当前用户和他们的朋友发布的帖子。我们所要做的就是更新我们主页的控制器并使用 API 的方法。在监听`post`事件的代码之后，我们添加以下代码：

```js
var getPosts = function() {
  model.fetch(function(err, result) {
    if(!err) {
      self.set('posts', result.posts);
    }
  });
};
getPosts();
```

调用`fetch`方法触发对模型端点`/api/content`的 API 的`GET`请求。这个过程被包装在一个函数中，因为当创建新帖子时会发生相同的操作。正如我们已经知道的，如果`model.create`成功，就会触发回调。我们将在那里添加`getPosts()`，这样用户就可以在动态中看到他/她的最新帖子：

```js
// frontend/js/controllers/Home.js
model.create(formData, function(error, result) {
  self.set('text', '');
  if(error) {
    self.set('error', error.error);
  } else {
    self.set('error', false);
    self.set('success', 'The post is saved  successfully.<br />What about adding another one?');
    getPosts();
  }
});
```

`getPosts`函数产生的结果是存储在名为`posts`的本地变量中的对象列表。同样的变量可以在 Ractive.js 模板中访问。我们需要遍历数组中的项目，并在屏幕上显示信息，如下所示：

```js
// frontend/tpl/home.html
<header>
  <navigation></navigation>
</header>
<div class="hero">
  {{#if posting === true}}
    <form enctype="multipart/form-data" method="post">
      ...
    </form>
    {{#each posts:index}}
      <div class="content-item">
        <h2>{{posts[index].userName}}</h2>
        {{posts[index].text}}
      </div>
    {{/each}}
  {{else}}
    <h1>Node.js by example</h1>
  {{/if}}
</div>
<appfooter />
```

在表单之后，我们使用`each`操作符来显示帖子的作者和文本。

在这一点上，我们网络中的用户将能够创建和浏览以文本块形式的消息。在下一节中，我们将扩展到目前为止编写的功能，并使上传图像与文本一起成为可能。

# 发布文件

我们正在构建一个单页面应用程序。这类应用程序的特点之一是所有操作都在不重新加载页面的情况下进行。上传文件而不改变页面一直是棘手的。过去，我们使用涉及隐藏 iframe 或小型 Flash 应用程序的解决方案。幸运的是，当 HTML5 出现时，它引入了**FormData**接口。

流行的 Ajax 是由`XMLHttpRequest`对象实现的。2005 年，Jesse James Garrett 创造了“Ajax”这个术语，我们开始使用它在 JavaScript 中进行 HTTP 请求。以以下方式执行`GET`或`POST`请求变得很容易：

```js
var http = new XMLHttpRequest();
var url = "/api/content";
var params = "text=message&author=name";
http.open("POST", url, true);

http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
http.setRequestHeader("Content-length", params.length);
http.setRequestHeader("Connection", "close");

http.onreadystatechange = function() {
  if(http.readyState == 4 && http.status === 200) {
    alert(http.responseText);
  }
}

http.send(params);
```

前面的代码生成了一个正确的`POST`请求，甚至设置了正确的标头。问题在于参数被表示为字符串。形成这样的字符串需要额外的工作。发送文件也很困难。这可能是相当具有挑战性的。

FormData 接口解决了这个问题。我们创建一个对象，它是表示表单字段及其值的键/值对集合。然后，我们将这个对象传递给`XMLHTTPRequest`类的`send`方法：

```js
var formData = new FormData();
var fileInput = document.querySelector('input[type="file"]');
var url = '/api/content';

formData.append("username", "John Black");
formData.append("id", 123456);
formData.append("userfile", fileInput.files[0]);

var request = new XMLHttpRequest();
request.open("POST", url);
request.send(formData);
```

我们所要做的就是使用`append`方法并指定`file`类型的`input` DOM 元素。其余工作由浏览器完成。

为了提供上传文件的功能，我们需要添加文件选择的 UI 元素。以下是`home.html`模板中表单的样子：

```js
<form enctype="multipart/form-data" method="post">
  <h3>What is on your mind?</h3>
  {{#if error && error != ''}}
    <div class="error">{{error}}</div>
  {{/if}}
  {{#if success && success != ''}}
    <div class="success">{{{success}}}</div>
  {{/if}}
  <label for="text">Text</label>
  <textarea value="{{text}}"></textarea>
  <input type="file" name="file" />
  <input type="button" value="Post" on-click="post" />
</form>
```

相同的代码，但是有一个新的`input`元素，类型等于`file`。到目前为止，我们的控制器中发送`POST`请求的实现并没有使用`FormData`接口。让我们改变这一点，并更新`controllers/Home.js`文件：

```js
this.on('post', function() {
  var files = this.find('input[type="file"]').files;
  var formData = new FormData();
  if(files.length > 0) {
    var file = files[0];
    if(file.type.match('image.*')) {
      formData.append('files', file, file.name);
    }
  }
  formData.append('text', this.get('text'));
  model.create(formData, function(error, result) {
    self.set('text', '');
    if(error) {
      self.set('error', error.error);
    } else {
      self.set('error', false);
      self.set('success', 'The post is saved  successfully.<br />What about adding another one?');
      getPosts();
    }
  });
});
```

代码已经改变。因此，代码创建了一个新的`FormData`对象，并使用`append`方法收集新帖子所需的信息。我们确保用户选择的文件被附加。默认情况下，HTML 输入只提供选择一个文件。但是，我们可以添加`multiple`属性，浏览器将允许我们选择多个文件。值得一提的是，我们过滤所选文件，并且只使用图像。

经过最新的更改，我们模型的`create`方法接受`FormData`对象而不是普通的 JavaScript 对象。因此，我们也必须更新模型：

```js
// models/Content.js
create: function(formData, callback) {
  var self = this;
  ajax.request({
    url: this.get('url'),
    method: 'POST',
    formData: formData,
    json: true
  })
  .done(function(result) {
    callback(null, result);
  })
  .fail(function(xhr) {
    callback(JSON.parse(xhr.responseText));
  });
}
```

`data`属性被`formData`属性替换。现在我们知道前端将选定的文件发送到 API。但是，我们没有处理`multipart/form-data`类型的`POST`数据的代码。通过`POST`请求发送的文件的处理并不简单，`processPOSTRequest`在这种情况下无法完成任务。

Node.js 拥有一个庞大的社区，有成千上万的模块可用。`formidable`模块是我们要使用的。它有一个相当简单的 API，并且处理包含文件的请求。文件上传过程中，`formidable`会将文件保存在服务器硬盘的特定位置。然后，我们会收到资源的路径。最后，我们必须决定如何处理它。

在`backend/API.js`文件中，应用流程分为`GET`和`POST`请求。我们将更新`POST`情况的一个重要部分。以下行包含了`formidable`的初始化：

```js
case 'POST':
  var formidable = require('formidable');
  var uploadDir = __dirname + '/../static/uploads/';
  var form = new formidable.IncomingForm();
  form.multiples = true;
  form.parse(req, function(err, data, files) {
    // ...
  });
break;
```

正如我们之前提到的，该模块将上传的文件保存在硬盘上的临时文件夹中。`uploadDir`变量包含了用户图片的更合适的位置。传递给`formidable`的`parse`函数的回调在`data`参数中接收普通文本字段，并在`files`中上传图像。

为了避免嵌套 JavaScript 回调的长链条，我们将一些逻辑提取到函数定义中。例如，将文件从`temporary`移动到`static`文件夹可以按以下方式执行：

```js
var processFiles = function(userId, callback) {
  if(files.files) {
    var fileName = userId + '_' + files.files.name;
    var filePath = uploadDir + fileName;
    fs.rename(files.files.path, filePath, function() {
      callback(fileName);
    });
  } else {
    callback();
  }
};
```

我们不想混合不同用户的文件。因此，我们将使用用户的 ID 并创建他/她自己的文件夹。还有一些其他问题可能需要我们处理。例如，我们可以为每个文件创建子文件夹，以防止已上传资源的覆盖。然而，为了尽可能保持代码简单，我们将在这里停止。

以下是将帖子保存到数据库的完整代码：

```js
case 'POST':
  var uploadDir = __dirname + '/../static/uploads/';
  var formidable = require('formidable');
  var form = new formidable.IncomingForm();
  form.multiples = true;
  form.parse(req, function(err, data, files) {
    if(!data.text || data.text === '') {
      error('Please add some text.', res);
    } else {
      var processFiles = function(userId, callback) {
        if(files.files) {
          var fileName = userId + '_' + files.files.name;
          var filePath = uploadDir + fileName;
          fs.rename(files.files.path, filePath, function(err) {
            if(err) throw err;
            callback(fileName);
          });
        } else {
          callback();
        }
      };
      var done = function() {
        response({
          success: 'OK'
        }, res);
      }
      getDatabaseConnection(function(db) {
        getCurrentUser(function(user) {
          var collection = db.collection('content');
          data.userId = user._id.toString();
          data.userName = user.firstName + ' ' + user.lastName;
          data.date = new Date();
          processFiles(user._id, function(file) {
            if(file) {
              data.file = file;
            }
            collection.insert(data, done);
          });
        }, req, res);
      });
    }
  });
break;
```

我们仍然需要与数据库建立连接并获取当前用户的个人资料。这里的不同之处在于，我们向存储在 MongoDB 中的对象附加了一个新的`file`属性。

最后，我们必须更新主页的模板，以便显示上传的文件：

```js
{{#each posts:index}}
  <div class="content-item">
    <h2>{{posts[index].userName}}</h2>
    {{posts[index].text}}
    {{#if posts[index].file}}
    <img src="img/{{posts[index].file}}" />
    {{/if}}
  </div>
{{/each}}
```

现在，`each`循环检查是否有文件与帖子文本一起传输。如果有，它会显示一个显示图像的`img`标签。通过这最后的添加，我们社交网络的用户将能够创建由文本和图片组成的内容。

# 总结

在本章中，我们为我们的应用程序做了一些非常重要的事情。通过扩展我们的后端 API，我们实现了内容的创建和传递。前端也进行了一些更改。

在下一章中，我们将继续添加新功能。我们将使创建品牌页面和活动成为可能。


# 第八章：创建页面和事件

第七章，*发布内容*，涵盖了发布内容。我们为用户提供了一个界面，可以将文本和图像发送到我们的数据库。稍后，这些资源将显示为主页上的消息源。在本章中，我们将学习如何创建页面和附加到这些页面的事件。以下是我们将要遵循的计划：

+   重构 API

+   添加创建页面的表单

+   在数据库中创建记录

+   显示当前添加的页面

+   显示特定页面

+   在页面上发布评论

+   显示评论

+   管理附加到特定页面的事件

# 重构 API

如果您检查上一章结束时得到的文件，您会发现`backend/API.js`文件非常大。随着工作的进行，它将变得越来越难处理。我们将重构系统的这一部分。

我们有一堆辅助方法，它们在整个路由处理程序中都被使用。诸如`response`、`error`和`getDatabaseConnection`之类的函数可以放在一个外部模块中。我们将在`backend`目录下创建一个新的`api`文件夹。新创建的`helpers.js`文件将承载所有这些实用函数：

```js
// backend/api/helpers.js
var MongoClient = require('mongodb').MongoClient;
var querystring = require('querystring');
var database;

var response = function(result, res) { ... };
var error = function(message, res) { ... };
var getDatabaseConnection = function(callback) { ... };
var processPOSTRequest = function(req, callback) { ... };
var validEmail = function(value) { ... };
var getCurrentUser = function(callback, req, res) { ... };

module.exports = {
  response: response,
  error: error,
  getDatabaseConnection: getDatabaseConnection,
  processPOSTRequest: processPOSTRequest,
  validEmail: validEmail,
  getCurrentUser: getCurrentUser
};
```

我们将跳过函数的实现，以免用已经看到的代码膨胀本章。我们还复制了一些方法使用的变量。

我们重构的下一步是将所有路由处理程序提取到它们自己的方法中。到目前为止，文件的结构如下：

```js
var Router = require('../frontend/js/lib/router')();
Router
.add('api/version', function(req, res) { ... })
.add('api/user/login', function(req, res) { ... })
```

整个结构是一堆路由定义及其相应的处理程序。我们经常有一个`switch`语句来检查请求的类型。实际上，每个函数(`req`，`res`)都可以由一个独立的模块表示。再次强调，我们不会粘贴所有创建的文件的内容，但我们会谈论最终结果。重构后，我们将有以下结构：

![重构 API](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00181.jpeg)

`API.js`中的行数显著减少。现在，我们只有路由的定义及其处理程序：

```js
var Router = require('../frontend/js/lib/router')();
Router
.add('api/version', require('./api/version'))
.add('api/user/login', require('./api/user-login'))
.add('api/user/logout', require('./api/user-logout'))
.add('api/user', require('./api/user'))
.add('api/friends/find', require('./api/friends-find'))
.add('api/friends/add', require('./api/friends-add'))
.add('api/friends', require('./api/friends'))
.add('api/content', require('./api/content'))
.add('api/pages/:id', require('./api/pages'))
.add('api/pages', require('./api/pages'))
.add(require('./api/default'));
module.exports = function(req, res) {
  Router.check(req.url, [req, res]);
}
```

新文件导出的函数仍然是相同的。您唯一需要考虑的是辅助函数。您必须在所有新模块中提供它们。例如，`friends.js`文件包含以下内容：

```js
var ObjectId = require('mongodb').ObjectID;
var helpers = require('./helpers');
var response = helpers.response;
var error = helpers.error;
var getDatabaseConnection = helpers.getDatabaseConnection;
var getCurrentUser = helpers.getCurrentUser;

module.exports = function(req, res) {
  ...
}
```

查看本章附带的文件以获取完整的源代码。

# 添加创建页面的表单

我们社交网络中的每个用户都应该能够浏览和创建页面。这是一个全新的功能。因此，我们需要一个新的路由和控制器。

1.  让我们从更新`frontend/js/app.js`开始，如下所示：

```js
.add('pages', function() {
  if(userModel.isLogged()) {
    var p = new Pages();
    showPage(p);
  } else {
    Router.navigate('login');
  }    
})
.add(function() {
  Router.navigate('home');
})
```

1.  就在默认处理程序的上方，我们将注册一个路由，创建一个名为`Pages`的新控制器的实例。我们将确保访问者在看到页面之前已登录。在同一文件中，顶部我们将添加`var Pages = require('./controllers/Pages');`。

1.  让我们深入研究`controllers/Page.js`文件，看看如何引导控制器：

```js
module.exports = Ractive.extend({
  template: require('../../tpl/pages'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  data: { },
  onrender: function() { }
});
```

1.  `onrender`函数仍然是空的，但我们将在接下来的几节中填充它。支持此页面的模板位于`frontend/tpl/pages.html`中：

```js
<header>
  <navigation></navigation>
</header>
<div class="hero">
  <form enctype="multipart/form-data" method="post">
    <h3>Add a new page</h3>
    {{#if error && error != ''}}
      <div class="error">{{error}}</div>
    {{/if}}
    {{#if success && success != ''}}
      <div class="success">{{{success}}}</div>
    {{/if}}
    <label>Title</label>
    <textarea value="{{title}}"></textarea>
    <label>Description</label>
    <textarea value="{{description}}"></textarea>
    <input type="button" value="Create" on-click="create" />
  </form>
</div>
<appfooter />
```

代码看起来类似于上一章中创建 UI 以添加内容时使用的代码。我们有成功和错误消息的占位符。有两个变量，`title`和`description`，以及一个分派`create`事件的按钮。

# 在数据库中创建记录

让我们继续处理用户按下**创建**按钮的情况。用户执行此操作后，我们必须获取文本区域的内容并向后端提交请求。因此，我们需要一个新的模型。让我们称之为`Pages.js`并将其保存在`models`目录下：

```js
// frontend/js/models/Pages.js
var ajax = require('../lib/Ajax');
var Base = require('./Base');
module.exports = Base.extend({
  data: {
    url: '/api/pages'
  },
  create: function(formData, callback) {
    var self = this;
    ajax.request({
      url: this.get('url'),
      method: 'POST',
      formData: formData,
      json: true
    })
    .done(function(result) {
      callback(null, result);
    })
    .fail(function(xhr) {
      callback(JSON.parse(xhr.responseText));
    });
  }
});
```

我们已经在上一章中讨论了`FormData`接口。我们将要使用的 API 端点是`/api/pages`。这是我们将发送`POST`请求的 URL。

现在我们已经显示了表单，并且模型已准备好进行后端通信，我们可以继续在控制器中编写代码。`onrender`处理程序是监听`create`事件的正确位置：

```js
onrender: function() {
  var model = new PagesModel();
  var self = this;
  this.on('create', function() {
    var formData = new FormData();
    formData.append('title', this.get('title'));
    formData.append('description', this.get('description'));
    model.create(formData, function(error, result) {
      if(error) {
        self.set('error', error.error);
      } else {
        self.set('title', '');
        self.set('description', '');
        self.set('error', false);
        self.set('success', 'The page was created successfully.
      }
    });
  });
}
```

模型的初始化在顶部。在获取用户填写的数据之后，我们将调用模型的`create`方法，并在之后处理响应。如果出现问题，我们的应用程序会显示错误消息。

这一部分的最后一步是更新 API，以便我们可以将数据保留在我们的数据库中。仍然没有与`/api/pages`匹配的路由。因此，让我们添加一个：

```js
// backend/API.js
.add('api/pages', require('./api/pages'))
.add(require('./api/default'));
```

我们重构了 API，以便处理请求的代码转到新的`/backend/api/pages.js`文件。在前几行中，有我们的辅助方法的快捷方式：

```js
var ObjectId = require('mongodb').ObjectID;
var helpers = require('./helpers');
var response = helpers.response;
var error = helpers.error;
var getDatabaseConnection = helpers.getDatabaseConnection;
var getCurrentUser = helpers.getCurrentUser;
```

这是在新的`pages`集合中创建新记录的代码。它可能看起来有点长，但其中的大部分内容已经在第七章中涵盖了，*发布内容*：

```js
module.exports = function(req, res) {
  var user;
  if(req.session && req.session.user) {
    user = req.session.user;
  } else {
    error('You must be logged in in order to use this  method.', res);
    return;
  }
  switch(req.method) {
    case 'GET': break;
    case 'POST':
      var formidable = require('formidable');
      var form = new formidable.IncomingForm();
      form.parse(req, function(err, formData, files) {
        var data = {
          title: formData.title,
          description: formData.description
        };
        if(!data.title || data.title === '') {
          error('Please add some title.', res);
        } else if(!data.description || data.description === '') {
          error('Please add some description.', res);
        } else {
          var done = function() {
            response({
              success: 'OK'
            }, res);
          }
          getDatabaseConnection(function(db) {
            getCurrentUser(function(user) {
              var collection = db.collection('pages');
              data.userId = user._id.toString();
              data.userName = user.firstName + ' ' + user.lastName;
              data.date = new Date();
              collection.insert(data, done);
            }, req, res);
          });
        }
      });
    break;
  };
}
```

创建和浏览页面是仅供已登录用户使用的功能。导出函数的前几行检查当前访问者是否有有效的会话。前端发送一个不带文件的`POST`请求，但我们仍然需要`formidable`模块，因为它具有良好的编程接口并且易于使用。每个页面都应该有标题和描述，我们将检查它们是否存在。如果一切正常，我们将使用众所周知的`getDatabaseConnection`函数在数据库中创建新记录。

# 显示当前添加的页面

很高兴我们开始将创建的页面保存在数据库中。但是，向用户显示页面，以便他们可以访问并添加评论也将是很好的。为了做到这一点，我们必须修改我们的 API，以便返回页面信息。如果您查看前面的代码，您会发现有一个留空的`GET`情况。以下代码获取所有页面，按日期排序，并将它们发送到浏览器：

```js
case 'GET':
  getDatabaseConnection(function(db) {
    var collection = db.collection('pages');
    collection.find({ 
      $query: { },
      $orderby: {
        date: -1
      }
    }).toArray(function(err, result) {
      result.forEach(function(value, index, arr) {
        arr[index].id = value._id;
        delete arr[index].userId;
      });
      response({
        pages: result
      }, res);
    });
  });
break;
```

在将 JSON 对象发送到前端之前，我们将删除创建者的 ID。用户的名称已经存在，将这些 ID 仅保留在后端是一个很好的做法。

快速重启后，当我们访问`/api/pages`时，Node.js 服务器将返回创建的页面。让我们继续前进，并更新我们应用程序客户端的`controllers/Pages.js`文件。在`onrender`处理程序中，我们将追加以下代码：

```js
var getPages = function() {
  model.fetch(function(err, result) {
    if(!err) {
      self.set('pages', result.pages);
    } else {
      self.set('error', err.error);
    }
  });
};
getPages();
```

我们将新添加的逻辑封装在一个函数中，因为当创建新页面时，我们必须经历相同的事情。模型完成了大部分工作。我们将简单地将对象数组分配给`pages`变量。此变量在组件的模板—`frontend/tpl/pages.html`—中使用如下：

```js
{{#each pages:index}}
  <div class="content-item">
    <h2>{{pages[index].title}}</h2>
    <p><small>Created by {{pages[index].userName}}</small></p>
    <p>{{pages[index].description}}</p>
    <p><a href="/pages/{{pages[index].id}}" class="button">Visit the page</a></p>
  </div>
{{/each}}
```

在下一节中，您将学习如何仅显示特定页面。我们在此代码中添加的链接将用户转发到新地址。此链接是一个包含仅一个页面信息的 URL。

# 展示特定页面

再次，要显示特定页面，我们需要更新我们的 API。我们有返回所有页面的代码，但如果要返回其中一个页面，则没有解决方案。我们肯定会使用页面的 ID。因此，这里是一个可以添加到`backend/API.js`的新路由：

```js
.add('api/pages/:id', require('./api/pages'))
.add('api/pages', require('./api/pages'))
```

您应该记住路由的顺序很重要。包含页面 ID 的路由应该在显示页面列表的路由之上。否则，应用程序将不断列出新的 URL，但我们将保持相同的处理程序。如果地址中有任何动态部分，我们的路由器会向函数发送一个额外的参数。因此，在`backend/api/pages.js`中，我们将`module.exports = function(req, res)`更改为`module.exports = function(req, res, params)`。在同一个文件中，我们将从数据库中获取所有页面。在这种情况下，我们希望修改代码，使得函数只返回与 URL 中传递的 ID 匹配的一条记录。到目前为止，我们的 MongoDB 查询看起来是这样的：

```js
collection.find({ 
  $query: { },
  $orderby: {
    date: -1
  }
}
```

在实践中，我们没有标准。现在，让我们将前面的代码更改为以下内容：

```js
var query;
if(params && params.id) {
  query = { _id: ObjectId(params.id) };
} else {
  query = {};
}
collection.find({ 
  $query: query,
  $orderby: {
    date: -1
  }
}
```

通过定义一个`query`变量，我们使得这个 API 方法的响应是有条件的。它取决于 URL 中 ID 的存在。如果有任何这样的 ID，它仍然返回一个对象数组，但里面只有一个项目。

在前端，我们可以使用相同的方法，或者换句话说，相同的控制器来处理两种情况——显示所有页面和仅显示一个页面。我们注册一个新的路由处理程序，将用户转发到相同的`Pages`控制器，如下所示：

```js
// frontend/js/app.js
.add('pages/:id', function(params) {
  if(userModel.isLogged()) {
    var p = new Pages({ 
      data: {
        pageId: params.id
      }
    });
    showPage(p);
  } else {
    Router.navigate('login');
  }
})
```

这一次，在控制器初始化期间传递了配置。在`data`属性中设置值会创建稍后在组件及其模板中可用的变量。在我们的情况下，`pageId`将通过`this.get('pageId')`访问。如果变量不存在，那么我们处于显示所有页面的模式。以下行显示单个页面的标题和描述：

```js
// controllers/Page.js
onrender: function() {
  var model = new PagesModel();
  var self = this;

  var pageId = this.get('pageId');
  if(pageId) {
    model.getPage(pageId, function(err, result) {
      if(!err && result.pages.length > 0) {
        var page = result.pages[0];
        self.set('pageTitle', page.title);
        self.set('pageDescription', page.description);
      } else {
        self.set('pageTitle', 'Missing page.');
      }
    });
    return;
  }

  …
```

到目前为止，我们使用的模型执行`POST`和`GET`请求，但在这种情况下我们不能使用它们。它们是为其他功能保留的。我们需要另一种接受页面 ID 的方法。这就是为什么我们将添加一个新的`getPage`函数：

```js
// models/Pages.js
getPage: function(pageId, callback) {
  var self = this;
  ajax.request({
    url: this.get('url') + '/' + pageId,
    method: 'GET',
    json: true
  })
  .done(function(result) {
    callback(null, result);
  })
  .fail(function(xhr) {
    callback(JSON.parse(xhr.responseText));
  });
}
```

我们没有任何数据要发送。我们只有一个不同的终端 URL。页面的 ID 附加在`/api/pages`字符串的末尾。这一部分始于后端的更改，以便我们知道 API 返回一个元素的数组。其余部分是设置`pageTitle`和`pageDescription`。

在模板中，我们使用相同的模式。您可以检查`pageId`是否存在，这就足以判断我们是否需要显示一个页面还是多个页面：

```js
{{#if pageId}}
  <div class="hero">
    <h1>{{pageTitle}}</h1>
    <p>{{pageDescription}}</p>
  </div>
  <hr />
{{else}}
  <div class="hero">
    <form enctype="multipart/form-data" method="post">
      ...
    </form>
  </div>
  {{#each pages:index}}
    ...
  {{/each}}
{{/if}}
```

在更改`frontend/tpl/pages.html`之后，我们为每个页面都有了一个唯一的 URL。然而，一个具有静态标题和描述的页面对于用户来说并不是很有趣。让我们添加一个评论部分。

# 发布评论到页面

在发送和处理 HTTP 请求的部分之前，我们必须提供一个用户界面来创建评论。我们将在`frontend/tpl/pages.html`中的页面标题和描述下方添加一个表单：

```js
<form enctype="multipart/form-data" method="post">
  <h3>Add a comment for this page</h3>
  {{#if error && error != ''}}
    <div class="error">{{error}}</div>
  {{/if}}
  {{#if success && success != ''}}
    <div class="success">{{{success}}}</div>
  {{/if}}
  <label for="text">Text</label>
  <textarea value="{{text}}"></textarea>
  <input type="button" value="Post" on-click="add-comment" />
</form>
```

点击按钮后触发的事件是`add-comment`。`Pages`控制器应该处理它并向后端发送请求。

如果你停下来思考一下评论的外观，你会注意到它们与用户在用户动态中看到的常规用户帖子相似。因此，我们将把评论保存为常规帖子，而不是在`pages`集合中创建新的集合或存储复杂的数据结构。对于客户端的代码来说，这意味着`ContentModel`类的一个更多的用例：

```js
// controllers/Pages.js
this.on('add-comment', function() {
  var contentModel = new ContentModel();
  var formData = new FormData();
  formData.append('text', this.get('text'));
  formData.append('pageId', pageId);
  contentModel.create(formData, function(error, result) {
    self.set('text', '');
    if(error) {
      self.set('error', error.error);
    } else {
      self.set('error', false);
      self.set('success', 'The post is saved successfully.');
    }
  });
});
```

模型的使用方式是相同的，除了一个事情——我们发送了一个额外的`pageId`变量。我们需要一些东西来区分在主页上发布的帖子和作为评论发布的帖子。API 仍然不会保存`pageId`。因此，我们必须在`backend/api/content.js`中进行一点更新，如下所示：

```js
form.parse(req, function(err, formData, files) {
  var data = {
    text: formData.text
  };
  if(formData.pageId) {
    data.pageId = formData.pageId;
  }
  …
```

当用户发表评论时，数据库中的记录将包含`pageId`属性。这足以使评论远离主页。另外，从另一个角度来看，这足以仅显示特定页面的评论。

# 显示评论

我们应该更新返回页面作为对象的 API 方法。除了标题和描述，我们还必须呈现一个新的`comments`属性。让我们打开`backend/api/pages.js`并创建一个函数来获取评论：

```js
var getComments = function(pageId, callback) {
  var collection = db.collection('content');
  collection.find({ 
    $query: {
      pageId: pageId
    },
    $orderby: {
      date: -1
    }
  }).toArray(function(err, result) {
    result.forEach(function(value, index, arr) {
      delete arr[index].userId;
      delete arr[index]._id;
    });
    callback(result);
  });
}
```

在前述方法中的关键时刻是形成 MongoDB 查询。这是我们过滤帖子并仅获取与传递的 ID 匹配的页面所做的地方。以下是对`GET`请求的更新代码：

```js
getDatabaseConnection(function(db) {
  var query;
  if(params && params.id) {
    query = { _id: ObjectId(params.id) };
  } else {
    query = {};
  }
  var collection = db.collection('pages');
  var getComments = function(pageId, callback) { ... }
  collection.find({ 
    $query: query,
    $orderby: {
      date: -1
    }
  }).toArray(function(err, result) {
    result.forEach(function(value, index, arr) {
      arr[index].id = value._id;
      delete arr[index]._id;
      delete arr[index].userId;
    });
    if(params.id && result.length > 0) {
      getComments(params.id, function(comments) {
        result[0].comments = comments;
        response({
          pages: result
        }, res);
      });
    } else {
      response({
        pages: result
      }, res);
    }
  });
});
```

有两种类型的响应。第一种是当我们在 URL 中添加了 ID 时使用，换句话说，当我们显示有关页面的信息时。在这种情况下，我们还必须获取评论。在另一种情况下，我们不需要评论，因为我们将仅显示列表。检查`params.id`是否存在足以决定发送哪种类型的响应。

一旦后端开始返回评论，我们将编写代码在浏览器中显示它们。在`frontend/js/controllers/Pages.js`中，我们将设置页面的标题和描述。我们可以直接将`comments`数组传递给模板，并循环遍历帖子，如下所示：

```js
var showPage = function() {
  model.getPage(pageId, function(err, result) {
    if(!err && result.pages.length > 0) {
      var page = result.pages[0];
      self.set('pageTitle', page.title);
      self.set('pageDescription', page.description);
      self.set('comments', page.comments);
    } else {
      self.set('pageTitle', 'Missing page.');
    }
  });
}
showPage();
```

我们将`model.getPage`的调用包装在一个函数中，以便我们可以在添加新评论后再次触发它。

这是模板中需要显示帖子下方的小更新：

```js
{{#each comments:index}}
  <div class="content-item">
    <h2>{{comments[index].userName}}</h2>
    <p>{{comments[index].text}}</p>
  </div>
{{/each}}
```

# 管理附加到特定页面的事件

本章我们将添加的最后一个功能是与一些创建的页面相关联的事件。到目前为止，我们有评论，实际上是保存在`content`集合中的普通帖子。我们将扩展实现并创建另一种类型的帖子。这些帖子仍然具有`pageId`属性，以便它们与动态源的帖子不同。但是，我们将引入一个`eventDate`变量。

在前端，我们需要一个新的 URL。我们应该保持包含页面 ID 的相同模式。这很重要，因为我们希望在正确的位置显示事件，而不希望将它们与页面列表混在一起。以下是新的路由注册：

```js
// frontend/js/app.js
.add('pages/:id/:events', function(params) {
  if(userModel.isLogged()) {
    var p = new Pages({ 
      data: {
        pageId: params.id,
        showEvents: true
      }
    });
    showPage(p);
  } else {
    Router.navigate('login');
  }
})
```

`Pages`控制器的模板肯定需要更改。我们需要支持两种视图。第一个显示一个表单和评论，第二个显示一个表单和事件列表。 `showEvents`变量将告诉我们要呈现哪种变体：

```js
// frontend/tpl/pages.html
{{#if showEvents}}
  <form enctype="multipart/form-data" method="post">
    <a href="/pages/{{pageId}}" class="button m-right right">View comments</a>
    <h3>Add new event</h3>
    ...
  </form>
  {{#each events:index}} … {{/each}}
{{else}}
  <form enctype="multipart/form-data" method="post">
    <a href="/pages/{{pageId}}/events" class="button right">View events</a>
    <h3>Add a comment for this page</h3>
    ...
  </form>
  {{#each comments:index}} … {{/each}}
{{/if}}
```

为了在视图之间切换，我们添加了两个额外的链接。当我们检查评论时，我们将看到**查看事件**，当我们跳转到事件时，我们将看到**查看评论**。

`controllers/Pages.js`文件也需要进行实质性更新。最重要的是，我们需要添加一个来自模板的`add-event`事件处理程序。当用户在新事件表单中按下按钮时触发它。它看起来像这样：

```js
this.on('add-event', function() {
  var contentModel = new ContentModel();
  var formData = new FormData();
  formData.append('text', this.get('text'));
  formData.append('eventDate', this.get('date'));
  formData.append('pageId', pageId);
  contentModel.create(formData, function(error, result) {
    ...
  });
});
```

这类似于添加评论，但是对于额外的`eventDate`属性。它也应该被设置为去`content`集合的对象的属性：

```js
// backend/api/content.js
if(formData.pageId) {
  data.pageId = formData.pageId;
}
if(formData.eventDate) {
  data.eventDate = formData.eventDate;
}
```

同一前端控制器的另一个更改是关于在模板中显示事件（帖子）列表。当我们获取页面的标题和描述时，我们知道我们将收到一个`comments`属性。后端将在一分钟内更新，但我们将假设我们还将有一个`events`属性。因此，我们将简单地将数组发送到模板：

```js
self.set('events', page.events);
```

在后端，我们已经从属于当前页面的`content`集合中获取了记录。问题在于记录现在是评论和事件的混合体。我们在上一节中添加的`getComments`函数可以更改为`getPageItems`，其实现基本上如下所示：

```js
var getPageItems = function(pageId, callback) {
  var collection = db.collection('content');
  collection.find({ 
    $query: {
      pageId: pageId
    },
    $orderby: {
      date: -1
    }
  }).toArray(function(err, result) {
    var comments = [];
    var events = [];
    result.forEach(function(value, index, arr) {
      delete value.userId;
      delete value._id;
      if(value.eventDate) {
        events.push(value);
      } else {
        comments.push(value);                
      }
    });
    events.sort(function(a, b) {
      return a.eventDate > b.eventDate;
    });
    callback(comments, events);
  });
}
```

我们形成了两个不同的`events`和`comments`数组。根据`eventDate`的存在，我们将用记录填充它们。在执行回调之前，我们将按日期对事件进行排序，先显示较早的事件。我们要做的最后一件事是使用`getPageItem`：

```js
getPageItems(params.id, function(comments, events) {
  result[0].comments = comments;
  result[0].events = events;
  …
}
```

# 总结

在本章中，我们扩展了我们的社交网络。现在每个客户都能够创建自己的页面，在那里留下评论或创建与页面相关的活动。我们的架构中添加了许多新组件。我们成功地重用了前几章的代码，这对于保持我们的代码库较小是很好的。

在第九章*标记、分享和点赞*中，我们将讨论帖子的标记、点赞和分享。
