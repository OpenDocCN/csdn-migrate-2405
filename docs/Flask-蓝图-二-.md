# Flask 蓝图（二）

> 原文：[`zh.annas-archive.org/md5/53AA49F14B72D97DBF009B5C4214AEF0`](https://zh.annas-archive.org/md5/53AA49F14B72D97DBF009B5C4214AEF0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Shutterbug，照片流 API

在本章中，我们将构建一个（主要是）基于 JSON 的 API，允许我们查看按时间顺序倒序排列的已添加照片列表——由于 Instagram 和类似的照片分享应用程序，这在近年来变得非常流行。为简单起见，我们将放弃许多这些应用程序通常围绕的社交方面；但是，我们鼓励您将前几章的知识与本章的信息相结合，构建这样的应用程序。

Shutterbug，我们即将开始的最小 API 应用程序，将允许用户通过经过身份验证的基于 JSON 的 API 上传他们选择的照片。

此外，我们将使用 Flask（实际上是 Werkzeug）的较少为人所知的功能之一，创建一个自定义中间件，允许我们拦截传入请求并修改全局应用程序环境，用于非常简单的 API 版本控制。

# 开始

和前几章一样，让我们为这个应用程序创建一个全新的目录和虚拟环境：

```py
$ mkdir -p ~/src/shutterbug && cd ~/src/shutterbug
$ mkvirtualenv shutterbug
$ pip install flask flask-sqlalchemy pytest-flask flask-bcrypt

```

创建以下应用程序布局以开始：

```py
├── application/
│   ├── __init__.py
│   └── resources
│       ├── __init__.py
│       └── photos.py
├── conftest.py
├── database.py
├── run.py
├── settings.py
└── tests/
```

### 注意

这里呈现的应用程序布局与我们在前几章中使用的典型基于 Blueprint 的结构不同；我们将使用典型 Flask-RESTful 应用程序建议的布局，这也适合 Shutterbug 应用程序的简单性。

# 应用程序工厂

在本章中，我们将再次使用应用程序工厂模式；让我们将我们的骨架`create_app`方法添加到`application/__init__.py`模块中，并包括我们的 Flask-SQLAlchemy 数据库初始化：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt

# Initialize the db extension, but without configuring
# it with an application instance.
db = SQLAlchemy()
flask_bcrypt = Bcrypt()

def create_app(config=None):
    app = Flask(__name__)

    if config is not None:
        app.config.from_object(config)

    db.init_app(app)
    flask_bcrypt.init_app(app)

    return app
```

让我们包含我们的基本`run.py`：

```py
from application import create_app

app = create_app()
app.run()
```

这应该使我们能够使用内置的 Werkzeug 应用程序服务器运行应用程序，代码如下：

```py
$ python run.py

```

# 插曲——Werkzeug

我们在本书的过程中已经几次谈到了 Werkzeug，但我们并没有真正解释它是什么，为什么我们使用它，或者它为什么有用。要理解 Werkzeug，我们首先需要知道它存在的原因。为此，我们需要了解 Python Web 服务器网关接口规范的起源，通常缩写为 WSGI。

如今，选择 Python Web 应用程序框架相对来说是一个相对简单的偏好问题：大多数开发人员根据以前的经验、必要性（例如，设计为异步请求处理的 Tornado）或其他可量化或不可量化的标准选择框架。

然而，几年前，应用程序框架的选择影响了您可以使用的 Web 服务器。由于当时所有 Python Web 应用程序框架以稍微不同的方式实现了它们自己的 HTTP 请求处理，它们通常只与 Web 服务器的子集兼容。开发人员厌倦了这种有点不方便的现状，提出了通过一个共同规范 WSGI 统一 Web 服务器与 Python 应用程序的交互的提案。

一旦建立了 WSGI 规范，所有主要框架都采用了它。此外，还创建了一些所谓的*实用*工具；它们的唯一目的是将官方 WSGI 规范与更健壮的中间 API 进行桥接，这有助于开发现代 Web 应用程序。此外，这些实用程序库可以作为更完整和健壮的应用程序框架的基础。

您现在可能已经猜到，Werkzeug 是这些 WSGI 实用程序库之一。当与模板语言 Jinja 和一些方便的默认配置、路由和其他基本 Web 应用程序必需品结合使用时，我们就有了 Flask。

Flask 是我们在本书中主要处理的内容，但是从 Werkzeug 中抽象出来的大部分工作都包含在其中。虽然它很大程度上不被注意到，但是可以直接与它交互，以拦截和修改请求的部分，然后 Flask 有机会处理它。在本章中，当我们为 JSON API 请求实现自定义 Werkzeug 中间件时，我们将探索其中的一些可能性。

# 使用 Flask-RESTful 创建简单的 API

使用 Flask 的一个巨大乐趣是它提供了看似无限的可扩展性和可组合性。由于它是一个相当薄的层，位于 Werkzeug 和 Jinja 之上，因此在约束方面对开发人员的要求并不多。

由于这种灵活性，我们可以利用 Flask-RESTful 等扩展，使得创建基于 JSON 的 API 变得轻松愉快。首先，让我们安装这个包：

```py
$ pip install flask-restful

```

接下来，让我们以通常的方式在我们的应用工厂中初始化这个扩展：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.bcrypt import Bcrypt
from flask.ext.restful import Api

# ………
api = Api()

def create_app(config=None):
    app = Flask(__name__)

    if config is not None:
        app.config.from_object(config)

    db.init_app(app)
    flask_bcrypt.init_app(app)

 api.init_app(app)

    return app
```

Flask-RESTful 扩展的主要构建块是资源的概念。资源在本质上是一个带有一些非常有用的默认设置的`Flask`方法视图，用于内容类型协商。如果直到现在你还没有遇到过 Flask 中`MethodView`的概念，不要担心！它们非常简单，并且通过允许您在类上定义方法，直接映射到基本的 HTTP 动词：`GET`、`PUT`、`POST`、`PATCH`和`DELETE`，为您提供了一个相对简单的接口来分离 RESTful 资源。Flask-RESTful 资源又扩展了`MethodView`类，因此允许使用相同的基于动词的路由处理风格。

更具体地说，这意味着 Flask-RESTful API 名词可以以以下方式编写。我们将首先将我们的照片资源视图处理程序添加到`application/resources/photos.py`中：

```py
class SinglePhoto(Resource):

    def get(self, photo_id):
        """Handling of GET requests."""
        pass

    def delete(self, photo_id):
        """Handling of DELETE requests."""
        pass

class ListPhoto(Resource):

    def get(self):
        """Handling of GET requests."""
        pass

    def post(self):
        """Handling of POST requests."""
        pass
```

### 注意

在前面的两个`Resource`子类中，我们定义了可以处理的 HTTP 动词的一个子集；我们并不需要为所有可能的动词定义处理程序。例如，如果我们的应用程序接收到一个 PATCH 请求到前面的资源中的一个，Flask 会返回 HTTP/1.1 405 Method Not Allowed。

然后，我们将这些视图处理程序导入到我们的应用工厂中，在`application/__init__.py`中，以便将这两个类绑定到我们的 Flask-RESTful API 对象：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.restful import Api
from flask.ext.bcrypt import Bcrypt

# Initialize the db extension, but without configuring
# it with an application instance.
db = SQLAlchemy()
api = Api()
flask_bcrypt = Bcrypt()

def create_app(config=None):
    app = Flask(__name__)

    if config is not None:
        app.config.from_object(config)

    db.init_app(app)
    flask_bcrypt.init_app(app)

 from .resources.photos import SinglePhoto, ListPhoto
 api.add_resource(ListPhoto, '/photos')
 api.add_resource(SinglePhoto, '/photos/<int:photo_id>')

    api.init_app(app)

    return app
```

### 注意

请注意，在调用`api.init_app(app)`之前，我们已经将资源绑定到了 API 对象。如果我们在绑定资源之前初始化，路由将不存在于 Flask 应用程序对象上。

我们可以通过启动交互式 Python 会话并检查 Flask 应用程序的`url_map`属性来确认我们定义的路由是否映射到应用程序对象。

### 提示

从应用程序文件夹的父文件夹开始会话，以便正确设置`PYTHONPATH`：

```py
In [1]: from application import create_app
In [2]: app = create_app()
In [3]: app.url_map
Out[3]:
Map([<Rule '/photos' (HEAD, POST, OPTIONS, GET) -> listphoto>,
 <Rule '/photos/<photo_id>' (HEAD, DELETE, OPTIONS, GET) -> singlephoto>,
 <Rule '/static/<filename>' (HEAD, OPTIONS, GET) -> static>])

```

前面的输出列出了一个 Werkzeug `Map`对象，其中包含三个`Rule`对象，每个对象列出了一个 URI，对该 URI 有效的 HTTP 动词，以及一个标准化标识符（视图处理程序可以是函数，也可以是`MethodView`子类，还有其他几个选项），指示将调用哪个视图处理程序。

### 注意

Flask 将自动处理所有已定义端点的 HEAD 和 OPTIONS 动词，并为静态文件处理添加一个默认的`/static/<filename>`路由。如果需要，可以通过在应用程序工厂中对`Flask`对象初始化设置`static_folder`参数为`None`来禁用此默认静态路由：

```py
 app = Flask(__name__, static_folder=None)

```

让我们对我们的骨架用户视图资源处理程序做同样的事情，我们将在`application/resources/users.py`中声明：

```py
from flask.ext.restful import Resource

class SingleUser(Resource):

    def get(self, user_id):
        """Handling of GET requests."""
        pass

class CreateUser(Resource):

    def post(self):
        """Handling of POST requests."""
        pass
```

### 注意

请注意，我们本可以将`post`方法处理程序放在`SingleUser`资源定义中，但相反，我们将其拆分为自己的资源。这并非绝对必要，但会使我们的应用程序更容易跟踪，并且只会花费我们额外的几行代码。

与我们在照片视图中所做的类似，我们将把它们添加到我们的 Flask-RESTful API 对象中的应用工厂中：

```py
def create_app(config=None):

    # …

    from .resources.photos import SinglePhoto, ListPhoto
    from .resources.users import SingleUser, CreateUser

    api.add_resource(ListPhoto, '/photos')
    api.add_resource(SinglePhoto, '/photos/<int:photo_id>')
    api.add_resource(SingleUser, '/users/<int:user_id>')
    api.add_resource(CreateUser, '/users')

    api.init_app(app)
    return app
```

## 使用混合属性改进密码处理

我们的`User`模型将与我们在上一章中使用的模型非常相似，并且将使用类属性`getter`/`setter`来处理`password`属性。这将确保无论我们是在对象创建时设置值还是手动设置已创建对象的属性，都能一致地应用 Bcrypt 密钥派生函数到原始用户密码。

这包括使用 SQLAlchemy 的`hybrid_property`描述符，它允许我们定义在类级别访问时（例如`User.password`，我们希望返回用户模型的密码字段的 SQL 表达式）与实例级别访问时（例如`User().password`，我们希望返回用户对象的实际加密密码字符串而不是 SQL 表达式）行为不同的属性。

我们将把密码类属性定义为`_password`，这将确保我们避免任何不愉快的属性/方法名称冲突，以便我们可以正确地定义混合的`getter`和`setter`方法。

由于我们的应用在数据建模方面相对简单，我们可以在`application/models.py`中使用单个模块来处理我们的模型：

```py
from application import db, flask_bcrypt
from sqlalchemy.ext.hybrid import hybrid_property

import datetime

class User(db.Model):
    """SQLAlchemy User model."""

    # The primary key for each user record.
    id = db.Column(db.Integer, primary_key=True)

    # The unique email for each user record.
    email = db.Column(db.String(255), unique=True, nullable=False)

    # The unique username for each record.
    username = db.Column(db.String(40), unique=True, nullable=False)

 # The bcrypt'ed user password
 _password = db.Column('password', db.String(60), nullable=False)

    #  The date/time that the user account was created on.
    created_on = db.Column(db.DateTime,
       default=datetime.datetime.utcnow)

    def __repr__(self):
        return '<User %r>' % self.username

 @hybrid_property
 def password(self):
 """The bcrypt'ed password of the given user."""

 return self._password

 @password.setter
 def password(self, password):
 """Bcrypt the password on assignment."""

        self._password = flask_bcrypt.generate_password_hash(password)
```

在同一个模块中，我们可以声明我们的`Photo`模型，它将负责维护与图像相关的所有元数据，但不包括图像本身：

```py
class Photo(db.Model):
    """SQLAlchemy Photo model."""

    # The unique primary key for each photo created.
    id = db.Column(db.Integer, primary_key=True)

    # The free-form text-based comment of each photo.
    comment = db.Column(db.Text())

    # Path to photo on local disk
    path = db.Column(db.String(255), nullable=False)

    #  The date/time that the photo was created on.
    created_on = db.Column(db.DateTime(),
        default=datetime.datetime.utcnow, index=True)

    # The user ID that created this photo.
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))

    # The attribute reference for accessing photos posted by this user.
    user = db.relationship('User', backref=db.backref('photos',
        lazy='dynamic'))

    def __repr__(self):
        return '<Photo %r>' % self.comment
```

## API 身份验证

对于大多数应用程序和 API，身份验证和授权的概念对于非平凡操作至关重要：

+   **身份验证**：这断言所提供的凭据的真实性，并确保它们属于已知实体；简单来说，这意味着确保提供给应用程序的用户名和密码属于有效用户。一旦验证，应用程序就会假定使用这些凭据执行的请求是代表给定用户执行的。

+   **授权**：这是经过身份验证的实体在应用程序范围内的可允许操作。在大多数情况下，授权预设了已经进行了预先身份验证步骤。实体可能已经经过身份验证，但没有被授权访问某些资源：如果您在 ATM 机上输入您的卡和 PIN 码（因此进行了身份验证），您可以查看自己的账户，但尝试查看另一个人的账户将会（希望！）导致拒绝，因为您没有被授权访问那些信息。

对于 Shutterbug，我们只关心身份验证。如果我们要添加各种功能，比如能够创建可以访问共享照片池的私人用户组，那么就需要系统化的授权来确定哪些用户可以访问哪些资源的子集。

### 身份验证协议

许多开发人员可能已经熟悉了几种身份验证协议：通常的标识符/密码组合是现有大多数网络应用程序的标准，而 OAuth 是许多现代 API 的标准（例如 Twitter、Facebook、GitHub 等）。对于我们自己的应用程序，我们将使用非常简单的 HTTP 基本身份验证协议。

虽然 HTTP 基本身份验证并不是最灵活也不是最安全的（实际上它根本不提供任何加密），但对于简单的应用程序、演示和原型 API 来说，实施这种协议是合理的。在 Twitter 早期，这实际上是您可以使用的唯一方法来验证其 API！此外，在通过 HTTPS 传输数据时，我们应该在任何生产级环境中这样做，我们可以确保包含用户标识和密码的明文请求受到加密，以防止任何可能监听的恶意第三方。

HTTP 基本身份验证的实现并不是过于复杂的，但绝对是我们可以转嫁给扩展的东西。让我们继续将 Flask-HTTPAuth 安装到我们的环境中，这包括创建扩展的实例：

```py
$ pip install flask-httpauth

```

并在我们的`application/__init__.py`中设置扩展：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.restful import Api
from flask.ext.bcrypt import Bcrypt
from flask.ext.httpauth import HTTPBasicAuth

# …

api = Api()
flask_bcrypt = Bcrypt()
auth = HTTPBasicAuth()

def create_app(config=None):
    # …

 import authentication

    api.add_resource(ListPhoto, '/photos')
    api.add_resource(SinglePhoto, '/photos/<int:photo_id>')

    # …
```

Flask-HTTPAuth 包括各种装饰器来声明处理程序/回调，以执行身份验证过程的各个部分。我们将实现一个可以最大程度控制身份验证方式的处理程序，并将其放在`application/authentication.py`中的新模块中。除了验证凭据外，我们还将在成功验证时将 SQLAlchemy 用户对象附加到 Flask 上下文本地`g`，以便我们可以在请求处理和响应生成的其他部分中利用这些数据：

```py
import sqlalchemy
from . import auth, flask_bcrypt
from .models import User
from flask import g

@auth.verify_password
def verify_password(username, password):
    """Verify a username/hashed password tuple."""

    try:
        user = User.query.filter_by(username=username).one()
    except sqlalchemy.orm.exc.NoResultFound:
        # We found no username that matched
        return False

    # Perform password hash comparison in time-constant manner.
    verified = flask_bcrypt.check_password_hash(user.password,
        password)

 if verified is True:
 g.current_user = user

    return verified
```

`auth.verify_password`装饰器允许我们指定一个接受用户名和密码的函数，这两者都从发送请求的 Authorization 头中提取出来。然后，我们将使用这些信息来查询具有相同用户名的用户的数据库，并在成功找到一个用户后，我们将确保提供的密码散列到与我们为该用户存储的相同值。如果密码不匹配或用户名不存在，我们将返回 False，Flask-HTTPAuth 将向请求客户端返回 401 未经授权的标头。

现在，要实际使用 HTTP 基本身份验证，我们需要将`auth.login_required`装饰器添加到需要身份验证的视图处理程序中。我们知道除了创建新用户之外，所有用户操作都需要经过身份验证的请求，所以让我们实现这一点：

```py
from flask.ext.restful import Resource
from application import auth

class SingleUser(Resource):

 method_decorators = [auth.login_required]

    def get(self, user_id):
        """Handling of GET requests."""
        pass

    # …
```

### 注意

由于 Resource 对象的方法的 self 参数指的是 Resource 实例而不是方法，我们不能在视图的各个方法上使用常规视图装饰器。相反，我们必须使用`method_decorators`类属性，它将按顺序应用已声明的函数到已调用的视图方法上，以处理请求。

## 获取用户

现在我们已经弄清楚了应用程序的身份验证部分，让我们实现 API 端点以创建新用户和获取现有用户数据。我们可以如下完善`SingleUser`资源类的`get()`方法：

```py
from flask.ext.restful import abort

# …

def get(self, user_id):
    """Handling of GET requests."""

    if g.current_user.id != user_id:
        # A user may only access their own user data.
        abort(403, message="You have insufficient permissions"
            " to access this resource.")

    # We could simply use the `current_user`,
    # but the SQLAlchemy identity map makes this a virtual
    # no-op and alos allows for future expansion
    # when users may access information of other users
    try:
        user = User.query.filter(User.id == user_id).one()
    except sqlalchemy.orm.exc.NoResultFound:
        abort(404, message="No such user exists!")

    data = dict(
        id=user.id,
        username=user.username,
        email=user.email,
        created_on=user.created_on)

    return data, 200
```

在前面的方法中发生了很多新的事情，让我们来分解一下。首先，我们将检查请求中指定的`user_id`（例如，`GET /users/1`）是否与当前经过身份验证的用户相同：

```py
if g.current_user.id != user_id:
        # A user may only access their own user data.
        abort(403, message="You have insufficient permissions"
            " to access this resource.")
```

虽然目前这可能看起来有些多余，但它在允许将来更简单地修改授权方案的同时，还扮演了遵循更符合 RESTful 方法的双重角色。在这里，资源是由其 URI 唯一指定的，部分由用户对象的唯一主键标识符构成。

经过授权检查后，我们将通过查询传递为命名 URI 参数的`user_id`参数，从数据库中提取相关用户：

```py
try:
    user = User.query.filter(User.id == user_id).one()
except sqlalchemy.orm.exc.NoResultFound:
    abort(404, message="No such user exists!")
```

如果找不到这样的用户，那么我们将使用 HTTP 404 Not Found 中止当前请求，并指定消息以使非 20x 响应的原因更清晰。

最后，我们将构建一个用户数据的字典，作为响应返回。我们显然不希望返回散列密码或其他敏感信息，因此我们将明确指定我们希望在响应中序列化的字段：

```py
data = dict(id=user.id, username=user.username, email=user.email,
            created_on=user.created_on)

    return data, 200
```

由于 Flask-RESTful，我们不需要显式地将我们的字典转换为 JSON 字符串：响应表示默认为`application/json`。然而，有一个小问题：Flask-RESTful 使用的默认 JSON 编码器不知道如何将 Python `datetime`对象转换为它们的 RFC822 字符串表示。这可以通过指定`application/json` MIME 类型表示处理程序并确保我们使用`flask.json`编码器而不是 Python 标准库中的默认`json`模块来解决。

我们可以在`application/__init__.py`模块中添加以下内容：

```py
from flask import Flask, json, make_response
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.restful import Api
from flask.ext.bcrypt import Bcrypt
from flask.ext.httpauth import HTTPBasicAuth

# …

db = SQLAlchemy()
# …

@api.representation('application/json')
def output_json(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {})
    return resp
```

### 创建新用户

从 API 中获取现有用户的类比当然是创建新用户。而典型的 Web 应用程序通过填写各种表单字段来完成这一过程，通过我们的 API 创建新用户需要将信息通过 POST 请求提交到服务器进行验证，然后将新用户插入数据库。这些步骤的实现应该放在我们的`CreateUser`资源的`post()`方法中：

```py
class CreateUser(Resource):

    def post(self):
        """Create a new user."""

        data = request.json
        user = User(**data)

        db.session.add(user)

        try:
            db.session.commit()
        except sqlalchemy.exc.IntegrityError:
            abort(409, message="User already exists!")

        data = dict(id=user.id, username=user.username, email=user.email, created_on=user.created_on)

        return data, 201, {'Location': url_for( 'singleuser', user_id=user.id, _external=True)}
```

### 注意

如果请求的内容类型设置为`application/json`，则`request.json`文件将填充 POST 数据。

在前面的方法实现中没有什么太意外的：我们从`request.json`中获取了 POST 数据，创建了一个`User`对象（非常不安全！您可以在本章稍后看到更好的替代方法），尝试将其添加到数据库中并捕获异常，如果同一用户名或电子邮件地址的用户已经存在，然后序列化一个 HTTP 201 Created 响应，其中包含新创建用户的 URI 的`Location`头。

#### 输入验证

虽然 Flask 包含一个相对简单的方式来通过`flask.request`代理对象访问 POST 的数据，但它不包含任何功能来验证数据是否按我们期望的格式进行格式化。这没关系！Flask 试图尽可能地与数据存储和操作无关，将这些工作留给开发人员。幸运的是，Flask-RESTful 包括`reqparse`模块，可以用于数据验证，其使用在精神上与用于 CLI 参数解析的流行`argparse`库非常相似。

我们将在`application/resources/users.py`模块中设置我们的新用户数据解析器/验证器，并声明我们的字段及其类型以及在 POST 数据中是否为有效请求所需的字段：

```py
from flask.ext.restful import Resource, abort, reqparse, url_for

# …

new_user_parser = reqparse.RequestParser()
new_user_parser.add_argument('username', type=str, required=True)
new_user_parser.add_argument('email', type=str, required=True)
new_user_parser.add_argument('password', type=str, required=True)
```

现在我们在模块中设置了`new_user_parser`，我们可以修改`CreateUser.post()`方法来使用它：

```py
def post(self):
    """Handling of POST requests."""

    data = new_user_parser.parse_args(strict=True)
    user = User(**data)

    db.session.add(user)

    # …
```

`new_user_parser.parse_args(strict=True)`的调用将尝试匹配我们之前通过`add_argument`定义的字段的声明类型和要求，并且在请求中存在任何字段未通过验证或者有额外字段没有明确考虑到的情况下，将内部调用`abort()`并返回 HTTP 400 错误（感谢`strict=True`选项）。

使用`reqparse`来验证 POST 的数据可能比我们之前直接赋值更加繁琐，但是安全性更高。通过直接赋值技术，恶意用户可能会发送任意数据，希望覆盖他们不应该访问的字段。例如，我们的数据库可能包含内部字段`subscription_exipires_on datetime`，一个恶意用户可能会提交一个包含这个字段值设置为遥远未来的 POST 请求。这绝对是我们想要避免的事情！

### API 测试

让我们应用一些我们在之前章节中学到的关于使用`pytest`进行功能和集成测试的知识。

我们的第一步（在必要的 pip 安装`pytest-flask`之后）是像我们在之前的章节中所做的那样添加一个`conftest.py`文件，它是我们`application/`文件夹的同级文件夹。

```py
import pytest
import os
from application import create_app, db as database

DB_LOCATION = '/tmp/test_shutterbug.db'

@pytest.fixture(scope='session')
def app():
    app = create_app(config='test_settings')
    return app

@pytest.fixture(scope='function')
def db(app, request):
    """Session-wide test database."""
    if os.path.exists(DB_LOCATION):
        os.unlink(DB_LOCATION)

    database.app = app
    database.create_all()

    def teardown():
        database.drop_all()
        os.unlink(DB_LOCATION)

    request.addfinalizer(teardown)
    return database

@pytest.fixture(scope='function')
def session(db, request):

    session = db.create_scoped_session()
    db.session = session

    def teardown():
        session.remove()

    request.addfinalizer(teardown)
    return session
```

前面的`conftest.py`文件包含了我们编写 API 测试所需的基本测试装置；这里不应该有任何意外。然后我们将添加我们的`test_settings.py`文件，它是新创建的`conftest.py`的同级文件，并填充它与我们想要在测试运行中使用的应用程序配置值：

```py
SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/test_shutterbug.db'
SECRET_KEY = b"\x98\x9e\xbaP'D\x03\xf5\x91u5G\x1f"
DEBUG = True
UPLOAD_FOLDER = '/tmp/'
TESTING = True

```

一旦这些都就位，我们就可以开始在`tests/test_users.py`中编写我们的测试函数和断言。我们的第一个测试将确保我们可以通过 API 创建一个新用户，并且新创建的资源的 URI 将在`Location`标头中返回给我们：

```py
from application.models import User
from flask import json
import base64

def test_create_new_user(db, session, client):
    """Attempt to create a basic user."""

    data = {'username': 'you', 'email': 'you@example.com',
            'password': 'foobar'}

    response = client.post('/users', data=data)
    assert response.status_code == 201
    assert 'Location' in response.headers

    user = User.query.filter(User.username == data['username']).one()

    assert '/users/{}'.format(user.id) in response.headers['Location']
```

一旦我们确定可以创建用户，下一个逻辑步骤是测试如果客户端尝试使用无效或缺少的参数创建用户，则会返回错误：

```py
def test_create_invalid_user(db, session, client):
    """Try to create a user with invalid/missing information."""

    data = {'email': 'you@example.com'}
    response = client.post('/users', data=data)

    assert response.status_code == 400
    assert 'message' in response.json
    assert 'username' in response.json['message']
```

作为对我们的 HTTP 基本身份验证实现的健全性检查，让我们还添加一个测试来获取单个用户记录，这需要对请求进行身份验证：

```py
def test_get_single_user_authenticated(db, session, client):
    """Attempt to fetch a user."""

    data = {'username': 'authed', 'email': 'authed@example.com',
            'password': 'foobar'}
    user = User(**data)
    session.add(user)
    session.commit()

    creds = base64.b64encode(
        b'{0}:{1}'.format(
            user.username, data['password'])).decode('utf-8')

    response = client.get('/users/{}'.format(user.id),
        headers={'Authorization': 'Basic ' + creds})

    assert response.status_code == 200
    assert json.loads(response.get_data())['id'] == user.id
```

未经身份验证的请求获取单个用户记录的相关测试如下：

```py
def test_get_single_user_unauthenticated(db, session, client):
    data = {'username': 'authed', 'email': 'authed@example.com',
            'password': 'foobar'}
    user = User(**data)
    session.add(user)
    session.commit()

    response = client.get('/users/{}'.format(user.id))
    assert response.status_code == 401
```

我们还可以测试我们非常简单的授权实现是否按预期运行（回想一下，我们只允许经过身份验证的用户查看自己的信息，而不是系统中其他任何用户的信息。）通过创建两个用户并尝试通过经过身份验证的请求访问彼此的数据来进行测试：

```py
def test_get_single_user_unauthorized(db, session, client):

    alice_data = {'username': 'alice', 'email': 'alice@example.com',
            'password': 'foobar'}
    bob_data = {'username': 'bob', 'email': 'bob@example.com',
            'password': 'foobar'}
    alice = User(**alice_data)
    bob = User(**bob_data)

    session.add(alice)
    session.add(bob)

    session.commit()

    alice_creds = base64.b64encode(b'{0}:{1}'.format(
        alice.username, alice_data['password'])).decode('utf-8')

    bob_creds = base64.b64encode(b'{0}:{1}'.format(
        bob.username, bob_data['password'])).decode('utf-8')

    response = client.get('/users/{}'.format(alice.id),
        headers={'Authorization': 'Basic ' + bob_creds})

    assert response.status_code == 403

    response = client.get('/users/{}'.format(bob.id),
        headers={'Authorization': 'Basic ' + alice_creds})

    assert response.status_code == 403
```

## 插曲 - Werkzeug 中间件

对于某些任务，我们有时需要在将请求路由到处理程序函数或方法之前修改传入请求数据和/或环境的能力。在许多情况下，实现这一点的最简单方法是使用`before_request`装饰器注册一个函数；这通常用于在`g`对象上设置`request-global`值或创建数据库连接。

虽然这应该足够涵盖大部分最常见的用例，但有时在 Flask 应用程序对象下方（构造请求代理对象时）但在 HTTP 服务器上方更方便。为此，我们有中间件的概念。此外，一个正确编写的中间件将在其他兼容的 WSGI 实现中可移植；除了应用程序特定的怪癖外，没有什么能阻止您在我们当前的 Flask 应用程序中使用最初为 Django 应用程序编写的中间件。

中间件相对简单：它们本质上是任何可调用的东西（类、实例、函数或方法，可以以类似于函数的方式调用），以便返回正确的响应格式，以便链中的其他中间件可以正确调用。

对于我们当前基于 API 的应用程序有用的中间件的一个例子是，它允许我们从请求 URI 中提取可选的版本号，并将此信息存储在环境中，以便在请求处理过程中的各个点使用。例如，对`/v0.1a/users/2`的请求将被路由到`/users/2`的处理程序，并且`v0.1a`将通过`request.environ['API_VERSION']`在 Flask 应用程序本身中可访问。

在`application/middlewares.py`中的新模块中，我们可以实现如下：

```py
import re

version_pattern = re.compile(r"/v(?P<version>[0-9a-z\-\+\.]+)", re.IGNORECASE)

class VersionedAPIMiddleware(object):
    """

    The line wrapping here is a bit off, but it's not critical.

    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')

        match = version_pattern.match(path)

        if match:
            environ['API_VERSION'] = match.group(1)
            environ['PATH_INFO'] = re.sub(version_pattern, '', path,
                count=1)
        else:
            environ['API_VERSION'] = None

        return self.app(environ, start_response)
```

我们将在工厂中将此中间件绑定到应用程序对象：

```py
# …

from .middlewares import VersionedAPIMiddleware

# …
def create_app(config=None):
    app = Flask(__name__, static_folder=None)
 app.wsgi_app = VersionedAPIMiddleware(app.wsgi_app)

    # …

    api.init_app(app)
    return app
```

### 注意

在添加多个 WSGI 中间件时，它们的顺序有时很重要。在添加可能修改 WSGI 环境的中间件时，请务必记住这一点。

一旦绑定，中间件将在 Flask 接收请求之前插入请求处理，即使我们明确实例化了一个 Flask 应用程序对象。在应用程序中访问`API_VERSION`值只是简单地查询绑定到请求环境的键：

```py
from flask import request
# …
# …
if request.environ['API_VERSION'] > 2:
    # Handle this differently
else:
    # Handle it normally
```

API 版本号的解析也可以扩展到检查 HTTP 头（自定义或其他），除了我们在此提供的基于 URL 的版本提取；可以为任一方便性提出论点。

### 回到 Shutterbug - 上传照片

现在我们有了一个最小但功能齐全的 API 来创建和获取用户，我们需要一个类似的 API 来上传照片。首先，我们将使用与之前相同的资源模式，另外定义一个`RequestParser`实例来验证有关照片的用户提交数据：

```py
from flask.ext.restful import Resource, reqparse
from flask import current_app, request, g, url_for
from application import auth, db, models
import uuid
import os
import werkzeug

new_photo_parser = reqparse.RequestParser()
new_photo_parser.add_argument('comment', type=str,
    required=False)
new_photo_parser.add_argument('photo',
    type=werkzeug.datastructures.FileStorage,
    required=True, location='files')

class UploadPhoto(Resource):

    method_decorators = [auth.login_required]

    def post(self):
        """Adds a new photo via form-encoded POST data."""

        data = new_photo_parser.parse_args(strict=True)

        # Save our file to the filesystem first
        f = request.files['photo']

        extension = os.path.splitext(f.filename)[1]
        name = werkzeug.utils.secure_filename(
            str(uuid.uuid4()) + extension)
        path = os.path.join(
            current_app.config['UPLOAD_FOLDER'], name)

        f.save(path)

        data['user_id'] = g.current_user.id
        data['path'] = path

        # Get rid of the binary data that was sent; we've already
        # saved this to disk.
        del data['photo']

        # Add a new Photo entry to the database once we have
        # successfully saved the file to the filesystem above.
        photo = models.Photo(**data)
        db.session.add(photo)
        db.session.commit()

        data = dict(id=photo.id,
            path=photo.path, comment=photo.comment,
            created_on=photo.created_on)

        return data, 201, {'Location': url_for('singlephoto',
            photo_id=photo.id, _external=True)}
```

请注意，在前面的`UploadPhoto`资源中，我们正在访问`request.files`以提取通过 POST 发送到端点的二进制数据。然后，我们解析出扩展名，生成一个唯一的随机字符串作为文件名，最后将文件保存到我们在应用程序配置中配置的已知`UPLOAD_FOLDER`中。

### 注意

请注意，我们使用`werkzeug.utils.secure_filename`函数来净化上传图像的扩展名，以确保它不容易受到路径遍历或其他基于文件系统的利用的影响，这在处理用户上传的二进制数据时很常见。

在接受将持久化到文件系统的不受信任数据时，应该执行许多其他验证和净化步骤（例如，确保文件的 MIME 类型与实际上传的扩展名和二进制数据匹配，限制图像的大小/尺寸），但出于简洁起见，我们省略了它们。数据验证技术和最佳实践本身就可以填满一整本书。

我们最终将图像持久化到的本地文件系统路径与可能陪伴照片上传的可选评论一起添加到我们的照片 SQLAlchemy 记录中。然后将整个记录添加到会话中，并提交到数据库，然后在标头中返回新创建的资产的位置的 201 响应。在这里，我们避免处理一些简单的错误条件，以便我们可以专注于所呈现的核心概念，并将它们的实现留给读者作为练习。

在尝试任何新的照片上传功能之前，请确保将资源绑定到我们应用程序工厂中的 API 对象：

```py
def create_app(config=None):
    # …

 from .resources.photos import (SinglePhoto, ListPhoto,
 UploadPhoto)
 # …

    api.add_resource(ListPhoto, '/photos')
 api.add_resource(UploadPhoto, '/photos')
    api.add_resource(SinglePhoto, '/photos/<int:photo_id>')
    api.add_resource(SingleUser, '/users/<int:user_id>')
    api.add_resource(CreateUser, '/users')

    # …
```

#### 分布式系统中的文件上传

我们已经大大简化了现代 Web 应用程序中文件上传的处理。当然，简单通常有一些缺点。

其中最明显的是，在前面的实现中，我们受限于单个应用服务器。如果存在多个应用服务器，则确保上传的文件在这些多个服务器之间保持同步将成为一个重大的运营问题。虽然有许多解决这个特定问题的解决方案（例如，分布式文件系统协议，如 NFS，将资产上传到远程存储，如 Amazon 的**简单存储服务**（**S3**）等），但它们都需要额外的思考和考虑来评估它们的利弊以及对应用程序结构的重大更改。

### 测试照片上传

由于我们正在进行一些测试，让我们通过在`tests/test_photos.py`中编写一些简单的测试来保持这个过程。首先，让我们尝试使用未经身份验证的请求上传一些二进制数据：

```py
import io
import base64
from application.models import User, Photo

def test_unauthenticated_form_upload_of_simulated_file(session, client):
    """Ensure that we can't upload a file via un-authed form POST."""

    data = dict(
        file=(io.BytesIO(b'A test file.'), 'test.png'))

    response = client.post('/photos', data=data)
    assert response.status_code == 401
```

然后，让我们通过正确验证的请求来检查明显的成功路径：

```py
def test_authenticated_form_upload_of_simulated_file(session, client):
    """Upload photo via POST data with authenticated user."""

    password = 'foobar'
    user = User(username='you', email='you@example.com',
        password=password)

    session.add(user)

    data = dict(
        photo=(io.BytesIO(b'A test file.'), 'test.png'))

    creds = base64.b64encode(
        b'{0}:{1}'.format(user.username, password)).decode('utf-8')

    response = client.post('/photos', data=data,
        headers={'Authorization': 'Basic ' + creds})

    assert response.status_code == 201
    assert 'Location' in response.headers

    photos = Photo.query.all()
    assert len(photos) == 1

    assert ('/photos/{}'.format(photos[0].id) in
        response.headers['Location'])
```

最后，让我们确保在提交（可选）评论时，它被持久化到数据库中：

```py
def test_upload_photo_with_comment(session, client):
    """Adds a photo with a comment."""

    password = 'foobar'
    user = User(username='you', email='you@example.com',
    password=password)

    session.add(user)

    data = dict(
        photo=(io.BytesIO(b'A photo with a comment.'),
        'new_photo.png'),
        comment='What an inspiring photo!')

    creds = base64.b64encode(
        b'{0}:{1}'.format(
            user.username, password)).decode('utf-8')

    response = client.post('/photos', data=data,
        headers={'Authorization': 'Basic ' + creds})

    assert response.status_code == 201
    assert 'Location' in response.headers

    photos = Photo.query.all()
    assert len(photos) == 1

    photo = photos[0]
    assert photo.comment == data['comment']
```

## 获取用户的照片

除了上传照片的能力之外，Shutterbug 应用程序的核心在于能够以逆向时间顺序获取经过认证用户上传的照片列表。为此，我们将完善`application/resources/photos.py`中的`ListPhoto`资源。由于我们希望能够对返回的照片列表进行分页，我们还将创建一个新的`RequestParser`实例来处理常见的页面/限制查询参数。此外，我们将使用 Flask-RESTful 的编组功能来序列化从 SQLAlchemy 返回的`Photo`对象，以便将它们转换为 JSON 并发送到请求的客户端。

### 注意

**编组**是 Web 应用程序（以及大多数其他类型的应用程序！）经常做的事情，即使你可能从未听说过这个词。简单地说，你将数据转换成更适合传输的格式，比如 Python 字典或列表，然后将其转换为 JSON 格式，并通过 HTTP 传输给发出请求的客户端。

```py
from flask.ext.restful import Resource, reqparse, fields, marshal
photos_parser = reqparse.RequestParser()
photos_parser.add_argument('page', type=int, required=False,
        default=1, location='args')
photos_parser.add_argument('limit', type=int, required=False,
        default=10, location='args')

photo_fields = {
    'path': fields.String,
    'comment': fields.String,
    'created_on': fields.DateTime(dt_format='rfc822'),
}

class ListPhoto(Resource):

    method_decorators = [auth.login_required]

    def get(self):
        """Get reverse chronological list of photos for the
        currently authenticated user."""

        data = photos_parser.parse_args(strict=True)
        offset = (data['page'] - 1) * data['limit']
        photos = g.current_user.photos.order_by(
            models.Photo.created_on.desc()).limit(
            data['limit']).offset(offset)

        return marshal(list(photos), photo_fields), 200
```

请注意，在前面的`ListPhoto.get()`处理程序中，我们根据请求参数提供的页面和限制计算了一个偏移值。页面和限制与我们的数据集大小无关，并且易于理解，适用于消费 API 的客户端。SQLAlchemy（以及大多数数据库 API）只理解偏移和限制。转换公式是众所周知的，并适用于任何排序的数据集。

# 摘要

本章的开始有些不同于之前的章节。我们的目标是创建一个基于 JSON 的 API，而不是一个典型的生成 HTML 并消费提交的 HTML 表单数据的 Web 应用程序。

我们首先稍微偏离一下，解释了 Werkzeug 的存在和用处，然后使用名为 Flask-RESTful 的 Flask 扩展创建了一个基本的 API。接下来，我们确保我们的 API 可以通过要求身份验证来保护，并解释了身份验证和授权之间微妙但根本的区别。

然后，我们看了如何实现 API 的验证规则，以确保客户端可以创建有效的资源（例如新用户、上传照片等）。我们使用`py.test`框架实现了几个功能和集成级别的单元测试。

我们通过实现最重要的功能——照片上传，完成了本章。我们确保这个功能按预期运行，并实现了照片的逆向时间顺序视图，这对 API 的消费者来说是必要的，以便向用户显示上传的图片。在此过程中，我们讨论了 Werkzeug 中间件的概念，这是一种强大但经常被忽视的方式，可以在 Flask 处理请求之前审查和（可能）修改请求。

在下一章中，我们将探讨使用和创建命令行工具，这将允许我们通过 CLI 接口和管理我们的 Web 应用程序。


# 第六章：Hublot - Flask CLI 工具

在管理 Web 应用程序时，通常有一些任务是我们希望完成的，而不必创建整个管理 Web 界面；即使这可能相对容易地通过诸如 Flask-Admin 之类的工具来实现。许多开发人员首先转向 shell 脚本语言。Bash 几乎在大多数现代 Linux 操作系统上都是通用的，受到系统管理员的青睐，并且足够强大，可以脚本化可能需要的任何管理任务。

尽管可敬的 Bash 脚本绝对是一个选择，但编写一个基于 Python 的脚本会很好，它可以利用我们为 Web 应用程序精心制作的一些应用程序特定的数据处理。这样做，我们可以避免重复大量精力和努力，这些精力和努力是在创建、测试和部署数据模型和领域逻辑的痛苦过程中投入的，这是任何 Web 应用程序的核心。这就是 Flask-Script 的用武之地。

### 注意

在撰写本文时，Flask 尚未发布 1.0 版本，其中包括通过 Flask 作者开发的`Click`库进行集成的 CLI 脚本处理。由于 Flask/Click 集成的 API 在现在和 Flask 1.0 发布之间可能会发生重大变化，因此我们选择通过 Flask-Script 包来实现本章讨论的 CLI 工具，这已经是 Flask 的事实标准解决方案相当长的时间了。但是，通过 Click API 创建管理任务可以考虑用于任何新的 Flask 应用程序-尽管实现方式有很大不同，但基本原则是足够相似的。

除了我们可能需要一个 shell 脚本执行的不经常的任务，例如导出计算数据，向一部分用户发送电子邮件等，还有一些来自我们以前应用程序的任务可以移植到 Flask-Script CLI 命令中：

+   创建/删除我们当前的数据库模式，从而替换我们以前项目中的`database.py`

+   运行我们的 Werkzeug 开发服务器，替换以前项目中的`run.py`

此外，由于 Flask-Script 是为 Flask 应用程序编写可重用 CLI 脚本的当前事实标准解决方案，许多其他扩展发布 CLI 命令，可以集成到您的现有应用程序中。

在本章中，我们将创建一个应用程序，将从`Github` API 中提取的数据存储在本地数据库中。

### 注意

Git 是一种**分布式版本控制系统**（**DVCS**），在过去几年中变得非常流行，而且理由充分。它已经迅速成为了大量使用各种语言编写的开源项目的首选版本控制系统。

GitHub 是 Git 开源和闭源代码存储库的最知名的托管平台，还配备了一个非常完整的 API，允许根据提供的经过身份验证的凭据，以编程方式访问可用的数据和元数据（评论、拉取请求、问题等）。

为了获取这些数据，我们将创建一个简单的 Flask 扩展来封装基于 REST 的 API 查询，以获取相关数据，然后我们将使用这个扩展来创建一个 CLI 工具（通过 Flask-Script），可以手动运行或连接到基于事件或时间的调度程序，例如 cron。

然而，在我们进行任何操作之前，让我们建立一个非常简单的应用程序框架，以便我们可以开始 Flask-Script 集成。

# 开始

我们再次使用基本的基于 Blueprint 的应用程序结构，并为这个新的冒险创建一个全新的虚拟环境和目录：

```py
$ mkdir -p ~/src/hublot && cd ~/src/hublot
$ mkvirtualenv hublot
$ pip install flask flask-sqlalchemy flask-script

```

我们将开始使用的应用程序布局与我们在以前基于 Blueprint 的项目中使用的非常相似，主要区别在于`manage.py`脚本，它将是我们的 Flask-Script CLI 命令的主要入口点。还要注意缺少`run.py`和`database.py`，这是我们之前提到的，并且很快会详细解释的。

```py
├── application
│   ├── __init__.py
│   └── repositories
│       ├── __init__.py
│       └── models.py
└── manage.py

```

与我们之前的工作保持一致，我们继续使用“应用工厂”模式，允许我们在运行时实例化我们的应用，而不是在模块导入时进行，就像我们将要使用的 Flask-SQLAlchemy 扩展一样。

我们的`application/__init__.py`文件包含以下内容，您应该会非常熟悉：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

# Initialize the db extension, but without configuring
# it with an application instance.
db = SQLAlchemy()

def create_app(config=None):
    app = Flask(__name__)

    if config is not None:
        app.config.from_object(config)

    # Initialize extensions
    db.init_app(app)

    return app
```

我们的`application/settings.py`文件包含了我们对于 Flask-SQLAlchemy 应用程序所需的基本内容：

```py
SQLALCHEMY_DATABASE_URI = 'sqlite:///../hublot.db'
```

### 注意

对于这个特定项目，我们将使用 SQLite 作为我们的首选数据库；如果您决定使用不同的数据库，请相应调整 URI。

为了简便起见，我们将引入简化的`Repository`和`Issue`模型，这些模型将包含我们想要收集的数据。这些模型将存在于`application/repositories/models.py`中：

```py
from application import db
from sqlalchemy.schema import UniqueConstraint
import datetime

class Repository(db.Model):
    """Holds the meta-information about a particular
    Github repository."""

    # The unique primary key for the local repository record.
    id = db.Column(db.Integer, primary_key=True)

    # The name of the repository.
    name = db.Column(db.String(length=255), nullable=False)

    # The github org/user that owns the repository.
    owner = db.Column(db.String(length=255), nullable=False)

    # The description (if any) of the repository.
    description = db.Column(db.Text())

    #  The date/time that the record was created on.
    created_on = db.Column(db.DateTime(), 
        default=datetime.datetime.utcnow, index=True)

    # The SQLAlchemy relation for the issues contained within this
    # repository.
    issues = db.relationship('Issue')

    __table_args__ = (UniqueConstraint('name', 'owner'), )

    def __repr__(self):
        return u'<Repository {}>'.format(self.name)
```

`Repository`模型实例将包含与`Issue`模型的一对多关系相关的给定 Git 存储库的元数据，我们将在下面定义。我们在这个`Repository`类中声明的字段在大部分情况下应该是不言自明的，唯一的例外是`__table__args__ dunder`。

### 注意

**dunder**是一个 Python 特有的新词，用于指代以两个下划线开头的任何变量或方法：*双下划线*或*dunder*。有几个内置的 dunder 方法（例如，`__init__`）和属性（例如，`__name__`），任何您声明并以两个下划线前缀的属性/方法/函数也将属于这个类别。

这个类属性允许我们能够为创建的底层 SQLAlchemy 表指定特定于表的配置。在我们的情况下，我们将用它来指定一个 UniqueConstraint 键，这个键是由名称和所有者的组合值组成的，否则通过典型的基于属性的字段定义是不可能的。

此外，我们定义了一个 issues 属性，其值是与`Issue`模型的关系；这是经典的一对多关系，访问存储库实例的 issues 属性将产生与相关存储库关联的问题列表。

### 注意

请注意，指定的关系不包括与查询性质或相关数据加载行为有关的任何参数。我们正在使用此应用程序的默认行为，这对于包含大量问题的存储库来说并不是一个好主意——在这种情况下，可能会更好地选择先前章节中使用的动态延迟加载方法。

我们在`Repository`模型中提到的`Issue`模型旨在包含与此处托管的 Git 存储库相关联的 GitHub 问题元数据。由于问题只在存储库的上下文中有意义，我们确保`repository_id`外键存在于所有问题中：

```py
class Issue(db.Model):
    """Holds the meta information regarding an issue that
    belongs to a repository."""

    # The autoincremented ID of the issue.
    id = db.Column(db.String(length=40), primary_key=True)
    # The repository ID that this issue belongs to.

    #
    # This relationship will produce a `repository` field
    # that will link back to the parent repository.
    repository_id = db.Column(db.Integer(), 
        db.ForeignKey('repository.id'))

    # The title of the issue
    title = db.Column(db.String(length=255), nullable=False)

    # The issue number
    number = db.Column(db.Integer(), nullable=False)

    state = db.Column(db.Enum('open', 'closed'), nullable=False)

    def __repr__(self):
        """Representation of this issue by number."""
        return '<Issue {}>'.format(self.number)
```

每个`Issue`模型的实例将封装关于创建的 GitHub 问题的非常有限的信息，包括问题编号、问题的状态（*关闭*或*打开*）以及问题的标题。

在以前的章节中，我们会创建一个`database.py`脚本来初始化在数据库中构建我们的 SQLAlchemy 模型。然而，在本章中，我们将使用 Flask-Script 来编写一个小的 CLI 命令，它将做同样的事情，但为我们提供一个更一致的框架来编写这些小的管理工具，并避免随着时间的推移而困扰任何非平凡应用的独立脚本文件的问题。

## manage.py 文件

按照惯例，Flask-Script 的主要入口点是一个名为`manage.py`的 Python 文件，我们将其放在`application/`包的同级目录中，就像我们在本章开头描述的项目布局一样。虽然 Flask-Script 包含了相当多的选项-配置和可定制性-我们将使用最简单的可用调用来封装我们在以前章节中使用的`database.py` Python 脚本的功能，以处理我们数据库的初始化。

我们实例化了一个`Manager`实例，它将处理我们各种命令的注册。`Manager`构造函数接受一个 Flask 应用实例作为参数，但它也（幸运地！）可以接受一个实现可调用接口并返回应用实例的函数或类：

```py
from flask.ext.script import Manager
from application import create_app, db

# Create the `manager` object with a
# callable that returns a Flask application object.
manager = Manager(app=create_app)
```

现在我们有了一个`manager`实例，我们可以使用这个实例的`command`方法来装饰我们想要转换为 CLI 命令的函数：

```py
@manager.command
def init_db():
 """Initialize SQLAlchemy database models."""

 db.create_all()

```

### 注意

请注意，默认情况下，我们用`command`方法包装的函数名称将是 CLI 调用中使用的标识符。

为了使整个过程运行起来，当我们直接调用`manage.py`文件时，我们调用管理器实例的`run`方法：

```py
if __name__ == '__main__':
    manager.run()
```

此时，我们可以通过 Python 解释器执行我们的 CLI 命令：

```py
$ python manage.py init_db

```

假设一切都按预期工作，我们应该看不到任何结果（或错误），并且我们的数据库应该被初始化为我们在模型定义中指定的表、列和索引。

让我们创建一个截然相反的命令，允许我们销毁本地数据库；在开发过程中对数据模型进行大量更改时，这有时会很方便：

```py
@manager.command
def drop_db():
 if prompt_bool(
 "Are you sure you want to lose all your data"):
 db.drop_all()

```

我们以与之前定义的`init_db`命令相同的方式调用这个新创建的`drop_db`命令：

```py
$ python manage.py drop_db

```

### 内置默认命令

除了让我们能够快速定义自己的 CLI 命令之外，Flask-Script 还包括一些默认值，这样我们就不必自己编写它们：

```py
usage: manage.py [-?] {shell,drop_db,init_db,runserver} ...

positional arguments:
 {shell,drop_db,init_db,runserver}
 shell           Runs a Python shell inside Flask application 
 context.
 drop_db
 init_db         Initialize SQLAlchemy database models.
 runserver       Runs the Flask development server i.e. 
 app.run()

optional arguments:
 -?, --help            show this help message and exit

```

### 注意

Flask-Script 会根据相关函数的`docstrings`自动生成已注册命令的帮助文本。此外，运行`manage.py`脚本而没有指定命令或使用`help`选项将显示可用顶级命令的完整列表。

如果出于任何原因，我们想要自定义默认设置，这是相对容易实现的。例如，我们需要开发服务器在 6000 端口上运行，而不是默认的 5000 端口：

```py
from flask.ext.script import Manager, prompt_bool, Server
# …

if __name__ == '__main__':
    manager.add_command('runserver', Server(port=6000))
    manager.run()
```

在这里，我们使用了定义 CLI 命令的另一种方法，即使用`manager.add_command`方法，它将一个名称和`flask.ext.script.command`的子类作为第二个参数。

同样地，我们可以覆盖默认的 shell 命令，以便我们的交互式 Python shell 包含对我们配置的 Flask-SQLAlchemy 数据库对象的引用，以及 Flask 应用对象：

```py
def _context():
    """Adds additional objects to our default shell context."""
    return dict(db=db, repositories=repositories)

if __name__ == '__main__':
    manager.add_command('runserver', Server(port=6000))
    manager.add_command('shell', Shell(make_context=_context))
    manager.run()
```

我们可以通过执行`manage.py`脚本来验证我们的`db`对象是否已经被包含，以调用交互式 shell。

```py
$ python manage.py shell

>>> type(db)
<class 'flask_sqlalchemy.SQLAlchemy'>
>>>

```

验证默认的 Flask 应用服务器是否在我们指定的端口上运行：

```py
$ python manage.py runserver
 * Running on http://127.0.0.1:6000/ (Press CTRL+C to quit)

```

Flask-Script 为默认的`runserver`和`shell`命令提供了几个配置选项，包括禁用它们的能力。您可以查阅在线文档以获取更多详细信息。

## Blueprints 中的 Flask-Script 命令

在我们应用程序级别的`manage.py`中创建临时 CLI 命令的能力既是一种祝福又是一种诅咒：祝福是因为它需要非常少的样板代码就可以运行起来，诅咒是因为它很容易变成一堆难以管理的代码混乱。

为了避免任何非平凡应用程序的不可避免的最终状态，我们将使用 Flask-Script 中子管理器的未充分利用的功能，以创建一组 CLI 命令，这些命令将存在于蓝图中，但可以通过标准的`manage.py`调用访问。这应该使我们能够将命令行界面的领域逻辑保存在与我们基于 Web 的组件的领域逻辑相同的位置。

### 子管理器

我们的第一个 Flask-Script 子管理器将包含解析 GitHub 项目 URL 的逻辑，以获取我们需要创建有效的`Repository`模型记录的组件部分：

```py
$ python manage.py repositories add "https://github.com/mitsuhiko/flask"\
 --description="Main Flask repository"

```

总体思路是，我们希望能够使用从“repositories”子管理器的“add”函数提供的位置和命名参数解析出名称、所有者和描述，从而创建一个新的`Repository`对象。

让我们开始创建一个模块，该模块将包含我们的存储库 CLI 命令，即`application/repositories/cli.py`，目前为空的`add`函数：

```py
from flask.ext.script import Manager

repository_manager = Manager(
    usage="Repository-based CLI actions.")

@repository_manager.command
def add():
    """Adds a repository to our database."""
    pass
```

请注意，我们的`repository_manager`实例是在没有应用程序实例或可返回应用程序实例的可调用对象的情况下创建的。我们将新创建的子管理器实例注册到我们的主应用程序管理器中，而不是在此处提供应用程序对象。

```py
from flask.ext.script import Manager, prompt_bool, Server, Shell
from application import create_app, db, repositories
from application.repositories.cli import repository_manager

# Create the `manager` object with a
# callable that returns a Flask application object.
manager = Manager(app=create_app)

# …
# …

if __name__ == '__main__':
    manager.add_command('runserver', Server(port=6000))
    manager.add_command('shell', Shell(make_context=_context))
 manager.add_command('repositories', repository_manager)
    manager.run()
```

这将使我们能够调用`repositories`管理器并显示可用的子命令：

```py
$ python manage.py repositories --help
usage: Repository-based CLI actions.

Repository-based CLI actions.

positional arguments:
 {add}
 add       Adds a repository to our database.

optional arguments:
 -?, --help  show this help message and exit

```

虽然这将不会产生任何结果（因为函数体是一个简单的 pass 语句），但我们可以调用我们的`add`子命令：

```py
$ python manage.py repositories add

```

### 所需和可选参数

在 Flask-Script 管理器中注册的任何命令都可以有零个或多个必需参数，以及任意默认值的可选参数。

我们的`add`命令需要一个强制参数，即要添加到我们数据库中的存储库的 URL，以及一个可选参数，即此存储库的描述。命令装饰器处理了许多最基本的情况，将命名函数参数转换为它们的 CLI 参数等效项，并将具有默认值的函数参数转换为可选的 CLI 参数。

这意味着我们可以指定以下函数声明来匹配我们之前写下的内容：

```py
@repository_manager.command
def add(url, description=None):
    """Adds a repository to our database."""

    print url, description
```

这使我们能够捕获提供给我们的 CLI 管理器的参数，并在我们的函数体中轻松地使用它们：

```py
$ python manage.py repositories add "https://github.com/mitsuhiko/flask" --description="A repository to add!"

https://github.com/mitsuhiko/flask A repository to add!

```

由于我们已经成功地编码了 CLI 工具的所需接口，让我们添加一些解析，以从 URL 中提取出我们想要的相关部分： 

```py
@repository_manager.command
def add(url, description=None):
    """Adds a repository to our database."""

 parsed = urlparse(url)

 # Ensure that our repository is hosted on github
 if parsed.netloc != 'github.com':
 print "Not from Github! Aborting."
 return 1

 try:
 _, owner, repo_name = parsed.path.split('/')
 except ValueError:
 print "Invalid Github project URL format!"
        return 1
```

### 注意

我们遵循`*nix`约定，在脚本遇到错误条件时返回一个介于 1 和 127 之间的非零值（约定是对语法错误返回 2，对其他任何类型的错误返回 1）。由于我们期望我们的脚本能够成功地将存储库对象添加到我们的数据库中，任何情况下如果这种情况没有发生，都可以被视为错误条件，因此应返回一个非零值。

现在我们正确捕获和处理 CLI 参数，让我们使用这些数据来创建我们的`Repository`对象，并将它们持久化到我们的数据库中：

```py
from flask.ext.script import Manager
from urlparse import urlparse
from application.repositories.models import Repository
from application import db
import sqlalchemy

# …

@repository_manager.command
def add(url, description=None):
    """Adds a repository to our database."""

    parsed = urlparse(url)

    # Ensure that our repository is hosted on github
    if parsed.netloc != 'github.com':
        print "Not from Github! Aborting."
        return 1

    try:
        _, owner, repo_name = parsed.path.split('/')
    except ValueError:
        print "Invalid Github project URL format!"
        return 1

 repository = Repository(name=repo_name, owner=owner)
 db.session.add(repository)

 try:
 db.session.commit()
 except sqlalchemy.exc.IntegrityError:
 print "That repository already exists!"
 return 1

 print "Created new Repository with ID: %d" % repository.id
    return 0
```

### 注意

请注意，我们已经处理了向数据库添加重复存储库（即具有相同名称和所有者的存储库）的情况。如果不捕获`IntegrityError`，CLI 命令将失败并输出指示未处理异常的堆栈跟踪。

现在运行我们新实现的 CLI 命令将产生以下结果：

```py
$ python manage.py repositories add "https://github.com/mitsuhiko/flask" --description="A repository to add!"

Created new Repository with ID: 1

```

成功创建我们的`Repository`对象可以在我们的数据库中进行验证。对于 SQLite，以下内容就足够了：

```py
$ sqlite3 hublot.db
SQLite version 3.8.5 2014-08-15 22:37:57
Enter ".help" for usage hints.

sqlite> select * from repository;

1|flask|mitsuhiko|A repository to add!|2015-07-22 04:00:36.080829

```

## Flask 扩展 - 基础知识

我们花了大量时间安装、配置和使用各种 Flask 扩展（Flask-Login、Flask-WTF、Flask-Bcrypt 等）。它们为我们提供了一个一致的接口来配置第三方库和工具，并经常集成一些使应用程序开发更加愉快的 Flask 特定功能。然而，我们还没有涉及如何构建自己的 Flask 扩展。

### 注意

我们只会查看创建有效的 Flask 扩展所需的框架，以便在项目中本地使用。如果您希望打包您的自定义扩展并在 PyPi 或 GitHub 上发布它，您将需要实现适当的`setup.py`和 setuptools 机制，以使这成为可能。您可以查看 setuptools 文档以获取更多详细信息。

### 何时应该使用扩展？

Flask 扩展通常属于以下两类之一：

+   封装第三方库提供的功能，确保当同一进程中存在多个 Flask 应用程序时，该第三方库将正常运行，并可能添加一些使与 Flask 集成更具体的便利函数/对象；例如，Flask-SQLAlchemy

+   不需要第三方库的模式和行为的编码，但确保应用程序具有一组一致的功能；例如，Flask-Login

您将在野外遇到或自己开发的大多数 Flask 扩展都属于第一类。第二类有点异常，并且通常是由在多个应用程序中观察到的常见模式抽象和精炼而来，以至于可以将其放入扩展中。

### 我们的扩展 - GitHubber

本章中我们将构建的扩展将封装`Github` API 的一个小部分，这将允许我们获取先前跟踪的给定存储库的问题列表。

### 注意

`Github` API 允许的功能比我们需要的更多，文档也很好。此外，存在几个第三方 Python 库，封装了大部分`Github` API，我们将使用其中一个。

为了简化与 GitHub 的 v3 API 的交互，我们将在本地虚拟环境中安装`github3.py` Python 包：

```py
$ pip install github3.py

```

由于我们正在在我们的 Hublot 应用程序中开发扩展，我们不打算引入自定义 Flask 扩展的单独项目的额外复杂性。然而，如果您打算发布和/或分发扩展，您将希望确保它以这样的方式结构化，以便可以通过 Python 包索引提供并通过 setuptools（或 distutils，如果您更愿意只使用标准库中包含的打包工具）进行安装。

让我们创建一个`extensions.py`模块，与`application/repositories/ package`同级，并引入任何 Flask 扩展都应包含的基本结构：

```py
class Githubber(object):
    """
    A Flask extension that wraps necessary configuration
    and functionality for interacting with the Github API
    via the `github3.py` 3rd party library.
    """

    def __init__(self, app=None):
        """
        Initialize the extension.

        Any default configurations that do not require
        the application instance should be put here.
        """

        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        Initialize the extension with any application-level 
        Configuration requirements.
        """
        self.app = app
```

对于大多数扩展，这就是所需的全部。请注意，基本扩展是一个普通的 Python 对象（俗称为 POPO）定义，增加了一个`init_app`实例方法。这个方法并不是绝对必要的。如果您不打算让扩展使用 Flask 应用程序对象（例如加载配置值）或者不打算使用应用程序工厂模式，那么`init_app`是多余的，可以省略。

我们通过添加一些配置级别的检查来完善扩展，以确保我们具有`GITHUB_USERNAME`和`GITHUB_PASSWORD`以进行 API 身份验证访问。此外，我们将当前扩展对象实例存储在`app.extensions`中，这使得扩展的动态使用/加载更加简单（等等）：

```py
    def init_app(self, app):
        """
        Initialize the extension with any application-level 
        Configuration requirements.

        Also store the initialized extension and application state
        to the `app.extensions`
        """

        if not hasattr(app, 'extensions'):
            app.extensions = {}

        if app.config.get('GITHUB_USERNAME') is None:
            raise ValueError(
                "Cannot use Githubber extension without "
                "specifying the GITHUB_USERNAME.")

        if app.config.get('GITHUB_PASSWORD') is None:
            raise ValueError(
                "Cannot use Githubber extension without "
                "specifying the GITHUB_PASSWORD.")

        # Store the state of the currently configured extension in
        # `app.extensions`.
        app.extensions['githubber'] = self
        self.app = app
```

### 注意

对`Github` API 进行身份验证请求需要某种形式的身份验证。GitHub 支持其中几种方法，但最简单的方法是指定帐户的用户名和密码。一般来说，这不是你想要要求用户提供的东西：最好在这些情况下使用 OAuth 授权流程，以避免以明文形式存储用户密码。然而，对于我们相当简单的应用程序和自定义扩展，我们将放弃扩展的 OAuth 实现（我们将在后面的章节中更广泛地讨论 OAuth），并使用用户名和密码组合。

单独使用，我们创建的扩展并没有做太多事情。让我们通过添加一个装饰属性的方法来修复这个问题，该方法实例化`github3.py Github` API 客户端库：

```py
from github3 import login

class Githubber(object):
    # …
    def __init__(self, app=None):

        self._client = None
        # …

    @property
    def client(self):
        if self._client:
            return self._client

        gh_client = login(self.app.config['GITHUB_USERNAME'],
                password=self.app.config['GITHUB_PASSWORD'])

        self._client = gh_client
        return self._client
```

在前面的`client`方法中，我们实现了缓存属性模式，这将确保我们只实例化一个`github3.py`客户端，每个创建的应用程序实例只实例化一次。此外，扩展将在第一次访问时延迟加载`Github` API 客户端，这通常是一个好主意。一旦应用程序对象被初始化，这让我们可以使用扩展的客户端属性直接与`github3.py` Python 库进行交互。

现在我们已经为我们的自定义 Flask 扩展设置了基本的设置，让我们在`application/__init__.py`中的应用工厂中初始化它并配置扩展本身：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from application.extensions import Githubber

# …
hubber = Githubber()

def create_app(config=None):
    app = Flask(__name__)
    # …

    # Initialize any extensions and bind blueprints to the
    # application instance here.
    db.init_app(app)
 hubber.init_app(app)

    return app
```

注意`hubber = Githubber()`的初始化和赋值发生在工厂本身之外，但实际的`init_app(app)`方法调用和隐含的扩展配置发生在我们初始化 Flask 应用程序对象之后的工厂中。你可能已经注意到了这种分割模式（我们在之前的章节中也讨论过几次），但现在你已经通过开发自己的扩展看到了它的原因。

考虑到这一点，我们在`application/repositories/cli.py`模块中添加了一个额外的函数，以增加一些额外的 CLI 工具功能：

```py
from flask.ext.script import Manager
from urlparse import urlparse
from application.repositories.models import Repository, Issue
from application import db, hubber
import sqlalchemy

# …

@repository_manager.command
def fetch_issues(repository_id):
    """Fetch all commits for the given Repository."""

    try:
        repo = Repository.query.get(repository_id)
    except sqlalchemy.orm.exc.NoResultFound:
        print "No such repository ID!"
        return 1

    r = hubber.client.repository(repo.owner, repo.name)
    issues = []

    for issue in r.iter_issues():
        i = Issue(repository_id=repo.id, title=issue.title,
                number=issue.number, state=issue.state)

        issues.append(i)

    db.session.add_all(issues)

       print "Added {} issues!".format(len(issues))
```

从数据库中获取存储库对象（基于通过 CLI 参数指定的 ID 值），我们调用了我们的`Githubber`扩展的`client.repository()`方法，我们将其导入为`hubber`，这是在工厂序言中分配的名称。由于我们的扩展的一部分负责使用所需的凭据进行初始化，因此我们不需要在调用它的 CLI 工具中处理这个问题。

一旦我们获得了对远程 GitHub 存储库的引用，我们就通过`github3.py`提供的`iter_issues()`方法迭代注册的问题，然后创建`Issue`实例，将其持久化到 SQLAlchemy 会话中。

### 注意

对当前的`Issue`模型的一个受欢迎的改进是在`repository_id`和数字上引入一个复合索引，并使用唯一约束来确保在同一存储库上多次运行前面的命令时不会重复导入问题。

在前面的 CLI 命令中，对重复插入的异常处理也需要发生。实现留给读者作为一个（相对简单的）练习。

这些类型的 CLI 工具非常有用，可以脚本化动作和行为，这些动作和行为在典型的 Web 应用程序的当前用户请求中可能被认为成本太高。你最不希望的是你的应用程序的用户等待几秒，甚至几分钟，以完成一些你几乎无法控制的操作。相反，最好让这些事件在带外发生。实现这一目标的流行方法包括 cron 作业和作业/任务队列，例如 Celery 实现的那些（可能是事件驱动的，而不是按照 cron 作业那样定期运行），等等。

# 摘要

阅读完本章后，您应该对 Flask 扩展和基于命令行的应用程序接口（通过 Flask-Script）的内部工作方式更加熟悉。

我们首先创建了一个简单的应用程序，用于存储在 GitHub 上托管的存储库和问题的数据，然后安装和配置了我们的`manage.py`脚本，以充当 Flask-Script 默认 CLI runserver 和 shell 命令的桥梁。我们添加了`drop_db`和`init_db`全局命令，以替换我们在之前章节中使用的`database.py`脚本。完成后，我们将注意力转向在蓝图中创建子管理器的脚本，我们可以通过主`manage.py`接口脚本进行控制。

最后，我们实现了自己的 Flask 扩展，包装了一些基本配置和资源实例化的`github3.py Github` API 客户端。完成后，我们回到之前创建的子管理脚本，并添加了获取存储在 GitHub 上的给定存储库 ID 的问题列表所需的功能。

在下一章中，我们将深入研究第三方 API，我们将构建一个应用程序，该应用程序使用 OAuth 授权协议，以实现通过 Twitter 和 Facebook 进行用户帐户创建和登录。


# 第七章：Dinnerly - 食谱分享

在本章中，我们将探讨所谓的社交登录的现代方法，其中我们允许用户使用来自另一个网络应用程序的派生凭证对我们的应用程序进行身份验证。目前，支持这种机制的最广泛的第三方应用程序是 Twitter 和 Facebook。

虽然存在其他几种广泛的网络应用程序支持这种集成类型（例如 LinkedIn、Dropbox、Foursquare、Google 和 GitHub 等），但您潜在用户的大多数将至少拥有 Twitter 或 Facebook 中的一个帐户，这两个是当今主要的社交网络。

为此，我们将添加、配置和部署 Flask-OAuthlib 扩展。该扩展抽象出了通常在处理基于 OAuth 的授权流程时经常遇到的一些困难和障碍（我们将很快解释），并包括功能以快速设置所需的默认值来协商提供者/消费者/资源所有者令牌交换。作为奖励，该扩展将为我们提供与用户代表的这些远程服务的经过身份验证的 API 进行交互的能力。

# 首先是 OAuth

让我们先把这个搞清楚：OAuth 可能有点难以理解。更加火上浇油的是，OAuth 框架/协议在过去几年中经历了一次重大修订。第 2 版于 2012 年发布，但由于各种因素，仍有一些网络应用程序继续实施 OAuth v1 协议。

### 注意

OAuth 2.0 与 OAuth 1.0 不兼容。此外，OAuth 2.0 更像是授权框架规范，而不是正式的协议规范。现代网络应用程序中大多数 OAuth 2.0 实现是不可互操作的。

为了简单起见，我们将概述 OAuth 2.0 授权框架的一般术语、词汇和功能。第 2 版是两个规范中更简单的一个，这是有道理的：后者的设计目标之一是使客户端实现更简单，更不容易出错。大部分术语在两个版本中是相似的，如果不是完全相同的。

虽然由于 Flask-OAuthlib 扩展和处理真正繁重工作的底层 Python 包，OAuth 授权交换的复杂性大部分将被我们抽象化，但对于网络应用程序和典型实现的 OAuth 授权框架（特别是最常见的授权授予流程）的一定水平的了解将是有益的。

## 为什么使用 OAuth？

适当的在线个人安全的一个重大错误是在不同服务之间重复使用访问凭证。如果您用于一个应用的凭证被泄露，这将使您面临各种安全问题。现在，您可能会在使用相同一组凭证的所有应用程序上受到影响，唯一的后期修复方法是去到处更改您的凭证。

比在不同服务之间重复使用凭证更糟糕的是，用户自愿将他们的凭证交给第三方服务，比如 Twitter，以便其他服务，比如 Foursquare，可以代表用户向 Twitter 发出请求（例如，在他们的 Twitter 时间轴上发布签到）。虽然不是立即明显，但这种方法的问题之一是凭证必须以明文形式存储。

出于各种原因，这种情况并不理想，其中一些原因是您作为应用程序开发人员无法控制的。

OAuth 在框架的 1 版和 2 版中都试图通过创建 API 访问委托的开放标准来解决跨应用程序共享凭据的问题。OAuth 最初设计的主要目标是确保应用程序 A 的用户可以代表其委托应用程序 B 访问，并确保应用程序 B 永远不会拥有可能危害应用程序 A 用户帐户的凭据。

### 注意

虽然拥有委托凭据的应用程序可以滥用这些凭据来执行一些不良操作，但根凭据从未被共享，因此帐户所有者可以简单地使被滥用的委托凭据无效。如果根帐户凭据简单地被提供给第三方应用程序，那么后者可以通过更改所有主要身份验证信息（用户名、电子邮件、密码等）来完全控制帐户，从而有效地劫持帐户。

## 术语

关于 OAuth 的使用和实施的大部分混乱源于对用于描述基本授权流的基本词汇和术语的误解。更糟糕的是，有几个流行的 Web 应用程序已经实施了 OAuth（以某种形式），并决定使用自己的词汇来代替官方 RFC 中已经决定的词汇。

### 注意

RFC，或称为请求评论，是来自**互联网工程任务组**（**IETF**）的一份文件或一组文件的备忘录式出版物，IETF 是管理大部分互联网建立在其上的开放标准的主要机构。RFC 通常由一个数字代码表示，该代码在 IETF 中唯一标识它们。例如，OAuth 2.0 授权框架 RFC 编号为 6749，可以在 IETF 网站上完整找到。

为了帮助减轻一些混乱，以下是 OAuth 实施中大多数基本组件的简化描述：

+   消费者：这是代表用户发出请求的应用程序。在我们的特定情况下，Dinnerly 应用程序被视为消费者。令人困惑的是，官方的 OAuth 规范是指客户端而不是消费者。更令人困惑的是，一些应用程序同时使用消费者和客户端术语。通常，消费者由必须保存在应用程序配置中的密钥和秘钥表示，并且必须受到良好的保护。如果恶意实体获得了您的消费者密钥和秘钥，他们就可以在向第三方提供商发出授权请求时假装成您的应用程序。

+   **提供者**：这是消费者代表用户试图访问的第三方服务。在我们的情况下，Twitter 和 Facebook 是我们将用于应用程序登录的提供者。其他提供者的例子可能包括 GitHub、LinkedIn、Google 以及任何其他提供基于授权流的 OAuth 授权的服务。

+   **资源所有者**：这是有能力同意委托资源访问的实体。在大多数情况下，资源所有者是所涉及应用程序的最终用户（例如，Twitter 和 Dinnerly）。

+   **访问令牌**：这是客户端代表用户向提供者发出请求以访问受保护资源的凭据。令牌可以与特定的权限范围相关联，限制其可以访问的资源。此外，访问令牌可能会在由提供者确定的一定时间后过期；此时需要使用刷新令牌来获取新的有效访问令牌。

+   **授权服务器**：这是负责在资源所有者同意委托他们的访问权限后向消费者应用程序发放访问令牌的服务器（通常由 URI 端点表示）。

+   **流程类型**：OAuth 2.0 框架提供了几种不同的授权流程概述。有些最适合于没有网络浏览器的命令行应用程序，有些更适合于原生移动应用程序，还有一些是为连接具有非常有限访问能力的设备而创建的（例如，如果您想将 Twitter 帐户特权委托给您的联网烤面包机）。我们最感兴趣的授权流程，不出所料，是为基本基于网络浏览器的访问而设计的。

有了上述词汇表，您现在应该能够理解官方 OAuth 2.0 RFC 中列出的官方抽象协议流程：

```py
 +--------+                               +---------------+
 |        |--(A)- Authorization Request ->|   Resource    |
 |        |                               |     Owner     |
 |        |<-(B)-- Authorization Grant ---|               |
 |        |                               +---------------+
 |        |
 |        |                               +---------------+
 |        |--(C)-- Authorization Grant -->| Authorization |
 | Client |                               |     Server    |
 |        |<-(D)----- Access Token -------|               |
 |        |                               +---------------+
 |        |
 |        |                               +---------------+
 |        |--(E)----- Access Token ------>|    Resource   |
 |        |                               |     Server    |
 |        |<-(F)--- Protected Resource ---|               |
 +--------+                               +---------------+

```

以下是从 RFC 6749 中列出的流程图中列出的步骤的描述，并且为了我们的目的更加相关：

1.  客户端（或消费者）请求资源所有者授予授权。这通常是用户被重定向到远程提供者的登录屏幕的地方，比如 Twitter，在那里解释了客户端应用程序希望访问您控制的受保护资源。同意后，我们进入下一步。

1.  客户端从资源所有者（用户）那里收到授权凭证，这是代表资源所有者对提供者实施的特定类型授权流程的授权的临时凭证。对于大多数 Web 应用程序来说，这通常是授权代码授予流程。

1.  一旦客户端收到授权凭证，它会将其发送到授权服务器，以代表资源所有者请求认证令牌。

1.  授权服务器验证授权凭证并对发出请求的客户端进行身份验证。在满足这两个要求后，服务器将有效的认证令牌返回给客户端，然后客户端可以使用该令牌代表用户向提供者发出经过认证的请求。

## 那么 OAuth 1.0 有什么问题呢？

理论上：没有太多问题。实际上：对于消费者来说，正确实施起来有些困难，而且极易出错。

在实施和使用 OAuth 1.0 提供程序时的主要困难围绕着消费者应用程序未能正确执行所需的加密请求签名。参数和参数必须从查询字符串中收集，还必须从请求正文和各种 OAuth 参数（例如，`oauth_nonce`，`oauth_signature_method`，`oauth_timestamp`等）中收集，然后进行 URL 编码（意味着非 URL 安全值被特殊编码以确保它们被正确传输）。一旦键/值对已被编码，它们必须按键的字典顺序进行排序（记住，编码后的键而不是原始键值），然后使用典型的 URL 参数分隔符将它们连接成一个字符串。此外，要提交请求的 HTTP 动词（例如，`GET`或`POST`）必须预先添加到我们刚刚创建的字符串中，然后跟随请求将被发送到的 URL。最后，签名密钥必须由消费者秘钥和 OAuth 令牌秘钥构建，然后传递给 HMAC-SHA1 哈希算法的实现，以及我们之前构建的有效载荷。

假设您已经全部正确理解了这些（很容易出现简单错误，比如按字母顺序而不是按字典顺序对密钥进行排序），那么请求才会被视为有效。此外，在发生签名错误的情况下，没有简单的方法确定错误发生的位置。

OAuth 1.0 需要这种相当复杂的过程的原因之一是，该协议的设计目标是它应该跨不安全的协议（如 HTTP）运行，但仍确保请求在传输过程中没有被恶意方修改。

尽管 OAuth 2.0 并不被普遍认为是 OAuth 1.0 的值得继任者，但它通过简单要求所有通信都在 HTTPS 上进行，大大简化了实现。

## 三步授权

在 OAuth 框架的所谓三步授权流程中，应用程序（`consumer`）代表用户（`resource owner`）发出请求，以访问远程服务（`provider`）上的资源。

### 注意

还存在一个两步授权流程，主要用于应用程序之间的访问，资源所有者不需要同意委托访问受保护资源。例如，Twitter 实现了两步和三步授权流程，但前者在资源访问和强制 API 速率限制方面没有与后者相同的访问范围。

这就是 Flask-Social 将允许我们为 Twitter 和 Facebook 实现的功能，我们选择的两个提供者，我们的应用程序将作为消费者。最终结果将是我们的 Dinnerly 应用程序将拥有这两个提供者的访问令牌，这将允许我们代表我们的用户（资源所有者）进行经过身份验证的 API 请求，这对于实现任何跨社交网络发布功能是必要的。

# 设置应用程序

再次，让我们为我们的项目设置一个基本的文件夹，以及相关的虚拟环境，以隔离我们的应用程序依赖关系：

```py
$ mkdir –p ~/src/dinnerly
$ mkvirtualenv dinnerly
$ cd ~/src/dinnerly

```

创建后，让我们安装我们需要的基本包，包括 Flask 本身以及 Flask-OAuthlib 扩展，我们值得信赖的朋友 Flask-SQLAlchemy 和我们在之前章节中使用过的 Flask-Login：

```py
$ pip install flask flask-oauthlib flask-sqlalchemy flask-login flask-wtf

```

我们将利用我们在过去章节中表现良好的 Blueprint 应用程序结构，以确保坚实的基础。现在，我们将有一个单一的用户 Blueprint，其中将处理 OAuth 处理：

```py
-run.py
-application
 ├── __init__.py
 └── users
     ├── __init__.py
     ├── models.py
    └── views.py

```

一旦建立了非常基本的文件夹和文件结构，让我们使用应用程序工厂来创建我们的主应用程序对象。现在，我们要做的只是在`application/__init__.py`中实例化一个非常简单的应用程序，其中包含一个 Flask-SQLAlchemy 数据库连接：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

# Deferred initialization of the db extension
db = SQLAlchemy()

def create_app(config=None):
    app = Flask(__name__, static_folder=None)

    if config is not None:
        app.config.from_object(config)

    db.init_app(app)
    return app
```

为了确保我们实际上可以运行应用程序并创建数据库，让我们使用简单的`run.py`和`database.py`脚本，将它们放在`application`文件夹的同级目录。`run.py`的内容与我们在之前章节中使用的内容类似：

```py
from application import create_app

app = create_app(config='settings')
app.run(debug=True)
```

### 注意

在本章的后面，我们将探讨运行 Dinnerly 应用程序的替代方法，其中大部分更适合生产部署。在`app.run()`上调用的 Werkzeug 开发服务器非常不适合除了本地开发之外的任何其他用途。

我们的`database.py`同样简单明了：

```py
from application import db, create_app
app = create_app(config='settings')
db.app = app

db.create_all()
```

这将允许我们根据我们的模型定义在数据库中创建相关的模式，但我们还没有声明模型；现在运行脚本基本上不会有任何操作。这没关系！在这变得有用之前我们还有很多工作要做。

## 声明我们的模型

与大多数应用程序一样，我们首先声明我们的数据模型和它们需要的任何关系。当然，我们需要一个`User`模型，它将是 OAuth 授权和令牌交换的核心。

正如您可能还记得我们对 OAuth 术语和基本的三步授权授予流程的简要概述，访问令牌是允许客户端（我们的 Dinnerly 应用程序）查询远程服务提供商（例如 Twitter 或 Facebook）资源的东西。由于我们需要这些令牌来向列出的服务提供商发出请求，我们希望将它们存储在某个地方，以便我们可以在没有用户为每个操作重新进行身份验证的情况下使用它们；这将非常繁琐。

我们的`User`模型将与我们以前使用过的`User`模型非常相似（尽管我们删除了一些属性以简化事情），我们将把它放在`application/users/models.py`的明显位置：

```py
import datetime
from application import db

class User(db.Model):

    # The primary key for each user record.
    id = db.Column(db.Integer, primary_key=True)

    # The username for a user. Might not be
    username = db.Column(db.String(40))

    #  The date/time that the user account was created on.
    created_on = db.Column(db.DateTime,
        default=datetime.datetime.utcnow)

    def __repr__(self):
        return '<User {!r}>'.format(self.username)
```

### 注意

请注意，我们没有包括有关密码的任何内容。由于此应用程序的意图是要求使用 Facebook 或 Twitter 创建帐户并登录，我们放弃了典型的用户名/密码凭据组合，而是将身份验证委托给这些第三方服务之一。

为了帮助我们的用户会话管理，我们将重用我们在之前章节中探讨过的 Flask-Login 扩展。以防您忘记，扩展的基本要求之一是在用于表示经过身份验证的用户的任何模型上声明四种方法：`is_authenticated`，`is_active`，`is_anonymous`和`get_id`。让我们将这些方法的最基本版本附加到我们已经声明的`User`模型中：

```py
class User(db.Model):

   # …

    def is_authenticated(self):
        """All our registered users are authenticated."""
        return True

    def is_active(self):
        """All our users are active."""
        return True

    def is_anonymous(self):
        """All users are not in an anonymous state."""
        return False

    def get_id(self):
        """Get the user ID as a Unicode string."""
        return unicode(self.id)
```

现在，您可能已经注意到`User`模型上没有声明的 Twitter 或 Facebook 访问令牌属性。当然，添加这些属性是一个选择，但我们将使用稍微不同的方法，这需要更多的前期复杂性，并且将允许添加更多提供程序而不会过度污染我们的`User`模型。

我们的方法将集中在创建用户与各种提供程序类型之间的多个一对一数据关系的想法上，这些关系将由它们自己的模型表示。让我们在`application/users/models.py`中添加我们的第一个提供程序模型到存储：

```py
class TwitterConnection(db.Model):

    # The primary key for each connection record.
    id = db.Column(db.Integer, primary_key=True)

    # Our relationship to the User that this
    # connection belongs to.
    user_id = db.Column(db.Integer(),
        db.ForeignKey('user.id'), nullable=False, unique=True)

    # The twitter screen name of the connected account.
    screen_name = db.Column(db.String(), nullable=False)

    # The Twitter ID of the connected account
    twitter_user_id = db.Column(db.Integer(), nullable=False)

    # The OAuth token
    oauth_token = db.Column(db.String(), nullable=False)

    # The OAuth token secret
    oauth_token_secret = db.Column(db.String(), nullable=False)
```

前面的模型通过`user_id`属性声明了与`User`模型的外键关系，除了主键之外的其他字段存储了进行身份验证请求所需的 OAuth 令牌和密钥，以代表用户访问 Twitter API。此外，我们还存储了 Twitter 的`screen_name`和`twitter_user_id`，以便将此值用作相关用户的用户名。保留 Twitter 用户 ID 有助于我们将 Twitter 上的用户与本地 Dinnerly 用户匹配（因为`screen_name`可以更改，但 ID 是不可变的）。

一旦`TwitterConnection`模型被定义，让我们将关系添加到`User`模型中，以便我们可以通过`twitter`属性访问相关的凭据：

```py
Class User(db.Model):
  # …

  twitter = db.relationship("TwitterConnection", uselist=False,
    backref="user")
```

这在`User`和`TwitterConnection`之间建立了一个非常简单的一对一关系。`uselist=False`参数确保配置的属性将引用标量值，而不是列表，这将是一对多关系的默认值。

因此，一旦我们获得了用户对象实例，我们就可以通过`user.twitter`访问相关的`TwitterConnection`模型数据。如果没有附加凭据，那么这将返回`None`；如果有附加凭据，我们可以像预期的那样访问子属性：`user.twitter.oauth_token`，`user.twitter.screen_name`等。

让我们为等效的`FacebookConnection`模型做同样的事情，它具有类似的属性。与`TwitterConnection`模型的区别在于 Facebook OAuth 只需要一个令牌（而不是组合令牌和密钥），我们可以选择存储 Facebook 特定的 ID 和名称（而在其他模型中，我们存储了 Twitter 的`screen_name`）：

```py
class FacebookConnection(db.Model):

    # The primary key for each connection record.
    id = db.Column(db.Integer, primary_key=True)

    # Our relationship to the User that this
    # connection belongs to.
    user_id = db.Column(db.Integer(),
        db.ForeignKey('user.id'), nullable=False)

    # The numeric Facebook ID of the user that this
    # connection belongs to.
    facebook_id = db.Column(db.Integer(), nullable=False)

    # The OAuth token
    access_token = db.Column(db.String(), nullable=False)

    # The name of the user on Facebook that this
    # connection belongs to.
    name = db.Column(db.String())
```

一旦我们建立了这个模型，我们就会想要像之前为`TwitterConnection`模型一样，将这种关系引入到我们的`User`模型中：

```py
class User(db.Model):

       # …

    facebook = db.relationship("FacebookConnection", 
        uselist=False, backref="user")
```

`user`实例的前述`facebook`属性的功能和用法与我们之前定义的`twitter`属性完全相同。

## 在我们的视图中处理 OAuth

有了我们基本的用户和 OAuth 连接模型，让我们开始构建所需的 Flask-OAuthlib 对象来处理授权授予流程。第一步是以我们应用程序工厂的通常方式初始化扩展。在此期间，让我们也初始化 Flask-Login 扩展，我们将用它来管理已登录用户的认证会话：

```py
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask_oauthlib.client import OAuth
 from flask.ext.login import LoginManager

# Deferred initialization of our extensions
db = SQLAlchemy()
oauth = OAuth()
login_manager = LoginManager()

def create_app(config=None):
    app = Flask(__name__, static_folder=None)

    if config is not None:
        app.config.from_object(config)

    db.init_app(app)
 oauth.init_app(app)
 login_manager.init_app(app)

    return app
```

现在我们有了一个`oauth`对象可供我们使用，我们可以为每个服务提供商实例化单独的 OAuth 远程应用程序客户端。让我们将它们放在我们的`application/users/views.py 模块`中：

```py
from flask.ext.login import login_user, current_user
from application import oauth

twitter = oauth.remote_app(
    'twitter',
    consumer_key='<consumer key>',
    consumer_secret='<consumer secret>',
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate')

facebook = oauth.remote_app(
    'facebook',
    consumer_key='<facebook app id>',
    consumer_secret='<facebook app secret>',
    request_token_params={'scope': 'email,publish_actions'},
    base_url='https://graph.facebook.com',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    access_token_method='GET',
    authorize_url='https://www.facebook.com/dialog/oauth')
```

现在，在实例化这些 OAuth 对象时似乎有很多事情要做，但其中大部分只是告诉通用的 OAuth 连接库各种三方 OAuth 授权授予流程的服务提供商 URI 端点在哪里。然而，有一些参数值需要您自己填写：消费者密钥（对于 Twitter）和应用程序密钥（对于 Facebook）。要获得这些值，您必须在相应的服务上注册一个新的 OAuth 客户端应用程序，您可以在这里这样做：

+   Twitter: [`apps.twitter.com/app/new`](https://apps.twitter.com/app/new)，然后转到**Keys**和**Access Tokens**选项卡以获取消费者密钥和消费者密钥。

+   Facebook: [`developers.facebook.com/apps/`](https://developers.facebook.com/apps/)，同意服务条款并注册您的帐户进行应用程序开发。然后，选择要添加的网站类型应用程序，并按照说明生成所需的应用程序 ID 和应用程序密钥。

在 Facebook 的情况下，我们通过`request_token_params`参数的`scope`键的`publish_actions`值请求了发布到相关用户的墙上的权限。这对我们来说已经足够了，但如果您想与 Facebook API 互动不仅仅是推送状态更新，您需要请求正确的权限集。Facebook 文档中有关于第三方应用程序开发者如何使用权限范围值执行不同操作的额外信息和指南。

一旦您获得了所需的密钥和密钥，就将它们插入到前述`oauth`远程应用程序客户端配置中留下的占位符中。

现在，我们需要让我们的应用程序处理授权流程的各个部分，这些部分需要用户从服务提供商那里请求授予令牌。我们还需要让我们的应用程序处理回调路由，服务提供商将在流程完成时重定向到这些路由，并携带各种 OAuth 令牌和密钥，以便我们可以将这些值持久化到我们的数据库中。

让我们创建一个用户 Blueprint 来对`application/users/views.py`中的各种路由进行命名空间处理，同时，我们还可以从 Flask 和 Flask-Login 中导入一些实用程序来帮助我们的集成：

```py
from flask import Blueprint, redirect, url_for, request
from flask.ext.login import login_user, current_user

from application.users.models import (
    User, TwitterConnection, FacebookConnection)
from application import oauth, db, login_manager
import sqlalchemy

users = Blueprint('users', __name__, template_folder='templates')
```

根据 Flask-Login 的要求，我们需要定义一个`user_loader`函数，它将通过 ID 从我们的数据库中获取用户：

```py
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
```

以非常相似的方式，Flask-OAuthlib 要求我们定义一个方法（每个服务一个）作为令牌获取器；而 Flask-Login 需要`user_loader`通过 ID 从数据库中获取用户。OAuthlib 需要一个函数来获取当前登录用户的 OAuth 令牌。如果当前没有用户登录，则该方法应返回`None`，表示我们可能需要开始授权授予流程来获取所需的令牌：

```py
@twitter.tokengetter
def get_twitter_token():
    """Fetch Twitter token from currently logged
    in user."""
    if (current_user.is_authenticated() and
            current_user.twitter):
        return (current_user.twitter.oauth_token,
                current_user.twitter.oauth_token_secret)
    return None

@facebook.tokengetter
def get_facebook_token():
    """Fetch Facebook token from currently logged
    in user."""
    if (current_user.is_authenticated() and
            current_user.facebook):
        return (current_user.facebook.oauth_token, )
    return None
```

### 注意

请注意，我们使用了 Flask-Login 提供的`current_user`代理对象来访问当前经过身份验证的用户的对象，然后我们调用了在本章前面定义的`User`模型中的`is_authenticated`方法。

接下来，我们需要定义路由和处理程序来启动三方授权授予。我们的第一个用户蓝图路由将处理使用 Twitter 作为第三方提供商的尝试登录：

```py
@users.route('/login/twitter')
def login_twitter():
    """Kick-off the Twitter authorization flow if
    not currently authenticated."""

    if current_user.is_authenticated():
        return redirect(url_for('recipes.index'))
    return twitter.authorize(
        callback=url_for('.twitter_authorized',
            _external=True))
```

前面的路由首先确定当前用户是否已经经过身份验证，并在他们已经经过身份验证时将其重定向到主`recipes.index`路由处理程序。

### 注意

我们已经为`recipes.index`路由设置了一些重定向，但我们还没有定义。如果您打算在我们设置这些之前测试应用程序的这一部分，您将不得不在蓝图路由中添加一个存根页面，或者将其更改为其他内容。

如果用户尚未经过身份验证，我们通过`twitter.authorize`方法调用来启动授权授予。这将启动 OAuth 流程，并在授权成功完成后（假设用户同意允许我们的应用程序访问他们的第三方受保护资源），Twitter 将调用 GET 请求到我们提供的回调 URL 作为第一个参数。这个请求将包含 OAuth 令牌和他们认为有用的任何其他信息（如`screen_name`）在查询参数中，然后由我们来处理请求，提取出我们需要的信息。

为此，我们定义了一个`twitter_authorized`路由处理程序，其唯一目的是提取出 OAuth 令牌和密钥，以便我们可以将它们持久化到我们的数据库中，然后使用 Flask-Login 的`login_user`函数为我们的 Dinnerly 应用程序创建一个经过身份验证的用户会话：

```py
@users.route('/login/twitter-authorized')
def twitter_authorized():
  resp = twitter.authorized_response()

  try:
    user = db.session.query(User).join(
      TwitterConnection).filter(
        TwitterConnection.oauth_token == 
          resp['oauth_token']).one()
    except sqlalchemy.orm.exc.NoResultFound:
      credential = TwitterConnection(
        twitter_user_id=int(resp['user_id']),
        screen_name=resp['screen_name'],
        oauth_token=resp['oauth_token'],
        oauth_token_secret=resp['oauth_token_secret'])

        user = User(username=resp['screen_name'])
        user.twitter = credential

        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)

  login_user(user)
  return redirect(url_for('recipes.index'))
```

在前面的路由处理程序中，我们首先尝试从授权流中提取 OAuth 数据，这些数据可以通过`twitter.authorized_response()`提供给我们。

### 注意

如果用户决定拒绝授权请求，那么`twitter.authorized_response()`将返回`None`。处理这种错误情况留给读者作为一个练习。

提示：闪存消息和重定向到描述发生情况的页面可能是一个很好的开始！

一旦从授权流的 OAuth 数据响应中提取出 OAuth 令牌，我们就会检查数据库，看看是否已经存在具有此令牌的用户。如果是这种情况，那么用户已经在 Dinnerly 上创建了一个帐户，并且只希望重新验证身份。（也许是因为他们正在使用不同的浏览器，因此他们没有之前生成的会话 cookie 可用。）

如果我们系统中没有用户被分配了 OAuth 令牌，那么我们将使用我们刚刚收到的数据创建一个新的`User`记录。一旦这个记录被持久化到 SQLAlchemy 会话中，我们就使用 Flask-Login 的`login_user`函数将他们登录。

虽然我们在这里专注于路由处理程序和 Twitter OAuth 授权授予流程，但 Facebook 的流程非常相似。我们的用户蓝图附加了另外两个路由，这些路由将处理希望使用 Facebook 作为第三方服务提供商的登录：

```py
@users.route('/login/facebook')
def login_facebook():
    """Kick-off the Facebook authorization flow if
    not currently authenticated."""

    if current_user.is_authenticated():
        return redirect(url_for('recipes.index'))
    return facebook.authorize(
        callback=url_for('.facebook_authorized',
            _external=True))
```

然后，我们定义了`facebook_authorized`处理程序，它将以与`twitter_authorized`路由处理程序非常相似的方式通过查询参数接收 OAuth 令牌参数：

```py
@users.route('/login/facebook-authorized')
def facebook_authorized():
  """Handle the authorization grant & save the token."""

  resp = facebook.authorized_response()
  me = facebook.get('/me')

  try:
    user = db.session.query(User).join(
      FacebookConnection).filter(
        TwitterConnection.oauth_token ==
          resp['access_token']).one()
    except sqlalchemy.orm.exc.NoResultFound:
      credential = FacebookConnection(
        name=me.data['name'],
        facebook_id=me.data['id'],
        access_token=resp['access_token'])

        user = User(username=resp['screen_name'])
        user.twitter = credential

        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)

  login_user(user)
  return redirect(url_for('recipes.index'))
```

这个处理程序与我们之前为 Twitter 定义的处理程序之间的一个不容忽视的区别是调用`facebook.get('/me')`方法。一旦我们执行了授权授予交换，facebook OAuth 对象就能够代表用户对 Facebook API 进行经过身份验证的请求。我们将利用这一新发现的能力来查询有关委托授权凭据的用户的一些基本细节，例如该用户的 Facebook ID 和姓名。一旦获得，我们将存储这些信息以及新创建用户的 OAuth 凭据。

## 创建食谱

现在我们已经允许用户使用 Twitter 或 Facebook 在 Dinnerly 上创建经过身份验证的帐户，我们需要在这些社交网络上创建一些值得分享的东西！我们将通过`application/recipes/models.py`模块创建一个非常简单的`Recipe`模型：

```py
import datetime
from application import db

class Recipe(db.Model):

    # The unique primary key for each recipe created.
    id = db.Column(db.Integer, primary_key=True)

    # The title of the recipe.
    title = db.Column(db.String())

    # The ingredients for the recipe.
    # For the sake of simplicity, we'll assume ingredients
    # are in a comma-separated string.
    ingredients = db.Column(db.Text())

    # The instructions for each recipe.
    instructions = db.Column(db.Text())

    #  The date/time that the post was created on.
    created_on = db.Column(db.DateTime(),
        default=datetime.datetime.utcnow,
        index=True)

    # The user ID that created this recipe.
    user_id = db.Column(db.Integer(), db.ForeignKey('user.id'))

    # User-Recipe is a one-to-many relationship.
    user = db.relationship('User',
            backref=db.backref('recipes'))
```

我们刚刚定义的`Recipe`模型并没有什么特别之处；它有一个标题、配料和说明。每个食谱都归属于一个用户，我们已经创建了必要的基于关系的字段和我们模型中的`ForeignKey`条目，以便我们的数据以通常的关系数据库方式正确链接在一起。有一些字段用于存储任何食谱中你所期望的典型内容：`title`、`ingredients`和`instructions`。由于 Dinnerly 的目的是在各种社交网络上分享食谱片段，我们应该添加一个方法来帮助生成食谱的简短摘要，并将其限制在 140 个字符以下（以满足 Twitter API 的要求）：

```py
def summarize(self, character_count=136):
    """
    Generate a summary for posting to social media.
    """

    if len(self.title) <= character_count:
        return self.title

    short = self.title[:character_count].rsplit(' ', 1)[0]
    return short + '...'
```

前面定义的`summarize`方法将返回`Recipe`的标题，如果标题包含的字符少于 140 个。如果包含的字符超过 140 个，我们将使用空格作为分隔符将字符串拆分成列表，使用`rsplit`（它从字符串的末尾而不是`str.split`所做的开头开始），然后附加省略号。

### 注意

我们刚刚定义的`summarize`方法只能可靠地处理 ASCII 文本。存在一些 Unicode 字符，可能与 ASCII 字符集中的空格相似，但我们的方法不会正确地在这些字符上拆分。

## 将食谱发布到 Twitter 和 Facebook

在发布新食谱时，我们希望自动将摘要发布到已连接到该用户的服务。当然，有许多方法可以实现这一点：

+   在我们尚未定义的食谱视图处理程序中，我们可以在成功创建/提交`Recipe`对象实例后调用相应的 OAuth 连接对象方法。

+   用户可能需要访问特定的 URI（或提交具体数据的表单），这将触发跨发布。

+   当`Recipe`对象提交到数据库时，我们可以监听 SQLAlchemy 发出的`after_insert`事件，并将我们的摘要推送到连接的社交网络上。

由于前两个选项相对简单，有点无聊，并且到目前为止我们在这本书中还没有探讨过 SQLAlchemy 事件，所以第三个选项是我们将要实现的。

### SQLAlchemy 事件

SQLAlchemy 的一个不太为人所知的特性是事件 API，它发布了几个核心和 ORM 级别的钩子，允许我们附加和执行任意代码。

### 注意

事件系统在精神上（如果不是在实现上）与我们在前一章中看到的 Blinker 分发系统非常相似。我们不是创建、发布和消费基于 blinker 的信号，而是简单地监听 SQLAlchemy 子系统发布的事件。

大多数应用程序永远不需要实现对已发布事件的处理程序。它们通常是 SQLAlchemy 的插件和扩展的范围，允许开发人员增强其应用程序的功能，而无需编写大量的样板连接器/适配器/接口逻辑来与这些插件或扩展进行交互。

我们感兴趣的 SQLAlchemy 事件被归类为 ORM 事件。即使在这个受限的事件范围内（还有大量其他已发布的核心事件，我们甚至不会在这里讨论），仍然有相当多的事件。大多数开发人员通常感兴趣的是映射器级别的事件：

+   `before_insert`：在发出与该实例对应的`INSERT`语句之前，此函数接收一个对象实例

+   `after_insert`：在发出与该实例对应的`INSERT`语句之后，此函数接收一个对象实例

+   `before_update`：在发出与该实例对应的`UPDATE`语句之前，此函数接收一个对象实例

+   `after_update`：在发出与该实例对应的`UPDATE`语句之后，此函数接收一个对象实例

+   `before_delete`：在发出与该实例对应的`DELETE`语句之前，此函数接收一个对象实例

+   `after_delete`：在发出与该实例对应的`DELETE`语句之后，此函数接收一个对象实例

每个命名事件都会与 SQLAlchemy 的`Mapper`对象一起发出（该对象定义了`class`属性与数据库列的对应关系），将被用于执行查询的连接对象，以及被操作的目标对象实例。

通常，开发人员会使用原始连接对象来执行简单的 SQL 语句（例如，增加计数器，向日志表添加一行等）。然而，我们将使用`after_insert`事件来将我们的食谱摘要发布到 Twitter 和 Facebook。

为了从组织的角度简化事情，让我们将 Twitter 和 Facebook 的 OAuth 客户端对象实例化移到它们自己的模块中，即`application/users/services.py`中：

```py
from application import oauth

twitter = oauth.remote_app(
    'twitter',
    consumer_key='<consumer key>',
    consumer_secret='<consumer secret>',
    base_url='https://api.twitter.com/1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    access_token_method='GET')

facebook = oauth.remote_app(
    'facebook',
    consumer_key='<consumer key>',
    consumer_secret='<consumer secret>',
    request_token_params={'scope': 'email,publish_actions'},
    base_url='https://graph.facebook.com',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    access_token_method='GET',
    authorize_url='https://www.facebook.com/dialog/oauth')
```

将此功能移动到一个单独的模块中，我们可以避免一些更糟糕的循环导入可能性。现在，在`application/recipes/models.py`模块中，我们将添加以下函数，当发出`after_insert`事件并由`listens_for`装饰器标识时将被调用：

```py
from application.users.services import twitter, facebook
from sqlalchemy import event

@event.listens_for(Recipe, 'after_insert')
def listen_for_recipe_insert(mapper, connection, target):
    """Listens for after_insert event from SQLAlchemy
    for Recipe model instances."""

    summary = target.summarize()

    if target.user.twitter:
        twitter_response = twitter.post(
            'statuses/update.json',
            data={'status': summary})
        if twitter_response.status != 200:
            raise ValueError("Could not publish to Twitter.")

    if target.user.facebook:
        fb_response = facebook.post('/me/feed', data={
            'message': summary
        })
        if fb_response.status != 200:
            raise ValueError("Could not publish to Facebook.")
```

我们的监听函数只需要一个目标（被操作的食谱实例）。我们通过之前编写的`Recipe.summarize()`方法获得食谱摘要，然后使用 OAuth 客户端对象的`post`方法（考虑到每个服务的不同端点 URI 和预期的负载格式）来创建用户已连接到的任何服务的状态更新。

### 提示

我们在这里定义的函数的错误处理代码有些低效；每个 API 可能返回不同的 HTTP 错误代码，很可能一个服务可能会接受帖子，而另一个服务可能会因为某种尚未知的原因而拒绝它。处理与多个远程第三方 API 交互时可能出现的各种故障模式是复杂的，可能是一本书的主题。

## 寻找共同的朋友

大多数现代的社交型网络应用程序的一个非常典型的特性是能够在你已经熟悉的应用程序上找到其他社交网络上的用户。这有助于您为应用程序实现任何类型的友谊/关注者模型。没有人喜欢在新平台上没有朋友，所以为什么不与您在其他地方已经交过的朋友联系呢？

通过找到用户在 Twitter 上正在关注的账户和当前存在于 Dinnerly 应用程序中的用户的交集，这相对容易实现。

### 注意

两个集合 A 和 B 的交集 C 是存在于 A 和 B 中的共同元素的集合，没有其他元素。

如果您还不了解数学集合的基本概念以及可以对其执行的操作，那么应该在您的阅读列表中加入一个关于天真集合论的入门课程。

我们首先添加一个路由处理程序，经过身份验证的用户可以查询该处理程序，以查找他们在`application/users.views.py`模块中的共同朋友列表。

```py
from flask import abort, render_template
from flask.ext.login import login_required

# …

@users.route('/twitter/find-friends')
@login_required
def twitter_find_friends():
    """Find common friends."""

    if not current_user.twitter:
        abort(403)

    twitter_user_id = current_user.twitter.twitter_user_id

    # This will only query 5000 Twitter user IDs.
    # If your users have more friends than that,
    # you will need to handle the returned cursor
    # values to iterate over all of them.
    response = twitter.get(
        'friends/ids?user_id={}'.format(twitter_user_id))

    friends = response.json().get('ids', list())
    friends = [int(f) for f in friends]

    common_friends = User.query.filter(
        User.twitter_user_id.in_(friends))

    return render_template('users/friends.html',
        friends=common_friends)
```

### 注意

在前面的方法中，我们使用了简单的`abort()`调用，但是没有阻止您创建模板，这些模板会呈现附加信息，以帮助最终用户理解为什么某个操作失败了。

前面的视图函数使用了我们可靠的 Flask-Login 扩展中的`login_required`装饰器进行包装，以确保对此路由的任何请求都是由经过身份验证的用户发出的。未经身份验证的用户由于某种明显的原因无法在 Dinnerly 上找到共同的朋友。

然后，我们确保经过身份验证的用户已连接了一组 Twitter OAuth 凭据，并取出`twitter_user_id`值，以便我们可以正确构建 Twitter API 请求，该请求要求用户的 ID 或`screen_name`。

### 提示

虽然`screen_name`可能比长数字标识符更容易调试和推理，但请记住，一个人随时可以在 Twitter 上更新`screen_name`。如果您想依赖这个值，您需要编写一些代码来验证并在远程服务上更改时更新本地存储的`screen_name`值。

一旦对远程服务上账户关注的人的 Twitter ID 进行了`GET`请求，我们解析这个结果并构建一个整数列表，然后将其传递给 User-mapped 类上的 SQLAlchemy 查询。现在我们已经获得了一个用户列表，我们可以将这些传递给我们的视图（我们不会提供实现，这留给读者作为练习）。

当然，找到共同的朋友只是方程的一半。一旦我们在 Twitter 上找到了我们的朋友，下一步就是在 Dinnerly 上也关注他们。为此，我们需要向我们的应用程序添加一个（最小的！）社交组件，类似于我们在上一章中实现的内容。

这将需要添加一些与数据库相关的实体，我们可以使用更新/添加相关模型的常规程序，然后重新创建数据库模式，但我们将利用这个机会来探索一种更正式的跟踪模式相关变化的方法。

# 插曲 - 数据库迁移

在应用程序开发的世界中，我们使用各种工具来跟踪和记录随时间变化的代码相关变化。一般来说，这些都属于版本控制系统的范畴，有很多选择：Git、Mercurial、Subversion、Perforce、Darcs 等。每个系统的功能略有不同，但它们都有一个共同的目标，即保存代码库的时间点快照（或代码库的部分，取决于所使用的工具），以便以后可以重新创建它。

Web 应用程序的一个方面通常难以捕捉和跟踪是数据库的当前状态。过去，我们通过存储整个 SQL 快照以及应用程序代码来解决这个问题，并指示开发人员删除并重新创建他们的数据库。对此的下一级改进将是创建一些小型基于 SQL 的脚本，应按特定顺序逐渐构建底层模式，以便在需要修改时，将另一个小型基于 SQL 的脚本添加到列表中。

虽然后一种方法非常灵活（它几乎可以适用于任何依赖关系数据库的应用程序），但是稍微抽象化，可以利用我们已经使用的 SQLAlchemy 对象关系模型的功能，这将是有益的。

## Alembic

这样的抽象已经存在，它叫做 Alembic。这个库由 SQLAlchemy 的相同作者编写，允许我们创建和管理对应于我们的 SQLAlchemy 数据模型所需的模式修改的变更集。

和我们在本书中讨论过的大多数库一样，Flask-Alembic 也被封装成了一个 Flask 扩展。让我们在当前的虚拟环境中安装它：

```py
$ pip install flask-alembic

```

由于大多数 Flask-Alembic 的功能可以和应该通过 CLI 脚本来控制，所以该软件包包括了启用 Flask-Script 命令的钩子。因此，让我们也安装这个功能：

```py
$ pip install flask-script

```

我们将创建我们的`manage.py` Python 脚本来控制我们的 CLI 命令，作为我们`application/包`的兄弟，并确保它包含用于集成 Flask-Alembic 的 db 钩子：

```py
from flask.ext.script import Manager, Shell, Server
from application import create_app, db
from flask_alembic.cli.script import manager as alembic_manager

# Create the `manager` object with a
# callable that returns a Flask application object.
manager = Manager(app=create_app)

def _context():
    """Adds additional objects to our default shell context."""
    return dict(db=db)

if __name__ == '__main__':
 manager.add_command('db', alembic_manager)
    manager.add_command('runserver', Server(port=6000))
    manager.add_command('shell', Shell(make_context=_context))
    manager.run()
```

现在我们已经安装了这两个扩展，我们需要配置 Flask-Alembic 扩展，以便它了解我们的应用对象。我们将在应用程序工厂函数中以通常的方式来做这个：

```py
# …
from flask.ext.alembic import Alembic

# …
# Intialize the Alembic extension
alembic = Alembic()

def create_app(config=None):
    app = Flask(__name__, static_folder=None)

    if config is not None:
        app.config.from_object(config)

    import application.users.models
    import application.recipes.models
       # …
 alembic.init_app(app)

    from application.users.views import users
    app.register_blueprint(users, url_prefix='/users')

    return app
```

让我们捕获当前数据库模式，这个模式是由我们在应用程序中定义的 SQLAlchemy 模型描述的：

```py
$ python manage.py db revision 'Initial schema.'

```

这将在`migrations/文件夹`中创建两个新文件（在第一次运行此命令时创建），其中一个文件将以一堆随机字符开头，后跟`_initial_schema.py`。

### 注意

看起来随机的字符实际上并不那么随机：它们是基于哈希的标识符，可以帮助迁移系统在多个开发人员同时为应用程序的不同部分工作迁移时以更可预测的方式运行，这在当今是相当典型的。

另一个文件`script.py.mako`是 Alembic 在调用命令时将使用的模板，用于生成这些自动修订摘要。这个脚本可以根据您的需要进行编辑，但不要删除任何模板`${foo}`变量！

生成的迁移文件包括两个函数定义：`upgrade()`和`downgrade()`。当 Alembic 获取当前数据库修订版（此时为`None`）并尝试将其带到目标（通常是最新）修订版时，将运行升级函数。`downgrade()`函数也是如此，但是方向相反。拥有这两个函数对于回滚类型的情况非常方便，当在包含不同迁移集的代码分支之间切换时，以及其他一些边缘情况。许多开发人员忽略了生成和测试降级迁移，然后在项目的生命周期的后期非常后悔。

根据您使用的关系数据库，您的确切迁移可能会有所不同，但它应该看起来类似于这样：

```py
"""Initial schema.

Revision ID: cd5ee4319a3
Revises:
Create Date: 2015-10-30 23:54:00.990549

"""

# revision identifiers, used by Alembic.
revision = 'cd5ee4319a3'
down_revision = None
branch_labels = ('default',)
depends_on = None

from alembic import op
import sqlalchemy as sa

def upgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=40), nullable=True),
    sa.Column('created_on', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('facebook_connection',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('facebook_id', sa.Integer(), nullable=False),
    sa.Column('access_token', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id')
    )
    op.create_table('recipe',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(), nullable=True),
    sa.Column('ingredients', sa.Text(), nullable=True),
    sa.Column('instructions', sa.Text(), nullable=True),
    sa.Column('created_on', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        op.f('ix_recipe_created_on'), 'recipe',
        ['created_on'], unique=False)
    op.create_table('twitter_connection',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('screen_name', sa.String(), nullable=False),
    sa.Column('twitter_user_id', sa.Integer(), nullable=False),
    sa.Column('oauth_token', sa.String(), nullable=False),
    sa.Column('oauth_token_secret', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id')
    )
    ### end Alembic commands ###

def downgrade():
    ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('twitter_connection')
    op.drop_index(
        op.f('ix_recipe_created_on'), table_name='recipe')
    op.drop_table('recipe')
    op.drop_table('facebook_connection')
    op.drop_table('user')
    ### end Alembic commands ###
```

现在，在这个脚本中有很多事情要做，或者至少看起来是这样。`upgrade()`函数中正在发生的是创建与我们在应用程序中定义的模型元数据和属于它们的字段相对应的表。通过比较当前模型定义和当前活动数据库模式，Alembic 能够推断出需要生成什么，并输出所需的命令列表来同步它们。

如果您熟悉关系数据库术语（列、主键、约束等），那么大多数语法元素应该相对容易理解，您可以在 Alembic 操作参考中阅读它们的含义：[`alembic.readthedocs.org/en/latest/ops.html`](http://alembic.readthedocs.org/en/latest/ops.html)

生成了初始模式迁移后，现在是应用它的时候了：

```py
$ python manage.py db upgrade

```

这将向您在 Flask-SQLAlchemy 配置中配置的关系型数据库管理系统发出必要的 SQL（基于生成的迁移）。

# 摘要

在这个相当冗长且内容丰富的章节之后，您应该会对 OAuth 及与 OAuth 相关的实现和一般术语感到更加放心，此外，数据库迁移的实用性，特别是由 Alembic 生成的与应用程序模型中声明的表和约束元数据同步的迁移风格。

本章从深入探讨 OAuth 授权授予流程和术语开始，考虑到 OAuth 的复杂性，这并不是一件小事！一旦我们建立了一定的知识基础，我们就实现了一个应用程序，利用 Flask-OAuthlib 为用户提供了创建账户并使用 Twitter 和 Facebook 等第三方服务进行登录的能力。

在完善示例应用程序的数据处理部分之后，我们转向了 Alembic，即 SQLAlchemy 数据迁移工具包，以将我们模型中的更改与我们的关系型数据库同步。

在本章开始的项目对于大多数具有社交意识的网络应用程序来说是一个很好的起点。我们强烈建议您利用本章和前几章学到的知识来创建一个现代、经过高度测试的、功能齐全的网络应用程序。
