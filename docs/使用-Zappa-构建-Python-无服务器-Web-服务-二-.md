# 使用 Zappa 构建 Python 无服务器 Web 服务（二）

> 原文：[`zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09`](https://zh.annas-archive.org/md5/3c97e70c885487f68835a4d0838eee09)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Zappa 构建基于 Flask 的 REST API

到目前为止，我们已经看到了如何开发基于 Flask 的应用程序，并在无服务器基础架构上部署它，我们已经创建了一个完整的 Web 应用程序以及 HTML 渲染过程，并且我们已经使用了各种 Flask 扩展以非常高效的方式构建了应用程序。

在本章中，我们将开发基于 Flask 的 RESTful API。这将涵盖使用 Flask 实现 REST API 并使用 Zappa 部署的 REST API。在第一章中，*无服务器的亚马逊网络服务*，我们看到了集成 AWS Lambda 和 API Gateway 的手动过程，所以现在我们将使用 Zappa 以自动化方式部署 REST API。Zappa 将通过配置代理设置来处理 Flask REST API 与 API Gateway 的集成，以传递请求以调用 Lambda 函数。

让我们继续我们的旅程，开发基于无服务器架构的 REST API。

在本章中，我们将涵盖以下主题：

+   安装和配置 Flask

+   设计 REST API

+   集成 Zappa

+   使用 Zappa 构建、测试和部署 REST API

# 技术要求

在开始实际实现之前，我们需要一些先决条件来创建基于 Flask 的 REST API：

+   Ubuntu 16.04 LTS

+   Python 3.6

+   虚拟环境

+   Flask 0.12.2

+   Flask-JWT 0.3.2

+   Flask-SQLAlchemy 2.3.2

+   Flask-Migrate 2.1.1

+   Flask-RESTful 0.3.6

+   Zappa 0.45.1

+   Flask

+   Flask 扩展

# 安装和配置 Flask

我们将开发一个基于 Flask 的 REST API，将其部署为 AWS Lambda 上的无服务器。因此，在这里，安装和配置 Flask 将在虚拟环境中进行。

我们将创建一个虚拟环境，并使其能够安装所有必需的软件包。可以使用以下命令完成：

```py
virtualenv .env -p python3.6
source .env/bin/activate
```

现在，我们将列出`requirements.txt`文件中的所有必需软件包，并一次性安装所有软件包。以下描述了`requirements.txt`文件的内容：

```py
Flask==0.12.2
Flask-JWT==0.3.2
Flask-SQLAlchemy==2.3.2
Flask-Migrate==2.1.1
flask-restful==0.3.6
zappa==0.45.1

```

现在，我们可以使用以下命令安装所有这些软件包：

```py
$ pip install -r requirements.txt
```

这是将在虚拟环境中安装的所有软件包。现在，让我们在下一节详细解释这些软件包。

# Flask 扩展

Flask 有许多可用的扩展，可以增强任何所需功能的能力。在我们的应用程序中，我们将使用多个扩展，如前一节中所述。这些扩展遵循一个通用模式，以便我们可以将它们与 Flask 应用程序对象集成。

我们将设计一个基于 Flask 的 REST API 应用程序，该应用程序将通过遵循 REST API 通信标准和验证，在 Todo 模型上具有基本的身份验证、授权和 CRUD 操作。

让我们在接下来的章节中看看这些扩展的用法。

# Flask-JWT

Flask-JWT 扩展在 Flask 环境中启用了**JWT**（**JSON Web Token**）功能。在设计 REST API 时，JWT 令牌对于验证和授权 API 访问起着重要作用。我们将在下一节中详细描述 JWT。

# 学习 JWT

**JWT**代表**JSON Web Token**。这是一种标准模式，用于实现 REST API 接口的安全性和真实性访问。JWT 令牌是服务器应用程序发出的数据的编码形式，用于验证客户端访问。客户端需要在 HTTP 请求中添加 JWT 令牌作为授权标头。

我们将使用 JWT 令牌来验证 REST API 的访问。如果您需要详细了解 JWT 机制，我建议阅读[`jwt.io/introduction/`](https://jwt.io/introduction/)上的 JWT 文档。

# Flask-RESTful

Flask-RESTful 扩展旨在使用 Flask 框架实现 REST API。该扩展遵循标准的 REST API 实现模式，并提供了一种实现 REST API 的简单方法。在实现 REST API 之前，您必须对 REST API 标准有基本的了解，因此让我们来看看 REST API 的基础知识。

# 开始 REST

**REST**代表**REpresentational State Transfer.**它是一个明确定义的标准，用于实现服务器-客户端通信以持久化数据。REST 遵循**JSON**（**JavaScript 对象表示**）数据表示格式来交换数据。

REST 在 HTTP 方法上定义了一些动词，用于执行 CRUD 操作，例如：

+   `GET`：检索记录列表和根 URL 中带有后缀 ID 参数的特定记录，还返回带有 200 状态代码的响应

+   `POST`：在服务器上创建记录，并返回带有 201 状态代码的响应

+   `PUT`：更新服务器上的所有记录字段，并返回带有 200 状态代码的响应

+   `PATCH`：更新服务器上记录集中的特定字段，并返回带有 200 状态代码的响应

+   `DELETE`：通过 URL 中的记录特定 ID 的帮助删除整个记录集，并返回带有 204 状态代码的响应

现在是时候看一些实际工作了。让我们继续下一节。

# 设计 REST API

我们将设计一个 REST API，用于对我们的 todos 模型执行 CRUD 操作。我们的应用程序将具有基本的身份验证和授权工作流，以保护 REST API 端点。

以下是我们应用程序的脚手架：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00047.jpeg)

```py
__init__.py, where we configured the Flask application object with extensions and the config object.
```

文件—`app`/`__init__.py`:

```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt import JWT, jwt_required, current_identity

from app.config import config

db = SQLAlchemy()
migrate = Migrate()

def create_app(environment):
    app = Flask(__name__)
    app.config.from_object(config[environment])

    db.init_app(app)
    migrate.init_app(app, db=db)

    from .auth.models import User

    def authenticate(email, password):
        data = request.json
        user = User.query.filter_by(email=data['email']).first()
        if user is not None and user.verify_password(data['password']):
            return user

    def identity(payload):
        user_id = payload['identity']
        return User.query.filter_by(id=user_id).first()

    jwt = JWT(app, authenticate, identity)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .todo import todo as todo_blueprint
    app.register_blueprint(todo_blueprint)

    return app
```

我们配置了 Flask 扩展，如 Flask-SQLAlchemy 和 Flask-Migration，这些都很简单。Flask-JWT 集成需要更多的工作，因为我们需要定义`authenticate`和`identity`方法，并在初始化 JWT 对象时将它们用作参数。这些方法负责对用户进行身份验证和识别用户。

除了扩展集成，我们将创建`auth`和`todoapps`作为 Flask 蓝图对象，并使用`register_blueprint`方法将它们注册到 Flask 应用程序对象中。

让我们详细描述每个包及其用途。

# 配置应用程序设置

在`config`包中，我们定义了应用程序级别的配置，根据定义的环境进行隔离。以下是`config.py`文件的内容。

文件—`config/config.py`:

```py
import os
from shutil import copyfile

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

def get_sqlite_uri(db_name):
    src = os.path.join(BASE_DIR, db_name)
    dst = "/tmp/%s" % db_name
    copyfile(src, dst)
    return 'sqlite:///%s' % dst

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(24)
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_RECORD_QUERIES = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    DEBUG = True
    BUNDLE_ERRORS = True
    SQLALCHEMY_DATABASE_URI = get_sqlite_uri('todo-dev.db')

class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = get_sqlite_uri('todo-prod.db')

config = {
    'dev': DevelopmentConfig,
    'prod': ProductionConfig,
}
```

`config`文件公开了`config`对象，其中包含根据您的环境不同的配置对象。类似地，您可以根据需要添加更多环境。

`get_sqlite_uri`方法被定义为将`db`文件设置在`tmp`目录中，因为 AWS Lambda 要求在执行时将 SQLite`.db`文件保存在内存中。

```py
BaseModel, which was inspired by Django's standard pattern to perform save, update, and delete operations. We can add more generic features if required.
```

文件—`config/models.py`:

```py

from app import db

class BaseModel:
    """
    Base Model with common operations.
    """

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def save(self):
        db.session.add(self)
        db.session.commit()
        return self
```

在这里，我们将`db`会话操作组合在一起，以执行特定的事务，如保存、更新和删除。这将帮助我们扩展模型类的功能。

# 实施认证

认证是保护 REST API 免受未经授权访问的重要功能。因此，为了实现认证层，我们将使用 JWT 机制。在这里，我们将设计两个 REST API，用于注册用户和登录访问。

```py
User model.
```

文件—`auth/models.py`:

```py
import re
from datetime import datetime

from app.config.models import BaseModel
from sqlalchemy.orm import synonym
from werkzeug.security import generate_password_hash, check_password_hash
from app import db

class User(BaseModel, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    _email = db.Column('email', db.String(64), unique=True)
    password_hash = db.Column(db.String(128))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User {0}>'.format(self.email)

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, email):
        if not len(email) <= 64 or not bool(re.match(r'^\S+@\S+\.\S+$', email)):
            raise ValueError('{} is not a valid email address'.format(email))
        self._email = email

    email = synonym('_email', descriptor=email)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        if not bool(password):
            raise ValueError('no password given')

        hashed_password = generate_password_hash(password)
        if not len(hashed_password) <= 128:
            raise ValueError('not a valid password, hash is too long')
        self.password_hash = hashed_password

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            'email': self.email
        }
```

这是一个基本的`User`模型，只有两个字段，即`email`和`password`。现在，我们将设计一个注册 API 和一个登录 API。注册 API 将只接受两个参数，电子邮件和密码，并将在数据库中创建一个用户记录。登录 API 将用于验证用户的凭据，并返回一个 JWT 令牌，该令牌将与其他 API 一起作为授权标头使用。

让我们创建注册和登录 API。以下是资源文件的代码片段，其中包括 API 实现逻辑的内容。

文件 - `auth/resources.py`：

```py
from flask import request, jsonify
from flask_restful import Resource, reqparse, abort
from flask_jwt import current_app
from app.auth.models import User

def generate_token(user):
    """ Currently this is workaround
    since the latest version that already has this function
    is not published on PyPI yet and we don't want
    to install the package directly from GitHub.
    See: https://github.com/mattupstate/flask-jwt/blob/9f4f3bc8dce9da5dd8a567dfada0854e0cf656ae/flask_jwt/__init__.py#L145
    """
    jwt = current_app.extensions['jwt']
    token = jwt.jwt_encode_callback(user)
    return token

class SignUpResource(Resource):
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('email', type=str, required=True)
    parser.add_argument('password', type=str, required=True)

    def post(self):
        args = self.parser.parse_args()
        if not User.query.filter_by(email=args['email']).scalar():
            User(
                email = args['email'],
                password = args['password']
            ).save()
            return {'message': 'Sign up successfully'}
        abort(400, message='Email already exists.')

class LoginResource(Resource):
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('email', type=str, required=True)
    parser.add_argument('password', type=str, required=True)

    def post(self):
        args = self.parser.parse_args()
        user = User.query.filter_by(email=args['email']).first()
        if user is not None and user.verify_password(args['password']):
            token = generate_token(user)
            return jsonify({'token': token.decode("utf-8")})
        abort(400, message='Invalid credentials')
```

Flask-RESTful 提供了一个`Resource`类，用于定义 API 资源。它遵循 REST 标准，并提供了一个简单的方法来创建 API。由于我们将在 HTTP 的大多数`request`方法上使用注册 API，我们创建了一个`post`方法。同样，我们设计了登录 API，我们在那里验证用户的凭据并返回一个令牌。

我们必须返回自定义方法来生成令牌，因为在撰写本文时，Flask-JWT `PyPI`仓库尚未发布更新版本，尽管这个功能已经添加到 GitHub 仓库中。

```py
auth/__init__.py file.
```

文件 - `auth/__init__.py`：

```py
from flask import Blueprint
from flask_restful import Api
from .resources import SignUpResource, LoginResource

auth = Blueprint('auth', __name__)
auth_api = Api(auth, catch_all_404s=True)

auth_api.add_resource(SignUpResource, '/signup', endpoint='signup')
auth_api.add_resource(LoginResource, '/login', endpoint='login')
```

在这里，我们创建了`Blueprint`对象并对其进行了配置。Flask-RESTful 提供了一个`API`类，使用这个类，我们注册了我们的注册和登录资源。就是这样。现在，我们可以用 JSON 数据访问注册和登录 URL 来执行操作。在部署过程之后，我们将对这些 REST API 进行完整演示。

# 实现 todo API

让我们开始 todo API 的实现。我们需要一个 todo REST API 端点来执行 CRUD 操作。根据 REST 标准，只会有一个端点 URL，比如`/todos/<todo_id>/`。这个端点将用于将 todo 数据持久化到数据库中。我们需要有一个 Todo 模型来持久化数据。以下是 Todo 模型的代码片段。

文件 - `todo/models.py`：

```py
from datetime import datetime
from app import db
from app.config.models import BaseModel

class Todo(db.Model, BaseModel):
    __tablename__ = 'todo'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    is_completed = db.Column(db.Boolean, default=False)
    created_by = db.Column(db.String(64), db.ForeignKey('user.email'))
    user = db.relationship('User', backref=db.backref('todos', lazy=True))

    def __init__(self, title, created_by=None, created_at=None):
        self.title = title
        self.created_by = created_by

    def __repr__(self):
        return '<{0} Todo: {1} by {2}>'.format(
            self.status, self.title, self.created_by or 'None')

    @property
    def status(self):
        return 'completed' if self.is_completed else 'open'

    def completed(self):
        self.is_completed = True
        self.save()

    def reopen(self):
        self.is_completed = False
        self.save()

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'created_by': self.created_by,
            'status': self.status,
        }
resources.py, which contains the todo's REST API.
```

文件 - `todo/resources.py`：

```py
from flask import request
from flask_restful import Resource, reqparse
from flask_jwt import current_identity, jwt_required

from .models import Todo

class TodoResource(Resource):

    decorators = [jwt_required()]

    def post(self):
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument('title', type=str, required=True)

        args = parser.parse_args(strict=True)
        todo = Todo(args['title'], created_by=current_identity.email).save()
        return todo.to_dict(), 201

    def get(self, todo_id=None):
        if todo_id:
            todos = Todo.query.filter_by(id=todo_id, created_by=current_identity.email)
        else:
            todos = Todo.query.filter_by(created_by=current_identity.email)
        return [todo.to_dict() for todo in todos]

    def patch(self, todo_id=None):
        parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument(
            'status',
            choices=('open', 'completed'),
            help='Bad choice: {error_msg}. Valid choices are \'open\' or \'completed\'.',
            required=True)

        if not todo_id:
            return {'error': 'method not allowed'}, 405
        args = parser.parse_args(strict=True)
        todo = Todo.query.filter_by(id=todo_id, created_by=current_identity.email).scalar()
        if args['status'] == "open":
            todo.reopen()
        elif args['status'] == 'completed':
            todo.completed()
        else:
            return {'error':'Invalid data!'}, 400
        return todo.to_dict(), 202

    def delete(self, todo_id=None):
        if not todo_id:
            return {'error': 'method not allowed'}, 405
        Todo.query.filter_by(id=int(todo_id), created_by=current_identity.email).delete()
        return {}, 204
```

在这里，我们定义了`TodoResource`类，它将处理`GET`、`POST`、`PUT`和`DELETE`的 HTTP 请求。根据请求类型，我们执行 CRUD 操作。我们还使用`reqparse`来定义从 HTTP 请求中所需数据的验证。

为了保护`TodoResource`，我们在`TodoResource`类的装饰器列表中添加了`jwt_required`方法，这将应用于所有相关方法。现在，`TodoResource` API 只能在有效的授权头部下使用，否则将会响应未经授权的访问错误。

我们将在接下来的章节中看到这个完整的工作过程。

# 使用 Zappa 构建、测试和部署 REST API

我们已经完成了开发，现在是时候将应用程序作为无服务器部署在 AWS Lambda 上了。我们已经在前一章中描述了配置 Zappa 及其相关配置的先决条件，所以这里我假设你已经配置了 Zappa 以及 AWS 配置。

# 配置 Zappa

一旦你配置了 Zappa，你可以为你的项目初始化 Zappa。你需要运行`zappa init`命令，并按照 CLI 问卷的指引来配置你的项目与 Zappa。我按照 Zappa 建议的默认配置设置进行了配置。`zappa init`命令将生成`zappa_settings.json`文件，我们可以根据需要自由修改这个文件。

```py
zappa_settings.json file.
```

文件 - `zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "run.app",
        "aws_region": "ap-south-1",
        "profile_name": "default",
        "project_name": "chapter-4",
        "runtime": "python3.6",
        "s3_bucket": "zappa-5xvirta98"
    }
}
```

Zappa 维护这个 JSON 文件以执行部署过程。现在，我们将继续部署应用程序。

# 使用 Zappa 启动部署

一旦你完成了 Zappa 的初始化，就该部署应用程序了。Zappa 提供了一个`zappa deploy`命令来部署应用程序。这个命令将执行部署过程，它将创建部署包作为 ZIP 文件，将其推送到 AWS S3，并配置 AWS Lambda 与 API Gateway。我们在第一章中详细描述了完整的部署过程。

一旦我们用`zappa deploy dev`命令运行这个，我们的应用程序将作为无服务器应用程序托管在 AWS Lambda 上。如果你想重新部署相同的应用程序，那么你需要运行`zappa update dev`命令，这将更新现有的应用程序。

让我们在下一节中看一下部署的应用程序演示。

# 演示部署的应用程序

Zappa 为部署的应用程序生成一个随机 URL，并且在每次新部署时都会生成 URL。但是，如果您只是更新部署，则不会更改 URL。这是我们从 Zappa 部署过程中获得的 URL：[`jrzlw1zpdi.execute-api.ap-south-1.amazonaws.com/dev/`](https://jrzlw1zpdi.execute-api.ap-south-1.amazonaws.com/dev/)。我们已经使用一些端点编写了 auth 和 todo API，因此您在基本 URL 上看不到任何内容。我们将使用在资源中定义的 API 端点。 

# 注册 API

我们设计了带有端点`/auth/signup`的注册 API，它期望两个参数—`email`和`password`。此端点负责在数据库中创建用户记录。一旦我们获得成功的响应，我们可以使用相同的用户凭据执行登录并访问其他 API。

以下是注册 API 的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00048.jpeg)

在这里，我们使用高级 REST 客户端应用程序测试 API。如您所见，我们正在使用注册 API 创建用户记录。注册 API 以状态码 200 进行响应。

# 登录 API

现在，我们在数据库中有一个用户记录，我们可以使用它来执行登录操作。登录 API 负责验证用户的凭据并返回 JWT 令牌。此 JWT 令牌将用于授权 todos API。以下是通过 REST 客户端使用的登录 API 的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00049.jpeg)

在这里，您可以看到登录 API 的执行，因为我们获得了将用于授权访问待办事项 API 的 JWT 令牌。

# 待办事项 API

现在我们通过登录 API 获得了 JWT 令牌，让我们执行待办事项 API。然而，在这里，我们将看到待办事项 API 的不同场景。我们的待办事项 API 有一个名为`todos/<todo_id>`的端点。

# 没有授权的待办事项 API

让我们尝试在不提供授权标头的情况下使用待办事项 API：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00050.jpeg)

如您所见，我们从应用程序得到了未经授权的错误。现在，我们将提供带有 JWT 令牌的授权标头。

# 带有授权标头的待办事项 API

我们将使用登录 API 返回的 JWT 令牌，并设置授权标头。授权标头的值将是`JWT <token>`。现在，让我们执行带有 CRUD 操作的 API。

`GET`请求如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00051.jpeg)

在这里，我们得到了数据库中所有待办事项记录的列表。由于我们设置了授权标头，我们获得了访问权限。

`POST`请求如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00052.jpeg)

在这里，我们创建了一个新的待办事项记录，并获得了状态码为`201`的响应。现在，使用基本 URL，我们可以执行`GET`和`POST`请求，但是，要执行对特定记录的`GET`、`PUT`和`DELETE`功能，我们需要在 URL 中提到`todo_id`。

没有有效负载数据的`POST`请求如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00053.jpeg)

在这里，由于我们没有提供任何有效负载，我们得到了验证错误。我们使用`flask_restful`库的`reqparse`模块来处理此验证。

带有待办事项 ID 的`GET`请求如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00054.jpeg)

您可以看到我们在 URL 中使用了待办事项 ID 来查看特定记录集。

`PATCH`请求如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00055.jpeg)

在这里，我们更新了待办事项的状态，并将待办事项记录标记为已完成。

带有无效数据的`PATCH`请求如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00056.jpeg)

在这里，由于我们使用`reqparse`模块定义了必需的选项，我们得到了验证错误，如下所示：

```py
parser = reqparse.RequestParser(bundle_errors=True)
        parser.add_argument(
            'status',
            choices=('open', 'completed'),
            help='Bad choice: {error_msg}. Valid choices are \'open\' or \'completed\'.',
            required=True)
```

`DELETE`请求如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00057.jpeg)

最后，我们使用 HTTP `DELETE`请求删除了记录。就是这样！我们已经完成了 REST API 的实现。

# 摘要

在本章中，我们学习了如何创建基于 Flask 的 REST API，并使用一些扩展进行配置。在 Flask-JWT 扩展的帮助下，我们实现了安全性。Flask-RESTful 扩展提供了一个简单的接口来设计 REST API。最后，我们配置了 Zappa 来在无服务器环境中部署应用程序。

在下一章中，我们将看到 Django 应用程序开发作为 AWS Lambda 上的无服务器应用程序。敬请关注。

# 问题

1.  我们为什么需要 JWT 实现？

1.  Zappa 设置文件中的`function_name`参数是什么？


# 第五章：使用 Zappa 构建 Django 应用程序

在本章中，我们将创建一个基于 Django 的图库应用程序，用户可以创建相册并上传图片。在 Django 中工作时，为静态和媒体内容提供服务是非常有趣和具有挑战性的。通常，开发人员将图像存储在文件存储中，并通过 URL 服务器提供。在这里，我们将在 AWS S3 中存储图像，并通过 AWS CloudFront 服务提供的 CDN 网络进行服务。

本章我们将涵盖的主题包括以下内容：

+   安装和配置 Django

+   设计图库应用程序

+   通过 AWS CloudFront CDN 提供静态和媒体文件

+   设置静态和媒体文件

+   集成 Zappa

+   使用 Zappa 构建、测试和部署 Django 应用程序

+   Django 管理命令

# 技术要求

在继续之前，让我们满足本章所需的一些先决条件。我们将开发一个基于 Django 的无服务器应用程序，因此我们需要满足以下用于开发此应用程序的要求：

+   Ubuntu 16.04/Mac/Windows

+   Pipenv 工具

+   Django

+   Django 存储

+   Django Imagekit

+   Boto3

+   Zappa

这些软件包是本章所需的软件包，我们将使用 pipenv 工具安装和配置这些软件包。现在我们将详细探讨配置。

# 安装和配置 Django

配置任何 Python 项目都需要遵循维护必要软件包版本的标准。许多开发人员喜欢维护`requriements.txt`文件，这有助于他们保持应用程序的稳定性。`requirements.txt`中特定软件包的任何版本升级可能会破坏整个应用程序。这就是开发人员严格遵循此标准以维护其应用程序的稳定版本的原因。

# 设置虚拟环境

我一直在遵循传统模式，直到我遇到了一个非常酷的工具，改变了我对维护`requirements.txt`文件的传统方法。现在你不再需要`requirements.txt`了。它叫做**pipenv**；我喜欢使用它。

Pipenv 是一个受多种不同语言的包管理工具启发的 Python 包管理工具。Pipenv 是 Python.org 官方推荐的（[`www.python.org/`](https://www.python.org/)）。这个工具赋予了管理 Python 包的标准。

# 安装 pipenv

您可以从任何地方初始化虚拟环境，并且它将跟踪每个软件包的安装。

首先，我们需要在系统级安装`pipenv`。因此，如果您使用的是 macOS，则可以像这样使用 Homebrew 安装`pipenv`：

```py
$ brew install pipenv
```

如果您使用的是 Ubuntu 17.10，则可以简单地添加 PPA 存储库并使用`apt`命令进行安装，如下所示：

```py
$ sudo apt install software-properties-common python-software-properties
$ sudo add-apt-repository ppa:pypa/ppa
$ sudo apt update
$ sudo apt install pipenv
```

您可以简单地在系统级别通过`pip`安装它，而不是从活动虚拟环境中使用`pip`。看一下这行代码：

```py
pip install pipenv
```

系统级安装将是在不使用任何虚拟环境的情况下进行的安装。它安装在系统的`bin`目录中，并且应该可以从终端控制台执行。

现在，您可以通过在终端控制台上执行`pipenv`命令来查看有关`pipenv`命令的详细信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00058.jpeg)

在这里，您可以看到有几个可用的命令，提供了一种非常灵活的方式来处理虚拟环境。

# 配置和安装软件包

现在，我们将为我们的项目创建一个虚拟环境并安装所需的软件包。

以下屏幕截图提到了虚拟环境创建过程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00059.jpeg)

如您从前面的屏幕截图中所见，我们使用以下命令创建了一个虚拟环境：

```py
$ pipenv --python python3.6
```

我们明确指出了所需的 Python 版本；你也可以指定任何 Python 版本。如果你着急，只想用 Python 版本 2 或 3 初始化，那么你可以运行以下命令：

```py
$ pipenv --two
```

你也可以使用这个：

```py
$ pipenv --three
Pipfile:
```

```py
[[source]]

url = "https://pypi.python.org/simple"
verify_ssl = true
name = "pypi"

[dev-packages]

[packages]

[requires]

python_version = "3.6"
```

它有不同的部分来管理所有的包。现在你可以使用以下命令安装任何包：

```py
 pipenv install <package-name>
```

由于我们将使用 Django 框架，我们将使用 pipenv 来安装 Django，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00060.jpeg)

一旦安装了任何包，`pipenv`就会创建一个`Pipfile.lock`文件。`Pipfile.lock`文件维护了每个安装包的提交哈希和依赖关系。

现在，如果你想激活虚拟环境，不用担心。你可以把一切都交给`pipenv`。`pipenv`提供了一个名为`pipenv shell`的命令，它在内部调用虚拟环境的`activate`命令。现在，你将使用激活的虚拟环境 shell。

不必在 shell 中或激活虚拟环境中，你可以使用命令`pipenv run <command as an argument>`在虚拟环境下执行任何命令，例如：

```py
 pipenv run python manage.py runserver
```

这真的很有趣，不是吗？

安装所有所需的包后，`Pipfile`将如下所示：

文件—`Pipfile`:

```py
[[source]]

url = "https://pypi.python.org/simple"
verify_ssl = true
name = "pypi"

[dev-packages]

[packages]

django = "*"
pylint = "*"
pillow = "*"
zappa = "*"
django-storages = "*"
"boto3" = "*"
boto = "*"
django-imagekit = "*"

[requires]

python_version = "3.6"

```

现在，我们已经完成了所需包的配置和安装。

让我们继续下一节，我们将创建一个基于 Django 的图库应用。

# 设计图库应用

一旦我们完成配置，就可以开始实现应用。`ImageGallery`应用将是直接的——用户可以创建一个新的相册记录，并一次上传多张图片。一旦相册创建完成，我们将在列表视图中显示所有现有的相册记录，以及关联的缩略图。

让我们根据我们的需求来看看实现阶段。

# 设计概述

我将基于 Django 创建一个图库应用。我们将使用 Django admin 来实现 UI。Django admin 有非常漂亮的 UI/UX 设计。因此，我们将创建一些模型，比如一个`PhotoAlbum`模型，它将与`Photo`模型有一对多的关系。

然后我们只需在 Django admin 面板中注册这些模型。一旦我们完成了 admin 配置，我们将配置静态和媒体设置，将动态图片上传到 Amazon S3 存储桶，并通过 CloudFront CDN 网络提供这些静态文件。

让我们仔细看看实现。

# 初始化项目

一旦你配置了`pipenv`，你需要使用命令`pipenv shell`启用虚拟环境。假设你在`pipenv` shell 中，这只是一个激活的虚拟环境。一旦启用虚拟环境，你就可以访问已安装的包。因此，我们将通过执行以下命令创建 Django 项目框架：

```py
django-admin.py startproject <project_name>
```

以下是项目创建过程的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00061.jpeg)

我已经创建了项目和一个应用。从之前的截图中，你可以看到项目和应用文件。

默认情况下，Django 在根`urls.py`文件中启用了 admin 面板。因此，我们不需要再次配置它。

现在让我们进入下一节的模型创建过程。

# 实现模型

我们将创建两个模型——`PhotoAlbum`和`Photo`模型，它们之间有一对多的关系。以下是`gallery/models.py`文件的代码片段：

文件—`gallery/models.py`:

```py
from django.db import models
from django.utils.translation import gettext as _
from imagekit.models import ImageSpecField
from imagekit.processors import ResizeToFill

# Create your models here.

def upload_path(instance, filename):
    return '{}/{}'.format(instance.album.name, filename)

class PhotoAlbum(models.Model):
    name = models.CharField(_('album name'), max_length=50)
    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'photo_album'
        verbose_name = 'photo album'
        verbose_name_plural = 'photo albums'

    def __str__(self):
        return self.name

class Photo(models.Model):
    album = models.ForeignKey(PhotoAlbum, related_name='photos', on_delete=models.CASCADE)
    image = models.ImageField(_('image'), upload_to=upload_path)
    image_thumbnail = ImageSpecField(source='image',
                                      processors=[ResizeToFill(100, 50)],
                                      format='JPEG',
                                      options={'quality': 60})
    created_at = models.DateTimeField(auto_now_add=True, auto_now=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'photo'
        verbose_name = 'photo'
        verbose_name_plural = 'photos'

    def __str__(self):
        return self.image.name.split('/')[1]

```

按计划，我已经创建了两个模型，以及它们的关系。在这里，`PhotoAlbum`很直接，因为它充当父类。`Photo`模型更有趣，因为我们将通过它存储图片。

在`Photo`模型中，我正在使用`django-imagekit`（[`github.com/matthewwithanm/django-imagekit`](https://github.com/matthewwithanm/django-imagekit)）库来创建和存储原始上传图像的缩略图。这非常有趣，因为它有许多功能可以让我们根据需要处理图像。我的意图是创建上传图像的缩略图；因此，我相应地进行了配置。

一旦您完成模型创建，您将需要运行`makemigrations`和迁移命令来创建实际的数据库表。查看以下截图，以了解`makemigrations`命令的过程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00062.jpeg)

一旦我们运行`makemigrations`命令，就可以准备在管理面板中配置这些模型。让我们继续进行下一节关于配置管理面板的部分。

# 与管理面板集成

将模型与 Django 管理面板集成需要在根`urls.py`文件中启用管理 URL 配置。让我们来看一下代码：

文件—`imageGalleryProject/urls.py`：

```py
from django.contrib import admin
from django.urls import path

urlpatterns = [
    path('admin/', admin.site.urls),
]
admin.py file:
```

文件—`gallery/admin.py`：

```py
from django.contrib import admin
from django.utils.html import mark_safe
from gallery.models import PhotoAlbum, Photo
# Register your models here.

class PhotoAdminInline(admin.TabularInline):
    model = Photo
    extra = 1
    fields = ( 'image', 'image_tag', )
    readonly_fields = ('image_tag',)

    def image_tag(self, instance):
        if instance.image_thumbnail.name:
            return mark_safe('<img src="img/%s" />' % instance.image_thumbnail.url)
        return ''
    image_tag.short_description = 'Image Thumbnail'

class PhotoAlbumAdmin(admin.ModelAdmin):
    inlines = [PhotoAdminInline]

admin.site.register(PhotoAlbum, PhotoAlbumAdmin)
```

在这里，我们将`Photo`模型配置为`TabularInline`，这样我们就可以在一个相册下添加多张照片或图片。在将应用程序部署到 AWS Lambda 后，我们将进行完整的工作流程演示。

此时，您可以在本地计算机上运行应用程序并存储图像。但是以后，我们希望部署在 AWS Lambda 上，然后将图像存储在 Amazon S3 存储桶中，并通过 Amazon CloudFront CDN 网络提供服务。

# 应用程序演示

我们已经将模型配置到管理面板中。现在，我们将使用`python manage.py runserver`命令来运行 Django 的本地服务器。它将在`http://locahost:8000 URL`上启动 Django 服务器。

以下是应用程序的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00063.jpeg)

如前面的截图所示，我们正在创建一个相册。我们定义了一对多的关系，并使用`TabularInline`在创建相册时接受多张照片。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00064.jpeg)

添加过程完成后，将出现列表页面。现在，您可以选择新创建的相册来查看或编辑现有的详细信息。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00065.jpeg)

在这里，您可以检查先前上传的图像是否显示为缩略图。我们使用了`django-imagekit`库来配置缩略图图像处理。

现在，我们将在下一节中看到配置 Amazon CloudFront CDN 所需的过程，并将其与我们的应用程序集成。

# 配置 Amazon CloudFront CDN

Amazon CloudFront 是更受欢迎的服务之一。它提供通过 CDN 网络提供静态文件的功能，有助于以更高效的方式分发静态内容，从而提高性能并降低延迟。

配置 Amazon CloudFront 时，我们通过 AWS 用户控制台创建 CloudFront 分发。

# 创建 CloudFront 分发

假设您有有效的 AWS 帐户，您可以使用您的凭据登录 AWS Web 控制台。从服务下拉菜单中选择 CloudFront 服务，然后单击“创建分发”按钮，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00066.jpeg)

在创建分发时，Amazon 提供了两种不同的方法，即 Web 和 RTMP。Web 方法用于需要通过 CDN 网络提供的静态内容，当所有静态文件都驻留在 Amazon S3 存储桶中时使用。RTMP 方法用于分发流媒体文件，允许用户在下载完成之前播放文件。

在我们的情况下，我们将选择 Web 方法，因为我们希望分发静态文件。您可以按照以下截图中显示的方法进行选择：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00067.jpeg)

选择 Web 方法后，将打开创建分发表单页面。在此页面上，我们将选择所需的字段来配置分发。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00068.jpeg)

成功创建云分发后，我们将把分发与我们的 Django 应用集成。

让我们继续下一节，在那里我们将配置应用中的静态和媒体文件。

# 设置静态和媒体文件

在 Django 中配置静态和动态文件是必不可少的。我们如何配置和提供静态和媒体文件会影响应用程序的整体性能。因此，应该以优化的方式来配置静态和媒体文件。让我们对此进行详细讨论。

# 标准配置

Django 有一个标准模式来配置静态和媒体文件。静态和媒体是两个不同的问题，其中静态文件指固定内容，如 HTML、JS、CSS 和图像。Django 在`settings.py`中定义了一些与静态文件相关的配置，并在`urls.py`中配置了 URL。媒体文件指通过上传动态处理的任何文件。Django 有一个非常好的机制来配置和管理静态 HTML、JS、CSS 和图像文件。

通常，默认的 Django 静态文件配置假定您将在静态目录下与代码库一起拥有静态文件，但在我们的情况下，我们希望将所有静态内容放在 Amazon S3 存储桶下，并通过 Amazon CloudFront 分发进行提供。

# django-storage

我们将使用`django-storage`（[`django-storages.readthedocs.io/en/latest/`](http://django-storages.readthedocs.io/en/latest/)），这是一个第三方插件，用于实现自定义存储后端。借助 Django 存储，我们将设置静态和媒体配置。

以下是设置自定义存储静态和媒体文件所需的代码片段：

文件—`gallery/utils.py`：

```py
from django.conf import settings
from storages.backends.s3boto import S3BotoStorage

class StaticStorage(S3BotoStorage):
    location = settings.STATICFILES_LOCATION

    @property
    def connection(self):
        if self._connection is None:
            self._connection = self.connection_class(
                self.access_key, self.secret_key,
                calling_format=self.calling_format, host='s3-ap-south-1.amazonaws.com')
        return self._connection

class MediaStorage(S3BotoStorage):
    location = settings.MEDIAFILES_LOCATION

    @property
    def connection(self):
        if self._connection is None:
            self._connection = self.connection_class(
                self.access_key, self.secret_key,
                calling_format=self.calling_format, host='s3-ap-south-1.amazonaws.com')
        return self._connection
```

现在我们将在`settings.py`文件中配置这两个自定义存储类，如下所示：

文件—`imageGalleryProject/settings.py`：

```py
AWS_HEADERS = {
    'Expires': 'Thu, 31 Dec 2099 20:00:00 GMT',
    'Cache-Control': 'max-age=94608000',
}

AWS_STORAGE_BUCKET_NAME = 'chapter-5'
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_CLOUDFRONT_DOMAIN = 'dl76lqo8jmttq.cloudfront.net'

MEDIAFILES_LOCATION = 'media'
MEDIA_ROOT = '/%s/' % MEDIAFILES_LOCATION
MEDIA_URL = '/%s/%s/' % (AWS_CLOUDFRONT_DOMAIN, MEDIAFILES_LOCATION)
DEFAULT_FILE_STORAGE = 'gallery.utils.MediaStorage'

STATICFILES_LOCATION = 'static'
STATIC_ROOT = '/%s/' % STATICFILES_LOCATION
STATIC_URL = '/%s/%s/' % (AWS_CLOUDFRONT_DOMAIN, STATICFILES_LOCATION)
STATICFILES_STORAGE = 'gallery.utils.StaticStorage'
```

这些是您需要放入`settings.py`中的设置，现在是时候配置`urls.py`了。我建议您更新根`urls.py`，如下所示：

文件—`imageGalleryProject/urls.py`：

```py
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    # ... the rest of your URLconf goes here ...
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
  + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

一旦您配置了 URL，那么您就准备好了。要验证配置，您可以运行`collectstatic`命令，将所有静态文件收集到配置的位置：

```py
$ python manage.py collectstatic
```

此命令将检索属于所述`INSTALL_APPS`的所有静态文件，并将它们上传到`STATIC_ROOT`。现在，当您上传任何文件时，它将被上传到 Amazon S3，并通过 Amazon CloudFront 提供。

现在是时候配置 Zappa 并进行部署了。

# 使用 Zappa 构建、测试和部署 Django 应用

Zappa 配置很简单。Zappa 包也可以在 pip 仓库中找到。但我们将使用 pipenv 来安装它，这可以帮助我们跟踪版本管理。以下是安装 Zappa 所需的命令：

```py
$ pipenv install zappa
```

安装 Zappa 后，您需要使用`zappa init`命令初始化 Zappa。此命令将提示一个 shell 调查问卷，以配置 Zappa 所需的基本信息。让我们看看下一节，我们将讨论 Zappa 的基本配置。

# 配置 Zappa

```py
zappa_settings.json file:
```

```py
{
    "dev": {
        "aws_region": "ap-south-1",
        "django_settings": "imageGalleryProject.settings",
        "profile_name": "default",
        "project_name": "imagegallerypro",
        "runtime": "python3.6",
        "s3_bucket": "chapter-5",
        "remote_env": "s3://important-credentials-bucket/environments.json"
    }
}
```

在这里，我们根据要求定义了配置。由于密钥定义了每个配置，我们可以看到它的用法。考虑以下内容：

+   `aws_region`：Lambda 将上传的 AWS 区域

+   `django_settings`：Django 设置文件的导入路径

+   `profile_name`：在`~/.aws/credentials`文件中定义的 AWS CLI 配置文件

+   `project_name`：上传 Lambda 函数的项目名称

+   `runtime`：Python 运行时解释器

+   `s3_bucket`：创建一个 Amazon S3 存储桶并上传部署包

+   `remote_env`：设置 Amazon S3 位置上传的 JSON 文件中提到的所有键值对的环境变量

在配置信息的帮助下，我们将继续部署。

# 构建和部署

一旦我们完成配置，就可以进行部署。Zappa 提供了两个不同的命令来执行部署，例如`zappa deploy <stage_name>`和`zappa update <stage_name>`。最初，我们将使用`zappa deploy <stage_name>`命令，因为这是我们第一次部署这个 Lambda 应用程序。

如果您已经部署了应用程序并希望重新部署它，那么您将使用`zappa update <stage_name>`命令。在上一章中，我们对 Zappa 的部署过程进行了详细讨论，因此如果需要，您可以参考这一点。

以下是我们部署过程的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00069.jpeg)

如您所见，成功部署后，我们得到了 API 网关端点 URL。让我们通过访问所述 URL 的管理面板来检查部署过程。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00070.jpeg)

哎呀！我们遇到了一个错误。这个错误说我们有一个无效的`HTTP_HOST`，这是真的，因为我们没有在`settings.py`文件的`ALLOWED_HOSTS`列表中配置它，如下所述：

```py
ALLOWED_HOSTS = ['localhost', 'cfsla2gds0.execute-api.ap-south-1.amazonaws.com']
```

这将解决问题。现在，让我们继续查看管理面板：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00071.jpeg)

哎呀！看起来好像我们未能加载静态内容。但是我们已经使用 Amazon S3 和 Amazon CloudFront 配置了静态和媒体内容。

因此，为了解决这个错误，我们需要运行`python manage.py collectstatic`命令。这个命令将把所有静态内容上传到 Amazon S3，并通过 Amazon CloudFront 可用。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00072.jpeg)

哇！我们解决了问题，我们的应用程序已经上线并且是无服务器的。部署真的很容易。希望您喜欢基于 Django 的应用程序的部署。

在这里，我们从未涉及任何服务器软件，如 Apache 或 Nginx 等复杂的配置。Zappa 使得将应用程序部署为无服务器变得非常容易。

现在我们将看看使用 Zappa 还可以做些什么。请参考我们的下一节，了解更多精彩内容！

# 使用 Zappa 进行 Django 管理命令

Zappa 提供了一个功能，可以直接从您的终端控制台在部署的 Lamdba 实例上执行 Django 的`manage`命令操作。通过`zappa manage <stage_name> <manage-command>`，您可以执行并检查您的 Django 应用程序的状态。

以下是执行此命令的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00073.jpeg)

尽管有一些限制。它只适用于 Django 的`manage`命令，因此它只适用于 Django 项目。

要传递任何参数，您可以使用字符串格式的`manage`命令，例如：

```py
$ zappa manage dev "migrate --fake-initial"
```

但对于那些需要用户输入的命令，例如`createsuperuser`，它将没有用处。因此，在这种情况下，您可以以字符串格式编写 Python 脚本，并将其作为参数传递给`zappa invoke <env> '<raw_script>' --raw`。看一下这个截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00074.jpeg)

就是这样。

希望你喜欢。这让开发人员的生活变得轻松。因为我们正在处理无服务器环境，所以可能需要这些功能。

# 摘要

我们学会了如何构建一个无服务器的 Django 应用程序。Zappa 使构建操作变得非常容易，并帮助您进行无服务器部署，非常方便。

在实现无服务器 Django 应用程序时，我们涵盖了所有必要的细节。我解释了为这个应用程序编写的代码；我还在我们的 GitHub 存储库中分享了整个代码库（[`github.com/PacktPublishing/Building-Serverless-Python-Web-Services-with-Zappa/tree/master/chapter_5/imageGalleryProject`](https://github.com/PacktPublishing/Building-Serverless-Python-Web-Services-with-Zappa/tree/master/chapter_5/imageGalleryProject)）。

希望你喜欢这一章。在下一章中，我们将实现相同的应用程序，但作为一个 RESTful API，并看看我们会遇到什么挑战。

# 问题

1.  什么是 Amazon CloudFront？

1.  pipenv 用于什么？


# 第六章：使用 Zappa 构建 Django REST API

在本章中，我们将使用 Django Rest Framework 创建一个 RESTful API。它将基于一个简单的 RESTful API，具有**CRUD**（**创建**，**检索**，**更新**和**删除**）操作。我们可以考虑之前开发的**ImageGallery**应用程序与 REST API 扩展。在这里，我们将为`PhotoAlbum`创建一个 API，用户可以通过 REST API 界面创建新相册以及图片。

本章我们将涵盖以下主题：

+   安装和配置 Django REST 框架

+   设计 REST API

+   使用 Zappa 构建、测试和部署 Django 应用程序

# 技术要求

在继续之前，有一些技术先决条件需要满足。这些先决条件是设置和配置开发环境所必需的。以下是所需软件的列表：

+   Ubuntu 16.04/Mac/Windows

+   Python 3.6

+   Pipenv 工具

+   Django

+   Django Rest Framework

+   Django Rest Framework JWT

+   Django 存储

+   Django Imagekit

+   Boto3

+   Zappa

我们将在虚拟环境中安装这些软件包。在下一节中，我们将看到有关安装过程的详细信息。

# 安装和配置 Django REST 框架

我们已经在第五章的*设置虚拟环境*部分详细介绍了虚拟环境设置过程。您可以按照这些说明配置 pipenv 工具并为本章创建一个新的虚拟环境。让我们转到下一节，使用 pipenv 工具安装所需的软件包。

# 安装所需的软件包

我们将使用 Django REST 框架开发 REST API，因此我们需要使用`pipenv install <package_name>`命令安装以下软件包：

+   `django`

+   `djangorestframework`

+   `djangorestframework-jwt`

+   `django-storages`

+   `django-imagekit`

+   `boto3`

+   `zappa`

您可以通过在空格分隔的其他软件包之后提及其他软件包来一次安装多个软件包，例如`pipenv install <package_one> <package_two> ...`。

安装这些软件包后，我们可以继续实施，并且将有以下提到的`Pipfile`：

文件—`Pipfile`：

```py
[[source]]

url = "https://pypi.python.org/simple"
verify_ssl = true
name = "pypi"

[dev-packages]

[packages]

django = "*"
djangorestframework = "*"
django-storages = "*"
django-imagekit = "*"
"boto3" = "*"
zappa = "*"

[requires]

python_version = "3.6"

```

Pipenv 在`Pipfile.lock`文件中维护版本及其 git 哈希。所以我们不需要担心。

我们已经完成了配置开发环境，现在是时候实施 REST API 了。请继续关注下一节，我们将使用 Django Rest Framework 设计 REST API。

# 设计 REST API

我们将为我们的 ImageGallery 应用程序设计 REST API。我们使用 Django 的管理界面开发了这个应用程序。现在我们将通过 RESTful API 界面扩展 ImageGallery 应用程序的现有实现。在实施解决方案之前，让我们简要介绍一下 Django REST 框架。

# 什么是 Django Rest Framework？

Django Rest Framework 是一个开源库，旨在以乐观的方式实现 REST API。它遵循 Django 设计模式，使用不同的术语。您可以在其文档网站([`www.django-rest-framework.org/#quickstart`](http://www.django-rest-framework.org/#quickstart))找到快速入门教程。

Django Rest Framework 是强大的，支持 ORM 和非 ORM 数据源。它内置支持可浏览的 API 客户端([`restframework.herokuapp.com/`](https://restframework.herokuapp.com/))和许多其他功能。

建议在生产环境中不要使用 Web Browsable API 界面。您可以通过在`settings.py`中设置渲染类来禁用它。

```py
settings.py file.
```

文件—`settings.py`：

```py
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    )
}
```

# 集成 REST 框架

要集成 Django REST Framework，您可以简单地使用 pipenv 包装工具进行安装，就像在之前设置虚拟环境的部分中提到的那样。安装完成后，您可以继续在`INSTALLED_APPS`设置中添加`rest_framework`。看一下这段代码：

```py
INSTALLED_APPS = (
    ...
    'rest_framework',
)
```

如果您想要在登录和注销视图以及 Web 浏览 API 一起使用，那么您可以在根`urls.py`文件中添加以下 URL 模式：

```py
urlpatterns = [
    ...
    url(r'^api-auth/', include('rest_framework.urls'))
]
```

就是这样！现在我们已经成功集成了 Django REST Framework，我们可以继续创建 REST API。在创建 REST API 之前，我们需要实现身份验证和授权层，以便我们的每个 REST API 都能免受未经授权的访问。

让我们在下一节看看如何使我们的 REST API 安全。敬请关注。

# 实施身份验证和授权

身份验证和授权是设计 REST API 时必须考虑的重要部分。借助这些层，我们可以防止未经授权的访问我们的应用程序。有许多类型的实现模式可用，但我们将使用**JWT**（**JSON Web Token**）。在[`en.wikipedia.org/wiki/JSON_Web_Token`](https://en.wikipedia.org/wiki/JSON_Web_Token)上了解更多信息。JWT 对于实现分布式微服务架构非常有用，并且不依赖于集中式服务器数据库来验证令牌的真实性。

有许多 Python 库可用于实现 JWT 令牌机制。在我们的情况下，我们希望使用`django-rest-framework-jwt`库（[`getblimp.github.io/django-rest-framework-jwt/`](https://getblimp.github.io/django-rest-framework-jwt/)），因为它提供了对 Django Rest Framework 的支持。

我假设您在之前描述的*虚拟环境*部分设置环境时已经安装了这个库。让我们看看下一节应该如何配置`django-rest-framework-jwt`库。

# 配置 django-rest-framework-jwt

安装完成后，您需要在`settings.py`中添加一些与权限和身份验证相关的预定义类，如下面的代码片段所示。

文件—`settings.py`：

```py
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
} 
```

现在我们需要根据用户凭据添加获取令牌的 URL。在根`urls.py`中，我们将添加以下语句：

```py
from django.urls import path
from rest_framework_jwt.views import obtain_jwt_token
#...

urlpatterns = [
    '',
    # ...

    path(r'api-token-auth/', obtain_jwt_token),
]
```

`api-token-auth` API 将在成功验证后返回一个 JWT 令牌，例如：

```py
$ curl -X POST -d "username=admin&password=password123" http://localhost:8000/api-token-auth/

{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFiZHVsd2FoaWQiLCJleHAiOjE1MjYwNDUwNjgsImVtYWlsIjoiYWJkdWx3YWhpZDI0QGdtYWlsLmNvbSJ9.Iw0ZTtdZpsQqrKIkf2VKoWw91txYp9DLkBYMS9OPoCU"}
```

这个令牌可以通过添加授权标头和令牌来授权所有其他受保护的 API，如下所示：

```py
$ curl -H "Authorization: JWT <your_token>" http://localhost:8000/protected-url/
```

还有其他用例，您可能需要对已发行的令牌执行许多操作。为此，您需要阅读`django-rest-framework-jwt`的文档（[`getblimp.github.io/django-rest-framework-jwt/`](https://getblimp.github.io/django-rest-framework-jwt/)）。

现在让我们开始为我们的 ImageGallery 应用程序实现 API。

# 实施序列化器

Django Rest Framework 设计了一个类似于 Django 表单模块的序列化器模块，用于实现 JSON 表示层。序列化器负责对数据进行序列化和反序列化；您可以在这里看到有关数据序列化的详细解释（[`www.django-rest-framework.org/tutorial/1-serialization/#creating-a-serializer-class`](http://www.django-rest-framework.org/tutorial/1-serialization/#creating-a-serializer-class)）。

序列化程序模块有许多有用的类，例如`Serializer`、`ModelSerializer`、`HyperlinkedModelSerializer`等([`www.django-rest-framework.org/api-guide/serializers/`](http://www.django-rest-framework.org/api-guide/serializers/))。每个类都具有类似的操作，但具有扩展功能。`Serializer`类用于设计类似于 Django 表单表示的自定义数据表示，`ModelSerializer`用于表示与 Django 的`ModelFrom`类似的模型类数据。`HyperlinkedModelSerializer`通过超链接表示扩展了`ModelSerializer`的表示，并使用主键来关联相关数据。

我们需要创建一个使用`ModelSerializer`的序列化程序类。看一下这段代码。

文件—`gallery`/`serializers.py`：

```py
from rest_framework import serializers
from gallery.models import PhotoAlbum, Photo

class PhotoSerializer(serializers.ModelSerializer):

    class Meta:
        model = Photo
        fields = ('id', 'image', 'created_at', 'updated_at')

class PhotoAlbumSerializer(serializers.ModelSerializer):

    class Meta:
        model = PhotoAlbum
        fields = ('id', 'name', 'photos', 'created_at', 'updated_at')
        depth = 1
```

在这里，我们创建了`PhotoSerializer`和`PhotoAlbumSerializer`类，使用`ModelSerializer`类。这些序列化程序与模型类相关联；因此，数据表示将基于模型结构。

让我们继续下一节，我们将创建视图。

# 实现 viewsets

```py
Photo and PhotoAlbum models.
```

文件—`gallery`/`views.py`：

```py
from rest_framework import viewsets
from gallery.models import Photo, PhotoAlbum
from gallery.serializers import PhotoSerializer, PhotoAlbumSerializer

class PhotoViewset(viewsets.ModelViewSet):

    queryset = Photo.objects.all()
    serializer_class = PhotoSerializer

    def get_queryset(self, *args, **kwargs):
        if 'album_id' not in self.kwargs:
            raise APIException('required album_id')
        elif 'album_id' in self.kwargs and \
                not Photo.objects.filter(album__id=self.kwargs['album_id']).exists():
                                            raise NotFound('Album not found')
        return Photo.objects.filter(album__id=self.kwargs['album_id'])

    def perform_create(self, serializer):
        serializer.save(album_id=int(self.kwargs['album_id']))

class PhotoAlbumViewset(viewsets.ModelViewSet):

    queryset = PhotoAlbum.objects.all()
    serializer_class = PhotoAlbumSerializer
```

在这里，您可以看到我们已经创建了与`Photo`和`PhotoAlbum`模型相关的两个不同的 viewsets 类。`PhotoAlbum`模型与`Photo`模型有一对多的关系。因此，我们将编写一个嵌套 API，例如`albums/(?P<album_id>[0-9]+)/photos`。为了根据`album_id`返回相关的照片记录，我们重写了`get_queryset`方法，以便根据给定的`album_id`过滤`queryset`。

类似地，我们重写了`perform_create`方法，以在创建新记录时设置关联的`album_id`。我们将在即将到来的部分中提供完整的演示。

让我们看一下 URL 配置，我们在那里配置了嵌套 API 模式。

# 配置 URL 路由

Django REST Framework 提供了一个`router`模块来配置标准的 URL 配置。它自动添加了与所述 viewsets 相关的所有必需的 URL 支持。在这里阅读更多关于`routers`的信息：[`www.django-rest-framework.org/api-guide/routers/`](http://www.django-rest-framework.org/api-guide/routers/)。以下是与我们的路由配置相关的代码片段。

文件—`gallery`/`urls.py`：

```py
from django.urls import path, include
from rest_framework import routers
from gallery.views import PhotoAlbumViewset, PhotoViewset

router = routers.DefaultRouter()
router.register('albums', PhotoAlbumViewset)
router.register('albums/(?P<album_id>[0-9]+)/photos', PhotoViewset)

urlpatterns = [
    path(r'', include(router.urls)),
]
```

在这里，我们创建了一个默认路由器，并注册了带有 URL 前缀的 viewsets。路由器将自动确定 viewsets，并生成所需的 API URL。

```py
urls.py file.
```

文件—`imageGalleryProject`/`urls.py`：

```py
from django.contrib import admin
from django.urls import path, include
from rest_framework_jwt.views import obtain_jwt_token

urlpatterns = [
    path('admin/', admin.site.urls),
    path(r'', include('gallery.urls')),
    path(r'api-token-auth/', obtain_jwt_token),
]
```

一旦您包含了`gallery.urls`模式，它将在应用程序级别可用。我们已经完成了实现，现在是时候看演示了。让我们继续下一节，我们将探索 Zappa 配置，以及在 AWS Lambda 上的执行和部署过程。

# 使用 Zappa 构建、测试和部署 Django 应用程序

Django 提供了一个轻量级的部署 Web 服务器，运行在本地机器的 8000 端口上。您可以在进入生产环境之前对应用程序进行调试和测试。在这里阅读更多关于它的信息([`docs.djangoproject.com/en/2.0/ref/django-admin/#runserver`](https://docs.djangoproject.com/en/2.0/ref/django-admin/#runserver))。

让我们继续下一节，我们将探索应用程序演示和在 AWS Lambda 上的部署。

# 在本地环境中执行

```py
python manage.py runserver command:
```

```py
$ python manage.py runserver
Performing system checks...
System check identified no issues (0 silenced).

May 14, 2018 - 10:04:25
Django version 2.0.5, using settings 'imageGalleryProject.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.
```

现在是时候看一下您的 API 的执行情况了。我们将使用 Postman，一个 API 客户端工具，来测试 REST API。您可以从[`www.getpostman.com/`](https://www.getpostman.com/)下载 Postman 应用程序。让我们在接下来的部分中看到所有 API 的执行情况。

# API 身份验证

在访问资源 API 之前，我们需要对用户进行身份验证并获取 JWT 访问令牌。让我们使用`api-token-auth`API 来获取访问令牌。我们将使用`curl`命令行工具来执行 API。以下是`curl`命令的执行：

```py
$ curl -H "Content-Type: application/json" -X POST -d '{"username":"abdulwahid", "password":"abdul123#"}' http://localhost:8000/api-token-auth/
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFiZHVsd2FoaWQiLCJleHAiOjE1Mjk1NjYxOTgsImVtYWlsIjoiYWJkdWx3YWhpZDI0QGdtYWlsLmNvbSJ9.QypghhspJrNsp-v_XxlZeQFi_Wsujqh27EjlJtOaY_4"}
```

在这里，我们收到了 JWT 令牌作为用户身份验证的响应。现在我们将使用这个令牌作为授权标头来访问其他 API 资源。

# 在 API "/albums/"上的 GET 请求

此 API 将列出`PhotoAlbum`模型的所有记录。让我们尝试使用 cRUL 命令以`GET`请求方法访问`/album/` API，如下所示：

```py
$ curl -i http://localhost:8000/albums/ 
HTTP/1.1 401 Unauthorized
Date: Thu, 21 Jun 2018 07:33:07 GMT
Server: WSGIServer/0.2 CPython/3.6.5
Content-Type: application/json
WWW-Authenticate: JWT realm="api"
Allow: GET, POST, HEAD, OPTIONS
X-Frame-Options: SAMEORIGIN
Content-Length: 58
Vary: Cookie

{"detail":"Authentication credentials were not provided."}
```

在这里，我们从服务器收到了 401 未经授权的错误，消息是未提供身份验证凭据。这就是我们使用 JWT 令牌身份验证机制保护所有 API 的方式。

现在，如果我们只是使用从身份验证 API 获取的访问令牌添加授权标头，我们将从服务器获取记录。以下是成功的 API 访问授权标头的 cURL 执行：

```py
$ curl -i -H "Authorization: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFiZHVsd2FoaWQiLCJleHAiOjE1Mjk1NjY4NjUsImVtYWlsIjoiYWJkdWx3YWhpZDI0QGdtYWlsLmNvbSJ9.Dnbwuf3Mu2kcfk8KrbC-ql94lfHzK0z_5TgCPl5CeaM" http://localhost:8000/albums/
HTTP/1.1 200 OK
Date: Thu, 21 Jun 2018 07:40:14 GMT
Server: WSGIServer/0.2 CPython/3.6.5
Content-Type: application/json
Allow: GET, POST, HEAD, OPTIONS
X-Frame-Options: SAMEORIGIN
Content-Length: 598

[
    {
        "created_at": "2018-03-17T22:39:08.513389Z",
        "id": 1,
        "name": "Screenshot",
        "photos": [
            {
                "album": 1,
                "created_at": "2018-03-17T22:47:03.775033Z",
                "id": 5,
                "image": "https://chapter-5.s3-ap-south-1.amazonaws.com/media/Screenshot/AWS_Lambda_Home_Page.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXNW3FK64BZR3DLA%2F20180621%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Date=20180621T073958Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=721acd5b023e13132f606a3f72bd672bad95a0dcb24572099c4cb49cdc34df71",
                "updated_at": "2018-03-17T22:47:18.298215Z"
            }
        ],
        "updated_at": "2018-03-17T22:47:17.328637Z"
    }
]
```

正如您所看到的，我们通过提供授权标头从`"/albums/"` API 获取了数据。在这里，我们可以使用`| python -m json.tool`以 JSON 可读格式打印返回响应。

# 在 API "/albums/<album_id>/photos/"上的 POST 请求

现在我们可以向现有记录添加更多照片。以下是 cRUL 命令执行的日志片段，我们正在将图像文件上传到现有相册：

```py
$ curl -i -H "Content-Type: multipart/form-data" -H "Authorization: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFiZHVsd2FoaWQiLCJleHAiOjE1Mjk1NzE5ODEsImVtYWlsIjoiYWJkdWx3YWhpZDI0QGdtYWlsLmNvbSJ9.3CHaV4uI-4xwbzAVdBA4ooHtaCdUrVn97uR_G8MBM0I" -X POST -F "image=@/home/abdulw/Pictures/serverless.png" http://localhost:8000/albums/1/photos/ HTTP/1.1 201 Created
Date: Thu, 21 Jun 2018 09:01:44 GMT
Server: WSGIServer/0.2 CPython/3.6.5
Content-Type: application/json
Allow: GET, POST, HEAD, OPTIONS
X-Frame-Options: SAMEORIGIN
Content-Length: 450

{
    "created_at": "2018-06-21T09:02:27.918719Z",
    "id": 7,
    "image": "https://chapter-5.s3-ap-south-1.amazonaws.com/media/Screenshot/serverless.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAJA3LNVLKPTEOWH5A%2F20180621%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Date=20180621T090228Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=4e28ef5daa6e1887344514d9953f17df743e747c32b532cde12b840241fa13f0",
    "updated_at": "2018-06-21T09:02:27.918876Z"
}
```

现在，您可以看到图像已上传到 AWS S3 存储，并且我们已经配置了 AWS S3 和 CloudFront，因此我们获得了 CDN 链接。让我们再次查看所有记录的列表：

```py
$ curl -H "Authorization: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFiZHVsd2FoaWQiLCJleHAiOjE1Mjk1NzIzNTYsImVtYWlsIjoiYWJkdWx3YWhpZDI0QGdtYWlsLmNvbSJ9.m2w1THn5Nrpy0dCi8k0bPdeo67OHNYEKO-yTX5Wnuig" http://localhost:8000/albums/ | python -m json.tool

[
    {
        "created_at": "2018-03-17T22:39:08.513389Z",
        "id": 1,
        "name": "Screenshot",
        "photos": [
            {
                "album": 1,
                "created_at": "2018-03-17T22:47:03.775033Z",
                "id": 5,
                "image": "https://chapter-5.s3-ap-south-1.amazonaws.com/media/Screenshot/AWS_Lambda_Home_Page.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAJA3LNVLKPTEOWH5A%2F20180621%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Date=20180621T090753Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=832abe952870228c2ae22aaece81c05dc1414a2e9a78394d441674634a6d2bbf",
                "updated_at": "2018-03-17T22:47:18.298215Z"
            },
            {
                "album": 1,
                "created_at": "2018-06-21T09:01:44.354167Z",
                "id": 6,
                "image": "https://chapter-5.s3-ap-south-1.amazonaws.com/media/Screenshot/serverless.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAJA3LNVLKPTEOWH5A%2F20180621%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Date=20180621T090753Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=90a00ad79f141c919d8e65474325534461cf837f462cb52a840afb3863b72013",
                "updated_at": "2018-06-21T09:01:44.354397Z"
            },
            {
                "album": 1,
                "created_at": "2018-06-21T09:02:27.918719Z",
                "id": 7,
                "image": "https://chapter-5.s3-ap-south-1.amazonaws.com/media/Screenshot/serverless.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAJA3LNVLKPTEOWH5A%2F20180621%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Date=20180621T090753Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=90a00ad79f141c919d8e65474325534461cf837f462cb52a840afb3863b72013",
                "updated_at": "2018-06-21T09:02:27.918876Z"
            }
        ],
        "updated_at": "2018-03-17T22:47:17.328637Z"
    }
]

```

现在我们的应用程序已根据我们的要求实施。我们可以继续使用 Zappa 在 AWS Lambda 上部署应用程序。现在让我们转向下一节来配置 Zappa。

# 配置 Zappa

```py
zappa_settings.json file:
```

```py
{
    "dev": {
        "aws_region": "ap-south-1",
        "django_settings": "imageGalleryProject.settings",
        "profile_name": "default",
        "project_name": "imagegallerypro",
        "runtime": "python3.6",
        "s3_bucket": "chapter-5",
        "remote_env": "s3://important-credentials-bucket/environments.json"
    }
}
```

在这里，我们根据要求定义了配置。由于密钥定义了每个配置，我们可以看到它的用法：

+   `aws_region`：Lambda 将上传的 AWS 区域。

+   `django_settings`：Django 设置文件的导入路径。

+   `profile_name`：在`~/.aws/credentials`文件中定义的 AWS CLI 配置文件。

+   `project_name`：上传 Lambda 函数的项目名称。

+   `runtime`：Python 运行时解释器。

+   `s3_bucket`：创建 Amazon S3 存储桶并上传部署包。

+   `remote_env`：设置 Amazon S3 位置上传的 JSON 文件中提到的所有键值对的环境变量。

借助这些配置信息，我们将继续部署。

# 构建和部署

一旦我们完成配置，就可以进行部署。Zappa 提供了两个不同的命令来执行部署，例如`zappa deploy <stage_name>`和`zappa update <stage_name>`。最初，我们将使用`zappa deploy <stage_name>`命令，因为这是我们第一次部署此 Lambda 应用程序。

如果您已经部署了应用程序并希望重新部署，那么您将使用`zappa update <stage_name>`命令。在上一章中，我们详细讨论了 Zappa 的部署过程，因此您可以参考它。

以下是我们部署过程的日志片段：

```py
$ zappa update dev
(python-dateutil 2.7.3 (/home/abdulw/.local/share/virtualenvs/imageGalleryProject-4c9zDR_T/lib/python3.6/site-packages), Requirement.parse('python-dateutil==2.6.1'), {'zappa'})
Calling update for stage dev..
Downloading and installing dependencies..
 - pillow==5.1.0: Downloading
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.95M/1.95M [00:00<00:00, 7.73MB/s]
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading imagegallerypro-dev-1529573380.zip (20.2MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 21.2M/21.2M [00:06<00:00, 2.14MB/s]
Updating Lambda function code..
Updating Lambda function configuration..
Uploading imagegallerypro-dev-template-1529573545.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.65K/1.65K [00:00<00:00, 28.9KB/s]
Deploying API Gateway..
Scheduling..
Unscheduled imagegallerypro-dev-zappa-keep-warm-handler.keep_warm_callback.
Scheduled imagegallerypro-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Your updated Zappa deployment is live!: https://cfsla2gds0.execute-api.ap-south-1.amazonaws.com/dev
https://cfsla2gds0.execute-api.ap-south-1.amazonaws.com/dev.
```

让我们转到下一节，我们将在部署的应用程序上执行一些操作。

# 在生产环境中执行

一旦您成功部署了应用程序，您将获得托管应用程序链接。这个链接就是通过将 AWS API 网关与 Zappa 的 AWS Lambda 配置生成的链接。

现在您可以在生产环境中使用应用程序。身份验证 API 的屏幕截图在下一节中。

# 身份验证 API

正如我们在本地环境中看到的身份验证执行一样，在生产环境中也是一样的。以下是部署在 AWS Lambda 上的身份验证 API 执行的日志片段：

```py
$ curl -H "Content-Type: application/json" -X POST -d '{"username":"abdulwahid", "password":"abdul123#"}' https://cfsla2gds0.execute-api.ap-south-1.amazonaws.com/dev/api-token-auth/
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFiZHVsd2FoaWQiLCJleHAiOjE1Mjk1NzQyOTMsImVtYWlsIjoiYWJkdWx3YWhpZDI0QGdtYWlsLmNvbSJ9.pHuHaJpjlESwdQxXMiqGOuy2_lpVW1X26RiB9NN8rhI"}
```

正如您在这里所看到的，功能不会对任何事物产生影响，因为应用程序正在无服务器环境中运行。让我们看看另一个 API。

# 对“/albums/”API 的 GET 请求

通过身份验证 API 获得的访问令牌，您有资格访问所有受保护的 API。以下是`/albums/`API 的`GET`请求的屏幕截图：

```py
$ curl -H "Authorization: JWT eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFiZHVsd2FoaWQiLCJleHAiOjE1Mjk1NzQ4MzgsImVtYWlsIjoiYWJkdWx3YWhpZDI0QGdtYWlsLmNvbSJ9.55NucqsavdgxcmNNs6_hbJMCw42mWPyylaVvuiP5KwI" https://cfsla2gds0.execute-api.ap-south-1.amazonaws.com/dev/albums/ | python -m json.tool

[
    {
        "created_at": "2018-03-17T22:39:08.513389Z",
        "id": 1,
        "name": "Screenshot",
        "photos": [
            {
                "album": 1,
                "created_at": "2018-03-17T22:47:03.775033Z",
                "id": 5,
                "image": "https://chapter-5.s3-ap-south-1.amazonaws.com/media/Screenshot/AWS_Lambda_Home_Page.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAJA3LNVLKPTEOWH5A%2F20180621%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Date=20180621T094957Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=0377bc8750b115b6bff2cd5acc024c6375f5fedc6de35275ea1392375041adc0",
                "updated_at": "2018-03-17T22:47:18.298215Z"
            }
        ],
        "updated_at": "2018-03-17T22:47:17.328637Z"
    }
]
```

就是这样。我们已经完成了无服务器环境的部署。希望对您有所帮助。

# 总结

在本章中，我们学习了如何在 Django REST 框架中开发 REST API。我们介绍了使用 JWT 身份验证机制保护 API 的过程。最后，我们使用 Zappa 在无服务器环境中部署了应用程序。

在下一章中，我们将使用非常轻量级的 Python 框架开发基于高性能 API 的应用程序。我们还将探索更多 Zappa 配置选项，以建立缓存机制。敬请关注，发现 Zappa 世界中更多的宝藏。

# 问题

1.  什么是 Django Rest 框架？

1.  Django-storage 有什么用？


# 第七章：使用 Zappa 构建猎鹰应用程序

在本章中，我们将实施一个基于猎鹰框架的应用程序。这个应用程序将与引用相关；您将能够获取每日引用和生成一个随机引用。我希望这对您来说是有趣的。我们将包括一个调度程序，它将负责从第三方 API 获取一个随机引用并将其放入我们的数据库中。我们将设置这个调度程序每天执行一次。让我们为这次旅行做好准备。

本章我们将涵盖以下主题：

+   安装和配置猎鹰

+   设计猎鹰 API

+   使用 Zappa 构建、测试和部署猎鹰 API

# 技术要求

在本章的开发工作中继续之前，我想建议先满足设置开发环境的先决条件。以下是技术要求的列表：

+   Ubuntu 16.04/macOS/Windows

+   Python 3.6

+   Pipenv 工具

+   猎鹰

+   Peewee

+   请求

+   Gunicorn

+   Zappa

在下一节中，我已经描述了设置环境的完整信息。让我们为此做好准备，探索通往无服务器的旅程。

# 安装和配置猎鹰

配置 Python 应用程序开发需要我们设置虚拟环境。借助虚拟环境，我们将维护所有所需的软件包。正如在第六章中讨论的那样，*使用 Zappa 构建 Django REST API*，pipenv 打包工具在虚拟环境中维护所有已安装的软件包，并跟踪版本和依赖项。让我们继续使用 pipenv 工具设置虚拟环境。

# 设置虚拟环境

在开始实际实施之前，我们将使用 pipenv 工具设置虚拟环境。以下是创建新虚拟环境的命令：

```py
$ pipenv --python python3.6
```

在这里，我明确提到了 Python 版本，因为我在我的系统上使用了许多其他 Python 版本。这个命令将创建一个`Pipfile`，如下所示：

```py
[[source]]

url = "https://pypi.python.org/simple"
verify_ssl = true
name = "pypi"

[dev-packages]

[packages]

[requires]

python_version = "3.6"
```

正如您所见，前面的代码中包含了关于环境的基本信息，但在软件包下面没有任何内容，因为我们还没有安装任何软件包。这个文件维护了所有已安装软件包的列表。pipenv 工具在`~/.local/share/virtualenvs/`创建一个虚拟环境，并且当我们调用前面的命令时，它将从该目录创建新的环境。一旦您执行了该命令，就会创建`Pipfile`，如前所述。

您可以执行`pipenv shell`命令来启用虚拟环境。让我们继续下一节，我们将安装所有所需的软件包。

# 安装所需的软件包

正如我们之前提到的，我们将创建一个基于猎鹰的 API 应用程序。因此，我们需要安装一些我们将在实现中使用的软件包。以下是我们将在实现中使用的软件包列表：

+   `falcon`

+   `zappa`

+   `gunicorn`

+   `peewee`

+   `requests`

您可以使用`pipenv install <package_name>`命令安装这些软件包。

您可以通过指定其他以空格分隔的软件包一次安装多个软件包，例如`pipenv install <package_one> <package_two> ...`。

一旦您安装了所有这些软件包，pipenv 将创建一个名为`Pipfile.lock`的文件，其中包含版本和依赖项的信息。`Pipfile`将被更新。

```py
Pipfile:
```

文件—`Pipfile`：

```py
[[source]]

url = "https://pypi.python.org/simple"
verify_ssl = true
name = "pypi"

[dev-packages]

pylint = "*"

[packages]

falcon = "*"
zappa = "*"
gunicorn = "*"
peewee = "*"
requests = "*"

[requires]

python_version = "3.6"
```

现在我们已经完成了虚拟环境的设置，是时候开始实施应用程序了。但在继续设置环境之前，让我们先了解一些重要的软件包及其用法。

# 什么是猎鹰？

猎鹰是一个裸金属 Python Web API 框架。它可以用于构建具有非常快速性能的微服务。

它非常灵活和易于实现。与其他框架相比，它具有显著的基准。有许多大型组织正在使用 Falcon，如领英、OpenStack、RackSpace 等。以下是 Falcon 网站上的示例代码片段：

```py
# sample.py

import falcon

class QuoteResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        quote = {
            'quote': (
                "I've always been more interested in "
                "the future than in the past."
            ),
            'author': 'Grace Hopper'
        }

        resp.media = quote

api = falcon.API()
api.add_route('/quote', QuoteResource())
```

它需要`gunicorn`在本地主机上执行 API，如下面的代码块所示：

```py
$ gunicorn sample:api
```

Falcon 真的很简单，而且在 Falcon 中更容易实现 REST API，因为它鼓励我们遵循 REST 架构风格。您可以在此处阅读有关 Falcon 的更多信息：[`falconframework.org/#`](https://falconframework.org/#)。

# 什么是 Peewee？

Peewee 是一个简单而小巧的**ORM**（**对象关系映射器**）。它旨在提供类似于 Django 或 SQLAlchemy 的 ORM 接口。它支持 MySQL、Postgres 和 SQLite 等数据库。

以下是 Peewee 的 GitHub 页面上的定义模型类的示例代码片段：

```py
from peewee import *
import datetime

db = SqliteDatabase('my_database.db')

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(unique=True)

class Tweet(BaseModel):
    user = ForeignKeyField(User, backref='tweets')
    message = TextField()
    created_date = DateTimeField(default=datetime.datetime.now)
    is_published = BooleanField(default=True)
```

这真的很棒——我们以 Django 风格设计数据库模型的可行性与一个小包装器。Peewee 真的很棒，可以考虑用于编写小型微服务。

在此处阅读有关 Peewee 的更多信息：[`docs.peewee-orm.com/en/latest/`](http://docs.peewee-orm.com/en/latest/)。

让我们继续下一节，我们将在实际中使用 Falcon 和 Peewee。

# 设计 Falcon API

我们将基于报价概念设计一个 REST API。报价可能是名人说的话，也可能是电影中的对话。我们将使用 Mashape 的**随机名人名言**API（[`market.mashape.com/andruxnet/random-famous-quotes`](https://market.mashape.com/andruxnet/random-famous-quotes)）。Mashape 是一个 API 平台，提供许多类别的 API。

在我们的情况下，我们将创建一个包含以下操作的单个 API：

+   生成或检索当天的报价

+   生成随机报价

对于第一个操作，我们将需要每天将来自 Mashape API 的随机报价存储到我们的数据库中。因此，我们需要设计一个任务调度程序，以便每天执行并将来自 Mashape API 的报价存储到我们的数据库中，以便我们的 API 用户可以获得当天的报价。

对于第二个操作，我们不需要将从 Mashape API 随机生成的每一条报价都持久化。相反，我们将生成的随机报价返回给我们的 API 用户。

# 搭建应用程序

在设计任何应用程序时，搭建是在实施解决方案之前必须考虑的重要步骤。它帮助我们以一种乐观的方式管理代码库。以下是我们应用程序的搭建：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-svls-py-websvc-zappa/img/00075.jpeg)

在这里，我们根据功能将代码库分成不同的模块。让我们在接下来的部分中看一下每个模块。

# 设计模型类

```py
models.py.
```

文件—`models.py`：

```py
import os
import datetime
from shutil import copyfile
from peewee import *

# Copy our working DB to /tmp..
db_name = 'quote_database.db'
src = os.path.abspath(db_name)
dst = "/tmp/{}".format(db_name)
copyfile(src, dst)

db = SqliteDatabase(dst)

class QuoteModel(Model):

    class Meta:
        database = db

    id = IntegerField(primary_key= True)
    quote = TextField()
    author = CharField()
    category = CharField()
    created_at = DateTimeField(default= datetime.date.today())

db.connect()
db.create_tables([QuoteModel])
```

在这里，我们通过扩展`Model`类定义了`QuoteModel`，并使用 Peewee 库的特性定义了属性。这里最重要的部分是数据库连接；正如您所看到的，我们使用了 SQLite 数据库。我们创建了数据库文件并将其放在`/tmp`目录中，以便在 AWS Lambda 环境中可以访问。

一旦我们使用`SqliteDatabase`类定义了数据库，我们就连接数据库并根据模型定义创建数据库表。

`db.create_tabless`方法只在表不存在时创建表。

现在我们准备使用这个`Model`类来执行任何查询操作。但是，在创建资源之前，让我们看一下`mashape.py`，在那里我们集成了第三方 API 以获取随机报价。

# Mashape API 集成

Mashape 是私人和公共 API 的最大 API 市场。有数千个 API 提供者和消费者注册。请查看市场[`market.mashape.com`](https://market.mashape.com/)。我们将使用随机名言引用 API([`market.mashape.com/andruxnet/random-famous-quotes`](https://market.mashape.com/andruxnet/random-famous-quotes))。一旦您登录 Mashape 市场，您可以详细了解这些 API。以下代码片段是我们用来获取随机引用的 API 之一。

```py
mashape.py file.
```

文件 - `mashape.py`：

```py
import os
import requests

def fetch_quote():
    response = requests.get(
        os.environ.get('Mashape_API_Endpoint'),
        headers={
            'X-Mashape-Key': os.environ.get('X_Mashape_Key'),
            'Accept': 'application/json'
        }
    )
    if response.status_code == 200:
        return response.json()[0]
    return response.json()
```

在这里，我们编写了一个名为`fetch_quote`的方法。此方法负责从 Mashape API 获取引用并以 Python 字典格式返回引用数据。根据我们的需求，我们将在不同的地方使用此方法。

# 创建 API 资源

```py
resources.py.
```

文件 - `resources.py`：

```py
import os
import datetime
import requests
import falcon

from models import QuoteModel
from mashape import fetch_quote

class QuoteResource:
    def on_get(self, req, resp):
        """Handles GET requests"""
        if req.get_param('type') in ['daily', None]:
            data = QuoteModel.select().where(QuoteModel.created_at == datetime.date.today())
            if data.exists():
                data = data.get()
                resp.media = {'quote': data.quote, 'author': data.author, 'category': data.category}
            else:
                quote = fetch_quote()
                QuoteModel.create(**quote)
                resp.media = quote
        elif req.get_param('type') == 'random':
            resp.media = fetch_quote()
        else:
            raise falcon.HTTPError(falcon.HTTP_400,'Invalid Quote type','Supported types are \'daily\' or \'random\'.')

api = falcon.API()
api.add_route('/quote', QuoteResource())
```

在这里，我们创建了`QuoteResource`类，并实现了`on_get`方法来处理`GET`请求。为了执行生成每日引用和随机引用的不同操作，我们定义了一个名为`type`的查询参数，例如，`http://<API_URL>?type=daily|random`。因此，根据查询参数，我们提供服务。

我们已经完成了实施。我们将在下一节中查看执行、调度和部署。

# 使用 Zappa 构建、测试和部署 Falcon API

与其他框架无关，Falcon 需要`gunicorn`库进行执行。Gunicorn 是一个轻量级的 Python WSGI HTTP 服务器。Falcon 没有任何默认行为来提供 WSGI 服务；相反，Falcon 主要关注 API 架构风格和性能。让我们继续在本地环境中执行 API。

# 使用 gunicorn 进行本地执行

对于本地执行，我们将使用`gunicorn`。以下是`gunicorn`执行的日志：

```py
$ gunicorn resources:api
[2018-05-18 15:40:57 +0530] [31655] [INFO] Starting gunicorn 19.8.1
[2018-05-18 15:40:57 +0530] [31655] [INFO] Listening at: http://127.0.0.1:8000 (31655)
[2018-05-18 15:40:57 +0530] [31655] [INFO] Using worker: sync
[2018-05-18 15:40:57 +0530] [31662] [INFO] Booting worker with pid: 31662
```

我们正在使用`resources`模块和`api`对象进行执行。我们使用`resources`模块创建了`api`对象。

# 每日引用的 API

我们实现了`/quote` API，并根据查询参数分离了操作。让我们执行`/quote?type=daily` API。以下是使用 cURL 命令行工具执行每日引用 API 的日志片段：

```py
$ curl http://localhost:8000/quote?type=daily
{"quote": "I'll get you, my pretty, and your little dog, too!", "author": "The Wizard of Oz", "category": "Movies"}
```

此 API 将每天返回一个独特的引用。

# 随机引用的 API

现在，让我们对`/quote` API 执行另一个操作，例如`/quote?type=random`。此 API 将在每个请求上返回一个随机引用。以下是 API 执行的日志：

```py
$ curl http://localhost:8000/quote?type=random
{"quote": "The only way to get rid of a temptation is to yield to it.", "author": "Oscar Wilde", "category": "Famous"}
```

此 API 将在每个请求上返回一个随机引用记录。

# 配置 Zappa

一旦我们在设置虚拟环境时安装了 Zappa，我们就可以配置 Zappa 与我们的应用程序。以下是我们将执行的操作，以配置 Zappa。

# Zappa 初始化

```py
settings.json file.
```

文件 - `zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "aws_region": "ap-south-1",
        "profile_name": "default",
        "project_name": "chapter-7",
        "runtime": "python3.6",
        "s3_bucket": "zappa-0edixmwpd",
        "remote_env": "s3://book-configs/chapter-7-config.json"
    }
}
```

在这里，我们根据要求定义了配置。由于密钥定义了每个配置，我们可以看到它的用法：

+   `aws_region`: lambda 将上传的 AWS 区域

+   `app_function`: 从`resources`模块导入`api`对象的导入路径

+   `profile_name`: 在`~/.aws/credentials`文件中定义的 AWS CLI 配置文件

+   `project_name`: 上传 lambda 函数的项目名称。

+   `runtime`: Python 运行时解释器

+   `s3_bucket`: 创建一个 Amazon S3 存储桶并上传部署包。

+   `remote_env`: 在 Amazon S3 位置上传的 JSON 文件中设置所有键值对的环境变量

借助这些配置信息，我们可以继续部署。

# Zappa 部署

一旦配置完成，我们就可以进行部署。Zappa 提供了两个不同的命令来执行部署，`zappa deploy <stage_name>`和`zappa update <stage_name>`。最初，我们使用`zappa deploy <stage_name>`命令，因为这是我们首次部署此 lambda 应用程序。

如果您已经部署了应用程序并希望重新部署，则可以使用`zappa update <stage_name>`命令。在前一章中，我们对 Zappa 的部署过程进行了详细讨论，因此您可以参考那里获取更多信息。

以下是我们部署过程的日志：

```py
$ zappa update dev
Important! A new version of Zappa is available!
Upgrade with: pip install zappa --upgrade
Visit the project page on GitHub to see the latest changes: https://github.com/Miserlou/Zappa
Calling update for stage dev..
Downloading and installing dependencies..
 - sqlite==python36: Using precompiled lambda package
Packaging project as zip.
Uploading chapter-7-dev-1529584381.zip (5.9MiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 6.17M/6.17M [00:03<00:00, 1.08MB/s]
Updating Lambda function code..
Updating Lambda function configuration..
Uploading chapter-7-dev-template-1529584474.json (1.6KiB)..
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 1.62K/1.62K [00:00<00:00, 9.09KB/s]
Deploying API Gateway..
Scheduling..
Unscheduled chapter-7-dev-schedulers.set_quote_of_the_day.
Unscheduled chapter-7-dev-zappa-keep-warm-handler.keep_warm_callback.
Scheduled chapter-7-dev-schedulers.set_quote_of_the_day with expression cron(0 12 * * ? *)!
Scheduled chapter-7-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
Your updated Zappa deployment is live!: https://0uqnn5ql3a.execute-api.ap-south-1.amazonaws.com/dev
```

在这里，我使用`zappa update dev`来部署我的现有应用程序。此命令将在最后打印部署的 URL；我们可以使用它在生产环境中测试应用程序。

# 在生产环境中执行

由于我们使用 Zappa 在 AWS Lambda 上部署了应用程序，Zappa 配置了具有代理到 AWS Lambda 的 API Gateway。因此，它将具有在前一节中提到的随机生成的 API Gateway 链接。

现在，让我们使用生成的链接执行我们的 API（[`0uqnn5ql3a.execute-api.ap-south-1.amazonaws.com/dev/quote`](https://0uqnn5ql3a.execute-api.ap-south-1.amazonaws.com/dev/quote)）。

# 每日引用 API 执行

执行操作将类似于本地执行，但它将对 API Gateway 产生一些影响，因为 AWS API Gateway 中有许多可用于增强 API 性能和优化的功能。

以下是使用 cURL 工具执行每日引用 API 的日志片段：

```py
$ curl https://0uqnn5ql3a.execute-api.ap-south-1.amazonaws.com/dev/quote?type=daily
{"quote": "You've got to ask yourself one question: 'Do I feel lucky?' Well, do ya, punk?", "author": "Dirty Harry", "category": "Movies"}
```

我们的应用程序作为无服务器应用程序正在运行。您可以使用它而不必过多担心服务器，因为它能够每秒提供数百万次请求，并且亚马逊将负责其可伸缩性和可用性。让我们尝试另一个 API。

# 随机引用 API 执行

让我们执行随机引用 API。以下是随机引用 API 执行的片段：

```py
$ curl -s -w 'Total time taken: %{time_total}\n' https://0uqnn5ql3a.execute-api.ap-south-1.amazonaws.com/dev/quote?type=random
{"quote": "A friendship founded on business is better than a business founded on friendship.", "author": "John D. Rockefeller", "category": "Famous"}
Total time taken: 1.369
```

您可以看到此执行需要 1.369 秒，因为我们明确发出了另一个请求到 Mashape API 以获取随机引用。通过为 API Gateway 服务添加缓存支持，我们可以使此执行更快。

# 在 API Gateway 上启用缓存

AWS API Gateway 提供了一个功能，可以为 API 端点响应添加缓存。它将有助于减少网络延迟，并向用户返回缓存的响应，而无需触发 AWS Lambda 函数。

Zappa 具有配置 AWS API Gateway 上缓存的能力；您无需手动从 AWS Web 控制台配置缓存。以下是在`zappa_settings.json`文件中添加的配置，以启用 API Gateway 上的缓存。

文件—`zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "aws_region": "ap-south-1",
        "profile_name": "default",
        "project_name": "chapter-7",
        "runtime": "python3.6",
        "s3_bucket": "zappa-0edixmwpd",
        "remote_env": "s3://book-configs/chapter-7-config.json",
        "cache_cluster_enabled": false,
 "cache_cluster_size": 0.5,
 "cache_cluster_ttl": 300,
 "cache_cluster_encrypted": false,
    }
}
```

如前所述，在`zappa_settings.json`文件中的缓存选项。让我们看看它的用法：

+   `cache_cluster_enabled`：默认为`false`；此选项设置为`true`以启用 API Gateway 缓存集群。

+   `cache_cluster_size`：默认为 0.5 GB；这表示缓存内存大小。如果需要，我们也可以增加大小。

+   `cache_cluster_ttl`：默认为 300 秒；此选项用于设置内存中响应缓存的**生存时间**（TTL）。最大限制为 3,600 秒，如果要禁用它，可以将其设置为 0 秒。

+   `cache_cluster_encrypted`：默认为`false`；如果要加密缓存的响应数据，则将此选项设置为`true`。

这就是您可以在没有任何手动干预的情况下启用 API Gateway 缓存机制的方法。只有`GET`请求方法应该被缓存。

AWS API Gateway 不支持免费套餐。它按小时计费。在[`aws.amazon.com/api-gateway/pricing/`](https://aws.amazon.com/api-gateway/pricing/)上阅读有关 API Gateway 定价的更多信息。

# 事件调度

AWS Lambda 可以与 AWS CloudWatch 事件一起配置。如果要定期执行 Lambda 函数，例如，每五分钟执行一次，您可以使用速率表达式，或者可以配置`cron`表达式以安排定时事件进行执行。

您可以在[`docs.aws.amazon.com/lambda/latest/dg/tutorial-scheduled-events-schedule-expressions.html`](https://docs.aws.amazon.com/lambda/latest/dg/tutorial-scheduled-events-schedule-expressions.html)阅读有关计划表达式的更多信息。

配置 AWS Lambda 与计划事件需要更多的手动干预。您可以查看官方文档[`docs.aws.amazon.com/lambda/latest/dg/with-scheduled-events.html`](https://docs.aws.amazon.com/lambda/latest/dg/with-scheduled-events.html)。

Zappa 提供了一种非常灵活的方式来配置计划事件，无需任何手动干预。

# 使用 Zappa 配置事件

Zappa 支持定时事件和 AWS 事件。定时事件与时间和日期相关，而 AWS 事件与任何 AWS 服务相关，例如 AWS S3 事件等。

我们可以根据任何 AWS 事件安排 Lambda 函数的执行，如下面的代码片段所示：

```py
{
    "production": {
       ...
       "events": [{
            "function": "your_module.process_upload_function",
            "event_source": {
                  "arn": "arn:aws:s3:::my-bucket",
                  "events": [
                    "s3:ObjectCreated:*" 
                  ]
               }
            }],
       ...
    }
}
```

Zappa 支持几乎所有 AWS 事件来执行 AWS lambda 函数。您可以在[`github.com/Miserlou/Zappa#executing-in-response-to-aws-events`](https://github.com/Miserlou/Zappa#executing-in-response-to-aws-events)阅读有关响应 AWS 事件执行的更多信息。

一旦添加了事件配置，您可以执行以下命令来安排事件：

```py
$ zappa schedule production 
```

在我们的案例中，我们将安排一个有时间限制的事件来执行一个函数，以获取每日报价并将其存储在数据库中。让我们看看如何配置我们的应用程序以安排每日事件。

# 安排一个事件来设置每日报价

由于我们已经设计了`/quote?type=daily` API 来获取每日报价，如果该报价存在于数据库中，则此 API 将返回该报价，否则将从 Mashape API 获取并将其存储在数据库中。此操作是为了防止 API 在数据库中不存在报价记录的情况下失败。

但是我们想要确保报价记录确实存在于数据库中。为此，我们将安排一个每日事件，将在午夜发生。我们将执行一个函数来执行`获取报价`操作。

以下是带有事件配置的 Zappa 设置片段。

文件—`zappa_settings.json`：

```py
{
    "dev": {
        "app_function": "resources.api",
        "aws_region": "ap-south-1",
        "profile_name": "default",
        "project_name": "chapter-7",
        "runtime": "python3.6",
        "s3_bucket": "zappa-0edixmwpd",
        "remote_env": "s3://book-configs/chapter-7-config.json",
        "cache_cluster_enabled": false,
        "cache_cluster_size": 0.5,
        "cache_cluster_ttl": 300,
        "cache_cluster_encrypted": false,
        "events": [{
 "function": "schedulers.set_quote_of_the_day",
 "expression": "cron(0 12 * * ? *)"
 }]
    }
}
schedulers module.
```

文件—`schedulers.py`：

```py
from models import QuoteModel
from mashape import fetch_quote

def set_quote_of_the_day(event, context):
    QuoteModel.create(**fetch_quote())
set_quote_of_the_day will be executed by the scheduled event and will perform the operation to fetch the quote and store it in the database.
```

现在，为了启用计划事件，让我们运行`zappa schedule dev`命令。以下是`schedule`命令执行的日志：

```py
$ zappa schedule dev
Calling schedule for stage dev..
Scheduling..
Unscheduled chapter-7-dev-zappa-keep-warm-handler.keep_warm_callback.
Unscheduled chapter-7-dev-schedulers.set_quote_of_the_day.
Scheduled chapter-7-dev-schedulers.set_quote_of_the_day with expression cron(0 12 * * ? *)!
Scheduled chapter-7-dev-zappa-keep-warm-handler.keep_warm_callback with expression rate(4 minutes)!
```

就是这样；我们现在已经完成了调度。现在，每天午夜，`set_quote_of_the_day`方法将被调用并执行获取报价的操作。

# 总结

在本章中，我们学习了如何基于 Falcon 框架创建高性能的 API。我们还学习了如何使用 Zappa 配置 API Gateway 缓存机制。我们涵盖的最有趣的部分是调度。现在，您不需要担心任何第三方调度工具，因为 Zappa 使基于时间和 AWS 事件的调度变得非常容易。

希望您喜欢本章。现在让我们进入下一章，探索 Zappa 的功能。我们将为我们的应用程序设置自定义域和 SSL 证书。

# 问题

1.  Falcon 与其他 Python 框架有什么不同？

1.  Peewee 库相对于`SQLAlchemy`的好处是什么？

1.  调度是如何工作的？
