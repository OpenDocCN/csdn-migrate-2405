# 精通 Flask（三）

> 原文：[`zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530`](https://zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：构建 RESTful API

表述状态转移，或者**REST**，是在客户端和服务器之间传输信息的一种方法。在 Web 上，REST 是建立在 HTTP 之上的，并允许浏览器和服务器通过利用基本的 HTTP 命令轻松通信。通过使用 HTTP 命令，REST 是平台和编程语言无关的，并且解耦了客户端和服务器，使开发更加容易。这通常用于需要在服务器上拉取或更新用户信息的 JavaScript 应用程序。REST 还用于为外部开发人员提供用户数据的通用接口。例如，Facebook 和 Twitter 在其应用程序编程接口（**API**）中使用 REST，允许开发人员获取信息而无需解析网站的 HTML。

# REST 是什么

在深入了解 REST 的细节之前，让我们看一个例子。使用一个客户端，这里是一个 Web 浏览器，和一个服务器，客户端通过 HTTP 向服务器发送请求以获取一些模型，如下所示：

![REST 是什么](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_08_01.jpg)

然后服务器将回应包含所有模型的文档。

![REST 是什么](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_08_02.jpg)

然后客户端可以通过`PUT` HTTP 请求修改服务器上的数据：

![REST 是什么](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_08_03.jpg)

然后服务器将回应已经修改了数据。这只是一个非常简化的例子，但它将作为 REST 定义的背景。

REST 不是严格的标准，而是对通信的一组约束，以定义一种可以以多种方式实现的方法。这些约束是通过多年与其他通信协议（如**远程过程调用**（**RPC**）或**简单对象访问协议**（**SOAP**））的试验和错误产生的。这些协议由于其严格性、冗长性和使用它们创建 API 的困难而被淘汰。这些系统的问题被识别出来，REST 的约束被创建出来，以防止这些问题再次发生。

第一个约束要求客户端和服务器必须有关注点的分离。客户端不能处理永久数据存储，服务器不能处理任何与用户界面有关的事务。

第二个约束是服务器必须是无状态的。这意味着处理请求所需的任何信息都存储在请求本身或由客户端存储。服务器无状态的一个例子是 Flask 中的会话对象。会话对象不会将其信息存储在服务器上，而是将其存储在客户端的 cookie 中。每次请求都会发送 cookie 给服务器解析，并确定所请求资源的必要数据是否存储在其中，而不是服务器为每个用户存储会话信息。

第三个约束是提供的所有资源必须具有统一的接口。这个约束有许多不同的部分，如下所示：

+   接口是围绕资源构建的，在我们的案例中是模型。

+   服务器发送的数据不是服务器中的实际数据，而是一个表示。例如，实际数据库不会随每个请求发送，而是发送数据的 JSON 抽象。

+   服务器发送的数据足以让客户端修改服务器上的数据。在前面的例子中，传递给客户端的 ID 起到了这个作用。

+   API 提供的每个资源必须以相同的方式表示和访问。例如，一个资源不能以 XML 表示，另一个以 JSON 表示，一个通过原始 TCP，一个通过 HTTP。

最后一个约束是系统必须允许层。负载均衡器、代理、缓存和其他服务器和服务可以在客户端和服务器之间起作用，只要最终结果与它们不在那里时相同。

当系统遵循所有这些约束时，被认为是一个 RESTful 系统。最常见的 RESTful 系统形式是由 HTTP 和 JSON 构建的。每个资源位于自己的 URL 路径上，并使用不同的 HTTP 请求类型进行修改。通常采用以下形式：

| HTTP 方法 | URL | 操作 |
| --- | --- | --- |
| `GET` | `http://host/resource` | 获取所有资源表示 |
| `GET` | `http://host/resource/1` | 获取 ID 为 1 的资源 |
| `POST` | `http://host/resource` | 从`POST`中的表单数据创建新资源 |
| `PUT` | `http://host/resource/1` | 修改 ID 为 1 的资源的现有数据 |
| `DELETE` | `http://host/resource/1` | 删除 ID 为 1 的资源 |

例如，对第二个`GET`请求的响应将如下所示：

```py
{
    "id": 100,
    "date": "2015-03-02T00:24:36+00:00",
    "title": "Resource #98"
}
```

在 REST API 中，返回正确的 HTTP 状态代码与响应数据同样非常重要，以便通知客户端服务器上实际发生了什么，而无需客户端解析返回的消息。以下是 REST API 中使用的主要 HTTP 代码及其含义的列表。

| HTTP 代码 | 名称 | 含义 |
| --- | --- | --- |
| 200 | OK | HTTP 的默认代码。请求成功，并返回了数据。 |
| 201 | 创建成功 | 请求成功，并在服务器上创建了一个新资源。 |
| 204 | 无内容 | 请求成功，但响应未返回任何内容。 |
| 400 | 错误请求 | 请求被拒绝，因为存在某种感知的客户端错误，要么是格式错误的请求，要么是缺少必需的数据。 |
| 401 | 未经授权 | 请求被拒绝，因为客户端未经身份验证，应在再次请求此资源之前进行身份验证。 |
| 403 | 禁止 | 请求被拒绝，因为客户端没有权限访问此资源。这与 401 代码相反，后者假定用户未经身份验证。403 代码表示无论身份验证如何，资源都是不可访问的。 |
| 404 | 未找到 | 请求的资源不存在。 |
| 405 | 方法不允许 | 请求被拒绝，因为 URL 不可用的 HTTP 方法。 |

# 设置 RESTful Flask API

在我们的应用程序中，我们将在数据库中创建一个博客文章数据的 RESTful 接口。数据的表示将以 JSON 格式发送。数据将使用前面表格中的一般形式进行检索和修改，但 URI 将是`/api/posts`。

我们可以使用标准的 Flask 视图来创建 API，但 Flask 扩展**Flask Restful**使任务变得更加容易。

安装 Flask Restful：

```py
$ pip install Flask-Restful

```

在`extensions.py`文件中，初始化将处理所有路由的`Api`对象：

```py
from flask.ext.restful import Api
…
rest_api = Api()
```

我们的 Post API 的控制逻辑和视图应存储在`controllers`文件夹中的新文件夹`rest`中。在此文件夹中，我们需要一个空的`__init__.py`和一个名为`post.py`的文件。在`post.py`中，让我们创建一个简单的*Hello World*示例： 

```py
from flask.ext.restful import Resource

class PostApi(Resource):
    def get(self):
        return {'hello': 'world'}
```

在 Flask Restful 中，每个 REST 资源都被定义为从`Resource`对象继承的类。就像第四章中显示的`MethodView`对象一样，从`Resource`对象继承的任何类都使用命名为 HTTP 方法的方法定义其逻辑。例如，当`GET` HTTP 方法命中`PostApi`类时，将执行`get`方法。

就像我们使用的其他 Flask 扩展一样，在`__init__.py`文件中的应用程序对象上需要初始化`Api`对象，该文件包含`create_app`函数。`PostApi`类还将使用`Api`对象的`add_resource()`方法定义其路由：

```py
from .extensions import (
    bcrypt,
    oid,
    login_manager,
    principals,
    rest_api
)
from .controllers.rest.post import PostApi

def create_app(object_name):
    …
    rest_api.add_resource(PostApi, '/api/post')
    rest_api.init_app(app)
```

现在，如果您在浏览器中打开`/api/post` URI，将显示*Hello World* JSON。

# GET 请求

对于我们的一些`GET`，`PUT`和`DELETE`请求，我们的 API 将需要修改帖子的 ID。`add_resource`方法可以接受多个路由，因此让我们添加捕获传递的 ID 的第二个路由：

```py
   rest_api.add_resource(
        PostApi,
        '/api/post',
        '/api/post/<int:post_id>',
        endpoint='api'
    )
```

现在`get`方法将需要接受`post_id`作为关键字参数：

```py
class PostApi(Resource):
    def get(self, post_id=None):
        if post_id:
            return {"id": post_id}

        return {"hello": "world"}
```

要发送到客户端的数据必须是 JSON 中的 Post 对象的表示，那么我们的 Post 对象将如何转换？Flask Restful 通过`fields`对象和`marshal_with`函数装饰器提供了将任何对象转换为 JSON 的方法。

## 输出格式

输出格式是通过创建代表基本类型的`field`对象的字典来定义的。字段的键定义了字段将尝试转换的属性。通过将字典传递给`marshal_with`装饰器，`get`方法尝试返回的任何对象都将首先使用字典进行转换。这也适用于对象列表：

```py
from flask import abort 
from flask.ext.restful import Resource, fields, marshal_with
from webapp.models import Post

post_fields = {
    'title': fields.String(),
    'text': fields.String(),
    'publish_date': fields.DateTime(dt_format='iso8601')
}

class PostApi(Resource):
    @marshal_with(post_fields)
    def get(self, post_id=None):
        if post_id:
            post = Post.query.get(post_id)
            if not post:
                abort(404)

            return post
        else:
            posts = Post.query.all()
            return posts
```

在浏览器中重新加载 API 时，每个 Post 对象将以 JSON 格式显示。但是，问题在于 API 不应返回帖子创建表单中所见的 WYSIWYG 编辑器中的 HTML。如前所述，服务器不应关心 UI，而 HTML 纯粹是用于输出规范。为了解决这个问题，我们需要一个自定义字段对象，它可以从字符串中去除 HTML。在名为`fields.py`的`rest`文件夹中添加以下内容：

```py
from HTMLParser import HTMLParser
from flask.ext.restful import fields

class HTMLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []

    def handle_data(self, d):
        self.fed.append(d)

    def get_data(self):
        return ''.join(self.fed)

    def strip_tags(html):
        s = HTMLStripper()
        s.feed(html)

    return s.get_data()

class HTMLField(fields.Raw):
    def format(self, value):
        return strip_tags(str(value))
```

现在，我们的`post_fields`字典应该更新以适应新字段：

```py
from .fields import HTMLField

post_fields = {
    'title': fields.String(),
    'text': HTMLField(),
    'publish_date': fields.DateTime(dt_format='iso8601')
}
```

使用标准库`HTMLParser`模块，我们现在有一个`strip_tags`函数，它将返回任何已清除 HTML 标记的字符串。通过从`fields.Raw`类继承并通过`strip_tags`函数发送值，定义了一个新的字段类型`HTMLfield`。如果页面再次重新加载，所有 HTML 都将消失，只剩下文本。

Flask Restful 提供了许多默认字段：

+   `fields.String`：这将使用`str()`转换值。

+   `fields.FormattedString`：这在 Python 中传递格式化的字符串，变量名在括号中。

+   `fields.Url`：这提供了与 Flask `url_for`函数相同的功能。

+   `fields.DateTime`：这将 Python `date`或`datetime`对象转换为字符串。格式关键字参数指定字符串应该是`ISO8601`日期还是`RFC822`日期。

+   `fields.Float`：这将将值转换为浮点数的字符串表示。

+   `fields.Integer`：这将将值转换为整数的字符串表示。

+   `fields.Nested`：这允许通过另一个字段对象的字典来表示嵌套对象。

+   `fields.List`：与 MongoEngine API 类似，此字段将另一个字段类型作为参数，并尝试将值列表转换为字段类型的 JSON 列表。

+   `fields.Boolean`：这将将值转换为布尔参数的字符串表示。

还有两个字段应该添加到返回的数据中：作者和标签。评论将被省略，因为它们应该包含在自己的资源下。

```py
nested_tag_fields = {
    'id': fields.Integer(),
    'title': fields.String()
}

post_fields = {
    'author': fields.String(attribute=lambda x: x.user.username),
    'title': fields.String(),
    'text': HTMLField(),
    'tags': fields.List(fields.Nested(nested_tag_fields)),
    'publish_date': fields.DateTime(dt_format='iso8601')
}
```

`author`字段使用`field`类的属性关键字参数。这允许表示对象的任何属性，而不仅仅是基本级别的属性。因为标签的多对多关系返回对象列表，所以不能使用相同的解决方案。使用`ListField`中的`NestedField`类型和另一个字段字典，现在可以返回标签字典的列表。这对 API 的最终用户有额外的好处，因为它们可以轻松查询标签 ID，就像有一个标签 API 一样。

## 请求参数

在向资源的基础发送`GET`请求时，我们的 API 当前发送数据库中的所有 Post 对象。如果对象的数量较少或使用 API 的人数较少，则这是可以接受的。但是，如果任一方增加，API 将对数据库施加大量压力。与 Web 界面类似，API 也应该进行分页。

为了实现这一点，我们的 API 将需要接受一个`GET`查询字符串参数`page`，指定要加载的页面。Flask Restful 提供了一种方法来获取请求数据并解析它。如果必需的参数不存在，或者类型不匹配，Flask Restful 将自动创建一个 JSON 错误消息。在名为`parsers.py`的`rest`文件夹中的新文件中，添加以下代码：

```py
from flask.ext.restful import reqparse

post_get_parser = reqparse.RequestParser()
post_get_parser.add_argument(
    'page',
    type=int,
    location=['args', 'headers'],
    required=False
)
```

现在，`PostApi`类将需要更新以与我们的解析器一起使用：

```py
from .parsers import post_get_parser

class PostApi(Resource):
    @marshal_with(post_fields)
    def get(self, post_id=None):
        if post_id:
            post = Post.query.get(post_id)
            if not post:
                abort(404)

            return post
        else:
            args = post_get_parser.parse_args()
            page = args['page'] or 1
            posts = Post.query.order_by(
                Post.publish_date.desc()
            ).paginate(page, 30)

            return posts.items
```

在上面的示例中，`RequestParser`在查询字符串或请求标头中查找`page`变量，并从该页面返回 Post 对象的页面。

使用`RequestParser`创建解析器对象后，可以使用`add_argument`方法添加参数。`add_argument`的第一个参数是要解析的参数的键，但`add_argument`还接受许多关键字参数：

+   `action`：这是解析器在成功解析后对值执行的操作。两个可用选项是`store`和`append`。`store`将解析的值添加到返回的字典中。`append`将解析的值添加到字典中列表的末尾。

+   `case_sensitive`：这是一个`boolean`参数，用于允许或不允许键区分大小写。

+   `choices`：这类似于 MongoEngine，是参数允许的值列表。

+   `default`：如果请求中缺少参数，则生成的值。

+   `dest`：这是将解析值添加到返回数据中的键。

+   `help`：这是一个消息，如果验证失败，将返回给用户。

+   `ignore`：这是一个`boolean`参数，允许或不允许类型转换失败。

+   `location`：这表示要查找数据的位置。可用的位置是：

+   `args`以查找`GET`查询字符串

+   `headers`以查找 HTTP 请求标头

+   `form`以查找 HTTP `POST`数据

+   `cookies`以查找 HTTP cookies

+   `json`以查找任何发送的 JSON

+   `files`以查找`POST`文件数据

+   required：这是一个`boolean`参数，用于确定参数是否是可选的。

+   store_missing：这是一个`boolean`参数，用于确定是否应存储默认值，如果参数不在请求中。

+   类型：这是 Python 类型，用于转换传递的值。

使用 Flask Restful 解析器，很容易向 API 添加新参数。例如，让我们添加一个用户参数，允许我们搜索用户发布的所有帖子。首先，在`parsers.py`文件中，添加以下内容：

```py
post_get_parser = reqparse.RequestParser()
post_get_parser.add_argument(
    'page',
    type=int,
    location=['json', 'args', 'headers']
)
post_get_parser.add_argument(
    'user',
    type=str,
    location=['json', 'args', 'headers']
)
```

然后，在`post.py`中添加以下内容：

```py
class PostApi(Resource):
    @marshal_with(post_fields)
    def get(self, post_id=None):
        if post_id:
            post = Post.query.get(post_id)
            if not post:
                abort(404)

            return post
        else:
            args = post_get_parser.parse_args()
            page = args['page'] or 1

            if args['user']:
                user = User.query.filter_by(
                    username=args['user']
                ).first()
                if not user:
                    abort(404)

                posts = user.posts.order_by(
                    Post.publish_date.desc()
                ).paginate(page, 30)
            else:
                posts = Post.query.order_by(
                    Post.publish_date.desc()
                ).paginate(page, 30)

            return posts.items
```

当从`Resource`调用 Flask 的`abort`函数时，Flask Restful 将自动创建一个错误消息，以与状态代码一起返回。

# POST 请求

使用我们对 Flask Restful 解析器的新知识，可以添加`POST`端点。首先，我们需要一个解析器，它将获取标题、正文文本和标签列表。在`parser.py`文件中，添加以下内容：

```py
post_post_parser = reqparse.RequestParser()
post_post_parser.add_argument(
    'title',
    type=str,
    required=True,
    help="Title is required"
)
post_post_parser.add_argument(
    'text',
    type=str,
    required=True,
    help="Body text is required"
)
post_post_parser.add_argument(
    'tags',
    type=str,
    action='append'
)
```

接下来，`PostApi`类将需要一个`post`方法来处理传入的请求。`post`方法将使用给定的标题和正文文本。此外，如果存在标签键，则将标签添加到帖子中，如果传递的标签不存在，则创建新标签：

```py
import datetime
from .parsers import (
    post_get_parser,
    post_post_parser
)
from webapp.models import db, User, Post, Tag

class PostApi(Resource):
    …
    def post(self, post_id=None):
        if post_id:
            abort(400)
        else:
            args = post_post_parser.parse_args(strict=True)
            new_post = Post(args['title']) 
            new_post.date = datetime.datetime.now()
            new_post.text = args['text']

            if args['tags']:
                for item in args['tags']:
                    tag = Tag.query.filter_by(title=item).first()

                    # Add the tag if it exists.
                    # If not, make a new tag
                    if tag:
                        new_post.tags.append(tag)
                    else:
                        new_tag = Tag(item) 
                        new_post.tags.append(new_tag)

            db.session.add(new_post)
            db.session.commit()
            return new_post.id, 201
```

在`return`语句处，如果返回一个元组，则第二个参数将被视为状态代码。还有一个作为额外标头值的第三个值，通过传递一个字典。

为了测试这段代码，必须使用与 Web 浏览器不同的工具，因为在浏览器中很难创建自定义的 POST 请求而不使用浏览器插件。而是使用名为 curl 的工具。**Curl**是 Bash 中包含的命令行工具，允许创建和操作 HTTP 请求。要使用 curl 执行`GET`请求，只需传递 URL：

```py
$ curl http://localhost:5000/api/post/1

```

要传递`POST`变量，使用`d`标志：

```py
$ curl -d "title=From REST" \
-d "text=The body text from REST" \
-d "tag=Python" \
http://localhost:5000/api/post

```

新创建的帖子的 id 应该被返回。但是，如果你现在在浏览器中加载你创建的帖子，会出现错误。这是因为我们的`Post`对象没有与之关联的用户。为了让帖子对象分配给用户，并且只有网站的经过身份验证的用户才有权限`POST`帖子，我们需要创建一个身份验证系统。

## 身份验证

为了解决我们的身份验证问题，可以使用 Flask-Login，并检查登录的 cookie 数据。然而，这将要求希望使用我们的 API 的开发人员通过 Web 界面登录他们的程序。我们也可以让开发人员在每个请求中发送他们的登录数据，但是只在绝对必要时发送敏感信息是一个很好的设计实践。相反，我们的 API 将提供一个`auth`端点，允许他们发送登录凭据并获得一个访问令牌。

这个`access`令牌将由 Flask 使用的 Python 库*it's dangerous*创建，用于对 cookie 上的会话数据进行编码，因此它应该已经安装。令牌将是一个由应用程序的秘钥加密签名的 Python 字典，其中包含用户的 id。这个令牌中编码了一个过期日期，在过期后将不允许使用。这意味着即使令牌被恶意用户窃取，它在客户端必须重新进行身份验证之前只能在有限的时间内使用。首先，需要一个新的解析器来处理解析用户名和密码数据：

```py
user_post_parser = reqparse.RequestParser()
user_post_parser.add_argument('username', type=str, required=True)
user_post_parser.add_argument('password', type=str, required=True)
```

在`rest`文件夹内新建一个名为`auth.py`的文件，添加以下代码：

```py
from flask import abort, current_app

from .parsers import user_post_parser
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

class AuthApi(Resource):
    def post(self):
        args = user_post_parser.parse_args()
        user = User.query.filter_by(
            username=args['username']
        ).one()

        if user.check_password(args['password']):
            s = Serializer(
                current_app.config['SECRET_KEY'], 
                expires_in=600
            )
            return {"token": s.dumps({'id': user.id})}
        else:
            abort(401)
```

### 注意

不要允许用户通过不安全的连接发送他们的登录凭据！如果你希望保护用户的数据，需要使用 HTTPS。最好的解决方案是要求整个应用程序都使用 HTTPS，以避免可能性。

我们的 API 的用户必须将从这个资源接收到的令牌传递给任何需要用户凭据的方法。但是，首先我们需要一个验证令牌的函数。在`models.py`文件中，`verify_auth_token`将是`User`对象上的`staticmethod`：

```py
from itsdangerous import (
    TimedJSONWebSignatureSerializer as Serializer,
    BadSignature,
    SignatureExpired
)
from flask import current_app

class User(db.Model):
…
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])

        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None

        user = User.query.get(data['id'])
        return user
```

我们的`POST`解析器需要一个令牌参数来接受`auth`令牌：

```py
post_post_parser = reqparse.RequestParser()
post_post_parser.add_argument(
    'token',
    type=str,
    required=True,
    help="Auth Token is required to create posts"
)
```

现在，我们的`post`方法可以正确地添加新的帖子，如下所示：

```py
class PostApi(Resource):
    def get(self, post_id=None):
       …

    def post(self, post_id=None):
        if post_id:
            abort(405)
        else:
            args = post_post_parser.parse_args(strict=True)

            user = User.verify_auth_token(args['token'])
            if not user:
                abort(401)

            new_post = Post(args['title'])
            new_post.user = user
            …
```

使用 curl，我们现在可以测试我们的`auth`和`post`API。为了简洁起见，这里省略了令牌，因为它非常长：

```py
$ curl -d "username=user" \
-d "password=password" \
http://localhost:5000/api/auth

{token: <the token>}

$ curl -d "title=From REST" \
-d "text=this is from REST" \
-d "token=<the token>" \
-d "tags=Python" \
-d "tags=Flask" \
http://localhost:5000/api/post

```

# PUT 请求

如本章开头的表格所列，`PUT`请求用于更改现有资源的值。与`post`方法一样，首先要做的是在`parsers.py`中创建一个新的解析器：

```py
post_put_parser = reqparse.RequestParser()
post_put_parser.add_argument(
    'token',
    type=str,
    required=True,
    help="Auth Token is required to edit posts"
)
post_put_parser.add_argument(
    'title',
    type=str
)
post_put_parser.add_argument(
    'text',
    type=str
)
post_put_parser.add_argument(
    'tags',
    type=str,
    action='append'
)
```

`put`方法的逻辑与`post`方法非常相似。主要区别在于每个更改都是可选的，任何没有提供`post_id`的请求都将被拒绝：

```py
from .parsers import (
    post_get_parser,
    post_post_parser,
    post_put_parser
)

class PostApi(Resource):
    @marshal_with(post_fields)
    def get(self, post_id=None):
        …

    def post(self, post_id=None):
        …

    def put(self, post_id=None):
        if not post_id:
            abort(400)

        post = Post.query.get(post_id)
        if not post:
            abort(404)

        args = post_put_parser.parse_args(strict=True)
        user = User.verify_auth_token(args['token'])
        if not user:
            abort(401)
        if user != post.user:
            abort(403)

        if args['title']:
            post.title = args['title']

        if args['text']:
            post.text = args['text']

        if args['tags']:
            for item in args['tags']:
                tag = Tag.query.filter_by(title=item).first()

                # Add the tag if it exists. If not, make a new tag
                if tag:
                    post.tags.append(tag)
                else:
                    new_tag = Tag(item)
                    post.tags.append(new_tag)

        db.session.add(post)
        db.session.commit()
        return post.id, 201
```

为了测试这个方法，curl 也可以使用`-X`标志创建`PUT`请求：

```py
$ curl -X PUT \
-d "title=Modified From REST" \
-d "text=this is from REST" \
-d "token=<the token>" \
-d "tags=Python" -d "tags=Flask" -d "tags=REST" \
http://localhost:5000/api/post/101

```

# DELETE 请求

最后，我们有`DELETE`请求，这是四种支持方法中最简单的。`delete`方法的主要区别在于它不返回任何内容，这是`DELETE`请求的接受标准：

```py
class PostApi(Resource):
    @marshal_with(post_fields)
    def get(self, post_id=None):
        …

    def post(self, post_id=None):
        …

    def put(self, post_id=None):
        …

    def delete(self, post_id=None):
        if not post_id:
            abort(400)

        post = Post.query.get(post_id)
        if not post:
            abort(404)

        args = post_delete_parser.parse_args(strict=True)
        user = verify_auth_token(args['token'])
        if user != post.user:
            abort(403)

        db.session.delete(post)
        db.session.commit()
        return "", 204
```

同样，我们可以测试：

```py
$ curl -X DELETE\
-d "token=<the token>"\
http://localhost:5000/api/post/102

```

如果一切顺利删除，你应该收到一个 204 状态码，什么都不应该显示出来。

在我们完全迁移出 REST 之前，读者还有一个最后的挑战，来测试你对 Flask Restful 的理解。尝试创建一个评论 API，不仅可以从`http://localhost:5000/api/comments`进行修改，还允许开发人员通过 URL`http://localhost:5000/api/post/<int:post_id>/comments`来修改特定帖子上的评论。

# 摘要

我们的 Post API 现在是一个完整的功能。如果开发者希望，他们可以使用这个 API 创建桌面或移动应用程序，而无需使用 HTML 抓取，这是一个非常繁琐和漫长的过程。给予希望将您的网站作为平台使用的开发者这样做的能力将增加您网站的受欢迎程度，因为他们实质上会通过他们的应用程序或网站为您提供免费广告。

在下一章中，我们将使用流行的程序 Celery 来异步运行程序和任务与我们的应用程序。


# 第九章：使用 Celery 创建异步任务

在创建 Web 应用程序时，保持请求处理时间在 50 毫秒左右以下是至关重要的。由于大部分响应时间都被等待用户连接所占据，额外的处理时间可能会挂起服务器。应该避免服务器上的任何额外处理。然而，在 Web 应用程序中，有几个操作可能需要花费超过几秒钟的时间，特别是涉及复杂的数据库操作或图像处理时。为了保护用户体验，将使用名为 Celery 的任务队列将这些操作移出 Flask 进程。

# Celery 是什么？

**Celery**是用 Python 编写的异步任务队列。Celery 通过 Python 多进程库*并发*运行任务，这些任务是用户定义的函数。Celery 接收消息，告诉它从**代理**开始任务，通常称为消息队列，如下图所示：

![Celery 是什么？](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_09_01.jpg)

**消息队列**是一个专门设计用于在生产者进程和消费者进程之间发送数据的系统。**生产者进程**是创建要发送到队列中的消息的任何程序，**消费者进程**是从队列中取出消息的任何程序。从生产者发送的消息存储在**先进先出**（**FIFO**）队列中，最旧的项目首先被检索。消息存储直到消费者接收消息，之后消息被删除。消息队列提供实时消息传递，而不依赖于轮询，即持续检查进程状态的过程。当消息从生产者发送时，消费者正在其连接到消息队列上*监听*新消息；消费者不会不断地联系队列。这种差异就像**AJAX**和**WebSockets**之间的差异；AJAX 需要与服务器保持不断的联系，而 WebSockets 只是一个持续的流。

可以用传统数据库替换消息队列。Celery 甚至内置了对 SQLAlchemy 的支持以实现这一点。然而，强烈不建议使用数据库作为 Celery 的代理。使用数据库代替消息队列需要消费者不断地轮询数据库以获取更新。此外，由于 Celery 使用多进程进行并发处理，大量读取的连接数量会迅速增加。在中等负载下，使用数据库需要生产者同时向数据库进行大量写入，而消费者正在读取。数据库不能有太多的连接同时进行读取、写入和更新相同的数据。当这种情况发生时，表通常会被锁定，所有其他连接都在等待每次写入完成后才能读取数据，反之亦然。更糟糕的是，这可能导致竞争条件，即并发事件更改和读取相同的资源，并且每个并发操作都使用过时版本的数据。特定于 Celery，这可能导致相同的操作针对相同的消息多次运行。

也可以使用消息队列作为代理和数据库来存储任务的结果。在前面的图表中，消息队列用于发送任务请求和任务结果。

然而，使用数据库存储任务的最终结果允许最终产品无限期地存储，而消息队列将在生产者接收数据后立即丢弃数据，如下图所示：

![Celery 是什么？](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_09_02.jpg)

这个数据库通常是一个键值 NoSQL 存储，以帮助处理负载。如果您计划对先前运行的任务进行分析，这将非常有用；否则，最好只使用消息队列。

甚至有一个选项可以完全丢弃任务的结果，而不返回任务的结果。这样做的缺点是生产者无法知道任务是否成功，但在较小的项目中通常足够。

对于我们的堆栈，我们将使用**RabbitMQ**作为消息代理。RabbitMQ 在所有主要操作系统上运行，并且非常简单设置和运行。Celery 还支持 RabbitMQ，无需任何额外的库，并且是 Celery 文档中推荐的消息队列。

### 注意

在撰写本文时，尚无法在 Python 3 中使用 RabbitMQ 与 Celery。您可以使用 Redis 代替 RabbitMQ。唯一的区别将是连接字符串。有关更多信息，请参见[`docs.celeryproject.org/en/latest/getting-started/brokers/redis.html`](http://docs.celeryproject.org/en/latest/getting-started/brokers/redis.html)。

# 设置 Celery 和 RabbitMQ

要使用`pip`安装 Celery，请运行以下命令：

```py
$ pip install Celery

```

我们还需要一个 Flask 扩展来帮助处理初始化 Celery：

```py
$ pip install Flask-Celery-Helper

```

Flask 文档指出，Flask 对 Celery 的扩展是不必要的。但是，在使用应用程序工厂组织应用程序时，使 Celery 服务器能够与 Flask 的应用程序上下文一起工作是很重要的。因此，我们将使用**Flask-Celery-Helper**来完成大部分工作。

接下来，需要安装 RabbitMQ。RabbitMQ 不是用 Python 编写的；因此，每个操作系统的安装说明都将不同。幸运的是，RabbitMQ 在[`www.rabbitmq.com/download.html`](https://www.rabbitmq.com/download.html)上为每个操作系统维护了详细的说明列表。

安装 RabbitMQ 后，打开终端窗口并运行以下命令：

```py
$ rabbitmq-server

```

这将启动一个带有用户名为 guest 和密码为 guest 的 RabbitMQ 服务器。默认情况下，RabbitMQ 只接受本地主机上的连接，因此这种设置对开发来说是可以的。

# 在 Celery 中创建任务

如前所述，Celery 任务只是执行一些操作的用户定义函数。但在编写任何任务之前，需要创建我们的 Celery 对象。这是 Celery 服务器将导入以处理运行和调度所有任务的对象。

至少，Celery 需要一个配置变量才能运行：与消息代理的连接。连接被定义为 URL，就像 SQLAlchemy 连接一样。后端，用于存储我们任务结果的地方，也被定义为 URL，如下面的代码所示：

```py
class DevConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///../database.db'
    CELERY_BROKER_URL = "amqp://guest:guest@localhost:5672//"
    CELERY_BACKEND = "amqp://guest:guest@localhost:5672//"
In the extensions.py file, the Celery class from Flask-Celery-Helper will be initialized:
```

```py
from flask.ext.celery import Celery
celery = Celery()
```

因此，为了使我们的 Celery 进程能够与数据库和任何其他 Flask 扩展一起工作，它需要在我们的应用程序上下文中工作。为了做到这一点，Celery 需要为每个进程创建我们应用程序的新实例。与大多数 Celery 应用程序不同，我们需要一个 Celery 工厂来创建应用程序实例并在其上注册我们的 Celery 实例。在顶级目录中的一个新文件中，与`manage.py`位于同一位置，命名为`celery_runner.py`，添加以下内容：

```py
import os
from webapp import create_app
from celery import Celery
from webapp.tasks import log

def make_celery(app):
    celery = Celery(
        app.import_name,
        broker=app.config['CELERY_BROKER_URL'],
        backend=app.config['CELERY_BACKEND_URL']
    )
    celery.conf.update(app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask

    return celery

env = os.environ.get('WEBAPP_ENV', 'dev')
flask_app = create_app(
    'webapp.config.%sConfig' % env.capitalize()
)
celery = make_celery(flask_app)
```

`make_celery`函数的作用是在 Python 的`with`块中包装对每个 Celery 任务的每次调用。这确保了对任何 Flask 扩展的每次调用都可以正常工作，因为它正在与我们的应用程序一起工作。还要确保不要将 Flask 应用程序实例命名为`app`，因为 Celery 会尝试导入任何名为`app`或`celery`的对象作为 Celery 应用程序实例。因此，将您的 Flask 对象命名为`app`将导致 Celery 尝试将其用作 Celery 对象。

现在，我们可以编写我们的第一个任务。这将是一个简单的任务，只是返回传递给它的任何字符串。在应用程序目录中的一个新文件中命名为`tasks.py`，添加以下内容：

```py
from webapp.extensions import celeryfrom webapp.extensions import celery
@celery.task()
def log(msg):
    return msg
```

现在，谜题的最后一部分是在新的终端窗口中运行 Celery 进程，称为**worker**。再次强调，这是将监听我们的消息代理以启动新任务的进程：

```py
$ celery worker -A celery_runner --loglevel=info

```

`loglevel`标志存在的原因是，您可以在终端窗口中看到任务已收到的确认以及其输出的可用性。

现在，我们可以向 Celery 工作进程发送命令。打开 `manage.py` shell 并导入 `log` 任务：

```py
>>> from webapp.tasks import log
>>> log("Message")
Message
>>> result = log.delay("Message")

```

该函数可以像调用其他函数一样调用；这样做将在当前进程中执行该函数。但是，在任务上调用 `delay` 方法将向工作进程发送消息，以使用给定的参数执行该函数。

在运行 Celery 工作进程的终端窗口中，您应该看到类似以下内容：

```py
Task tasks.log succeeded in 0.0005873600021s: 'Message'

```

对于任何异步任务，`ready` 方法可用于判断任务是否成功完成。如果为真，则可以使用 `get` 方法来检索任务的结果。

```py
>>> result.ready()
True
>>> result.get()
"Message"

```

`get` 方法会导致当前进程等待，直到 `ready` 函数返回 `True` 以检索结果。因此，在调用任务后立即调用 `get` 实质上使任务同步。因此，任务实际上很少返回值给生产者。绝大多数任务执行某些操作然后退出。

当在 Celery 工作进程上运行任务时，可以通过 `state` 属性访问任务的状态。这允许更细粒度地了解任务在工作进程中当前正在执行的操作。可用的状态如下：

+   `FAILURE`：任务失败，所有重试也失败

+   `PENDING`：任务尚未被工作进程接收

+   `RECEIVED`：任务已被工作进程接收，但尚未处理

+   `RETRY`：任务失败，正在等待重试

+   `REVOKED`：任务已停止

+   `STARTED`：工作进程已开始处理任务

+   `SUCCESS`：任务成功完成

在 Celery 中，如果任务失败，则任务可以使用 `retry` 方法重新调用自身，如下所示：

```py
@celery.task(bind=True)
def task(self, param):
    try:
        some_code
    except Exception, e:
        self.retry(exc=e)
```

装饰器函数中的 `bind` 参数告诉 Celery 将任务对象的引用作为函数的第一个参数传递。使用 `self` 参数，可以调用 `retry` 方法，该方法将使用相同的参数重新运行任务。可以将其他参数传递给函数装饰器，以更改任务的行为：

+   `max_retries`：这是任务在被声明为失败之前可以重试的最大次数。

+   `default_retry_delay`：这是在再次运行任务之前等待的时间（以秒为单位）。如果您预期导致任务失败的条件是短暂的，例如网络错误，那么最好将其保持在大约一分钟左右。

+   `rate_limit`：这指定在给定间隔内允许运行此任务的唯一调用总数。如果值是整数，则是每秒允许运行此任务的总数。该值也可以是形式为 *x/m* 的字符串，表示每分钟 *x* 个任务，或形式为 *x/h* 的字符串，表示每小时 *x* 个任务。例如，传入 *5/m* 将只允许每分钟调用此任务五次。

+   `time_limit`：如果指定，任务将在运行时间超过此秒数时被终止。

+   `ignore_result`：如果不使用任务的返回值，则不要将其发送回。

最好为每个任务指定所有这些内容，以避免任务不会运行的任何机会。

# 运行 Celery 任务

`delay` 方法是 `apply_async` 方法的简写版本，格式如下所示：

```py
task.apply_async(
    args=[1, 2],
    kwargs={'kwarg1': '1', 'kwarg2': '2'}
)
```

但是，`args` 关键字可以是隐式的：

```py
apply_async([1, 2], kwargs={'kwarg1': '1', 'kwarg2': '2'})
```

调用 `apply_async` 允许您在任务调用中定义一些额外的功能，这些功能在 `delay` 方法中无法指定。首先，`countdown` 选项指定工作进程在接收到任务后等待运行任务的时间（以秒为单位）：

```py
>>> from webapp.tasks import log
>>> log.apply_async(["Message"], countdown=600)

```

`countdown` 不能保证任务将在 `600` 秒后运行。`countdown` 只表示任务在 *x* 秒后准备处理。如果所有工作进程都忙于处理其他任务，则任务将不会立即运行。

`apply_async` 提供的另一个关键字参数是 `eta` 参数。`eta` 通过一个指定任务应该运行的确切时间的 Python `datetime` 对象传递。同样，`eta` 不可靠。

```py
>>> import datetime
>>> from webapp.tasks import log
# Run the task one hour from now
>>> eta = datetime.datetime.now() + datetime.timedelta(hours=1)
>>> log.apply_async(["Message"], eta=eta)

```

## Celery 工作流

Celery 提供了许多方法来将多个依赖任务分组在一起，或者并行执行多个任务。这些方法受到函数式编程语言中的语言特性的很大影响。然而，要理解这是如何工作的，我们首先需要了解签名。考虑以下任务：

```py
@celery.task()
def multiply(x, y):
    return x * y
```

让我们看看一个**签名**的实际操作以理解它。打开 `manage.py` shell：

```py
>>> from celery import signature
>>> from webapp.tasks import multiply
# Takes the same keyword args as apply_async
>>> signature('webapp.tasks.multiply', args=(4, 4) , countdown=10)
webapp.tasks.multiply(4, 4)
# same as above
>>> from webapp.tasks import multiply
>>> multiply.subtask((4, 4), countdown=10)
webapp.tasks.multiply(4, 4)
# shorthand for above, like delay in that it doesn't take
# apply_async's keyword args
>>> multiply.s(4, 4)
webapp.tasks.multiply(4, 4)
>>> multiply.s(4, 4)()
16
>>> multiply.s(4, 4).delay()

```

调用任务的签名，有时称为任务的**子任务**，会创建一个可以传递给其他函数以执行的函数。执行签名，就像示例中倒数第三行那样，会在当前进程中执行函数，而不是在工作进程中执行。

### 部分

任务签名的第一个应用是函数式编程风格的部分。**部分**是最初接受许多参数的函数；然而，对原始函数应用操作以返回一个新函数，因此前 *n* 个参数始终相同。一个例子是一个不是任务的 `multiply` 函数：

```py
>>> new_multiply = multiply(2)
>>> new_multiply(5)
10
# The first function is unaffected
>>> multiply(2, 2)
4

```

这是一个虚构的 API，但这与 Celery 版本非常接近：

```py
>>> partial = multiply.s(4)
>>> partial.delay(4)

```

工作窗口中的输出应该显示 **16**。基本上，我们创建了一个新函数，保存到部分中，它将始终将其输入乘以四。

### 回调

一旦任务完成，根据前一个任务的输出运行另一个任务是非常常见的。为了实现这一点，`apply_async` 函数有一个 `link` 方法：

```py
>>> multiply.apply_async((4, 4), link=log.s())

```

工作器输出应该显示 `multiply` 任务和 `log` 任务都返回 **16**。

如果您有一个不需要输入的函数，或者您的回调不需要原始方法的结果，则必须使用 `si` 方法将任务签名标记为不可变：

```py
>>> multiply.apply_async((4, 4), link=log.si("Message"))

```

**回调**可以用来解决现实世界的问题。如果我们想要在每次任务创建新用户时发送欢迎电子邮件，那么我们可以通过以下调用产生该效果：

```py
>>> create_user.apply_async(("John Doe", password), link=welcome.s())

```

部分和回调可以结合产生一些强大的效果：

```py
>>> multiply.apply_async((4, 4), link=multiply.s(4))

```

重要的是要注意，如果保存了此调用并在其上调用了 `get` 方法，则结果将是 **16** 而不是 **64**。这是因为 `get` 方法不会返回回调方法的结果。这将在以后的方法中解决。

### 组

`group` 函数接受一个签名列表，并创建一个可调用函数来并行执行所有签名，然后返回所有结果的列表：

```py
>>> from celery import group
>>> sig = group(multiply.s(i, i+5) for i in range(10))
>>> result = sig.delay()
>>> result.get()
[0, 6, 14, 24, 36, 50, 66, 84, 104, 126]

```

### 链

`chain` 函数接受任务签名，并将每个结果的值传递给链中的下一个值，返回一个结果如下：

```py
>>> from celery import chain
>>> sig = chain(multiply.s(10, 10), multiply.s(4), multiply.s(20))
# same as above
>>> sig = (multiply.s(10, 10) | multiply.s(4) | multiply.s(20))
>>> result = sig.delay()
>>> result.get()
8000

```

链和部分可以进一步发展。链可以用于在使用部分时创建新函数，并且链可以嵌套如下：

```py
# combining partials in chains
>>> func = (multiply.s(10) | multiply.s(2))
>>> result = func.delay(16)
>>> result.get()
200
# chains can be nested
>>> func = (
 multiply.s(10) | multiply.s(2) | (multiply.s(4) | multiply.s(5))
)
>>> result = func.delay(16)
>>> result.get()
800

```

### 和弦

`chord` 函数创建一个签名，将执行一组签名，并将最终结果传递给回调：

```py
>>> from celery import chord
>>> sig = chord(
 group(multiply.s(i, i+5) for i in range(10)),
 log.s()
)
>>> result = sig.delay()
>>> result.get()
[0, 6, 14, 24, 36, 50, 66, 84, 104, 126]

```

就像链接参数一样，回调不会随着 `get` 方法返回。

使用 `chain` 语法与组和回调自动创建一个和弦签名：

```py
# same as above
>>> sig = (group(multiply.s(i, i+5) for i in range(10)) | log.s())
>>> result = sig.delay()
>>> result.get()
[0, 6, 14, 24, 36, 50, 66, 84, 104, 126]

```

### 定期运行任务

Celery 还有能力定期调用任务。对于熟悉 ***nix** 操作系统的人来说，这个系统很像命令行实用程序 `cron`，但它的额外好处是在我们的源代码中定义，而不是在某个系统文件中。因此，当我们的代码准备发布到 第十三章 *部署 Flask 应用* 中时，更新将更容易。此外，所有任务都在应用上下文中运行，而由 `cron` 调用的 Python 脚本则不会。

要添加定期任务，请将以下内容添加到 `DevConfig` 配置对象中：

```py
import datetime
…

CELERYBEAT_SCHEDULE = {
    'log-every-30-seconds': {
        'task': 'webapp.tasks.log',
        'schedule': datetime.timedelta(seconds=30),
        'args': ("Message",)
    },
}
```

此`configuration`变量定义了`log`任务应该每 30 秒运行一次，并将`args`元组作为参数传递。任何`timedelta`对象都可以用来定义运行任务的间隔。

要运行周期性任务，需要另一个名为`beat`工作程序的专门工作程序。在另一个终端窗口中，运行以下命令：

```py
$ celery -A celery_runner beat

```

如果您现在观看主要的`Celery`工作程序中的终端输出，您应该每 30 秒看到一个日志事件。

如果您的任务需要以更具体的间隔运行，例如，每周二在 6 月的凌晨 3 点和下午 5 点？对于非常具体的间隔，有`Celery` `crontab`对象。

为了说明`crontab`对象如何表示间隔，以下是一些示例：

```py
>>> from celery.schedules import crontab
# Every midnight
>>> crontab(minute=0, hour=0)
# Once a 5AM, then 10AM, then 3PM, then 8PM
>>> crontab(minute=0, hour=[5, 10, 15, 20])
# Every half hour
>>> crontab(minute='*/30')
# Every Monday at even numbered hours and 1AM
>>> crontab(day_of_week=1, hour ='*/2, 1')

```

该对象具有以下参数：

+   `分钟`

+   小时

+   `星期几`

+   `每月的日期`

+   `月份`

这些参数中的每一个都可以接受各种输入。使用纯整数时，它们的操作方式与`timedelta`对象类似，但它们也可以接受字符串和列表。当传递一个列表时，任务将在列表中的每个时刻执行。当传递一个形式为**/x*的字符串时，任务将在模运算返回零的每个时刻执行。此外，这两种形式可以组合成逗号分隔的整数和除法的字符串。

# 监控 Celery

当我们的代码被推送到服务器时，我们的`Celery`工作程序将不会在终端窗口中运行，它将作为后台任务运行。因此，Celery 提供了许多命令行参数来监视您的`Celery`工作程序和任务的状态。这些命令采用以下形式：

```py
$ celery –A celery_runner <command>

```

查看工作程序状态的主要任务如下：

+   `状态`：这会打印运行的工作程序以及它们是否正常运行

+   `结果`：当传递一个任务 id 时，这显示任务的返回值和最终状态

+   `清除`：使用此命令，代理中的所有消息将被删除

+   `检查活动`：这将列出所有活动任务

+   `检查已安排`：这将列出所有已使用`eta`参数安排的任务

+   `检查已注册`：这将列出所有等待处理的任务

+   `检查统计`：这将返回一个字典，其中包含有关当前运行的工作程序和代理的统计信息

## 使用 Flower 进行基于 Web 的监控

**Flower**是一个基于 Web 的实时管理工具，用于 Celery。在 Flower 中，可以监视所有活动的，排队的和已完成的任务。Flower 还提供了关于每个图表在队列中停留的时间以及执行所需的时间和每个任务的参数的图表和统计信息。

要安装 Flower，请使用以下`pip`：

```py
$ pip install flower

```

要运行它，只需将`flower`视为`Celery`命令，如下所示：

```py
$ celery flower -A celery_runner --loglevel=info

```

现在，打开浏览器到`http://localhost:5555`。最好在任务运行时熟悉界面，因此转到命令行并输入以下内容：

```py
>>> sig = chord(
 group(multiply.s(i, i+5) for i in xrange(10000)),
 log.s()
)
>>> sig.delay()

```

您的工作程序现在将开始处理 10,000 个任务。在任务运行时浏览不同的页面，看看 Flower 在工作程序真正忙碌时如何与其交互。

# 创建一个提醒应用

让我们来看一些 Celery 中的真实例子。假设我们网站上的另一页现在需要一个提醒功能。用户可以创建提醒，将在指定时间发送电子邮件到指定位置。我们需要一个模型，一个任务，以及一种在每次创建模型时自动调用我们的任务的方法。

让我们从以下基本的 SQLAlchemy 模型开始：

```py
class Reminder(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    date = db.Column(db.DateTime())
    email = db.Column(db.String())
    text = db.Column(db.Text())

    def __repr__(self):
        return "<Reminder '{}'>".format(self.text[:20])
```

现在我们需要一个任务，将发送电子邮件到模型中的位置。在我们的`tasks.py`文件中，添加以下任务：

```py
import smtplib
from email.mime.text import MIMEText

@celery.task(
    bind=True,
    ignore_result=True,
    default_retry_delay=300,
    max_retries=5
)
def remind(self, pk):
    reminder = Reminder.query.get(pk)
    msg = MIMEText(reminder.text)

    msg['Subject'] = "Your reminder"
    msg['From'] = your_email
    msg['To'] = reminder.email

    try:
        smtp_server = smtplib.SMTP('localhost')
        smtp_server.starttls()
        smtp_server.login(user, password)
        smtp_server.sendmail(
            your_email, 
            [reminder.email],
            msg.as_string()
        )
        smtp_server.close()

        return
    except Exception, e:
        self.retry(exc=e)
```

请注意，我们的任务接受的是主键而不是模型。这是对抗竞争条件的一种保护，因为传递的模型可能在工作程序最终处理它时已经过时。您还需要用自己的登录信息替换占位符电子邮件和登录。

当用户创建提醒模型时，我们如何调用我们的任务？我们将使用一个名为`events`的 SQLAlchemy 功能。SQLAlchemy 允许我们在我们的模型上注册回调，当对我们的模型进行特定更改时将被调用。我们的任务将使用`after_insert`事件，在新数据输入到数据库后被调用，无论模型是全新的还是正在更新。

我们需要在`tasks.py`中的回调：

```py
def on_reminder_save(mapper, connect, self):
    remind.apply_async(args=(self.id,), eta=self.date)
```

现在，在`__init__.py`中，我们将在我们的模型上注册我们的回调：

```py
from sqlalchemy import event
from .tasks import on_reminder_save

def create_app(object_name):
    app = Flask(__name__)
    app.config.from_object(object_name)

    db.init_app(app)
    event.listen(Reminder, 'after_insert', on_reminder_save)
    …
```

现在，每当模型被保存时，都会注册一个任务，该任务将向我们的用户发送一封电子邮件。

# 创建每周摘要

假设我们的博客有很多不使用 RSS 而更喜欢邮件列表的人，这是大量的用户。我们需要一种方法，在每周末结束时创建一个新帖子列表，以增加我们网站的流量。为了解决这个问题，我们将创建一个摘要任务，该任务将由一个 beat worker 在每个星期六的上午 10 点调用。

首先，在`tasks.py`中，让我们创建我们的任务如下：

```py
@celery.task(
    bind=True,
    ignore_result=True,
    default_retry_delay=300,
    max_retries=5
)
def digest(self):
    # find the start and end of this week
    year, week = datetime.datetime.now().isocalendar()[0:2]
    date = datetime.date(year, 1, 1)
    if (date.weekday() > 3):
        date = date + datetime.timedelta(days=7 - date.weekday())
    else:
        date = date - datetime.timedelta(days=date.weekday())
    delta = datetime.timedelta(days=(week - 1) * 7)
    start, end = date + delta, date + delta + datetime.timedelta(days=6)

    posts = Post.query.filter(
        Post.publish_date >= start,
        Post.publish_date <= end
    ).all()

    if (len(posts) == 0):
        return

    msg = MIMEText(
        render_template("digest.html", posts=posts),
        'html'
    )

    msg['Subject'] = "Weekly Digest"
    msg['From'] = your_email

    try:
        smtp_server = smtplib.SMTP('localhost')
        smtp_server.starttls()
        smtp_server.login(user, password)
        smtp_server.sendmail(
            your_email,
            [recipients],
            msg.as_string()
        )
        smtp_server.close()

        return
    except Exception, e:
        self.retry(exc=e)
```

我们还需要在`config.py`的配置对象中添加一个周期性计划来管理我们的任务：

```py
CELERYBEAT_SCHEDULE = {
    'weekly-digest': {
        'task': 'tasks.digest',
        'schedule': crontab(day_of_week=6, hour='10')
    },
}
```

最后，我们需要我们的电子邮件模板。不幸的是，电子邮件客户端中的 HTML 已经非常过时。每个电子邮件客户端都有不同的渲染错误和怪癖，找到它们的唯一方法就是在所有客户端中打开您的电子邮件。许多电子邮件客户端甚至不支持 CSS，而那些支持的也只支持很少的选择器和属性。为了弥补这一点，我们不得不使用 10 年前的网页开发方法，也就是使用带有内联样式的表进行设计。这是我们的`digest.html`：

```py
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html >
    <head>
        <meta http-equiv="Content-Type"
              content="text/html; charset=UTF-8" />
        <meta name="viewport"
              content="width=device-width, initial-scale=1.0"/>
        <title>Weekly Digest</title>
    </head>
    <body>
        <table align="center"
               border="0"
               cellpadding="0"
               cellspacing="0"
               width="500px">
            <tr>
                <td style="font-size: 32px;
                           font-family: Helvetica, sans-serif;
                           color: #444;
                           text-align: center;
                           line-height: 1.65">
                    Weekly Digest
                </td>
            </tr>
            {% for post in posts %}
                <tr>
                    <td style="font-size: 24px;
                               font-family: sans-serif;
                               color: #444;
                               text-align: center;
                               line-height: 1.65">
                        {{ post.title }}
                    </td>
                </tr>
                <tr>
                    <td style="font-size: 14px;
                               font-family: serif;
                               color: #444;
                               line-height:1.65">
                        {{ post.text | truncate(500) | safe }}
                    </td>
                </tr>
                <tr>
                    <td style="font-size: 12px;
                               font-family: serif;
                               color: blue;
                               margin-bottom: 20px">
                        <a href="{{ url_for('.post', post_id=post.id) }}">Read More</a>
                    </td>
                </tr>
            {% endfor %}
        </table>
    </body>
</html>
```

现在，每周末，我们的摘要任务将被调用，并且会向我们邮件列表中的所有用户发送一封电子邮件。

# 总结

Celery 是一个非常强大的任务队列，允许程序员将较慢的任务的处理推迟到另一个进程中。现在您了解了如何将复杂的任务移出 Flask 进程，我们将看一下一系列简化 Flask 应用程序中一些常见任务的 Flask 扩展。


# 第十章：有用的 Flask 扩展

正如我们在整本书中所看到的，Flask 的设计是尽可能小，同时又给您提供了创建 Web 应用程序所需的灵活性和工具。然而，许多 Web 应用程序都具有许多共同的特性，这意味着许多应用程序将需要编写执行相同任务的代码。为了解决这个问题，人们已经为 Flask 创建了扩展，以避免重复造轮子，我们已经在整本书中看到了许多 Flask 扩展。本章将重点介绍一些更有用的 Flask 扩展，这些扩展内容不足以单独成章，但可以节省大量时间和烦恼。

# Flask Script

在第一章中，*入门*，我们使用 Flask 扩展 Flask Script 创建了一个基本的管理脚本，以便轻松运行服务器并使用 shell 进行调试。在本章中，我们将介绍那些基本介绍中未涉及的功能。

在 Flask Script 中，您可以创建自定义命令以在应用程序上下文中运行。所需的只是创建一个命令，用 Flask Script 提供的装饰器函数装饰一个普通的 Python 函数。例如，如果我们想要一个任务，返回字符串"Hello, World!"，我们将把以下内容添加到`manage.py`中：

```py
@manager.command
def test():
    print "Hello, World!"
```

从命令行，现在可以使用以下命令运行`test`命令：

```py
$ python manage.py test
Hello, World!

```

删除测试命令，让我们创建一个简单的命令，以帮助为我们的应用程序设置新开发人员的 SQLite 数据库并填充测试数据。这个命令部分地来自第四章中创建的脚本，*创建蓝图控制器*：

```py
@manager.command
def setup_db():
    db.create_all()

    admin_role = Role()
    admin_role.name = "admin"
    admin_role.description = "admin"
    db.session.add(admin_role)

    default_role = Role()
    default_role.name = "default"
    default_role.description = "default"
    db.session.add(default_role)

    admin = User()
    admin.username = "admin"
    admin.set_password("password")
    admin.roles.append(admin_role)
    admin.roles.append(default_role)
    db.session.add(admin)

    tag_one = Tag('Python')
    tag_two = Tag('Flask')
    tag_three = Tag('SQLAlechemy')
    tag_four = Tag('Jinja')
    tag_list = [tag_one, tag_two, tag_three, tag_four]

    s = "Body text"

    for i in xrange(100):
        new_post = Post("Post {}".format(i))
        new_post.user = admin
        new_post.publish_date = datetime.datetime.now()
        new_post.text = s
        new_post.tags = random.sample(
            tag_list,
            random.randint(1, 3)
        )
        db.session.add(new_post)

    db.session.commit()
```

现在，如果有新的开发人员被分配到项目中，他们可以从我们的服务器下载`git repo`，安装`pip`库，运行`setup_db`命令，然后就可以运行项目了。

Flask Script 还提供了两个实用函数，可以轻松添加到我们的项目中。

```py
from flask.ext.script.commands import ShowUrls, Clean
…
manager = Manager(app)
manager.add_command("server", Server())
manager.add_command("show-urls", ShowUrls())
manager.add_command("clean", Clean())
```

`show-urls`命令列出了在`app`对象上注册的所有路由以及与该路由相关的 URL。这在调试 Flask 扩展时非常有用，因为可以轻松地查看其蓝图的注册是否有效。清理命令只是从工作目录中删除`.pyc`和`.pyo`编译的 Python 文件。

# Flask Debug Toolbar

Flask Debug Toolbar 是一个 Flask 扩展，通过将调试工具添加到应用程序的 Web 视图中，帮助开发。它会提供一些信息，比如视图渲染代码中的瓶颈，以及渲染视图所需的 SQLAlchemy 查询次数。

像往常一样，我们将使用`pip`来安装 Flask Debug Toolbar：

```py
$ pip install flask-debugtoolbar

```

接下来，我们需要将 Flask Debug Toolbar 添加到`extensions.py`文件中。由于在本章中我们将经常修改这个文件，所以以下是文件的开头以及初始化 Flask Debug Toolbar 的代码：

```py
from flask import flash, redirect, url_for, session
from flask.ext.bcrypt import Bcrypt
from flask.ext.openid import OpenID
from flask_oauth import OAuth
from flask.ext.login import LoginManager
from flask.ext.principal import Principal, Permission, RoleNeed
from flask.ext.restful import Api
from flask.ext.celery import Celery
from flask.ext.debugtoolbar import DebugToolbarExtension

bcrypt = Bcrypt()
oid = OpenID()
oauth = OAuth()
principals = Principal()
celery = Celery()
debug_toolbar = DebugToolbarExtension()
```

现在，需要在`__init__.py`中的`create_app`函数中调用初始化函数：

```py
from .extensions import (
    bcrypt,
    oid,
    login_manager,
    principals,
    rest_api,
    celery,
    debug_toolbar,
)

def create_app(object_name):

    debug_toolbar.init_app(app)
```

这就是让 Flask Debug Toolbar 运行起来所需的全部内容。如果应用程序的`config`中的`DEBUG`变量设置为*true*，则工具栏将显示出来。如果`DEBUG`没有设置为*true*，则工具栏将不会被注入到页面中。

![Flask Debug Toolbar](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_10_01.jpg)

在屏幕的右侧，您将看到工具栏。每个部分都是一个链接，点击它将在页面上显示一个值表。要获取呈现视图所调用的所有函数的列表，请点击**Profiler**旁边的复选标记以启用它，重新加载页面，然后点击**Profiler**。这个视图可以让您快速诊断应用程序中哪些部分最慢或被调用最多。

默认情况下，Flask Debug Toolbar 拦截`HTTP 302 重定向`请求。要禁用此功能，请将以下内容添加到您的配置中：

```py
class DevConfig(Config):
    DEBUG = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False
```

另外，如果您使用 Flask-MongoEngine，可以通过覆盖渲染的面板并添加 MongoEngine 的自定义面板来查看渲染页面时所做的所有查询。

```py
class DevConfig(Config):
    DEBUG = True
    DEBUG_TB_PANELS = [
        'flask_debugtoolbar.panels.versions.VersionDebugPanel',
        'flask_debugtoolbar.panels.timer.TimerDebugPanel',
        'flask_debugtoolbar.panels.headers.HeaderDebugPanel',
        'flask_debugtoolbar.panels.request_vars.RequestVarsDebugPanel',
        'flask_debugtoolbar.panels.config_vars.ConfigVarsDebugPanel ',
        'flask_debugtoolbar.panels.template.TemplateDebugPanel',
        'flask_debugtoolbar.panels.logger.LoggingPanel',
        'flask_debugtoolbar.panels.route_list.RouteListDebugPanel'
        'flask_debugtoolbar.panels.profiler.ProfilerDebugPanel',
        'flask.ext.mongoengine.panels.MongoDebugPanel'
    ]
    DEBUG_TB_INTERCEPT_REDIRECTS = False
```

这将在工具栏中添加一个与默认 SQLAlchemy 非常相似的面板。

# Flask Cache

在第七章中，*使用 Flask 进行 NoSQL*，我们了解到页面加载时间是确定您的 Web 应用程序成功的最重要因素之一。尽管我们的页面并不经常更改，而且由于新帖子不会经常发布，但我们仍然在用户浏览器每次请求页面时渲染模板并查询数据库。

Flask Cache 通过允许我们存储视图函数的结果并返回存储的结果而不是再次渲染模板来解决了这个问题。首先，我们需要从`pip`安装 Flask Cache：

```py
$ pip install Flask-Cache

```

接下来，在`extensions.py`中初始化它：

```py
from flask.ext.cache import Cache

cache = Cache()
```

然后，在`__init__.py`中的`create_app`函数中注册`Cache`对象：

```py
from .extensions import (
    bcrypt,
    oid,
    login_manager,
    principals,
    rest_api,
    celery,
    debug_toolbar,
    cache
)

def create_app(object_name):
    …
    cache.init_app(app)
```

在我们开始缓存视图之前，需要告诉 Flash Cache 我们希望如何存储新函数的结果。

```py
class DevConfig(Config):
    …
    CACHE_TYPE = 'simple'
```

`simple`选项告诉 Flask Cache 将结果存储在 Python 字典中的内存中，对于绝大多数 Flask 应用程序来说是足够的。我们将在本节后面介绍更多类型的缓存后端。

## 缓存视图和函数

为了缓存视图函数的结果，只需在任何函数上添加装饰器：

```py
@blog_blueprint.route('/')
@blog_blueprint.route('/<int:page>')
@cache.cached(timeout=60)
def home(page=1):
    posts = Post.query.order_by(
        Post.publish_date.desc()
    ).paginate(page, 10)
    recent, top_tags = sidebar_data()

    return render_template(
        'home.html',
        posts=posts,
        recent=recent,
        top_tags=top_tags
    )
```

`timeout`参数指定缓存结果在函数再次运行并再次存储之前应该持续多少秒。要确认视图实际上被缓存了，可以在调试工具栏上查看 SQLAlchemy 部分。此外，我们可以通过激活分析器并比较之前和之后的时间来看到缓存对页面加载时间的影响。在作者顶级的笔记本电脑上，主博客页面需要 34 毫秒来渲染，主要是因为对数据库进行了 8 次不同的查询。但在激活缓存后，这个时间减少到 0.08 毫秒。这是速度提高了 462.5%！

视图函数并不是唯一可以被缓存的东西。要缓存任何 Python 函数，只需在函数定义中添加类似的装饰器：

```py
@cache.cached(timeout=7200, key_prefix='sidebar_data')
def sidebar_data():
    recent = Post.query.order_by(
        Post.publish_date.desc()
    ).limit(5).all()

    top_tags = db.session.query(
        Tag, func.count(tags.c.post_id).label('total')
    ).join(
        tags
    ).group_by(
        Tag
    ).order_by('total DESC').limit(5).all()

    return recent, top_tags
```

关键字参数`key_prefix`对于非视图函数是必要的，以便 Flask Cache 正确地存储函数的结果。这需要对每个被缓存的函数都是唯一的，否则函数的结果将互相覆盖。另外，请注意，此函数的超时设置为 2 小时，而不是前面示例中的 60 秒。这是因为这个函数的结果不太可能改变，如果数据过时，这不是一个大问题。

## 带参数的函数缓存

然而，普通的缓存装饰器不考虑函数参数。如果我们使用普通的缓存装饰器缓存了带有参数的函数，它将对每个参数集返回相同的结果。为了解决这个问题，我们使用`memoize`函数：

```py
    class User(db.Model):
        …

        @staticmethod
        @cache.memoize(60)
        def verify_auth_token(token):
            s = Serializer(current_app.config['SECRET_KEY'])

            try:
                data = s.loads(token)
            except SignatureExpired:
                return None
            except BadSignature:
                return None

            user = User.query.get(data['id'])
            return user
```

`Memoize`存储传递给函数的参数以及结果。在前面的例子中，`memoize`被用来存储`verify_auth_token`方法的结果，该方法被多次调用并且每次都查询数据库。如果传递给它相同的令牌，这个方法可以安全地被记忆化，因为它每次都返回相同的结果。唯一的例外是如果用户对象在函数被存储的 60 秒内被删除，但这是非常不可能的。

小心不要对依赖于全局作用域变量或不断变化数据的函数进行`memoize`或缓存。这可能导致一些非常微妙的错误，甚至在最坏的情况下会导致数据竞争。最适合 memoization 的候选者是所谓的纯函数。纯函数是当传递相同的参数时将产生相同结果的函数。函数运行多少次都无所谓。纯函数也没有任何副作用，这意味着它们不会改变全局作用域变量。这也意味着纯函数不能执行任何 IO 操作。虽然`verify_auth_token`函数不是纯函数，因为它执行数据库 IO，但这没关系，因为正如之前所述，底层数据很少会改变。

在开发应用程序时，我们不希望缓存视图函数，因为结果会不断变化。为了解决这个问题，将`CACHE_TYPE`变量设置为 null，并在生产配置中将`CACHE_TYPE`变量设置为 simple，这样当应用程序部署时，一切都能按预期运行：

```py
class ProdConfig(Config):
    …
    CACHE_TYPE = 'simple'

class DevConfig(Config):
    …
    CACHE_TYPE = 'null'
```

## 使用查询字符串缓存路由

一些路由，比如我们的主页和`post`路由，通过 URL 传递参数并返回特定于这些参数的内容。如果缓存这样的路由，就会遇到问题，因为无论 URL 参数如何，路由的第一次渲染都将返回所有请求。解决方案相当简单。缓存方法中的`key_prefix`关键字参数可以是一个字符串或一个函数，该函数将被执行以动态生成一个键。这意味着可以创建一个函数来生成一个与 URL 参数相关联的键，因此只有在之前调用过具有特定参数组合的请求时，每个请求才会返回一个缓存的页面。在`blog.py`文件中，添加以下内容：

```py
def make_cache_key(*args, **kwargs):
    path = request.path
    args = str(hash(frozenset(request.args.items())))
    lang = get_locale()
    return (path + args + lang).encode('utf-8')

@blog_blueprint.route(
    '/post/<int:post_id>',
    methods=('GET', 'POST')
)
@cache.cached(timeout=600, key_prefix=make_cache_key)
def post(post_id):
    …
```

现在，每个单独的帖子页面将被缓存 10 分钟。

## 使用 Redis 作为缓存后端

如果视图函数的数量或传递给缓存函数的唯一参数的数量变得太大而超出内存限制，您可以使用不同的缓存后端。正如在第七章中提到的，*在 Flask 中使用 NoSQL*，Redis 可以用作缓存的后端。要实现该功能，只需将以下配置变量添加到`ProdConfig`类中，如下所示：

```py
class ProdConfig(Config):
    …
    CACHE_TYPE = 'redis'
    CACHE_REDIS_HOST = 'localhost'
    CACHE_REDIS_PORT = '6379'
    CACHE_REDIS_PASSWORD = 'password'
    CACHE_REDIS_DB = '0'
```

如果用自己的数据替换变量的值，Flask Cache 将自动创建到您的`redis`数据库的连接，并使用它来存储函数的结果。所需的只是安装 Python `redis`库：

```py
$ pip install redis

```

## 使用 memcached 作为缓存后端

与`redis`后端一样，`memcached`后端提供了一种替代的存储结果的方式，如果内存选项太过限制。与`redis`相比，`memcached`旨在缓存对象以供以后使用，并减少对数据库的负载。`redis`和`memcached`都可以达到相同的目的，选择其中一个取决于个人偏好。要使用`memcached`，我们需要安装其 Python 库：

```py
$ pip install memcache

```

连接到您的`memcached`服务器在配置对象中处理，就像`redis`设置一样：

```py
class ProdConfig(Config):
    …
    CACHE_TYPE = 'memcached'
    CACHE_KEY_PREFIX = 'flask_cache'
    CACHE_MEMCACHED_SERVERS = ['localhost:11211']
```

# Flask Assets

Web 应用程序中的另一个瓶颈是下载页面的 CSS 和 JavaScript 库所需的 HTTP 请求数量。只有在加载和解析页面的 HTML 之后才能下载额外的文件。为了解决这个问题，许多现代浏览器会同时下载许多这些库，但是浏览器发出的同时请求数量是有限制的。

服务器上可以做一些事情来减少下载这些文件所花费的时间。开发人员使用的主要技术是将所有 JavaScript 库连接成一个文件，将所有 CSS 库连接成另一个文件，同时从结果文件中删除所有空格和换行符。这样可以减少多个 HTTP 请求的开销，删除不必要的空格和换行符可以将文件大小减少多达 30％。另一种技术是告诉浏览器使用专门的 HTTP 头在本地缓存文件，因此文件只有在更改后才会再次加载。这些手动操作可能很繁琐，因为它们需要在每次部署到服务器后进行。

幸运的是，Flask Assets 实现了上述所有技术。Flask Assets 通过给它一个文件列表和一种连接它们的方法来工作，然后在模板中添加一个特殊的控制块，代替正常的链接和脚本标签。然后，Flask Assets 将添加一个链接或脚本标签，链接到新生成的文件。要开始使用 Flask Assets，需要安装它。我们还需要安装`cssmin`和`jsmin`，这是处理文件修改的 Python 库：

```py
$ pip install Flask-Assets cssmin jsmin

```

现在，需要创建要连接的文件集合，即命名捆绑包。在`extensions.py`中，添加以下内容：

```py
from flask_assets import Environment, Bundle

assets_env = Environment()

main_css = Bundle(
    'css/bootstrap.css',
    filters='cssmin',
    output='css/common.css'
)

main_js = Bundle(
    'js/jquery.js',
    'js/bootstrap.js',
    filters='jsmin',
    output='js/common.js'
)
```

每个`Bundle`对象都需要无限数量的文件作为位置参数来定义要捆绑的文件，一个关键字参数`filters`来定义要通过的过滤器，以及一个`output`来定义`static`文件夹中要保存结果的文件名。

### 注意

`filters`关键字可以是单个值或列表。要获取可用过滤器的完整列表，包括自动 Less 和 CSS 编译器，请参阅[`webassets.readthedocs.org/en/latest/`](http://webassets.readthedocs.org/en/latest/)上的文档。

虽然我们的网站样式较轻，CSS 捆绑包中只有一个文件。但是将文件放入捆绑包仍然是一个好主意，原因有两个。

在开发过程中，我们可以使用未压缩版本的库，这样调试更容易。当应用程序部署到生产环境时，库会自动进行压缩。

这些库将被发送到浏览器，并带有缓存头，通常在 HTML 中链接它们不会。

在测试 Flask Assets 之前，需要进行三项更改。首先，在`__init__.py`格式中，需要注册扩展和捆绑包：

```py
from .extensions import (
    bcrypt,
    oid,
    login_manager,
    principals,
    rest_api,
    celery,
    debug_toolbar,
    cache,
    assets_env,
    main_js,
    main_css
)

def create_app(object_name):
    …
    assets_env.init_app(app)

    assets_env.register("main_js", main_js)
    assets_env.register("main_css", main_css)
```

接下来，`DevConfig`类需要一个额外的变量，告诉 Flask Assets 在开发过程中不要编译库：

```py
class DevConfig(Config):
    DEBUG = True
    DEBUG_TB_INTERCEPT_REDIRECTS = False

    ASSETS_DEBUG = True
```

最后，`base.html`文件中的链接和脚本标签都需要用 Flask Assets 的控制块替换。我们有以下内容：

```py
<link rel="stylesheet" href=https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css>
```

用以下内容替换：

```py
{% assets "main_css" %}
<link rel="stylesheet" type="text/css" href="{{ ASSET_URL }}" />
{% endassets %}
```

我们还有以下内容：

```py
<script src="img/jquery.min.js"></script>
<script src="img/bootstrap.min.js"></script>
```

用以下内容替换：

```py
{% assets "main_js" %}
<script src="img/{{ ASSET_URL }}"></script>
{% endassets %}
```

现在，如果重新加载页面，所有的 CSS 和 JavaScript 现在都将由 Flask Assets 处理。

# Flask Admin

在第六章中，*保护您的应用程序*，我们创建了一个界面，允许用户创建和编辑博客文章，而无需使用命令行。这足以演示本章介绍的安全措施，但仍然没有办法使用界面删除帖子或为其分配标签。我们也没有办法删除或编辑我们不希望普通用户看到的评论。我们的应用程序需要的是一个功能齐全的管理员界面，与 WordPress 界面相同。这对于应用程序来说是一个常见的需求，因此创建了一个名为 Flask Admin 的 Flask 扩展，以便轻松创建管理员界面。要开始使用 Flask Admin，请使用`pip`安装 Flask Admin：

```py
$ pip install Flask-Admin

```

像往常一样，在`extensions.py`中需要创建`extension`对象：

```py
from flask.ext.admin import Admin

admin = Admin()
```

然后，需要在`__init__.py`中的`app`对象上注册该对象：

```py
from .extensions import (
    bcrypt,
    oid,
    login_manager,
    principals,
    rest_api,
    celery,
    debug_toolbar,
    cache,
    assets_env,
    main_js,
    main_css,
    admin
)

def create_app(object_name):
    …
    admin.init_app(app)
```

如果您导航到`localhost:5000/admin`，您现在应该看到空的 Flask Admin 界面：

![Flask Admin](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_10_02.jpg)

Flask Admin 通过在定义一个或多个路由的`admin`对象上注册视图类来工作。Flask Admin 有三种主要类型的视图：`ModelView`、`FileAdmin`和`BaseView`视图。

## 创建基本管理页面

`BaseView`类允许将普通的 Flask 页面添加到您的`admin`界面中。这通常是 Flask Admin 设置中最少使用的视图类型，但如果您希望包括类似使用 JavaScript 图表库的自定义报告，您可以使用基本视图。在名为`admin.py`的控制器文件夹中添加以下内容：

```py
from flask.ext.admin import BaseView, expose

class CustomView(BaseView):
    @expose('/')
    def index(self):
        return self.render('admin/custom.html')

    @expose('/second_page')
    def second_page(self):
        return self.render('admin/second_page.html')
```

在`BaseView`的子类中，如果它们一起定义，可以一次注册多个视图。但是请记住，`BaseView`的每个子类都需要至少一个在路径`/`上公开的方法。此外，除了路径`/`中的方法之外，管理员界面的导航中将不会有其他方法，并且必须将它们链接到类中的其他页面。`expose`和`self.render`函数的工作方式与普通 Flask API 中的对应函数完全相同。

要使您的模板继承 Flask Admin 的默认样式，请在模板目录中创建一个名为`admin`的新文件夹，其中包含一个名为`custom.html`的文件，并添加以下 Jinja 代码：

```py
{% extends 'admin/master.html' %}
{% block body %}
    This is the custom view!
    <a href="{{ url_for('.second_page') }}">Link</a>
{% endblock %}
```

要查看此模板，需要在`admin`对象上注册`CustomView`的实例。这将在`create_app`函数中完成，而不是在`extensions.py`文件中，因为我们的一些管理页面将需要数据库对象，如果注册在`extensions.py`中会导致循环导入。在`__init__.py`中，添加以下代码来注册该类：

```py
from webapp.controllers.admin import CustomView
…
def create_app(object_name):
    …
    admin.add_view(CustomView(name='Custom'))
```

`name`关键字参数指定`admin`界面顶部导航栏上使用的标签应该读取`Custom`。在将`CustomView`注册到`admin`对象之后，您的`admin`界面现在应该有第二个链接在导航栏中，如下所示。

![Creating basic admin pages](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_10_03.jpg)

## 创建数据库管理页面

Flask Admin 的主要功能来自于您可以通过将您的 SQLAlchemy 或 MongoEngine 模型提供给 Flask Admin 来自动创建数据的管理员页面。创建这些页面非常容易；在`admin.py`中，只需添加以下代码：

```py
from flask.ext.admin.contrib.sqla import ModelView
# or, if you use MongoEngine
from flask.ext.admin.contrib.mongoengine import ModelView

class CustomModelView(ModelView):
    pass
```

然后，在`__init__.py`中，按照以下方式注册要使用的模型和数据库`session`对象的类：

```py
from controllers.admin import CustomView, CustomModelView
from .models import db, Reminder, User, Role, Post, Comment, Tag

def create_app(object_name):

    admin.add_view(CustomView(name='Custom'))
    models = [User, Role, Post, Comment, Tag, Reminder]

    for model in models:
       admin.add_view(
           CustomModelView(model, db.session, category='models')
       )
```

`category`关键字告诉 Flask Admin 将具有相同类别值的所有视图放入导航栏上的同一个下拉菜单中。

如果您现在转到浏览器，您将看到一个名为**Models**的新下拉菜单，其中包含指向数据库中所有表的管理页面的链接，如下所示：

![Creating database admin pages](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_10_04.jpg)

每个模型的生成界面提供了许多功能。可以创建新的帖子，并可以批量删除现有的帖子。可以从这个界面设置所有字段，包括关系字段，这些字段实现为可搜索的下拉菜单。`date`和`datetime`字段甚至具有带有日历下拉菜单的自定义 JavaScript 输入。总的来说，这是对第六章中手动创建的界面的巨大改进，*保护您的应用程序*。

## 增强文章管理

虽然这个界面在质量上有了很大的提升，但还是有一些功能缺失。我们不再拥有原始界面中可用的所见即所得编辑器，这个页面可以通过启用一些更强大的 Flask Admin 功能来改进。

要将所见即所得编辑器添加回`post`创建页面，我们需要一个新的`WTForms`字段，因为 Flask Admin 使用 Flask WTF 构建其表单。我们还需要用这种新的字段类型覆盖`post`编辑和创建页面中的`textarea`字段。需要做的第一件事是在`forms.py`中使用`textarea`字段作为基础创建新的字段类型：

```py
from wtforms import (
    widgets,
    StringField,
    TextAreaField,
    PasswordField,
    BooleanField
)

class CKTextAreaWidget(widgets.TextArea):
    def __call__(self, field, **kwargs):
        kwargs.setdefault('class_', 'ckeditor')
        return super(CKTextAreaWidget, self).__call__(field, **kwargs)

class CKTextAreaField(TextAreaField):
    widget = CKTextAreaWidget()
```

在这段代码中，我们创建了一个新的字段类型`CKTextAreaField`，它为`textarea`添加了一个小部件，而小部件所做的就是向 HTML 标签添加一个类。现在，要将此字段添加到`Post`管理员页面，`Post`将需要自己的`ModelView`：

```py
from webapp.forms import CKTextAreaField

class PostView(CustomModelView):
    form_overrides = dict(text=CKTextAreaField)
    column_searchable_list = ('text', 'title')
    column_filters = ('publish_date',)

    create_template = 'admin/post_edit.html'
    edit_template = 'admin/post_edit.html'
```

在这段代码中有几个新的东西。首先，`form_overrides`类变量告诉 Flask Admin 用这种新的字段类型覆盖名称文本的字段类型。`column_searchable_list`函数定义了哪些列可以通过文本进行搜索。添加这个将允许 Flask Admin 在概述页面上包括一个搜索字段，用于搜索已定义字段的值。接下来，`column_filters`类变量告诉 Flask Admin 在此模型的概述页面上创建一个`filters`界面。`filters`界面允许非文本列通过向显示的行添加条件进行过滤。使用上述代码的示例是创建一个过滤器，显示所有`publish_date`值大于 2015 年 1 月 1 日的行。最后，`create_template`和`edit_template`类变量允许您定义 Flask Admin 要使用的自定义模板。对于我们将要使用的自定义模板，我们需要在 admin 文件夹中创建一个新文件`post_edit.html`。在这个模板中，我们将包含与第六章中使用的相同的 JavaScript 库，*保护您的应用*：

```py
{% extends 'admin/model/edit.html' %}
{% block tail %}
    {{ super() }}
    <script
        src="img/ckeditor.js">
    </script>
{% endblock %}
```

继承模板的尾部块位于文件末尾。创建模板后，您的`post`编辑和创建页面应如下所示：

![增强帖子的管理](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_10_05.jpg)

## 创建文件系统管理员页面

大多数`admin`界面涵盖的另一个常见功能是能够从 Web 访问服务器的文件系统。幸运的是，Flask Admin 通过`FileAdmin`类包含了这个功能

```py
class CustomFileAdmin(FileAdmin):
    pass
Now, just import the new class into your __init__.py file and pass in the path that you wish to be accessible from the web:
import os
from controllers.admin import (
    CustomView,
    CustomModelView,
    PostView,
    CustomFileAdmin
)

def create_app(object_name):

    admin.add_view(
        CustomFileAdmin(
            os.path.join(os.path.dirname(__file__), 'static'),
            '/static/',
            name='Static Files'
        )
    )
```

## 保护 Flask Admin

目前，整个`admin`界面对世界都是可访问的；让我们来修复一下。`CustomView`中的路由可以像任何其他路由一样进行保护：

```py
class CustomView(BaseView):
    @expose('/')
    @login_required
    @admin_permission.require(http_exception=403)
    def index(self):
        return self.render('admin/custom.html')

    @expose('/second_page')
    @login_required
    @admin_permission.require(http_exception=403)
    def second_page(self):
        return self.render('admin/second_page.html')
```

要保护`ModeView`和`FileAdmin`子类，它们需要定义一个名为`is_accessible`的方法，该方法返回*true*或*false*。

```py
class CustomModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated() and\
               admin_permission.can()

class CustomFileAdmin(FileAdmin):
    def is_accessible(self):
        return current_user.is_authenticated() and\
               admin_permission.can()
```

因为我们在第六章中正确设置了我们的身份验证，所以这个任务很简单。

# Flask Mail

本章将介绍的最终 Flask 扩展是 Flask Mail，它允许您从 Flask 的配置中连接和配置您的 SMTP 客户端。Flask Mail 还将帮助简化第十二章中的应用测试，*测试 Flask 应用*。第一步是使用`pip`安装 Flask Mail：

```py
$ pip install Flask-Mail

```

接下来，在`extentions.py`文件中需要初始化`Mail`对象：

```py
from flask_mail import Mail

mail = Mail()
```

`flask_mail`将通过读取`app`对象中的配置变量连接到我们选择的 SMTP 服务器，因此我们需要将这些值添加到我们的`config`对象中：

```py
class DevConfig(Config):

    MAIL_SERVER = 'localhost'
    MAIL_PORT = 25
    MAIL_USERNAME = 'username'
    MAIL_PASSWORD = 'password'
```

最后，在`__init__.py`中的`app`对象上初始化`mail`对象：

```py
from .extensions import (
    bcrypt,
    oid,
    login_manager,
    principals,
    rest_api,
    celery,
    debug_toolbar,
    cache,
    assets_env,
    main_js,
    main_css,
    admin,
    mail
)

def create_app(object_name):

    mail.init_app(app)
```

要了解 Flask Mail 如何简化我们的邮件代码，这是在第九章中创建的提醒任务，*使用 Celery 创建异步任务*，但使用 Flask Mail 而不是标准库 SMTP 模块：

```py
from flask_mail import Message
from webapp.extensions import celery, mail

@celery.task(
    bind=True,
    ignore_result=True,
    default_retry_delay=300,
    max_retries=5
)
def remind(self, pk):
    reminder = Reminder.query.get(pk)
    msg = MIMEText(reminder.text)
    msg = Message("Your reminder",
                  sender="from@example.com",
                  recipients=[reminder.email])

    msg.body = reminder.text
    mail.send(msg)
```

# 摘要

本章大大增加了我们应用的功能。我们现在拥有一个功能齐全的管理员界面，在浏览器中有一个有用的调试工具，两个大大加快页面加载速度的工具，以及一个使发送电子邮件变得不那么头疼的实用程序。

正如本章开头所述，Flask 是一个基本的框架，允许您挑选并选择您想要的功能。因此，重要的是要记住，在您的应用程序中并不需要包含所有这些扩展。如果您是应用程序的唯一内容创建者，也许命令行界面就是您所需要的，因为添加这些功能需要开发时间和维护时间，当它们不可避免地出现故障时。本章末尾提出了这个警告，因为许多 Flask 应用程序变得难以管理的主要原因之一是它们包含了太多的扩展，测试和维护所有这些扩展变成了一项非常庞大的任务。

在下一章中，您将学习扩展的内部工作原理以及如何创建自己的扩展。
