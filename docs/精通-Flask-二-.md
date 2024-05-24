# 精通 Flask（二）

> 原文：[`zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530`](https://zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用蓝图创建控制器

**模型视图控制器**（**MVC**）方程的最后一部分是控制器。我们已经在`main.py`文件中看到了视图函数的基本用法。现在，我们将介绍更复杂和强大的版本，并将我们零散的视图函数转化为统一的整体。我们还将讨论 Flask 如何处理 HTTP 请求的生命周期以及定义 Flask 视图的高级方法。

# 请求设置、拆卸和应用全局

在某些情况下，需要跨所有视图函数访问特定于请求的变量，并且还需要从模板中访问。为了实现这一点，我们可以使用 Flask 的装饰器函数`@app.before_request`和对象`g`。函数`@app.before_request`在每次发出新请求之前执行。Flask 对象`g`是每个特定请求需要保留的任何数据的线程安全存储。在请求结束时，对象被销毁，并在新请求开始时生成一个新对象。例如，以下代码检查 Flask `session`变量是否包含已登录用户的条目；如果存在，它将`User`对象添加到`g`中：

```py
from flask import g, session, abort, render_template

@app.before_request
def before_request():
    if ‘user_id’ in session:
        g.user = User.query.get(session[‘user_id’])

@app.route(‘/restricted’)
def admin():
    if g.user is None:
        abort(403)
    return render_template(‘admin.html’)
```

多个函数可以使用`@app.before_request`进行装饰，并且它们都将在请求的视图函数执行之前执行。还存在一个名为`@app.teardown_request`的装饰器，它在每个请求结束后调用。请记住，这种处理用户登录的方法只是一个示例，不安全。推荐的方法在第六章 *保护您的应用*中有介绍。

# 错误页面

向最终用户显示浏览器的默认错误页面会让用户失去应用的所有上下文，他们必须点击*返回*按钮才能返回到您的站点。要在使用 Flask 的`abort()`函数返回错误时显示自己的模板，可以使用`errorhandler`装饰器函数：

```py
@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404
```

`errorhandler`还可用于将内部服务器错误和 HTTP 500 代码转换为用户友好的错误页面。`app.errorhandler()`函数可以接受一个或多个 HTTP 状态码，以定义它将处理哪个代码。返回元组而不仅仅是 HTML 字符串允许您定义`Response`对象的 HTTP 状态代码。默认情况下，这被设置为`200`。

# 基于类的视图

在大多数 Flask 应用中，视图由函数处理。但是，当许多视图共享公共功能或有代码片段可以拆分为单独的函数时，将视图实现为类以利用继承将非常有用。

例如，如果我们有渲染模板的视图，我们可以创建一个通用的视图类，以保持我们的代码*DRY*：

```py
from flask.views import View

class GenericView(View):
    def __init__(self, template):
        self.template = template
        super(GenericView, self).__init__()

    def dispatch_request(self):
        return render_template(self.template)

app.add_url_rule(
    '/', view_func=GenericView.as_view(
        'home', template='home.html'
    )
)
```

关于此代码的第一件事是我们视图类中的`dispatch_request()`函数。这是我们视图中充当普通视图函数并返回 HTML 字符串的函数。`app.add_url_rule()`函数模仿`app.route()`函数，因为它将路由与函数调用绑定在一起。第一个参数定义了函数的路由，`view_func`参数定义了处理路由的函数。`View.as_view()`方法传递给`view_func`参数，因为它将`View`类转换为视图函数。第一个参数定义了视图函数的名称，因此诸如`url_for()`之类的函数可以路由到它。其余参数传递给`View`类的`__init__`函数。

与普通的视图函数一样，除了`GET`之外的 HTTP 方法必须明确允许`View`类。要允许其他方法，必须添加一个包含命名方法列表的类变量：

```py
class GenericView(View):
    methods = ['GET', 'POST']
    …
    def dispatch_request(self):
        if request.method == ‘GET’:
            return render_template(self.template)
        elif request.method == ‘POST’:
            …
```

## 方法类视图

通常，当函数处理多个 HTTP 方法时，由于大量代码嵌套在`if`语句中，代码可能变得难以阅读：

```py
@app.route('/user', methods=['GET', 'POST', 'PUT', 'DELETE'])
def users():
    if request.method == 'GET':
        …
    elif request.method == 'POST':
        …
    elif request.method == 'PUT':
        …
    elif request.method == 'DELETE':
        …
```

这可以通过`MethodView`类来解决。`MethodView`允许每个方法由不同的类方法处理以分离关注点：

```py
from flask.views import MethodView

class UserView(MethodView):
    def get(self):
        …
    def post(self):
        …
    def put(self):
        …
    def delete(self):
        …

app.add_url_rule(
    '/user',
    view_func=UserView.as_view('user')
)
```

# 蓝图

在 Flask 中，**蓝图**是扩展现有 Flask 应用程序的一种方法。蓝图提供了一种将具有共同功能的视图组合在一起的方式，并允许开发人员将其应用程序分解为不同的组件。在我们的架构中，蓝图将充当我们的*控制器*。

视图被注册到蓝图中；可以为其定义一个单独的模板和静态文件夹，并且当它具有所有所需的内容时，可以在主 Flask 应用程序上注册蓝图内容。蓝图的行为很像 Flask 应用程序对象，但实际上并不是一个独立的应用程序。这就是 Flask 扩展提供视图函数的方式。为了了解蓝图是什么，这里有一个非常简单的例子：

```py
from flask import Blueprint
example = Blueprint(
    'example',
    __name__,
    template_folder='templates/example',
    static_folder='static/example',
    url_prefix="/example"
)

@example.route('/')
def home():
    return render_template('home.html')
```

蓝图需要两个必需参数——蓝图的名称和包的名称——这些参数在 Flask 内部使用；将`__name__`传递给它就足够了。

其他参数是可选的，并定义蓝图将在哪里查找文件。因为指定了`templates_folder`，蓝图将不会在默认模板文件夹中查找，并且路由将呈现`templates/example/home.html`而不是`templates/home.html`。`url_prefix`选项会自动将提供的 URI 添加到蓝图中的每个路由的开头。因此，主页视图的 URL 实际上是`/example/`。

`url_for()`函数现在必须告知所请求的路由位于哪个蓝图中：

```py
{{ url_for('example.home') }}
```

此外，`url_for()`函数现在必须告知视图是否在同一个蓝图中呈现：

```py
{{ url_for('.home') }}
```

`url_for()`函数还将在指定的静态文件夹中查找静态文件。

要将蓝图添加到我们的应用程序中：

```py
app.register_blueprint(example)
```

让我们将我们当前的应用程序转换为使用蓝图的应用程序。我们首先需要在所有路由之前定义我们的蓝图：

```py
blog_blueprint = Blueprint(
    'blog',
    __name__,
    template_folder='templates/blog',
    url_prefix="/blog"
)
```

现在，因为模板文件夹已经定义，我们需要将所有模板移到模板文件夹的子文件夹中，命名为 blog。接下来，我们所有的路由需要将`@app.route`改为`@blog_blueprint.route`，并且任何类视图分配现在需要注册到`blog_blueprint`。记住，模板中的`url_for()`函数调用也需要更改为在路由前加上一个句点以指示该路由在同一个蓝图中。

在文件末尾，在`if __name__ == '__main__':`语句之前，添加以下内容：

```py
app.register_blueprint(blog_blueprint)
```

现在我们所有的内容都回到了应用程序中，该应用程序在蓝图下注册。因为我们的基本应用程序不再具有任何视图，让我们在基本 URL 上添加一个重定向：

```py
@app.route('/')
def index():
    return redirect(url_for('blog.home'))
```

为什么是 blog 而不是`blog_blueprint`？因为 blog 是蓝图的名称，而名称是 Flask 在内部用于路由的。`blog_blueprint`是 Python 文件中的变量名称。

# 总结

我们现在的应用程序在一个蓝图中运行，但这给了我们什么？假设我们想要在我们的网站上添加一个照片分享功能；我们可以将所有视图函数分组到一个蓝图中，该蓝图具有自己的模板、静态文件夹和 URL 前缀，而不会担心破坏网站其余部分的功能。在下一章中，通过升级我们的文件和代码结构，蓝图将变得更加强大，通过将它们分离成不同的文件。


# 第五章：高级应用程序结构

我们的应用程序已经从一个非常简单的例子发展成一个可扩展的基础，可以很容易地构建强大的功能。然而，将整个应用程序代码都放在一个文件中会不必要地使我们的代码混乱。为了使应用程序代码更清晰、更易理解，我们将把整个代码转换为一个 Python 模块，并将代码分割成多个文件。

# 项目作为一个模块

目前，你的文件夹结构应该是这样的：

```py
webapp/
  config.py
  database.db
  main.py
  manage.py
  env/
  migrations/
    versions/
  static/
    css/
    js/
  templates/
    blog/
```

为了将我们的代码转换为一个模块，我们的文件将被转换为这个文件夹结构：

```py
webapp/
  manage.py
  database.db
  webapp/
    __init__.py
    config.py
    forms.py
    models.py
    controllers/
      __init__.py
      blog.py
    static/
      css/
      js/
    templates/
      blog/
  migrations/
    versions/
```

我们将逐步创建这个文件夹结构。要做的第一个改变是在你的应用程序中创建一个包含模块的文件夹。在这个例子中，它将被称为`webapp`，但可以被称为除了博客以外的任何东西，因为控制器被称为博客。如果有两个要从中导入的博客对象，Python 将无法正确地从父目录中导入`blog.py`文件中的对象。

接下来，将`main.py`和`config.py`——静态和模板文件夹，分别移动到你的项目文件夹中，并创建一个控制器文件夹。我们还需要在`project`文件夹中创建`forms.py`和`models.py`文件，以及在控制器文件夹中创建一个`blog.py`文件。此外，`main.py`文件需要重命名为`__init__.py`。

文件名`__init__.py`看起来很奇怪，但它有一个特定的功能。在 Python 中，通过在文件夹中放置一个名为`__init__.py`的文件，可以将文件夹标记为模块。这允许程序从文件夹中的 Python 文件中导入对象和变量。

### 注意

要了解更多关于在模块中组织 Python 代码的信息，请参考官方文档[`docs.python.org/2/tutorial/modules.html#packages`](https://docs.python.org/2/tutorial/modules.html#packages)。

## 重构代码

让我们开始将我们的 SQLAlchemy 代码移动到`models.py`文件中。从`__init__.py`中剪切所有模型声明、标签表和数据库对象，并将它们与 SQLAlchemy 导入一起复制到`models.py`文件中。此外，我们的`db`对象将不再使用`app`对象作为参数进行初始化，因为`models.py`文件中没有`app`对象，导入它将导致循环导入。相反，我们将在初始化模型后将 app 对象添加到`db`对象中。这将在我们的`__init__.py`文件中实现。

你的`models.py`文件现在应该是这样的：

```py
from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()

tags = db.Table(
    'post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'))
)

class User(db.Model):
    …

class Post(db.Model):
    …

class Comment(db.Model):
    …

class Tag(db.Model):
    …
```

接下来，`CommentForm`对象以及所有 WTForms 导入都应该移动到`forms.py`文件中。`forms.py`文件将保存所有 WTForms 对象在它们自己的文件中。

`forms.py`文件应该是这样的：

```py
from flask_wtf import Form
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Length

class CommentForm(Form):
    …
```

`blog_blueprint`数据函数、它的所有路由以及`sidebar_data`数据函数需要移动到控制器文件夹中的`blog.py`文件中。

`blog.py`文件现在应该是这样的：

```py
import datetime
from os import path
from sqlalchemy import func
from flask import render_template, Blueprint

from webapp.models import db, Post, Tag, Comment, User, tags
from webapp.forms import CommentForm

blog_blueprint = Blueprint(
    'blog',
    __name__,
    template_folder=path.join(path.pardir, 'templates', 'blog')
    url_prefix="/blog"
)

def sidebar_data():
    …
```

现在，每当创建一个新的蓝图时，可以在控制器文件夹中为其创建一个新的文件，将应用程序代码分解为逻辑组。此外，我们需要在控制器文件夹中创建一个空的`__init__.py`文件，以便将其标记为模块。

最后，我们专注于我们的`__init__.py`文件。`__init__.py`文件中应该保留的内容只有`app`对象的创建、`index`路由和`blog_blueprint`在`app`对象上的注册。然而，还有一件事要添加——数据库初始化。通过`db.init_app()`函数，我们将在导入`app`对象后将`app`对象添加到`db`对象中：

```py
from flask import Flask, redirect, url_for
from config import DevConfig

from models import db
from controllers.blog import blog_blueprint

app = Flask(__name__)
app.config.from_object(DevConfig)

db.init_app(app)

@app.route('/')
def index():
    return redirect(url_for('blog.home'))

app.register_blueprint(blog_blueprint)

if __name__ == '__main__':
    app.run()
```

在我们的新结构生效之前，有两件最后需要修复的事情，如果你使用的是 SQLite——`config.py`中的 SQLAlchemy 数据库 URL 需要更新，以及`manage.py`中的导入需要更新。因为 SQLite 数据库的 SQLAlchemy URL 是一个相对文件路径，所以它必须更改为：

```py
from os import path

class DevConfig(object):
    SQLALCHEMY_DATABASE_URI = 'sqlite://' + path.join(
        path.pardir,
        'database.db'
    )
```

要修复`manage.py`的导入，用以下内容替换`main.py`中的导入：

```py
from webapp import app
from webapp.models import db, User, Post, Tag, Comment
```

现在，如果你运行`manage.py`文件，你的应用将以新的结构运行。

# 应用工厂

现在我们以模块化的方式使用蓝图，然而，我们可以对我们的抽象进行另一个改进，即为我们的应用创建一个**工厂**。工厂的概念来自**面向对象编程**（**OOP**）世界，它简单地意味着一个函数或对象创建另一个对象。我们的应用工厂将接受我们在书的开头创建的`config`对象之一，并返回一个 Flask 应用对象。

### 注意

对象工厂设计是由现在著名的《设计模式：可复用面向对象软件的元素》一书所推广的。要了解更多关于这些设计模式以及它们如何帮助简化项目代码的信息，请查看[`en.wikipedia.org/wiki/Structural_pattern`](https://en.wikipedia.org/wiki/Structural_pattern)。

为我们的应用对象创建一个工厂函数有几个好处。首先，它允许环境的上下文改变应用的配置。当服务器创建应用对象进行服务时，它可以考虑服务器中任何必要的更改，并相应地改变提供给应用的配置对象。其次，它使测试变得更加容易，因为它允许快速测试不同配置的应用。第三，可以非常容易地创建使用相同配置的同一应用的多个实例。这对于需要在多个不同的服务器之间平衡网站流量的情况非常有用。

现在应用工厂的好处已经清楚，让我们修改我们的`__init__.py`文件来实现它：

```py
from flask import Flask, redirect, url_for
from models import db
from controllers.blog import blog_blueprint

def create_app(object_name):
    app = Flask(__name__)
    app.config.from_object(object_name)

    db.init_app(app)

    @app.route('/')
    def index():
        return redirect(url_for('blog.home'))

    app.register_blueprint(blog_blueprint)

    return app
```

对文件的更改非常简单；我们将代码包含在一个函数中，该函数接受一个`config`对象并返回一个应用对象。我们需要修改我们的`manage.py`文件，以便与`create_app`函数一起工作，如下所示：

```py
import os
from flask.ext.script import Manager, Server
from flask.ext.migrate import Migrate, MigrateCommand
from webapp import create_app
from webapp.models import db, User, Post, Tag, Comment

# default to dev config
env = os.environ.get('WEBAPP_ENV', 'dev')
app = create_app('webapp.config.%sConfig' % env.capitalize())
…
manager = Manager(app)
manager.add_command("server", Server())
```

当我们创建配置对象时，提到了应用运行的环境可能会改变应用的配置。这段代码有一个非常简单的例子，展示了环境变量的功能，其中加载了一个环境变量，并确定要给`create_app`函数的`config`对象。环境变量是 Bash 中的**全局变量**，可以被许多不同的程序访问。它们可以用以下语法在 Bash 中设置：

```py
$ export WEBAPP_ENV="dev"

```

读取变量时：

```py
$ echo $WEBAPP_ENV
dev

```

您也可以按以下方式轻松删除变量：

```py
$ unset $WEBAPP_ENV
$ echo $WEBAPP_ENV

```

在生产服务器上，您将把`WEBAPP_ENV`设置为`prod`。一旦在第十三章 *部署 Flask 应用*中部署到生产环境，并且当我们到达第十二章 *测试 Flask 应用*时，即可清楚地看到这种设置的真正威力，该章节涵盖了对项目进行测试。

# 总结

我们已经将我们的应用转变为一个更加可管理和可扩展的结构，这将在我们继续阅读本书并添加更多高级功能时为我们节省许多麻烦。在下一章中，我们将为我们的应用添加登录和注册系统，以及其他功能，使我们的网站更加安全。


# 第六章：保护您的应用程序

我们有一个大部分功能正常的博客应用，但缺少一些关键功能，比如用户登录、注册以及从浏览器添加和编辑帖子。用户登录功能可以通过许多不同的方式创建，因此每个部分演示了创建登录的互斥方法。第一种方法是直接使用浏览器的 cookies，第二种方法是使用名为**Flask Login**的 Flask 扩展。

# 设置

在我们立即开始创建用户认证系统之前，需要进行大量的设置代码。为了运行任何类型的认证，我们的应用程序将需要以下所有常见的元素：

+   首先，用户模型将需要适当的密码哈希

+   其次，需要登录表单和注册表单来验证用户输入

+   其次，需要登录视图和注册视图以及每个视图的模板

+   其次，需要设置各种社交登录，以便在实施登录系统时将它们与登录系统绑定

## 更新模型

直到现在，我们的用户的密码以明文形式存储在数据库中。这是一个重大的安全漏洞。如果任何恶意用户能够访问数据库中的数据，他们可以登录到任何账户。这样的违规行为的后果将比我们的网站更大。互联网上有很多人在许多网站上使用相同的密码。

如果攻击者能够获得电子邮件和密码的组合，很可能可以使用这些信息登录到 Facebook 账户甚至银行账户。

为了保护我们用户的密码，它们将使用一种名为**哈希算法**的单向加密方法进行加密。单向加密意味着在信息加密后，无法从结果中恢复原始信息。然而，对于相同的数据，哈希算法将始终产生相同的结果。提供给哈希算法的数据可以是从文本文件到电影文件的任何内容。在这种情况下，数据只是一串字符。有了这个功能，我们的密码可以被存储为**哈希值**（已经被哈希过的数据）。然后，当用户在登录或注册页面输入他们的密码时，输入的文本密码将通过相同的哈希算法发送，然后验证存储的哈希和输入的哈希是否匹配。

有许多哈希算法，其中大多数都不安全，因为它们很容易被**暴力破解**。黑客不断尝试将数据通过哈希算法，直到有匹配的数据。为了最好地保护用户密码，bcrypt 将是我们选择的哈希算法。**Bcrypt**被特意设计成对计算机来说是低效和慢的（毫秒级对比微秒级），从而使其更难以被暴力破解。要将 bcrypt 添加到我们的项目中，需要安装**Flask Bcrypt**包，方法如下：

```py
$ pip install Flask-Bcrypt

```

这是第二个将在`app`对象上初始化的 Flask 扩展，另一个是 SQLAlchemy 对象。`db`对象存储在`models.py`文件中，但没有明显的地方来初始化 Flask Bcrypt。为了保存所有未来的扩展，需要在与`__init__.py`文件相同的目录中添加名为`extensions.py`的文件。在其中，需要初始化 Flask Bcrypt：

```py
from flask.ext.bcrypt import Bcrypt
bcrypt = Bcrypt()
```

然后将其添加到`app`对象中：

```py
from webapp.extensions import bcrypt

def create_app(object_name):
    app = Flask(__name__)
    app.config.from_object(object_name)

    db.init_app(app)
    bcrypt.init_app(app)
```

Bcrypt 现在已经准备好使用。为了让我们的`User`对象使用 bcrypt，我们将添加两个方法来设置密码并检查字符串是否与存储的哈希匹配：

```py
from webapp.extensions import bcrypt

class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))
    posts = db.relationship(
        'Post',
        backref='user',
        lazy='dynamic'
    )

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
```

现在，我们的`User`模型可以安全地存储密码。接下来，我们的登录过程需要使用这些方法来创建新用户和检查密码。

## 创建表单

需要三种表单：登录表单、注册表单和**发布创建**页面的表单。登录表单将包含用户名和密码字段：

```py
from wtforms import (
    StringField,
    TextAreaField,
    PasswordField,
    BooleanField
)
from wtforms.validators import DataRequired, Length, EqualTo, URL

class LoginForm(Form):
    username = StringField('Username', [
        DataRequired(), Length(max=255)
    ])
    password = PasswordField('Password', [DataRequired()])

   def validate(self):
        check_validate = super(LoginForm, self).validate()

        # if our validators do not pass
        if not check_validate:
            return False

        # Does our the exist
        user = User.query.filter_by(
           username=self.username.data
        ).first()
        if not user:
            self.username.errors.append(
                'Invalid username or password'
            )
            return False

        # Do the passwords match
        if not self.user.check_password(self.password.data):
            self.username.errors.append(
                'Invalid username or password'
            )
            return False

        return True
```

除了正常的验证外，我们的`LoginForm`方法还将检查传递的用户名是否存在，并使用`check_password()`方法来检查哈希值。

### 使用 reCAPTCHA 保护您的表单免受垃圾邮件攻击

注册表单将包含用户名字段、带有确认字段的密码字段和名为 reCAPTCHA 字段的特殊字段。CAPTCHA 是 Web 表单上的一个特殊字段，用于检查输入表单数据的人是否真的是一个人，还是一个正在向您的站点发送垃圾邮件的自动化程序。reCAPTCHA 只是 CAPTCHA 的一种实现。reCAPTCHA 已经集成到 WTForms 中，因为它是 Web 上最流行的实现。

要使用 reCAPTCHA，您需要从[`www.google.com/recaptcha/intro/index.html`](https://www.google.com/recaptcha/intro/index.html)获取 reCAPTCHA 登录。由于 reCAPTCHA 是 Google 产品，您可以使用 Google 账户登录。

登录后，它将要求您添加一个站点。在这种情况下，任何名称都可以，但域字段必须包含`localhost`。一旦部署您的站点，您的域也必须添加到此列表中。

现在您已经添加了一个站点，下拉菜单中将显示有关服务器和客户端集成的说明。当我们创建登录和注册视图时，给定的`script`标签将需要添加到我们的模板中。WTForms 需要从此页面获取的是如下截图中显示的密钥：

![使用 reCAPTCHA 保护您的表单免受垃圾邮件攻击](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_06_01.jpg)

记住永远不要向公众展示这些密钥。由于这些密钥仅注册给`localhost`，因此可以在此处显示而不会受到影响。

将这些密钥添加到`config.py`文件中的`config`对象中，以便 WTForms 可以访问它们，如下所示：

```py
class Config(object):
    SECRET_KEY = 'Key Here'
    RECAPTCHA_PUBLIC_KEY = 
"6LdKkQQTAAAAAEH0GFj7NLg5tGicaoOus7G9Q5Uw"
    RECAPTCHA_PRIVATE_KEY =
'6LdKkQQTAAAAAMYroksPTJ7pWhobYb88fTAcxcYn'
```

以下是我们的注册表单：

```py
class RegisterForm(Form):
    username = StringField('Username', [
        DataRequired(),
        Length(max=255)
    ])
    password = PasswordField('Password', [
        DataRequired(),
        Length(min=8)
    ])
    confirm = PasswordField('Confirm Password', [
        DataRequired(),
        EqualTo('password')
    ])
    recaptcha = RecaptchaField()

    def validate(self):
        check_validate = super(RegisterForm, self).validate()

        # if our validators do not pass
        if not check_validate:
            return False

        user = User.query.filter_by(
            username=self.username.data
        ).first()

        # Is the username already being used
        if user:
            self.username.errors.append(
                "User with that name already exists"
            )
            return False

        return True
```

帖子创建表单将只包含标题的文本输入和帖子内容的文本区域输入：

```py
class PostForm(Form):
    title = StringField('Title', [
        DataRequired(), 
        Length(max=255)
    ])
    text = TextAreaField('Content', [DataRequired()])
```

## 创建视图

在上一章中，包含重定向到博客主页的索引视图存储在`create_app`函数中。这对于一个视图来说是可以的。现在，本节将在站点的基本 URL 上添加许多视图。因此，我们需要在`controllers/main.py`中添加一个新的控制器：

```py
main_blueprint = Blueprint(
    'main',
    __name__,
    template_folder='../templates/main'
)

@main_blueprint.route('/')
def index():
    return redirect(url_for('blog.home'))
```

登录和注册视图将创建我们的表单对象并将它们传递给模板。目前，如果传递的数据验证通过，登录表单将不执行任何操作。实际的登录功能将在下一节中添加。但是，如果数据通过验证，注册视图将创建一个新用户。除了登录和注册视图之外，还需要一个注销视图，目前也不会执行任何操作。

在`main.py`控制器中，添加以下内容：

```py
from webapp.forms import LoginForm, RegisterForm

@main_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        flash("You have been logged in.", category="success") 
        return redirect(url_for('blog.home'))

    return render_template('login.html', form=form)

@main_blueprint.route('/logout', methods=['GET', 'POST'])
def logout():
    flash("You have been logged out.", category="success")
    return redirect(url_for('.home'))

@main_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        new_user = User()
        new_user.username = form.username.data
        new_user.set_password(form.username.data)

        db.session.add(new_user)
        db.session.commit()

        flash(
            "Your user has been created, please login.", 
            category="success"
        )

           return redirect(url_for('.login'))

    return render_template('register.html', form=form)
```

在前面的代码中使用的`login.html`和`register.html`模板（放置在`templates/main`文件夹中）可以使用第三章中创建的`form`宏来创建，但是 reCAPTCHA 的`script`标签尚不能添加到`register.html`中。

首先，我们的子模板需要一种方法来向`base.html`模板添加新的 JavaScript 文件。还需要一种方法让我们的视图使用 Flask 的`flash`函数向用户闪现消息。在`base.html`文件中还需要添加一个新的内容块以及对消息的循环：

```py
<body>
  <div class="container">
    <div class="jumbotron">
      <h1><a href="{{ url_for('blog.home') }}">My Blog</a></h1>
      <p>Welcome to the blog!</p>
    </div>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
           <div class="alert alert-{{ category }} alert-dismissible" 
             role="alert">
           <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>

           {{ message }}
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% block body %}
    {% endblock %}
  </div>
  <script 
    src="img/jquery.min.js"> 
    </script>
  <script 
    src="img/bootstrap.min.js"> 
    </script>
  {% block js %}
  {% endblock %}
</body>
```

您的登录页面现在应该类似于以下内容：

![创建视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_06_02.jpg)

您的注册页面应该如下所示：

![创建视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_06_03.jpg)

现在我们需要创建帖子创建和编辑页面，以便可以进行安全保护。这两个页面将需要将文本区域字段转换为**所见即所得**（**WYSIWYG**）编辑器，以处理将帖子文本包装在 HTML 中。在`blog.py`控制器中，添加以下视图：

```py
from webapp.forms import CommentForm, PostForm

@blog_blueprint.route('/new', methods=['GET', 'POST'])
def new_post():
    form = PostForm()

    if form.validate_on_submit():
        new_post = Post(form.title.data)
        new_post.text = form.text.data
        new_post.publish_date = datetime.datetime.now() 

        db.session.add(new_post)
        db.session.commit()

    return render_template('new.html', form=form)

@blog_blueprint.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_post(id):

    post = Post.query.get_or_404(id)
    form = PostForm()

    if form.validate_on_submit():
        post.title = form.title.data
        post.text = form.text.data
        post.publish_date = datetime.datetime.now()

        db.session.add(post)
        db.session.commit()

        return redirect(url_for('.post', post_id=post.id))

    form.text.data = post.text

    return render_template('edit.html', form=form, post=post)
```

这个功能与用于添加新评论的代码非常相似。文本字段的数据在视图中设置，因为没有简单的方法在模板中设置`TextAreaField`的内容。

`new.html` 模板将需要一个用于所见即所得编辑器的 JavaScript 文件。**CKEditor** 安装和使用非常简单。现在，我们的 `new.html` 文件可以按以下方式创建：

```py
{% extends "base.html" %}
{% block title %}Post Creation{% endblock %}
{% block body %}
<div class="row">
  <h1 class="text-center">Create A New Post</h1>
  <form method="POST" action="{{ url_for('.new_post') }}">
    {{ form.hidden_tag() }}
    <div class="form-group">
      {{ form.title.label }}
      {% if form.title.errors %}
        {% for e in form.title.errors %}
          <p class="help-block">{{ e }}</p>
        {% endfor %}
      {% endif %}
      {{ form.title(class_='form-control') }}
    </div>
    <div class="form-group">
      {{ form.text.label }}
      {% if form.text.errors %}
        {% for e in form.text.errors %}
          <p class="help-block">{{ e }}</p>
        {% endfor %}
      {% endif %}
      {{ form.text(id="editor", class_='form-control') }}
    </div>
    <input class="btn btn-primary" type="submit" value="Submit">
  </form>
</div>
{% endblock %}

{% block js %}
<script src="img/ckeditor.js"></script>
<script>
    CKEDITOR.replace('editor');
</script>
{% endblock %}
```

这就是将用户输入存储为 HTML 在数据库中所需的全部内容。因为我们在帖子模板中传递了安全过滤器，所以 HTML 代码在我们的帖子页面上显示正确。`edit.html` 模板类似于 `new.html` 模板。唯一的区别是 `form` 开放标签和创建 `title` 字段：

```py
<form method="POST" action="{{ url_for('.edit_post', id=post.id) }}">
…
{{ form.title(class_='form-control', value=post.title) }}
…
</form>
```

`post.html` 模板将需要一个按钮，以将作者链接到编辑页面：

```py
<div class="row">
  <div class="col-lg-6">
    <p>Written By <a href="{{ url_for('.user', username=post.user.username) 
      }}">{{ post.user.username }}</a> on {{ post.publish_date }}</p>
  </div>
  …
  <div class="row">
    <div class="col-lg-2">
    <a href="{{ url_for('.edit_post', id=post.id) }}" class="btn btn- 
      primary">Edit</a>
  </div>
</div>
```

当我们能够检测到当前用户时，编辑按钮将只显示给创建帖子的用户。

## 社交登录

随着时间的推移，将替代登录和注册选项集成到您的网站变得越来越重要。每个月都会有另一个公告称密码已从热门网站中被盗。实现以下登录选项意味着我们网站的数据库永远不会为该用户存储密码。

验证由一个大型品牌公司处理，用户已经对其信任。通过使用社交登录，用户对其所使用的网站的信任程度要低得多。您的登录流程也变得更短，降低了用户使用您的应用的门槛。

社交认证用户表现为普通用户，与基于密码的登录方法不同，它们可以同时使用。

### OpenID

**OpenID** 是一种开放协议，允许在一个站点上的用户由实现该协议的任何第三方站点进行身份验证，这些站点被称为 **Relaying Parties** (**RPs**)。OpenID 登录表示为来自其中一个 RP 的 URL，通常是网站的个人资料页面。

### 注意

要了解使用 OpenID 的所有网站列表以及如何使用每个网站，转到 [`openid.net/get-an-openid/`](http://openid.net/get-an-openid/)。

要将 OpenID 添加到 Flask，需要一个名为 **Flask-OpenID** 的 Flask 扩展：

```py
$ pip install Flask-OpenID

```

我们的应用程序将需要一些东西来实现 OpenID：

+   一个新的表单对象

+   登录和注册页面的表单验证

+   表单提交后的回调以登录用户或创建新用户

在 `extensions.py` 文件中，可以按以下方式初始化 OpenID 对象：

```py
from flask.ext.bcrypt import Bcrypt
from flask.ext.openid import OpenID
bcrypt = Bcrypt()
oid = OpenID()
```

在 `__init__.py` 文件中，将 `oid` 对象注册到 `app` 对象：

```py
from .models import db

def create_app(object_name):
    app = Flask(__name__)
    app.config.from_object(object_name)

    db.init_app(app)
    bcrypt.init_app(app)
    oid.init_app(app)
```

新的 `form` 对象只需要 RP 的 URL：

```py
from wtforms.validators import DataRequired, Length, EqualTo, URL

class OpenIDForm(Form):
    openid = StringField('OpenID URL', [DataRequired(), URL()])
```

在登录和注册视图上，将初始化 `OpenIDForm()`，如果数据有效，将发送登录请求：

```py
from webapp.extensions import oid
…

@main_blueprint.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    form = LoginForm()
    openid_form = OpenIDForm()

    if openid_form.validate_on_submit():
        return oid.try_login(
            openid_form.openid.data,
            ask_for=['nickname', 'email'],
            ask_for_optional=['fullname']
        )

    if form.validate_on_submit():
        flash("You have been logged in.", category="success")
        return redirect(url_for('blog.home'))

    openid_errors = oid.fetch_error()
    if openid_errors:
        flash(openid_errors, category="danger")

    return render_template(
       'login.html',
       form=form,
       openid_form=openid_form
    )

@main_blueprint.route('/register', methods=['GET', 'POST'])
@oid.loginhandler
def register():
    form = RegisterForm()
    openid_form = OpenIDForm()

    if openid_form.validate_on_submit():
        return oid.try_login(
            openid_form.openid.data,
            ask_for=['nickname', 'email'],
            ask_for_optional=['fullname']
        )

    if form.validate_on_submit():
        new_user = User(form.username.data)
        new_user.set_password(form.password.data)

        db.session.add(new_user)
        db.session.commit()

        flash(
            "Your user has been created, please login.", 
            category="success"
        )

        return redirect(url_for('.login'))

    openid_errors = oid.fetch_error()
    if openid_errors:
        flash(openid_errors, category="danger")

    return render_template(
        'register.html',
        form=form,
        openid_form=openid_form
    )
```

两个视图都有新的装饰器 `@oid.loginhandler`，告诉 Flask-OpenID 监听来自 RP 的身份验证信息。使用 OpenID，登录和注册是相同的。可以从登录表单创建用户，也可以从注册表单登录。两个页面上都出现相同的字段，以避免用户混淆。

要处理用户创建和登录，需要在 `extensions.py` 文件中创建一个新函数：

```py
@oid.after_login
def create_or_login(resp):
    from models import db, User
    username = resp.fullname or resp.nickname or resp.email
    if not username:
        flash('Invalid login. Please try again.', 'danger')
        return redirect(url_for('main.login'))

    user = User.query.filter_by(username=username).first()
    if user is None:
        user = User(username)
        db.session.add(user)
        db.session.commit()

    # Log the user in here
    return redirect(url_for('blog.home'))
```

每次从 RP 收到成功响应后都会调用此函数。如果登录成功并且不存在与该身份对应的用户对象，则此函数将创建一个新的 `User` 对象。如果已经存在，则即将到来的身份验证方法将登录用户。OpenID 不需要返回所有可能的信息，因此可能只会返回电子邮件而不是全名。这就是为什么用户名可以是昵称、全名或电子邮件的原因。在函数内导入 `db` 和 `User` 对象，以避免从导入 `bcrypt` 对象的 `models.py` 文件中导入循环导入。

### Facebook

要使用 Facebook 登录，以及后来的 Twitter，使用名为 **OAuth** 的协议。我们的应用程序不会直接使用 OAuth，而是将使用另一个名为 **Flask OAuth** 的 Flask 扩展：

```py
$ pip install Flask-OAuth

```

使用 Facebook 登录，我们的应用程序需要使用我们应用程序的密钥定义一个 Facebook OAuth 对象。定义一个视图，将用户重定向到 Facebook 服务器上的登录授权过程，并在 Facebook 方法上定义一个函数，从登录过程中加载`auth`令牌。

首先，需要在[`developers.facebook.com`](http://developers.facebook.com)创建一个 Facebook 应用。创建新应用后，查找列出应用程序 ID 和密钥的面板。

![Facebook](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_06_04.jpg)

在`extensions.py`中添加以下代码时使用这些值：

```py
from flask_oauth import OAuth

bcrypt = Bcrypt()
oid = OpenID()
oauth = OAuth()

…

facebook = oauth.remote_app(
    'facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=' FACEBOOK_APP_ID',
    consumer_secret=' FACEBOOK_APP_SECRET',
    request_token_params={'scope': 'email'}
)
@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('facebook_oauth_token')
```

在 Facebook 开发者界面中，请确保添加新的授权网站为`http://localhost:5000/`，否则登录将无法工作。在`main.py`控制器中，添加以下代码：

```py
from webapp.extensions import oid, facebook
…

@main_blueprint.route('/facebook')
def facebook_login():
    return facebook.authorize(
        callback=url_for(
            '.facebook_authorized',
            next=request.referrer or None,
            _external=True
        )
    )

@main_blueprint.route('/facebook/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )

    session['facebook_oauth_token'] = (resp['access_token'], '')

    me = facebook.get('/me')
    user = User.query.filter_by(
        username=me.data['first_name'] + " " + me.data['last_name']
    ).first()

    if not user:
        user = User(me.data['first_name'] + " " + me.data['last_name'])
        db.session.add(user)
        db.session.commit()

    # Login User here
    flash("You have been logged in.", category="success")

    return redirect(
        request.args.get('next') or url_for('blog.home')
    )
```

第一个路由`facebook_login`只是重定向到 Facebook 网站上的登录过程。`facebook_authorized`视图接收来自 Facebook 服务器的响应，并且与 OpenID 过程一样，要么创建一个新用户，要么登录用户。现在，要开始这个过程，向注册和登录模板添加以下链接：

```py
<h2 class="text-center">Register With Facebook</h2>
<a href="{{ url_for('.facebook_login') }}">Login via Facebook</a>
```

### Twitter

Twitter 登录过程非常相似。要创建 Twitter 应用并获取您的密钥，请转到[`apps.twitter.com/`](https://apps.twitter.com)。在`extensions.py`中：

```py
twitter = oauth.remote_app(
    'twitter',
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    consumer_key='',
    consumer_secret=''
)

@twitter.tokengetter
def get_twitter_oauth_token():
    return session.get('twitter_oauth_token')
```

在`main.py`控制器中，添加以下视图：

```py
@main_blueprint.route('/twitter-login')
def twitter_login():
    return twitter.authorize(
        callback=url_for(
            '.twitter_authorized',
            next=request.referrer or None,
            _external=True
        )
    )

@main_blueprint.route('/twitter-login/authorized')
@twitter.authorized_handler
def twitter_authorized(resp):
    if resp is None:
        return 'Access denied: reason: {} error: {}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['twitter_oauth_token'] = resp['oauth_token'] + \
        resp['oauth_token_secret']

    user = User.query.filter_by(
        username=resp['screen_name']
    ).first()

    if not user:
        user = User(resp['screen_name'], '')
        db.session.add(user)
        db.session.commit()

    # Login User here
    flash("You have been logged in.", category="success")

    return redirect(
        request.args.get('next') or url_for('blog.home')
    )
```

这些视图执行与它们的 Facebook 对应项相同的功能。最后，在注册和登录模板中，添加以下链接以开始登录过程：

```py
<h2 class="text-center">Register With Twitter</h2>
<a href="{{ url_for('.twitter_login') }}">Login</a>
```

# 使用会话

在 Flask 中创建身份验证的一种方法是使用`session`对象。`session`对象是 Flask 中的一个对象，它为服务器提供了一种使用 cookie 在用户浏览器中存储信息的简单方式。存储的数据使用应用程序的密钥进行加密签名。如果用户尝试修改 cookie，则签名将不再有效，cookie 将无法读取。

会话对象具有与`dict`对象相同的 API。要向其中添加数据，只需使用此代码：

```py
session['key'] = data
```

要检索数据，请使用此代码：

```py
session['key']
```

要登录用户，将用户名键添加到会话中，并设置为当前用户的用户名。

```py
@main_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Add the user's name to the cookie
        session['username'] = form.username.data

    return render_template('login.html', form=form)
```

要注销用户，可以从会话中弹出密钥：

```py
@main_blueprint.route('/logout', methods=['GET', 'POST'])
def logout():
    # Remove the username from the cookie
    session.pop('username', None)
    return redirect(url_for('.login'))
```

要检查用户当前是否已登录，视图可以测试会话中是否存在用户名键。考虑以下新帖子视图：

```py
@blog_blueprint.route('/new', methods=['GET', 'POST'])
def new_post ():
    if 'username' not in session:
        return redirect(url_for('main.login'))
    …
```

我们的一些模板将需要访问当前用户对象。在每个请求开始时，我们的`blog`蓝图可以检查会话中是否存在用户名。如果是，则将`User`对象添加到`g`对象中，通过模板可以访问。

```py
@blog_blueprint.before_request
def check_user():
    if 'username' in session:
        g.current_user = User.query.filter_by(
            username=session['username']
        ).one()
    else:
        g.current_user = None
```

我们的登录检查可以更改为：

```py
@blog_blueprint.route('/new', methods=['GET', 'POST'])
def new_post():
    if not g.current_user:
        return redirect(url_for('main.login'))
    …
```

此外，帖子页面上的编辑按钮只有在当前用户是作者时才会出现：

```py
{% if g.current_user == post.user %}
<div class="row">
  <div class="col-lg-2">
    <a href="{{ url_for('.edit_post', id=post.id) }}" class="btn btn- 
      primary">Edit</a>
  </div>
</div>
{% endif %}
```

编辑页面本身还应执行以下检查：

```py
@blog_blueprint.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit_post(id):
    if not g.current_user:
        return redirect(url_for('main.login'))

    post = Post.query.get_or_404(id)

    if g.current_user != post.user:
        abort(403)
    …
```

现在，我们的应用程序具有一个功能齐全的登录系统，具有传统的用户名和密码组合以及许多社交登录。但是，此系统中还有一些功能未涵盖。例如，如果我们希望一些用户只能评论而给其他人创建帖子的权限呢？此外，我们的登录系统没有实现`记住我`功能。为了覆盖这些功能，我们将重构我们的应用程序，使用名为**Flask 登录**的 Flask 扩展，而不是直接使用会话。

# Flask 登录

要开始使用 Flask 登录，首先需要下载它：

```py
$ pip install flask-login

```

主要的 Flask 登录对象是`LoginManager`对象。像其他 Flask 扩展一样，在`extensions.py`中初始化`LoginManager`对象：

```py
from flask.ext.login import LoginManager
…
login_manager = LoginManager()
```

有一些需要在对象上更改的配置选项：

```py
login_manager.login_view = "main.login"
login_manager.session_protection = "strong"
login_manager.login_message = "Please login to access this page"
login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(userid):
    from models import User
    return User.query.get(userid)
```

上述配置值定义了哪个视图应该被视为登录页面，以及用户在登录时应该看到什么样的消息。将选项`session_protection`设置为`strong`可以更好地防止恶意用户篡改他们的 cookie。当检测到篡改的 cookie 时，该用户的会话对象将被删除，并强制用户重新登录。`load_user`函数接受一个 id 并返回`User`对象。这是为了让 Flask Login 检查 id 是否标识了正确的用户对象。

`User`模型需要更新，包括一些用于 Flask Login 的方法。首先是`is_authenticated`，用于检查`User`对象是否已登录。接下来是`is_active`，用于检查用户是否已经通过某种激活过程，比如电子邮件确认。否则，它允许网站管理员封禁用户而不删除他们的数据。然后，`is_anonymous`用于检查这个用户是否是匿名用户且未登录。最后，`get_id`函数返回该`User`对象的唯一`unicode`标识符。

这个应用程序将使用一个简单的实现方式：

```py
from flask.ext.login import AnonymousUserMixin
…

class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))
    posts = db.relationship(
        'Post',
        backref='user',
        lazy='dynamic'
    )

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

    def is_authenticated(self):
        if isinstance(self, AnonymousUserMixin):
            return False
        else:
            return True

    def is_active(self):
        return True

    def is_anonymous(self):
        if isinstance(self, AnonymousUserMixin):
            return True
        else:
            return False

    def get_id(self):
        return unicode(self.id)
```

在 Flask Login 中，站点上的每个用户都继承自某个用户对象。默认情况下，它们继承自`AnonymousUserMixin`对象。如果您的站点需要一些匿名用户的功能，可以创建一个从`AnonymousUserMixin`继承的类，并将其设置为默认用户类，如下所示：

```py
login_manager.anonymous_user = CustomAnonymousUser
```

### 注意

要更好地理解**混入**的概念，请访问[`en.wikipedia.org/wiki/Mixin`](https://en.wikipedia.org/wiki/Mixin)。

要使用 Flask Login 登录用户，使用：

```py
from flask.ext.login import login_user
login_user(user_object)
```

Flask Login 会处理所有的会话处理。要让用户被记住，添加`remember=True`到`login_user`调用中。可以在登录表单中添加复选框，让用户选择：

```py
from wtforms import (
    StringField,
    TextAreaField,
    PasswordField,
    BooleanField
)

class LoginForm(Form):
    username = StringField('Username', [
        DataRequired(),
        Length(max=255)
    ])
    password = PasswordField('Password', [DataRequired()])
    remember = BooleanField("Remember Me")
    …
```

在登录视图中，添加这个：

```py
if form.validate_on_submit():
    user = User.query.filter_by(
        username=form.username.data
    ).one()
    login_user(user, remember=form.remember.data)
```

要注销当前用户，使用以下命令：

```py
from flask.ext.login import login_user, logout_user
logout_user()
```

要保护视图不被未经授权的用户访问并将他们发送到登录页面，需要添加`login_required`装饰器如下：

```py
from flask.ext.login import login_required

@blog_blueprint.route('/new', methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    …
```

Flask Login 还提供了一个代理，用于表示已登录用户的`current_user`。这个代理在视图和模板中都可用。因此，在我们的博客控制器中，可以删除自定义的`before_request`处理程序，并且我们对`g.current_user`的调用应该替换为`current_user`。

现在，使用 Flask Login，我们应用程序的登录系统更加符合 Python 的风格和安全。还有一个最后的功能要实现：用户角色和权限。

## 用户角色

要向我们的应用程序添加用户权限，我们的`User`模型将需要与`Role`对象的多对多关系，并且还需要另一个名为**Flask Principal**的 Flask 扩展。

使用我们从第二章中的代码，*使用 SQLAlchemy 创建模型*，向`User`对象添加一个多对多的关系很容易：

```py
roles = db.Table(
    'role_users',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

class User(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    posts = db.relationship(
        'Post',
        backref='user',
        lazy='dynamic'
    )
    roles = db.relationship(
        'Role',
        secondary=roles,
        backref=db.backref('users', lazy='dynamic')
    )

    def __init__(self, username):
        self.username = username

        default = Role.query.filter_by(name="default").one()
        self.roles.append(default)
    …

class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Role {}>'.format(self.name)
```

从命令行中，使用以下命令填充角色表格，包括三个角色：admin，poster 和 default。这些将作为 Flask Principal 的主要权限。

Flask Principal 围绕着身份的概念展开。应用程序中的某个东西，在我们的例子中是一个`User`对象，与之关联了一个身份。身份提供`Need`对象，它们本质上只是命名元组。`Needs`定义了身份可以做什么。权限是用`Need`初始化的，并且它们定义了资源需要访问的`Need`对象。

Flask Principal 提供了两个方便的`Need`对象：`UserNeed`和`RoleNeed`，这正是我们应用程序所需要的。在`extensions.py`中，Flask Principal 将被初始化，并且我们的`RoleNeed`对象将被创建：

```py
from flask.ext.principal import Principal, Permission, RoleNeed
principals = Principal()
admin_permission = Permission(RoleNeed('admin'))
poster_permission = Permission(RoleNeed('poster'))
default_permission = Permission(RoleNeed('default'))
```

Flask Principal 需要一个函数，在身份发生变化后向其中添加`Need`对象。因为这个函数需要访问`app`对象，所以这个函数将驻留在`__init__.py`文件中：

```py
from flask.ext.principal import identity_loaded, UserNeed, RoleNeed
from extensions import bcrypt, oid, login_manager, principals
def create_app(object_name):
    app = Flask(__name__)
    app.config.from_object(object_name)

    db.init_app(app)
    bcrypt.init_app(app)
    oid.init_app(app)
    login_manager.init_app(app)
    principals.init_app(app)

    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        # Set the identity user object
        identity.user = current_user

        # Add the UserNeed to the identity
        if hasattr(current_user, 'id'):
            identity.provides.add(UserNeed(current_user.id))

        # Add each role to the identity
        if hasattr(current_user, 'roles'):
            for role in current_user.roles:
                identity.provides.add(RoleNeed(role.name))
     …
```

现在，当身份发生变化时，它将添加一个`UserNeed`和所有的`RoleNeed`对象。当用户登录或注销时，身份发生变化：

```py
from flask.ext.principal import (
    Identity,
    AnonymousIdentity,
    identity_changed
)    
@main_blueprint.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    …

    if form.validate_on_submit():
        user = User.query.filter_by(
            username=form.username.data
        ).one()
        login_user(user, remember=form.remember.data)

        identity_changed.send(
            current_app._get_current_object(),
            identity=Identity(user.id)
        )

        flash("You have been logged in.", category="success")
        return redirect(url_for('blog.home'))
@main_blueprint.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()

    identity_changed.send(
        current_app._get_current_object(),
        identity=AnonymousIdentity()
    )

    flash("You have been logged out.", category="success")
    return redirect(url_for('.login'))
```

当用户登录时，他们的身份将触发`on_identity_loaded`方法，并设置他们的`Need`对象。现在，如果我们有一个页面，我们只想让发布者访问：

```py
from webapp.extensions import poster_permission
@blog_blueprint.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@poster_permission.require(http_exception=403)
def edit_post(id):
    …
```

我们还可以在同一个视图中用`UserNeed`检查替换我们的用户检查，如下所示：

```py
from webapp.extensions import poster_permission, admin_permission

@blog_blueprint.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@poster_permission.require(http_exception=403)
def edit_post(id):
    post = Post.query.get_or_404(id)
    permission = Permission(UserNeed(post.user.id))

    # We want admins to be able to edit any post
    if permission.can() or admin_permission.can():
        form = PostForm()

        if form.validate_on_submit():
            post.title = form.title.data
            post.text = form.text.data
            post.publish_date = datetime.datetime.now()

            db.session.add(post)
            db.session.commit()

            return redirect(url_for('.post', post_id=post.id))

        form.text.data = post.text
        return render_template('edit.html', form=form, post=post)

    abort(403)
```

### 注意

访问[`pythonhosted.org/Flask-Principal/`](https://pythonhosted.org/Flask-Principal/)上的 Flask Principal 文档，了解如何创建更复杂的`Need`对象。

# 摘要

我们的用户现在拥有安全登录、多重登录和注册选项，以及明确的访问权限。我们的应用程序具备成为一个完整的博客应用程序所需的一切。在下一章中，本书将停止跟随这个示例应用程序，以介绍一种名为**NoSQL**的技术。


# 第七章：使用 Flask 与 NoSQL

**NoSQL**（缩写为**Not Only SQL**）数据库是任何非关系型数据存储。它通常侧重于速度和可伸缩性。在过去的 7 年里，NoSQL 一直在网页开发领域掀起了风暴。像 Netflix 和 Google 这样的大公司宣布他们正在将许多服务迁移到 NoSQL 数据库，许多较小的公司也跟随着这样做。

这一章将偏离本书的其余部分，其中 Flask 不会是主要焦点。在一本关于 Flask 的书中，专注于数据库设计可能看起来有些奇怪，但选择正确的数据库对于设计技术栈来说可能是最重要的决定。在绝大多数网络应用中，数据库是瓶颈，因此你选择的数据库将决定应用的整体速度。亚马逊进行的一项研究表明，即使 100 毫秒的延迟也会导致 1%的销售额减少，因此速度应该始终是网络开发人员的主要关注点之一。此外，程序员社区中有大量关于选择流行的 NoSQL 数据库然后并不真正了解数据库在管理方面需要什么的恐怖故事。这导致大量数据丢失和崩溃，进而意味着失去客户。总的来说，毫不夸张地说，你选择应用的数据库可能是应用成功与否的关键。

为了说明 NoSQL 数据库的优势和劣势，将对每种 NoSQL 数据库进行检查，并阐明 NoSQL 与传统数据库之间的区别。

# NoSQL 数据库的类型

NoSQL 是一个用来描述数据库中非传统数据存储方法的总称。更让人困惑的是，NoSQL 也可能指的是关系型但没有使用 SQL 作为查询语言的数据库，例如**RethinkDB**。绝大多数 NoSQL 数据库不是关系型的，不像 RDBMS，这意味着它们无法执行诸如`JOIN`之类的操作。缺少`JOIN`操作是一种权衡，因为它允许更快的读取和更容易的去中心化，通过将数据分布在多个服务器甚至是不同的数据中心。

现代 NoSQL 数据库包括键值存储、文档存储、列族存储和图数据库。

## 键值存储

**键值** NoSQL 数据库的工作方式类似于 Python 中的字典。一个键关联一个值，并通过该键访问。此外，就像 Python 字典一样，大多数键值数据库的读取速度不受条目数量的影响。高级程序员会知道这是**O(1)读取**。在一些键值存储中，一次只能检索一个键，而不是传统 SQL 数据库中的多行。在大多数键值存储中，值的内容是不可*查询*的，但键是可以的。值只是二进制块；它们可以是从字符串到电影文件的任何东西。然而，一些键值存储提供默认类型，如字符串、列表、集合和字典，同时还提供添加二进制数据的选项。

由于其简单性，键值存储通常非常快。但是，它们的简单性使它们不适合大多数应用程序的主数据库。因此，大多数键值存储用例是存储需要在一定时间后过期的简单对象。这种模式的两个常见示例是存储用户会话数据和购物车数据。此外，键值存储通常用作应用程序或其他数据库的缓存。例如，经常运行或 CPU 密集型查询或函数的结果与查询或函数名称一起存储为键。应用程序在运行数据库上的查询之前将检查键值存储中的缓存，从而减少页面加载时间和对数据库的压力。此功能的示例将在第十章中展示，*有用的 Flask 扩展*。

最流行的键值存储是**Redis**，**Riak**和**Amazon DynamoDB**。

## 文档存储

**文档存储**是最流行的 NoSQL 数据库类型之一，通常用于替代 RDBMS。数据库将数据存储在称为文档的键值对集合中。这些文档是无模式的，意味着没有文档必须遵循另一个文档的结构。此外，可以在文档创建后附加额外的键。大多数文档存储将数据存储在**JSON**（**JavaScript 对象表示法**）中，JSON 的超集，或 XML 中。例如，以下是存储在 JSON 中的两个不同的帖子对象：

```py
{
    "title": "First Post",
    "text": "Lorem ipsum...",
    "date": "2015-01-20",
    "user_id": 45
}
{
    "title": "Second Post",
    "text": "Lorem ipsum...",
    "date": "2015-01-20",
    "user_id": 45,
    "comments": [
        {
            "name": "Anonymous",
            "text": "I love this post."
        }
    ]
}
```

请注意，第一个文档没有评论数组。如前所述，文档是无模式的，因此此格式是完全有效的。无模式还意味着在数据库级别没有类型检查。数据库上没有任何内容可以阻止将整数输入到帖子的标题字段中。无模式数据是文档存储的最强大功能，并吸引许多人采用它们的应用程序。但是，它也可能被认为非常危险，因为有一个检查可以阻止错误或格式错误的数据进入数据库。

一些文档存储将类似的对象收集到文档集合中，以便更容易地查询对象。但是，在一些文档存储中，所有对象都是一次查询的。文档存储存储每个对象的元数据，这允许查询并返回匹配的文档中的所有值。

最流行的文档存储是**MongoDB**，**CouchDB**和**Couchbase**。

## 列族存储

**列族存储**，也称为宽列存储，与键值存储和文档存储有许多共同之处。列族存储是最快的 NoSQL 数据库类型，因为它们设计用于大型应用程序。它们的主要优势是能够处理大量数据，并且通过以智能方式将数据分布在多台服务器上，仍然具有非常快的读写速度。

列族存储也是最难理解的，部分原因是列族存储的行话，因为它们使用与 RDBMS 相同的术语，但含义大相径庭。为了清楚地理解列族存储是什么，让我们直接举个例子。让我们在典型的列族存储中创建一个简单的*用户到帖子*关联。

首先，我们需要一个用户表。在列族存储中，数据是通过唯一键存储和访问的，例如键值存储，但内容是无结构的列，例如文档存储。考虑以下用户表：

| 键 | 杰克 | 约翰 |
| --- | --- | --- |
| **列** | **全名** | **生物** | **位置** | **全名** | **生物** |
| **值** | 杰克·斯托弗 | 这是我的个人简介 | 美国密歇根州 | 约翰·多 | 这是我的个人简介 |

请注意，每个键都包含列，这些列也是键值对。而且，并不要求每个键具有相同数量或类型的列。每个键可以存储数百个唯一的列，或者它们可以都有相同数量的列，以便更容易进行应用程序开发。这与键值存储形成对比，后者可以存储每个键的任何类型的数据。这也与文档存储略有不同，后者可以在每个文档中存储类型，比如数组和字典。现在让我们创建我们的帖子表：

| 键 | 帖子/1 | 帖子/2 |
| --- | --- | --- |
| **列** | **标题** | **日期** | **文本** | **标题** | **日期** | **文本** |
| **值** | 你好，世界 | 2015-01-01 | 发布的文本... | 仍然在这里 | 2015-02-01 | 发布的文本... |

在我们继续之前，有几件事情需要了解关于列族存储。首先，在列族存储中，数据只能通过单个键或键范围进行选择；无法查询列的内容。为了解决这个问题，许多程序员使用外部搜索工具与他们的数据库一起使用，比如**Elasticsearch**，它将列的内容存储在可搜索的格式中，并返回匹配的键供数据库查询。这种限制性是为什么在列族存储中适当的*模式*设计是如此关键的，必须在存储任何数据之前仔细考虑。

其次，数据不能按列的内容排序。数据只能按键排序，这就是为什么帖子的键是整数的原因。这样可以按照输入顺序返回帖子。这不是用户表的要求，因为没有必要按顺序排序用户。

第三，没有`JOIN`运算符，我们无法查询包含用户键的列。根据我们当前的模式，没有办法将帖子与用户关联起来。要创建这个功能，我们需要一个第三个表来保存用户到帖子的关联：

| 键 | 杰克 |
| --- | --- |
| **列** | 帖子 | 帖子/1 | 帖子/1 |
| **值** |   | 帖子/2 | 帖子/2 |

这与我们迄今为止看到的其他表略有不同。`帖子`列被命名为超级列，它是一个包含其他列的列。在这个表中，超级列与我们的用户键相关联，它包含了一个帖子到一个帖子的位置的关联。聪明的读者可能会问，为什么我们不把这个关联存储在用户表中，就像在文档存储中解决问题的方式一样。这是因为常规列和超级列不能存储在同一张表中。您必须在创建每个表时选择一个。

要获取用户的所有帖子列表，我们首先必须查询帖子关联表，使用我们的用户键，使用返回的关联列表获取帖子表中的所有键，并使用这些键查询帖子表。

如果这个查询对你来说似乎是一个绕圈子的过程，那是因为它确实是这样，而且它是有意设计成这样的。列族存储的限制性质使得它能够如此快速地处理如此多的数据。删除诸如按值和列名搜索等功能，使列族存储能够处理数百 TB 的数据。毫不夸张地说，SQLite 对程序员来说比典型的列族存储更复杂。

因此，大多数 Flask 开发人员应该避免使用列族存储，因为它给应用程序增加了不必要的复杂性。除非您的应用程序要处理每秒数百万次的读写操作，否则使用列族存储就像用原子弹钉打钉子。

最受欢迎的列族存储包括**BigTable**、**Cassandra**和**HBase**。

## 图数据库

图数据库旨在描述然后查询关系，它们类似于文档存储，但具有创建和描述两个**节点**之间链接的机制。

图存储中的节点是单个数据，通常是一组键值对或 JSON 文档。节点可以被标记为属于某个类别，例如用户或组。在定义了节点之后，可以创建任意数量的节点之间的单向关系（称为**链接**），并带有自己的属性。例如，如果我们的数据有两个用户节点，每个用户都认识对方，我们可以在它们之间定义两个“认识”链接来描述这种关系。这将允许您查询所有认识一个用户的人，或者一个用户认识的所有人。

![图形数据库](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_07_01.jpg)

图存储还允许您按照链接的属性进行查询。这使您可以轻松地创建否则复杂的查询，例如在 2001 年 10 月被一个用户标记为已知的所有用户。图存储可以从节点到节点跟随链接，创建更复杂的查询。如果这个示例数据集有更多的群组，我们可以查询那些我们认识的人已经加入但我们还没有加入的群组。或者，我们可以查询与某个用户在同一群组的人，但该用户不认识他们。图存储中的查询还可以跟随大量的链接来回答复杂的问题，比如“纽约有哪些评分为三星或更高的餐厅，提供汉堡，我的朋友们喜欢吗？”

图数据库最常见的用例是构建推荐引擎。例如，假设我们有一个图存储，其中填充了来自社交网络网站的朋友数据。利用这些数据，我们可以通过查询用户来构建一个共同的朋友查找器，其中超过两个朋友标记他们为朋友。

图数据库很少被用作应用程序的主要数据存储。大多数图存储的用途是，每个节点都充当主数据库中数据片段的表示，通过存储其唯一标识符和少量其他标识信息。

最流行的图存储是 Neo4j 和 InfoGrid。

# RDBMS 与 NoSQL

NoSQL 是一种工具，就像任何工具一样，它有特定的用例，它擅长的地方，以及其他工具更适合的用例。没有人会用螺丝刀来敲钉子。这是可能的，但使用锤子会让工作更容易。NoSQL 数据库的一个很大的问题是，人们在 RDBMS 可以同样好甚至更好地解决问题时采用了它们。

要了解何时使用哪种工具，我们必须了解两种系统的优势和劣势。

## RDBMS 数据库的优势

关系型数据库管理系统（RDBMS）的最大优势之一是其成熟性。RDBMS 背后的技术已经存在了 40 多年，基于关系代数和关系演算的坚实理论。由于它们的成熟性，在许多不同行业中，它们都有着长期的、经过验证的数据处理记录。

### 数据安全

安全性也是 RDBMS 的最大卖点之一。RDBMS 有几种方法来确保输入到数据库中的数据不仅是正确的，而且数据丢失几乎是不存在的。这些方法结合在一起形成了所谓的**ACID**，即原子性、一致性、隔离性和持久性。ACID 是一组事务规则，保证事务的安全处理。

首先，原子性要求每个事务要么全部完成，要么全部失败。这很像 Python 之禅中的思维方式：“错误不应悄悄地过去。除非明确地被消除。”如果数据更改或输入存在问题，事务不应继续操作，因为后续操作很可能需要先前的操作成功。

其次，一致性要求事务修改或添加的任何数据都要遵循每个表的规则。这些规则包括类型检查、用户定义的约束，如“外键”、级联规则和触发器。如果任何规则被违反，那么根据原子性规则，事务将被取消。

第三，隔离要求如果数据库并发运行事务以加快写入速度，那么如果它们按顺序运行，事务的结果将是相同的。这主要是数据库程序员的规则，而不是 Web 开发人员需要担心的事情。

最后，持久性要求一旦接受了一个事务，数据就绝不能丢失，除非在事务被接受后发生硬盘故障。如果数据库崩溃或断电，持久性原则要求在问题发生之前写入的任何数据在服务器备份时仍然存在。这基本上意味着一旦事务被接受，所有事务必须被写入磁盘。

### 速度和规模

一个常见的误解是 ACID 原则使得关系型数据库无法扩展并且速度慢。这只是一半正确；关系型数据库完全可以扩展。例如，由专业数据库管理员配置的 Oracle 数据库可以处理每秒数万个复杂查询。像 Facebook、Twitter、Tumblr 和 Yahoo!这样的大公司正在有效地使用 MySQL，而由于其速度优势，PostgreSQL 正在成为许多程序员的首选。

然而，关系型数据库最大的弱点是无法通过将数据跨多个数据库进行分割来轻松扩展。这并非不可能，正如一些批评者所暗示的那样，只是比 NoSQL 数据库更困难。这是由于`JOIN`的性质，它需要扫描整个表中的所有数据，即使它分布在多个服务器上。存在一些工具来帮助创建分区设置，但这仍然主要是专业数据库管理员的工作。

### 工具

在评估编程语言时，对于或反对采用它的最有力的观点是其社区的规模和活跃程度。更大更活跃的社区意味着如果遇到困难会有更多的帮助，并且更多的开源工具可用于项目中。

数据库也不例外。例如 MySQL 或 PostgreSQL 等关系型数据库为商业环境中几乎每种语言都有官方库，而其他语言也有非官方库。诸如 Excel 之类的工具可以轻松地从这些数据库中下载最新数据，并允许用户像对待任何其他数据集一样处理它。每个数据库都有几个免费的桌面 GUI，并且一些是由数据库的公司赞助的官方支持的。

## NoSQL 数据库的优势

许多人使用 NoSQL 数据库的主要原因是它在传统数据库上的速度优势。许多 NoSQL 数据库可以在开箱即用的情况下比关系型数据库表现出色。然而，速度是有代价的。许多 NoSQL 数据库，特别是文档存储，为了可用性而牺牲了一致性。这意味着它们可以处理许多并发读写，但这些写入可能彼此冲突。这些数据库承诺“最终一致性”，而不是在每次写入时进行一致性检查。简而言之，许多 NoSQL 数据库不提供 ACID 事务，或者默认情况下已关闭。一旦启用 ACID 检查，数据库的速度会接近传统数据库的性能。每个 NoSQL 数据库都以不同的方式处理数据安全，因此在选择一个数据库之前仔细阅读文档非常重要。

吸引人们使用 NoSQL 的第二个特性是其处理非格式化数据的能力。将数据存储为 XML 或 JSON 允许每个文档具有任意结构。存储用户设计的数据的应用程序从采用 NoSQL 中受益良多。例如，允许玩家将他们的自定义级别提交到某个中央存储库的视频游戏现在可以以可查询的格式存储数据，而不是以二进制大块存储。

吸引人们使用 NoSQL 的第三个特性是轻松创建一组协同工作的数据库集群。没有`JOIN`或者只通过键访问值使得在多台服务器之间分割数据相对来说是一个相当简单的任务，与关系型数据库相比。这是因为`JOIN`需要扫描整个表，即使它分布在许多不同的服务器上。当文档或键可以通过简单的算法分配到服务器时，`JOIN`变得更慢，例如，可以根据其唯一标识符的起始字符将其分配到服务器。例如，以字母 A-H 开头的所有内容发送到服务器一，I-P 发送到服务器二，Q-Z 发送到服务器三。这使得查找连接客户端的数据位置非常快。

## 在选择数据库时使用哪种

因此，每个数据库都有不同的用途。在本节的开头就提到了一个主要问题，即程序员在选择 NoSQL 数据库作为技术栈时的主要问题是，他们选择了一个关系型数据库同样适用的情况下。这源于一些常见的误解。首先，人们试图使用关系型思维和数据模型，并认为它们在 NoSQL 数据库中同样适用。人们通常会产生这种误解，因为 NoSQL 数据库网站上的营销是误导性的，并鼓励用户放弃他们当前的数据库，而不考虑非关系模型是否适用于他们的项目。

其次，人们认为必须只使用一个数据存储来进行应用程序。许多应用程序可以从使用多个数据存储中受益。以使用 Facebook 克隆为例，它可以使用 MySQL 来保存用户数据，redis 来存储会话数据，文档存储来保存人们共享的测验和调查数据，以及图形数据库来实现查找朋友的功能。

如果一个应用程序功能需要非常快的写入，并且写入安全性不是主要关注点，那么就使用文档存储数据库。如果需要存储和查询无模式数据，那么应该使用文档存储数据库。

如果一个应用程序功能需要存储一些在指定时间后自行删除的东西，或者数据不需要被搜索，那么就使用键值存储。

如果一个应用程序功能依赖于查找或描述两个或多个数据集之间的复杂关系，则使用图形存储。

如果一个应用程序功能需要保证写入安全性，每个条目可以固定到指定的模式，数据库中的不同数据集需要使用 JOIN 进行比较，或者需要对输入的数据进行约束，那么就使用关系型数据库。

# Flask 中的 MongoDB

MongoDB 远远是最受欢迎的 NoSQL 数据库。MongoDB 也是 Flask 和 Python 中最受支持的 NoSQL 数据库。因此，我们的示例将重点放在 MongoDB 上。

MongoDB 是一个文档存储的 NoSQL 数据库。文档存储在集合中，允许对类似的文档进行分组，但在存储文档时不需要文档之间的相似性。文档在一个名为 BSON 的 JSON 超集中定义，BSON 代表二进制 JSON。BSON 允许以二进制格式存储 JSON，而不是字符串格式，节省了大量空间。BSON 还区分了存储数字的几种不同方式，例如 32 位整数和双精度浮点数。

为了理解 MongoDB 的基础知识，我们将使用 Flask-MongoEngine 来覆盖前几章中 Flask-SQLAlchemy 的相同功能。请记住，这些只是例子。重构我们当前的代码以使用 MongoDB 没有任何好处，因为 MongoDB 无法为我们的用例提供任何新功能。MongoDB 的新功能将在下一节中展示。

## 安装 MongoDB

要安装 MongoDB，请转到[`www.mongodb.org/downloads`](https://www.mongodb.org/downloads)，并从标题“下载并运行 MongoDB 自己”下的选项卡中选择您的操作系统。每个支持版本的操作系统都有安装说明列在安装程序的下载按钮旁边。

要运行 MongoDB，请转到 bash 并运行：

```py
$ mongod

```

这将在窗口打开的时间内运行服务器。

## 设置 MongoEngine

在开始之前，需要使用 pip 安装 MongoEngine：

```py
$ pip install Flask-MongoEngine

```

在`models.py`文件中，将创建一个代表我们数据库的 mongo 对象：

```py
from flask.ext.mongoengine import MongoEngine
…
db = SQLAlchemy()
mongo = MongoEngine()
```

与 SQLAlchemy 对象一样，我们的 mongo 对象需要在`__init__.py`中的 app 对象上初始化。

```py
from models import db, mongo
…
db.init_app(app)
mongo.init_app(app)
```

在我们的应用程序运行之前，我们的`config.py`中的`DevConfig`对象需要设置 mongo 连接的参数：

```py
MONGODB_SETTINGS = {
    'db': 'local',
    'host': 'localhost',
    'port': 27017
}
```

这些是全新 MongoDB 安装的默认值。

## 定义文档

MongoEngine 是围绕 Python 对象系统构建的 ORM，专门用于 MongoDB。不幸的是，没有支持所有 NoSQL 驱动程序的 SQLAlchemy 风格的包装器。在关系型数据库管理系统中，SQL 的实现是如此相似，以至于创建一个通用接口是可能的。然而，每个文档存储的基本实现都有足够的不同，以至于创建类似接口的任务比它的价值更麻烦。

您的 mongo 数据库中的每个集合都由从 mongo.Document 继承的类表示：

```py
class Post(mongo.Document):
    title = mongo.StringField(required=True)
    text = mongo.StringField()
    publish_date = mongo.DateTimeField(
        default=datetime.datetime.now()
    )

    def __repr__(self):
        return "<Post '{}'>".format(self.title)
```

每个类变量都是文档所属的键的表示，这在本例中代表了一个 Post 类。类变量名称用作文档中的键。

与 SQLAlchemy 不同，无需定义主键。唯一的 ID 将在 ID 属性下为您生成。前面的代码将生成一个类似于以下的 BSON 文档：

```py
{
    "_id": "55366ede8b84eb00232da905",
    "title": "Post 0",
    "text": "<p>Lorem ipsum dolor...",
    "publish_date": {"$date": 1425255876037}
}
```

### 字段类型

有许多字段，每个字段代表 Mongo 中的一个不同数据类别。与底层数据库不同，每个字段在允许保存或更改文档之前提供类型检查。最常用的字段如下：

+   BooleanField

+   DateTimeField

+   DictField

+   DynamicField

+   EmbeddedDocumentField

+   FloatField

+   IntField

+   ListField

+   ObjectIdField

+   ReferenceField

+   StringField

### 注意

要获取字段的完整列表和详细文档，请访问 MongoEngine 网站[`docs.mongoengine.org`](http://docs.mongoengine.org)。

其中大多数都以它们接受的 Python 类型命名，并且与 SQLAlchemy 类型的工作方式相同。但是，还有一些新类型在 SQLAlchemy 中没有对应的。`DynamicField`是一个可以容纳任何类型值并且对值不执行类型检查的字段。`DictField`可以存储`json.dumps()`序列化的任何 Python 字典。`ReferenceField`只是存储文档的唯一 ID，并且在查询时，MongoEngine 将返回引用的文档。与`ReferenceField`相反，`EmbeddedDocumentField`将传递的文档存储在父文档中，因此不需要进行第二次查询。`ListField`类型表示特定类型的字段列表。

这通常用于存储对其他文档的引用列表或嵌入式文档的列表，以创建一对多的关系。如果需要一个未知类型的列表，可以使用`DynamicField`。每种字段类型都需要一些常见的参数，如下所示。

```py
Field(
    primary_key=None
    db_field=None,
    required=False,
    default=None,
    unique=False,
    unique_with=None,
    choices=None
)
```

`primary_key`参数指定您不希望 MongoEngine 自动生成唯一键，而应使用字段的值作为 ID。现在，该字段的值将从`id`属性和字段的名称中访问。

`db_field`定义了每个文档中键的名称。如果未设置，它将默认为类变量的名称。

如果将`required`定义为`True`，则该键必须存在于文档中。否则，该类型的文档不必存在该键。当查询定义了一个类的不存在键时，它将返回 None。

`default`指定如果未定义值，则该字段将被赋予的值。

如果`unique`设置为`True`，MongoEngine 会检查确保集合中没有其他文档具有该字段的相同值。

当传递字段名称列表时，`unique_with`将确保在组合中取值时，所有字段的值对于每个文档都是唯一的。这很像 RDBMS 中的多列`UNIQUE`索引。

最后，当给定一个列表时，`choices`选项将限制该字段的可允许值为列表中的元素。

### 文档类型

MongoEngine 定义文档的方法可以根据集合的不同实现灵活性或严格性。从`mongo.Document`继承意味着只有在类中定义的键才能保存到数据库中。类中定义的键可以为空，但其他所有内容都将被忽略。另一方面，如果您的类继承`mongo.DynamicDocument`，任何设置的额外字段都将被视为`DynamicFields`并将与文档一起保存。

```py
class Post(mongo.DynamicDocument):
    title = mongo.StringField(required=True, unique=True)
    text = mongo.StringField()
    …
```

为了展示不推荐的极端情况，以下类是完全有效的；它没有必填字段，并允许设置任何字段：

```py
class Post(mongo.DynamicDocument):
    pass
```

最后一种文档类型是`EmbeddedDocument`。`EmbeddedDocument`只是一个传递给`EmbeddedDocumentField`并按原样存储在文档中的文档，如下所示：

```py
class Comment(mongo.EmbeddedDocument):
    name = mongo.StringField(required=True)
    text = mongo.StringField(required=True)
    date = mongo.DateTimeField(
        default=datetime.datetime.now()
    )

```

为什么在它们似乎执行相同功能时使用`EmbeddedDocumentField`而不是`DictField`？使用每个的最终结果是相同的。然而，嵌入式文档为数据定义了一个结构，而`DictField`可以是任何东西。为了更好地理解，可以这样想：`Document`对应于`DynamicDocument`，而`EmbeddedDocument`对应于`DictField`。

### meta 属性

使用`meta`类变量，可以手动设置文档的许多属性。如果您正在处理现有数据集并希望将您的类连接到集合，请设置`meta`字典的 collection 键：

```py
class Post(mongo.Document):
    …
    meta = {'collection': 'user_posts'}
```

您还可以手动设置集合中文档的最大数量以及每个文档的大小。在此示例中，只能有 10,000 个文档，每个文档的大小不能超过 2 MB：

```py
 class Post(mongo.Document):
    …
    meta = {
```

```py
        'collection': 'user_posts',
        'max_documents': 10000,
        'max_size': 2000000
    }
```

索引也可以通过 MongoEngine 设置。索引可以使用字符串设置单个字段，或使用元组设置多字段：

```py
class Post(mongo.Document):
    …
    meta = {
```

```py
        'collection': 'user_posts',
        'max_documents': 10000,
        'max_size': 2000000,
        'indexes': [
            'title',
            ('title', 'user')
        ]
    }
```

集合的默认排序可以通过`meta`变量和**ordering key**进行设置。当在字段前加上`-`时，它告诉 MongoEngine 按该字段的降序顺序排序结果。如果在字段前加上`+`，它告诉 MongoEngine 按该字段的升序顺序排序结果。如果在查询中指定了`order_by`函数，将覆盖此默认行为，这将在*CRUD*部分中显示。

```py
class Post(mongo.Document):
    …
    meta = {
```

```py
        'collection': 'user_posts',
        'max_documents': 10000,
        'max_size': 2000000,
        'indexes': [
            'title',
            ('title', 'user')
        ],
        'ordering': ['-publish_date']
    }
```

`meta`变量还可以启用从用户定义的文档继承，这默认情况下是禁用的。原始文档的子类将被视为父类的成员，并将存储在同一集合中，如下所示：

```py
class Post(mongo.Document):
    …
    meta = {'allow_inheritance': True}

class Announcement(Post):
    …
```

## CRUD

如第二章中所述，使用 SQLAlchemy 创建模型，任何数据存储必须实现四种主要形式的数据操作。它们是创建新数据，读取现有数据，更新现有数据和删除数据。

### 创建

要创建新文档，只需创建类的新实例并调用`save`方法。

```py
>>> post = Post()
>>> post.title = "Post From The Console"
>>> post.text = "Lorem Ipsum…"
>>> post.save()

```

否则，可以将值作为关键字传递给对象创建：

```py
>>> post = Post(title="Post From Console", text="Lorem Ipsum…")

```

与 SQLAlchemy 不同，MongoEngine 不会自动保存存储在`ReferenceFields`中的相关对象。要保存对当前文档的引用文档的任何更改，请将`cascade`传递为`True`：

```py
>>> post.save(cascade=True)

```

如果您希望插入文档并跳过其对类定义中定义的参数的检查，则将 validate 传递为`False`。

```py
>>> post.save(validate=False)

```

### 提示

记住这些检查是有原因的。只有在非常充分的理由下才关闭它

#### 写入安全性

默认情况下，MongoDB 在确认写入发生之前不会等待数据写入磁盘。这意味着已确认的写入可能失败，无论是硬件故障还是写入时发生的某些错误。为了确保数据在 Mongo 确认写入之前写入磁盘，请使用`write_concern`关键字。**写关注**告诉 Mongo 何时应该返回写入的确认：

```py
# will not wait for write and not notify client if there was an error
>>> post.save(write_concern={"w": 0})
# default behavior, will not wait for write
>>> post.save(write_concern={"w": 1})
# will wait for write
>>> post.save(write_concern={"w": 1, "j": True})

```

### 注意

如 RDBMS 与 NoSQL 部分所述，您了解您使用的 NoSQL 数据库如何处理写入非常重要。要了解有关 MongoDB 写入关注的更多信息，请访问[`docs.mongodb.org/manual/reference/write-concern/`](http://docs.mongodb.org/manual/reference/write-concern/)。

### 阅读

要访问数据库中的文档，使用`objects`属性。要读取集合中的所有文档，请使用`all`方法：

```py
>>> Post.objects.all()
[<Post: "Post From The Console">]

```

要限制返回的项目数量，请使用`limit`方法：

```py
# only return five items
>>> Post.objects.limit(5).all()

```

此`limit`命令与 SQL 版本略有不同。在 SQL 中，`limit`命令也可用于跳过第一个结果。要复制此功能，请使用`skip`方法如下：

```py
# skip the first 5 items and return items 6-10
>>> Post.objects.skip(5).limit(5).all()

```

默认情况下，MongoDB 返回按其创建时间排序的结果。要控制此行为，有`order_by`函数：

```py
# ascending
>>> Post.objects.order_by("+publish_date").all()
# descending
>>> Post.objects.order_by("-publish_date").all()

```

如果您只想要查询的第一个结果，请使用`first`方法。如果您的查询返回了空值，并且您期望它是这样的，请使用`first_or_404`来自动中止并返回 404 错误。这与其 Flask-SQLAlchemy 对应物完全相同，并由 Flask-MongoEngine 提供。

```py
>>> Post.objects.first()
<Post: "Post From The Console">
>>> Post.objects.first_or_404()
<Post: "Post From The Console">

```

`get`方法也具有相同的行为，它期望查询只返回一个结果，否则将引发异常：

```py
# The id value will be different your document
>>> Post.objects(id="5534451d8b84ebf422c2e4c8").get()
<Post: "Post From The Console">
>>> Post.objects(id="5534451d8b84ebf422c2e4c8").get_or_404()
<Post: "Post From The Console">

```

`paginate`方法也存在，并且与其 Flask-SQLAlchemy 对应物具有完全相同的 API：

```py
>>> page = Post.objects.paginate(1, 10)
>>> page.items()
[<Post: "Post From The Console">]

```

此外，如果您的文档具有`ListField`方法，则可以使用文档对象上的`paginate_field`方法来分页显示列表项。

#### 过滤

如果您知道要按字段过滤的确切值，请将其值作为关键字传递给`objects`方法：

```py
>>> Post.objects(title="Post From The Console").first()
<Post: "Post From The Console">

```

与 SQLAlchemy 不同，我们不能通过真值测试来过滤结果。相反，使用特殊的关键字参数来测试值。例如，要查找 2015 年 1 月 1 日后发布的所有帖子：

```py
>>> Post.objects(
 publish_date__gt=datetime.datetime(2015, 1, 1)
 ).all()
[<Post: "Post From The Console">]

```

关键字末尾的`__gt`称为操作符。MongoEngine 支持以下操作符：

+   `ne`：不等于

+   `lt`：小于

+   `lte`：小于或等于

+   `gt`：大于

+   `gte`：大于或等于

+   `not`：否定操作符，例如，`publish_date__not__gt`

+   `in`：值在列表中

+   `nin`：值不在列表中

+   `mod`：*value % a == b*，*a*和*b*作为(*a*, *b*)传递

+   `all`：提供的值列表中的每个项目都在字段中

+   `size`：列表的大小

+   `exists`：字段存在值

MongoEngine 还提供了以下操作符来测试字符串值：

+   `exact`：字符串等于该值

+   `iexact`：字符串等于该值（不区分大小写）

+   `contains`：字符串包含该值

+   `icontains`：字符串包含该值（不区分大小写）

+   `startswith`：字符串以该值开头

+   `istartswith`：字符串以该值开头（不区分大小写）

+   `endswith`：字符串以该值结尾

+   `iendswith`：字符串以该值结尾（不区分大小写）`更新`

这些运算符可以组合在一起，创建与前几节中创建的相同强大的查询。例如，要查找所有在 2015 年 1 月 1 日之后创建的帖子，标题中不包含`post`一词，正文以`Lorem`一词开头，并按发布日期排序，最新的在前：

```py
>>> Post.objects(
 title__not__icontains="post",
 text__istartswith="Lorem",
 publish_date__gt=datetime.datetime(2015, 1, 1),
).order_by("-publish_date").all()

```

但是，如果有一些无法用这些工具表示的复杂查询，那么也可以传递原始的 Mongo 查询：

```py
>>> Post.objects(__raw__={"title": "Post From The Console"})

```

### 更新

要更新对象，需要在查询结果上调用`update`方法。

```py
>>> Post.objects(
 id="5534451d8b84ebf422c2e4c8"
 ).update(text="Ipsum lorem")

```

如果查询只应返回一个值，则使用`update_one`仅修改第一个结果：

```py
>>> Post.objects(
 id="5534451d8b84ebf422c2e4c8"
 ).update_one(text="Ipsum lorem")

```

与传统的 SQL 不同，在 MongoDB 中有许多不同的方法来更改值。使用运算符以不同的方式更改字段的值：

+   `set`：这设置一个值（与之前给定的相同）

+   `unset`：这会删除一个值并移除键

+   `inc`：这增加一个值

+   `dec`：这减少一个值

+   `push`：这将一个值附加到列表

+   `push_all`：这将多个值附加到列表

+   `pop`：这会移除列表的第一个或最后一个元素

+   `pull`：这从列表中移除一个值

+   `pull_all`：这会从列表中移除多个值

+   `add_to_set`：仅当列表中不存在时，将值添加到列表中

例如，如果需要将`Python`值添加到具有`MongoEngine`标签的所有`Post`文档的名为标签的`ListField`中：

```py
>>> Post.objects(
 tags__in="MongoEngine",
 tags__not__in="Python"
 ).update(push__tags="Python")

```

相同的写关注参数对于更新存在。

```py
>>> Post.objects(
 tags__in="MongoEngine"
 ).update(push__tags="Python", write_concern={"w": 1, "j": True})

```

### 删除

要删除文档实例，请调用其`delete`方法：

```py
>>> post = Post.objects(
 id="5534451d8b84ebf422c2e4c8"
 ).first()
>>> post.delete()

```

## NoSQL 中的关系

就像我们在 SQLAlchemy 中创建关系一样，我们可以在 MongoEngine 中创建对象之间的关系。只有使用 MongoEngine，我们将在没有`JOIN`运算符的情况下这样做。

### 一对多关系

在 MongoEngine 中创建一对多关系有两种方法。第一种方法是通过使用`ReferenceField`在两个文档之间创建关系，指向另一个对象的 ID。

```py
class Post(mongo.Document):
    …
    user = mongo.ReferenceField(User)
```

访问`ReferenceField`的属性直接访问引用对象如下：

```py
>>> user = User.objects.first()
>>> post = Post.objects.first()
>>> post.user = user
>>> post.save()
>>> post.user
<User Jack>

```

与 SQLAlchemy 不同，MongoEngine 没有办法访问具有与另一个对象的关系的对象。使用 SQLAlchemy，可以声明`db.relationship`变量，允许用户对象访问具有匹配`user_id`列的所有帖子。MongoEngine 中不存在这样的并行。

一个解决方案是获取要搜索的帖子的用户 ID，并使用用户字段进行过滤。这与 SQLAlchemy 在幕后执行的操作相同，但我们只是手动执行：

```py
>>> user = User.objects.first()
>>> Post.objects(user__id=user.id)

```

创建一对多关系的第二种方法是使用带有`EmbeddedDocument`的`EmbeddedDocumentField`：

```py
class Post(mongo.Document):
    title = mongo.StringField(required=True)
    text = mongo.StringField()
    publish_date = mongo.DateTimeField(
        default=datetime.datetime.now()
    )
    user = mongo.ReferenceField(User)
    comments = mongo.ListField(
        mongo.EmbeddedDocumentField(Comment)
    )
```

访问`comments`属性会给出所有嵌入文档的列表。要向帖子添加新评论，将其视为列表并将`comment`文档附加到其中：

```py
>>> comment = Comment()
>>> comment.name = "Jack"
>>> comment.text = "I really like this post!"
>>> post.comments.append(comment)
>>> post.save()
>>> post.comments
[<Comment 'I really like this post!'>]

```

请注意，评论变量上没有调用`save`方法。这是因为评论文档不是真正的文档，它只是`DictField`的抽象。还要记住，文档只能有 16MB 大，所以要小心每个文档上有多少`EmbeddedDocumentFields`以及每个文档上有多少`EmbeddedDocuments`。

### 多对多关系

文档存储数据库中不存在多对多关系的概念。这是因为使用`ListFields`它们变得完全无关紧要。为了按照惯例为`Post`对象创建标签功能，添加一个字符串列表：

```py
class Post(mongo.Document):
    title = mongo.StringField(required=True)
    text = mongo.StringField()
    publish_date = mongo.DateTimeField(
        default=datetime.datetime.now()
    )
    user = mongo.ReferenceField(User)
    comments = mongo.ListField(
        mongo.EmbeddedDocumentField(Comment)
    )
    tags = mongo.ListField(mongo.StringField())
```

现在，当我们希望查询具有特定标签或多个标签的所有`Post`对象时，这是一个简单的查询：

```py
>>> Post.objects(tags__in="Python").all()
>>> Post.objects(tags__all=["Python", "MongoEngine"]).all()

```

对于每个用户对象上的角色列表，可以提供可选的 choices 参数来限制可能的角色：

```py
available_roles = ('admin', 'poster', 'default')

class User(mongo.Document):
    username = mongo.StringField(required=True)
    password = mongo.StringField(required=True)
    roles = mongo.ListField(
        mongo.StringField(choices=available_roles)
    )

    def __repr__(self):
        return '<User {}>'.format(self.username)
```

# 利用 NoSQL 的强大功能

到目前为止，我们的 MongoEngine 代码应该如下所示：

```py
available_roles = ('admin', 'poster', 'default')

class User(mongo.Document):
    username = mongo.StringField(required=True)
    password = mongo.StringField(required=True)
    roles = mongo.ListField(
        mongo.StringField(choices=available_roles)
    )

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Comment(mongo.EmbeddedDocument):
    name = mongo.StringField(required=True)
    text = mongo.StringField(required=True)
    date = mongo.DateTimeField(
        default=datetime.datetime.now()
    )

    def __repr__(self):
        return "<Comment '{}'>".format(self.text[:15])

class Post(mongo.Document):
    title = mongo.StringField(required=True)
    text = mongo.StringField()
    publish_date = mongo.DateTimeField(
        default=datetime.datetime.now()
    )
    user = mongo.ReferenceField(User)
    comments = mongo.ListField(
        mongo.EmbeddedDocumentField(Comment)
    )
    tags = mongo.ListField(mongo.StringField())

    def __repr__(self):
        return "<Post '{}'>".format(self.title)
```

这段代码实现了与 SQLAlchemy 模型相同的功能。为了展示 NoSQL 的独特功能，让我们添加一个在 SQLAlchemy 中可能实现但更加困难的功能：不同的帖子类型，每种类型都有自己的自定义内容。这将类似于流行博客平台 Tumblr 的功能。

首先，允许您的帖子类型充当父类，并从`Post`类中删除文本字段，因为并非所有帖子都会有文本：

```py
class Post(mongo.Document):
    title = mongo.StringField(required=True)
    publish_date = mongo.DateTimeField(
        default=datetime.datetime.now()
    )
    user = mongo.ReferenceField(Userm)
    comments = mongo.ListField(
        mongo.EmbeddedDocumentField(Commentm)
    )
    tags = mongo.ListField(mongo.StringField())

    meta = {
        'allow_inheritance': True
    }
```

每种帖子类型都将继承自`Post`类。这样做将使代码能够将任何`Post`子类视为`Post`。我们的博客应用将有四种类型的帖子：普通博客帖子、图片帖子、视频帖子和引用帖子。

```py
class BlogPost(Post):
    text = db.StringField(required=True)

    @property
    def type(self):
        return "blog"

class VideoPost(Post):
    url = db.StringField(required=True)

    @property
    def type(self):
        return "video"

class ImagePost(Post):
    image_url = db.StringField(required=True)

    @property
    def type(self):
        return "image"

class QuotePost(Post):
    quote = db.StringField(required=True)
    author = db.StringField(required=True)

    @property
    def type(self):
        return "quote"
```

我们的帖子创建页面需要能够创建每种帖子类型。`forms.py`中的`PostForm`对象，用于处理帖子创建，将需要修改以首先处理新字段。我们将添加一个选择字段来确定帖子类型，一个用于引用类型的`author`字段，一个用于保存 URL 的`image`字段，以及一个用于保存嵌入式 HTML iframe 的`video`字段。引用和博客帖子内容都将共享`text`字段，如下所示：

```py
class PostForm(Form):
    title = StringField('Title', [
        DataRequired(),
        Length(max=255)
    ])
    type = SelectField('Post Type', choices=[
        ('blog', 'Blog Post'),
        ('image', 'Image'),
        ('video', 'Video'),
        ('quote', 'Quote')
    ])
    text = TextAreaField('Content')
    image = StringField('Image URL', [URL(), Length(max=255)])
    video = StringField('Video Code', [Length(max=255)])
    author = StringField('Author', [Length(max=255)])
```

`blog.py`控制器中的`new_post`视图函数还需要更新以处理新的帖子类型：

```py
@blog_blueprint.route('/new', methods=['GET', 'POST'])
@login_required
@poster_permission.require(http_exception=403)
def new_post():
    form = PostForm()

    if form.validate_on_submit():
        if form.type.data == "blog":
            new_post = BlogPost()
            new_post.text = form.text.data
        elif form.type.data == "image":
            new_post = ImagePost()
            new_post.image_url = form.image.data
        elif form.type.data == "video":
            new_post = VideoPost()
            new_post.video_object = form.video.data
        elif form.type.data == "quote":
            new_post = QuotePost()
            new_post.text = form.text.data
            new_post.author = form.author.data

        new_post.title = form.title.data
        new_post.user = User.objects(
            username=current_user.username
        ).one()

        new_post.save()

    return render_template('new.html', form=form)
```

渲染我们的表单对象的`new.html`文件将需要显示添加到表单的新字段：

```py
<form method="POST" action="{{ url_for('.new_post') }}">
…
<div class="form-group">
    {{ form.type.label }}
    {% if form.type.errors %}
        {% for e in form.type.errors %}
            <p class="help-block">{{ e }}</p>
        {% endfor %}
    {% endif %}
    {{ form.type(class_='form-control') }}
</div>
…
<div id="image_group" class="form-group">
    {{ form.image.label }}
    {% if form.image.errors %}
         {% for e in form.image.errors %}
            <p class="help-block">{{ e }}</p>
         {% endfor %}
    {% endif %}
    {{ form.image(class_='form-control') }}
</div>
<div id="video_group" class="form-group">
    {{ form.video.label }}
    {% if form.video.errors %}
        {% for e in form.video.errors %}
            <p class="help-block">{{ e }}</p>
        {% endfor %}
    {% endif %}
    {{ form.video(class_='form-control') }}
</div>
<div id="author_group" class="form-group">
    {{ form.author.label }}
        {% if form.author.errors %}
            {% for e in form.author.errors %}
                <p class="help-block">{{ e }}</p>
            {% endfor %}
        {% endif %}
        {{ form.author(class_='form-control') }}
</div>
<input class="btn btn-primary" type="submit" value="Submit">
</form>

```

现在我们有了新的输入，我们可以添加一些 JavaScript 来根据帖子类型显示和隐藏字段：

```py
{% block js %}
<script src="img/ckeditor.js"></script>
<script>
    CKEDITOR.replace('editor');

    $(function () {
        $("#image_group").hide();
        $("#video_group").hide();
        $("#author_group").hide();

        $("#type").on("change", function () {
            switch ($(this).val()) {
                case "blog":
                    $("#text_group").show();
                    $("#image_group").hide();
                    $("#video_group").hide();
                    $("#author_group").hide();
                    break;
                case "image":
                    $("#text_group").hide();
                    $("#image_group").show();
                    $("#video_group").hide();
                    $("#author_group").hide();
                    break;
                case "video":
                    $("#text_group").hide();
                    $("#image_group").hide();
                    $("#video_group").show();
                    $("#author_group").hide();
                    break;
                case "quote":
                    $("#text_group").show();
                    $("#image_group").hide();
                    $("#video_group").hide();
                    $("#author_group").show();
                    break;
            }
        });
    })
</script>
{% endblock %}
```

最后，`post.html`需要能够正确显示我们的帖子类型。我们有以下内容：

```py
<div class="col-lg-12">
    {{ post.text | safe }}
</div>
All that is needed is to replace this with:
<div class="col-lg-12">
    {% if post.type == "blog" %}
        {{ post.text | safe }}
    {% elif post.type == "image" %}
        <img src="img/{{ post.image_url }}" alt="{{ post.title }}">
    {% elif post.type == "video" %}
        {{ post.video_object | safe }}
    {% elif post.type == "quote" %}
        <blockquote>
            {{ post.text | safe }}
        </blockquote>
        <p>{{ post.author }}</p>
    {% endif %}
</div>
```

# 摘要

在本章中，介绍了 NoSQL 和传统 SQL 系统之间的基本区别。我们探讨了 NoSQL 系统的主要类型，以及应用程序可能需要或不需要使用 NoSQL 数据库的原因。利用我们应用程序的模型作为基础，展示了 MongoDB 和 MongoEngine 的强大之处，以及设置复杂关系和继承的简单性。在下一章中，我们的博客应用将通过一个专为希望使用我们网站构建自己服务的其他程序员设计的功能进行扩展，即 RESTful 端点。
