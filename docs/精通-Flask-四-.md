# 精通 Flask（四）

> 原文：[`zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530`](https://zh.annas-archive.org/md5/3704FA7246A3AC34DE99A41EE212E530)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：创建自己的扩展

从本书的第一章开始，我们一直在向我们的应用程序中添加 Flask 扩展，以添加新功能并节省我们花费大量时间重新发明轮子。到目前为止，这些 Flask 扩展是如何工作的还是未知的。在本章中，我们将创建两个简单的 Flask 扩展，以更好地理解 Flask 的内部工作，并允许您使用自己的功能扩展 Flask。

# 创建 YouTube Flask 扩展

首先，我们要创建的第一个扩展是一个简单的扩展，允许在 Jinja 模板中嵌入 YouTube 视频，标签如下：

```py
{{ youtube(video_id) }}
```

`video_id`对象是任何 YouTube URL 中`v`后面的代码。例如，在 URL [`www.youtube.com/watch?v=_OBlgSz8sSM`](https://www.youtube.com/watch?v=_OBlgSz8sSM) 中，`video_id`对象将是`_OBlgSz8sSM`。

目前，这个扩展的代码将驻留在`extensions.py`中。但是，这只是为了开发和调试目的。当代码准备分享时，它将被移动到自己的项目目录中。

任何 Flask 扩展需要的第一件事是将在应用程序上初始化的对象。这个对象将处理将其`Blueprint`对象添加到应用程序并在 Jinja 上注册`youtube`函数：

```py
from flask import Blueprint

class Youtube(object):
    def __init__(self, app=None, **kwargs):
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.register_blueprint(app)

    def register_blueprint(self, app):
        module = Blueprint(
            "youtube",
            __name__,
            template_folder="templates"
        )
        app.register_blueprint(module)
        return module
```

到目前为止，这段代码唯一做的事情就是在`app`对象上初始化一个空的蓝图。下一段所需的代码是视频的表示。接下来将是一个处理 Jinja 函数参数并渲染 HTML 以在模板中显示的类：

```py
from flask import (
    flash,
    redirect,
    url_for,
    session,
    render_template,
    Blueprint,
    Markup
)

class Video(object):
    def __init__(self, video_id, cls="youtube"):
        self.video_id = video_id
        self.cls = cls

    def render(self, *args, **kwargs):
        return render_template(*args, **kwargs)

    @property
    def html(self):
        return Markup(
            self.render('youtube/video.html', video=self)
        )
```

这个对象将从模板中的`youtube`函数创建，并且模板中传递的任何参数都将传递给这个对象以渲染 HTML。在这段代码中还有一个新对象，`Markup`，我们以前从未使用过。`Markup`类是 Flask 自动转义 HTML 或将其标记为安全包含在模板中的方式。如果我们只返回 HTML，Jinja 会自动转义它，因为它不知道它是否安全。这是 Flask 保护您的网站免受**跨站脚本攻击**的方式。

下一步是创建将在 Jinja 中注册的函数：

```py
def youtube(*args, **kwargs):
    video = Video(*args, **kwargs)
    return video.html
```

在`YouTube`类中，我们必须在`init_app`方法中向 Jinja 注册函数：

```py
class Youtube(object):
    def __init__(self, app=None, **kwargs):
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.register_blueprint(app)
        app.add_template_global(youtube)
```

最后，我们必须创建 HTML，将视频添加到页面中。在`templates`目录中的一个名为`youtube`的新文件夹中，创建一个名为`video.html`的新 HTML 文件，并将以下代码添加到其中：

```py
<iframe
    class="{{ video.cls }}"
    width="560"
    height="315" 
    src="img/{{ video.video_id }}"
    frameborder="0"
    allowfullscreen>
</iframe>
```

这是在模板中嵌入 YouTube 视频所需的所有代码。现在让我们来测试一下。在`extensions.py`中，在`Youtube`类定义下方初始化`Youtube`类：

```py
youtube_ext = Youtube()
```

在`__init__.py`中，导入`youtube_ext`变量，并使用我们创建的`init_app`方法将其注册到应用程序上：

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
    mail,
    youtube_ext
)

def create_app(object_name):
    …
    youtube_ext.init_app(app)
```

现在，作为一个简单的例子，在博客主页的顶部添加`youtube`函数：

```py
{{ youtube("_OBlgSz8sSM") }}
```

这将产生以下结果：

![创建 YouTube Flask 扩展](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_11_01.jpg)

## 创建 Python 包

为了使我们的新 Flask 扩展可供他人使用，我们必须从到目前为止编写的代码中创建一个可安装的 Python 包。首先，我们需要一个新的项目目录，位于当前应用程序目录之外。我们需要两样东西：一个`setup.py`文件，稍后我们将填写它，和一个名为`flask_youtube`的文件夹。在`flask_youtube`目录中，我们将有一个`__init__.py`文件，其中将包含我们为扩展编写的所有代码。

以下是包含在`__init__.py`文件中的该代码的最终版本：

```py
from flask import render_template, Blueprint, Markup

class Video(object):
    def __init__(self, video_id, cls="youtube"):
        self.video_id = video_id
        self.cls = cls

    def render(self, *args, **kwargs):
        return render_template(*args, **kwargs)

    @property
    def html(self):
        return Markup(
            self.render('youtube/video.html', video=self)
        )

def youtube(*args, **kwargs):
    video = Video(*args, **kwargs)
    return video.html

class Youtube(object):
    def __init__(self, app=None, **kwargs):
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.register_blueprint(app)
        app.add_template_global(youtube)

    def register_blueprint(self, app):
        module = Blueprint(
            "youtube",
            __name__,
            template_folder="templates"
        )
        app.register_blueprint(module)
        return module
```

还在`flask_youtube`目录中，我们将需要一个`templates`目录，其中将包含我们放在应用程序`templates`目录中的`youtube`目录。

为了将这段代码转换成 Python 包，我们将使用名为`setuptools`的库。`setuptools`是一个 Python 包，允许开发人员轻松创建可安装的包。`setuptools`将捆绑代码，以便`pip`和`easy_install`可以自动安装它们，并且甚至可以将你的包上传到**Python Package Index**（**PyPI**）。

### 注意

我们一直从 PyPI 安装的所有包都来自`pip`。要查看所有可用的包，请转到[`pypi.python.org/pypi`](https://pypi.python.org/pypi)。

要获得这个功能，只需要填写`setup.py`文件即可。

```py
from setuptools import setup, find_packages
setup(
    name='Flask-YouTube',
    version='0.1',
    license='MIT',
    description='Flask extension to allow easy embedding of YouTube videos',
    author='Jack Stouffer',
    author_email='example@gmail.com',
    platforms='any',
    install_requires=['Flask'],
    packages=find_packages()
)
```

这段代码使用`setuptools`中的`setup`函数来查找你的源代码，并确保安装你的代码的机器具有所需的包。大多数属性都相当容易理解，除了`package`属性，它使用`setuptools`中的`find_packages`函数。`package`属性的作用是找到我们源代码中要发布的部分。我们使用`find_packages`方法自动找到要包含的代码部分。这基于一些合理的默认值，比如查找带有`__init__.py`文件的目录并排除常见的文件扩展名。

虽然这不是强制性的，但这个设置也包含了关于作者和许可的元数据，如果我们要在 PyPI 页面上上传这个设置，这些信息也会被包含在其中。`setup`函数中还有更多的自定义选项，所以我鼓励你阅读[`pythonhosted.org/setuptools/`](http://pythonhosted.org/setuptools/)上的文档。

现在，你可以通过运行以下命令在你的机器上安装这个包：

```py
$ python setup.py build
$ python setup.py install

```

这将把你的代码安装到 Python 的`packages`目录中，或者如果你使用`virtualenv`，它将安装到本地的`packages`目录中。然后，你可以通过以下方式导入你的包：

```py
from flask_youtube import Youtube
```

# 使用 Flask 扩展修改响应

因此，我们创建了一个扩展，为我们的模板添加了新的功能。但是，我们如何创建一个修改应用程序在请求级别行为的扩展呢？为了演示这一点，让我们创建一个扩展，它通过压缩响应的内容来修改 Flask 的所有响应。这是 Web 开发中的常见做法，以加快页面加载时间，因为使用像**gzip**这样的方法压缩对象非常快速，而且在 CPU 方面相对便宜。通常，这将在服务器级别处理。因此，除非你希望仅使用 Python 代码托管你的应用程序，这在现实世界中并没有太多用处。

为了实现这一点，我们将使用 Python 标准库中的`gzip`模块来在每个请求处理后压缩内容。我们还需要在响应中添加特殊的 HTTP 头，以便浏览器知道内容已经被压缩。我们还需要在 HTTP 请求头中检查浏览器是否能接受 gzip 压缩的内容。

就像以前一样，我们的内容最初将驻留在`extensions.py`文件中：

```py
from flask import request 
from gzip import GzipFile
from io import BytesIO
…

class GZip(object):
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.after_request(self.after_request)

    def after_request(self, response):
        encoding = request.headers.get('Accept-Encoding', '')

        if 'gzip' not in encoding or \
           not response.status_code in (200, 201):
            return response

        response.direct_passthrough = False

        contents = BytesIO()
        with GzipFile(
            mode='wb',
            compresslevel=5,
            fileobj=contents) as gzip_file:
            gzip_file.write(response.get_data())

        response.set_data(bytes(contents.getvalue()))

        response.headers['Content-Encoding'] = 'gzip'
        response.headers['Content-Length'] = response.content_length

        return response

flask_gzip = GZip()
```

就像以前的扩展一样，我们的压缩对象的初始化器适应了普通的 Flask 设置和应用工厂设置。在`after_request`方法中，我们注册一个新的函数来在请求后事件上注册一个新函数，以便我们的扩展可以压缩结果。

`after_request`方法是扩展的真正逻辑所在。首先，它通过查看请求头中的`Accept-Encoding`值来检查浏览器是否接受 gzip 编码。如果浏览器不接受 gzip，或者没有返回成功的响应，函数将只返回内容并不对其进行任何修改。但是，如果浏览器接受我们的内容并且响应成功，那么我们将压缩内容。我们使用另一个名为`BytesIO`的标准库类，它允许文件流被写入和存储在内存中，而不是在中间文件中。这是必要的，因为`GzipFile`对象期望写入文件对象。

数据压缩后，我们将响应对象的数据设置为压缩的结果，并在响应中设置必要的 HTTP 头值。最后，gzip 内容被返回到浏览器，然后浏览器解压内容，大大加快了页面加载时间。

为了测试浏览器中的功能，您必须禁用**Flask Debug Toolbar**，因为在撰写本文时，其代码中存在一个 bug，它期望所有响应都以 UTF-8 编码。

如果重新加载页面，什么都不应该看起来不同。但是，如果您使用所选浏览器的开发人员工具并检查响应，您将看到它们已经被压缩。

# 摘要

现在我们已经通过了两个不同类型的 Flask 扩展的示例，您应该非常清楚我们使用的大多数 Flask 扩展是如何工作的。利用您现在拥有的知识，您应该能够为您的特定应用程序添加任何额外的 Flask 功能。

在下一章中，我们将看看如何向我们的应用程序添加测试，以消除我们对代码更改是否破坏了应用程序功能的猜测。


# 第十二章：测试 Flask 应用程序

在本书中，每当我们对应用程序的代码进行修改时，我们都必须手动将受影响的网页加载到浏览器中，以测试代码是否正确工作。随着应用程序的增长，这个过程变得越来越繁琐，特别是如果您更改了低级别且在各处都使用的东西，比如 SQLAlchemy 模型代码。

为了自动验证我们的代码是否按预期工作，我们将使用 Python 的内置功能，通常称为单元测试，对我们应用程序的代码进行检查。

# 什么是单元测试？

测试程序非常简单。它只涉及运行程序的特定部分，并说明您期望的结果，并将其与程序片段实际的结果进行比较。如果结果相同，则测试通过。如果结果不同，则测试失败。通常，在将代码提交到 Git 存储库之前以及在将代码部署到实时服务器之前运行这些测试，以确保破损的代码不会进入这两个系统。

在程序测试中，有三种主要类型的测试。单元测试是验证单个代码片段（如函数）正确性的测试。第二种是集成测试，它测试程序中各个单元一起工作的正确性。最后一种测试类型是系统测试，它测试整个系统的正确性，而不是单独的部分。

在本章中，我们将使用单元测试和系统测试来验证我们的代码是否按计划工作。在本章中，我们不会进行集成测试，因为代码中各部分的协同工作方式不是由我们编写的代码处理的。例如，SQLAlchemy 与 Flask 的工作方式不是由我们的代码处理的，而是由 Flask SQLAlchemy 处理的。

这带我们来到代码测试的第一个规则之一。为自己的代码编写测试。这样做的第一个原因是很可能已经为此编写了测试。第二个原因是，您使用的库中的任何错误都将在您想要使用该库的功能时在您的测试中显现出来。

# 测试是如何工作的？

让我们从一个非常简单的 Python 函数开始进行测试。

```py
def square(x):
    return x * x
```

为了验证此代码的正确性，我们传递一个值，并测试函数的结果是否符合我们的期望。例如，我们会给它一个输入为 5，并期望结果为 25。

为了说明这个概念，我们可以在命令行中使用`assert`语句手动测试这个函数。Python 中的`assert`语句简单地表示，如果`assert`关键字后的条件语句返回`False`，则抛出异常如下：

```py
$ python
>>> def square(x): 
...     return x * x
>>> assert square(5) == 25
>>> assert square(7) == 49
>>> assert square(10) == 100
>>> assert square(10) == 0
Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
AssertionError

```

使用这些`assert`语句，我们验证了平方函数是否按预期工作。

# 单元测试应用程序

Python 中的单元测试通过将`assert`语句组合到它们自己的函数中的类中来工作。这个类中的测试函数集合被称为测试用例。测试用例中的每个函数应该只测试一件事，这是单元测试的主要思想。在单元测试中只测试一件事会迫使您逐个验证每个代码片段，而不会忽略代码的任何功能。如果编写单元测试正确，您最终会得到大量的单元测试。虽然这可能看起来过于冗长，但它将为您节省后续的麻烦。

在构建测试用例之前，我们需要另一个配置对象，专门用于设置应用程序进行测试。在这个配置中，我们将使用 Python 标准库中的`tempfile`模块，以便在文件中创建一个测试 SQLite 数据库，当测试结束时会自动删除。这样可以确保测试不会干扰我们的实际数据库。此外，该配置禁用了 WTForms CSRF 检查，以允许我们在测试中提交表单而无需 CSRF 令牌。

```py
import tempfile

class TestConfig(Config):
    db_file = tempfile.NamedTemporaryFile()

    DEBUG = True
    DEBUG_TB_ENABLED = False

    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + db_file.name

    CACHE_TYPE = 'null'
    WTF_CSRF_ENABLED = False

    CELERY_BROKER_URL = "amqp://guest:guest@localhost:5672//"
    CELERY_BACKEND_URL = "amqp://guest:guest@localhost:5672//"

    MAIL_SERVER = 'localhost'
    MAIL_PORT = 25
    MAIL_USERNAME = 'username'
    MAIL_PASSWORD = 'password'
```

## 测试路由功能

让我们构建我们的第一个测试用例。在这个测试用例中，我们将测试如果我们访问它们的 URL，路由函数是否成功返回响应。在项目目录的根目录中创建一个名为`tests`的新目录，然后创建一个名为`test_urls.py`的新文件，该文件将保存所有路由的单元测试。每个测试用例都应该有自己的文件，并且每个测试用例都应该专注于你正在测试的代码的一个区域。

在`test_urls.py`中，让我们开始创建内置的 Python`unittest`库所需的内容。该代码将使用 Python 中的`unittest`库来运行我们在测试用例中创建的所有测试。

```py
import unittest

class TestURLs(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
```

让我们看看当运行这段代码时会发生什么。我们将使用`unittest`库的自动查找测试用例的能力来运行测试。`unittest`库查找的模式是`test*.py`：

```py
$ python -m unittest discover

---------------------------------------------------------------------
Ran 0 tests in 0.000s

OK

```

因为测试用例中没有测试，所以测试用例成功通过。

### 注意

测试脚本是从脚本的父目录而不是测试文件夹本身运行的。这是为了允许在测试脚本中导入应用程序代码。

为了测试 URL，我们需要一种在不实际运行服务器的情况下查询应用程序路由的方法，以便返回我们的请求。Flask 提供了一种在测试中访问路由的方法，称为测试客户端。测试客户端提供了在我们的路由上创建 HTTP 请求的方法，而无需实际运行应用程序的`app.run()`。

在这个测试用例中，我们将需要测试客户端对象，但是在每个`unittest`中添加代码来创建测试客户端并没有太多意义，因为我们有`setUp`方法。`setUp`方法在每个单元测试之前运行，并且可以将变量附加到 self 上，以便测试方法可以访问它们。在我们的`setUp`方法中，我们需要使用我们的`TestConfig`对象创建应用程序对象，并创建测试客户端。

此外，我们需要解决三个问题。前两个在 Flask Admin 和 Flask Restful 扩展中，当应用程序对象被销毁时，它们内部存储的 Blueprint 对象不会被移除。第三，Flask SQLAlchemy 的初始化程序在`webapp`目录之外时无法正确添加应用程序对象：

```py
class TestURLs(unittest.TestCase):
    def setUp(self):
        # Bug workarounds
        admin._views = []
        rest_api.resources = []

        app = create_app('webapp.config.TestConfig')
        self.client = app.test_client()

        # Bug workaround
        db.app = app

        db.create_all()
```

### 注意

在撰写本文时，之前列出的所有错误都存在，但在阅读本章时可能已经不存在。

除了`setUp`方法之外，还有`tearDown`方法，它在每次单元测试结束时运行。`tearDown`方法用于销毁`setUp`方法中创建的任何无法自动垃圾回收的对象。在我们的情况下，我们将使用`tearDown`方法来删除测试数据库中的表，以便每个测试都有一个干净的起点。

```py
class TestURLs(unittest.TestCase):
    def setUp(self):
        …

    def tearDown(self):
        db.session.remove()
        db.drop_all()
```

现在我们可以创建我们的第一个单元测试。第一个测试将测试访问我们应用程序的根目录是否会返回`302 重定向`到博客主页，如下所示：

```py
class TestURLs(unittest.TestCase):
    def setUp(self):
        …

    def tearDown(self):
        …

    def test_root_redirect(self):
        """ Tests if the root URL gives a 302 """

        result = self.client.get('/')
        assert result.status_code == 302
        assert "/blog/" in result.headers['Location']
```

每个单元测试必须以单词`test`开头，以告诉`unittest`库该函数是一个单元测试，而不仅仅是测试用例类中的某个实用函数。

现在，如果我们再次运行测试，我们会看到我们的测试被运行并通过检查：

```py
$ python -m unittest discover
.
---------------------------------------------------------------------
Ran 1 tests in 0.128s

OK

```

编写测试的最佳方法是事先询问自己要寻找什么，编写`assert`语句，并编写执行这些断言所需的代码。这迫使您在开始编写测试之前询问自己真正要测试什么。为每个单元测试编写 Python 文档字符串也是最佳实践，因为每当测试失败时，它将与测试名称一起打印，并且在编写 50 多个测试后，了解测试的确切目的可能会有所帮助。

与使用 Python 的内置`assert`关键字不同，我们可以使用`unittest`库提供的一些方法。当这些函数内部的`assert`语句失败时，这些方法提供了专门的错误消息和调试信息。

以下是`unittest`库提供的所有特殊`assert`语句及其功能列表：

+   `assertEqual(x, y)`: 断言 `x == y`

+   `assertNotEqual(x, y)`: 断言 `x != y`

+   `assertTrue(x)`: 断言 `x` 是 `True`

+   `assertFalse(x)`: 断言 `x` 是 `False`

+   `assertIs(x, y)`: 断言 `x` 是 `y`

+   `assertIsNot(x, y)`: 断言 `x` 不是 `y`

+   `assertIsNone(x)`: 断言 `x` 是 `None`

+   `assertIsNotNone(x)`: 断言 `x` 不是 `None`

+   `assertIn(x, y)`: 断言 `x` 在 `y` 中

+   `assertNotIn(x, y)`: 断言 `x` 不在 `y` 中

+   `assertIsInstance(x, y)`: 断言 `isinstance(x, y)`

+   `assertNotIsInstance(x, y)`: 断言不是 `isinstance(x, y)`

如果我们想测试普通页面的返回值，单元测试将如下所示：

```py
class TestURLs(unittest.TestCase):
    def setUp(self):
        …

    def tearDown(self):
        …

    def test_root_redirect(self):
        …
```

请记住，此代码仅测试 URL 是否成功返回。返回数据的内容不是这些测试的一部分。

如果我们想测试提交登录表单之类的表单，可以使用测试客户端的 post 方法。让我们创建一个`test_login`方法来查看登录表单是否正常工作：

```py
class TestURLs(unittest.TestCase):
    …
    def test_login(self):
        """ Tests if the login form works correctly """

        test_role = Role("default")
        db.session.add(test_role)
        db.session.commit()

        test_user = User("test")
        test_user.set_password("test")
        db.session.add(test_user)
        db.session.commit()

        result = self.client.post('/login', data=dict(
            username='test',
            password="test"
        ), follow_redirects=True)

        self.assertEqual(result.status_code, 200)
        self.assertIn('You have been logged in', result.data)
```

对返回数据中字符串的额外检查是因为返回代码不受输入数据有效性的影响。post 方法将适用于测试本书中创建的任何表单对象。

现在您了解了单元测试的机制，可以使用单元测试来测试应用程序的所有部分。例如，测试应用程序中的所有路由，测试我们制作的任何实用函数，如`sidebar_data`，测试具有特定权限的用户是否可以访问页面等。

如果您的应用程序代码具有任何功能，无论多么小，都应该为其编写测试。为什么？因为任何可能出错的事情都会出错。如果您的应用程序代码的有效性完全依赖于手动测试，那么随着应用程序的增长，某些事情将被忽视。一旦有事情被忽视，就会将错误的代码部署到生产服务器上，这会让您的用户感到恼火。

# 用户界面测试

为了测试应用程序代码的高级别，并创建系统测试，我们将编写与浏览器一起工作的测试，并验证 UI 代码是否正常工作。使用一个名为 Selenium 的工具，我们将创建 Python 代码，纯粹通过代码来控制浏览器。您可以在屏幕上找到元素，然后通过 Selenium 对这些元素执行操作。单击它或输入按键。此外，Selenium 允许您通过访问元素的内容，例如其属性和内部文本，对页面内容执行检查。对于更高级的检查，Selenium 甚至提供了一个接口来在页面上运行任意 JavaScript。如果 JavaScript 返回一个值，它将自动转换为 Python 类型。

在触及代码之前，需要安装 Selenium：

```py
$ pip install selenium

```

要开始编写代码，我们的 UI 测试需要在名为`test_ui.py`的测试目录中拥有自己的文件。因为系统测试不测试特定的事物，编写用户界面测试的最佳方法是将测试视为模拟典型用户流程。在编写测试之前，写下我们的虚拟用户将模拟的具体步骤：

```py
import unittest

class TestURLs(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_add_new_post(self):
        """ Tests if the new post page saves a Post object to the
            database

            1\. Log the user in
            2\. Go to the new_post page
            3\. Fill out the fields and submit the form
            4\. Go to the blog home page and verify that the post 
               is on the page
        """
        pass
```

现在我们知道了我们的测试要做什么，让我们开始添加 Selenium 代码。在`setUp`和`tearDown`方法中，我们需要代码来启动 Selenium 控制的 Web 浏览器，然后在测试结束时关闭它。

```py
import unittest
from selenium import webdriver
class TestURLs(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Firefox()
    def tearDown(self):
        self.driver.close()
```

这段代码生成一个由 Selenium 控制的新的 Firefox 窗口。当然，为了使其工作，你需要在计算机上安装 Firefox。还有其他浏览器的支持，但它们都需要额外的程序才能正常工作。Firefox 在所有浏览器中具有最好的支持。

在编写测试代码之前，让我们按照以下方式探索 Selenium API：

```py
$ python
>>> from selenium import webdriver
>>> driver = webdriver.Firefox()
# load the Google homepage
>>> driver.get("http://www.google.com")
# find a element by its class
>>> search_field = driver.find_element_by_class_name("gsfi")
# find a element by its name
>>> search_field = driver.find_element_by_name("q")
# find an element by its id
>>> search_field = driver.find_element_by_id("lst-ib")
# find an element with JavaScript
>>> search_field = driver.execute_script(
 "return document.querySelector('#lst-ib')"
)
# search for flask
>>> search_field.send_keys("flask")
>>> search_button = driver.find_element_by_name("btnK")
>>> search_button.click()

```

这些是我们将要使用的 Selenium 的主要功能，但还有许多其他方法可以查找和与网页上的元素进行交互。有关可用功能的完整列表，请参阅 Selenium-Python 文档[`selenium-python.readthedocs.org`](http://selenium-python.readthedocs.org)。

在编写测试时，Selenium 中有两个需要牢记的要点，否则你将遇到几乎无法从错误消息中调试的非常奇怪的错误：

1.  Selenium 的设计就像有一个实际的人控制浏览器一样。这意味着如果页面上看不到一个元素，Selenium 就无法与其交互。例如，如果一个元素覆盖了你想点击的另一个元素，比如一个模态窗口在按钮前面，那么按钮就无法被点击。如果元素的 CSS 将其显示设置为`none`或可见性设置为`hidden`，结果将是一样的。

1.  屏幕上指向元素的所有变量都存储为指向浏览器中这些元素的指针，这意味着它们不存储在 Python 的内存中。如果页面在不使用`get`方法的情况下发生更改，比如点击链接并创建新的元素指针时，测试将崩溃。这是因为驱动程序将不断寻找先前页面上的元素，而在新页面上找不到它们。驱动程序的`get`方法清除所有这些引用。

在以前的测试中，我们使用测试客户端来模拟对应用程序对象的请求。然而，因为我们现在使用的是需要直接通过 Web 浏览器与应用程序进行交互的东西，我们需要一个实际运行的服务器。这个服务器需要在用户界面测试运行之前在一个单独的终端窗口中运行，以便它们有东西可以请求。为了做到这一点，我们需要一个单独的 Python 文件来使用我们的测试配置运行服务器，并设置一些模型供我们的 UI 测试使用。在项目目录的根目录下新建一个名为`run_test_server.py`的新文件，添加以下内容：

```py
from webapp import create_app
from webapp.models import db, User, Role

app = create_app('webapp.config.TestConfig')

db.app = app
db.create_all()

default = Role("default")
poster = Role("poster")
db.session.add(default)
db.session.add(poster)
db.session.commit()

test_user = User("test")
test_user.set_password("test")
test_user.roles.append(poster)
db.session.add(test_user)
db.session.commit()

app.run()
```

现在我们既有了测试服务器脚本，又了解了 Selenium 的 API，我们终于可以为我们的测试编写代码了：

```py
class TestURLs(unittest.TestCase):
    def setUp(self):
        …

    def tearDown(self):
        …

    def test_add_new_post(self):
        """ Tests if the new post page saves a Post object to the
            database

            1\. Log the user in
            2\. Go to the new_post page
            3\. Fill out the fields and submit the form
            4\. Go to the blog home page and verify that
               the post is on the page
        """
        # login
        self.driver.get("http://localhost:5000/login")

        username_field = self.driver.find_element_by_name(
            "username"
        )
        username_field.send_keys("test")

        password_field = self.driver.find_element_by_name(
            "password"
        )
        password_field.send_keys("test")

        login_button = self.driver.find_element_by_id(
            "login_button"
        )
        login_button.click()

        # fill out the form
        self.driver.get("http://localhost:5000/blog/new")

        title_field = self.driver.find_element_by_name("title")
        title_field.send_keys("Test Title")

        # find the editor in the iframe
        self.driver.switch_to.frame(
            self.driver.find_element_by_tag_name("iframe")
        )
        post_field = self.driver.find_element_by_class_name(
            "cke_editable"
        )
        post_field.send_keys("Test content")
        self.driver.switch_to.parent_frame()

        post_button = self.driver.find_element_by_class_name(
            "btn-primary"
        )
        post_button.click()

        # verify the post was created
        self.driver.get("http://localhost:5000/blog")
        self.assertIn("Test Title", self.driver.page_source)
        self.assertIn("Test content", self.driver.page_source)
```

这个测试中使用了我们之前介绍的大部分方法。然而，在这个测试中有一个名为`switch_to`的新方法。`switch_to`方法是驱动程序的上下文，允许选择`iframe`元素内的元素。通常情况下，父窗口无法使用 JavaScript 选择`iframe`内的任何元素，但因为我们直接与浏览器进行交互，我们可以访问`iframe`元素的内容。我们需要像这样切换上下文，因为在创建页面内的 WYSIWYG 编辑器中使用`iframe`。在`iframe`内选择元素完成后，我们需要使用`parent_frame`方法切换回父上下文。

现在你已经拥有了测试服务器代码和用户界面代码的测试工具。在本章的其余部分，我们将专注于工具和方法，以使您的测试更加有效，以确保应用程序的正确性。

# 测试覆盖率

现在我们已经编写了测试，我们必须知道我们的代码是否经过了充分的测试。测试覆盖率的概念，也称为代码覆盖率，是为了解决这个问题而发明的。在任何项目中，测试覆盖率表示在运行测试时执行了项目中多少百分比的代码，以及哪些代码行从未运行过。这给出了项目中哪些部分在我们的单元测试中没有被测试的想法。要将覆盖报告添加到我们的项目中，请使用以下命令使用 pip 安装覆盖库：

```py
$ pip install coverage

```

覆盖库可以作为一个命令行程序运行，它将在测试运行时运行您的测试套件并进行测量。

```py
$ coverage run --source webapp --branch -m unittest discover

```

`--source`标志告诉覆盖仅报告`webapp`目录中文件的覆盖率。如果不包括这个标志，那么应用程序中使用的所有库的百分比也将被包括在内。默认情况下，如果执行了`if`语句中的任何代码，就会说整个`if`语句已经执行。`--branch`标志告诉`coverage`禁用这一点，并测量所有内容。

在`coverage`运行我们的测试并进行测量后，我们可以以两种方式查看其发现的报告。第一种是在命令行上查看每个文件的覆盖百分比：

```py
$ coverage report
Name                               Stmts   Miss Branch BrMiss  Cover
--------------------------------------------------------------------
webapp/__init__                       51      0      6      0   100%
webapp/config                         37      0      0      0   100%
webapp/controllers/__init__            0      0      0      0   100%
webapp/controllers/admin              27      4      0      0    85%
webapp/controllers/blog               77     45      8      8    38%
webapp/controllers/main               78     42     20     16    41%
webapp/controllers/rest/__init__       0      0      0      0   100%
webapp/controllers/rest/auth          13      6      2      2    47%
webapp/controllers/rest/fields        17      8      0      0    53%
webapp/controllers/rest/parsers       19      0      0      0   100%
webapp/controllers/rest/post          85     71     44     43    12%
webapp/extensions                     56     14      4      4    70%
webapp/forms                          48     15     10      7    62%
webapp/models                         89     21      4      3    74%
webapp/tasks                          41     29      4      4    27%
--------------------------------------------------------------------
TOTAL                                638    255    102     87    54%

```

第二种是使用覆盖的 HTML 生成功能在浏览器中查看每个文件的详细信息。

```py
$ coverage html

```

上述命令创建了一个名为`htmlcov`的目录。当在浏览器中打开`index.html`文件时，可以单击每个文件名以显示测试期间运行和未运行的代码行的详细情况。

![测试覆盖率](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_12_01.jpg)

在上面的截图中，打开了`blog.py`文件，覆盖报告清楚地显示了帖子路由从未执行过。然而，这也会产生一些错误的负面影响。由于用户界面测试未测试覆盖程序运行的代码，因此它不计入我们的覆盖报告。为了解决这个问题，只需确保测试用例中有测试，测试每个单独的函数，这些函数在用户界面测试中应该被测试。

在大多数项目中，目标百分比约为 90%的代码覆盖率。很少有项目的 100%代码是可测试的，随着项目规模的增加，这种可能性会减少。

# 测试驱动开发

现在我们已经编写了测试，它们如何融入开发过程？目前，我们正在使用测试来确保在创建某些功能后代码的正确性。但是，如果我们改变顺序，使用测试来从一开始就创建正确的代码呢？这就是**测试驱动开发**（**TDD**）的主张。

TDD 遵循一个简单的循环来编写应用程序中新功能的代码：

![测试驱动开发](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_12_02.jpg)

此图像的来源是维基百科上的用户 Excirial

在使用 TDD 的项目中，你在实际构建任何控制你实际构建的代码之前，编写的第一件事是测试。这迫使项目中的程序员在编写任何代码之前规划项目的范围、设计和要求。在设计 API 时，它还迫使程序员从消费者的角度设计 API 的接口，而不是在编写所有后端代码之后设计接口。

在 TDD 中，测试旨在第一次运行时失败。TDD 中有一句话，如果你的测试第一次运行时没有失败，那么你实际上并没有测试任何东西。这意味着你很可能在编写测试之后测试被测试单元给出的结果，而不是应该给出的结果。

在第一次测试失败后，您不断编写代码，直到所有测试通过。对于每个新功能，这个过程都会重复。

一旦所有原始测试通过并且代码被清理干净，TDD 告诉你停止编写代码。通过仅在测试通过时编写代码，TDD 还强制执行“你不会需要它”（YAGNI）哲学，该哲学规定程序员只应实现他们实际需要的功能，而不是他们认为他们将需要的功能。在开发过程中，当程序员试图在没有人需要的情况下预先添加功能时，会浪费大量的精力。

例如，在我参与的一个 PHP 项目中，我发现了以下代码，用于在目录中查找图像：

```py
$images = glob(
    $img_directory . "{*.jpg, *.jpeg, *.gif, *.png, *.PNG, *.Png, *.PnG, *.pNG, *.pnG, *.pNg, *.PNg}",
    GLOB_BRACE
);
```

在 PHP 中，glob 是一个函数，它查找目录中的内容，以找到与模式匹配的文件。我质问了编写它的程序员。他对`.png`扩展名的不同版本的解释是，某个用户上传了一个带有`.PNG`扩展名的文件，而函数没有找到它，因为它只寻找扩展名的小写版本。他试图解决一个不存在的问题，以确保他不必再次触及这段代码，我们可能会觉得浪费了一点时间，但这段代码是整个代码库的缩影。如果这个项目遵循 TDD，就会为大写文件扩展名添加一个测试用例，添加代码以通过测试，然后问题就解决了。

TDD 还提倡“保持简单，愚蠢”（KISS）的理念，这个理念规定从一开始就应该把简单作为设计目标。TDD 提倡 KISS，因为它需要小的、可测试的代码单元，这些单元可以相互分离，不依赖于共享的全局状态。

此外，在遵循 TDD 的项目中，测试始终保持最新的文档。编程的一个公理是，对于任何足够大的程序，文档总是过时的。这是因为当程序员在更改代码时，文档是最后考虑的事情之一。然而，通过测试，项目中的每个功能都有清晰的示例（如果项目的代码覆盖率很高）。测试一直在更新，因此展示了程序的功能和 API 应该如何工作的良好示例。

现在你已经了解了 Flask 的功能以及如何为 Flask 编写测试，你在 Flask 中创建的下一个项目可以完全使用 TDD。

# 总结

现在你已经了解了测试以及它对你的应用程序能做什么，你可以创建保证不会有太多错误的应用程序。你将花更少的时间修复错误，更多的时间添加用户请求的功能。

在下一章中，我们将通过讨论在服务器上将应用程序部署到生产环境的方式来完成这本书。

作为对读者的最后挑战，在进入下一章之前，尝试将你的代码覆盖率提高到 95%以上。


# 第十三章：部署 Flask 应用程序

现在我们已经到达了书的最后一章，并且在 Flask 中制作了一个完全功能的 Web 应用程序，我们开发的最后一步是使该应用程序对外开放。有许多不同的方法来托管您的 Flask 应用程序，每种方法都有其优缺点。本章将介绍最佳解决方案，并指导您在何种情况下选择其中一种。

请注意，在本章中，术语服务器用于指代运行操作系统的物理机器。但是，当使用术语 Web 服务器时，它指的是服务器上接收 HTTP 请求并发送响应的程序。

# 在您自己的服务器上部署

部署任何 Web 应用程序的最常见方法是在您可以控制的服务器上运行它。在这种情况下，控制意味着可以使用管理员帐户访问服务器上的终端。与其他选择相比，这种部署方式为您提供了最大的自由度，因为它允许您安装任何程序或工具。这与其他托管解决方案相反，其中 Web 服务器和数据库是为您选择的。这种部署方式也恰好是最便宜的选择。

这种自由的缺点是您需要负责保持服务器运行，备份用户数据，保持服务器上的软件最新以避免安全问题等。关于良好的服务器管理已经写了很多书。因此，如果您认为您或您的公司无法承担这种责任，最好选择其他部署选项之一。

本节将基于基于 Debian Linux 的服务器，因为 Linux 是远远最受欢迎的运行 Web 服务器的操作系统，而 Debian 是最受欢迎的 Linux 发行版（一种特定的软件和 Linux 内核的组合，作为一个软件包发布）。任何具有 bash 和名为 SSH 的程序（将在下一节介绍）的操作系统都适用于本章。唯一的区别将是安装服务器上软件的命令行程序。

这些 Web 服务器将使用名为**Web 服务器网关接口**（**WSGI**）的协议，这是一种旨在允许 Python Web 应用程序与 Web 服务器轻松通信的标准。我们永远不会直接使用 WSGI，但我们将使用的大多数 Web 服务器接口都将在其名称中包含 WSGI，如果您不知道它是什么，可能会感到困惑。

## 使用 fabric 将代码推送到您的服务器

为了自动化设置和将应用程序代码推送到服务器的过程，我们将使用一个名为 fabric 的 Python 工具。Fabric 是一个命令行程序，它使用名为 SSH 的工具在远程服务器上读取和执行 Python 脚本。SSH 是一种协议，允许一台计算机的用户远程登录到另一台计算机并在命令行上执行命令，前提是用户在远程机器上有一个帐户。

要安装`fabric`，我们将使用`pip`如下：

```py
$ pip install fabric

```

`fabric`命令是一组命令行程序，将在远程机器的 shell 上运行，本例中为 bash。我们将创建三个不同的命令：一个用于运行单元测试，一个用于根据我们的规格设置全新的服务器，一个用于让服务器使用`git`更新其应用程序代码的副本。我们将把这些命令存储在项目目录根目录下的一个名为`fabfile.py`的新文件中。

因为它是最容易创建的，让我们首先创建测试命令：

```py
from fabric.api import local

def test():
    local('python -m unittest discover')
```

要从命令行运行此函数，我们可以使用`fabric`命令行界面，通过传递要运行的命令的名称来运行：

```py
$ fab test
[localhost] local: python -m unittest discover
.....
---------------------------------------------------------------------
Ran 5 tests in 6.028s
OK

```

Fabric 有三个主要命令：`local`，`run`和`sudo`。`local`函数在前面的函数中可见，`run`在本地计算机上运行命令。`run`和`sudo`函数在远程计算机上运行命令，但`sudo`以管理员身份运行命令。所有这些函数都会通知 fabric 命令是否成功运行。如果命令未成功运行，这意味着在这种情况下我们的测试失败，函数中的任何其他命令都不会运行。这对我们的命令很有用，因为它允许我们强制自己不要将任何未通过测试的代码推送到服务器。

现在我们需要创建一个命令来从头开始设置新服务器。这个命令将安装我们的生产环境需要的软件，并从我们的集中式`git`存储库下载代码。它还将创建一个新用户，该用户将充当 web 服务器的运行者以及代码存储库的所有者。

### 注意

不要使用 root 用户运行您的 web 服务器或部署您的代码。这会使您的应用程序面临各种安全漏洞。

这个命令将根据您的操作系统而有所不同，我们将根据您选择的服务器在本章的其余部分中添加这个命令：

```py
from fabric.api import env, local, run, sudo, cd

env.hosts = ['deploy@[your IP]']

def upgrade_libs():
    sudo("apt-get update")
    sudo("apt-get upgrade")

def setup():
    test()
    upgrade_libs()

    # necessary to install many Python libraries 
    sudo("apt-get install -y build-essential")
    sudo("apt-get install -y git")
    sudo("apt-get install -y python")
    sudo("apt-get install -y python-pip")
    # necessary to install many Python libraries
    sudo("apt-get install -y python-all-dev")

    run("useradd -d /home/deploy/ deploy")
    run("gpasswd -a deploy sudo")

    # allows Python packages to be installed by the deploy user
    sudo("chown -R deploy /usr/local/")
    sudo("chown -R deploy /usr/lib/python2.7/")

    run("git config --global credential.helper store")

    with cd("/home/deploy/"):
        run("git clone [your repo URL]")

    with cd('/home/deploy/webapp'):
        run("pip install -r requirements.txt")
        run("python manage.py createdb")
```

此脚本中有两个新的 fabric 功能。第一个是`env.hosts`赋值，它告诉 fabric 应该登录到的机器的用户和 IP 地址。其次，有与关键字一起使用的`cd`函数，它在该目录的上下文中执行任何函数，而不是在部署用户的主目录中。修改`git`配置的行是为了告诉`git`记住存储库的用户名和密码，这样您就不必每次希望将代码推送到服务器时都输入它。此外，在设置服务器之前，我们确保更新服务器的软件以保持服务器的最新状态。

最后，我们有一个将新代码推送到服务器的功能。随着时间的推移，这个命令还将重新启动 web 服务器并重新加载来自我们代码的任何配置文件。但这取决于您选择的服务器，因此这将在后续部分中填写。

```py
def deploy():
    test()
    upgrade_libs()
    with cd('/home/deploy/webapp'):
        run("git pull")
        run("pip install -r requirements.txt")
```

因此，如果我们要开始在新服务器上工作，我们只需要运行以下命令：

```py
$ fabric setup
$ fabric deploy
```

## 使用 supervisor 运行您的 web 服务器

现在我们已经自动化了更新过程，我们需要服务器上的一些程序来确保我们的 web 服务器以及如果您没有使用 SQLite 的话数据库正在运行。为此，我们将使用一个名为 supervisor 的简单程序。supervisor 的所有功能都是自动在后台进程中运行命令行程序，并允许您查看正在运行的程序的状态。Supervisor 还监视其正在运行的所有进程，如果进程死掉，它会尝试重新启动它。

要安装`supervisor`，我们需要将其添加到`fabfile.py`中的设置命令中：

```py
def setup():
    …
    sudo("apt-get install -y supervisor")
```

告诉`supervisor`要做什么，我们需要创建一个配置文件，然后在部署`fabric`命令期间将其复制到服务器的`/etc/supervisor/conf.d/`目录中。当`supervisor`启动并尝试运行时，它将加载此目录中的所有文件。

在项目目录的根目录中新建一个名为`supervisor.conf`的文件，添加以下内容：

```py
[program:webapp]
command=
directory=/home/deploy/webapp
user=deploy

[program:rabbitmq]
command=rabbitmq-server
user=deploy

[program:celery]
command=celery worker -A celery_runner 
directory=/home/deploy/webapp
user=deploy
```

### 注意

这是使 web 服务器运行所需的最低配置。但是，supervisor 还有很多配置选项。要查看所有自定义内容，请访问 supervisor 文档[`supervisord.org/`](http://supervisord.org/)。

此配置告诉`supervisor`在`deploy`用户的上下文中运行命令`/home/deploy/webapp`。命令值的右侧为空，因为它取决于您正在运行的服务器，并将填充到每个部分中。

现在我们需要在部署命令中添加一个`sudo`调用，将此配置文件复制到`/etc/supervisor/conf.d/`目录中，如下所示。

```py
def deploy():
    …
    with cd('/home/deploy/webapp'):
        …
        sudo("cp supervisord.conf /etc/supervisor/conf.d/webapp.conf")

    sudo('service supervisor restart')
```

许多项目只是在服务器上创建文件然后忘记它们，但是将配置文件存储在我们的`git`存储库中，并在每次部署时复制它们具有几个优点。首先，这意味着如果出现问题，可以使用`git`轻松恢复更改。其次，这意味着我们不必登录服务器即可对文件进行更改。

### 注意

不要在生产中使用 Flask 开发服务器。它不仅无法处理并发连接，还允许在服务器上运行任意 Python 代码。

## Gevent

让 Web 服务器运行起来的最简单的选择是使用一个名为 gevent 的 Python 库来托管您的应用程序。Gevent 是一个 Python 库，它提供了一种在 Python 线程库之外进行并发编程的替代方式，称为**协程**。Gevent 具有一个接口来运行简单且性能良好的 WSGI 应用程序。一个简单的 gevent 服务器可以轻松处理数百个并发用户，这比互联网上网站的用户数量多 99%。这种选择的缺点是它的简单性意味着缺乏配置选项。例如，无法向服务器添加速率限制或添加 HTTPS 流量。这种部署选项纯粹是为了那些您不希望接收大量流量的网站。记住 YAGNI；只有在真正需要时才升级到不同的 Web 服务器。

### 注意

协程有点超出了本书的范围，因此可以在[`en.wikipedia.org/wiki/Coroutine`](https://en.wikipedia.org/wiki/Coroutine)找到一个很好的解释。

要安装`gevent`，我们将使用`pip`：

```py
$ pip install gevent

```

在项目目录的根目录中新建一个名为`gserver.py`的文件，添加以下内容：

```py
from gevent.wsgi import WSGIServer
from webapp import create_app

app = create_app('webapp.config.ProdConfig')

server = WSGIServer(('', 80), app)
server.serve_forever()
```

要在 supervisor 中运行服务器，只需将命令值更改为以下内容：

```py
[program:webapp]
command=python gserver.py 
directory=/home/deploy/webapp
user=deploy

```

现在，当您部署时，`gevent`将通过在每次添加新依赖项后适当地 pip 冻结来自动安装，也就是说，如果您在每次添加新依赖项后都进行 pip 冻结。

## Tornado

Tornado 是部署 WSGI 应用程序的另一种非常简单的纯 Python 方式。Tornado 是一个设计用来处理成千上万个同时连接的 Web 服务器。如果您的应用程序需要实时数据，Tornado 还支持 WebSockets，以实现与服务器的持续、长期的连接。

### 注意

不要在 Windows 服务器上生产使用 Tornado。Tornado 的 Windows 版本不仅速度慢得多，而且被认为是质量不佳的测试版软件。

为了将 Tornado 与我们的应用程序一起使用，我们将使用 Tornado 的`WSGIContainer`来包装应用程序对象，使其与 Tornado 兼容。然后，Tornado 将开始监听端口*80*的请求，直到进程终止。在一个名为`tserver.py`的新文件中，添加以下内容：

```py
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from webapp import create_app
app = WSGIContainer(create_app("webapp.config.ProdConfig"))
http_server = HTTPServer(app)
http_server.listen(80)
IOLoop.instance().start()
```

要在 supervisor 中运行 Tornado，只需将命令值更改为以下内容：

```py
[program:webapp]
command=python tserver.py 
directory=/home/deploy/webapp
user=deploy
```

## Nginx 和 uWSGI

如果您需要更高的性能或自定义，部署 Python Web 应用程序的最流行方式是使用 Web 服务器 Nginx 作为 WSGI 服务器 uWSGI 的前端，通过使用反向代理。反向代理是网络中的一个程序，它从服务器检索内容，就好像它们是从代理服务器返回的一样：

![Nginx 和 uWSGI](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_01.jpg)

Nginx 和 uWSGI 是以这种方式使用的，因为我们既可以获得 Nginx 前端的强大功能，又可以拥有 uWSGI 的自定义功能。

Nginx 是一个非常强大的 Web 服务器，通过提供速度和定制性的最佳组合而变得流行。Nginx 始终比其他 Web 服务器（如 Apache httpd）更快，并且原生支持 WSGI 应用程序。它实现这种速度的方式是通过几个良好的架构决策，以及早期决定他们不打算像 Apache 那样覆盖大量用例。功能集较小使得维护和优化代码变得更加容易。从程序员的角度来看，配置 Nginx 也更容易，因为没有一个需要在每个项目目录中用`.htaccess`文件覆盖的巨大默认配置文件（`httpd.conf`）。

其中一个缺点是 Nginx 的社区比 Apache 要小得多，因此如果遇到问题，您可能不太可能在网上找到答案。此外，有可能在 Nginx 中不支持大多数程序员在 Apache 中习惯的功能。

uWSGI 是一个支持多种不同类型的服务器接口（包括 WSGI）的 Web 服务器。uWSGI 处理应用程序内容以及诸如负载平衡流量等事项。

要安装 uWSGI，我们将使用`pip`。

```py
$ pip install uwsgi

```

为了运行我们的应用程序，uWSGI 需要一个包含可访问的 WSGI 应用程序的文件。在项目目录的顶层中创建一个名为`wsgi.py`的新文件，添加以下内容：

```py
from webapp import create_app

app = create_app("webapp.config.ProdConfig")
```

为了测试 uWSGI，我们可以使用以下命令从命令行运行它：

```py
$ uwsgi --socket 127.0.0.1:8080 \
--wsgi-file wsgi.py \
--callable app \
--processes 4 \
--threads 2

```

如果您在服务器上运行此操作，您应该能够访问*8080*端口并查看您的应用程序（如果您没有防火墙的话）。

这个命令的作用是从`wsgi.py`文件中加载 app 对象，并使其可以从*8080*端口的`localhost`访问。它还生成了四个不同的进程，每个进程有两个线程，这些进程由一个主进程自动进行负载平衡。对于绝大多数网站来说，这个进程数量是过剩的。首先，使用一个进程和两个线程，然后逐步扩展。

我们可以创建一个文本文件来保存配置，而不是在命令行上添加所有配置选项，这样可以带来与在 supervisor 部分列出的配置相同的好处。

在项目目录的根目录中的一个名为`uwsgi.ini`的新文件中添加以下代码：

```py
[uwsgi]
socket = 127.0.0.1:8080
wsgi-file = wsgi.py
callable = app
processes = 4
threads = 2
```

### 注意

uWSGI 支持数百种配置选项，以及几个官方和非官方的插件。要充分利用 uWSGI 的功能，您可以在[`uwsgi-docs.readthedocs.org/`](http://uwsgi-docs.readthedocs.org/)上查阅文档。

现在让我们从 supervisor 运行服务器：

```py
[program:webapp]
command=uwsgi uwsgi.ini
directory=/home/deploy/webapp
user=deploy
```

我们还需要在设置函数中安装 Nginx：

```py
def setup():
    …
    sudo("apt-get install -y nginx")
```

因为我们是从操作系统的软件包管理器中安装 Nginx，所以操作系统会为我们处理 Nginx 的运行。

### 注意

在撰写本文时，官方 Debian 软件包管理器中的 Nginx 版本已经过时数年。要安装最新版本，请按照这里的说明进行操作：[`wiki.nginx.org/Install`](http://wiki.nginx.org/Install)。

接下来，我们需要创建一个 Nginx 配置文件，然后在推送代码时将其复制到`/etc/nginx/sites-available/`目录中。在项目目录的根目录中的一个名为`nginx.conf`的新文件中添加以下内容：

```py
server {
    listen 80;
    server_name your_domain_name;

    location / {
        include uwsgi_params;
        uwsgi_pass 127.0.0.1:8080;
    }

    location /static {
        alias /home/deploy/webapp/webapp/static;
    }
}
```

这个配置文件的作用是告诉 Nginx 在*80*端口监听传入请求，并将所有请求转发到在*8080*端口监听的 WSGI 应用程序。此外，它对静态文件的任何请求进行了例外处理，并直接将这些请求发送到文件系统。绕过 uWSGI 处理静态文件可以大大提高性能，因为 Nginx 在快速提供静态文件方面非常出色。

最后，在`fabfile.py`文件中：

```py
def deploy():
    …
    with cd('/home/deploy/webapp'):
        …
        sudo("cp nginx.conf "
             "/etc/nginx/sites-available/[your_domain]")
        sudo("ln -sf /etc/nginx/sites-available/your_domain "
             "/etc/nginx/sites-enabled/[your_domain]") 

    sudo("service nginx restart")
```

## Apache 和 uWSGI

使用 Apache httpd 与 uWSGI 基本上具有相同的设置。首先，我们需要在项目目录的根目录中的一个名为`apache.conf`的新文件中创建一个 apache 配置文件：

```py
<VirtualHost *:80>
    <Location />
        ProxyPass / uwsgi://127.0.0.1:8080/
    </Location>
</VirtualHost>
```

这个文件只是告诉 Apache 将所有端口为*80*的请求传递到端口为*8080*的 uWSGI Web 服务器。但是，此功能需要来自 uWSGI 的额外 Apache 插件，名为`mod-proxy-uwsgi`。我们可以在 set 命令中安装这个插件以及 Apache：

```py
def setup():

    sudo("apt-get install -y apache2")
    sudo("apt-get install -y libapache2-mod-proxy-uwsgi")
```

最后，在`deploy`命令中，我们需要将我们的 Apache 配置文件复制到 Apache 的配置目录中：

```py
def deploy():
    …
    with cd('/home/deploy/webapp'):
        …
        sudo("cp apache.conf "
             "/etc/apache2/sites-available/[your_domain]")
        sudo("ln -sf /etc/apache2/sites-available/[your_domain] "
             "/etc/apache2/sites-enabled/[your_domain]") 

    sudo("service apache2 restart")
```

# 在 Heroku 上部署

Heroku 是本章将要介绍的**平台即服务**（**PaaS**）提供商中的第一个。PaaS 是提供给 Web 开发人员的一项服务，允许他们在由他人控制和维护的平台上托管他们的网站。以牺牲自由为代价，您可以确保您的网站将随着用户数量的增加而自动扩展，而无需您额外的工作。使用 PaaS 通常也比运行自己的服务器更昂贵。

Heroku 是一种旨在对 Web 开发人员易于使用的 PaaS，它通过连接已经存在的工具并不需要应用程序中的任何大更改来工作。Heroku 通过读取名为`Procfile`的文件来工作，该文件包含您的 Heroku dyno 基本上是一个坐落在服务器上的虚拟机将运行的命令。在开始之前，您将需要一个 Heroku 帐户。如果您只是想进行实验，可以使用免费帐户。

在目录的根目录中新建一个名为`Procfile`的文件，添加以下内容：

```py
web: uwsgi uwsgi.ini 
```

这告诉 Heroku 我们有一个名为 web 的进程，它将运行 uWSGI 命令并传递`uwsgi.ini`文件。Heroku 还需要一个名为`runtime.txt`的文件，它将告诉它您希望使用哪个 Python 运行时（在撰写本文时，最新的 Python 版本是 2.7.10）：

```py
python-2.7.10
```

最后，我们需要对之前创建的`uwsgi.ini`文件进行一些修改：

```py
[uwsgi]
http-socket = :$(PORT)
die-on-term = true
wsgi-file = wsgi.py
callable = app
processes = 4
threads = 2
```

我们将端口设置为 uWSGI 监听环境变量端口，因为 Heroku 不直接将 dyno 暴露给互联网。相反，它有一个非常复杂的负载均衡器和反向代理系统，因此我们需要让 uWSGI 监听 Heroku 需要我们监听的端口。此外，我们将**die-on-term**设置为 true，以便 uWSGI 正确监听来自操作系统的终止信号事件。

要使用 Heroku 的命令行工具，我们首先需要安装它们，可以从[`toolbelt.heroku.com`](https://toolbelt.heroku.com)完成。

接下来，您需要登录到您的帐户：

```py
$ heroku login

```

我们可以使用 foreman 命令测试我们的设置，以确保它在 Heroku 上运行之前可以正常工作：

```py
$ foreman start web

```

Foreman 命令模拟了 Heroku 用于运行我们的应用的相同生产环境。要创建将在 Heroku 服务器上运行应用程序的 dyno，我们将使用`create`命令。然后，我们可以推送到`git`存储库上的远程分支 Heroku，以便 Heroku 服务器自动拉取我们的更改。

```py
$ heroku create
$ git push heroku master

```

如果一切顺利，您应该在新的 Heroku dyno 上拥有一个可工作的应用程序。您可以使用以下命令在新的标签页中打开新的 Web 应用程序：

```py
$ heroku open

```

要查看 Heroku 部署中的应用程序运行情况，请访问[`mastering-flask.herokuapp.com/`](https://mastering-flask.herokuapp.com/)。

## 使用 Heroku Postgres

正确地维护数据库是一项全职工作。幸运的是，我们可以利用 Heroku 内置的功能之一来自动化这个过程。Heroku Postgres 是由 Heroku 完全维护和托管的 Postgres 数据库。因为我们正在使用 SQLAlchemy，所以使用 Heroku Postgres 非常简单。在您的 dyno 仪表板上，有一个指向**Heroku Postgres**信息的链接。点击它，您将被带到一个页面，就像这里显示的页面一样：

![使用 Heroku Postgres](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_02.jpg)

点击**URL**字段，您将获得一个 SQLAlchemy URL，您可以直接复制到生产配置对象中。

## 在 Heroku 上使用 Celery

我们已经设置了生产 Web 服务器和数据库，但我们仍然需要设置 Celery。使用 Heroku 的许多插件之一，我们可以在云中托管 RabbitMQ 实例，同时在 dyno 上运行 Celery worker。

第一步是告诉 Heroku 在`Procfile`中运行您的 celery worker：

```py
web: uwsgi uwsgi.ini
celery: celery worker -A celery_runner
```

接下来，要安装 Heroku RabbitMQ 插件并使用免费计划（名为`lemur`计划），请使用以下命令：

```py
$  heroku addons:create cloudamqp:lemur

```

### 注意

要获取 Heroku 插件的完整列表，请转到[`elements.heroku.com/addons`](https://elements.heroku.com/addons)。

在 Heroku Postgres 列出的仪表板上的相同位置，您现在将找到**CloudAMQP**：

![在 Heroku 上使用 Celery](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_03.jpg)

点击它还会给您一个可复制的 URL 屏幕，您可以将其粘贴到生产配置中：

![在 Heroku 上使用 Celery](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_04.jpg)

# 在亚马逊网络服务上部署

**亚马逊网络服务**（**AWS**）是由亚马逊维护的一组应用程序平台，构建在运行[amazon.com](http://amazon.com)的相同基础设施之上。为了部署我们的 Flask 代码，我们将使用亚马逊弹性 Beanstalk，而数据库将托管在亚马逊关系数据库服务上，我们的 Celery 消息队列将托管在亚马逊简单队列服务上。

## 在亚马逊弹性 Beanstalk 上使用 Flask

Elastic Beanstalk 是一个为 Web 应用程序提供许多强大功能的平台，因此 Web 开发人员无需担心维护服务器。

例如，您的 Elastic Beanstalk 应用程序将通过利用更多服务器自动扩展，因为同时使用您的应用程序的人数增加。对于 Python 应用程序，Elastic Beanstalk 使用 Apache 与`mod_wsgi`结合连接到 WSGI 应用程序，因此不需要额外的配置。

在我们开始之前，您将需要一个[Amazon.com](http://Amazon.com)账户并登录[`aws.amazon.com/elasticbeanstalk`](http://aws.amazon.com/elasticbeanstalk)。登录后，您将看到如下图所示的屏幕：

![在亚马逊弹性 Beanstalk 上使用 Flask](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_05.jpg)

点击下拉菜单选择 Python，如果您的应用程序需要特定的 Python 版本，请务必点击**更改平台版本**并选择您需要的 Python 版本。您将通过设置过程，并最终您的应用程序将在亚马逊的服务器上进行初始化过程。在此期间，我们可以安装 Elastic Beanstalk 命令行工具。这些工具将允许我们自动部署应用程序的新版本。要安装它们，请使用`pip`：

```py
$ pip install awsebcli

```

在我们部署应用程序之前，您将需要一个 AWS Id 和访问密钥。要做到这一点，请点击显示在页面顶部的用户名的下拉菜单，然后点击**安全凭据**。

![在亚马逊弹性 Beanstalk 上使用 Flask](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_06.jpg)

然后，点击灰色框，上面写着**访问密钥**以获取您的 ID 和密钥对：

![在亚马逊弹性 Beanstalk 上使用 Flask](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_07.jpg)

一旦您拥有密钥对，请不要与任何人分享，因为这将使任何人都能完全控制您在 AWS 上的所有平台实例。现在我们可以设置命令行工具。在您的项目目录中，运行以下命令：

```py
$ eb init

```

选择您之前创建的应用程序，将此目录与该应用程序绑定。我们可以通过运行以下命令来查看应用程序实例上正在运行的内容：

```py
$ eb open

```

现在，您应该只看到一个占位应用程序。让我们通过部署我们的应用程序来改变这一点。Elastic Beanstalk 在您的项目目录中寻找名为`application.py`的文件，并且它期望在该文件中有一个名为 application 的 WSGI 应用程序，因此现在让我们创建该文件：

```py
from webapp import create_app
application = create_app("webapp.config.ProdConfig")
```

创建了该文件后，我们最终可以部署应用程序：

```py
$ eb deploy

```

这是在 AWS 上运行 Flask 所需的。要查看该书的应用程序在 Elastic Beanstalk 上运行，请转到[`masteringflask.elasticbeanstalk.com`](http://masteringflask.elasticbeanstalk.com)。

## 使用亚马逊关系数据库服务

亚马逊关系数据库服务是一个在云中自动管理多个方面的数据库托管平台，例如节点故障时的恢复以及在不同位置保持多个节点同步。

要使用 RDS，转到服务选项卡，然后单击关系数据库服务。要创建数据库，请单击**开始**，然后按照简单的设置过程进行操作。

一旦您的数据库已配置并创建，您可以使用 RDS 仪表板上列出的**端点**变量以及数据库名称和密码来在生产配置对象中创建 SQLAlchemy URL：

![使用亚马逊关系数据库服务](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_08.jpg)

这就是在云上使用 Flask 创建一个非常弹性的数据库所需的全部步骤！

## 使用 Celery 与亚马逊简单队列服务

为了在 AWS 上使用 Celery，我们需要让 Elastic Beanstalk 实例在后台运行我们的 Celery worker，并设置**简单队列服务**（**SQS**）消息队列。为了让 Celery 支持 SQS，它需要从`pip`安装一个辅助库：

```py
$ pip install boto

```

在 SQS 上设置一个新的消息队列非常容易。转到服务选项卡，然后单击应用程序选项卡中的**简单队列服务**，然后单击**创建新队列**。在一个非常简短的配置屏幕之后，您应该看到一个类似以下的屏幕：

![使用 Celery 与亚马逊简单队列服务](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-flask/img/B03929_13_09.jpg)

现在我们必须将`CELERY_BROKER_URL`和`CELERY_BACKEND_URL`更改为新的 URL，其格式如下：

```py
sqs://aws_access_key_id:aws_secret_access_key@
```

这使用了您在 Elastic Beanstalk 部分创建的密钥对。

最后，我们需要告诉 Elastic Beanstalk 在后台运行 Celery worker。我们可以在项目根目录下的一个新目录中的`.ebextensions`文件夹中使用`.conf`文件来完成这个操作（注意文件夹名称开头的句点）。在这个新目录中的一个文件中，可以随意命名，添加以下命令：

```py
  celery_start: 
    command: celery multi start worker1 -A celery_runner
```

现在每当实例重新启动时，此命令将在服务器运行之前运行。

# 总结

正如本章所解释的，托管应用程序有许多不同的选项，每种选项都有其优缺点。选择一个取决于您愿意花费的时间和金钱以及您预期的用户总数。

现在我们已经到达了本书的结尾。我希望这本书对您理解 Flask 以及如何使用它轻松创建任何复杂度的应用程序并进行简单维护有所帮助。
