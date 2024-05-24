# Flask 框架秘籍（三）

> 译者：[Liusple](https://blog.csdn.net/Liusple)
> 
> 来源：<https://blog.csdn.net/liusple/category_7379896.html>

# 第十章：调试，错误处理和测试

直到现在，我们一直专注于应用开发，并且一次只增加一个特性。了解我们的应用程序的健壮程度并跟踪应用程序的工作和执行情况是非常重要的。这反过来又导致了在应用程序出现问题时被通知的必要性。开发应用程序时漏掉某些边缘情况是正常的，通常情况下，即使是测试用例也会遗漏它们。了解这些边缘情况是有必要的，当他们真正发生时，可以相应的进行处理。
测试本身是一个非常大的话题，有很多书在讲述它。这里我们尝试理解 Flask 测试的基本知识。

这一章，我们将包含下面小节：

*   设置基本 logging 文件
*   错误发生时发送邮件
*   使用 Sentry 监测异常
*   使用 pdb 调试
*   创建第一个简单测试
*   为视图和逻辑编写更多的测试
*   Nose 库集成
*   使用 mocking 避免真实 API 访问
*   确定测试覆盖率
*   使用 profiling 寻找瓶颈

## 介绍

高效的日志功能和快速调试能力是选择应用开发框架时需要考虑的因素。框架拥有越好的日志和调试能力，应用开发就会变得更快，维护也会更容易。它有助于帮助开发者快速找出应用里的问题，有时日志可以在终端用户发现问题前提前发现问题。高效的错误处理在增加用户满意度方面和减轻开发者调试痛苦方面都扮演着重要的角色。即使代码是完美的，应用有时也会报错。为什么？答案是显而易见的，虽然代码是完美的，但是这个世界并不是。有数不清的情况会发生，作为开发者，我们总是想知道背后的原因。编写应用测试是编写优秀软件的重要支柱之一。
Python 自带的日志调试系统在 Flask 下也可以很好的工作。我们这一章将使用这个日志调试系统，之后去使用一个炫酷的服务叫做 Sentry，它极大程度上减少了调试日志的痛苦。
我们已经阐述了应用开发中测试的重要性，我们将看到如何为 Flask 应用编写单元测试。我们同样将看到如何测量代码覆盖率和寻找应用瓶颈。

## 设置基本 logging 文件

通常，Flask 不会为我们生成日志，除了带有堆栈跟踪信息的错误，这些错误会被发送给 logger(我们将在本章的其余部分看到更多关于这一点的说明)。当在开发模式下，使用 run.py 运行应用时会产生很多的堆栈信息，但是在生产环境下很难奢望还拥有这些信息。幸运的是，logging 库提供了很多 log 处理方法可以根据需要进行使用。

#### 准备

我们将开始我们的商品目录应用，使用 FileHandler 添加一些基本 logging。他们将信息记录在文件系统的特定文件里。

#### 怎么做

首先，需要改动`__init__.py`：

```py
app.config['LOG_FILE'] = 'application.log'

if not app.debug:
    import logging
    from logging import FileHandler
    file_handler = FileHandler(app.config['LOG_FILE'])
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler) 
```

这里我们增加了一个配置用于指定日志文件的位置。这指的是从应用目录的相对路径，除非特别指定绝对路径。接下来，我们要检查是否启用 debug 模式，如果否，在文件里添加一个日志输出，并设置日志等级为 INFO.DEBUG，这个是最低级别，将会记录所有级别的信息。更多细节，参见日志库文档。

之后，在应用需要日志的地方仅需添加 logger，应用就会将日志信息记录到指定文件。让我们在 views.py 添加一些 loggers 进行演示：

```py
@catalog.route('/')
@catalog.route('/<lang>/')
@catalog.route('/<lang>/home')
@template_or_json('home.html')
def home():
    products = Product.query.all()
    app.logger.info(
        'Home page with total of %d products' % len(products)
    )
    return {'count': len(products)}

@catalog.route('/<lang>/product/<id>')
def product(id):
    product = Product.query.filter_by(id=id).first()
    if not product:
        app.logger.warning('Requested product not found.')
        abort(404)
    return render_template('product.html', product=product) 
```

前面代码中，我们为视图添加了一些 logger。home()里的第一个 logger 等级是 info，product()等级是 warning。如果我们在`__init__.py`设置日志等级为 INFO，两者都将被记录。但是如果设置等级为 WARNING，只有 warning 日志会被记录。

#### 原理

前面代码会在应用根目录创建一个叫做 application.log 的文件。日志会被记录到这个文件，内容看起来像下面这样，内容根据被调用的 handler 不同而有所区别。第一个是来自 home 的请求，第二个是请求商品不存在时的情况：

```py
Home page with total of 1 products
Requested product not found. 
```

#### 更多

*   阅读 Python 日志库文档了解更多 handlers，参见`https://docs.python.org/dev/library/logging.handlers.html`

## 发生错误时发送邮件

这是一个好的主意，在未知事情发生的时候去接收这些错误。实现这非常的容易，并且为错误处理的带来了便利。

#### 准备

我们将采用上一小节的应用，给它添加 mail_handler，来使得应用可以在发生错误的时候发送邮件。同时，我们将演示怎么使用 Gmail 和 SMTP 服务器创建这些 e-mail。

#### 怎么做

首先向配置文件`__init__.py`添加处理程序。这和我们在上一小节添加 file_handler 是类似的：

```py
RECEPIENTS = ['some_receiver@gmail.com']

if not app.debug:
    import logging
    from logging import FileHandler, Formatter
    from logging.handlers import SMTPHandler
    file_handler = FileHandler(app.config['LOG_FILE'])
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    mail_handler = SMTPHandler(
        ("smtp.gmail.com", 587), 'sender@gmail.com', RECEPIENTS,
        'Error occurred in your application',
        ('sender@gmail.com', 'some_gmail_password'), secure=())
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)
    for handler in [file_handler, mail_handler]:
        handler.setFormatter(Formatter(
            '%(asctime)s %(levelname)s: %(message)s '           
            '[in %(pathname)s:%(lineno)d]'
        )) 
```

这里我们设置了一些 e-mail 地址，错误发生的时候会给这些地址发送邮件。同时注意 mail_handler 中设置了日志等级为 EROOR。这是因为只有重要和关键的事情才需要发送邮件。
更多配置 SMTPHanderder 的细节，参见它的文档。

###### 提示

确保关闭 run.py 中的 debug 标记，这样才能使能应用日志，并且为内部应用程序错误发送电子邮件(错误 500)。

#### 原理

为了引起一个内部应用错误，只需在处理程序任何地方拼错关键字即可。你将在你的邮箱中收到一封邮件，具有配置中设置的格式和完整的堆栈信息以供参考。

#### 更多

当找不到页面时（404），我们还可能希望记录所有这些错误。为此，我们只需稍微修改一下 errorhandler 方法：

```py
@app.errorhandler(404)
def page_not_found(e):
    app.logger.error(e)
    return render_template('404.html'), 404 
```

## 使用 Sentry 监控异常

Sentry 是一个工具，它简化了监控异常的过程，同时也给用户带来了深入了解这些错误的可能。日志中的错误很大程度上会被我们眼睛忽略掉。Sentry 分类了不同类型的错误，对错误的重复次数进行计数。这有助于理解错误的严重性，并帮助我们相应地处理它们。

#### 准备

我们将从 Sentry 安装和配置开始。有很多安装和配置 Sentry 的方法。Sentry 还提供了一个基于 SaaS 的托管解决方案，您可以跳过前面讨论的安装部分，直接进行集成。可以从`https://www.getsentry.com`获取 Sentry。

这里，我们将讨论一个非常基础的 Sentry 安装和配置方法，剩下的留给你们自己实现。我们将使用 PostgreSQL 做为 Sentry 的数据库，因为这是 Sentry 团队强烈推荐使用的。运行下面命令：

```py
$ pip install sentry[postgres] 
```

Sentry 是一个服务程序，我们需要一个客户端去访问它。推荐使用 Raven，通过下面命令可以安装:

```py
$ pip install raven[flask] 
```

这里还需要一个库:blinker。这用来处理 Flask 应用的信号（这已经超出本书的范围了，但是你可以阅读`https://pypi.python.org/pypi/blinker`了解更多）。可以使用下面命令安装：

```py
$ pip install blinker 
```

#### 怎么做

安装好了之后，我们需要去给 Sentry 服务器添加配置。首先，在你选择的路径初始化配置文件。推荐在当前虚拟环境里一个名字为 etc 的文件夹下做初始化。可以通过下面命令运行：

```py
$ sentry init etc/sentry.conf.py 
```

之后，基础配置看起来像这样：

```py
from sentry.conf.server import *

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'sentry', # Name of the postgres database
        'USER': 'postgres', # Name of postgres user
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
        'OPTIONS': {
            'autocommit': True,
        }
    }
}
SENTRY_URL_PREFIX = 'http://localhost:9000'
SENTRY_WEB_HOST = '0.0.0.0'
SENTRY_WEB_PORT = 9000
SENTRY_WEB_OPTIONS = {
    'workers': 3, # the number of gunicorn workers
    'limit_request_line': 0, # required for raven-js
    'secure_scheme_headers': {'X-FORWARDED-PROTO': 'https'},
} 
```

我们同样可以配置邮件服务器的细节，使得 Sentry 在错误发生的时候发送邮件，高效的从日志里获取信息，就像上一小节做的那样。详情可以参见 `http://sentry.readthedocs.org/en/latest/quickstart/index.html#configure-outbound-mail`。

现在，在 postgres 中，我们需要去创建 Sentry 中使用的数据库，并升级初始集合：

```py
$ createdb -E utf-8 sentry
$ sentry --config=etc/sentry.conf.py upgrade 
```

升级进程将创建一个默认的超级用户。如果没有，请运行下面命令：

```py
$ sentry --config=etc/sentry.conf.py createsuperuser
Username: sentry
Email address: someuser@example.com
Password:
Password (again):
Superuser created successfully.
$ sentry --config=etc/sentry.conf.py repair –owner=sentry 
```

上一个命令中，sentry 是在创建超级用户时选择的用户名。
现在，开启 Sentry 服务仅仅需要运行下面的命令：

```py
$ sentry --config=etc/sentry.conf.py start 
```

通常，Sentry 运行在 9000 端口，可以通过`http://localhost:9000/`访问到。

接下来，我们需要使用 GUI 在 Sentry 中创建一个团队（team），然后创建一个项目去记录我们应用的错误日志。使用超级用户登录 Sentry 后，会看到一个按钮，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/b23031a4c34fa29b1311cd022b486513.png)

根据表单要求创建一个团队和项目。项目表单看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/359a42a23c20836115c4a09721fc7380.png)

之后，下个屏幕截图看起来像这样。这里的细节将用于我们的 Flask 应用程序的配置。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/77012bc72dc736222adf73b654f0ca0d.png)

现在，拷贝前面截图中高亮的部分，然后粘贴到 Flask 配置文件中。这将使得任何未被捕捉到的错误会被记录到 Sentry。

#### 原理

Sentry 记录一个错误，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/c4d902e0dbcb9ff11eeb72082472b04e.png)

还可以在 Sentry 中记录消息和用户定义的异常。将这个留给你们自己去实现。

## 使用 pdb 调试

大多数 Python 开发者读这本书的时候可能已经对 Python 调试器 pdb 的用法有一点了解。对于那些不知道它的人来说，pdb 是一个用于调试 Python 程序的交互式调试器。我们可以在需要的地方设置断点，使用单步调试，看堆栈信息。
许多新的开发者可能持有这样的观点，调试可以使用日志就可以了。但是调试器可以让我们看到运行流程，每一步的运行状态，会节省很多的开发时间。

#### 准备

这一小节将使用 Python 内带的 pdb 模块，使用上一小节的应用做为演示。

#### 怎么做

使用 pdb 大多是情况下非常的简单。我们仅仅需要在需要打断点的地方插入下面一句就可以了；

```py
import pdb; pdb.set_trace() 
```

这将触发应用在这个断点停止执行，之后可以使用调试器命令单步执行。
现在，在我们的方法中插入这一句，在商品处理函数中：

```py
def products(page=1):
    products = Product.query.paginate(page, 10)
    import pdb; pdb.set_trace()
    return render_template('products.html', products=products) 
```

当来到这一行的时候，调试器提示符就会启动；看起来像这样：

```py
-> return render_template('products.html', products=product)
(Pdb) u
> /Users/shalabhaggarwal/workspace/flask_heroku/lib/python2.7/sitepackages/Flask-0.10.1-py2.7.egg/flask/app.py(1461)dispatch_request()
-> return self.view_functionsrule.endpoint
(Pdb) u
> /Users/shalabhaggarwal/workspace/flask_heroku/lib/python2.7/sitepackages/Flask-0.10.1-py2.7.egg/flask/app.py(1475)full_dispatch_request()
-> rv = self.dispatch_request()
(Pdb) u
> /Users/shalabhaggarwal/workspace/flask_heroku/lib/python2.7/sitepackages/Flask-0.10.1-py2.7.egg/flask/app.py(1817)wsgi_app()
-> response = self.full_dispatch_request() 
```

看 Pdb 中使用的 u，这意味单步执行。该语句中的所有变量，参数属性在当前上下文中都可以使用，以帮助解决问题或理解代码的运行流程。

#### 其他

*   更多调试器命令参见 `https://docs.python.org/2/library/pdb.html#debugger-commands`

## 创建第一个简单测试

测试是任何开发过程中的一个核心，在维护和扩展中也是如此。尤其是 web 应用程序面临高流量，高用户的情况下，测试变的尤其重要，因为用户反馈决定了程序的命运。这一小节，我们将看到如何开始编写测试，后面小节也会讲到更复杂的测试。

#### 准备

在应用根目录下新建一个文件：`app_tests.py`，即`my_app`文件夹里面。
Python 库 unittest2 需要使用下面命令安装：

```py
$ pip install unittest2 
```

#### 怎么做

开始，`app_tests.py`测试文件看起来像这样：

```py
import os
from my_app import app, db
import unittest2 as unittest
import tempfile 
```

前面的代码导入了需要的包。我们将使用 unittest2（前面已经使用 pip 安装了）。需要一个 tempfile 来动态创建 SQLite 数据库。
所有的测试用例需要继承 unitest.TestCase:

```py
class CatalogTestCase(unittest.TestCase):

    def setUp(self):
        self.test_db_file = tempfile.mkstemp()[1]
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + self.test_db_file
        app.config['TESTING'] = True
        self.app = app.test_client()
        db.create_all() 
```

前面方法在任何测试方法运行前运行，里面新建了一个测试客户端。这个类里面需要测试的方法是以`test_`前缀开头的。这里，在应用配置里设置了数据库的名字，是一个时间戳，这将不会重复。同样设置了 TESTING 标记为 True，关闭了错误捕捉，为了更好的进行测试。最后运行 db 的 create_all()方法创建所需的数据库表。看下面代码：

```py
def tearDown(self):
    os.remove(self.test_db_file) 
```

前面方法会在测试运行完后运行。我们移除了当前的数据库文件。看下面代码：

```py
def test_home(self):
    rv = self.app.get('/')
    self.assertEqual(rv.status_code, 200) 
```

前面代码是我们的第一个测试，我们发送了一个 HTTP GET 请求到我们的应用，然后测试返回码是否是 200，200 代表这是一个成功的 GET 请求。

```py
if __name__ == '__main__':
    unittest.main() 
```

#### 原理

为了运行测试文件，仅仅需要在终端运行下面命令：

```py
$ python app_tests.py 
```

下面截图显示了测试的输出结果：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/0716d2a84c3f96e55bee44bccf3fa22d.png)

## 为视图和逻辑编写更多的测试

上一小节，我们开始为 Flask 应用编写测试了，这一小节，我们将为应用编写更多的测试，这些测试将覆盖视图，以便测试行为和逻辑。

#### 准备

我们将继续使用上一小节的`app_tests.py`文件。

#### 怎么做

在编写任何测试前，需要在 setUp()方法中添加一些配置，关闭 CSRF token，因为测试环境不会生成它们：

```py
app.config['WTF_CSRF_ENABLED'] = False 
```

下面是这一小节需要创建的测试用例，我们会逐步介绍每一个测试用例：

```py
def test_products(self):
    "Test Products list page"
    rv = self.app.get('/en/products')
    self.assertEqual(rv.status_code, 200)
    self.assertTrue('No Previous Page' in rv.data)
    self.assertTrue('No Next Page' in rv.data) 
```

前面测试发送一个 GET 请求到/products，然后 assert 返回状态码是否是 200。同样 assert 有没有前一页和后一页（做为模板渲染逻辑的一部分）。看下面代码：

```py
def test_create_category(self):
    "Test creation of new category"
    rv = self.app.get('/en/category-create')
    self.assertEqual(rv.status_code, 200)

    rv = self.app.post('/en/category-create')
    self.assertEqual(rv.status_code, 200)
    self.assertTrue('This field is required.' in rv.data)

    rv = self.app.get('/en/categories')
    self.assertEqual(rv.status_code, 404)
    self.assertFalse('Phones' in rv.data)
    rv = self.app.post('/en/category-create', data={
        'name': 'Phones',
    })
    self.assertEqual(rv.status_code, 302)

    rv = self.app.get('/en/categories')
    self.assertEqual(rv.status_code, 200)
    self.assertTrue('Phones' in rv.data)

    rv = self.app.get('/en/category/1')
    self.assertEqual(rv.status_code, 200)
    self.assertTrue('Phones' in rv.data) 
```

前面测试创建一个 category，并且 assert 相应的状态信息。当一个 category 成功创建的时候，我们将重定向到新建好的 category 页面，这时候状态码是 302。看下面代码：

```py
def test_create_product(self):
"Test creation of new product"
rv = self.app.get('/en/product-create')
self.assertEqual(rv.status_code, 200)

rv = self.app.post('/en/product-create')
self.assertEqual(rv.status_code, 200)
self.assertTrue('This field is required.' in rv.data)

# Create a category to be used in product creation
rv = self.app.post('/en/category-create', data={
    'name': 'Phones',
})
self.assertEqual(rv.status_code, 302)

rv = self.app.post('/en/product-create', data={
    'name': 'iPhone 5',
    'price': 549.49,
    'company': 'Apple',
    'category': 1
})
self.assertEqual(rv.status_code, 302)

rv = self.app.get('/en/products')
self.assertEqual(rv.status_code, 200)
self.assertTrue('iPhone 5' in rv.data) 
```

前面测试创建了一个商品，assert 了每个调用相应的状态信息。

###### 提示 【待修改】

做为这个测试的一部分，我们对 create_product()方法做了一些修改。之前见到的`image = request.files['image']`被替换为了`image = request.files`和`request.files['image']`。这是因为在使用 HTML 表单的时候，我们有一个空的参数 request.files[‘image’]，但是现在我们没有了。

看下面代码：

```py
def test_search_product(self):
    "Test searching product"
    # Create a category to be used in product creation
    rv = self.app.post('/en/category-create', data={
        'name': 'Phones',
    })
    self.assertEqual(rv.status_code, 302)

    # Create a product
    rv = self.app.post('/en/product-create', data={
        'name': 'iPhone 5',
        'price': 549.49,
        'company': 'Apple',
        'category': 1
    })
    self.assertEqual(rv.status_code, 302)

    # Create another product
    rv = self.app.post('/en/product-create', data={
        'name': 'Galaxy S5',
        'price': 549.49,
        'company': 'Samsung',
        'category': 1
    })
    self.assertEqual(rv.status_code, 302)

    self.app.get('/')

    rv = self.app.get('/en/product-search?name=iPhone')
    self.assertEqual(rv.status_code, 200)
    self.assertTrue('iPhone 5' in rv.data)
    self.assertFalse('Galaxy S5' in rv.data)

    rv = self.app.get('/en/product-search?name=iPhone 6')
    self.assertEqual(rv.status_code, 200)
    self.assertFalse('iPhone 6' in rv.data) 
```

前面测试文件新建了一个 category 和两个 product。之后，搜索一个产品，并确保结果中只返回搜索的产品。

#### 怎么做

运行测试文件，需要在终端运行下面命令：

```py
$ python app_tests.py -v
test_create_category (__main__.CatalogTestCase)
Test creation of new category ... ok
test_create_product (__main__.CatalogTestCase)
Test creation of new product ... ok
test_home (__main__.CatalogTestCase)
Test home page ... ok
test_products (__main__.CatalogTestCase)
Test Products list page ... ok
test_search_product (__main__.CatalogTestCase)
Test searching product ... ok
---------------------------------------------------------------
Ran 5 tests in 0.189s

OK 
```

上面输出表明了测试的结果。

## Nose 库集成

Nose 是一个库，可以用来使得测试更容易更有趣。它提供了许多工具来加强测试。尽管 Nose 可以用于多种用途，最重要的用法仍然是测试收集器和运行器。Nose 从当前工作目录下的 Python 源文件、目录和软件包中自动收集测试用例。我们将重点关注如何使用 Nose 运行单个测试，而不是每次运行全部测试。

#### 准备

首先，安装 Nose 库：

```py
$ pip install nose 
```

#### 怎么做

我们可以使用 Nose 运行应用中所有的测试，通过下面命令：

```py
$ nosetests -v
Test creation of new category ... ok
Test creation of new product ... ok
Test home page ... ok
Test Products list page ... ok
Test searching product ... ok
---------------------------------------------------------------
Ran 5 tests in 0.399s

OK 
```

这将选择应用程序中的所有测试，并运行它们，即使我们有多个测试文件。
为了运行单个测试文件，需使用下面命令：

```py
$ nosetests app_tests.py 
```

现在，如果需要运行单个测试，可以使用下面命令：

```py
$ nosetests app_tests:CatalogTestCase.test_home 
```

当我们有一个内存密集型的应用程序和大量的测试用例时，这一点变得非常重要。测试本身可能会花费大量的时间来运行，而且每次这样做对开发人员来说都是非常令人沮丧的。相反，我们更愿意只运行那些与所做的更改有关的测试，或者在某个更改上失败的测试。

#### 其他

*   还有许多其他配置 Nose 的方法。参见`http://nose.readthedocs.org/en/latest/usage.html`。

## 使用 mocking 避免真实 API 访问

## 确定测试覆盖率

前一小节，包含了测试编写，但测试还有一个重要的方法是测试覆盖。覆盖率表示测试覆盖了我们多少的代码。覆盖率越高，测试越高（尽管这不是优秀测试的唯一标准）。这一小节，我们将检查我们应用的覆盖率。

###### 提示

记住百分百的测试率并不意味着代码是完美的。然后在多数情况下，这比没有测试或者低覆盖率要好很多。没有测试的东西都可能是存在问题的。

#### 准备

我们将使用一个库叫做 coverage。安装它：

```py
$ pip install coverage 
```

#### 怎么做

最简单的获取覆盖率细节的方法是使用命令行。仅需运行下面命令：

```py
$ coverage run –source=../<Folder name of application> --omit=app_tests.py,run.py app_tests.py 
```

这里–source 表示需要覆盖率中需要考虑的目录，–omit 表示需要忽略的文件。

现在，在终端打印报告，需运行：

```py
$ coverage report 
```

下面截图显示了输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/998ea4e02deb06832cdf6c8008ae256b.png)

为了得到覆盖率 HTML 形式的输出，运行下面命令：

```py
$ coverage html 
```

这会在当前工作目录中创建一个新的文件夹叫做 htmlcov。仅需在用浏览器打开其中的 index.html，就可以看到所有的细节。
或者，我们可以在测试文件中包含一段代码，这样每次运行测试时都会获得覆盖率报告。在 app_tests.py 中最前面添加以下代码片段：

```py
import coverage
cov = coverage.coverage(
    omit = [
    '/Users/shalabhaggarwal/workspace/mydev/lib/python2.7/sitepackages/*',
    'app_tests.py'
    ]
)
cov.start() 
```

这里，导入了 coverage 库，然后创建了一个对象；告诉 coverage 忽略所有的 site-packages（通常 coverage 会包含所有的依赖），以及测试文件本身。然后，我们开始计算覆盖率的过程。
最后，修改最后一个代码块：

```py
if __name__ == '__main__':
    try:
        unittest.main()
    finally:
        cov.stop()
        cov.save()
        cov.report()
        cov.html_report(directory = 'coverage')
        cov.erase() 
```

前面的代码，首先将 unittest.main()放在 try..finally 块中。这是因为在执行完所有测试之后，unittest.main()会退出。现在，在这个方法完成之后，覆盖率的代码会运行。我们首先停止覆盖率报告，保存它，在控制台上打印报告，然后在删除临时文件.coverage 之前产生 HTML 版本的报告（这些是自动完成的）。

#### 原理

现在运行命令：

```py
$ python app test.py 
```

输出看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/c58225174f8fee5736dde12db8a75c8f.png)

#### 其他

*   使用 Nose 库也是可以测量覆盖率的。这留给你们自己探索。参见`https://nose.readthedocs.org/en/latest/plugins/cover.html?highlight=coverage`。

## 使用 profiling 寻找瓶颈

当我们决定去扩展应用的时候，Profiling 是一个重要的工具。在扩展前，我们希望知道哪一个进程是一个瓶颈，影响了整体上的运行。Python 有一个自带的分析器叫做 cProfile 可以帮助我们做这件事，但是为了生活更加的美好，Werkzeug 自带一个基于 cProfile 的 ProfilerMiddleware。我们将使用它来寻找应用瓶颈。

#### 准备

我们将使用上一小节的应用，新建一个文件叫做 generate_profile.py，在里面增加 ProfileMiddleware。

#### 怎么做

在 run.py 旁边，新建一个文件 generate_profile.py，这个文件就像 run.py 一样，但是它使用 ProfilerMiddleware：

```py
from werkzeug.contrib.profiler import ProfilerMiddleware
from my_app import app
app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions = [10])
app.run(debug=True) 
```

这里，我们从 werkzeug 导入了 ProfileMiddleware，然后修改 wsgi_app 去使用它，限制输出只打印 10 个调用的结果。

#### 原理

现在，使用 generate_profile.py 运行应用：

```py
$ python generate_profile.py 
```

之后新建一个新的商品。然后特定调用的输出类似于下面截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/ea9dec14738c10fff80d8119e1ff930b.png)

从前面截图中看出，这个过程中最密集的调用是对数据库的调用。所以，如果我们决定在未来某个时候提高性能，那么这个是首先需要考虑的问题。

# 第十一章：部署

现在，我们已经知道了如何使用不同的方法去编写 Flask 应用。部署一个应用和管理部署和开发应用一样重要。有许多部署应用的方式，需要去选择一个最合适的方式。从安全和性能角度来说，合理正确的部署是非常重要的。有许多方式来监控部署之后的应用，其中一些是收费的，也有一些是免费的。根据提供的需求和特性来决定是否使用。

这一章将包含下面小节：

*   使用 Apache 部署
*   使用 uWSGI 和 Nginx 部署
*   使用 Gunicorn 和 Supervisor 部署
*   使用 Tornado 部署
*   使用 Fabric 进行部署
*   S3 文件上传
*   使用 Heroku 部署
*   使用 AWS Elastic Beanstalk 部署
*   使用 Pingdom 监控应用
*   使用 New Relic 进行应用性能管理和监控

## 介绍

这一章，我们将讨论多种应用部署技术和监控技术。
每种工具和技术有它自己的特性。举个例子，给应用添加太多的监控事实证明是对应用的额外负担，对开发者同样如此。相似的，如果不使用监控，会错过未被检测出来的用户错误和引起用户不满。
所以，应该选择恰当的工具，这样才能让生活和谐。
部署监控工具中，我们将讨论 Pingdom 和 New Relic。Sentry 是另一个从开发人员的角度来看,被证明是最有益的工具。我们已经在第十章讨论过它了。

## 使用 Apache 部署

首先，我们将学习怎么使用 Apache 部署 Flask 应用。对于 Python web 应用来说，我将使用 mod_wsgi，它实现了一个简单的 Apache 模块，可以托管（host）任何 Python 应用，也支持 WSGI 接口。

###### 提示

mod_wsgi 不同于 Apache，需要被单独安装。

#### 准备

我们将从商品应用程序开始，对其进行适当的调整，使用 Apache HTTP 服务器部署它。
首先，使得我们的应用可安装，那样我们的应用和所有的依赖都会在 Python 加载路径上。可以使用第一章的 setup.py 脚本完成功能。对于这个应用稍微修改了 script 脚本:

```py
packages=[
    'my_app',
    'my_app.catalog',
],
include_package_data=True,
zip_safe = False, 
```

首先，我们列出了所有需要作为应用程序一部分的安装包。它们每个都需要一个`__init__.py`文件。zip_safe 标记告诉安装者不要将这个应用作为 ZIP 文件进行安装。include_package_data 从相同目录下的 MANIFEST.in 文件里读取内容，包含提到的所有包。MANIFEST.in 看起来像这样：

```py
recursive-include my_app/templates *
recursive-include my_app/static *
recursive-include my_app/translations * 
```

现在，安装应用只需使用下面的命令：

```py
$ python setup.py install 
```

###### 提示

mod_wsgi 的安装跟操作系统有关系。在 Debian 系列系统里安装很简单，使用安装工具即可，比如 apt 或者 aptitude。更多细节，参见`https://code.google.com/p/modwsgi/wiki/InstallationInstructions and https://github.com/GrahamDumpleton/mod_wsgi`。

#### 怎么做

我们需要新建一些文件，第一个是 app.wsgi。这将使我们的应用作为 WSGI 应用进行加载：

```py
activate_this = '<Path to virtualenv>/bin/activate_this.py'
execfile(activate_this, dict(__file__=activate_this))

from my_app import app as application
import sys, logging
logging.basicConfig(stream = sys.stderr) 
```

如果是在 virtualenv 下执行的安装，需要在应用加载前激活虚拟环境。如果是在系统下进行的安装，前两句不需要。然后把 app 对象作为 application 导入。最下面两句是可选的，它们用标准 lgger 进行输出，默认情况下 mod_wsgi 是没开启的。

###### 提示

app 对象需要作为 application 进行导入，因为 mod_wsgi 期望 application 这样的关键字。

接下来是一个配置文件被 Apache HTTP 服务器用来服务应用。这个文件命名为 apache_wsgi.conf:

```py
<VirtualHost *>
        WSGIScriptAlias / <Path to application>/flask_catalog_deployment/app.wsgi
        <Directory <Path to application>/flask_catalog_deployment>
            Order allow,deny
            Allow from all
        </Directory>
</VirtualHost> 
```

前面的代码是 Apache 配置，这个告诉 HTTP 服务器需要加载应用的目录。

最后一步是在 apache2/httpd.conf 文件添加 apache_wsgi.conf 文件的路径，使用服务器运行的时候加载我们的应用：

```py
Include <Path to application>/flask_catalog_deployment/apache_wsgi.conf 
```

#### 原理

使用下面命令重启 Apache 服务器服务：

```py
$ sudo apachectl restart 
```

在浏览器打开`http://127.0.0.1/`会看到应用的主页。任何错误发生的时候可以通过`/var/log/apache2/error_log`（不同操作系统该文件路径不一样）文件查看。

#### 更多

我们可能会发现商品图片可能会失效。为此，需要对应用配置做一个小的修改：

```py
app.config['UPLOAD_FOLDER'] = '<Some static absolutepath>/flask_test_uploads' 
```

我们选择了一个 static 路径，因为我们不希望每次应用修改或安装的时候都进行修改。
现在，包括这个路径到 apache_wsgi.conf 中：

```py
Alias /static/uploads/ "<Some static absolutepath>/flask_test_uploads/"
<Directory "<Some static absolute path>/flask_test_uploads">
    Order allow,deny
    Options Indexes
    Allow from all
    IndexOptions FancyIndexing
</Directory> 
```

之后，安装应用和重启 apachectl。

#### 其他

*   [`httpd.apache.org/`](http://httpd.apache.org/)
*   [`code.google.com/p/modwsgi/`](https://code.google.com/p/modwsgi/)
*   [`wsgi.readthedocs.org/en/latest/`](http://wsgi.readthedocs.org/en/latest/)
*   [`pythonhosted.org/setuptools/setuptools.html#setting-the-zip-safe-flag`](https://pythonhosted.org/setuptools/setuptools.html#setting-the-zip-safe-flag)

## 使用 uWSGI 和 Nginx 部署

对于那些已经知道 uWSGI 和 Nginx 的人来说，没有更多需要解释的了。uWSGI 是和服务器的一个协议，提供了一个完整的 stack 托管服务。Nginx 是一个反向代理和 HTTP 服务器，它非常的轻便，几乎可以处理无限量的请求。Nginx 能够无缝的使用 uWSGI，并为了更好的性能提供了许多底层的优化。

#### 准备

我们将使用上一小节的应用，还有 app.wsgi，setup.py，MANIFEST.ini 文件。同样，上一小节对应用配置文件的修改同样适用于这一小节。

###### 提示

关闭可能在运行的 HTTP 服务器，比如 Apache 等等。

#### 怎么做

首先，需要安装 uWSGI 和 Nginx。在 Debian 发行版比如 Ubuntu 上，安装很容易，可以使用：

```py
# sudo apt-get install nginx
# sudo apt-get install uWSGI 
```

###### 提示

你可以在 virtualenv 里使用 pip install uWSGI 安装 uWSGI。

不同的操作系统，各个软件安装方法不同，需参见各自文档。

确保有一个用于 uWSGI 的文件夹 apps-enabled，这里将放置应用特定的 uWSGI 配置文件。也要确保有一个供 Nginx 使用的 sites-enabled 文件夹，这里放置网站特定的配置文件。通常安装好软件后他们都在/etc/文件下已经存在了。如何没有根据不同操作系统进行相应的创建。

接下来，我们将在应用里创建一个叫做 uwsgi.ini 的文件：

```py
[uwsgi]
http-socket = :9090
plugin = python
wsgi-file = <Path to application>/flask_catalog_deployment/app.wsgi
processes = 3 
```

为了测试 uWSGI 是否正常工作，需运行下面命令：

```py
$ uwsgi --ini uwsgi.ini 
```

前面命令相对于运行下面命令：

```py
$ uwsgi --http-socket :9090 --plugin python --wsgi-file app.wsgi 
```

现在，在浏览器输入`http://127.0.0.1:9090/`。这将打开应用主页。

创建一个软链接到 apps-enabled 文件夹：

```py
$ ln -s <path/to/uwsgi.ini> <path/to/apps-enabled> 
```

在向下继续之前，编辑前面的文件，使用 socket 替换 http-socket。这将协议从 HTTP 改为 uWSGI（更多参见`http://uwsgi-docs.readthedocs.org/en/latest/Protocol.html`）。现在，创建一个新的文件叫做 nginx-wsgi.conf。这包含用于服务应用的 Nginx 配置和静态文件：

```py
location / {
    include uwsgi_params;
    uwsgi_pass 127.0.0.1:9090;
}
location /static/uploads/{
    alias <Some static absolute path>/flask_test_uploads/;
} 
```

前面代码块，uwsgi_pass 指定 uWSGI 服务器需要被映射到的指定位置。
创建一个软连接到 sites-enabled 文件夹：

```py
$ ln -s <path/to/nginx-wsgi.conf> <path/to/sites-enabled> 
```

编辑 nginx.conf 文件（通常位置是/etc/nginx/nginx.conf），增加下面行：

```py
include <path/to/sites-enabled>/*; 
```

做好这些之后，重启 Nginx：

```py
$ sudo nginx -s reload 
```

浏览器输入`http://127.0.0.1/`来看通过 Nginx 和 uWSGI 服务的程序。

###### 提示

这一小节的一些指令会根据操作系统的不同而不同。不同包的安装方法也不一样。

#### 其他

*   了解更多 uWSGI，参见`http://uwsgi-docs.readthedocs.org/en/latest/`。
*   了解更多 Nginx，参见`http://nginx.com/`
*   DigitalOcean 写了一篇很好的文章关于这个话题。参见`https://www.digitalocean.com/community/tutorials/how-to-deploy-python-wsgi-applications-using-uwsgi-web-server-with-nginx`
*   了解 Apache 和 Nginx 的不同，参见 Anturis 的文章，`https://anturis.com/blog/nginx-vs-apache/`

## 使用 Gunicorn 和 Supervisor 部署

Gunicorn 是一个为了 Unix 的 WSGI HTTP 的服务器。它非常的轻便，快速。它的简单性在于它与各种 web 框架的广泛兼容性。
Supervisor 是一个监控工具能够控制各种进程，处理这些进程的启动，并且在这些进程异常退出的时候重启它们。它能够被扩展到使用 XML-RPC API 控制远程位置上的程序，而不用登录远程服务器（我们不会在这里讨论这，因为已经超出了本书的范围）。
需要记住的一件事是这些工具能够和之前章节提到的工具比如 Nginx 一起配合。

#### 准备

我们将从 gunicorn 和 supervisor 安装开始：

```py
$ pip install gunicorn
$ pip install supervisor 
```

#### 怎么做

检查 gunicorn 是否正常工作，需在应用文件夹里运行下面命令：

```py
$ gunicorn -w 4 -b 127.0.0.1:8000 my_app:app 
```

之后，在浏览器输入`http://127.0.0.1:8000/`可以看到应用的主页。
现在需要使用 Supervisor 去做相同的事情，让应用作为后台进程运行，这将让 Supervisor 自身控制进程而不是人为控制。首先，需要一个 Supervisor 配置文件。在 virtualenv 里运行下面命令可以获得配置文件。Supervisor 通常会寻找 etc 文件夹，里面存在一个 supervisord.conf 文件。在系统层面的安装下，这个文件夹是/etc，但在 virtualenv 里，会在 virtualenv 里寻找 etc，然后返回到/etc/：

```py
$ echo_supervisord_conf > etc/supervisord.conf 
```

###### 提示

echo_supervisord_conf 是由 Supervisor 提供的，它向特定位置输出一个配置文件。

下面命令将会在 etc 文件夹里创建一个叫做 supervisord.conf 的文件。在这个文件里添加下面代码块：

```py
[program:flask_catalog]
command=<path/to/virtualenv>/bin/gunicorn -w 4 -b 127.0.0.1:8000 my_
app:app
directory=<path/to/virtualenv>/flask_catalog_deployment
user=someuser # Relevant user
autostart=true
autorestart=true
stdout_logfile=/tmp/app.log
stderr_logfile=/tmp/error.log 
```

###### 提示

注意不应该使用 root 权限去运行这个应用。当应用程序崩溃时是一个巨大的安全漏洞，可能会伤害操作系统本身。

#### 原理

现在运行下面命令：

```py
$ supervisord
$ supervisorctl status
flask_catalog RUNNING pid 40466, uptime 0:00:03 
```

第一个命令启动 supervisord 服务器，接下来查看所有进程的状态。

###### 提示

这一小节提到的工具可以和 Nginx 配合，其中 Ninx 作为代理服务器。建议你自己尝试一下。
每次当修改应用的时候，都需要重启 Gunicorn，以便让这些修改生效，运行下面命令：

```py
$ supervisorctl restart all 
```

你可以重启特定程序而不是所有：

```py
$ supervisorctl restart flask_catalog 
```

#### 其他

*   [`gunicorn-docs.readthedocs.org/en/latest/index.html`](http://gunicorn-docs.readthedocs.org/en/latest/index.html)
*   [`supervisord.org/index.html`](http://supervisord.org/index.html)

## 使用 Tornado 部署

Tornado 是一个完整的 web 框架，它本身也是一个 web 服务器。这里，我们将使用 Flask 去创建应用，包含一个基本的 URL 路由和模板，服务器部分由 Tornado 完成。Tornado 是为了支持上千的并发请求而创建的。

###### 提示

Tornado 在配合使用 WSGI 应用的时候会存在一些限制。所以慎重选择。阅读更多，参见`http://www.tornadoweb.org/en/stable/wsgi.html#running-wsgi-apps-on-tornado-servers`。

#### 准备

安装 Tornado 使用：

```py
$ pip install tornado 
```

#### 怎么做

接下来，创建一个叫做 tornado_server.py 的文件，填写下面的内容：

```py
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from my_app import app

http_server = HTTPServer(WSGIContainer(app))
http_server.listen(5000)
IOLoop.instance().start() 
```

这里，我们为应用创建了一个 WSGT 容器；这个容器被用来创建一个 HTTP 服务器，端口是 5000。

#### 原理

使用下面命令运行前一小节创建的 Python 文件：

```py
$ python tornado_server.py 
```

浏览器输入`http://127.0.0.1:5000/`可以看见主页。

###### 提示

Tornado 可以和 Nginx（作为代理服务器），Supervisor（进程管理）一起使用为了最好的效果。这留给你们自己完成。

## 使用 Fabric 进行部署

Fabric 是 Python 的一个命令行工具；它简化了使用 SSH 部署应用或系统管理任务的过程。同时它允许执行远程服务器的 shell 命令，使得部署简化了，因为所有操作现在可以被压缩到一个 Python 文件里，在需要的时候运行即可。因此，它减轻了每次都得登录进服务器然后手动输入命令行升级程序的痛苦。

#### 准备

安装 Fabric：

```py
$ pip install fabric 
```

我们将使用上一小节的应用。创建一个 Fabric 文件对远程服务器进行部署。

相似的，假设远程服务器已经创建好了，所有 virtualenv 环境里的依赖包都安装好了。

#### 怎么做

首先在应用里创建一个叫做 fabfile.py 的文件， 最好在应用根目录下，即和 setup.py，run.py 同一层目录。Fabric 通常期望文件的名字是 fabfile.py。如果使用了一个不同的名字，在执行的时候需要明确的指定。
一个基本的 Fabric 文件看起来像这样：

```py
from fabric.api import sudo, cd, prefix, run

def deploy_app():
    "Deploy to the server specified"
    root_path = '/usr/local/my_env'
    with cd(root_path):
        with prefix("source %s/bin/activate" % root_path):
            with cd('flask_catalog_deployment'):
                run('git pull')
                run('python setup.py install')
            sudo('bin/supervisorctl restart all') 
```

这里，首先进入 virtualenv，然后使能它，然后进入应用程序。然后从 Git 导入代码，然后使用 setup.py install 更新应用。之后，重启 supervisor 进行，这样修改可以生效。

###### 提示

这里使用的大多数命令是很简单的。除了 prefix，它将后续所有的命令封装在它的块中。这意味着，先激活 virtualenv，然后在 with 块中所有的命令将会在 virtualenv 激活状态下运行的。在离开 with 块的时候，会离开 virtualenv 环境。

#### 原理

运行这个文件，需要提供脚本所要执行的远程服务器。所以命令看起来是：

```py
$ fab -H my.remote.server deploy_app 
```

#### 更多

我们可以在 fab 脚本里指定远程地址，这可能是个好主意。因为部署服务器在大多数情况下是相同的。
为了做到这些，fab 脚本看起来像这样：

```py
from fabric.api import settings

def deploy_app_to_server():
    "Deploy to the server hardcoded"
    with settings(host_string='my.remote.server'):
        deploy_app() 
```

这里，我们硬编码了 host 然后调用了之前创建好的方法进行部署。

## S3 文件上传

Amazon 将 S3 解释为存储，是为了让开发者使用大规模的计算更容易。S3 通过 web 接口提供了一个非常简单的接口，这使得存储和在大量数据里的检索变得简单。直到现在，在我们的商品目录应用中，我们看到在创建商品过程中图片管理存在问题。如果这些图像存储在某个地方，并且可以从任何地方访问，这些问题将消失。我们将使用 S3 解决这个问题。

#### 准备

Amazon 提供 boto，一个完整的 Python 库，提供了和 Amazon Web Service 之间的接口。大部分的 AWS 特性可以使用 boto 完成。安装 boto：

```py
$ pip install boto 
```

#### 怎么做

现在对已经存在的商品目录程序做一些修改，来使用 S3 上传文件。
首先，做配置，来允许 boto 访问 S3。在应用配置文件里增加下面语句，即，`my_app/__init__.py`：

```py
app.config['AWS_ACCESS_KEY'] = 'Amazon Access Key'
app.config['AWS_SECRET_KEY'] = 'Amazon Secret Key'
app.config['AWS_BUCKET'] = 'flask-cookbook' 
```

接下来，对 views.py 文件做些修改：

```py
from boto.s3.connection import S3Connection 
```

上面从 boto 导入了需要的东西。接下来，替换 create_product()里面的两行：

```py
filename = secure_filename(image.filename)
image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename)) 
```

使用下面这些替换这两行：

```py
filename = image.filename
conn = S3Connection(
    app.config['AWS_ACCESS_KEY'], app.config['AWS_SECRET_KEY']
)
bucket = conn.create_bucket(app.config['AWS_BUCKET'])
key = bucket.new_key(filename)
key.set_contents_from_file(image)
key.make_public()
key.set_metadata(
    'Content-Type', 'image/' + filename.split('.')[-1].lower()
) 
```

最后需要修改 product.html，这里修改图片 src 路径。使用下面语句提供之前的 img src:

```py
<img src="{{ 'https://s3.amazonaws.com/' + config['AWS_BUCKET'] + '/' + product.image_path }}"/> 
```

#### 原理

现在，像平常一样运行这个应用，然后创建一个商品。当创建好的商品进行渲染时，商品图像会花一点时间才出来，因为现在图片是由 S3 提供的（而不是本地机器）。如果出现这个现象，说明 S3 集成成功了。

## 使用 Heroku 部署

Heroku 是一个云应用平台，提供了一个简单的快速的方式去构建和部署 web 应用。Heroku 管理服务器，部署，和开发者开发应用时的操作。使用 Heroku toolbelt 来部署 Heroku 是相当简单。

#### 准备

我们将使用上一小节的应用。
第一步需下载 Heroku toolbelt，可以通过`https://toolbelt.heroku.com/`下载。
一旦 toolbelt 被安装了，就可以在终端中使用一系列命令了。我们在这一小节后面会见到。

###### 提示

建议使用一个新的 virtualenv 执行 Heroku 部署，以便为应用只安装需要的包。这将使得部署应用更快更容易。

现在，运行下面命令登录 Heroku 账户，并且和服务器同步 SSH key：

```py
$ heroku login
Enter your Heroku credentials.
Email: shalabh7777@gmail.com
Password (typing will be hidden):
Authentication successful. 
```

如果不存在，将提示您创建新的 SSH 密钥。根据具体情况进行操作。

#### 怎么做

现在，我们已经有了一个需要被部署到 Heroku 的应用了。首先，Heroku 需要知道部署时候需要运行的命令 。在 Procfile 里面添加下面内容：

```py
web: gunicorn -w 4 my_app:app 
```

这里，我们将告诉 Heroku 去运行这个命令来启动应用。

###### 提示

Profile 里面还可以做很多许多其他的配置和命令。更多细节，参见 Heroku 文档。

Heroku 需要知道需要被安装的依赖包。通过 requirements.txt 文件完成：

```py
Flask==0.10.1
Flask-Restless==0.14.0
Flask-SQLAlchemy==1.0
Flask-WTF==0.10.0
Jinja2==2.7.3
MarkupSafe==0.23
SQLAlchemy==0.9.7
WTForms==2.0.1
Werkzeug==0.9.6
boto==2.32.1
gunicorn==19.1.1
itsdangerous==0.24
mimerender==0.5.4
python-dateutil==2.2
python-geoip==1.2
python-geoip-geolite2==2014.0207
python-mimeparse==0.1.4
six==1.7.3
wsgiref==0.1.2 
```

这个文件包含应用所有的依赖，还有依赖的依赖。产生这个文件的一个简单方式是使用下面命令：

```py
$ pip freeze > requirements.txt 
```

这将用 virtualenv 里被安装的所有包来创建/更新 requirements.txt 文件。
现在，需要创建应用的 Git 仓库。为此，需运行下面命令：

```py
$ git init
$ git add .
$ git commit -m "First Commit" 
```

现在，有了一个 Git 仓库，并且添加了所有的文件。

###### 提示

确保在仓库里有一个.gitignore 文件来保证不添加临时文件比如.pyc 到仓库里。

现在，创建一个 Heroku 应用，然后添加应用到 Heroku：

```py
$ heroku create
Creating damp-tor-6795... done, stack is cedar
http://damp-tor-6795.herokuapp.com/ | git@heroku.com:damp-tor-6795.git
Git remote heroku added
$ git push heroku master 
```

最后一个命令之后，许多东西会打印在终端上。这些表面了所有正在安装的包和最终启动的应用程序。

#### 原理

在前面命令成功完成之后，仅仅需要在浏览器打开部署最后 Heroku 提供的 URL 或者运行下面命令：

```py
$ heroku open 
```

这将打开应用主页。尝试创建一个新的商品并上传图片，之后会看到由 Amazon S3 提供的图片了。
为了看到应用的日志，运行下面命令：

```py
$ heroku logs 
```

#### 更多

我们刚刚做的部署有一个小故障。每次通过 git push 命令更新部署时，SQLite 都会被重写。解决办法是使用 Heroku 提供的 Postgres。建议你们自己去做一下。

## 使用 AWS Elastic Beanstalk 部署

上一小节，我们看到如何将应用部署到服务器，使用 Heroku 是很容易做到这个的。相似的，Amazon 有一个服务叫做 Elastic Beanstalk，允许开发者很容易的部署他们的应用到 Amazon EC2。仅仅需要一些配置，一个 Flask 应用使用 Elastic Beanstalk 就可以在几分钟类就部署到 AWS。

#### 准备

我们将使用上一小节的应用。唯一保持一样的文件是 requirement.txt。上一小节其余添加的文件就可以被忽略，这一小节不会用到。

现在，首先要做的是从 Amazon 网站下载 AWS Elastic Beanstalk 命令行工具库。地址是`http://aws.amazon.com/code/6752709412171743`。这将下载一个 ZIP 包，需要进行解压然后放置在适当的位置。
这个工具的路径应该被添加进环境变量 PATH 中，这样这个命令才可以全局使用。这个可以通过 export 命令实现：

```py
$ export PATH=$PATH:<path to unzipped EB CLI package>/eb/linux/python2.7/ 
```

同样需要添加路径到~/.profile 或者~./bash_profile 文件：

```py
$ export PATH=$PATH:<path to unzipped EB CLI package>/eb/linux/python2.7/ 
```

#### 怎么做

使用 Beanstalk 进行部署时，有一些惯例需要去遵守。Beanstalk 假设存在一个文件叫做 application.py，它包含了应用对象（我们的例子中就是 app 对象）。Beanstalk 把这个文件视为 WSGI 文件，它将用在部署中。

###### 提示

在使用 Apache 部署一节中，有一个文件叫做 app.wsgi，在这个文件中我们导入 app 对象为 application，因为 apache/mod_wsgi 需要这样做。Amazon 也需要这样做，因为通常情况下，Amazon 背后使用的是 Apache 进行的部署。

application.py 文件内容看起来像这样：

```py
from my_app import app as application
import sys, logging
logging.basicConfig(stream = sys.stderr) 
```

现在，在应用里创建一个 Git 仓库，提交这些文件：

```py
$ git init
$ git add .
$ git commit -m "First Commit" 
```

###### 提示

确保在仓库里有一个.gitignore 文件，防止添加临时文件进仓库，比如.pyc。
现在需要到 Elastic Beanstalk 运行下面命令：

```py
$ eb init 
```

前面命令表示初始化 Elastic Beanstalk 实例。为了创建 EC2 实例，它将要求 AWS 凭据以及其他许多配置选项，这些可以根据需要进行选择。更多细节参见`http://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_Python_flask.html`。

做完这些之后，运行下面命令触发服务器的创建，然后部署应用：

```py
$ eb start 
```

###### 提示

上面命令背后的事情是，先创建了 EC2 实例(一卷)，分配一个弹性 IP，然后运行下面命令将我们的应用程序 push 到新创建的服务器，以便进行部署: $ git aws.push

这将花一点时间完成。当完成的时候，你可以使用下面命令检查应用的状态：

```py
$ eb status –verbose 
```

当需要升级应用的时候，仅仅需要使用 git 提交修改，然后使用 push:

```py
$ git aws.push 
```

#### 原理

当部署进程完成的时候，它会给你一个应用 URL。在浏览器输入 URL，就可以看见应用了。
然后你会发现一些问题。静态文件比如 CSS，JS 工作不正常。这是因为 Beanstalk 里的 static 路径没有配置正确。这可以通过 AWS 管理控制台里的应用监控/配置页面修改应用配置进行修复。看下面截图进行更好的理解：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/23aad70ba967f79fc38e3bb54b8684cf.png)

点击左边选项中的 Configuration 选项。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/14ee4d5d8f12e1ca6861658b69bc4044.png)

注意到前面截屏中高亮的部分。这是每个应用中需要改变的地方。打开 Software Settings。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/957a7a6c9729f238121b1c82a86c16f8.png)

修改 virtual path 的/static/，如上图截屏所示。

在这些修改完成之后，Elastic Beanstalk 创建的环境会自动更新，将花一点时间。当处理结束的时候，再一次检查应用看 static 文件是否正确工作了。

## 使用 Pingdom 监控应用

Pingdom 是一个网站监控工具，当你网站宕机的时候能够快速通知你。这个工具背后的思想是每一个间隔 ping 一下网站，比如 30s。如果 ping 失败了，它将通过 e-mail，SMS 等通知你。它将保持一个更快的频率来 ping 网站，直到网站恢复。还有其他一些监控特性，但这里我们会不涉及。

#### 准备

因为 Pingdom 是一个 Saa 服务，第一步得注册一个账号。Pingdom 提供了一个月的免费试用，如果你想尝试的话。网站是：`https://www.pingdom.com`。
我们使用上一小节的应用做演示。

#### 怎么做

成功注册之后，创建一个时间检查。看一下下面的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/0c2622e5223ebd854948a0da778bbd2a.png)

如你所见，我已经为 AWS 实例添加了一个检查。为了创建一个新的检查，点击 ADD NEW 按钮。填写弹出来的表单。

#### 原理

在成功创建检查之后，有意的在代码里引发一个错误来破坏应用，然后部署到 AWS。当有错误的应用部署的时候，你将收到一封邮件。邮件看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/6cac884f558640028ae57b646f448499.png)

一旦，你的应用修复了，然后重新部署了，下一封邮件将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/712d148cb2ecd8349d2aec6e83a31728.png)

## 使用 New Relic 进行应用性能管理和监控

New Relic 是一个分析软件，提供了接近实时的操作和应用分析。它提供了应用各个方面的分析。它可以完成分析器的工作。事实上工作起来的情形是，我们的应用发送数据给 New Relic，而不是 New Relic 向我们应用请求分析。

#### 准备

我们将使用上一小节的应用，使用 AWS 部署的。
第一步注册 New Relic 账号。在简单注册流程和邮件验证完成后，将登陆主页。这里，可以显示 license key，这会用来连接应用到这个账户。主页看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/f6b66709769ffe0e3c772035433246e7.png)

这里点击 Reveal your license key。

#### 怎么做

一旦你获得了 license key，我们需要去安装 newrelic 库：

```py
$ pip install newrelic 
```

现在，需要产生一个叫做 newrelic.ini 的文件，它将包含关于许可密钥，我们的应用程序的名称，等等这些细节。使用下面命令完成：

```py
$ newrelic-admin generate-config LICENSE-KEY newrelic.ini 
```

前面命令中，用你账户真实的 license key 替换 LICENSE-KEY。现在有了一个新的文件叫做 newrelic.ini。打开并进行编辑应用的名字或其他东西。

为了验证 newrelic.ini 是否可用正常使用，运行下面命令：

```py
$ newrelic-admin validate-config newrelic.ini 
```

这将告诉我们验证是否成功。如果不，检查 license key 是否正确。

现在，在应用配置文件`my_app/__init__.py`最上面添加下面几行。确保下面几行添加在其他行之前：

```py
import newrelic.agent
newrelic.agent.initialize('newrelic.ini') 
```

现在，需要更新 requirements.txt 文件。运行下面命令：

```py
$ pip freeze > requirements.txt 
```

之后，提交修改，然后部署到应用到 AWS 使用下面命令：

```py
$ git aws.push 
```

#### 原理

一旦你的应用成果部署到 AWS，它将发送分析数据到 New Relic，并且主页有了一个新的应用可以添加。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/3c66afaa981eced2a03c42bf7c1bfbda.png)

打开应用分析页面，大量的统计数据将会出现。它还将显示哪些调用花费了最长的时间，以及应用是如何处理的。你同样可以看到多个选项卡对应于不同类型的监控。

# 第十二章：其他贴士和技巧

这本书已经覆盖了使用 Flask 创建 web 应用需要知道的所有东西。但还是有很多需要你自己去探索。最后一章，我们将讲述额外一些小节，如果有必要的话，他们可以被添加进应用。

这一章，将包含下面内容：

*   使用 Whoosh 进行全文搜索
*   使用 Elasticsearch 进行全文搜索
*   使用 signals
*   使用缓存
*   为 Flask 应用支持 E-mail
*   理解异步操作
*   使用 Celery

## 介绍

这一章，我们首先将学习如何使用 Whoosh 和 Elasticsearch 进行全文搜索。全文搜索对于提供大量内容和选项的 Web 应用程序（如电子商务网站）非常重要。接下来我们将捕捉信号，这些信号是在应用里某些操作执行时被发送的。然后为我们的 Flask 应用实现缓存。
我们同样将会看到应用如何支持发送 e-mail。然后将看到如何实现应用异步。通常，WSGI 应用是同步和阻塞的，不能同时处理多个同步请求。我们将看到如何通过一个简单的例子解决这个问题。我们还会集成 Celery 到我们的应用，看一个任务队列对应用带来的好处。

## 使用 Whoosh 进行全文搜索

Whoosh 是使用 Python 完成的一个快速全文索引和搜索库。它是一个完全 Pythonic 的 API，使得开发者为他们的应用增加搜索功能非常容易和高效。这一节，我们将使用一个叫做 Flask-WhooshAlchemy 的包，它集成了 Whoosh 文本搜索功能和 SQLAlchemy，以便用于 Flask 应用中。

#### 准备

使用下面命令安装 Flask-WhooshAlchemy：

```py
$ pip install flask_whooshalchemy 
```

它将安装需要的包和依赖。

###### 译者注

flask_whooshalchemy 不支持 Python3，另外对中文支持也不好，不推荐使用，可以使用 jieba。

#### 怎么做

使用 SQLAlchemy 集成 Whoosh 和 Flask 是非常简单的。首先，我们需要提供一个 Whoosh 目录的路径，这个目录下将创建模型索引。这应该在应用配置里完成，即`my_app/__init__.py`:

```py
app.config['WHOOSH_BASE'] = '/tmp/whoosh' 
```

你可以选择任意你喜欢的路径，可以是绝对路径也可以是相对路径。

接下来，我们需要改变 models.py 文件，使得一些 string/text 字段可搜索：

```py
import flask.ext.whooshalchemy as whooshalchemy
from my_app import app

class Product(db.Model):
    __searchable__ = ['name', 'company']
    # … Rest of code as before … #

whooshalchemy.whoosh_index(app, Product)

class Category(db.Model):
    __searchable__ = ['name']
    # … Rest of code as before … #

whooshalchemy.whoosh_index(app, Category) 
```

注意每个模型添加的`__searchable__`语句。它告诉 Whoosh 去创建这些字段的索引。记住这些字段应该是 text 或者是 string 类型的。whoosh_index 语句告诉应用为这些模型创建索引，如果他们还不存在的话。

做好这些之后，添加一个 handler 使用 Whoosh 进行搜索。可以在 views.py 处理这些：

```py
@catalog.route('/product-search-whoosh')
@catalog.route('/product-search-whoosh/<int:page>')
def product_search_whoosh(page=1):
    q = request.args.get('q')
    products = Product.query.whoosh_search(q)
    return render_template(
        'products.html', products=products.paginate(page, 10)
    ) 
```

这里，通过 q 获取 URL 参数，然后传递它的值到 whoosh_search()方法里。这个方法将会对 Product 模型的 name 和 company 字段进行全文搜索。我们前面已经进行了设置，使得模型里的 name 和 company 变得可搜索了。

#### 原理

在第四章基于 SQL 搜索一节中我们实现了一个基于基本字段搜索的方法。但是在使用 Whoosh 情况下，搜索时我们不需要指定任何字段。我们可以输入任何字段，如何匹配上可搜索字段的话，将会返回结果，并按照相关性进行排序。

首先，在应用创建一些商品。现在，打开`http://127.0.0.1:5000/product-search-whoosh?q=iPhone`，结果页将显示商品名包含 iPhone 的列表。

###### 提示

Whoosh 提供了一些高级选项，我们可以控制哪些字段可以搜索或者结果是如何排序的。你可以根据应用的需要自行探索。

#### 其他

*   参考 `https://pythonhosted.org/Whoosh/`
*   参考 `https://pypi.python.org/pypi/Flask-WhooshAlchemy`

## 使用 Elasticsearch 进行全文搜索

Elasticsearch 是一个基于 Lucene 的搜索服务，是一个开源信息检索库。ElasticSearch 提供了一个分布式全文搜索引擎，它具有 RESTful Web 接口和 schema-free JSON 文档。这一小节，我们将使用 Elasticsearch 为我们的 Flask 应用完成全文搜索。

#### 准备

我们将使用一个叫做 pyelasticsearch 的 Python 库，它使得处理 Elasticsearch 很容易：

```py
$ pip install pyelasticsearch 
```

我们同样需要安装 Elasticsearch 服务本身。可以从`http://www.elasticsearch.org/download/`下载。解压文件，然后运行下面命令：

```py
$ bin/elasticsearch 
```

默认情况下，将在`http://localhost:9200/`上运行 Elasticsearch 服务。

#### 怎么做

为了演示集成，我们将从向应用配置添加 Elasticsearch 开始，即`my_app/__init__.py`:

```py
from pyelasticsearch import ElasticSearch
from pyelasticsearch.exceptions import IndexAlreadyExistsError

es = ElasticSearch('http://localhost:9200/')
try:
    es.create_index('catalog')
except IndexAlreadyExistsError, e:
    pass 
```

这里，我们从 ElasticSearch 类创建了一个 es 对象，它接收了服务器 URL。然后创建了一个叫做 catalog 的索引。他们是在 try-except 块中处理的，因为如果索引已经存在 ，将会抛出 IndexAlradyExistsError，通过捕捉异常，可以忽略这个错误。

接下来，我们需要往 Elasticsearch 索引里添加文档（document）。可以在视图和模型里完成这些，但是最好是将它添加在模型层。所以，我们将在 models.py 里完成这些:

```py
from my_app import es

class Product(db.Model):

    def add_index_to_es(self):
        es.index('catalog', 'product', {
            'name': self.name,
            'category': self.category.name
        })
        es.refresh('catalog')

class Category(db.Model):

    def add_index_to_es(self):
        es.index('catalog', 'category', {
            'name': self.name,
        })
        es.refresh('catalog') 
```

这里，在每个模型里，我们添加了一个叫做 add_index_to_es()的方法，这个方法将添加与当前 Product 或者 Category 对象对应的文档到 catalog 索引里，并伴随相关的文件类型，即 product 或 category。最后，我们刷新索引以保证新建的索引可以被搜索到。

`add_index_to_es()`方法可以在我们创建，更新，删除商品时被调用。为了演示，我们仅仅在 views.py 创建商品时添加了这个方法：

```py
from my_app import es

def create_product():
    #... normal product creation as always ...#
    db.session.commit()
    product.add_index_to_es()
    #... normal process as always ...#

@catalog.route('/product-search-es')
@catalog.route('/product-search-es/<int:page>')
def product_search_es(page=1):
    q = request.args.get('q')
    products = es.search(q)
    return products 
```

同时，添加一个`product_search_es()`方法，允许在刚刚创建的 Elasticsearch 上进行搜索。对 create_category()方法做同样的处理。

#### 怎么做

假设已经在每个类别里面创建一些商品。现在，如果打开`http://127.0.0.1:5000/product-search-es?q=galaxy`，我们将看到类似于下面截图的回复：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/b4dda003eb4c6626a1befbf50f2a1207.png)

## 使用 signals

Signals 可以理解为应用里发生的事件。这些事件可以被一些特定接收方订阅，当事件发生的时候会触发一个函数。事件的发生由发送方广播，发送方可以指定接收方触发函数里可以使用的参数。

###### 提示

您应该避免修改信号中的任何应用程序数据，因为信号不是按指定的顺序执行的，而且很容易导致数据损坏。

#### 准备

我们将使用一个叫做 binker 的 Python 库，它提供了一些信号特性。Flask 内建了对 blinker 的支持，可以很大程度上使用信号。其中一些核心信号是由 Flask 提供的。

这一小节，我们将使用上一小节的应用，通过信号添加额外的 product 和 category 文档（documents）到索引里。

#### 怎么做

首先，我们创建新建商品和类别时的信号。可以在 models.py 中处理这个。也可以在任何我们希望的文件里处理，因为信号是在全局范围创建的：

```py
from blinker import Namespace

catalog_signals = Namespace()
product_created = catalog_signals.signal('product-created')
category_created = catalog_signals.signal('category-created') 
```

我们使用 Namespace 去创建信号，因为这将在自定义命名空间创建他们，而不是在全局空间，这将有助于管理信号。我们创造了两个信号，可以从他们的名字明白他们的意思。

之后，我们需要去为这些信号创建订阅者，给他们绑定函数。为了这个目的，`add_index_to_es()`需要被移除，在全局范围需要创建新的函数：

```py
def add_product_index_to_es(sender, product):
    es.index('catalog', 'product', {
        'name': product.name,
        'category': product.category.name   
    })
    es.refresh('catalog')

product_created.connect(add_product_index_to_es, app)

def add_category_index_to_es(sender, category):
    es.index('catalog', 'category', {
        'name': category.name,
    })
    es.refresh('catalog')

category_created.connect(add_category_index_to_es, app) 
```

前面的代码中，我们使用.connect()为信号创建了订阅者。这个方法接收一个函数，这个函数会在事件发生时调用。它同样接收一个发送方做为可选参数。app 对象作为发送者被提供，因为，我们不希望我们的函数在任何应用任何地方触发的时候都会被调用。这在扩展的情况下尤其适用，可以被多个应用程序使用。接收方调用的函数接收发送者作为第一个参数，如果发送方没提供的话，通常情况下是 None。我们提供`product/category`作为第二个参数，为了将这条记录添加进 Elasticsearch 索引。

现在，我们仅仅需要触发可以被接收方捕捉的信号。可以在 views.py 处理这些。为了达到这个目的，需要移除`add_index_to_es()`方法，使用.send()方法替换他们：

```py
from my_app.catalog.models import product_created, category_created

def create_product():
    #... normal product creation as always ...#
    db.session.commit()
    product_created.send(app, product=product)
    # product.add_index_to_es()
    #... normal process as always ...# 
```

对 create_category()做同样的处理。

#### 原理

当一个商品被创建的时候，`product_created`信号被触发了，app 做为发送方，商品做为关键参数。这个会在 models.py 中被捕捉，当`add_product_index_to_es()`函数被调用的时候，会向目录索引添加文档。

#### 其他

*   参考资料 `https://pypi.python.org/pypi/blinker`
*   参考资料 `http://flask.pocoo.org/docs/0.10/signals/#core-signals`
*   Flask-SQLAlchemy 提供的信号可以在`https://pythonhosted.org/Flask-SQLAlchemy/signals.html`找到

## 使用缓存

当应用程序的响应时间增加成为一个问题时，缓存成为了任何 Web 应用程序的重要组成部分。Flask 本身默认不提供任何缓存支持，但是 Werkzeug 支持。Werkzeug 对缓存提供了基本的支持，并可以使用多种后端（backend），比如 Memcached 和 Redis。

#### 准备

我们将安装一个叫做 Flask-Cache 的扩展，这会在很大程度上简化缓存的使用：

```py
$ pip install Flask-Cache 
```

#### 怎么做

首先，需初始化 Cache。将在应用配置里进行处理，`my_app/__init__.py`：

```py
from flask.ext.cache import Cache

cache = Cache(app, config={'CACHE_TYPE': 'simple'}) 
```

这里，使用 simple 做为 Cache 的类型，缓存存储在内存里。不建议在生产环境这样做。对于生产环境，需使用 Redis，Memcached，文件系统等等这些。Flask-Cache 对这些全部支持。

接下来，需在方法里增加缓存；这是非常容易实现的。我们仅仅需要对视图方法增加@cache.cached(timeout=<time>)装饰器。列出所有的商品类别可以这样做（在 views.py 中处理）：</time>

```py
from my_app import cache
@catalog.route('/categories')
@cache.cached(timeout=120)
def categories():
    # Fetch and display the list of categories 
```

这种缓存方式以键值对的形式进行存储，键为请求路径，值为这个方法的输出值。

#### 原理

在添加了前面的代码后，检查缓存是否生效。首先访问`http://127.0.0.1:5000/categories`获取类别列表。在将会在缓存里为这个 URL 存储一个键值对。现在，快速的创建一个新的类别，然后再次访问商品类别列表页面。你将看到新建的类别没有被列出来。等几分钟，然后刷新页面。新的类别才会被展示出来。这是因为第一次访问的时候类别列表被缓存了，有效时间是 2 分钟，即 120 秒。

这可能看起来像是应用的一个错误，但是在大型应用程序中，减少对数据库的访问次数是一种恩惠，并且整个应用程序体验也会得到改善。缓存通常用于那些结果不经常更新的处理程序。

#### 更多

我们中的许多人可能认为，在单个类别或产品页面中，这种缓存将失败，因为每个记录都有一个单独的页面。解决这个问题的方法是 memoization。当一个方法用同样参数进行多次调用时，结果应该是从缓存中加载而不是访问数据库。实现 memoization 非常简单:

```py
@catalog.route('/product/<id>')
@cache.memoize(120)
def product(id):
    # Fetch and display the product 
```

现在，如果我们在浏览器输入`http://127.0.0.1:5000/product/1`，第一次请求将从数据库读取数据。但是，第二次，如果做相同的访问，将从缓存加载数据。如果我们打开另一个商品页面`http://127.0.0.1:5000/product/2`，将从数据库获取商品细节。

#### 其他

*   了解更多 Flask-Cache，参见`https://pythonhosted.org/Flask-Cache/`
*   了解更多 memoization，参见`http://en.wikipedia.org/wiki/Memoization`

## 为 Flask 应用支持 E-mail

发送邮件功能是任何 web 应用最基础功能中的一个。基于 Python 的应用，可以使用 smptblib 非常容易的完成这一功能。在 Flask 中，使用 Flask-Mail 扩展更加简化了这一过程。

#### 准备

Flask-Mail 通过 pip 安装：

```py
$ pip install Flask-Mail 
```

让我们以一个简单的例子为例，每当添加新类别时，将向应用管理者发送一封 e-mail。

#### 怎么做

首先，需要在应用配置里实例化 Mail 对象，即`my_app/__init__.py`:

```py
from flask_mail import Mail

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gmail_username'
app.config['MAIL_PASSWORD'] = 'gmail_password'
app.config['MAIL_DEFAULT_SENDER'] = ('Sender name', 'sender email')
mail = Mail(app) 
```

同时，我们需一些配置去创建 e-mail 服务和发送者账号。前面的代码是一个配置 Gmail 账户的简单示例。任何 SMTP 服务可以像这样建立。还有一些其他选项可以选择，可以参见 Flask-Mail 文档`https://pythonhosted.org/Flask-Mail`。

#### 原理

在类别创建的时候发送 e-mail，我们需要对 view.py 做下面修改：

```py
from my_app import mail
from flask_mail import Message

@catalog.route('/category-create', methods=['GET', 'POST'])
def create_category():
    # … Create category … #
    db.session.commit()
    message = Message(
        "New category added",
        recipients=['some-receiver@domain.com']
    )
    message.body = 'New category "%s" has been created' % category.name
    mail.send(message)
    # … Rest of the process … # 
```

这里，一个新的 e-mail 将从我们创建的发送方发送给接收列表方。

#### 更多

现在，假设需要发送一封非常大的邮件，包含非常多的 HTML 文本。将这些全都写在 Python 文件里会使得代码丑陋和难以管理。一个简单的方法是创建模板，然后在发送邮件的时候渲染。我创建了两个模板，一个是 HTML 文本，一个纯文本。

category-create-email-text.html 模板看起来像这样：

```py
A new category has been added to the catalog.
The name of the category is {{ category.name }}.
Click on the URL below to access the same:
{{ url_for('catalog.category', id=category.id, _external = True) }}
This is an automated email. Do not reply to it. 
```

category-create-email-html.html 模板看起来像这样：

```py
<p>A new category has been added to the catalog.</p>
<p>The name of the category is <a href="{{ url_for('catalog.category', id=category.id, _external = True) }}">
        <h2>{{ category.name }}</h2>
    </a>.
</p>
<p>This is an automated email. Do not reply to it.</p> 
```

之后，我们需修改之前在 views.py 里创建 e-mail 的代码；

```py
message.body = render_template(
    "category-create-email-text.html", category=category
)
message.html = render_template(
    "category-create-email-html.html", category=category
) 
```

#### 其他

*   阅读下一小节，明白怎么将耗时的 email 发送过程用一个异步线程处理

## 理解异步操作

应用中有一些操作可能是耗时的，会使用应用变慢，即使这并不是真正意义上的慢。但这降低了用户体验。为了解决这个问题，最简单的方式是使用线程进行异步操作。这一小节，我们将使用 Python 的 thread 和 threading 库来完成这一功能。threading 库是 thread 的一个简单接口；它提供了更多功能和隐藏了用户不常使用的一些东西。

#### 准备

我们将使用上一小节的应用代码。我们中的许多人可能会注意到当邮件在发送的时候，应用在等待这一过程完成，事实上这是不必要的。E-mail 发送可以在后台处理，这样我们的应用对用户来说响应就变得及时。

#### 怎么做

使用 thread 库处理异步是非常简单。仅仅需要在 views.py 里增加这些代码：

```py
import thread

def send_mail(message):
    with app.app_context():
        mail.send(message)
# Replace the line below in create_category()
#mail.send(message)
# by
thread.start_new_thread(send_mail, (message,)) 
```

你可以看到，在一个新的线程里发生邮件，这个线程接收一个叫 message 的参数。我们需要去创建一个新的`send_mail()`方法，因为我们的 e-mail 模板包含`url_for`，所以`send_mail`方法仅能运行在应用上下文中，默认情况下在一个新建的线程里不可用。

同时，发送 e-mail 同样可以使用 threading 库：

```py
from threading import Thread

# Replace the previously added line in create_category() by
new_thread = Thread(target=send_mail, args=[message])
new_thread.start() 
```

实际上，效果和前面一样，但是 threading 库提供了在需要的时候启动线程的灵活性，而不是同时创建和启动线程。

#### 原理

很容易观察上面代码的效果。比较这个应用的执行效果和前一小节的应用效果。你会发现这个应用响应性更强。其他一种方式是监测日志输出，在 e-mail 发送之前，新建的类别页面将会加载。

## 使用 Celery

Celery 是为 Python 准备的任务队列。早期的时候有一个扩展是集成了 Flask 和 Celery，但是在 Celery3.0 的时候，这个扩展被废弃了。现在，Celery 可以直接在 Flask 里使用，而仅仅需做一些配置。前面小节，我们实现了异步发送邮件，这一小节将使用 Celery 完成同样的功能。

#### 准备

安装 Celery:

```py
$ pip install celery 
```

在 Flask 下使用 Celery，我们仅仅需要修改一点 Flask app 配置。这里，使用 Redis 做为代理（broker）。
我们将使用前一小节的应用，然后使用 Celery 完成它。

#### 怎么做

首先要做的是，在应用配置文件里做一些配置，即`my_app/__init__.py`:

```py
from celery import Celery

app.config.update(
    CELERY_BROKER_URL='redis://localhost:6379',
    CELERY_RESULT_BACKEND='redis://localhost:6379'
)
def make_celery(app):
    celery = Celery(
        app.import_name, broker=app.config['CELERY_BROKER_URL']
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
```

前面的代码直接来自于 Flask 网站，大部分情况下可以在应用里这样使用：

```py
celery = make_celery(app) 
```

运行 Celery 进程，需执行下面命令：

```py
$ celery worker -b redis://localhost:6379 --app=my_app.celery -l INFO 
```

###### 提示

确保 Redis 运行在 broker URL 上，如配置中所指定的那样。

这里，-b 指定了 broker，-app 指定了在配置文件里创建的 celery 对象。
现在，仅仅需要在 views.py 里使用 celery 对象去异步发送邮件：

```py
from my_app import celery

@celery.task()
def send_mail(message):
    with app.app_context():
        mail.send(message)

# Add this line wherever the email needs to be sent
send_mail.apply_async((message,)) 
```

如果我们希望一个方法作为 Celery 任务运行只需增加@celery.task 装饰器即可。Celery 进程会自动检测到这些方法。

#### 原理

现在，我们创建了一个商品，并且一封邮件发送了，我们可以在 Celery 进程日志里看到一个任务正在运行，看起来像这样：

```py
[2014-08-28 01:16:47,365: INFO/MainProcess] Received task: my_app.catalog.views.send_mail[d2ca07ae-6b47-4b76-9935-17b826cdc340]
[2014-08-28 01:16:55,695: INFO/MainProcess] Task my_app.catalog.views.send_mail[d2ca07ae-6b47-4b76-9935-17b826cdc340] succeeded in 8.329121886s: None 
```

#### 其他

*   更多 Celery 信息，参见 `http://docs.celeryproject.org/en/latest/index.html`