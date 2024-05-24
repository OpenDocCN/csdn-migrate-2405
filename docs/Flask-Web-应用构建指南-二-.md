# Flask Web 应用构建指南（二）

> 原文：[`zh.annas-archive.org/md5/5AC5010B2FEF93C4B37A69C597C8617D`](https://zh.annas-archive.org/md5/5AC5010B2FEF93C4B37A69C597C8617D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：如果没有经过测试，那就不是游戏，兄弟！

您编写的软件是否具有质量？您如何证明？

通常根据特定的需求编写软件，无论是错误报告、功能和增强票据，还是其他。为了具有质量，软件必须完全和准确地满足这些需求；也就是说，它应该做到符合预期。

就像您会按下按钮来了解它的功能一样（假设您没有手册），您必须测试您的代码以了解它的功能或证明它应该做什么。这就是您确保**软件质量**的方式。

在软件开发过程中，通常会有许多共享某些代码库或库的功能。例如，您可以更改一段代码以修复错误，并在代码的另一个点上创建另一个错误。软件测试也有助于解决这个问题，因为它们确保您的代码执行了应该执行的操作；如果您更改了一段错误的代码并且破坏了另一段代码，您也将破坏一个测试。在这种情况下，如果您使用**持续集成**，则破损的代码将永远不会到达生产环境。

### 提示

不知道什么是持续集成？请参考[`www.martinfowler.com/articles/continuousIntegration.html`](http://www.martinfowler.com/articles/continuousIntegration.html)和[`jenkins-ci.org/`](https://jenkins-ci.org/)。

测试是如此重要，以至于有一个称为**测试驱动开发**（**TDD**）的软件开发过程，它规定测试应该在实际代码之前编写，并且只有当测试本身得到满足时，实际代码才是*准备就绪*。TDD 在高级开发人员及以上中非常常见。就为了好玩，我们将在本章中从头到尾使用 TDD。

# 有哪些测试类型？

我们想要测试，我们现在就想要；但是我们想要什么样的测试呢？

测试有两种主要分类，根据你对内部代码的访问程度：**黑盒**和**白盒**测试。

黑盒测试是指测试人员对其正在测试的实际代码没有知识和/或访问权限。在这些情况下，测试包括检查代码执行前后的系统状态是否符合预期，或者给定的输出是否对应于给定的输入。

白盒测试有所不同，因为您将可以访问您正在测试的实际代码内部，以及代码执行前后的系统预期状态和给定输入的预期输出。这种测试具有更强烈的主观目标，通常与性能和软件质量有关。

在本章中，我们将介绍如何实施黑盒测试，因为它们更容易让其他人接触并且更容易实施。另一方面，我们将概述执行白盒测试的工具。

代码库可能经过多种方式测试。我们将专注于两种类型的自动化测试（我们不会涵盖手动测试技术），每种测试都有不同的目标：**单元测试**和**行为测试**。这些测试各自有不同的目的，并相互补充。让我们看看这些测试是什么，何时使用它们以及如何在 Flask 中运行它们。

## 单元测试

单元测试是一种技术，您可以针对具有有意义功能的最小代码片段（称为**单元**）对输入和预期输出进行测试。通常，您会对代码库中不依赖于您编写的其他函数和方法的函数和方法运行单元测试。

在某种意义上，测试实际上是将单元测试堆叠在一起的艺术（首先测试一个函数，然后相互交互的函数，然后与其他系统交互的函数），以便整个系统最终得到充分测试。

对于 Python 的单元测试，我们可以使用内置模块`doctest`或`unittest`。`doctest`模块用于作为测试用例运行来自对象文档的嵌入式交互式代码示例。Doctests 是 Unittest 的一个很好的补充，Unittest 是一个更健壮的模块，专注于帮助您编写单元测试（正如其名称所暗示的那样），最好不要单独使用。让我们看一个例子：

```py
# coding:utf-8

"""Doctest example"""

import doctest
import unittest

def sum_fnc(a, b):
    """
    Returns a + b

    >>> sum_fnc(10, 20)
    30
    >>> sum_fnc(-10, -20)
    -30
    >>> sum_fnc(10, -20)
    -10
    """
    return a + b

class TestSumFnc(unittest.TestCase):
    def test_sum_with_positive_numbers(self):
        result = sum_fnc(10, 20)
        self.assertEqual(result, 30)

    def test_sum_with_negative_numbers(self):
        result = sum_fnc(-10, -20)
        self.assertEqual(result, -30)

    def test_sum_with_mixed_signal_numbers(self):
        result = sum_fnc(10, -20)
        self.assertEqual(result, -10)

if __name__ == '__main__':
    doctest.testmod(verbose=1)
    unittest.main()
```

在前面的例子中，我们定义了一个简单的`sum_fnc`函数，它接收两个参数并返回它们的和。`sum_fnc`函数有一个解释自身的文档字符串。在这个文档字符串中，我们有一个函数调用和输出的交互式代码示例。这个代码示例是由`doctest.testmod()`调用的，它检查给定的输出是否对于调用的函数是正确的。

接下来，我们有一个名为`TestSumFnc`的`TestCase`，它定义了三个测试方法（`test_<test_name>`），并且几乎完全与我们的文档字符串测试相同。这种方法的不同之处在于，我们能够在没有测试结果的情况下发现问题，*如果*有问题。如果我们希望对我们的文档字符串和测试用例做完全相同的事情，我们将在测试方法中使用`assert` Python 关键字来将结果与预期结果进行比较。相反，我们使用了`assertEqual`方法，它不仅告诉我们如果结果有问题，还告诉我们问题是结果和预期值都不相等。

如果我们希望检查我们的结果是否大于某个值，我们将使用`assertGreater`或`assertGreaterEqual`方法，这样断言错误也会告诉我们我们有什么样的错误。

### 提示

良好的测试彼此独立，以便一个失败的测试永远不会阻止另一个测试的运行。从测试中导入测试依赖项并清理数据库是常见的做法。

在编写脚本或桌面应用程序时，前面的情况很常见。Web 应用程序对测试有不同的需求。Web 应用程序代码通常是响应通过浏览器请求的用户交互而运行，并返回响应作为输出。要在这种环境中进行测试，我们必须模拟请求并正确测试响应内容，这通常不像我们的`sum_fnc`的输出那样直截了当。响应可以是任何类型的文档，它可能具有不同的大小和内容，甚至您还必须担心响应的 HTTP 代码，这包含了很多上下文含义。

为了帮助您测试视图并模拟用户与您的 Web 应用程序的交互，Flask 为您提供了一个测试客户端工具，通过它您可以向您的应用程序发送任何有效的 HTTP 方法的请求。例如，您可以通过`PUT`请求查询服务，或者通过`GET`请求查看常规视图。这是一个例子：

```py
# coding:utf-8

from flask import Flask, url_for, request
import unittest

def setup_database(app):
    # setup database ...
    pass

def setup(app):
    from flask import request, render_template

    # this is not a good production setup
    # you should register blueprints here
    @app.route("/")
    def index_view():
        return render_template('index.html', name=request.args.get('name'))

def app_factory(name=__name__, debug=True):
    app = Flask(name)
    app.debug = debug
    setup_database(app)
    setup(app)
    return app

class TestWebApp(unittest.TestCase):
    def setUp(self):
        # setUp is called before each test method
        # we create a clean app for each test
        self.app = app_factory()
        # we create a clean client for each test
        self.client = self.app.test_client()

    def tearDown(self):
        # release resources here
        # usually, you clean or destroy the test database
        pass

    def test_index_no_arguments(self):
        with self.app.test_request_context():
            path = url_for('index_view')
            resp = self.client.get(path)
            # check response content
            self.assertIn('Hello World', resp.data)

    def test_index_with_name(self):
        with self.app.test_request_context():
            name = 'Amazing You'
            path = url_for('index_view', name=name)
            resp = self.client.get(path)
            # check response content
            self.assertIn(name, resp.data)

if __name__ == '__main__':
    unittest.main()
```

前面的例子是一个完整的例子。我们使用`app_factory`模式来创建我们的应用程序，然后我们在`setUp`中创建一个应用程序和客户端，这在每个测试方法运行之前运行，我们创建了两个测试，一个是当请求接收到一个名称参数时，另一个是当请求没有接收到名称参数时。由于我们没有创建任何持久资源，我们的`tearDown`方法是空的。如果我们有任何类型的数据库连接和固定装置，我们将不得不在`tearDown`中重置数据库状态，甚至删除数据库。

此外，要注意`test_request_context`，它用于在我们的测试中创建一个请求上下文。我们创建这个上下文，以便`url_for`能够返回我们的视图路径，如果没有设置`SERVER_NAME`配置，它需要一个请求上下文。

### 提示

如果您的网站使用子域，设置`SERVER_NAME`配置。

## 行为测试

在单元测试中，我们测试函数的输出与预期结果。如果结果不是我们等待的结果，将引发断言异常以通知问题。这是一个简单的黑盒测试。现在，一些奇怪的问题：您是否注意到您的测试是以与错误报告或功能请求不同的方式编写的？您是否注意到您的测试不能被非技术人员阅读，因为它实际上是代码？

我想向您介绍 lettuce（[`lettuce.it/`](http://lettuce.it/)），这是一个能够将**Gherkin**语言测试转换为实际测试的工具。

### 提示

有关 Gherkin 语言的概述，请访问[`github.com/cucumber/cucumber/wiki/Gherkin`](https://github.com/cucumber/cucumber/wiki/Gherkin)。

Lettuce 可以帮助您将实际用户编写的功能转换为测试方法调用。这样，一个功能请求就像：

功能：计算总和

为了计算总和

作为学生

实现`sum_fnc`

+   **场景**：正数之和

+   **假设**我有数字 10 和 20

+   **当**我把它们加起来

+   **然后**我看到结果 30

+   **场景**：负数之和

+   **假设**我有数字-10 和-20

+   **当**我把它们加起来

+   **然后**我看到结果-30

+   **场景**：混合信号之和

+   **假设**我有数字 10 和-20

+   **当**我把它们加起来

+   **然后**我看到结果-10

该功能可以转换为将测试软件的实际代码。确保 lettuce 已正确安装：

```py
pip install lettuce python-Levenshtein

```

创建一个`features`目录，并在其中放置一个`steps.py`（或者您喜欢的任何其他 Python 文件名），其中包含以下代码：

```py
# coding:utf-8
from lettuce import *
from lib import sum_fnc

@step('Given I have the numbers (\-?\d+) and (\-?\d+)')
def have_the_numbers(step, *numbers):
    numbers = map(lambda n: int(n), numbers)
    world.numbers = numbers

@step('When I sum them')
def compute_sum(step):
    world.result = sum_fnc(*world.numbers)

@step('Then I see the result (\-?\d+)')
def check_number(step, expected):
    expected = int(expected)
    assert world.result == expected, "Got %d; expected %d" % (world.result, expected)
```

我们刚刚做了什么？我们定义了三个测试函数，have_the_numbers，compute_sum 和 check_number，其中每个函数都接收一个`step`实例作为第一个参数，以及用于实际测试的其他参数。用于装饰我们的函数的 step 装饰器用于将从我们的 Gherkin 文本解析的字符串模式映射到函数本身。我们的装饰器的另一个职责是将从步骤参数映射到函数的参数的参数解析为参数。

例如，`have_the_numbers`的步骤具有正则表达式模式（`\-?\d+`）和（`\-?\d+`），它将两个数字映射到我们函数的`numbers`参数。这些值是从我们的 Gherkin 输入文本中获取的。对于给定的场景，这些数字分别是[10, 20]，[-10, -20]和[10, -20]。最后，`world`是一个全局变量，您可以在步骤之间共享值。

使用功能描述行为对开发过程非常有益，因为它使业务人员更接近正在创建的内容，尽管它相当冗长。另外，由于它冗长，不建议在测试孤立的函数时使用，就像我们在前面的例子中所做的那样。行为应该由业务人员编写，也应该测试编写人员可以直观证明的行为。例如，“如果我点击一个按钮，我会得到某物的最低价格”或“假设我访问某个页面，我会看到一些消息或一些链接”。

“点击这里，然后那里发生了什么”。检查渲染的请求响应有点棘手，如果您问我的话。为什么？在我们的第二个例子中，我们验证了给定的字符串值是否在我们的`resp.data`中，这是可以的，因为我们的响应返回`complete`。我们不使用 JavaScript 在页面加载后渲染任何内容或显示消息。如果是这种情况，我们的验证可能会返回错误的结果，因为 JavaScript 代码不会被执行。

为了正确呈现和验证`view`响应，我们可以使用无头浏览器，如**Selenium**或**PhantomJS**（参见[`pythonhosted.org/Flask-Testing/#testing-with-liveserver`](https://pythonhosted.org/Flask-Testing/#testing-with-liveserver)）。**Flask-testing**扩展也会有所帮助。

## Flask-testing

与大多数 Flask 扩展一样，Flask-testing 并没有做太多事情，但它所做的事情都做得很好！我们将讨论 Flask-testing 提供的一些非常有用的功能：LiveServer 设置，额外的断言和 JSON 响应处理。在继续之前，请确保已安装：

```py
pip install flask-testing blinker

```

### LiveServer

LiveServer 是一个 Flask-testing 工具，允许您连接到无头浏览器，即不会将内容可视化呈现的浏览器（如 Firefox 或 Chrome），但会执行所有脚本和样式，并模拟用户交互。每当您需要在 JavaScript 交互后评估页面内容时，请使用 LiveServer。我们将使用 PhantomJS 作为我们的无头浏览器。我给您的建议是，您像我们的祖先一样安装旧浏览器，从源代码编译它。请按照[`phantomjs.org/build.html`](http://phantomjs.org/build.html)上的说明进行操作（您可能需要安装一些额外的库以获得 phantom 的全部功能）。`build.sh`文件将在必要时建议您安装它。

### 提示

编译**PhantomJS**后，确保它在您的 PATH 中被找到，将二进制文件`bin/phantomjs`移动到`/usr/local/bin`。

确保安装了 Selenium：

```py
pip install selenium

```

我们的代码将如下所示：

```py
# coding:utf-8

"""
Example adapted from https://pythonhosted.org/Flask-Testing/#testing-with-liveserver
"""

import urllib2
from urlparse import urljoin
from selenium import webdriver
from flask import Flask, render_template, jsonify, url_for
from flask.ext.testing import LiveServerTestCase
from random import choice

my_lines = ['Hello there!', 'How do you do?', 'Flask is great, ain't it?']

def setup(app):
    @app.route("/")
    def index_view():
        return render_template('js_index.html')

    @app.route("/text")
    def text_view():
        return jsonify({'text': choice(my_lines)})

def app_factory(name=None):
    name = name or __name__
    app = Flask(name)
    setup(app)
    return app

class IndexTest(LiveServerTestCase):
    def setUp(self):
        self.driver = webdriver.PhantomJS()

    def tearDown(self):
        self.driver.close()

    def create_app(self):
        app = app_factory()
        app.config['TESTING'] = True
        # default port is 5000
        app.config['LIVESERVER_PORT'] = 8943
        return app

    def test_server_is_up_and_running(self):
        resp = urllib2.urlopen(self.get_server_url())
        self.assertEqual(resp.code, 200)

    def test_random_text_was_loaded(self):
        with self.app.test_request_context():
            domain = self.get_server_url()
            path = url_for('.index_view')
            url = urljoin(domain, path)

            self.driver.get(url)
            fillme_element = self.driver.find_element_by_id('fillme')
            fillme_text = fillme_element.text
            self.assertIn(fillme_text, my_lines)

if __name__ == '__main__':
    import unittest
    unittest.main()
```

`templates/js_index.html`文件应如下所示：

```py
<html>
<head><title>Hello You</title></head>
<body>
<span id="fillme"></span>

<!-- Loading JQuery from CDN -->
<!-- what's a CDN? http://www.rackspace.com/knowledge_center/article/what-is-a-cdn -->
<script type="text/javascript" src="img/jquery-2.1.3.min.js"></script>
<script type="text/javascript">
  $(document).ready(function(){
    $.getJSON("{{ url_for('.text_view') }}",
    function(data){
       $('#fillme').text(data['text']);
    });
  });
</script>
</body></html>
```

前面的例子非常简单。我们定义了我们的工厂，它创建了我们的应用程序并附加了两个视图。一个返回一个带有脚本的`js_index.html`，该脚本查询我们的第二个视图以获取短语，并填充`fillme` HTML 元素，第二个视图以 JSON 格式返回一个从预定义列表中随机选择的短语。

然后我们定义`IndexTest`，它扩展了`LiveServerTestCase`，这是一个特殊的类，我们用它来运行我们的实时服务器测试。我们将我们的实时服务器设置为在不同的端口上运行，但这并不是必需的。

在`setUp`中，我们使用 selenium WebDriver 创建一个`driver`。该驱动程序类似于浏览器。我们将使用它通过 LiveServer 访问和检查我们的应用程序。`tearDown`确保每次测试后关闭我们的驱动程序并释放资源。

`test_server_is_up_and_running`是不言自明的，在现实世界的测试中实际上是不必要的。

然后我们有`test_random_text_was_loaded`，这是一个非常繁忙的测试。我们使用`test_request_context`来创建一个请求上下文，以便使用`url_open.get_server_url`生成我们的 URL 路径，这将返回我们的实时服务器 URL；我们将这个 URL 与我们的视图路径连接起来并加载到我们的驱动程序中。

使用加载的 URL（请注意，URL 不仅加载了，而且脚本也执行了），我们使用`find_element_by_id`来查找元素`fillme`并断言其文本内容具有预期值之一。这是一个简单的例子。例如，您可以测试按钮是否在预期位置；提交表单；并触发 JavaScript 函数。Selenium 加上 PhantomJS 是一个强大的组合。

### 提示

当您的开发是由功能测试驱动时，您实际上并没有使用**TDD**，而是**行为驱动开发**（**BDD**）。通常，两种技术的混合是您想要的。

### 额外的断言

在测试代码时，您会注意到一些测试有点重复。为了处理这种情况，可以创建一个具有特定例程的自定义 TestCases，并相应地扩展测试。使用 Flask-testing，您仍然需要这样做，但是要编写更少的代码来测试您的 Flask 视图，因为`flask.ext.testing.TestCase`捆绑了常见的断言，许多在 Django 等框架中找到。让我们看看最重要的（在我看来，当然）断言：

+   `assert_context(name, value)`: 这断言一个变量是否在模板上下文中。用它来验证给定的响应上下文对于一个变量具有正确的值。

+   `assert_redirects(response, location)`: 这断言了响应是一个重定向，并给出了它的位置。在写入存储后进行重定向是一个很好的做法，比如在成功的 POST 后，这是这个断言的一个很好的使用案例。

+   `assert_template_used(name, tmpl_name_attribute='name')`：这断言了请求中使用了给定的模板（如果您没有使用 Jinja2，则需要 `tmpl_name_attribute`；在我们的情况下不需要）；无论何时您渲染一个 HTML 模板，都可以使用它！

+   `assert404(response, message=None)`: 这断言了响应具有 404 HTTP 状态码；它对于“雨天”场景非常有用；也就是说，当有人试图访问不存在的内容时。它非常有用。

### JSON 处理

Flask-testing 为您提供了一个可爱的技巧。每当您从视图返回一个 JSON 响应时，您的响应将有一个额外的属性叫做 `json`。那就是您的 JSON 转换后的响应！以下是一个例子：

```py
# example from https://pythonhosted.org/Flask-Testing/#testing-json-responses
@app.route("/ajax/")
def some_json():
    return jsonify(success=True)

class TestViews(TestCase):
    def test_some_json(self):
        response = self.client.get("/ajax/")
        self.assertEquals(response.json, dict(success=True))
```

# 固定装置

良好的测试总是在考虑预定义的、可重现的应用程序状态下执行；也就是说，无论何时您在选择的状态下运行测试，结果都将是等价的。通常，这是通过自己设置数据库数据并清除缓存和任何临时文件（如果您使用外部服务，您应该模拟它们）来实现的。清除缓存和临时文件并不难，而设置数据库数据则不然。

如果您使用 **Flask-SQLAlchemy** 来保存您的数据，您需要在您的测试中某个地方硬编码如下：

```py
attributes = { … }
model = MyModel(**attributes)
db.session.add(model)
db.session.commit()
```

这种方法不易扩展，因为它不容易重复使用（当您将其定义为一个函数和一个方法时，为每个测试定义它）。有两种方法可以为测试填充您的数据库：**固定装置** 和 **伪随机数据**。

使用伪随机数据通常是特定于库的，并且生成的数据是上下文特定的，而不是静态的，但有时可能需要特定的编码，就像当您定义自己的字段或需要字段的不同值范围时一样。

固定装置是最直接的方法，因为您只需在文件中定义您的数据，并在每个测试中加载它。您可以通过导出数据库数据，根据您的方便进行编辑，或者自己编写。JSON 格式在这方面非常受欢迎。让我们看看如何实现这两种方法：

```py
# coding:utf-8
# == USING FIXTURES ===
import tempfile, os
import json

from flask import Flask
from flask.ext.testing import TestCase
from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    gender = db.Column(db.String(1), default='U')

    def __unicode__(self):
        return self.name

def app_factory(name=None):
    name = name or __name__
    app = Flask(name)
    return app

class MyTestCase(TestCase):
    def create_app(self):
        app = app_factory()
        app.config['TESTING'] = True
        # db_fd: database file descriptor
        # we create a temporary file to hold our data
        self.db_fd, app.config['DATABASE'] = tempfile.mkstemp()
        db.init_app(app)
        return app

    def load_fixture(self, path, model_cls):
        """
        Loads a json fixture into the database
        """
        fixture = json.load(open(path))

        for data in fixture:
            # Model accepts dict like parameter
            instance = model_cls(**data)
            # makes sure our session knows about our new instance
            db.session.add(instance)

        db.session.commit()

    def setUp(self):
        db.create_all()
        # you could load more fixtures if needed
        self.load_fixture('fixtures/users.json', User)

    def tearDown(self):
        # makes sure the session is removed
        db.session.remove()

        # close file descriptor
        os.close(self.db_fd)

        # delete temporary database file
        # as SQLite database is a single file, this is equivalent to a drop_all
        os.unlink(self.app.config['DATABASE'])

    def test_fixture(self):
        marie = User.query.filter(User.name.ilike('Marie%')).first()
        self.assertEqual(marie.gender, "F")

if __name__ == '__main__':
    import unittest
    unittest.main()
```

上述代码很简单。我们创建一个 SQLAlchemy 模型，将其链接到我们的应用程序，并在设置期间加载我们的固定装置。在 `tearDow`n 中，我们确保我们的数据库和 SQLAlchemy 会话对于下一个测试来说是全新的。我们的固定装置是使用 JSON 格式编写的，因为它足够快速且可读。

如果我们使用伪随机生成器来创建我们的用户（查找 Google 上关于这个主题的 **模糊测试**），我们可以这样做：

```py
def new_user(**kw):
    # this way we only know the user data in execution time
    # tests should consider it
    kw['name'] = kw.get('name', "%s %s" % (choice(names), choice(surnames)) )
    kw['gender'] = kw.get('gender', choice(['M', 'F', 'U']))
    return kw
user = User(**new_user())
db.session.add(user)
db.session.commit()
```

请注意，由于我们不是针对静态场景进行测试，我们的测试也会发生变化。通常情况下，固定装置在大多数情况下就足够了，但伪随机测试数据在大多数情况下更好，因为它迫使您的应用处理真实场景，而这些通常被忽略。

## 额外 - 集成测试

集成测试是一个非常常用的术语/概念，但其含义非常狭窄。它用于指代测试多个模块一起测试它们的集成。由于使用 Python 从同一代码库中测试多个模块通常是微不足道且透明的（这里导入，那里调用，以及一些输出检查），您通常会听到人们在指代测试他们的代码与不同代码库进行集成测试时使用术语 **集成测试**，或者当系统添加了新的关键功能时。

# 总结

哇！我们刚刚度过了一章关于软件测试的内容！这是令人自豪的成就。我们学到了一些概念，比如 TDD、白盒测试和黑盒测试。我们还学会了如何创建单元测试；测试我们的视图；使用 Gherkin 语言编写功能并使用 lettuce 进行测试；使用 Flask-testing、Selenium 和 PhantomJS 来测试用户角度的 HTML 响应；还学会了如何使用固定装置来控制我们应用程序的状态，以进行正确可重复的测试。现在，您可以使用不同的技术以正确的方式测试 Flask 应用程序，以满足不同的场景和需求。

在下一章中，事情会变得非常疯狂，因为我们的研究对象将是使用 Flask 的技巧。下一章将涵盖蓝图、会话、日志记录、调试等内容，让您能够创建更加健壮的软件。到时见！


# 第八章：Flask 的技巧或巫术 101

在尝试更高级的 Flask 主题之前，你还能等多久？我肯定不能！在本章中，我们将学习技术和模块，这些对于更好更高效地使用 Flask 至关重要。

高质量的软件需要花费很长时间编码，或者低质量的软件可以很快交付？真正的 Web 开发，也就是你在月底拿到薪水的那种，需要可维护性，生产力和质量才能成为可能。

正如我们之前讨论的，软件质量与测试密切相关。衡量软件质量的一种方法是验证其功能与预期功能的接近程度。这种衡量并不考虑质量评估的主观方面。例如，客户可能认为他最新项目的设计很丑，认为一个经过良好测试的，符合功能的 Web 项目是*糟糕的*。在这些情况下，你所能做的就是为设计重构收取一些额外的费用。

### 提示

如果你遇到这种情况，可以让你的客户更接近开发过程，以避免这种情况。尝试在 Google 或 DuckDuckGo 中搜索“scrum”。

在谈论**生产力**和**可维护性**时，方法有很多！你可以购买一个像 PyCharm 或 WingIDE 这样的好的集成开发环境（IDE）来提高你的生产力，或者雇佣第三方服务来帮助你测试你的代码或控制你的开发进度，但这些只能做到这么多。良好的架构和任务自动化将是大多数项目中的最好朋友。在讨论如何组织你的代码以及哪些模块将帮助你节省一些打字之前，让我们讨论一下过早优化和过度设计，这是焦虑的开发人员/分析师/好奇的经理的两个可怕的症状。

# 过度设计

制作软件有点像制作公寓，有一些相似之处。在开始之前，你会提前计划你想要创造的东西，以便将浪费降到最低。与公寓相反，你不必计划你的软件，因为它在开发过程中很可能会发生变化，而且很多计划可能只是浪费。

这种“计划刚刚好”的方法的问题在于你不知道未来会发生什么，这可能会将我们内心的一点点偏执变成一些大问题。一个人可能最终会编写针对完全系统故障或复杂软件需求场景的代码，而这些可能永远不会发生。你不需要多层架构，缓存，数据库集成，信号系统等等，来创建一个 hello world，也不需要少于这些来创建一个 Facebook 克隆。

这里的信息是：不要使你的产品比你知道它需要的更健壮或更复杂，也不要浪费时间计划可能永远不会发生的事情。

### 提示

始终计划合理的安全性，复杂性和性能水平。

# 过早优化

你的软件足够快吗？不知道？那么为什么要优化代码，我的朋友？当你花时间优化你不确定是否需要优化的软件时，如果没有人抱怨它运行缓慢，或者你在日常使用中没有注意到它运行缓慢，你可能正在浪费时间进行过早优化。

所以，开始 Flask 吧。

# 蓝图 101

到目前为止，我们的应用程序都是平面的：美丽的，单文件的 Web 应用程序（不考虑模板和静态资源）。在某些情况下，这是一个不错的方法；减少了对导入的需求，易于使用简单的编辑器进行维护，但是...

随着我们的应用程序的增长，我们发现需要上下文地安排我们的代码。Flask 蓝图允许你将项目模块化，将你的视图分片成“类似应用程序”的对象，称为**蓝图**，这些蓝图可以稍后由你的 Flask 应用程序加载和公开。大型应用程序受益于使用蓝图，因为代码变得更有组织性。

在功能上，它还可以帮助您以更集中的方式配置已注册的视图访问和资源查找。测试、模型、模板和静态资源可以按蓝图进行排序，使您的代码更易于维护。如果您熟悉**Django**，可以将蓝图视为 Django 应用程序。这样，注册的蓝图可以访问应用程序配置，并可以使用不同的路由进行注册。

与 Django 应用程序不同，蓝图不强制执行特定的结构，就像 Flask 应用程序本身一样。例如，您可以将蓝图结构化为模块，这在某种程度上是方便的。

例子总是有帮助的，对吧？让我们看一个蓝图的好例子。首先，在我们的虚拟环境中安装了示例所需的库：

```py
# library for parsing and reading our HTML
pip install lxml
# our test-friendly library
pip install flask-testing

```

然后我们定义了我们的测试（因为我们喜欢 TDD！）：

```py
# coding:utf-8
# runtests.py

import lxml.html

from flask.ext.testing import TestCase
from flask import url_for
from main import app_factory
from database import db

class BaseTest(object):
    """
    Base test case. Our test cases should extend this class.
    It handles database creation and clean up.
    """

    def create_app(self):
        app = app_factory()
        app.config['TESTING'] = True
        return app

    def setUp(self):
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/ex01_test.sqlite'
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

class PostDetailTest(BaseTest, TestCase):
    def add_single_post(self):
        from blog import Post

        db.session.add(Post(title='Some text', slug='some-text', content='some content'))
        db.session.commit()

        assert Post.query.count() == 1

    def setUp(self):
        super(PostDetailTest, self).setUp()
        self.add_single_post()

    def test_get_request(self):
        with self.app.test_request_context():
            url = url_for('blog.posts_view', slug='some-text')
            resp = self.client.get(url)
            self.assert200(resp)
            self.assertTemplateUsed('post.html')
            self.assertIn('Some text', resp.data)

class PostListTest(BaseTest, TestCase):
    def add_posts(self):
        from blog import Post

        db.session.add_all([
            Post(title='Some text', slug='some-text', content='some content'),
            Post(title='Some more text', slug='some-more-text', content='some more content'),
            Post(title='Here we go', slug='here-we-go', content='here we go!'),
        ])
        db.session.commit()

        assert Post.query.count() == 3

    def add_multiple_posts(self, count):
        from blog import Post

        db.session.add_all([
            Post(title='%d' % i, slug='%d' % i, content='content %d' % i) for i in range(count)
        ])
        db.session.commit()

        assert Post.query.count() == count

    def test_get_posts(self):
        self.add_posts()

        # as we want to use url_for ...
        with self.app.test_request_context():
            url = url_for('blog.posts_view')
            resp = self.client.get(url)

            self.assert200(resp)
            self.assertIn('Some text', resp.data)
            self.assertIn('Some more text', resp.data)
            self.assertIn('Here we go', resp.data)
            self.assertTemplateUsed('posts.html')

    def test_page_number(self):
        self.add_multiple_posts(15)

        with self.app.test_request_context():
            url = url_for('blog.posts_view')
            resp = self.client.get(url)

            self.assert200(resp)

            # we use lxml to count how many li results were returned
            handle = lxml.html.fromstring(resp.data)
            self.assertEqual(10, len(handle.xpath("//ul/li")))

if __name__ == '__main__':
    import unittest
    unittest.main()
```

在前面的代码中，我们测试了一个单个视图`blog.posts_view`，它有两个路由，一个用于帖子详细信息，另一个用于帖子列表。如果我们的视图接收到一个`slug`参数，它应该只返回具有 slug 属性值的第一个`Post`；如果没有，它将返回最多 10 个结果。

现在我们可以创建一个视图，使用满足我们测试的蓝图：

```py
# coding:utf-8
# blog.py

from flask import Blueprint, render_template, request
from database import db

# app is usually a good name for your blueprint instance
app = Blueprint(
    'blog',  # our blueprint name and endpoint prefix
    # template_folder points out to a templates folder in the current module directory
    __name__, template_folder='templates'
)

class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    slug = db.Column(db.String(100), nullable=False, unique=True)
    content = db.Column(db.Text(), nullable=False)

    def __unicode__(self):
        return self.title

@app.route("/")
@app.route("/<slug>")
def posts_view(slug=None):
    if slug is not None:
        post = Post.query.filter_by(slug=slug).first()
        return render_template('post.html', post=post)

    # lets paginate our result
    page_number = into(request.args.get('page', 1))
    page = Post.query.paginate(page_number, 10)

    return render_template('posts.html', page=page)
```

创建蓝图非常简单：我们提供蓝图名称，该名称也用作所有蓝图视图的端点前缀，导入名称（通常为`__name__`），以及我们认为合适的任何额外参数。在示例中，我们传递了`template_folder`作为参数，因为我们想使用模板。如果您正在编写服务，可以跳过此参数。另一个非常有用的参数是`url_prefix`，它允许我们为所有路径定义默认的 URL 前缀。

### 提示

如果我们的蓝图名称是`blog`，并且我们注册了一个方法`index_view`，我们对该视图的端点将是`blog.index_view`。端点是对视图的“名称引用”，您可以将其转换为其 URL 路径。

下一步是在我们的 Flask 应用程序中注册我们的蓝图，以便使我们编写的视图可访问。还创建了一个`database.py`模块来保存我们的 db 实例。

请注意，我们的 Post 模型将被`db.create_all`识别，因为它是在`blog.py`中定义的；因此，当模块被导入时，它变得可见。

### 提示

如果您在任何地方导入了一个模块中定义的模型类，那么它的表可能不会被创建，因为 SQLAlchemy 将不知道它。避免这种情况的一种方法是让所有模型都由定义蓝图的模块导入。

```py
# coding:utf-8
# database.py
from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()
## database.py END

# coding:utf-8
# main.py
from flask import Flask
from database import db
from blog import app as blog_bp

def app_factory(name=None):
    app = Flask(name or __name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/ex01.db'

    db.init_app(app)

    # let Flask know about blog blueprint
    app.register_blueprint(blog_bp)
    return app

# running or importing?
if __name__ == '__main__':
    app = app_factory()
    app.debug = True

    # make sure our tables are created
    with app.test_request_context():
        db.create_all()

    app.run()
```

我们在这里有什么？一个`app_factory`，它创建我们的 Flask 应用程序，在`/tmp/`中设置默认数据库，这是一个常见的 Linux 临时文件夹；初始化我们的数据库管理器，在`database.py`中定义；并使用`register_blueprint`注册我们的蓝图。

我们设置了一个例行程序来验证我们是在运行还是导入给定的模块（对于`runtests.py`很有用，因为它从`main.py`导入）；如果我们正在运行它，我们创建一个应用程序，将其设置为调试模式（因为我们正在开发），在临时测试上下文中创建数据库（`create_all`不会在上下文之外运行），并运行应用程序。

模板（`post.html`和`posts.html`）仍然需要编写。您能写出来使测试通过吗？我把它留给你来做！

我们当前的示例项目结构应该如下所示：

![蓝图 101](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-webapp-flask/img/3863_08_01.jpg)

嗯，我们的项目仍然是平的；所有模块都在同一级别上，上下文排列，但是平的。让我们尝试将我们的博客蓝图移动到自己的模块中！我们可能想要这样的东西：

![蓝图 101](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-webapp-flask/img/3863_08_02.jpg)

博客模板位于博客包中的模板文件夹中，我们的模型位于`models.py`中，我们的视图位于`views.py`中（就像 Django 应用程序一样，对吧？）。

可以轻松进行这种更改。主要是创建一个`blog`文件夹，并在其中放置一个带有以下内容的`__init__.py`文件：

```py
# coding:utf-8
from views import *
```

将`Post`类定义和 db 导入移到`models.py`中，并将特定于博客的模板`post.html`和`posts.html`移到包内的`templates`文件夹中。由于`template_folder`是相对于当前模块目录的，因此无需更改我们的蓝图实例化。现在，运行您的测试。它们应该可以正常工作，无需修改。

喝一口水，戴上你的战斗头盔，让我们继续下一个话题：记录！

# 哦，天啊，请告诉我你有日志…

在面对一个你无法完全理解的神秘问题之前，你永远不会知道记录有多么重要。了解为什么会出现问题是人们将记录添加到他们的项目中的第一个，也可能是主要的原因。但是，嘿，什么是记录？

记录是存储有关事件的记录以供以后进一步分析的行为。关于记录的一个重要概念与记录级别有关，它允许您对信息类型和相关性进行分类。

Python 标准库捆绑了一个记录库，实际上非常强大，通过处理程序和消息，可以记录到流、文件、电子邮件或您认为合适的任何其他解决方案。让我们尝试一些有用的记录示例，好吗？

```py
# coding:utf-8
from flask import Flask
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# default flask logging handler pushes messages into the console
# works DEBUG mode only
app.config['LOG_FILENAME'] = '/var/tmp/project_name.log'
# log warning messages or higher
app.config['LOG_LEVEL'] = logging.WARNING
app.config['ADMINS'] = ['you@domain.com']
app.config['ENV'] = 'production'

def configure_file_logger(app, filename, level=logging.DEBUG):
    # special file handler that overwrites logging file after
    file_handler = RotatingFileHandler(
        filename=filename,
        encoding='utf-8',  # cool kids use utf-8
        maxBytes=1024 * 1024 * 32,  # we don't want super huge log files ...
        backupCount=3  # keep up to 3 old log files before rolling over
    )

    # define how our log messages should look like
    formatter = logging.Formatter(u"%(asctime)s %(levelname)s\t: %(message)s")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    app.logger.addHandler(file_handler)

def configure_mail_logger(app, level=logging.ERROR):
    """
    Notify admins by e-mail in case of error for immediate action
    based on from http://flask.pocoo.org/docs/0.10/errorhandling/#error-mails
    """

    if app.config['ENV'] == 'production':
        from logging.handlers import SMTPHandler

        mail_handler = SMTPHandler(
            '127.0.0.1',
            'server-error@domain.com',
            app.config['ADMINS'], 'YourApplication Failed')

        mail_handler.setLevel(level)
        app.logger.addHandler(mail_handler)

if __name__ == '__main__':
    app.debug = True
    configure_file_logger(app, '/var/tmp/project_name.dev.log')
    configure_mail_logger(app)
    app.run()
```

在我们的示例中，我们创建了两个常见的记录设置：记录到文件和记录到邮件。它们各自的方式非常有用。在`configure_file_logger`中，我们定义了一个函数，将一个`RotatingFileHandler`注册到其中，以保存所有具有给定级别或以上的日志消息。在这里，我们不使用常规的`FileHandler`类，因为我们希望保持我们的日志文件可管理（也就是：小）。`RotatingFileHandler`允许我们为我们的日志文件定义一个最大大小，当日志文件大小接近`maxBytes`限制时，处理程序会“旋转”到一个全新的日志文件（或覆盖旧文件）。

记录到文件中非常简单，主要用于跟踪应用程序中的执行流程（主要是 INFO、DEBUG 和 WARN 日志）。基本上，文件记录应该在您有应该记录但不应立即阅读甚至根本不阅读的消息时使用（如果发生意外情况，您可能希望阅读 DEBUG 日志，但其他情况则不需要）。这样，在出现问题时，您只需查看日志文件，看看出了什么问题。邮件记录有另一个目标…

要配置我们的邮件记录器，我们定义一个名为`configure_mail_logger`的函数。它创建并注册一个`SMTPHandler`到我们的记录器在给定的记录级别；这样，每当记录一个具有该记录级别或更高级别的消息时，就会向注册的管理员发送一封电子邮件。

邮件记录有一个主要目的：尽快通知某人（或很多人）发生了重要事件，比如可能危及应用程序的错误。您可能不希望为此类处理程序设置低于 ERROR 的记录级别，因为会有太多的邮件需要跟踪。

关于记录的最后一条建议是，理智的项目都有良好的记录。追溯用户问题报告甚至邮件错误消息是很常见的。定义良好的记录策略并遵循它们，构建工具来分析您的日志，并设置适合项目需求的记录轮换参数。产生大量记录的项目可能需要更大的文件，而没有太多记录的项目可能可以使用较高值的`backupCount`。一定要仔细考虑一下。

# 调试、DebugToolbar 和幸福

在调试模式下运行 Flask 项目（`app.debug = True`）时，每当 Flask 检测到您的代码已更改，它将重新启动您的应用程序。如果给定的更改破坏了您的应用程序，Flask 将在控制台中显示一个非常简单的错误消息，可以很容易地分析。您可以从下往上阅读，直到找到第一行提到您编写的文件的行；这就是错误生成的地方。现在，从上往下阅读，直到找到一行告诉您确切的错误是什么。如果这种方法不够用，如果您需要读取变量值，例如更好地理解发生了什么，您可以使用`pdb`，标准的 Python 调试库，就像这样：

```py
# coding:utf-8
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index_view(arg=None):
    import pdb; pdb.set_trace()  # @TODO remove me before commit
    return 'Arg is %s' % arg

if __name__ == '__main__':
    app.debug = True
    app.run()
```

每当调用`pdb.set_trace`时，将打开一个`pdb`控制台，它非常像 Python 控制台。因此，您可以查询任何您需要的值，甚至进行代码评估。

使用`pdb`很好，但是，如果您只想了解您的请求发生了什么，例如使用的模板，CPU 时间（这可能会让您困惑！），已记录的消息等，Flask-DebugToolbar 可能是一个非常方便的扩展。

## Flask-DebugToolbar

想象一下，您可以直接在渲染的模板中看到您的请求的 CPU 时间，并且可以验证使用哪个模板来渲染该页面，甚至可以实时编辑它。那会很好吗？您想看到它成真吗？那么请尝试以下示例：

首先，确保已安装扩展：

```py
pip install flask-debugtoolbar

```

然后是一些精彩的代码：

```py
# coding:utf-8
from flask import Flask, render_template
from flask_debugtoolbar import DebugToolbarExtension

app = Flask(__name__)
# configure your application before initializing any extensions
app.debug = True
app.config['SECRET_KEY'] = 'secret'  # required for session cookies to work
app.config['DEBUG_TB_TEMPLATE_EDITOR_ENABLED'] = True
toolbar = DebugToolbarExtension(app)

@app.route("/")
def index_view():
    # please, make sure templates/index.html exists ; )
    return render_template('index.html')

if __name__ == '__main__':
    app.run()
```

使用 Flask-DebugToolbar 没有什么神秘的。将`debug`设置为`True`，添加`secret_key`，并初始化扩展。当您在浏览器中打开`http://127.0.0.1:5000/`时，您应该看到类似这样的东西：

![Flask-DebugToolbar](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-webapp-flask/img/3863_08_03.jpg)

右侧的可折叠面板是调试工具栏在每个 HTML 响应中插入的一小部分 HTML，它允许您检查响应，而无需使用`pdb`等调试器。在示例中，我们将`DEBUG_TB_TEMPLATE_EDITOR_ENABLED`设置为`True`；此选项告诉 DebugToolbar 我们希望直接从浏览器中编辑渲染的模板。只需转到**模板** | **编辑模板**来尝试。

# 会话或在请求之间存储用户数据

有时，在应用程序中会出现这样的情况，需要在请求之间保留数据，但无需将其持久化在数据库中，比如用于标识已登录用户的身份验证令牌，或者用户添加到购物车中的商品。在这些危险时刻，请使用 Flask 会话。

Flask 会话是使用浏览器 cookie 和加密实现的请求之间的瞬时存储解决方案。Flask 使用秘钥值来加密您在会话中设置的任何值，然后将其设置在 cookie 中；这样，即使恶意人士可以访问受害者的浏览器，也无法读取 cookie 的内容。

### 提示

由于秘钥用于加密会话数据，因此为您的秘钥设置一个强大的值非常重要。`os.urandom(24)`可能会为部署环境创建一个强大的秘钥。

会话中存储的数据是瞬时的，因为不能保证它在任何时候都会存在，因为用户可能会清除浏览器的 cookie，或者 cookie 可能会过期，但如果您设置了它，它很可能会存在。在开发时，始终考虑这一点。

Flask 会话的一个重大优势是其简单性；您可以像使用常规字典一样使用它，就像这样：

```py
# coding:utf-8

from flask import Flask, render_template, session, flash
from flask.ext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
# strong secret key!!
app.config['SECRET_KEY'] = '\xa6\xb5\x0e\x7f\xd3}\x0b-\xaa\x03\x03\x82\x10\xbe\x1e0u\x93,{\xd4Z\xa3\x8f'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/ex05.sqlite'
db = SQLAlchemy(app)

class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    sku = db.Column(db.String(30), unique=True)
    name = db.Column(db.String(255), nullable=False)

    def __unicode__(self):
        return self.name

@app.route("/cart/add/<sku>")
def add_to_cart_view(sku):
    product = Product.query.filter_by(sku=sku).first()

    if product is not None:
        session['cart'] = session.get('cart') or dict()
        item = session['cart'].get(product.sku) or dict()
        item['qty'] = item.get('qty', 0) + 1
        session['cart'][product.sku] = item
        flash(u'%s add to cart. Total: %d' % (product, item['qty']))

    return render_template('cart.html')

def init():
    """
    Initializes and populates the database
    """
    db.create_all()

    if Product.query.count() == 0:
        db.session.add_all([
            Product(sku='010', name='Boots'),
            Product(sku='020', name='Gauntlets'),
            Product(sku='030', name='Helmets'),
        ])
        db.session.commit()

if __name__ == '__main__':
    app.debug = True

    with app.test_request_context():
        init()

    app.run()
# == END
# cart.html
<html><head>
  <title>Cart</title>
</head><body>
{% with messages = get_flashed_messages() %}
  {% if messages %}
  <ul>
    {% for message in messages %}
    <li>{{ message }}</li>
    {% endfor %}
  {% endif %}
  </ul>
{% endwith %}
</body></html>
```

在示例中，我们定义了一个非常简单的产品模型，带有 ID、名称、sku（用于在商店中识别产品的特殊字段），以及一个视图，将请求的产品添加到用户会话中的购物车中。正如您所看到的，我们并不假设会话中有任何数据，始终保持谨慎。我们也不需要在更改后“保存”会话，因为 Flask 足够聪明，会自动注意到您的会话已经更改并保存它……实际上，这里有一个小技巧。Flask 会话只能检测到会话是否被修改，如果您修改了它的第一级值。例如：

```py
session['cart'] = dict()  # new cart
# modified tells me if session knows it was changed
assert session.modified == True
session.modified = False  # we force it to think it was not meddled with
session['cart']['item'] = dict()
# session does not know that one of its children was modified
assert session.modified == False
# we tell it, forcing a update
session.modified =True
# session will be saved, now
```

现在运行您的项目，并在浏览器中打开 URL `http://localhost:5000/cart/add/010`。看到每次重新加载时计数器是如何增加的吗？嗯，那就是会话在工作！

# 练习

让我们把知识付诸实践吧？尝试制作一个商店网站应用，比如一个在线宠物商店。它应该有宠物服务，例如洗澡和兽医咨询，还有一个小商店，出售宠物配饰。这应该足够简单（很多工作！但是简单）。

# 总结

这是一个密集的章节。我们概述了重要的概念——如性能和可维护性、生产力和质量——快速讨论了过早优化和过度工程化，并将我们的努力集中在学习如何用 Flask 编写更好的代码上。

蓝图允许您使用 Flask 创建强大的大型项目，并通过一个完整的示例进行了讨论；我们学习了如何记录到文件和邮件以及每个的重要性，与 Flask-DebugToolbar 度过了愉快的时光（非常方便！），并且将默认的会话设置和使用牢记在心。

你现在是一个有能力的 Flask 开发者。我感到非常自豱！

就像一个人在尝试漂移之前先学会开车一样，我们将在下一章开始我们的 Flask 漂移。我们的重点将是利用 Flask 提供的广泛扩展生态系统来创建令人惊叹的项目。这将非常有趣！到时见！


# 第九章：扩展，我是如何爱你

我们已经在前几章中使用扩展来增强我们的示例；Flask-SQLAlchemy 用于连接到关系数据库，Flask-MongoEngine 用于连接到 MongoDB，Flask-WTF 用于创建灵活可重用的表单，等等。扩展是一种很好的方式，可以在不妨碍您的代码的情况下为项目添加功能，如果您喜欢我们迄今为止所做的工作，您会喜欢这一章，因为它专门介绍了扩展！

在本章中，我们将了解一些迄今为止忽视的非常流行的扩展。我们要开始了吗？

# 如何配置扩展

Flask 扩展是您导入的模块，（通常）初始化，并用于与第三方库集成。它们通常是从`flask.ext.<extension_name>`（这是扩展模式的一部分）导入的，并应该在 PyPi 存储库中以 BSD、MIT 或其他不太严格的许可证下可用。

扩展最好有两种状态：未初始化和已初始化。这是一个好的做法，因为在实例化扩展时，您的 Flask 应用程序可能不可用。我们在上一章的示例中只有在主模块中导入 Flask-SQLAlchemy 后才进行初始化。好的，知道了，但初始化过程为何重要呢？

嗯，正是通过初始化，扩展才能从应用程序中获取其配置。例如：

```py
from flask import Flask
import logging

# set configuration for your Flask application or extensions
class Config(object):
    LOG_LEVEL = logging.WARNING

app = Flask(__name__)
app.config.from_object(Config)
app.run()
```

在上面的代码中，我们创建了一个配置类，并使用`config.from_object`加载了它。这样，`LOG_LEVEL`就可以在所有扩展中使用，通过对应用实例的控制。

```py
app.config['LOG_LEVEL']
```

将配置加载到`app.config`的另一种方法是使用环境变量。这种方法在部署环境中特别有用，因为您不希望将敏感的部署配置存储在版本控制存储库中（这是不安全的！）。它的工作原理如下：

```py
…
app.config.from_envvar('PATH_TO_CONFIGURATION')
```

如果`PATH_TO_CONFIGURATION`设置为 Python 文件路径，例如`/home/youruser/someconfig.py`，那么`someconfig.py`将加载到配置中。像这样做：

```py
# in the console
export  PATH_TO_CONFIGURATION=/home/youruser/someconfig.py

```

然后创建配置：

```py
# someconfig.py
import logging
LOG_LEVEL = logging.WARNING
```

早期的配置方案都有相同的结果。

### 提示

请注意，`from_envvar`将从运行项目的用户加载环境变量。如果将环境变量导出到您的用户并作为另一个用户（如 www-data）运行项目，则可能无法找到您的配置。

# Flask-Principal 和 Flask-Login（又名蝙蝠侠和罗宾）

如项目页面所述（[`pythonhosted.org/Flask-Principal/`](https://pythonhosted.org/Flask-Principal/)），Flask-Principal 是一个权限扩展。它管理谁可以访问什么以及在什么程度上。通常情况下，您应该与身份验证和会话管理器一起使用它，就像 Flask-Login 的情况一样，这是我们将在本节中学习的另一个扩展。

Flask-Principal 通过四个简单的实体处理权限：**Identity**，**IdentityContext**，**Need**和**Permission**。

+   **Identity**：这意味着 Flask-Principal 识别用户的方式。

+   **IdentityContext**：这意味着针对权限测试的用户上下文。它用于验证用户是否有权执行某些操作。它可以用作装饰器（阻止未经授权的访问）或上下文管理器（仅执行）。

**Need**是您需要满足的标准（啊哈时刻！），以便做某事，比如拥有角色或权限。Principal 提供了一些预设的需求，但您也可以轻松创建自己的需求，因为 Need 只是一个命名元组，就像这样一个：

```py
from collections import namedtuplenamedtuple('RoleNeed', ['role', 'admin'])
```

+   **权限**：这是一组需要，应满足以允许某事。将其解释为资源的守护者。

鉴于我们已经设置好了我们的授权扩展，我们需要针对某些内容进行授权。一个常见的情况是将对管理界面的访问限制为管理员（不要说任何话）。为此，我们需要确定谁是管理员，谁不是。Flask-Login 可以通过提供用户会话管理（登录和注销）来帮助我们。让我们尝试一个例子。首先，确保安装了所需的依赖项：

```py
pip install flask-wtf flask-login flask-principal flask-sqlalchemy

```

然后：

```py
# coding:utf-8
# this example is based in the examples available in flask-login and flask-principal docs

from flask_wtf import Form

from wtforms import StringField, PasswordField, ValidationError
from wtforms import validators

from flask import Flask, flash, render_template, redirect, url_for, request, session, current_app
from flask.ext.login import UserMixin
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_user, logout_user, login_required, current_user
from flask.ext.principal import Principal, Permission, Identity, AnonymousIdentity, identity_changed
from flask.ext.principal import RoleNeed, UserNeed, identity_loaded

principal = Principal()
login_manager = LoginManager()
login_manager.login_view = 'login_view'
# you may also overwrite the default flashed login message
# login_manager.login_message = 'Please log in to access this page.'
db = SQLAlchemy()

# Create a permission with a single Need
# we use it to see if an user has the correct rights to do something
admin_permission = Permission(RoleNeed('admin'))
```

由于我们的示例现在太大了，我们将逐步理解它。首先，我们进行必要的导入并创建我们的扩展实例。我们为`login_manager`设置`login_view`，以便它知道如果用户尝试访问需要用户身份验证的页面时应该重定向到哪里。请注意，Flask-Principal 不处理或跟踪已登录的用户。这是 Flask-Login 的魔术！

我们还创建了我们的`admin_permission`。我们的管理员权限只有一个需求：角色管理员。这样，我们定义了我们的权限接受用户时，这个用户需要拥有角色`admin`。

```py
# UserMixin implements some of the methods required by Flask-Login
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean, default=False)
    username = db.Column(db.String(60), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    roles = db.relationship(
        'Role', backref='roles', lazy='dynamic')

    def __unicode__(self):
        return self.username

    # flask login expects an is_active method in your user model
    # you usually inactivate a user account if you don't want it
    # to have access to the system anymore
    def is_active(self):
        """
        Tells flask-login if the user account is active
        """
        return self.active

class Role(db.Model):
    """
    Holds our user roles
    """
    __tablename__ = 'roles'
    name = db.Column(db.String(60), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __unicode__(self):
        return self.name
```

我们在这里有两个模型，一个用于保存我们的用户信息，另一个用于保存我们的用户角色。角色通常用于对用户进行分类，比如`admin`；您的系统中可能有三个管理员，他们都将拥有管理员角色。因此，如果权限正确配置，他们都将能够执行“管理员操作”。请注意，我们为用户定义了一个`is_active`方法。该方法是必需的，我建议您始终覆盖它，即使`UserMixin`已经提供了实现。`is_active`用于告诉`login`用户是否活跃；如果不活跃，他可能无法登录。

```py
class LoginForm(Form):
    def get_user(self):
        return User.query.filter_by(username=self.username.data).first()

    user = property(get_user)

    username = StringField(validators=[validators.InputRequired()])
    password = PasswordField(validators=[validators.InputRequired()])

    def validate_username(self, field):
        "Validates that the username belongs to an actual user"
        if self.user is None:
            # do not send a very specific error message here, otherwise you'll
            # be telling the user which users are available in your database
            raise ValidationError('Your username and password did not match')

    def validate_password(self, field):
        username = field.data
        user = User.query.get(username)

        if user is not None:
            if not user.password == field.data:
                raise ValidationError('Your username and password did not match')
```

在这里，我们自己编写了`LoginForm`。你可能会说：“为什么不使用`model_form`呢？”嗯，在这里使用`model_form`，您将不得不使用您的应用程序初始化数据库（您目前还没有）并设置上下文。太麻烦了。

我们还定义了两个自定义验证器，一个用于检查`username`是否有效，另一个用于检查`password`和`username`是否匹配。

### 提示

请注意，我们为这个特定表单提供了非常广泛的错误消息。我们这样做是为了避免向可能的攻击者提供太多信息。

```py
class Config(object):
    "Base configuration class"
    DEBUG = False
    SECRET_KEY = 'secret'
    SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/ex03.db'

class Dev(Config):
    "Our dev configuration"
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:////tmp/dev.db'

def setup(app):
    # initializing our extensions ; )
    db.init_app(app)
    principal.init_app(app)
    login_manager.init_app(app)

    # adding views without using decorators
    app.add_url_rule('/admin/', view_func=admin_view)
    app.add_url_rule('/admin/context/', view_func=admin_only_view)
    app.add_url_rule('/login/', view_func=login_view, methods=['GET', 'POST'])
    app.add_url_rule('/logout/', view_func=logout_view)

    # connecting on_identity_loaded signal to our app
    # you may also connect using the @identity_loaded.connect_via(app) decorator
    identity_loaded.connect(on_identity_loaded, app, False)

# our application factory
def app_factory(name=__name__, config=Dev):
    app = Flask(name)
    app.config.from_object(config)
    setup(app)
    return app
```

在这里，我们定义了我们的配置对象，我们的`app`设置和应用程序工厂。我会说，设置是棘手的部分，因为它使用`app`方法注册视图，而不是装饰器（是的，与使用`@app.route`相同的结果），并且我们将我们的`identity_loaded`信号连接到我们的应用程序，以便用户身份在每个请求中都被加载和可用。我们也可以将其注册为装饰器，就像这样：

```py
@identity_loaded.connect_via(app)

# we use the decorator to let the login_manager know of our load_user
# userid is the model id attribute by default
@login_manager.user_loader
def load_user(userid):
    """
    Loads an user using the user_id

    Used by flask-login to load the user with the user id stored in session
    """
    return User.query.get(userid)

def on_identity_loaded(sender, identity):
    # Set the identity user object
    identity.user = current_user

    # in case you have resources that belong to a specific user
    if hasattr(current_user, 'id'):
        identity.provides.add(UserNeed(current_user.id))

    # Assuming the User model has a list of roles, update the
    # identity with the roles that the user provides
    if hasattr(current_user, 'roles'):
        for role in current_user.roles:
            identity.provides.add(RoleNeed(role.name))
```

`load_user` 函数是 Flask-Login 要求的，用于使用会话存储中存储的`userid`加载用户。如果没有找到`userid`，它应该返回`None`。不要在这里抛出异常。

`on_identity_loaded` 被注册到 `identity_loaded` 信号，并用于加载存储在模型中的身份需求。这是必需的，因为 Flask-Principal 是一个通用解决方案，不知道您如何存储权限。

```py
def login_view():
    form = LoginForm()

    if form.validate_on_submit():
        # authenticate the user...
        login_user(form.user)

        # Tell Flask-Principal the identity changed
        identity_changed.send(
            # do not use current_app directly
            current_app._get_current_object(),
            identity=Identity(form.user.id))
        flash("Logged in successfully.")
        return redirect(request.args.get("next") or url_for("admin_view"))

    return render_template("login.html", form=form)

@login_required  # you can't logout if you're not logged
def logout_view():
    # Remove the user information from the session
    # Flask-Login can handle this on its own = ]
    logout_user()

    # Remove session keys set by Flask-Principal
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)

    # Tell Flask-Principal the user is anonymous
    identity_changed.send(
        current_app._get_current_object(),
        identity=AnonymousIdentity())

    # it's good practice to redirect after logout
    return redirect(request.args.get('next') or '/')
```

`login_view` 和 `logout_view` 就像它们的名字一样：一个用于认证，另一个用于取消认证用户。在这两种情况下，您只需确保调用适当的 Flask-Login 函数（`login_user` 和 `logout_user`），并发送适当的 Flask-Principal 信号（并在注销时清除会话）。

```py
# I like this approach better ...
@login_required
@admin_permission.require()
def admin_view():
    """
    Only admins can access this
    """
    return render_template('admin.html')

# Meh ...
@login_required
def admin_only_view():
    """
    Only admins can access this
    """
    with admin_permission.require():
        # using context
        return render_template('admin.html')
```

最后，我们有我们的实际视图：`admin_view` 和 `admin_only_view`。它们两者都做同样的事情，它们检查用户是否使用 Flask-Login 登录，然后检查他们是否有足够的权限来访问视图。这里的区别是，在第一种情况下，`admin_view`使用权限作为装饰器来验证用户的凭据，并在第二种情况下作为上下文。

```py
def populate():
    """
    Populates our database with a single user, for testing ; )

    Why not use fixtures? Just don't wanna ...
    """
    user = User(username='student', password='passwd', active=True)
    db.session.add(user)
    db.session.commit()
    role = Role(name='admin', user_id=user.id)
    db.session.add(role)
    db.session.commit()

if __name__ == '__main__':
    app = app_factory()

    # we need to use a context here, otherwise we'll get a runtime error
    with app.test_request_context():
        db.drop_all()
        db.create_all()
        populate()

    app.run()
```

`populate` 用于在我们的数据库中添加适当的用户和角色，以便您进行测试。

### 提示

关于我们之前的例子需要注意的一点：我们在用户数据库中使用了纯文本。在实际的代码中，你不想这样做，因为用户通常会在多个网站使用相同的密码。如果密码是纯文本，任何访问数据库的人都能知道它并测试它是否与敏感网站匹配。[`flask.pocoo.org/snippets/54/`](http://flask.pocoo.org/snippets/54/)中提供的解决方案可能有助于避免这种情况。

现在这是一个你可以与前面的代码一起使用的`base.html`模板的示例：

```py
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{% block title %}{% endblock %}</title>

  <link rel="stylesheet" media="screen,projection"
    href="https://cdnjs.cloudflare.com/ajax/libs/materialize/0.96.1/css/materialize.min.css" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"/>
  <style type="text/css">
    .messages{
      position: fixed;
      list-style: none;
      margin:0px;
      padding: .5rem 2rem;
      bottom: 0; left: 0;
      width:100%;
      background-color: #abc;
      text-align: center;
    }
  </style>
</head>
<body>
  {% with messages = get_flashed_messages() %}
    {% if messages %}
    <ul class='messages'>
        {% for message in messages %}
        <li>{{ message }}</li>
        {% endfor %}
    </ul>
    {% endif %}
  {% endwith %}

  <header>
     <nav>
      <div class="container nav-wrapper">
        {% if current_user.is_authenticated() %}
        <span>Welcome to the admin interface, {{ current_user.username }}</span>
        {% else %}<span>Welcome, stranger</span>{% endif %}

        <ul id="nav-mobile" class="right hide-on-med-and-down">
          {% if current_user.is_authenticated() %}
          <li><a href="{{ url_for('logout_view') }}?next=/admin/">Logout</a></li>
          {% else %}
          <li><a href="{{ url_for('login_view') }}?next=/admin/">Login</a></li>
          {% endif %}
        </ul>
      </div>
    </nav>
  </header>
  <div class="container">
    {% block content %}{% endblock %}
  </div>
  <script type="text/javascript" src="img/jquery-2.1.1.min.js"></script>
  <script src="img/materialize.min.js"></script>
</body>
</html>
```

请注意，我们在模板中使用`current_user.is_authenticated()`来检查用户是否经过身份验证，因为`current_user`在所有模板中都可用。现在，尝试自己编写`login.html`和`admin.html`，并扩展`base.html`。

## 管理员就像老板一样

Django 之所以如此出名的原因之一是因为它有一个漂亮而灵活的管理界面，我们也想要一个！

就像 Flask-Principal 和 Flask-Login 一样，我们将用来构建我们的管理界面的扩展 Flask-Admin 不需要特定的数据库来使用。你可以使用 MongoDB 作为关系数据库（与 SQLAlchemy 或 PeeWee 一起），或者你喜欢的其他数据库。

与 Django 相反，Django 的管理界面专注于应用程序/模型，而 Flask-Admin 专注于页面/模型。你不能（没有一些重编码）将整个蓝图（Flask 的 Django 应用程序等效）加载到管理界面中，但你可以为你的蓝图创建一个页面，并将蓝图模型注册到其中。这种方法的一个优点是你可以轻松选择所有模型将被列出的位置。

在我们之前的例子中，我们创建了两个模型来保存我们的用户和角色信息，所以，让我们为这两个模型创建一个简单的管理员界面。我们确保我们的依赖已安装：

```py
pip install flask-admin

```

然后：

```py
# coding:utf-8

from flask import Flask
from flask.ext.admin import Admin
from flask.ext.admin.contrib.sqla import ModelView
from flask.ext.login import UserMixin
from flask.ext.sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    active = db.Column(db.Boolean, default=False)
    username = db.Column(db.String(60), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)
    roles = db.relationship(
        'Role', backref='roles', lazy='dynamic')

    def __unicode__(self):
        return self.username

    # flask login expects an is_active method in your user model
    # you usually inactivate a user account if you don't want it
    # to have access to the system anymore
    def is_active(self):
        """
        Tells flask-login if the user account is active
        """
        return self.active

class Role(db.Model):
    """
    Holds our user roles
    """
    __tablename__ = 'roles'
    name = db.Column(db.String(60), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __unicode__(self):
        return self.name

# Flask and Flask-SQLAlchemy initialization here
admin = Admin()
admin.add_view(ModelView(User, db.session, category='Profile'))
admin.add_view(ModelView(Role, db.session, category='Profile'))

def app_factory(name=__name__):
    app = Flask(name)
    app.debug = True
    app.config['SECRET_KEY'] = 'secret'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/ex04.db'

    db.init_app(app)
    admin.init_app(app)
    return app

if __name__ == '__main__':
    app = app_factory()

    # we need to use a context here, otherwise we'll get a runtime error
    with app.test_request_context():
        db.drop_all()
        db.create_all()

    app.run()
```

在这个例子中，我们创建并初始化了`admin`扩展，然后使用`ModelView`向其注册我们的模型，这是一个为我们的模型创建**CRUD**的特殊类。运行此代码，尝试访问`http://127.0.0.1:5000/admin/`；您将看到一个漂亮的管理界面，顶部有一个主页链接，下面是一个包含两个链接的个人资料下拉菜单，指向我们的模型 CRUDs 的**用户**和**角色**。这只是一个非常基本的例子，不算太多，因为你不能拥有一个像那样对所有用户开放的管理界面。

我们向管理员视图添加身份验证和权限验证的一种方法是通过扩展`ModelView`和`IndexView`。我们还将使用一个称为`mixin`的很酷的设计模式：

```py
# coding:utf-8
# permissions.py

from flask.ext.principal import RoleNeed, UserNeed, Permission
from flask.ext.principal import Principal

principal = Principal()

# admin permission role
admin_permission = Permission(RoleNeed('admin'))

# END of FILE

# coding:utf-8
# admin.py

from flask import g
from flask.ext.login import current_user, login_required
from flask.ext.admin import Admin, AdminIndexView, expose
from flask.ext.admin.contrib.sqla import ModelView

from permissions import *

class AuthMixinView(object):
    def is_accessible(self):
        has_auth = current_user.is_authenticated()
        has_perm = admin_permission.allows(g.identity)
        return has_auth and has_perm

class AuthModelView(AuthMixinView, ModelView):
    @expose()
    @login_required
    def index_view(self):
        return super(ModelView, self).index_view()

class AuthAdminIndexView(AuthMixinView, AdminIndexView):
    @expose()
    @login_required
    def index_view(self):
        return super(AdminIndexView, self).index_view()

admin = Admin(name='Administrative Interface', index_view=AuthAdminIndexView())
```

我们在这里做什么？我们重写`is_accessible`方法，这样没有权限的用户将收到一个禁止访问的消息，并重写`AdminIndexView`和`ModelView`的`index_view`，添加`login_required`装饰器，将未经身份验证的用户重定向到登录页面。`admin_permission`验证给定的身份是否具有所需的权限集——在我们的例子中是`RoleNeed('admin')`。

### 提示

如果你想知道 mixin 是什么，请尝试这个链接[`stackoverflow.com/questions/533631/what-is-a-mixin-and-why-are-they-useful`](http://stackoverflow.com/questions/533631/what-is-a-mixin-and-why-are-they-useful)。

由于我们的模型已经具有**创建、读取、更新、删除**（**CRUD**）和权限控制访问，我们如何修改我们的 CRUD 以仅显示特定字段，或阻止添加其他字段？

就像 Django Admin 一样，Flask-Admin 允许你通过设置类属性来更改你的 ModelView 行为。我个人最喜欢的几个是这些：

+   `can_create`: 这允许用户使用 CRUD 创建模型。

+   `can_edit`: 这允许用户使用 CRUD 更新模型。

+   `can_delete`: 这允许用户使用 CRUD 删除模型。

+   `list_template`、`edit_template`和`create_template`：这些是默认的 CRUD 模板。

+   `list_columns`: 这意味着列在列表视图中显示。

+   `column_editable_list`：这表示可以在列表视图中编辑的列。

+   `form`：这是 CRUD 用来编辑和创建视图的表单。

+   `form_args`：这用于传递表单字段参数。像这样使用它：

```py
form_args = {'form_field_name': {'parameter': 'value'}}  # parameter could be name, for example
```

+   `form_overrides`：像这样使用它来覆盖表单字段：

```py
form_overrides = {'form_field': wtforms.SomeField}
```

+   `form_choices`：允许你为表单字段定义选择。像这样使用它：

```py
form_choices = {'form_field': [('value store in db', 'value display in the combo box')]}
```

一个例子看起来像这样：

```py
class AuthModelView(AuthMixinView, ModelView):
    can_edit= False
    form = MyAuthForm

    @expose()
    @login_required
    def index_view(self):
        return super(ModelView, self).index_view()
```

## 自定义页面

现在，如果你想要在管理界面中添加一个自定义的**报告页面**，你肯定不会使用模型视图来完成这个任务。对于这些情况，像这样添加一个自定义的`BaseView`：

```py
# coding:utf-8
from flask import Flask
from flask.ext.admin import Admin, BaseView, expose

class ReportsView(BaseView):
    @expose('/')
    def index(self):
        # make sure reports.html exists
        return self.render('reports.html')

app = Flask(__name__)
admin = Admin(app)
admin.add_view(ReportsView(name='Reports Page'))

if __name__ == '__main__':
    app.debug = True
    app.run()
```

现在你有了一个带有漂亮的报告页面链接的管理界面。不要忘记编写一个`reports.html`页面，以使前面的示例工作。

那么，如果你不希望链接显示在导航栏中，因为你已经在其他地方有了它，怎么办？覆盖`BaseView.is_visible`方法，因为它控制视图是否会出现在导航栏中。像这样做：

```py
class ReportsView(BaseView):
…
  def is_visible(self):
    return False
```

# 摘要

在这一章中，我们只是学习了一些关于用户授权和认证的技巧，甚至尝试创建了一个管理界面。这是相当多的知识，将在你日常编码中帮助你很多，因为安全性（确保人们只与他们可以和应该互动的内容进行互动）是一个非常普遍的需求。

现在，我的朋友，你知道如何开发健壮的 Flask 应用程序，使用 MVC、TDD、与权限和认证控制集成的关系型和 NoSQL 数据库；表单；如何实现跨站点伪造保护；甚至如何使用开箱即用的管理工具。

我们的研究重点是了解 Flask 开发世界中所有最有用的工具（当然是我认为的），以及如何在一定程度上使用它们。由于范围限制，我们没有深入探讨任何一个，但基础知识肯定是展示过的。

现在，你可以进一步提高对每个介绍的扩展和库的理解，并寻找新的扩展。下一章也试图在这个旅程中启发你，建议阅读材料、文章和教程（等等）。

希望你到目前为止已经喜欢这本书，并且对最后的笔记感到非常愉快。


# 第十章：现在怎么办？

Flask 目前是最受欢迎的 Web 框架，因此为它找到在线阅读材料并不难。例如，快速在谷歌上搜索肯定会给你找到一两篇你感兴趣的好文章。尽管如此，像部署这样的主题，尽管在互联网上讨论得很多，但仍然会在我们的网页战士心中引起怀疑。因此，我们在最后一章中提供了一个很好的“像老板一样部署你的 Flask 应用程序”的逐步指南。除此之外，我们还会建议你一些非常特别的地方，那里的知识就在那里，浓厚而丰富，等着你去获取智慧。通过这一章，你将能够将你的产品从代码部署到服务器，也许，只是也许，能够得到一些应得的高分！欢迎来到这一章，在这里代码遇见服务器，你遇见世界！

# 你的部署比我的前任好

部署不是每个人都熟悉的术语；如果你最近还不是一个 Web 开发人员，你可能对它不太熟悉。以一种粗犷的斯巴达方式，我们可以将部署定义为准备和展示你的应用程序给世界的行为，确保所需的资源可用，并对其进行调整，因为适合开发阶段的配置与适合部署的配置是不同的。在 Web 开发的背景下，我们谈论的是一些非常具体的行动：

+   将你的代码放在服务器上

+   设置你的数据库

+   设置你的 HTTP 服务器

+   设置你可能使用的其他服务

+   将所有内容联系在一起

## 将你的代码放在服务器上

首先，什么是服务器？我们所说的服务器是指具有高可靠性、可用性和可维护性（RAS）等服务器特性的计算机。这些特性使服务器中运行的应用程序获得一定程度的信任，即使在出现任何环境问题（如硬件故障）之后，服务器也会继续运行。

在现实世界中，人们有预算，一个普通的计算机（你在最近的商店买的那种）很可能是运行小型应用程序的最佳选择，因为“真正的服务器”非常昂贵。对于小项目预算（现在也包括大项目），创建了一种称为服务器虚拟化的强大解决方案，其中昂贵的高 RAS 物理服务器的资源（内存、CPU、硬盘等）被虚拟化成虚拟机（VM），它们就像真实硬件的较小（更便宜）版本一样。像 DigitalOcean（https://digitalocean.com/）、Linode（https://www.linode.com/）和 RamNode（https://www.ramnode.com/）这样的公司专注于向公众提供廉价可靠的虚拟机。

现在，鉴于我们的 Web 应用程序已经准备就绪（我的意思是，我们的最小可行产品已经准备就绪），我们必须在某个对我们的目标受众可访问的地方运行代码。这通常意味着我们需要一个 Web 服务器。从前面一段提到的公司中选择两台便宜的虚拟机，使用 Ubuntu 进行设置，然后让我们开始吧！

## 设置你的数据库

关于数据库，部署过程中你应该知道的最基本的事情之一是，最好的做法是让你的数据库和 Web 应用程序在不同的（虚拟）机器上运行。你不希望它们竞争相同的资源，相信我。这就是为什么我们雇了两台虚拟服务器——一台将运行我们的 HTTP 服务器，另一台将运行我们的数据库。

让我们开始设置数据库服务器；首先，我们将我们的 SSH 凭据添加到远程服务器，这样我们就可以在不需要每次输入远程服务器用户密码的情况下进行身份验证。在此之前，如果你没有它们，生成你的 SSH 密钥，就像这样：

```py
# ref: https://help.github.com/articles/generating-ssh-keys/
# type a passphrase when asked for one
ssh-keygen -t rsa -b 4096 -C "your_email@example.com"

```

现在，假设您的虚拟机提供程序为您的远程机器提供了 IP 地址、root 用户和密码，我们将如下创建一个无密码的 SSH 身份验证与我们的服务器：

```py
# type the root password when requested
ssh-copy-id root@ipaddress

```

现在，退出您的远程终端，尝试 SSH `root@ipaddress`。密码将不再被请求。

第二步！摆脱非数据库的东西，比如 Apache，并安装 Postgres（[`www.postgresql.org/`](http://www.postgresql.org/)），迄今为止最先进的开源数据库：

```py
# as root
apt-get purge apache2-*
apt-get install postgresql
# type to check which version of postgres was installed (most likely 9.x)
psql -V

```

现在我们设置数据库。

将默认用户 Postgres 连接到角色`postgres`：

```py
sudo -u postgres psql

```

为我们的项目创建一个名为`mydb`的数据库：

```py
CREATE DATABASE mydb;

```

创建一个新的用户角色来访问我们的数据库：

```py
CREATE USER you WITH PASSWORD 'passwd'; # please, use a strong password
# We now make sure "you" can do whatever you want with mydb
# You don't want to keep this setup for long, be warned
GRANT ALL PRIVILEGES ON DATABASE mydb TO you;

```

到目前为止，我们已经完成了很多工作。首先，我们删除了不必要的包（只有很少）；安装了我们的数据库 Postgres 的最新支持版本；创建了一个新的数据库和一个新的“用户”；并授予了我们的用户对我们的新数据库的完全权限。让我们了解每一步。

我们首先删除 Apache2 等内容，因为这是一个数据库服务器设置，所以没有必要保留 Apache2 包。根据安装的 Ubuntu 版本，您甚至需要删除其他包。这里的黄金法则是：安装的包越少，我们就要关注的包就越少。只保留最少的包。

然后我们安装 Postgres。根据您的背景，您可能会问——为什么是 Postgres 而不是 MariaDB/MySQL？嗯，嗯，亲爱的读者，Postgres 是一个完整的解决方案，支持 ACID，文档（JSONB）存储，键值存储（使用 HStore），索引，文本搜索，服务器端编程，地理定位（使用 PostGIS）等等。如果您知道如何安装和使用 Postgres，您就可以在一个单一的解决方案中访问所有这些功能。我也更喜欢它比其他开源/免费解决方案，所以我们将坚持使用它。

安装 Postgres 后，我们必须对其进行配置。与我们迄今为止使用的关系数据库解决方案 SQLite 不同，Postgres 具有基于角色的强大权限系统，控制着可以被访问或修改的资源，以及由谁访问或修改。这里的主要概念是，角色是一种非常特殊的组，它可能具有称为**权限**的权限，或者与之相关或包含它的其他组。例如，在`psql`控制台内运行的`CREATE USER`命令（Postgres 的交互式控制台，就像 Python 的）实际上并不是创建一个用户；实际上，它是在创建一个具有登录权限的新角色，这类似于用户概念。以下命令等同于`psql`内的创建用户命令：

```py
CREATE ROLE you WITH LOGIN;

```

现在，朝着我们最后的目标，有`GRANT`命令。为了允许角色执行操作，我们授予它们权限，比如登录权限，允许我们的“用户”登录。在我们的示例中，我们授予您对数据库`mydb`的所有可用权限。我们这样做是为了能够创建表，修改表等等。通常您不希望您的生产 Web 应用程序数据库用户（哇！）拥有所有这些权限，因为在发生安全漏洞时，入侵者将能够对您的数据库执行任何操作。因为通常（咳咳从不！）不会在用户交互中更改数据库结构，所以在 Web 应用程序中使用一个权限较低的用户并不是问题。

### 提示

PgAdmin 是一个令人惊叹的、用户友好的、Postgres 管理应用程序。只需使用 SSH 隧道（[`www.pgadmin.org/docs/dev/connect.html`](http://www.pgadmin.org/docs/dev/connect.html)），就可以快乐了！

现在测试您的数据库设置是否正常工作。从控制台连接到它：

```py
psql -U user_you -d database_mydb -h 127.0.0.1 -W

```

在被要求时输入你的密码。我们之前的命令实际上是我们在使用 Postgres 时使用的一个技巧，因为我们是通过网络接口连接到数据库的。默认情况下，Postgres 假设你试图使用与你的系统用户名相同的角色和数据库进行连接。除非你像我们一样通过网络接口连接，否则你甚至不能以与你的系统用户名不同的角色名称进行连接。

## 设置 web 服务器

设置你的 web 服务器会更加复杂，因为它涉及修改更多的文件，并确保它们之间的配置是稳固的，但我们会做到的，你会看到的。

首先，我们要确保我们的项目代码在我们的 web 服务器上（这不是与数据库服务器相同的服务器，对吧？）。我们可以以多种方式之一来做到这一点：使用 FTP（请不要），简单的 fabric 加 rsync，版本控制，或者版本加 fabric（开心脸！）。让我们看看如何做后者。

假设你已经在你的 web 服务器虚拟机中创建了一个名为`myuser`的常规用户，请确保已经安装了 fabric：

```py
sudo apt-get install python-dev
pip install fabric

```

还有，在你的项目根目录中创建一个名为`fabfile.py`的文件：

```py
# coding:utf-8

from fabric.api import *
from fabric.contrib.files import exists

env.linewise = True
# forward_agent allows you to git pull from your repository
# if you have your ssh key setup
env.forward_agent = True
env.hosts = ['your.host.ip.address']

def create_project():
    if not exists('~/project'):
        run('git clone git://path/to/repo.git')

def update_code():
    with cd('~/project'):
        run('git pull')
def reload():
    "Reloads project instance"
    run('touch --no-dereference /tmp/reload')
```

有了上述代码和安装了 fabric，假设你已经将你的 SSH 密钥复制到了远程服务器，并已经与你的版本控制提供商（例如`github`或`bitbucket`）进行了设置，`create_project`和`update_code`就可以使用了。你可以像这样使用它们：

```py
fab create_project  # creates our project in the home folder of our remote web server
fab update_code  # updates our project code from the version control repository

```

这非常容易。第一条命令将你的代码放入存储库，而第二条命令将其更新到你的最后一次提交。

我们的 web 服务器设置将使用一些非常流行的工具：

+   **uWSGI**：这用于应用服务器和进程管理

+   **Nginx**：这用作我们的 HTTP 服务器

+   **UpStart**：这用于管理我们的 uWSGI 生命周期

UpStart 已经随 Ubuntu 一起提供，所以我们以后会记住它。对于 uWSGI，我们需要像这样安装它：

```py
pip install uwsgi

```

现在，在你的虚拟环境`bin`文件夹中，会有一个 uWSGI 命令。记住它的位置，因为我们很快就会需要它。

在你的项目文件夹中创建一个`wsgi.py`文件，内容如下：

```py
# coding:utf-8
from main import app_factory

app = app_factory(name="myproject")
```

uWSGI 使用上面的文件中的应用实例来连接到我们的应用程序。`app_factory`是一个创建应用程序的工厂函数。到目前为止，我们已经看到了一些。只需确保它返回的应用程序实例已经正确配置。就应用程序而言，这就是我们需要做的。接下来，我们将继续将 uWSGI 连接到我们的应用程序。

我们可以在命令行直接调用我们的 uWSGI 二进制文件，并提供加载 wsgi.py 文件所需的所有参数，或者我们可以创建一个`ini`文件，其中包含所有必要的配置，并将其提供给二进制文件。正如你可能猜到的那样，第二种方法通常更好，因此创建一个看起来像这样的 ini 文件：

```py
[uwsgi]
user-home = /home/your-system-username
project-name = myproject
project-path = %(user-home)/%(myproject)

# make sure paths exist
socket = %(user-home)/%(project-name).sock
pidfile = %(user-home)/%(project-name).pid
logto = /var/tmp/uwsgi.%(prj).log
touch-reload = /tmp/reload
chdir = %(project-path)
wsgi-file = %(project-path)/wsgi.py
callable = app
chmod-socket = 664

master = true
processes = 5
vacuum = true
die-on-term = true
optimize = 2
```

`user-home`，`project-name`和`project-path`是我们用来简化我们工作的别名。`socket`选项指向我们的 HTTP 服务器将用于与我们的应用程序通信的套接字文件。我们不会讨论所有给定的选项，因为这不是 uWSGI 概述，但一些更重要的选项，如`touch-reload`，`wsgi-file`，`callable`和`chmod-socket`，将得到详细的解释。Touch-reload 特别有用；你指定为它的参数的文件将被 uWSGI 监视，每当它被更新/触摸时，你的应用程序将被重新加载。在一些代码更新之后，你肯定想重新加载你的应用程序。Wsgi-file 指定了哪个文件有我们的 WSGI 兼容应用程序，而`callable`告诉 uWSGI wsgi 文件中实例的名称（通常是 app）。最后，我们有 chmod-socket，它将我们的套接字权限更改为`-rw-rw-r--`，即对所有者和组的读/写权限；其他人可能只读取这个。我们需要这样做，因为我们希望我们的应用程序在用户范围内，并且我们的套接字可以从`www-data`用户读取，这是服务器用户。这个设置非常安全，因为应用程序不能干扰系统用户资源之外的任何东西。

我们现在可以设置我们的 HTTP 服务器，这是一个非常简单的步骤。只需按照以下方式安装 Nginx：

```py
sudo apt-get install nginx-full

```

现在，您的 http 服务器在端口 80 上已经运行起来了。让我们确保 Nginx 知道我们的应用程序。将以下代码写入`/etc/nginx/sites-available`中的名为`project`的文件：

```py
server {
    listen 80;
    server_name PROJECT_DOMAIN;

    location /media {
        alias /path/to/media;
    }
    location /static {
        alias /path/to/static;
    }

    location / {
        include         /etc/nginx/uwsgi_params;
        uwsgi_pass      unix:/path/to/socket/file.sock;
    }
}
```

前面的配置文件创建了一个虚拟服务器，运行在端口 80 上，监听域`server_name`，通过`/static`和`/media`提供静态和媒体文件，并监听将所有访问指向`/`的路径，使用我们的套接字处理。我们现在打开我们的配置并关闭 nginx 的默认配置：

```py
sudo rm /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/project /etc/nginx/sites-enabled/project

```

我们刚刚做了什么？虚拟服务器的配置文件位于`/etc/nginx/sites-available/`中，每当我们希望 nginx 看到一个配置时，我们将其链接到已启用的站点。在前面的配置中，我们刚刚禁用了`default`并通过符号链接启用了`project`。Nginx 不会自行注意到并加载我们刚刚做的事情；我们需要告诉它重新加载其配置。让我们把这一步留到以后。

我们需要在`/etc/init`中创建一个最后的文件，它将使用 upstart 将我们的 uWSGI 进程注册为服务。这部分非常简单；只需创建一个名为`project.conf`（或任何其他有意义的名称）的文件，内容如下：

```py
description "uWSGI application my project"

start on runlevel [2345]
stop on runlevel [!2345]

setuid your-user
setgid www-data

exec /path/to/uwsgi --ini /path/to/ini/file.ini
```

前面的脚本使用我们的项目`ini`文件（我们之前创建的）作为参数运行 uWSGI，用户为"your-user"，组为 www-data。用您的用户替换`your-user`（…），但不要替换`www-data`组，因为这是必需的配置。前面的运行级别配置只是告诉 upstart 何时启动和停止此服务。您不必进行干预。

运行以下命令行来启动您的服务：

```py
start project

```

接下来重新加载 Nginx 配置，就像这样：

```py
sudo /etc/init.d/nginx reload

```

如果一切顺利，媒体路径和静态路径存在，项目数据库设置指向私有网络内的远程服务器，并且上帝对您微笑，您的项目应该可以从您注册的域名访问。击掌！

# StackOverflow

StackOverflow 是新的谷歌术语，用于黑客和软件开发。很多人使用它，所以有很多常见问题和很好的答案供您使用。只需花几个小时阅读关于[`stackoverflow.com/search?q=flask`](http://stackoverflow.com/search?q=flask)的最新趋势，您肯定会学到很多！

# 结构化您的项目

由于 Flask 不强制执行项目结构，您有很大的自由度来尝试最适合您的方式。大型单文件项目可行，类似 Django 的结构化项目可行，平面架构也可行；可能性很多！因此，许多项目都提出了自己建议的架构；这些项目被称为样板或骨架。它们专注于为您提供一个快速启动新 Flask 项目的方法，利用他们建议的代码组织方式。

如果您计划使用 Flask 创建一个大型 Web 应用程序，强烈建议您至少查看其中一个这些项目，因为它们可能已经面临了一些您可能会遇到的问题，并提出了解决方案：

+   Flask-Empty ([`github.com/italomaia/flask-empty`](https://github.com/italomaia/flask-empty))

+   Flask-Boilerplate ([`github.com/mbr/flask-bootstrap`](https://github.com/mbr/flask-bootstrap))

+   Flask-Skeleton ([`github.com/sean-/flask-skeleton`](https://github.com/sean-/flask-skeleton))

# 总结

我必须承认，我写这本书是为了自己。在一个地方找到构建 Web 应用程序所需的所有知识是如此困难，以至于我不得不把我的笔记放在某个地方，浓缩起来。我希望，如果您读到这一段，您也和我一样觉得，这本书是为您写的。这是一次愉快的挑战之旅。

你现在能够构建功能齐全的 Flask 应用程序，包括安全表单、数据库集成、测试，并利用扩展功能，让你能够在短时间内创建强大的软件。我感到非常自豪！现在，去告诉你的朋友你有多棒。再见！

# 附言

作为一个个人挑战，拿出你一直梦想编码的项目，但从未有勇气去做的，然后制作一个 MVP（最小可行产品）。创建你想法的一个非常简单的实现，并将其发布到世界上看看；然后，给我留言。我很乐意看看你的作品！
