# Flask 框架秘籍（一）

> 译者：[Liusple](https://blog.csdn.net/Liusple)
> 
> 来源：<https://blog.csdn.net/liusple/category_7379896.html>

# 第一章：Flask 配置

第一章将会帮助你去理解不同的 Flask 配置方法来满足每个项目各式各样的需求。

在这一章，将会涉及到以下方面：

*   用 virtualenv 搭建环境
*   处理基本配置
*   基于类的配置
*   组织静态文件
*   用实例文件夹（instance floders）进行部署
*   视图和模型的融合（composition）
*   用蓝本（blueprint）创建一个模块化的 web 应用
*   使用 setuptools 使 Flask 应用可安装

## 介绍

> “Flask is a microframework for Python based on Werkzeug, Jinja2 and good intentions.”

何为微小？是不是意味着 Flask 在功能性上有所欠缺或者必须只能用一个文件来完成 web 应用？并不是这样！它说明的事实是 Flask 目的在于保持核心框架的微小但是高度可扩展。这使得编写应用或者扩展非常的容易和灵活，同时也给了开发者为他们的应用选择他们想要配置的余地，没有在数据库，模板引擎和其他方面做出强制性的限制。通过这一章你将会学到一些建立和配置 Flask 的方法。
开始 Flask 几乎不需要 2 分钟。建立一个简单的 Hello World 应用就和烤派一样简单：

```py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello to the World of Flask!'

if __name__ == '__main__':
    app.run() 
```

现在需要安装 Flask，这可以通过 pip 实现：

```py
$ pip install Flask 
```

之前的一小段就是完整的基于 Flask 的 web 应用。导入的 Flask 类创建的实例是一个 web 服务器网关接口(Web Server Gateway Interface WSGI)应用。所以代码里的 app 成为了我们的 WSGI 应用。因为这个一个独立的模块，我们用`__name__` 和`'__main__'` 字符串做比较。如果我们将这些保存为名字是 app.py 的文件，这个应用可以使用下面的命令来运行：

```py
$ python app.py 
 * Running on http://127.0.0.1:5000/ 
```

现在如果在浏览器中输入 http:/127.0.0.1:5000/，将会看见应用在运行。

###### 提示

千万不要将你的文件保存为 flask.py，如果你这样做了，将会和导入的 Flask 冲突。

## 用 virtualenv 搭建环境

Flask 能够通过使用 pip 或者 easy_install 进行安装，但我们应该使用 virtualenv 来创建应用环境。通过为应用创建一个单独的环境可以防止全局 Python 被我们自定义的安装所影响。单独的环境是有用的，因为你可以多个应用程序有同一个库的多个版本，或者一些包可能有相同库的不同版本作为它们的依赖。virtualenv 在单独的环境里管理这些，不会让任何错误版本的库影响到任何其他应用。

#### 怎么做

首先用 pip 安装 virtualenv，然后创建一个名字为 my_flask_env 的环境。这同时会创建一个相同名字的文件夹：

```py
$ pip install virtualenv
$ virtualenv my_flask_env 
```

现在运行下面命令：

```py
$ cd my_flask_env
$ source bin/activate
$ pip install flask 
```

这将激活环境并且在其中安装 Flask。现在可以在这个环境中对我们的应用做任何事情，而不会影响到任何其他 Python 环境。

#### 原理

直到现在，我们已经使用 pip install flask 多次了。顾名思义，这个命令的意思是安装 Flask，就像安装其他 Python 包一样。如果仔细观察一下通过 pip 安装 Flask 的过程，我们将会看到一些包被安装了。下面是 Flask 包安装过程的一些摘要：

```py
$ pip install -U flask
Downloading/unpacking flask
......
......
Many more lines......
......
Successfully installed flask Werkzeug Jinja2 itsdangerous markupsafe
Cleaning up... 
```

###### 提示

在前面的命令中，-U 指的是安装与升级。这将会用最新的版本覆盖已经存在的安装。
如果观察的够仔细，总共有五个包被安装了，分别是 flask，Werkzeug，Jinja2，itsdangerous，markupsafe。Flask 依赖这些包，如果这些包缺失了，Flask 将不会工作。

#### 其他

为了更美好的生活，我们可以使用 virtualenvwrapper。顾名思义，这是对 virtualenv 的封装，使得处理多个 virtualenv 更容易。

###### 提示

记住应该通过全局的方式安装 virtualenvwrapper。所以需要停用还处在激活状态的 virtualenv，可以用下面的命令：

$ deactivate

同时，你可能因为权限问题不被允许在全局环境安装 virtualenvwrapper。这种情况下需要切换到超级用户或者使用 sudo。

可以用下面的命令来安装 virtualenvwrapper：

```py
$ pip install virtualenvwrapper
$ export WORKON_HOME=~/workspace
$ source /usr/local/bin/virtualenvwrapper.sh 
```

在上面的代码里，我们安装了 virtualenvwrapper，创建了一个名字为 WORKON_HOME 的环境变量，同时给它赋值了一个路径，当用 virtualenvwrapper 创建虚拟环境时，虚拟环境将会安装在这个路径下面。安装 Flask 可以使用下面的命令：

```py
$ mkvirtualenv flask
$ pip install flask 
```

停用虚拟环境，只需运行下面的命令：

```py
$ deactivate 
```

激活已经存在的 virtualenv，可以运行下面的命令：

```py
$ workon flask 
```

#### 其他

参考和安装链接如下：

*   [`pypi.python.org/pypi/virtualenv`](https://pypi.python.org/pypi/virtualenv)
*   [`pypi.python.org/pypi/virtualenvwrapper`](https://pypi.python.org/pypi/virtualenvwrapper)
*   [`pypi.python.org/pypi/Flask`](https://pypi.python.org/pypi/Flask)
*   [`pypi.python.org/pypi/Werkzeug`](https://pypi.python.org/pypi/Werkzeug)
*   [`pypi.python.org/pypi/Jinja2`](https://pypi.python.org/pypi/Jinja2)
*   [`pypi.python.org/pypi/itsdangerous`](https://pypi.python.org/pypi/itsdangerous)
*   [`pypi.python.org/pypi/MarkupSafe`](https://pypi.python.org/pypi/MarkupSafe)

## 处理基本配置

首先想到的应该是根据每个需求去配置一个 Flask 应用。这一小节，我们将会去理解 Flask 不同的配置方法。

#### 准备

在 Flask 中，配置能够通过 Flask 的一个名为 config 的属性来完成。config 是字典数据类型的一个子集，我们能够像字典一样修改它。

#### 怎么做

举个例子，需要将我们的应用运行在调试模式下，需要写出下面这样的代码：

```py
app = Flask(__name__)
app.config['DEBUG'] = True 
```

###### 提示

debug 布尔变量可以从 Flask 对象而不是 config 角度来设置：

```py
app.debug = True 
```

同样也可以使用下面这行代码：

```py
app.run(debug=True) 
```

使用调试模将会使服务器在有代码改变的时候自动重载，同时它也在出错的时候提供了非常有用的调试信息。

Flask 还提供了许多配置变量，我们将会在相关的章节接触他们。
当应用越来越大的时候，就产生了在一个文件中管理这些配置的需要。在大部分案例中特定于机器基础的配置都不是版本控制系统的一部分。因为这些，Flask 提供了多种方式去获取配置。常用的几种是：

*   通 pyhton 配置文件(*.cfg)，通过使用:`app.config.from_pyfile('myconfig.cfg')`获取配置

*   通过一个对象，通过使用:`app.config.from_object('myapplication.default_settings')`获取配置或者也可以使用:`app.config.from_object(__name__)` #从当前文件加载配置

*   通过环境变量，通过使用:`app.config.from_envvar('PATH_TO_CONFIG_FILE')`获取配置

#### 原理

Flask 足够智能去找到那些用大写字母写的配置变量。同时这也允许我们在配置文件/对象里定义任何局部变量，剩下的就交给 Flask。

###### 提示

最好的配置方式是在 app.py 里定义一些默认配置，或者通过应用本身的任何对象，然后从配置文件里加载同样的配置去覆盖它们。所以代码看起来像这样：

```py
app = Flask(__name__)
DEBUG = True
TESTING = True
app.config.from_object(__name__) #译者注：这句话作用是导入当前文件里定义的配置，比如 DEBUG 和 TESTING
app.config.from_pyfile('/path/to/config/file') 
```

## 基于类的配置

配置生产，测试等不同模式的方式是通过使用类继承。当项目越来越大，可以有不同的部署模式，比如开发环境，staging，生产等等，每种模式都有一些不同的配置，也会存在一些相同的配置。

#### 怎么做

我们可以有一个默认配置基类，其他类可以继承基类也可以重载或者增加特定发布环境的配置变量。
下面是一个使用默认配置基类的例子：

```py
class BaseConfig(object):
    'Base config class'
    SECRET_KEY = 'A random secret key'
    DEBUG = True
    TESTING = False
    NEW_CONFIG_VARIABLE = 'my value'

class ProductionConfig(BaseConfig):
    'Production specific config'
    DEBUG = False
    SECRET_KEY = open('/path/to/secret/file').read()

class StagingConfig(BaseConfig):
    'Staging specific config'
    DEBUG = True

class DevelopmentConfig(BaseConfig):
    'Development environment specific config'
    DEBUG = True
    TESTING = True
    SECRET_KEY = 'Another random secret key' 
```

###### 提示

SECRET KEY 应该被存储在单独的文件里，因为从安全角度考虑，它不应该是版本控制系统的一部分。应该被保存在机器自身的本地文件系统，或者个人电脑或者服务器。

#### 原理

现在，通过 from_object()可以使用任意一个刚才写的类来加载应用配置。前提是我们将刚才基于类的配置保存在了名字为 configuration.py 的文件里：

```py
app.config.from_object('configuration.DevelopmentConfig') 
```

总体上，这使得管理不同环境下的配置更加灵活和容易。

###### 提示

书源码下载地址：
[`pan.baidu.com/s/1o7GyZUi`](https://pan.baidu.com/s/1o7GyZUi) 密码：x9rw
[`download.csdn.net/download/liusple/10186764`](http://download.csdn.net/download/liusple/10186764)

## 组织静态文件

将 JavaScript，stylesheets，图像等静态文件高效的组织起来是所有 web 框架需要考虑的事情。

#### 怎么做

Flask 推荐一个特定的方式组织静态文件：

```py
my_app/
    - app.py
    - config.py
    - __init__.py
    - static/
        - css/
        - js/
        - images/
            - logo.png 
```

当需要在模板中渲染他们的时候（比如 logo.png），我们可以通过下面方式使用静态文件：

```py
<img src='/statimg/logo.png'> 
```

#### 原理

如果在应用根目录存在一个和 app.py 同一层目录的名字为 static 的文件夹，Flask 会自动的去读这个文件夹下的内容，而不需要任何其他配置。

#### 其它

与此同时，我们可以在 app.py 定义应用的时候为应用对象提供一个名为 static_folder 的参数：

```py
app=Flask(__name__, static_folder='/path/to/static/folder') 
```

在怎么做一节里的 img src 中，static 指的是这个应用 static_url_path 的值。可以通过下面方法修改：

```py
app = Flask(
    __name__, static_url_path='/differentstatic',
    static_folder='/path/to/static/folder'
) 
```

现在，渲染静态文件，可以使用：

```py
<img src='/differentstatic/logo.png'> 
```

###### 提示

通常一个好的方式是使用 url_for 去为静态文件创建 URLS，而不是明确的定义他们：

```py
<img src='{{ url_for('static', filename="logo.png") }}'> 
```

我们将会在下面章节看到更多这样的用法。

## 使用实例文件夹（instance folders）进行特定部署

Flask 也提供了高效管理特定部署的其他方式。实例文件夹允许我们从版本控制系统中费力出特定的部署文件。我们知道不同部署环境比如开发，生产，他们的配置文件是分开的。但还有很多其他文件比如数据库文件，会话文件，缓存文件，其他运行时文件。所以我们可以用实例文件夹像一个 holder bin 一样来存放这些文件。

#### 怎么做

通常，如果在我们的应用里有一个名字问 instance 的文件夹，应用可以自动的识别出实例文件夹：

```py
my_app/
    - app.py
    - instance/
        - config.cfg 
```

在应用对象里，我们可以用 instance_path 明确的定义实例文件夹的绝对路径：

```py
app = Flask(
    __name__, instance_path='/absolute/path/to/instance/folder'
) 
```

为了从实例文件夹加载配置文件，可以在应用对象里使用 instance_relative_config 参数：

```py
app = Flask(__name__, instance_relative_config=True) 
```

这告诉我们的应用从实例文件夹加载配置。下面的实例演示了它如何工作：

```py
app = Flask(
    __name__, instance_path='path/to/instance/folder',
    instance_relative_config=True
)
app.config.from_pyfile('config.cfg', silent=True) 
```

#### 原理

前面的代码，首先，实例文件夹从给定的路径被加载了，然后，配置从实例文件夹里一个名为 config.cfg 的文件中加载。silent=True 是可选的，用来在实例文件夹里没发现 config.cfg 时不报错误。如果 silent=True 没有给出，并且 config.cfg 没有找到，应用将失败，给出下面的错误：

```py
IOError: [Errno 2] Unable to load configuration file (No such file or directory): '/absolute/path/to/config/file' 
```

###### 提示

用 instance_relative_config 从实例文件夹加载配置好像是一个对于的工作，可以使用一个配置方法代替。但是这个过程的美妙之处在于，实例文件夹的概念是完全独立于配置的。

译者注:可以参考[这篇博客](https://www.cnblogs.com/m0m0/p/5624315.html)理解实例文件夹。

## 视图和模型的结合(composition)

随着应用的变大，我们需要用模块化的方式组织我们的应用。下面我们将重构 Hello World 应用。

#### 怎么做

1.  首先在我们的应用里创建一个文件夹，移动所有的文件到这个新的文件夹里。
2.  然后在新建的文件夹里创建一个名为`__init__.py`的文件，这将使得文件夹变成一个模块。
3.  之后，在顶层目录创建一个新的名为 run.py 的文件。从名字可以看出，这个文件将会用来运行这个应用。
4.  最后，创建单独的文件夹作为模块。

通过下面的文件结构可以更好的理解：

```py
flask_app/
    - run.py
    - my_app/
        – __init__.py
        - hello/
            - __init__.py
            - models.py
            - views.py 
```

首先，`flask_app/run.py`文件里的内容看起来像这样：

```py
from my_app import app
app.run(debug=True) 
```

然后，`flask_app/my_app/__init__.py`文件里的内容看起来像这样：

```py
from flask import Flask
app = Flask(__name__)

import my_app.hello.views 
```

然后，存在一个空文件使得文件夹可以作为一个 Python 包，`flask_app/my_app/hello/__init__.py`:

```py
# No content.
# We need this file just to make this folder a python module. 
```

模型文件，`flask_app/my_app/hello/models.py`，有一个非持久性的键值存储：

```py
MESSAGES = {
    'default': 'Hello to the World of Flask!',
} 
```

最后是视图文件，`flask_app/my_app/hello/views.py`。这里，我们获取与请求键相对于的消息，并提供相应的服务创建或更新一条消息：

```py
from my_app import app
from my_app.hello.models import MESSAGES

@app.route('/')
@app.route('/hello')
def hello_world():
    return MESSAGES['default']

@app.route('/show/<key>')
def get_message(key):
    return MESSAGES.get(key) or "%s not found!" % key

@app.route('/add/<key>/<message>')
def add_or_update_message(key, message):
    MESSAGES[key] = message
    return "%s Added/Updated" % key 
```

###### 提示

记住上面的实例代码不能用在生产环境下。仅仅为了让 Flask 初学者更容易理解进行的示范。

#### 原理

可以看到在`my_app/__init__.py`和`my_app/hello/views.py`之间有一个循环导入，前者从后者导入 views，后者从前者导入 app。所以，这实际上将会使得这两个模块相互依赖，但是在这里是没问题的，因为我们不会在`my_app/__init__.py`里使用 views。我们在文件的底部导入 views，所以它们不会被使用到。

在这个实例中，我们使用了一个非常简单的基于内存的非持久化键值对。当然我们能够在 views.py 文件里重写 MESSAGES，但是最好的方式是保持模型层和视图层的相互独立。

现在，可以用 run.py 就可以运行 app 了：

```py
$ python run.py
* Running on http://127.0.0.1:5000/
* Restarting with reloader 
```

###### 提示

上面加载信息表示应用正运行在调试模式下，这个应用将会在代码更改的时候重新加载。

现在可以看到我们在 MESSAGES 里面定义的默认消息。可以通过打开`http://127.0.0.1:5000/show/default`来看到这些消息。通过`http://127.0.0.1:5000/add/great/Flask%20is%20great`增加一个新的消息。这将会更新 MESSAGES 键值对，看起来像这样：

```py
MESSAGES = {
    'default': 'Hello to the World of Flask!',
    'great': 'Flask is great!!',
} 
```

现在可以在浏览器打开`http://127.0.0.1:5000/show/great`，我们将会看到我们的消息，否则会看到一个 not-found 消息。

#### 其他

下一章节，使用蓝图创建一个模块化的 web 应用，提供了一个更好的方式来组织你的 Flask 应用，也是一个对循环导入的现成解决方案。

## 使用蓝图（blueprint）创建一个模块化的 web 应用

蓝图是 Flask 的一个概念用来帮助大型应用真正的模块化。通过提供一个集中的位置来注册应用中的所有组件，使得应用调度变得简单。蓝本看起来像是一个应用对象，但却不是。它看上去更像是一个可插拔（pluggable）的应用或者是一个更大应用的一小部分。一个蓝本实际上是一组可以注册到应用上的操作集合，并且表示了如何构建一个应用。

#### 准备

我们将会利用上一小节的应用做为例子，通过使用蓝图修改它，使它正常工作。

#### 怎么做

下面是一个使用蓝图的 Hello World 例子。它的效果和前一章节相似，但是更加模块化和可扩展。
首先，从`flask_app/my_app/__init__.py`文件开始：

```py
from flask import Flask
from my_app.hello.views import hello

app = Flask(__name__)
app.register_blueprint(hello) 
```

接下来，视图文件，`my_app/hello/views.py`，将会看起来像下面这些代码：

```py
from flask import Blueprint
from my_app.hello.models import MESSAGES

hello = Blueprint('hello', __name__)

@hello.route('/')
@hello.route('/hello')
def hello_world():
    return MESSAGES['default']

@hello.route('/show/<key>')
def get_message(key):
    return MESSAGES.get(key) or "%s not found!" % key

@hello.route('/add/<key>/<message>')
def add_or_update_message(key, message):
    MESSAGES[key] = message
    return "%s Added/Updated" % key 
```

我们在`flask_app/my_app/hello/views.py`文件里定义了一个蓝本。我们不需要在这里使用任何应用对象，完整的路由是通过使用名为 hello 的蓝图定义的。我们用@hello.route 替代了@app.route。这个蓝本在`flask_app/my_app/__init__.py`被导入了，并且注册在了应用对象上。

我们可以在应用里创建任意数量的蓝图和做大部分的活动(activities)，比如提供不同的模板路径和静态文件夹路径。我们甚至为蓝图创建不同的 URL 前缀或者子域。

#### 原理

这个应用的工作方式和上一个应用完全一样。唯一的差别是代码组织方式的不同。

#### 其他

*   理解上一小节，视图和模型的组合，对理解这一章节有所帮助。

## 使用 setuptools 使 Flask 应用可安装

现在我们已经有了一个 Flask 应用了，但是怎么去像安装其他 Python 包一样来安装它呢？

#### 怎么做

使用 Python 的 setuptools 库可以很容易使 Flask 应用可安装。我们需要在应用文件夹里创建一个名为 setup.py 的文件，并且配置它去为应用运行一个安装脚本。它将处理任何依赖，描述，加载测试包，等等。
下面是 Hello World 应用安装脚本 setup.py 的一个简单实例：

```py
#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
from setuptools import setup

setup(
    name = 'my_app',
    version='1.0',
    license='GNU General Public License v3',
    author='Shalabh Aggarwal',
    author_email='contact@shalabhaggarwal.com',
    description='Hello world application for Flask',
    packages=['my_app'],
    platforms='any',
    install_requires=[
        'flask',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
) 
```

#### 原理

前面的脚本里大部分的配置都是不言而喻的。当我们的应用可从 PyPI 可获取时，分类器(classifiers)是有用的。这将会帮助其他用户通过使用分类器(classiflers)来搜索我们的应用。
现在我们可以用 install 关键字来运行这个文件：

```py
$ python setup.py install 
```

这将会安装我们的应用，并且也会安装在 install_requires 里提到的依赖，所以 Flask 和所有 Flask 的依赖都会被安装。现在这个应用可以在 Python 环境里像使用其他 Python 包一样来使用了。



# 第二章：使用 Jinja2 模板

这一章将会从 Flask 的角度来介绍 Jinja2 模板的基础知识；我们同时会学习怎么用模块化和可扩展的模板来创建应用。这一章，将会覆盖以下小节：

*   Bootstrap 布局
*   块组合(block composition)和布局继承(layout inheritance)
*   创建自定义的上下文处理器
*   创建自定义的 Jinja2 过滤器
*   为表单创建自定义宏(custom macro)
*   高级日期和时间格式

## 介绍

在 Flask 中，我们完全可以不用第三方模板引擎写一个完整的 web 应用。举个栗子，看下面的代码；这是一个简单的包含 HTML 样式的 Hello World 应用：

```py
from flask import Flask
app = Flask(__name__)

@app.route('/')
@app.route('/hello')
@app.route('/hello/<user>')
def hello_world(user=None):
    user = user or 'Shalabh'
    return '''
<html>
    <head>
        <title>Flask Framework Cookbook</title>
    </head>
    <body>
        <h1>Hello %s!</h1>
        <p>Welcome to the world of Flask!</p>
    </body>
</html>''' % user

if __name__ == '__main__':
    app.run() 
```

在涉及上千行 HTML，JS 和 CSS 代码的大型应用中，使用上面编写方式可行吗？当然不！
这里，模板拯救了我们，因为我们能够保持模板独立来构建我们的视图代码。Flask 提供了对 Jinja2 的默认支持，不过我们可以使用任何其他合适的模板引擎。进一步来说，Jinja2 提供了许多额外的特性来使我们的模板更加强大和模块化。

## Bootstrap 布局

大部分的 Flask 应用遵循一个特定的方式去布置模板。在这一小节，我们将会讨论 Flask 应用中推荐的布置模板的方式。

#### 准备

通常，Flask 期待模板被放置在应用根目录下名为 templates 的文件夹中。如果这个文件夹是存在的，Flask 将会自动读取目录，使得在使用 render_template()的时候文件下的目标可获得，这些方式将在本书大量的使用。

#### 怎么做

用一个小的应用来演示。这个应用和第一章的应用非常相似。首先需要做的是在 my_app 文件夹下新增一个名为 templates 的文件夹。这个应用结构看起来像下面这样：

```py
flask_app/
    - run.py
    my_app/
        – __init__.py
        - hello/
            - __init__.py
            - views.py
        - templates
        - 
```

我们需要去对应用做些修改。视图文件`my_app/hello/views.py`中的 hello_world 方法将会看起来像这样：

```py
from flask import render_template, request

@hello.route('/')
@hello.route('/hello')
def hello_world():
    user = request.args.get('user', 'Shalabh')
    return render_template('index.html', user=user) 
```

在前面的方法中，我们去查询 URL 查询 user 参数。如果找到，就使用它，如果没找到，就使用默认的值，Shalabh。然后这个值将会被传递到要呈现的模板上下文（context）中，也就是 index.html，稍后渲染后的模板会被加载。
第一步，`my_app/templates/index.html`模板将看起来像这样：

```py
<html>
    <head>
        <title>Flask Framework Cookbook</title>
    </head>
    <body>
        <h1>Hello {{ user }}!</h1>
        <p>Welcome to the world of Flask!</p>
    </body>
</html> 
```

#### 原理

现在在浏览器打开 URL：`http://127.0.0.1:5000/hello`，将会看到一个响应，像下面这样：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/42d4e518a6e81b32a83a6d1e9ed9ad1c.png)

我们也可以传递参数 user 给 URL，比如：`http://127.0.0.1:5000/hello?user=John`，将会看到下面这个响应：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/edf8cc1f79fd94fe9c54fab660d0b300.png)

从 views.py 中可以看出，传递给 URL 的参数可以通过 request 的 request.args.get(‘user’)方法获得，然后传递给了模板上下文中，模板将使用 render_template 进行渲染。使用 Jinja2 占位符{{ user }}解析出这个参数，它的真实值来自于模板上下文中 user 变量值。占位符里放置的所有表达式都依赖于模板上下文。

###### 其他

*   Jinja2 文档可以通过`http://jinja.pocoo.org/`获得。

## 块组合和布局继承

通常一个 web 应用将会有许多不同的页面。但，一个网站内大部分页面的头部和底部是差不多的。同样的，菜单也类似。实际上只有中心内容存在差别，剩下都是一样的。因为这些,Jinja2 提供了一个很好的模板间继承方式。

这是一个很好的实践去构建一个基础模板，包含网站的基本布局比如头部和尾部。

#### 准备

这一小节，我们将会尝试去创建一个小的应用，它包含一个主页和商品页(就像我们看到的购物网站那样)。我们会使用 Bootstrap 去给模板做一个最简约的设计。Bootstrap 可以从`http://getbootstrap.com`下载。

在 models.py 有一些写死的产品数据。他们会在 views.py 被读取，通过 render_template()方法，他们会被当做上下文变量发送给模板。剩下的解析和显示是通过模板语言处理的，在这里就是 Jinja2。

#### 怎么做

看一下项目结构：

```py
flask_app/
    - run.py
    my_app/
        – __init__.py
        - product/
            - __init__.py
            - views.py
            - models.py
    - templates/
        - base.html
        - home.html
        - product.html
    - static/
        - js/
            - bootstrap.min.js
        - css/
            - bootstrap.min.css
            - main.css 
```

上面的结构中，`static/css/bootstrap.min.css`和`static/js/bootstrap.min.js`是可以从 Bootstrap 网站下载的标准文件。run.py 和之前一样。介绍一下应用其余的东西。首先，我们定义了模型，`my_app/product/models.py`。这一章节，我们会使用一个简单的非持久化的键值对存储。我们提前准备了一些写死的商品记录：

```py
PRODUCTS = {
    'iphone': {
        'name': 'iPhone 5S',
        'category': 'Phones',
        'price': 699,
    },
    'galaxy': {
        'name': 'Samsung Galaxy 5',
        'category': 'Phones',
        'price': 649,
    },
    'ipad-air': {
        'name': 'iPad Air',
        'category': 'Tablets',
        'price': 649,
    },
    'ipad-mini': {
        'name': 'iPad Mini',
        'category': 'Tablets',
        'price': 549
    }
} 
```

接下来是视图文件，`my_app/product/views.py`。这里我们将会遵循蓝图方式去写应用。

```py
from werkzeug import abort
from flask import render_template
from flask import Blueprint]
from my_app.product.models import PRODUCTS

product_blueprint = Blueprint('product', __name__)

@product_blueprint.route('/')
@product_blueprint.route('/home')
def home():
    return render_template('home.html', products=PRODUCTS)

@product_blueprint.route('/product/<key>')
def product(key):
    product = PRODUCTS.get(key)
    if not product:
        abort(404)
    return render_template('product.html', product=product) 
```

被传递到 Blueprint 构造函数中的蓝本的名字：product，会被添加到在这个蓝图里定义的端点（endpoints）中。看一下 base.html 代码。

###### 提示

当想终止一个请求并给出特定的错误信息时，使用 abort()会很方便。Flask 提供了一些基本的错误信息页面，也可以根据需要自定义。我们将会在第四章创建自定义的 404 和 500 处理器章节看到相关用法。

应用的配置文件，`my_app/__init__.py`，将会看起来像这样：

```py
from flask import Flask
from my_app.product.views import product_blueprint

app = Flask(__name__)
app.register_blueprint(product_blueprint) 
```

除了 Bootstrap 提供的 CSS 代码，我们有自定义的 CSS 代码，`my_app/static/css/main.css`:

```py
body {
    padding-top: 50px;
}
.top-pad {
    pdding: 40px 15px;
    text-align: center;
} 
```

来看一下模板，第一个模板是所有模板的基础。所以可以被命名为 base.html，位置为`my_app/templates/base.html`：

```py
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Flask Framework Cookbook</title>
        <link href="{{ url_for('static', filename='css/bootstrap.min.css') }}" rel="stylesheet">
        <link href="{{ url_for('static', filename='css/main.css') }}" rel="stylesheet">
    </head>
    <body>
        <div class="navbar navbar-inverse navbar-fixed-top" role="navigation">
            <div class="container">
                <div class="navbar-header">
                    <a class="navbar-brand" href="{{ url_for('product.home') }}">Flask Cookbook</a>
                </div>
            </div>
        </div>
        <div class="container">
            {% block container %}{% endblock %}
        </div>

        <!-- jQuery (necessary for Bootstrap's JavaScript plugins) -->
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.0.0/jquery.min.js"></script>
        <script src="{{ url_for('static', filename='js/bootstrap.min.js') }}"></script>
    </body>
</html> 
```

前面大部分代码是 HTML 和 Jinja2 的语法，前一小节已经接触过了。需要指出的是如何使用 url_for()来获取蓝本 URLs。蓝本的名字将会被添加到所有的端点中。这是非常有用的，因为当我们的应用有大量的蓝本时，其中一些是可以有相似的 URLs。

主页，`my_app/templates/home.html`，我们遍历了所有产品和=并展示他们：

```py
{% extends 'base.html' %}
{% block container %}
    <div class="top-pad">

        {% for id, product in products.items() %}
            <div class="well">
                <h2>
                    <a href="{{ url_for('products.product', key=id) }}">{{ product['name'] }}</a>
                    <small>$ {{ product['price'] }}</small>
                </h2>
            </div>
        {% endfor %}
    </div>
{% endblock %} 
```

###### 译者注

书里原文写的是 products.iteritems()，运行会错误，Python3 下应为 products.items()

单独的产品页面，`my_app/templates/product.html`，看起来像这样：

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        <h1>{{ product['name'] }}
            <small>{{ product['category'] }}</small>
        </h1>
        <h3>$ {{ product['price'] }}</h3>
    </div>
{% endblock %} 
```

#### 原理

在上面的模板结构中，我们可以看到使用了继承模式。base.html 对于所有其他模板而言是一个基础。home.html 从 base.html 继承而来，product.html 继承自 home.html。在 product.html 中，我们重写了在 home.html 中定义的 container 块。运行这个应用，输出看起来像这样：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/86b5f1732255c562574c00ddd8d6b7d6.png)

前面的截图展示了主页的样子。注意浏览器中的 URL。产品页面看起来像这样：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/910eba27398ab61b8d97d3ab48af02a1.png)

#### 其他

*   下面两小节将扩展这个应用

## 创建一个自定义的上下文处理器(context processor)

有时，我们想要在模板里直接计算或者处理一个值。Jinja2 维持了一个宗旨：逻辑处理应该在视图里处理而不能在模板里，目的是保持模板的干净。在这样情况下使用上下文处理器会很方便。我们可以传递值到一个方法里，然后用 Python 进行处理，之后结果会被返回。因此，我们基本上只需在模板上下文里添加一个函数(得益于 Python 允许我们可以传递函数像传递其他对象一样)。

#### 怎么做

让我们以这种格式展示产品名字的描述:Category / Prduct-name:

```py
@product_blueprint.context_processor
def some_processor():
    def full_name(product):
        return '{0} / {1}'.format(product['category'], prodyct['name'])
    return {'full_name': full_name} 
```

一个上下文就是一个简单的字典，可以修改，增加或删除值。任何用@product_blueprint.context_processor 修饰的方法应该返回一个字典，用来更新实际的上下文。

我们可以像这样使用前面的上下文处理器：

```py
{{ full_name(product) }} 
```

下面将这个处理器添加到应用中商品列表里(`flask_app/my_app/templates/product.html`)：

```py
{% extends 'home.html' %}

{% block container %}
    <div class="top-pad">
        <h4>{{ full_name(product) }}</h4>
        <h1>{{ product['name'] }}
            <small>{{ product['category'] }}</small>
        </h1>
        <h3>$ {{ product['price'] }}</h3>
    </div>
{% endblock %} 
```

这个 HTML 页面将看起来像这样：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/4cd9cd63e97bc3bdde78b20d4429f38e.png)

#### 其他

*   通过阅读块组合和布局继承来理解这一小节中的上下文(context)。

## 创建一个自定义的 Jinja2 过滤器

看了前面小节，有经验的开发者可能认为使用上下文处理器来描述商品名字是愚蠢的。我们可以简单的写一个过滤器去得到相同的结果；同时会变得更简洁。使用过滤器去描述商品名字的代码看起来像这样：

```py
@product_blueprint.template_filter('full_name')
def full_name_filter(product):
    return '{0} / {1}'.format(product['category'], product['name']) 
```

可以像下面这样使用它：

```py
{{ product | full_name }} 
```

前面的代码和上一小节的效果是一样的。

###### 译者注

template_filter()方法好像新版本的 Flask 已经取消了，应该使用 add_app_template_filter()替代。
所以注册过滤器代码得改为：

```py
def full_name_filter(product):
    return '{0} / {1}'.format(product['category'], product['name'])

product_blueprint.add_app_template_filter(full_name_filter, 'full_name') 
```

#### 怎么做

让事情变得高端一点，创建一个过滤器来基于本地语言格式化货币：

```py
import ccy
from flask impor request

@app.template_filter('format_currenty')
def format_currency_filter(amount):
    currency_code = ccy.countryccy(request.accept_languages.best[-2:])
    return '{0} {1}'.format(currency_code, amount) 
```

###### 译者注

同上，需改写为：

```py
def format_currency_filter(amount):
    currency_code = ccy.countryccy(request.accept_languages.best[-2:])
    return '{0} {1}'.format(currency_code, amount)

product_blueprint.add_app_template_filter(format_currency_filter, 'format_currency') 
```

###### 提示

request.accept_language 列表在请求里没有 ACCEPT-LANGUAGE 头的时候可能会无效。

前面一小段代码需要安装包：ccy：

```py
$ pip install ccy 
```

这个过滤器将会获取最匹配当前浏览器配置的语言（我的是 en-US），然后从配置字符串里获取最后两个字符，然后根据最后两个字符表示的 ISO 国家代码去获取货币。

#### 原理

这个过滤器可以在模板里这样使用：

```py
<h3>{{ product['price'] | format_currenty }}</h3> 
```

结果看起来像这样：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/658aabe53038f7e8f7030b3a7ed16b62.png)

## 为表单创建一个自定义的宏（macro）

宏允许我们去编写可以重复使用的 HTML 代码。它们类似于常规编程语言中的函数。我们可以传递参数给宏就像我们在 Python 中对函数做的那样，然后我们可以使用宏去处理 HTML 块。宏可以被调用任意次数，输出将会根据其中的逻辑而变化。

#### 准备

在 Jinja2 中使用宏非常普遍的并且有很多使用案例。这里我们将看到如何创建一个宏和如何使用它。

#### 怎么做

输入表单是 HTML 许多冗余代码中的一个。大部分字段（fields）都有相似的代码，仅仅是样式做了些修改。下面是一个宏，它在调用的时候创建输入字段。为了更好的服用，创建宏的方式最好方式是在一个单独的文件里进行，比如`_helpers.html`:

```py
{% macro render_field(name, class='', value='', type='text') -%}
    <input type="{{ type }}" name="{{ name }}" class="{{ class }}" value="{{ value }}">
{%- endmacro %} 
```

###### 提示

在/之前%之后的减号（-）将会消除代码块之前之后的空格，使 HTML 代码能容易阅读。

现在，这个宏使用前需导入：

```py
{% from '_helpers.html' import render_field %} 
```

然后，使用方法如下：

```py
<fieldset>
    {{ render_field('username', 'icon-user') }}
    {{ render_field('password', 'icon-key', type='password') }}
</fieldset> 
```

这是一个很好的实践是在不同文件里定义不同的宏来保持代码的简洁和增加代码的可读性。如果一个宏不能在当前文件之外访问，需要在名称前面加上一个下划线来命名宏。

## 高级的时间和日期格式

在 web 应用里格式化日期和时间是一个很痛苦的事情。使用 datetime 库在 Python 层面处理增加了开销，正确的处理时区也是非常复杂的。当存储到数据库时，我们都需要标准化时间戳到 UTC，但是需要向全时间用户展示的时候，时间戳每次都需要被处理。
更机智的方式是在客户端处理他们，也就是在浏览器。浏览器总是知道用户的准确时区，并能够正确的处理时间和日期。同时，减少应用不必要的消耗。为此，我们将使用 Moment.js。

#### 准备

和其他 JS 库一样，我们的应用可以用下面的方式包含 Moment.js。我们仅仅需要将 moment.min.js 文件放置在 static/js 文件夹中。通过添加下面的代码和其他 JS 库，Moment.js 将在 HTML 中变得可用：

```py
<script src="/static/js/moment.min.js"></script> 
```

基本的使用 Moment.js 的方法见下面代码。可以在浏览器的控制台使用它们：

```py
>>> moment().calendar();
"Today at 4:49 PM"
>>> moment().endOf('day').fromNow();
"in 7 hours"
>>> moment().format('LLLL');
"Tuesday, April 15 2014 4:55 PM" 
```

###### 译者注

导入 moment.min.js 最好在页头导入，如果在页尾导入，会出现 moment is not defined 的错误。

#### 怎么做

在我们的应用里使用 Moment.js 最好的方式是用 Python 写一个修饰器（wrapper），然后通过 Jinja2 环境变量使用它。更多信息参见`http://runnable.com/UqGXnKwTGpQgAAO7/dates-and-times-in-flask-for-python`寻求更多信息:

```py
from jinja2 import Markup

class momentjs(object):
    def __init__(self, timestamp):
        self.timestamp = timestamp

    # Wrapper to call moment.js method
    def render(self, format):
        return Markup("<script>\ndocument.write(moment(\"%s\").%s);\n</script>" %(self.timestamp.strftime("%Y-%m-%dT%H:%M:%S"), format))

    # Format time
    def format(self, fmt):
        return self.render("format(\"%s\")" % fmt)

    def calendar(self):
        return self.render("calendar()")

    def fromNow(self):
        return self.render("fromNow()") 
```

当我们需要的时候可以添加许多 Moment.js 方法到之前的类中。现在，在 app.py 文件中，我们设置这个类到 Jinja 环境变量中。

```py
# Set jinja template global
app.jinja_env.globals['momentjs'] = momentjs 
```

可以在模板中像下面这样使用它：

```py
<p>Current time: {{ momentjs(timestamp).calendar() }}</p>
<br/>
<p>Time: {{momentjs(timestamp).format('YYYY-MM-DD HH:mm:ss')}}</p>
<br/>
<p>From now: {{momentjs(timestamp).fromNow()}}</p> 
```

#### 其他

*   Moment.js 库的更多信息参见：`http://momentjs.com/`



# 第三章：Flask 中的数据模型

这一章将会覆盖任何应用中最重要的部分：和数据库的交互。本章中将介绍如何用 Flask 连接数据库系统，定义模型，查询数据。

本章将包含下面小节：

*   创建一个 SQLAlchemy DB 实例
*   创建一个基本的商品模型
*   创建一个关系类别模型
*   使用 Alembic 和 Flask-Migrate 实现数据库迁移（migration）
*   用 Redis 建立模型数据索引
*   使用非关系型数据库 MongoDB

## 介绍

Flask 被设计的足够灵活来支持任何数据库。最简单的方式是直接使用 sqlite3，sqlite3 它提供了 DB-API2.0 接口，不提供 ORM。sqlite3 使用 SQL 语句和数据库对话。这种方法不推荐用来构建大型应用，因为最终维护应用会变成一个噩梦。同样，用这种方法实际上是不存在模型的，所有的事情在视图函数中进行，比如在视图函数中编写查询语句去和数据库交互。

本章我们将使用广泛使用的 SQLAlchemy 为 Flask 应用创建一个 ORM 层。同时学习如何编写一个使用 NoSQL 数据库的 Flask 应用。

###### 提示

ORM 的指的是对象关系映射（Object Relation Mapping/Modeling），抽象的表明了我们的应用数据如何存储，如何处理。强大的 ORM 使得设计和查询业务逻辑非常简单和简洁。

## 创建一个 SQLAlchemy DB 实例

SQLAlchemy 是一个 Python SQL 工具集，它提供了一个 ORM，可以灵活高效的处理 SQL，并且通过它能够感受到 Python 的面向对象特性。

#### 准备

Flask-SQLAlchemy 是一个扩展，为 Flask 提供了 SQLAlchemy 接口。
安装 Flask-SQLAlchemy:

```py
$ pip install flask-sqlalchemy 
```

使用 Flask-SQLAlchemy 首先要做的是设置应用配置参数，告诉 SQLAlchemy 数据库的位置：

```py
app.config['SQLALCHENY_DATABASE_URI'] = os.environ('DATABASE_URI') 
```

SQLALCHEMY_DATABASE_URI 是数据库协议的组合，需要认证，需要数据库的名字。用 SQLite 举例，它看起来像这样：

```py
sqlite:tmp/test.db 
```

用 PostgreSQL 举例，看起来像这样：

```py
postgresql://yourusername:yourpassword@localhost/yournewdb. 
```

这个扩展提供了一个叫做 Model 的类，它用来为我们的应用定义模型。了解更多数据库 URLS 参见
`http://docs.sqlalchemy.org/en/rel_0_9/core/engines.html#database-urls`。

###### 提示

除了 SQLite，都需要安装独立的数据库。比如，如果需要使用 PostgreSQL,需要安装 psycopg2.

#### 怎么做

用一个小应用进行演示。下面的小节也一直会使用这个应用。这里，我们将会看到如何创建一个 db 实例，和一些基本的 DB 命令。文件结构看起来像这样：

```py
flask_catalog/
    - run.py
    my_app/
        - __init__.py 
```

首先从 flask_app/run.py 开始，这已经在书里见到很多次了：

```py
from my_app import app
app.run(debug=True) 
```

然后是应用配置文件，`flask_app/my_app/__init__.py`:

```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:tmp/test.sqlite'
db = SQLAlchemy(app) 
```

###### 译者注

原书为 from flask.ext.sqlalchemy import SQLAlchemy，现已不建议这么使用。
原书为 sqlite:tmp/test.db，改为 sqlite:tmp/test.sqlite。

我们配置 SQLALCHEMY_DATABASE_URI 为一个特定的路径。然后我们创建了一个 SQLAlchemy 对象叫做 db。从名字可以看出，这个对象将会处理所有和 ORM 相关的活动。之前提到过，db 对象有一个名为 Model 的类，它提供了在 Flask 创建模型的基础。任何类都可以继承 Model 去创建模型，模型将作为数据库表。

现在如果在浏览器打开`http://127.0.0.1:5000`，我们看不到任何东西。因为应用里就没有东西。

#### 更多

有时你可能需要一个单独的 SQLAlchemy db 实例可以被多个应用使用或者动态的创建应用。在这些情况下，我们不会讲一个 db 实例绑定在一个单独的应用上。这里我们必须和应用上下文一起工作以达到预期的结果。
这种情况下，使用 SQLAlchemy 注册方式将有所不同：

```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    db.init_app(app)
    return app 
```

###### 提示

上面的方法也可以用来初始化其他 Flask 扩展，而且这在实际应用中是很通常的做法。

现在，所有使用全局 db 实例的操作都需要一个 Flask 上下文了：

```py
Flask application context
>>> from my_app import create_app
>>> app = create_app()
>>> app.test_request_context().push()
>>> # Do whatever needs to be done
>>> app.test_request_context().pop()
Or we can use context manager
with app():
    # We have flask application context now till we are inside the with block 
```

#### 其他

*   下面章节将扩展当前的应用为一个完整的应用，以帮助我们更好的理解 ORM

## 创建一个基本的商品模型

这一小节，我们将创建一个应用帮助我们在网站目录中显示商品。它也可以用来向目录中添加商品也可以根据需要删除他们。从前面章节可以看到，也可以使用非持久化的存储，但是现在我们将数据存储在数据库里做持久化存储。

#### 怎么做

文件夹目录看起来像这样：

```py
flask_catalog/
    - run.py
    my_app/
        – __init__.py
        catalog/
            - __init__.py
            - views.py
            - models.py 
```

首先，修改应用配置文件，`flask_catalog/my_app/__init__.py`：

```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:tmp/test.sqlite'
db = SQLAlchemy(app)

from my_app.catalog.views import catalog
app.register_blueprint(catalog)

db.create_all() 
```

最后一句 db.create_all()，告诉应用在特定的数据库里创建所有的表。所以，当应用运行的时候，如果表不存在的话，所有的表将会创建。现在是时候去在`flask_catalog/my_app/catalog/models.py`中创建模型了：

```py
from my_app import db

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    price = db.Column(db.Float)

    def __init__(self, name, price):
        self.name = name
        self.price = price

    def __repr__(self):
        return '<Product %d>' % self.id 
```

这个文件中，我们创建了一个叫做 Product 的模型，它有三个字段，id，name，price。id 是一个自增长的字段，它会存储记录的 ID 并且做为主键。name 是一个字符串类型的字段，price 是浮点类型的。

现在为视图添加一个新的文件，`flask_catalog/my_app/catalog/views.py`。在这个文件里我们有许多视图方法来处理商品模型和应用：

```py
from flask import request, jsonify, Blueprint
from my_app import app, db
from my_app.catalog.models import Product

catalog = Blueprint('catalog', __name__)

@catalog.route('/')
@catalog.route('/home')
def home():
    return "Welocme to the Catolog Home." 
```

这个方法处理了主页看起来像什么样子。大多数情况下会在应用里使用模板进行渲染。我们稍后会继续讨论这个问题，现在看下下面的代码：

```py
@catalog.route('/product/<id>')
def product(id):
    product = Product.query.get_or_404(id)
    return 'Product - %s, $%s' % (product.name, product.price) 
```

这个方法控制了当用户用商品特定 ID 进行搜索时的输出。我们用 ID 过滤商品，当商品被找到的时候返回它的信息；如果没有找到，产生一个 404 错误。看下面的代码：

```py
@catalog.route('/products')
def products():
    products = Product.query.all()
    res = {}
    for product in products:
        res[product.id] = {
            'name': product.name,
            'price': str(product.price)
    }
    return jsonify(res) 
```

这个方法以 JSON 格式返回了所有商品信息。看下面代码：

```py
@catalog.route('/product-create', methods=['POST',])
def create_product():
    name = request.form.get('name')
    price = request.form.get('price')
    product = Product(name, price)
    db.session.add(product)
    db.session.commit()
    return "Product created" 
```

这个方法控制了数据库中商品的创建。我们首先从 request 请求中获取信息，然后用这些信息创建一个 Product 实例。然后将这个 Product 实例添加到数据库会话中（session），然后提交保存这条记录到数据库。

#### 原理

首先，数据库是空的没有任何商品。这可以通过在浏览器打开`http://127.0.0.1:5000/products`进行确认。页面上仅仅会显示一个{}。
现在，要去创建一个商品。为此我们需要发送一个 POST 请求，POST 请求可以很容易的通过使用 Python request 库实现：

```py
>>> import requests
>>> requests.post('http://127.0.0.1:5000/product-create', data={'name': 'iPhone 5S', 'price': '549.0'}) 
```

想要确认商品是否在数据库里了，可以在浏览器里再一次输入`http://127.0.0.1:5000/products`。这次，它会以 JSON 的形式输出商品信息。

#### 其他

*   在下一小节，创建一个关系类别模型，中将会演示表之间的关系

## 创建一个关系类别模型

前一小节，我们创建了一个简单的商品模型。但是，在实际情况下，应用会更加复杂，各个表之间有各种各样的关系（relationships）。这些关系可以是一对一的，一对多的，多对一的，或者是多对多的。这一小节，我们将用例子去理解他们中的一些。

#### 怎么做

假设我们每个商品类别可以有多个商品，但是每个商品至少有一个类别。让我们修改之前的一些代码，同时对模型和视图做出修改。在模型中我们增加了一个 Category 模型，在视图中，我们增加了新的方法去处理类别相关的调用。

首先修改 models.py，增加 Category 模型，并且修改 Product 模型：

```py
from my_app import db

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    price = db.Column(db.Float)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    category = db.relationship('Category', backref=db.backref('products', lazy='dynamic'))

    def __init__(self, name, price, category):
        self.name = name
        self.price = price
        self.category = category

    def __repr__(self):
        return '<Product %d>' % self.id 
```

在前面的 Product 模型中，注意新增加的两个字段 category_id 和 category。category_id 是 Category 模型的外键，category 代表关系表。从他们的定义可以看出一个是关系，另一个使用这个关系在数据库中存储外键值。这是一个从商品到类别的简单多对一的关系。同时，注意 category 字段中的 backref 参数；这个参数允许我们可以在视图里编写 category.prodycts 从 Category 模型获取商品。从另一端看这一个一对多的关系。考虑下面代码：

```py
calss Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Category %d>' % self.id 
```

前面的代码是 Category 模型，它仅仅只有一个 name 字段。
现在修改 views.py 来适应模型的改变：

```py
from my_app.catalog.models import Product, Category

@catalog.route('/products')
def products():
    products = Product.query.all()
    res = {}
    for product in products:
        res[product.id] = {
            'name': product.name,
            'price': product.price,
            'category': product.category.name
        }
    return jsonify(res) 
```

这里，我们只做了一个修改，在返回商品 JSON 信息的时候添加了 category 信息。看下面的代码：

```py
@catalog.route('/product-create', methods=['POST',])
def create_product():
    name = request.form.get('name')
    price = request.form.get('price')
    categ_name = request.form.get('category')
    category = Category.query.filter_by(name=categ_name).first()
    if not category:
        category = Category(categ_name)
    product = Product(name, price, category)
    db.session.add(product)
    db.session.commit()
    return "Product created." 
```

看一下是如何在创建商品之前查找类别的。首先，使用请求中的类别名在已经存在的类别里进行搜索。如果找到了，就使用它进行商品的创建。否则，就创建一个新的类别。看下面的代码：

```py
@catalog.route('/category-create', methods=['POST',])
def create_category():
    name = request.form.get('name')
    category = Category(name)
    db.session.add(category)
    db.session.commit()
    return 'Category created.' 
```

前面的是一个非常简单的使用请求里的 name 来创建类别的方法。看下面的代码：

```py
@catalog.route('/categories')
def categories():
    categories = Category.query.all()
    res = {}
    for category in categoires:
        res[category.id] = {
            'name': category.name
        }
        for product in category.products:

            res[category.id]['products'] = {
                'id': product.id,
                'name': product.name,
                'price': product.price
            }
    return jsonify(res) 
```

上面代码有点复杂。首先从数据库里获取到所有的类别信息，然后遍历每个类别，获取所有的商品信息，然后用 JSON 的形式返回。

###### 译者注

上面代码是存在问题的，它的原意是想列出每个类别下所有的商品，但是结果只能列出一个。可以改为：

```py
@catalog.route('/categories')
def categories():
    categories = Category.query.all()
    res = {}
    for category in categories:
        res[category.id] = {
            'name': category.name
        }
        res[category.id]['products'] = []
        for product in category.products:
            p = {
                'id': product.id,
                'name': product.name,
                'price': product.price
            }
            res[category.id]['products'].append(p)
    return jsonify(res) 
```

## 使用 Alembic 和 Flask-Migrate 进行数据库迁移（migration）

现在我们想要在 Product 模型中添加一个新的叫做 company 的字段。一种方式是去通过使用 db.drop_all()和 db.create_all()删除数据库然后新建一个。但是，这种方法不能用于生产中。我们希望迁移我们的数据库到最新的模型，并保持所有数据完整。
为此，我们使用 Alembic，这是一个基于 Python 的工具来管理数据库迁移和使用 SQLAlchemy 作为底层引擎。Alembic 在很大程度上提供了自动迁移，但有一些限制(当然，我们不能期望任何工具是完美的)。我们使用一个叫做 Flask-Migrate 的扩展来简化迁移的过程。

#### 准备

先安装 Flask-Migrate

```py
$ pip install Flask-Migrate 
```

这个将会安装 Flask-Script 和 Alembic 还有其他一些依赖。Flask-Script 使得 Flask-Migrate 提供一些简单使用的命令行参数，这些参数对用户而言是一个高级别的抽象，并且隐藏了所有复杂的特性（如果需要的话事实上也不是很难的去自定义）。

#### 怎么做

为了能够迁移，需要稍微去修改一下 app 定义，`my_app/__init__.py`看起来像这样：

```py
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:tmp/test.sqlite'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

# import my_app.catalog.views
from my_app.catalog.views import catalog
app.register_blueprint(catalog)

db.create_all() 
```

同时，需要对 run.py 做些小改动：

```py
from my_app import manager
manager.run() 
```

run.py 的改动是因为我们需要使用 Flask script manager 的方式去启动应用。script manager 同样提供了额外的命令行参数。在这个例子中我们将使用 db 做为命令行参数。
如果我们把 run.py 当做脚本运行时，给它传递–help 参数，终端这时候将会展示所有的选项，看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/151c44f70cf908c87a3696e791f75118.png)

现在，运行这个应用，可以使用：

```py
$ python run.py runserver 
```

初始化迁移，需要运行 init 命令：

```py
$ python run.py db init 
```

之后当我们对模型做了更改，需要运行 migrate 命令：

```py
$ python run.py db migrate 
```

为了将更改反映到数据库上，需要运行 upgrade 命令：

```py
$ python run.py db upgrade 
```

#### 原理

现在，修改商品模型，添加一个新的字段 company：

```py
class Product(db.Model):
    # ...
    # Same product model as last recipe
    # ...
    company = db.Column(db.String(100)) 
```

migrate 的结果看起来像这样：

```py
$ python run.py db migrate
INFO [alembic.migration] Context impl SQLiteImpl.
INFO [alembic.migration] Will assume non-transactional DDL.
INFO [alembic.autogenerate.compare] Detected added column 
    'product.company' Generating <path/to/application>/
    flask_catalog/migrations/versions/2c08f71f9253_.py ... done 
```

前面的代码，我们看到 Alembic 将新的模型和数据库进行比较，然后检测到 product 新增了 company 一列（由 Product 模型创建）。

相似的，upgrade 的的输出将看起来像这样：

```py
$ python run.py db upgrade
INFO [alembic.migration] Context impl SQLiteImpl.
INFO [alembic.migration] Will assume non-transactional DDL.
INFO [alembic.migration] Running upgrade None -> 2c08f71f9253, empty message 
```

这里，Alembic 用之前检测到的迁移来升级数据库。可以看到输出中有一个 16 进制数。这代表了执行迁移的版本。
Alembic 内部使用它来追踪数据库表的更改。

## 用 Redis 建立模型数据索引

也许有些特性要去实现，但是不想对他们做持久化存储。所以，我们可以将他们存储在内存里保持一段时间，然后隐藏他们，举个例子，在网站上向访问者展示访问过的商品列表。

#### 准备

我们将使用 Redis 来做到这些，使用下面命令安装 Redis:

```py
$ pip install redis 
```

确保你的 Redis 服务器在运行，以便链接。安装和运行 Redis 服务器，参见：`http://redis.io/topics/quickstart`

然后我们需要和 Redis 连接。在`my_app/__init__.py`中添加下面代码可以做到这些：

```py
from redis import Redis
redis = Redis() 
```

我们可以在应用中需要用到 Redis 的地方构造 redis，比如定义 app 的地方，或者在视图文件里。最好是在应用
文件中做，因为这样连接将在整个应用中保持打开，仅仅通过导入 redis 就能够在任何需要的地方使用，。

#### 怎么做

我们将在 Redis 中设置一个集合来存储最近浏览过的商品。当我们浏览商品的时候会填充它。该记录将在 10 分钟后过期。对 views.py 做如下修改：

```py
from my_app import redis

@catalog.route('/product/<id>')
def product(id):
    product = Product.query.get_or_404(id)
    product_key = 'product-%s' % product.id
    redis.set(product_key, product.name)
    redis.expire(product_key, 600)
    return 'Product - %s, $%s' % (product.name, product.price) 
```

###### 提示

好的习惯是从配置文件获取 expire 时间，600。可以在`my_app/__init__.py`中设置该值，然后从这里获取。

在前面的方法中，注意 redis 对象的 set()和 expire()方法。首先，我们在 Redis 中使用 product_key 设置商品的 ID。然后，我们设置过期时间为 600 秒。

现在我们将查找缓存中还存活的键。然后获取和这些键相匹配的商品，之后返回他们：

```py
@catalog.route('/recent-products')
def recent_products():
    keys_alive = redis.keys('product-*')
    products = [redis.get(k).decode("utf-8") for k in keys_alive]
    return jsonify({'products': products}) 
```

###### 译者注

我运行代码的时候，因为 redis.get(k)获取到的字符串是 unicode 类型的，如果没有 decode(“utf-8”)，jsonify 解析会出错，所以这里加上解码。

#### 原理

当用户访问一个商品的时候就会有一条记录被存储，这条记录将保持 600 秒。下面的 10 分钟这个商品将被列在最近商品中，除非再一次被访问，然后再一次设置为 10 分钟。

## 使用非关系型数据库 MongoDB

有时，我们正在构建的应用程序中使用的数据可能根本不是结构化的，也可以是半结构化的，也可以是其模式随时间变化的数据。在这种情况下，我们将避免使用 RDBMS，因为它增加了痛苦，并且难以理解和维护。这时应该使用 NoSQL 数据库。
同时，在当前流行的开发环境下，由于开发速度快，不一定能够第一次设计出完美的结构（scheam）。NoSQL 提供了修改结构的灵活性，而不需要太多麻烦。
在生产环境中，数据库通常在短时间内增长到一个巨大的规模。这极大地影响了整个系统的性能。垂直和水平缩放技术（Vertical-and horizontal-scaling）也是可用的，但是非常昂贵。这些情况下，可以考虑使用 NoSQL 数据库，因为它就是为了这个目的而被设计的。NoSQL 数据库能够在大型集群上运行，并处理大量生成的高速数据，这使得它们在使用传统 RDBMS 处理伸缩性（scaling）问题时是一个不错的选择。
这里将使用 MongoDB 来演示 Flask 如何集成 NoSQL。

#### 准备

Flask 有许多 MongoDB 的扩展。我们将使用 Flask-MongoEngine，因为它提供了一个非常好的抽象，让我们很容易理解。通过下面命令安装它：

```py
$ pip install flask-mongoengine 
```

记住去开启 MongoDB 服务器，以便连接。更多安装和运行 MongoDB 的信息，可以参见`http://docs.mongodb.org/manual/installation/`

#### 怎么做

下面使用 MongoDB 重写我们的应用。首先修改`my_app/__init__.py`:

```py
from flask import Flask
from flask_mongoengine import MongoEngine
from redis import Redis

app = Flask(__name__)
app.config['MONGODB_SETTINGS']  = {'DB': 'my_catalog'}
app.debug = True
db = MongoEngine(app)

redis = Redis()

from my_app.catalog.views import catalog
app.register_blueprint(catalog) 
```

###### 提示

现在我们使用 MONGODB_SETTINGS 的配置而不是通常 SQLAlchemy-centric 的配置。这里，我们只需指定数据库的名字就可以使用。首先，我们需要在 MongoDB 中创建数据库，使用下面命令：

```py
>>> mongo
MongoDB shell version: 2.6.4
> use my_catalog
switched to db my_catalog 
```

接下来，我们将使用 MongoDB 字段创建一个 Product 模型。修改`flask_catalog/my_app/catalog/models.py`:

```py
import datetime
from my_app import db

class Product(db.Document):
    created_at = db.DateTimeField(default=datetime.datetime.now, required=True)
    key = db.StringField(max_length=255, required=True)
    name = db.StringField(max_length=255, required=True)
    price = db.DecimalField()

    def __repr__(self):
        return '<Product %r>' % self.id 
```

#### 其他

注意创建模型的 MongoDB 字段和前面小节使用的 SQLAlchemy 是相似的。这里取消了 ID 字段，我们设置了 created_at，这个字段将会存储记录创建的时间戳。

接下来是视图文件，`flask_catalog/my_app/catalog/views.py`:

```py
from decimal import Decimal
from flask import request, Blueprint, jsonify
from my_app.catalog.models import Product

catalog = Blueprint('catalog', __name__)

@catalog.route('/')
@catalog.route('/home')
def home():
    return "Welcome to the Catalog Home."

@catalog.route('/product/<key>')
def product(key):
    product = Product.objects.get_or_404(key=key)
    return 'Product - %s, $%s' % (product.name, product.price)

@catalog.route('/products')
def products():
    products = Product.objects.all()
    res = {}
    for product in products:
        res[product.key] = {
            'name': product.name,
            'price': str(product.price)
        }
    return jsonify(res)

@catalog.route('/product-create', methods=['POST',])
def create_product():
    name = request.form.get('name')
    key = request.form.get('key')
    price = request.form.get('price')
    product = Product(
        name=name,
        key=key,
        price=Decimal(price)
    )
    product.save()
    return 'Product created.' 
```

你会发现这非常类似于基于 SQLAlchemy 模型创建的视图。仅仅存在一些差异，而且是很容易理解的。

# 第四章：视图的使用

对于任何 Web 应用程序，控制与 Web 请求的交互以及适当的响应来满足这些请求是非常重要的。这一章将讲解正确处理请求的各种方式，然后用最好的方式设计他们。

这一章将包含下面的小节：

*   基于函数的视图和 URL 路由
*   基于类的视图
*   URL 路由和商品分页
*   渲染模板
*   处理 XHR 请求
*   优雅的装饰请求
*   创建自定义的 404 和 500 处理
*   Flash 消息用于更好的用户反馈
*   基于 SQL 的搜索

#### 介绍

Flask 为我们的应用程序提供了几种设计和布局 URL 路由的方法。同时，它提供了基于类的方式（类可以被继承和根据需要进行修改）来处理视图，这种方式和函数一样简单。前面版本中，Flask 支持基于函数的视图。但是，受 Django 影响，在 0.7 版本的时候，Flask 介绍了一个热插拔（pluggable）视图的概念，这允许我们去创建类，然后编写类的方法。这使得构建 RESTful API 的过程非常简单。同时，我可以进一步探索 Werkzeug，使用更灵活但是稍复杂的 URL maps。事实上，大型应用程序和框架更喜欢使用 URL maps。

## 基于函数的视图和 URL 路由

这是 Flask 里最简单的编写视图的方法。我们仅仅需要编写一个方法然后用端点（endpoint）装饰它。

#### 准备

为理解这一小节，可以从任何一个 Flask 应用开始。这个应用可以是一个新的，空的或者任何复杂的应用。我们需要做的是理解这一小节列出的方法。

#### 怎么做

下面是三种最常用的方法来处理各种各样的请求，用简单的例子说明一下。

```py
# A simple GET request
@app.route('/a-get-request')    
def get_request():
    bar = request.args.get('foo', 'bar')
    return 'A simple Flask request where foo is %s' % bar 
```

一个处理 GET 请求的例子看起来就像上面这样。我们检查 URL 查询参数是否含有一个叫 foo 的参数。如果有，就在响应中展示他们；否则使用默认值 bar。

```py
# A simple POST request
@app.route('/a-post-request', method=['POST'])
def post_request():
    bar = request.form.get('foo', 'bar')
    return 'A simple Flask request where foo is %s' % bar 
```

和 GET 请求很相似，只有一点差别，路由（route）现在有了一个额外的参数：methods。同时，用 request.form 替换了 request.args，因为 POST 请求假定数据是以表单方式提交的。

###### 提示

是否真有必要将 GET 和 POST 写在单独的方法里？当然不！

```py
# A simple GET/POST request
@app.route('/a-request', methods=['GET', 'POST'])
def some_request():
    if request.method == 'GET':
        bar = request.args.get('foo', 'bar')
    else:
        bar = request.form.get('foo', 'bar')
    return 'A simple Flask request where foo is %s' % bar 
```

在这里，我们可以看到我们已经将前两种方法合并为一个，现在 GET 和 POST 都由一个视图函数处理。

#### 原理

让我们试着理解前面的方法。
默认的，任何 Flask 视图函数仅仅支持 GET 请求。为了让处理函数支持其他请求，我们需要告诉 route()装饰器我们想要支持的方法。这就是我们在 POST 和 GET/POST 这两个方法中做的。

对于 GET 请求，request 对象将会查找 args，即 request.args.get()，对于 POST 方法，将查找 form，即 request.form.get()。
此外，如果我们尝试向只支持 POST 的方法发出 GET 请求，则请求将失败，导致 405 错误。所有方法都是如此。看下面的截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/28948af5d317fe944ffe7319120952ad.png)

#### 更多

有时，我们可能希望有一个 URL 映射模式，可以将带端点的 URL 规则定义在一个单独的地方，而不是分散在应用的各处。为此，我们不能用 route()装饰方法，应该像下面这样在应用对象定义路由：

```py
def get_request():
    bar = request.args.get('foo', 'bar')
    return 'A simple Flask request where foo is %s' % bar

app = Flask(__name__)
app.add_url_rule('/a-get-request', view_func=get_request) 
```

确保为 view_func 分配的方法提供了正确的相对路径。

## 基于类的视图

Flask 在 0.7 版本介绍了热插拔（pluggable）视图的概念；这为现有的实现增加了很大的灵活性。我们可以用类的方式编写视图，这些视图可以用通用的方式编写，并允许继承。

#### 准备

理解这一小节之前需理解上一小节。

#### 怎么做

Flask 提供一个叫做 View 的类，我们可以继承它做自定义的处理。
下面是一个简单的 GET 请求例子：

```py
from flask.views import View

class GetRequest(View):
    def dispatch_request(self):
        bar = request.args.get('foo', 'bar')
        return 'A simple Flask request where foo is %s' % bar

app.add_url_rule(
    '/a-get-request', view_func=GetRequest.as_view('get_request')
) 
```

为了同时满足 GET 和 POST 请求，我们可以编写以下代码：

```py
from flask.views import View

class GetPostRequest(View):
    methods = ['GET', 'POST']

    def dispatch_request(self):
        if request.method == 'GET':
            bar = request.args.get('foo', 'bar')
        if request.method == 'POST':
            bar = request.form.get('foo', 'bar')
        return 'A simple Flask request where foo is %s' % bar

app.add_url_rule(
    '/a-request', view_func=GetPostRequest.as_view('a_request')
) 
```

#### 原理

默认情况下，Flask 视图函数仅仅支持 GET 请求。基于类的视图也是如此。为了支持或者处理各种类型的请求，我们需要通过类 methods 属性来告诉我们的类，我们需要支持的 HTTP 方法。这正是我们在之前的 GET/POST 请求示例中所做的。
对于 GET 请求，request 将会查找 args，即 request.args.get()，对于 POST 将会查找 form，即 request.form.get()。
另外，如果我们试图对只支持 POST 的方法进行 GET 请求，则请求将失败，报 405 错误。其他方法也是如此。

#### 更多

现在很多人认为不可能在 View 类里仅仅只声明 GET 和 POST 方法，然后 Flask 会处理剩余的东西。对于这个问题的回答是使用 MethodView。让我们用 MethodView 来写之前的片段：

```py
from flask.views import MethodView

class GetPostRequest(MethodView):

    def get(self):
        bar = request.args.get('foo', 'bar')
        return 'A simple Flask request where foo is %s' % bar

    def post(self):
        bar = request.form.get('foo', 'bar')
        return 'A simple Flask request where foo is %s' % bar

app.add_url_rule(
    '/a-reqquest', view_func=GetPostRequest.as_view('a_request')
) 
```

#### 其他

*   参见前一小节，明白基于函数的视图和基于类的视图差别

## URL 路由和商品分页

有时，我们可能需要解析不同部分的 URL 的各个部分。举个例子，我们的 URL 可以有一个整数部分，字符串部分，特定长度的字符串部分，斜杠等等。我们可以使用 URL 转换器（converters）解析 URL 中的所有这些组合。这一小节，我们将会看到如何做到这些。同时，我们将会学习如何使用 Flask-SQLAlchemy 扩展完成分页。

#### 准备

我们已经看到了几个基本 URL 转换器的实例。这一小节，我们将会看到一些高级的 URL 转换器并学习如何使用它们。

#### 怎么做

假设我们有一个 URL 路由像下面这样:

```py
@app.route('/test/<name>')
def get_name(name):
    return name 
```

这里，`http://127.0.0.1:5000/test/Shalabh`里的 Shalabh 会被解析出来，然后传入到 get_name 方法的 name 参数中。这是一个 unicode 或者字符串转换器，是默认的，不需要显式地指定。

我们同样可以有一些特定长度的字符串。假设我们想要去解析一个 URL 包括一个国家码和货币码。国家码通常是两个字符长度，货币码是三个字符长度。可以像下面这样做：

```py
@app.route('/test/<string(minlength=2,maxlength=3):code>')
def get_name(code):
    return code 
```

URL 中含有的 US 和 USD 都将被匹配，`http://127.0.0.1:5000/test/USD`和`http://127.0.0.1:5000/test/US`处理方法类似。我们还可以通过 length 参数匹配准确的长度，而不是 minlength 和 maxlength。
我们可以用类似的方式解析整数：

```py
@app.route('/test/<int:age>')
def get_age(age):
    return str(age) 
```

我们可以指定期望的最大值和最小值是多少，比如，`@app.route('/test/<int(min=18,max=99):age>')`。在前面的例子里，我们也可以解析 float 数，只需将 int 改为 float。

有时，我们希望忽略 URL 中的斜杠或者解析文件系统路径中 URL 或者其它 URL 路径。可以这样做：

```py
@app.route('/test/<path:file>/end')
def get_file(file):
    return file 
```

如果接收到类似于`http://127.0.0.1:5000/test/usr/local/app/settings.py/end`的请求，`usr/local/app/settings.py`将会作为 file 参数传递到这个方法中。

#### 给应用添加分页

在第三章，我们创建了一个处理程序来展示数据库里的商品列表。如果我们有成百上千个商品，将会在一个列表里展示所有的商品，这将花费一些时间。同时，如果我们想要在模板里渲染这些商品，我们不应该在一个页面里展示超过 10~20 个的商品。分页将有助于构建优秀的应用。

```py
@catalog.route('/products')
@catalog.route('/products/<int:page>')
def products(page=1):
    products = Product.query.paginate(page, 10).items
    res = {}
    for product in products:
        res[product.id] = {
            'name': product.name,
            'price': product.price,
            'category': product.category.name
        }
    return jsonify(res) 
```

在前面的处理程序中，我们添加了一个新的 URL 路径，给它添加了一个 page 参数。现在，`http://127.0.0.1:5000/products`和`http://127.0.0.1:5000/products/1`是一样的，他们都会返回数据库里的前 10 个商品。`http://127.0.0.1:5000/products/2`将会返回下 10 个商品，以此类推。

###### 提示

paginate()方法接收三个参数，返回一个 Pagination 类的对象。三个参数是：

*   page：需要被列出的当前页码。
*   per_page：每页需要列出的条目数量。
*   error_out：如果该页没找到条目，将会报 404 错误。为了防止这个的发生，可以设置`error_out`为 False，这样将返回空的列表。

## 渲染模板

在编写了视图之后，我们肯定希望将内容呈现在模板上并得到底层数据库的数据。

#### 准备

为了渲染模板，我们将使用 Jinja2 作为模板语言。参见第二章去深入理解模板。

#### 怎么做

我们将继续使用前面的小节的商品目录应用程序。现在，我们修改视图来渲染模板，然后将数据库的信息展示在这些模板上面。
下面是修改过的 views.py 代码和模板。
首先开始修改视图，`flask_catalog_template/my_app/catalog/views.py`，在特定处理方法里渲染模板：

```py
from flask import render_template

@catalog.route('/')
@catalog.route('/home')
def home():
    return render_template('home.html') 
```

注意 render_template()方法。当 home 方法被调用时，将会渲染 home.html。看下面的代码：

```py
@catalog.route('/product/<id>') 
def product(id):
    product = Product.query.get_or_404(id)
    return render_template('product.html', product=product) 
```

这里，product.html 模板将会在模板中渲染 product 对象。看下面代码：

```py
@catalog.route('/products')
@catalog.route('/products/<int:page>')
def products(page=1):
    products = Product.query.paginate(page, 10)
    return render_template('products.html', products=products) 
```

这里，products.html 模板将会用分页好的 product 列表对象进行渲染。看下面代码：

```py
@catalog.route('/product-create', methods=['POST','GET'])
def create_product():
    # … Same code as before …
    return render_template('product-create.html') 
```

从前面的代码里可以看到，在这个例子里，新建的商品将被模板渲染。同样也可以使用 redirect()，但是我们将在下面的小节讲到它。现在看下面的代码：

```py
@catalog.route('/category-create', methods=['POST',])
def create_category():
    # ... Same code as before ...
    return render_template('category.html', category=category)

@catalog.route('/category/<id>')
def category(id):
    category = Category.query.get_or_404(id)
    return render_template('category.html', category=category)

@catalog.route('/categories')
def categories():
    categories = Category.query.all()
    return render_template('categories.html', categories=categories) 
```

上面三个处理方法和之前讨论过的渲染商品模板过程类似。

下面是创建的所有模板。理解这些模板是如何编写出来的，是如何工作的，需要参见第二章。

`flask_catalog_template/my_app/templates/home.html` 看起来像这样：

```py
{% extends 'base.html' %}
{% block container %}
    <h1>Welcome to the Catalog Home</h1>
    <a href="{{ url_for('catalog.products') }}">Click here to see the catalog</a>
{% endblock %} 
```

`flask_catalog_template/my_app/templates/product.html` 看起来像这样：

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        <h1>{{ product.name }}<small> {{ product.category.name}}</small></h1>
        <h4>{{ product.company }}</h4>
        <h3>{{ product.price }}</h3>
    </div>
{% endblock %} 
```

`flask_catalog_template/my_app/templates/products.html` 看起来像这样：

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        {% for product in products.items %}
            <div class="well">
                <h2>
                    <a href="{{ url_for('catalog.product', id=product.id)}}">{{ product.name }}</a>
                    <small>$ {{ product.price }}</small>
                </h2>
            </div>
        {% endfor %}
        {% if products.has_prev %}
            <a href="{{ url_for('catalog.products', page=products.prev_num) }}">
                {{"<< Previous Page"}}
            </a>
        {% else %}
            {{"<< Previous Page"}}
        {% endif %} |
        {% if products.has_next %}
            <a href="{{ url_for('catalog.products', page=products.next_num) }}"> 
                {{"Next page >>"}}
             </a>
        {% else %}
            {{"Next page >>"}}
        {% endif %}
    </div>
{% endblock %} 
```

`flask_catalog_template/my_app/templates/category.html` 看起来像这样：

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        <h2>{{ category.name }}</h2>
        <div class="well">
            {% for product in category.products %}
                <h3>
                    <a href="{{ url_for('catalog.product', id=product.id) }}">{{ product.name }}</a>
                    <small>$ {{ product.price }}</small>
                </h3>
            {% endfor %}
        </div>
    </div>
{% endblock %} 
```

`flask_catalog_template/my_app/templates/categories.html` 看起来像这样：

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        {% for category in categories %}
            <a href="{{ url_for('catalog.category', id=category.id) }}">
                <h2>{{ category.name }}</h2>
            </a>
        {% endfor %}
    </div>
{% endblock %} 
```

#### 原理

我们的视图方法在最后都有一个`render_template`方法。这意味着在成功完成请求之后，将使用一些参数去渲染模板。

###### 提示

注意在 products.html 是如何完成分页的。还可以进一步改进，显示两个导航链接之间的页面编号。建议你们自己探索。

## 处理 XHR 请求

Asynchronous JavaScript XMLHttpRequest (XHR)，即熟知的 Ajax，Ajax 在过去的几年里已经成为了 web 应用重要的一部分。随着单页（one-page）应用和 JavaScript 应用框架，比如 AngularJS，BackboneJS 等的出现，web 发展技术呈现指数级增长。

#### 准备

Flask 提供了一个简单的方法在视图函数里处理 XHR 请求。我们甚至可以对正常的 web 请求和 XHR 做通用化的处理。我们仅仅需要在 request 对象里寻找一个标志，来决定所需调用的方法。

我们将升级前面小节的商品目录应用来演示 XHR 请求。

#### 怎么做

Flask request 对象含有一个标记叫做`is_xhr`，通过它可以判断请求是 XHR 请求还是一个简单的 web 请求。通常，当有一个 XHR 请求时，调用方希望结果返回的是 JSON 格式，这样可以用来在网页上正确的位置渲染内容，而不是重新加载整个页面。
所以，假设我们在主页上有一个 Ajax 请求来获取数据库中商品的数量。一种方式是将商品数量放进`render_template()`上下文。另一种方法是将此信息作为 Ajax 调用的一个响应。我们将使用第二种方式，以便理解怎么用 Flask 处理 XHR：

```py
from flask import request, render_template, jsonify

@catalog.route('/')
@catalog.route('/home')
def home():
    if request.is_xhr:
        products = Product.query.all()
        return jsonify({'count': len(products)})
    return render_template('home.html') 
```

###### 提示

将 XHR 处理和常规请求写在一个方法里将变得有些臃肿，因为随着应用的增长，XHR 和常规请求业务逻辑将有所不同。
在这些情况下，XHR 请求和常规请求需要分开。这甚至可以扩展到使用蓝图来保持 URL 的简洁。

前面的方法中，我们首先检查这是否是一个 XHR 请求。如果是，则返回 JSON 数据，否则像之前做的一样渲染 home.html。修改`flask_catalog_template/my_app/templates/base.html`，增加一个 scripts 块。这里展示的空块可以放置在包含 BootstrapJS 脚本的后面：

```py
{% block scripts %}

{% endblock %} 
```

接下来，看一下`flask_catalog_template/my_app/templates/home.html`，这里发送了一个 Ajax 请求给了 home()处理程序，该处理程序检查该请求是否是 XHR。如果是，它从数据库取得商品的数量，然后以 JSON 的形式返回出去。看一下 scripts 块里的代码：

```py
{% extends 'base.html' %}
{% block container %}
    <h1>Welcome to the Catalog Home</h1>
    <a href="{{ url_for('catalog.products') }}" id="catalog_link">
        Click here to see the catalog
    </a>
{% endblock %}

{% block scripts %}
<script>
$(document).ready(function(){
    $.getJSON("/home", function(data) {
        $('#catalog_link').append('<span class="badge">' + data.count + span>');
    });
});
</script>
{% endblock %} 
```

#### 原理

现在主页包含了一个标记（badge），会展示数据库里商品的数量。此标记只在整个页面加载后才加载。当数据库商品数量非常巨大时，加载标记和加载页面其他内容的差别才会体现出来。
下面的截图显示了主页的样子：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/0fbf8efbe95900c2299f9b2666e67c40.png)

###### 译者注

如果没有出现商品数量，原因之一可能是 base.html 中引用的 jquery 是访问不到的，可以替换 jquery 地址为：
`<script src="https://code.jquery.com/jquery-3.1.1.min.js"></script>`

## 优雅的装饰请求

有一些人可能认为每次检查请求是否是 XHR，会让代码可读性变得很差。为了解决这个问题，我们有一个简单的解决方案。可以写一个装饰器为我们处理冗余代码。

#### 准备

这一小节，我们将写一个装饰器。装饰器对于 Python 的初学者来说可能很陌生。如果是这样，参见`http://legacy.python.org/dev/peps/pep-0318/`来理解装饰器。

#### 怎么做

下面是为了这一章所写的装饰器：

```py
from functools import wraps

def template_or_json(template=None):
    """Return a dict from your view and this will either pass it to a template or render json. Use like:
    @template_or_json('template.html')
    """

    def decorated(f):
        @wraps(f)
        def decorated_fn(*args, **kwargs):
            ctx = f(*args, **kwargs)
            if request.is_xhr or not template:
                return jsonify(ctx)
            else:
                return render_template(template, **ctx)
        return decorated_fn
    return decorated 
```

这个装饰器做的就是之前小节中我们对 XHR 的处理，即检查请求是否是 XHR，根据结果是否决定是渲染模板还是返回 JSON 数据。

现在，让我们将装饰器用在 home()上：

```py
@app.route('/')
@app.route('/home')
@template_or_json('home.html')
def home():
    products = Product.query.all()
    return {'count': len(products)} 
```

## 创建自定义的 404 和 500 处理

每个应用都会在某些情况下向用户抛出错误。这些错误可能是由于输入了一个错误的 URL（404），服务器内部错误（500），或者一个用户被禁止访问的（403）导致的。一个好的应用程序可以以交互的方式处理这些错误而不是显示一个丑陋的白色页面，这对大多数用户来说毫无意义。Flask 对所有的错误提供了一个容易使用的装饰器。

#### 准备

Flask 对象 app 有一个叫做 errorhandler()的方法，这使得处理应用程序错误的方式更加美观和高效。

#### 怎么做

看下面的代码：

```py
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404 
```

这里，我们创建了一个用 errorhandler()装饰的方法，当 404 Not Found 错误发生的时候它渲染了 404.html 模板。

下面是`flask_catalog_template/my_app/templates/404.html`的代码，在 404 错误发生的时候进行渲染。

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        <h3>Hola Friend! Looks like in your quest you have reached a location which does not exist yet.</h3>
        <h4>To continue, either check your map location (URL) or go back <a href="{{ url_for('catalog.home') }}">home</a></h4>
    </div>
{% endblock %} 
```

#### 原理

如果输入了一个错误的 URL，比如`http://127.0.0.1:5000/i-am-lost`，我们将看到下面的样子：
![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/e552f6121aeee2383ff05fd6dd02b9e7.png)

类似地，我们可以为其他错误代码添加错误处理程序。

#### 更多

还可以根据应用程序需求创建自定义错误并将其和错误代码和自定义错误输出绑定。可以通过下面代码做到这些：

```py
class MyCustom404(Exception):
    pass

@app.errorhandler(MyCustom404)
def special_page_not_found(error):
    return rendera_template("errors/custom_404.html"), 404 
```

## Flash 消息为了更好的用户反馈

所有 web 应用的重要一部分是良好的用户反馈。举个例子，当用户创建一个商品的时候，好的用户体验是提示用户商品已经创建好了。

#### 准备

我们将向已经存在的商品目录应用程序添加 flash 消息功能。我们得确保为应用添加了一个密匙（secret key），因为会话（session）依赖于这个密匙，当缺失密匙的时候，flash 消息会出错。

#### 怎么做

为了演示 flash 消息，我们将在创建商品时提示 flash 消息。首先，在`flask_catalog_template/my_app/__init__.py`添加一个密匙。

```py
app.secret_key = 'some_random_key' 
```

现在修改`flask_catalog_template/my_app/catalog/views.py`的`create_product()`，当创建商品的时候向用户提示一个消息。同时，这个处理程序做了一个小的修改，现在可以通过 web 接口使用 form 来创建产品：

```py
from flask import flash

@catalog.route('/product-create', methods=['GET', 'POST'])
def create_product():
    if request.method == "POST":
        name = request.form.get('name')
        price = request.form.get('price')
        categ_name = request.form.get('category')
        category = Category.query.filter_by(name=categ_name).first()
        if not category:
            category = Category(categ_name)
        product = Product(name, price, category)
        db.session.add(product)
        db.session.commit()
        flash('The product %s has been created' % name, 'success')
        return redirect(url_for('catalog.product', id=product.id))
    return render_template('product-create.html') 
```

在前面的方法中，我们首先检查请求类型是否是 POST，如果是，我们继续进行商品创建，或者呈现表单来创建商品。同时，注意 flash 消息，它提醒用户一个商品创建成功了。flash()的第一个参数是要被显示的消息，第二个参数是消息的类型。我们可以使用消息类型中的任何合适的标识符。这稍后可以确定要显示的警告消息类型。
新增了一个模板；它包含了商品表单的代码。模板的路径是：`flask_catalog_template/my_app/templates/product-create.html`:

```py
{% extends 'home.html' %}
{% block container %}
    <div class="top-pad">
        <form class="form-horizontal" method="POST" action="{{ url_for('catalog.create_product') }}" role="form">
            <div class="form-group">
                <label for="name" class="col-sm-2 control-label">Name</label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" id="name" name="name">
                </div>
            </div>
            <div class="form-group">
                <label for="price" class="col-sm-2 control-label">Price</label>
                <div class="col-sm-10">
                    <input type="number" class="form-control" id="price" name="price">
                </div>
                </div>
            <div class="form-group">
                <label for="category" class="col-sm-2 control-label">Category</label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" id="category" name="category">
                </div>
            </div>
            <button type="submit" class="btn btn-default">Submit</button>
        </form>
    </div>
{% endblock %} 
```

我们将修改我们的基础模板，`flask_catalog_template/my_app/templates/base.html`来支持 flash 消息。仅仅需要在 container 块前添加`<div>`里的代码：

```py
<br/>
<div>
    {% for category, message in get_flashed_messages (with_categories=true) %}
        <div class="alert alert-{{category}} alert-dismissable">
            <button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>
            {{ message }}
        </div>
    {% endfor %}
</div> 
```

###### 提示

看`<div>`容器，我们添加了一个机制显示 flash 消息，在模板中获取 flash 消息需使用`get_flashed_messages()`。

#### 原理

当访问`http://127.0.0.1:5000/product-create`的时候将看到下面截图中这样的表单：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/10aa9f18ce26bb08894f687dd4ce72f0.png)

填写表单点击 Submit。商品页顶部将显示一个提醒消息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-fw-cb/img/dbd91dee997415f8e994d13ae0154e69.png)

## 基于 SQL 的搜索

在任何应用中，能够基于某些标准在数据中搜索记录是很重要的。这一小节，我们将用 SQLAlchemy 完成基本的基于 SQL 的搜索。同样的方法也可以用来搜索任何其他数据库系统。

#### 准备

开始的时候我们已经在商品目录应用程序中完成了一定程度的搜索。当展示商品页的时候，我们用 ID 搜索特定的商品。现在我们将进一步深入，在名称和类别的基础上进行搜索。

#### 怎么做

下面是一个方法，将在目录应用程序里通过 name，price，company，category 搜索。我们可以搜索一个或多个标准（criterion）（除了 category，它仅能被单独搜索）。注意，对于不同的值有不同的表示形式。比如价格中的浮点数可以用相等进行搜索，但是在字符串的情况下可以使用相似进行搜索。同时，留意 join 是如何完成 category 的搜索的。这些方法在视图文件里完成，即，`flask_catalog_template/my_app/catalog/views.py`:

```py
from sqlalchemy.orm.util import join
@catalog.route('/product-search')
@catalog.route('/product-search/<int:page>')
def product_search(page=1):
    name = request.args.get('name')
    price = request.args.get('price')
    company = request.args.get('company')
    category = request.args.get('category')
    products = Product.query
    if name:
        products = products.filter(Product.name.like('%' + name + '%'))
    if price:
        products = products.filter(Product.price == price)
    if company:
        products = products.filter(Product.company.like('%' + company + '%'))
    if category:
        products = products.select_from(join(Product, Category)).filter(Category.name.like('%' + category + '%'))
    return render_template(
        'products.html', products=products.paginate(page, 10)
    ) 
```

#### 原理

输入一个 URL 进行商品的搜索，比如`http://127.0.0.1:5000/product-search?name=iPhone`。这将搜索名称为 iPhone 的商品，然后在 pruducts.html 模板上列出搜索结果。相似的，当需要的时候我们可以搜索 price 或者 company，或者 category。为了更好的理解，你可以尝试各种各样的组合。

###### 提示

我们使用相同的产品列表页面来呈现搜索结果。使用 Ajax 实现搜索将非常有趣。这留给你自己完成。

