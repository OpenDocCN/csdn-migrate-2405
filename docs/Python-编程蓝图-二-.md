# Python 编程蓝图（二）

> 原文：[`zh.annas-archive.org/md5/86404db5905a76ae5db4e50dd816784e`](https://zh.annas-archive.org/md5/86404db5905a76ae5db4e50dd816784e)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：在 Twitter 上投票

在上一章中，我们实现了一个终端应用程序，作为流行音乐服务 Spotify 的远程控制器。在这个应用程序中，我们可以搜索艺术家，浏览专辑，以及浏览每张专辑中的曲目。最后，我们甚至可以请求在用户的活动设备上播放曲目。

这一次，我们将开发一个将与 Twitter 集成的应用程序，利用其 REST API。 Twitter 是一个自 2006 年以来就存在的社交网络，拥有超过 3 亿活跃用户。私人用户、公司、艺术家、足球俱乐部，你几乎可以在 Twitter 上找到任何东西。但我认为让 Twitter 如此受欢迎的是它的简单性。

与博客文章不同，Twitter 的帖子或*推文*必须简短并直奔主题，而且准备发布的时间也不需要太长。另一个使 Twitter 如此受欢迎的原因是该服务是一个很好的新闻来源。如果你想要了解世界上正在发生的事情，政治、体育、科技等等，Twitter 就是你要去的地方。

除此之外，Twitter 对于开发者来说有一个相当不错的 API，为了利用这一点，我们将开发一个应用程序，用户可以使用标签投票。在我们的应用程序中，我们将配置要监视的标签，并且它将自动定期获取与该标签匹配的最新推文，对它们进行计数，并在用户界面中显示它们。

在本章中，您将学习以下内容：

+   创建一个推文应用程序

+   使用`OAuth`库并实现三步验证流程

+   使用 Twitter API 搜索最新的推文

+   使用`Tkinter`构建一个简单的用户界面

+   学习多进程和响应式编程的基础知识

# 设置环境

首先，我们要做的事情通常是设置我们的开发环境，第一步是为我们的应用程序创建一个虚拟环境。我们的应用程序将被称为`twittervotes`，所以让我们继续创建一个名为`twittervotes`的虚拟环境：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/9cf0dbeb-8a22-4726-930f-c0869b9b0dbf.png)

当`virtualenv`环境创建好后，您可以使用以下命令激活它：

```py
. twittervotes/bin/activate
```

太好了！现在让我们设置项目的目录结构。它应该如下所示：

```py
twittervotes
├── core
│   ├── models
│   └── twitter
└── templates
```

让我们深入了解一下结构：

| `twittervotes` | 应用程序的根目录。在这里，我们将创建应用程序的入口点，以及一个小的辅助应用程序来执行 Twitter 身份验证。 |
| --- | --- |
| `twittervotes/core` | 这将包含我们项目的所有核心功能。它将包含身份验证代码、读取配置文件、向 Twitter API 发送请求等等。 |
| `twittervotes/core/models` | 用于保存应用程序数据模型的目录。 |
| `twittervotes/core/twitter` | 在`twitter`目录中，我们将保留与 Twitter API 交互的`helper`函数。 |
| `twittervotes/templates` | 在这里，我们将保存我们应用程序将使用的所有 HTML 模板。 |

接下来，是时候添加我们项目的依赖关系了。继续在`twittervotes`目录中创建一个名为`requirements.txt`的文件，内容如下：

```py
Flask==0.12.2
oauth2==1.9.0.post1
PyYAML==3.12
requests==2.18.4
Rx==1.6.0
```

以下表格解释了前面的依赖关系的含义：

| `Flask` | 我们将在这里使用 Flask 创建一个简单的 Web 应用程序，以便与 Twitter 进行身份验证。 |
| --- | --- |
| `oauth2` | 这是一个很棒的包，它将在执行`OAuth`身份验证时抽象出很多复杂性。 |
| `PyYAML` | 我们将使用这个包来创建和读取 YAML 格式的配置文件。 |
| `Requests` | 允许我们通过 HTTP 访问 Twitter API。 |
| `Rx` | 最后，我们将使用 Python 的 Reactive Extensions，以便在新的推文计数到达时，可以对我们的 UI 进行响应式更新。 |

文件创建后，运行命令`pip install -r requirements.txt`，您应该会看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/40df8c49-f4b0-4320-bef0-833905edb509.png)如果运行命令`pip freeze`，您将获得以 pip 格式列出的依赖项列表，并且您将注意到输出列出了比我们实际添加到`requirements`文件中的依赖项更多的依赖项。 原因是我们的项目需要的软件包也有依赖项，并且它们也将被安装。 因此，如果您安装的软件包比您在`requirements`文件中指定的要多，请不要担心。

现在我们的环境已经设置好，我们可以开始创建我们的 Twitter 应用程序。 通常，在开始编码之前，请确保您的代码已经在 Git 等源代码控制系统下； 有很多在线服务可以免费托管您的存储库。

通过这种方式，您可以回滚项目的不同版本，如果您的计算机出现问题，也不会丢失工作。 话虽如此，让我们创建我们的 Twitter 应用程序。

# 创建 Twitter 应用程序

在本节中，我们将创建我们的第一个 Twitter 应用程序，以便可以使用 Twitter REST API。 如果您还没有帐户，则需要创建一个帐户。 如果您不使用 Twitter，我强烈建议您使用； 这是一个了解所有新闻和开发世界正在发生的事情的好方法，也是在 Python 社区中结交新朋友的好方法。

创建帐户后，转到[`apps.twitter.com/`](https://apps.twitter.com/)，使用您的登录凭据登录，您将进入一个页面，您可以在该页面上看到您已经创建的应用程序的列表（第一次，您可能会有一个空的应用程序列表），并且在同一页上，您将有可能创建新的应用程序。 单击右上角的“创建新应用程序”按钮，它将打开以下页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/4599e1a6-0846-42c4-9920-11341efa9cec.png)

在此表单中，有三个必填字段-名称，描述和网站：

+   **名称**：这是您的应用程序的名称； 这也是在执行授权时将呈现给您的应用程序用户的名称。 名称不需要遵循任何特定的命名约定，您可以随意命名。

+   **描述**：顾名思义，这是您的应用程序的描述。 这个字段也将呈现给您的应用程序用户，因此最好有描述您的应用程序的好文本。 在这种情况下，我们不需要太多文本。 让我们添加`用于在 Twitter 上使用标签投票的应用程序`。

+   **网站**：指定您的应用程序的网站； 它也将在授权期间呈现给用户，并且是用户可以下载或获取有关您的应用程序的更多信息的网站。 由于我们处于开发阶段，我们可以添加一个占位符，例如[`www.example.com`](http://www.example.com)。

+   **回调 URL**：这与上一章中的 Spotify 终端应用程序中的回调 URL 的工作方式相同。 这是 Twitter 将调用以发送授权代码的 URL。 这不是必需的字段，但我们需要它，所以让我们继续添加；`http://localhost:3000/callback`。

填写所有字段后，您只需要勾选 Twitter 开发者协议并单击“创建 Twitter 应用程序”按钮。

如果一切顺利，您将被引导到另一个页面，您可以在该页面上看到您新创建的应用程序的更多详细信息。 在应用程序名称下方，您将看到一个带有选项卡的区域，显示有关应用程序的设置和不同信息的选项卡：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/469924a4-645a-46fc-837d-bd1517bc4733.png)

在第一个选项卡“详细信息”中，我们要复制所有我们将用于执行身份验证的 URL。滚动到“应用程序设置”，并复制“请求令牌 URL”、“授权 URL”和“访问令牌 URL”：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/e709f442-79ec-4474-8cfc-d18c21a0b195.png)

太好了！现在让我们转到“密钥和访问令牌”选项卡，复制“消费者密钥”和“消费者密钥”*：*

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/30c5220e-277f-4cc8-b2b4-db7c7bb37429.png)

现在我们已经复制了所有必要的信息，我们可以创建一个将被我们的应用程序使用的配置文件。将所有这些内容保存在配置文件中是一种良好的做法，这样我们就不需要在代码中硬编码这些 URL。

我们将*消费者密钥*和*消费者密钥*添加到我们项目中的配置文件；正如名称所示，这个密钥是*秘密*的，所以如果您计划在 GitHub 等服务中为您的代码创建存储库，请确保将配置文件添加到`.gitignore`文件中，以便密钥不被推送到云存储库。永远不要与任何人分享这些密钥；如果您怀疑有人拥有这些密钥，您可以在 Twitter 应用的网站上为您的应用生成新的密钥。

# 添加配置文件

在这一部分，我们将为我们的应用程序创建配置文件；配置文件将采用 YAML 格式。如果您想了解有关 YAML 的更多信息，可以查看网站[`yaml.org/`](http://yaml.org/)，在那里您将找到示例、规范，以及可以用于操作 YAML 文件的不同编程语言的库列表。

对于我们的应用程序，我们将使用 PyYAML，它将允许我们以非常简单的方式读取和写入 YAML 文件。我们的配置文件非常简单，所以我们不需要使用库的任何高级功能，我们只想读取内容并写入，我们要添加的数据非常平坦；我们不会有任何嵌套对象或任何类型的列表。

让我们获取我们从 Twitter 获取的信息，并将其添加到配置文件中。在应用程序的`twittervotes`目录中创建一个名为`config.yaml`的文件，内容如下：

```py
consumer_key: '<replace with your consumer_key>'
consumer_secret: '<replace with your consumer secret>'
request_token_url: 'https://api.twitter.com/oauth/request_token'
authorize_url: 'https://api.twitter.com/oauth/authorize'
access_token_url: 'https://api.twitter.com/oauth/access_token'
api_version: '1.1'
search_endpoint: 'https://api.twitter.com/1.1/search/tweets.json'
```

太好了！现在我们将在我们的项目中创建第一个 Python 代码。如果您已经阅读了前几章，那么读取配置文件的函数对您来说将是熟悉的。这个想法很简单：我们将读取配置文件，解析它，并创建一个我们可以轻松使用来访问我们添加到配置中的数据的模型。首先，我们需要创建配置模型。

在`twittervotes/core/models/`中创建一个名为`models.py`的文件，内容如下：

```py
from collections import namedtuple

Config = namedtuple('Config', ['consumer_key',
                               'consumer_secret',
                               'request_token_url',
                               'access_token_url',
                               'authorize_url',
                               'api_version',
                               'search_endpoint', ])
```

在上一章中对`namedtuple`进行了更详细的介绍，所以我不会再详细介绍它；如果您还没有阅读第二章，只需知道`namedtuple`是一种类，这段代码将使用第二个参数中指定的字段定义一个名为`Config`的`namedtuple`。

太好了，现在让我们在`twittervotes/core/models`中创建另一个名为`__init__.py`的文件，并导入我们刚刚创建的`namedtuple`：

```py
from .models import Config
```

现在是时候创建读取 YAML 文件并将其返回给我们的函数了。在`twittervotes/core/`中创建一个名为`config.py`的文件。让我们开始添加导入语句：

```py
import os
import yaml

from .models import Config
```

我们将使用`os`包轻松获取用户当前目录并操作路径。我们还导入 PyYAML，以便读取 YAML 文件，最后，从`models`模块中导入我们刚刚创建的`Config`模型。

然后我们定义两个函数，首先是`_read_yaml_file`函数。这个函数有两个参数——`filename`，是我们要读取的配置文件的名称，还有`cls`，可以是我们用来存储配置数据的`class`或`namedtuple`。

在这种情况下，我们将传递`Config`——`namedtuple`，它具有我们将要读取的 YAML 配置文件相同的属性：

```py
def _read_yaml_file(filename, cls):
    core_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(core_dir, '..', filename)

    with open(file_path, mode='r', encoding='UTF-8') as file:
        config = yaml.load(file)
        return cls(**config)
```

首先，我们使用`os.path.abspath`函数，将特殊变量`__file__`作为参数传递。当一个模块被加载时，变量`__file__`将被设置为与模块同名。这将使我们能够轻松找到加载配置文件的位置。因此，以下代码段将返回核心模块的路径。

`/projects/twittervotes/core`：

```py
core_dir = os.path.dirname(os.path.abspath(__file__)) will return
```

我们知道配置文件将位于`/projects/twittervotes/`，所以我们需要将`..`与路径连接起来，以在目录结构中向上移动一级，以便读取文件。这就是我们构建完整配置文件路径的原因。

`file_path = os.path.join(core_dir, '..', filename)`

这将使我们能够从系统中的任何位置运行此代码。

我们以 UTF-8 编码以读取模式打开文件，并将其传递给`yaml.load`函数，将结果赋给`config`变量。`config`变量将是一个包含配置文件中所有数据的字典。

这个函数的最后一行是有趣的部分：如果你还记得，`cls`参数是一个`class`或者`namedtuple`，所以我们将配置字典的值作为参数展开。在这里，我们将使用`Config`——`namedtuple`，所以`cls(**config)`等同于`Config`，`(**config)`，使用`**`传递参数将等同于逐个传递所有参数：

```py
Config(
    consumer_key: ''
    consumer_secret: ''
    app_only_auth: 'https://api.twitter.com/oauth2/token'
    request_token_url: 'https://api.twitter.com/oauth/request_token'
    authorize_url: 'https://api.twitter.com/oauth/authorize'
    access_token_url: 'https://api.twitter.com/oauth/access_token'
    api_version: '1.1'
    search_endpoint: '')
```

现在我们要添加我们需要的第二个函数，`read_config`函数：

```py
def read_config():
    try:
        return _read_yaml_file('config.yaml', Config)
    except IOError as e:
        print(""" Error: couldn\'t file the configuration file 
        `config.yaml`
        'on your current directory.

        Default format is:',

        consumer_key: 'your_consumer_key'
        consumer_secret: 'your_consumer_secret'
        request_token_url: 
        'https://api.twitter.com/oauth/request_token'
        access_token_url:  
        'https://api.twitter.com/oauth/access_token'
        authorize_url: 'https://api.twitter.com/oauth/authorize'
        api_version: '1.1'
        search_endpoint: ''
        """)
        raise
```

这个函数非常简单；它只是利用我们刚刚创建的`_read_yaml_file`函数，将`config.yaml`文件作为第一个参数传递，并将`Config`、`namedtuple`作为第二个参数传递。

我们捕获`IOError`异常，如果文件在应用程序目录中不存在，则会抛出该异常；在这种情况下，我们会抛出一个帮助消息，向您的应用程序用户显示配置文件应该如何结构化。

最后一步是将其导入到`twittervotes/core`目录中的`__init__.py`中：

```py
from .config import read_config
```

让我们在 Python REPL 中尝试一下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/614acd5c-35c0-47b3-93aa-ad1c894123e2.png)

太棒了，它的工作原理就像我们想要的那样！在下一节中，我们可以开始创建执行认证的代码。

# 执行认证

在本节中，我们将创建一个程序，该程序将为我们执行认证，以便我们可以使用 Twitter API。我们将使用一个简单的 Flask 应用程序来实现这一点，该应用程序将公开两个路由。第一个是根路径`/`，它将加载和呈现一个简单的 HTML 模板，其中包含一个按钮，该按钮将重定向我们到 Twitter 认证对话框。

我们要创建的第二个路由是`/callback`。还记得我们在 Twitter 应用程序配置中指定的回调 URL 吗？这是在我们授权应用程序后将被调用的路由。它将返回一个授权令牌，该令牌将用于向 Twitter API 发出请求。所以让我们开始吧！

在我们开始实现 Flask 应用程序之前，我们需要在我们的模型模块中添加另一个模型。这个模型将代表请求授权数据。打开`twittervotes/core/models`中的`models.py`文件，并添加以下代码：

```py
RequestToken = namedtuple('RequestToken', ['oauth_token',
                                         'oauth_token_secret',
                                        'oauth_callback_confirmed'])
```

这将创建一个名为`RequestToken`的`namedtuple`，包含字段`oauth_token`、`oauth_token_secret`和`outh_callback_confirmed`；这些数据对我们执行认证的第二步是必要的。

最后，在`twittervotes/core/models`目录中打开`__init__.py`文件，并导入我们刚刚创建的`RequestToken` `namedtuple`，如下所示：

```py
from .models import RequestToken
```

既然我们已经有了模型，让我们开始创建 Flask 应用程序。让我们添加一个非常简单的模板，显示一个按钮，该按钮将启动认证过程。

在`twittervotes`目录中创建一个名为`templates`的新目录，并创建一个名为`index.html`的文件，内容如下：

```py
<html>
    <head>
    </head>
    <body>
       <a href="{{link}}"> Click here to authorize </a>
    </body>
</html>
```

# 创建 Flask 应用程序

完美，现在让我们在`twittervotes`目录中添加一个名为`twitter_auth.py`的文件。我们将在其中创建三个函数，但首先让我们添加一些导入：

```py
from urllib.parse import parse_qsl

import yaml

from flask import Flask
from flask import render_template
from flask import request

import oauth2 as oauth

from core import read_config
from core.models import RequestToken
```

首先，我们从`urllib.parse`模块中导入`parser_qls`来解析返回的查询字符串，以及`yaml`模块，这样我们就可以读取和写入`YAML`配置文件。然后我们导入构建 Flask 应用程序所需的一切。我们在这里要导入的最后一个第三方模块是`oauth2`模块，它将帮助我们执行`OAuth`认证。

最后，我们导入我们的函数`read_config`和我们刚刚创建的`RequestToken` `namedtuple`。

在这里，我们创建了我们的 Flask 应用程序和一些全局变量，这些变量将保存客户端、消费者和`RequestToken`实例的值：

```py
app = Flask(__name__)

client = None
consumer = None
req_token = None
```

我们要创建的第一个函数是一个名为`get_req_token`的函数，内容如下：

```py
def get_oauth_token(config):

    global consumer
    global client
    global req_token

    consumer = oauth.Consumer(config.consumer_key, 
     config.consumer_secret)
    client = oauth.Client(consumer)

    resp, content = client.request(config.request_token_url, 'GET')

    if resp['status'] != '200':
        raise Exception("Invalid response 
        {}".format(resp['status']))

    request_token = dict(parse_qsl(content.decode('utf-8')))

    req_token = RequestToken(**request_token)
```

这个函数的参数是一个配置实例，全局语句告诉解释器函数中使用的`req_token`将引用全局变量。

我们使用在创建 Twitter 应用程序时获得的消费者密钥和消费者密钥创建一个消费者对象。当消费者创建后，我们可以将其传递给客户端函数来创建客户端，然后我们调用请求函数，这个函数将执行请求到 Twitter，传递请求令牌 URL。

当请求完成时，响应和内容将被存储在变量`resp`和`content`中。紧接着，我们测试响应状态是否不是`200`或`HTTP.OK`；在这种情况下，我们会引发一个异常，否则我们解析查询字符串以获取发送回来的值，并创建一个`RequestToken`实例。

# 创建应用程序路由

现在我们可以开始创建路由了。首先，我们要添加根路由：

```py
@app.route('/')
def home():

    config = read_config()

    get_oauth_token(config)

    url = f'{config.authorize_url}?oauth_token=
    {req_token.oauth_token}'

    return render_template('index.html', link=url)
```

我们读取配置文件并将其传递给`get_oauth_token`函数。这个函数将用`oauth_token`的值填充全局变量`req_token`；我们需要这个令牌来开始授权过程。然后我们使用从配置文件中获取的`authorize_url`值和`OAuth`请求令牌构建授权 URL。

最后，我们使用`render_template`来渲染我们创建的`index.html`模板，并且还向函数传递了第二个参数，即上下文。在这种情况下，我们创建了一个名为`link`的项目，其值设置为`url`。如果你还记得`index.html`模板，那里有一个`"{{url}}"`的占位符。这个占位符将被我们在`render_template`函数中分配给`link`的值所替换。

默认情况下，Flask 使用 Jinja2 作为模板引擎，但可以更改为您喜欢的引擎；我们不会在本书中详细介绍如何做到这一点，因为这超出了我们的范围。

我们要添加的最后一个路由是`/callback`路由，这将是 Twitter 在授权后调用的路由：

```py
@app.route('/callback')
def callback():

    global req_token
    global consumer

    config = read_config()

    oauth_verifier = request.args.get('oauth_verifier', '')

    token = oauth.Token(req_token.oauth_token,
                        req_token.oauth_token_secret)

    token.set_verifier(oauth_verifier)

    client = oauth.Client(consumer, token)

    resp, content = client.request(config.access_token_url, 'POST')
    access_token = dict(parse_qsl(content.decode('utf-8')))

    with open('.twitterauth', 'w') as req_auth:
        file_content = yaml.dump(access_token, 
        default_flow_style=False)
        req_auth.write(file_content)

    return 'All set! You can close the browser window and stop the 
    server.'
```

回调路由的实现从使用全局语句开始，这样我们就可以使用全局变量`req_token`和`consumer`。

现在我们来到了有趣的部分。在授权后，Twitter 会返回一个`outh_verifier`，所以我们从请求参数中获取它并将其设置为变量`oauth_verifier`；我们使用在授权过程的第一部分中获得的`oauth_token`和`oauth_token_secret`创建一个`Token`实例。

然后我们在`Token`对象中设置`oauth_verifier`，最后创建一个新的客户端，我们将使用它来执行一个新的请求。

我们解码从请求接收到的数据，并将其添加到访问令牌变量中，最后，我们将`access_token`的内容写入`twittervotes`目录中的`.twitterauth`文件。这个文件也是 YAML 格式，所以我们将在`config.py`文件中添加另一个模型和一个新的函数来读取新的设置。

请注意，这个过程只需要做一次。这就是我们将数据存储在`.twitterauth`文件中的原因。进一步的请求只需要使用这个文件中包含的数据。

如果您检查`.twitterauth`文件的内容，您应该有类似以下的内容：

```py
oauth_token: 31******95-**************************rt*****io
oauth_token_secret: NZH***************************************ze8v
screen_name: the8bitcoder
user_id: '31******95'
x_auth_expires: '0'
```

要完成 Flask 应用程序，我们需要在文件末尾添加以下代码：

```py
if __name__ == '__main__':
    app.run(host='localhost', port=3000)
```

让我们在`twittervotes/core/models/`中的`models.py`文件中添加一个新的模型，内容如下：

```py
RequestAuth = namedtuple('RequestAuth', ['oauth_token',
                                         'oauth_token_secret',
                                         'user_id',
                                         'screen_name',
                                         'x_auth_expires', ])
```

太棒了！还有一件事——我们需要在`twittervotes/core/models`目录中的`__init__.py`文件中导入新的模型：

```py
from .models import RequestAuth
```

另外，让我们在`twittervotes/core`中的`config.py`文件中添加一个函数来读取`.twittervotes`文件。首先，我们需要导入我们刚刚创建的`RequestAuth`——`namedtuple`：

```py
from .models import RequestAuth
```

然后我们创建一个名为`read_reqauth`的函数，如下所示：

```py
def read_reqauth():
    try:
        return _read_yaml_file('.twitterauth', RequestAuth)
    except IOError as e:
        print(('It seems like you have not authorized the  
        application.\n'
               'In order to use your twitter data, please run the '
               'auth.py first.'))
```

这个函数非常简单：我们只是调用`_read_yaml_file`，将`.twitterauth`文件和我们刚刚创建的新的`namedtuple`，`RequestAuth`作为参数传递进去。同样，如果发生错误，我们会引发异常并显示帮助消息。

现在我们可以尝试进行身份验证。在`twittervotes`目录中，执行脚本`twitter_auth.py`。您应该会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/a1052ea8-4738-468c-8caf-a568a927ddb4.png)

太棒了！服务器已经启动，所以我们可以打开浏览器，转到`http://localhost:3000`。您应该会看到一个非常简单的页面，上面有一个链接可以进行身份验证：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/f28c4eee-25af-45b5-9e14-5393bcf250dd.png)

如果您使用浏览器开发工具检查链接，您将看到链接指向授权端点，并传递了我们创建的`oauth_token`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/a23ce439-f6f8-4e4d-ac05-2552bf452cf7.png)

继续点击链接，您将被发送到授权页面：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/8d73d3dc-f1c8-409d-b33a-f7833b594ba1.png)

如果您点击“授权应用”按钮，您将被重定向回本地主机，并显示成功消息：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/ce6bc11b-7601-4b60-847b-4bdbb247c79a.png)

如果您注意到 Twitter 发送给我们的 URL，您会发现一些信息。这里的重点是`oauth_verifier`，我们将其设置为请求令牌，然后我们执行最后一个请求以获取访问令牌。现在您可以关闭浏览器，停止 Flask 应用程序，并在`twittervotes`目录中的`.twitterauth`文件中查看结果：

```py
oauth_token: 31*******5-KNAbN***********************K40
oauth_token_secret: d**************************************Y3
screen_name: the8bitcoder
user_id: '31******95'
x_auth_expires: '0'
```

现在，我们在这里实现的所有功能对于其他用户使用我们的应用程序非常有用；然而，如果您正在授权自己的 Twitter 应用程序，有一种更简单的方法可以获取访问令牌。让我们看看如何做到这一点。

返回到[`apps.twitter.com/`](https://apps.twitter.com/)中的 Twitter 应用程序设置；选择 Keys and Access Tokens 选项卡并滚动到最底部。如果您已经授权了这个应用程序，您将在`.twitterauth`文件中看到与我们现在相同的信息，但如果您还没有授权该应用程序，您将看到一个看起来像下面这样的 Your Access Token 部分：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/a155fb51-8b1d-443a-bb29-9eebada375ce.png)

如果您点击“创建我的访问令牌”，Twitter 将为您生成访问令牌：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/48983a7f-97bd-4851-a5a1-45ddc1151e89.png)

访问令牌创建后，您只需将数据复制到`.twitterauth`文件中。

# 构建 Twitter 投票应用程序

现在我们的环境已经设置好，我们已经看到了如何在 Twitter 上创建一个应用程序并执行三条腿的身份验证，现在是时候开始构建实际的应用程序来计算 Twitter 投票了。

我们首先创建一个模型类来表示一个标签。在`twittervotes/core/twitter`目录中创建一个名为`hashtag.py`的文件，内容如下：

```py
class Hashtag:
    def __init__(self, name):
        self.name = name
        self.total = 0
  self.refresh_url = None
```

这是一个非常简单的类。我们可以将一个名称作为参数传递给初始化程序；名称是没有井号(`#`)的标签。在初始化程序中，我们定义了一些属性：名称，将设置为我们传递给初始化程序的参数，然后是一个名为`total`的属性，它将为我们保留标签的使用次数。

最后，我们设置`refresh_url`。`refresh_url`将用于执行对 Twitter API 的查询，这里有趣的部分是`refresh_url`已经包含了最新返回的 tweet 的`id`，因此我们可以使用它来仅获取我们尚未获取的 tweet，以避免多次计数相同的 tweet。

`refresh_url`看起来像下面这样：

```py
refresh_url': '?since_id=963341767532834817&q=%23python&result_type=mixed&include_entities=1
```

现在我们可以打开`twittervotes/core/twitter`目录中的`__init__.py`文件，并导入我们刚刚创建的类，如下所示：

```py
from .hashtag import Hashtag
```

太棒了！现在继续在`twittervotes/core/`目录中创建一个名为`request.py`的文件。

像往常一样，我们开始添加一些导入：

```py
import oauth2 as oauth
import time
from urllib.parse import parse_qsl
import json

import requests

from .config import read_config
from .config import read_reqauth
```

首先，我们导入`oauth2`包，我们将使用它来执行身份验证；我们准备请求，并用`SHA1`密钥对其进行签名。我们还导入`time`来设置`OAuth`时间戳设置。我们导入函数`parse_qsl`，我们将使用它来解析查询字符串，以便我们可以准备一个新的请求来搜索最新的 tweets，以及`json`模块，这样我们就可以反序列化 Twitter API 发送给我们的 JSON 数据。

然后，我们导入我们自己的函数`read_config`和`read_req_auth`，这样我们就可以读取两个配置文件。最后，我们导入`json`包来解析结果和`requests`包来执行对 Twitter 搜索端点的实际请求：

```py
def prepare_request(url, url_params):
    reqconfig = read_reqauth()
    config = read_config()

    token = oauth.Token(
        key=reqconfig.oauth_token,
        secret=reqconfig.oauth_token_secret)

    consumer = oauth.Consumer(
        key=config.consumer_key,
        secret=config.consumer_secret)

    params = {
        'oauth_version': "1.0",
        'oauth_nonce': oauth.generate_nonce(),
        'oauth_timestamp': str(int(time.time()))
    }

    params['oauth_token'] = token.key
    params['oauth_consumer_key'] = consumer.key

    params.update(url_params)

    req = oauth.Request(method="GET", url=url, parameters=params)

    signature_method = oauth.SignatureMethod_HMAC_SHA1()
    req.sign_request(signature_method, consumer, token)

    return req.to_url()
```

这个函数将读取两个配置文件——`config.org`配置文件包含我们需要的所有端点 URL，以及消费者密钥。`.twitterauth`文件包含我们将用于创建`Token`对象的`oauth_token`和`oauth_token_secret`。

之后，我们定义一些参数。根据 Twitter API 文档，`oauth_version`应该始终设置为`1.0`。我们还发送`oauth_nonce`，这是我们必须为每个请求生成的唯一令牌，最后是`oauth_timestamp`，这是请求创建的时间。Twitter 将拒绝在发送请求之前太长时间创建的请求。

我们附加到参数的最后一件事是`oauth_token`，它是存储在`.twitterath`文件中的令牌，以及消费者密钥，它是存储在`config.yaml`文件中的密钥。

我们执行一个请求来获取授权，如果一切顺利，我们用 SHA1 密钥对请求进行签名，并返回请求的 URL。

现在我们要添加一个函数，该函数将执行一个请求来搜索特定的标签，并将结果返回给我们。让我们继续添加另一个名为`execute_request`的函数：

```py
def execute_request(hashtag):
    config = read_config()

 if hashtag.refresh_url:
        refresh_url = hashtag.refresh_url[1:]
        url_params = dict(parse_qsl(refresh_url))
 else:
        url_params = {
            'q': f'#{hashtag.name}',
            'result_type': 'mixed'
  }

    url = prepare_request(config.search_endpoint, url_params)

    data = requests.get(url)

    results = json.loads(data.text)

    return (hashtag, results, )
```

这个函数将以`Hashtag`对象作为参数，并且在这个函数中我们要做的第一件事是读取配置文件。然后我们检查`Hashtag`对象的`refresh_url`属性是否有值；如果有，我们将删除`refresh_url`字符串前面的`?`符号。

之后，我们使用函数`parse_qsl`来解析查询字符串，并返回一个元组列表，其中元组中的第一项是参数的名称，第二项是其值。例如，假设我们有一个看起来像这样的查询字符串：

```py
'param1=1&param2=2&param3=3'
```

如果我们使用`parse_qsl`，将这个查询字符串作为参数传递，我们将得到以下列表：

```py
[('param1', '1'), ('param2', '2'), ('param3', '3')]
```

然后，如果我们将这个结果传递给`dict`函数，我们将得到一个像这样的字典：

```py
{'param1': '1', 'param2': '2', 'param3': '3'}
```

如我之前所示，`refresh_url`的格式如下：

```py
refresh_url': '?since_id=963341767532834817&q=%23python&result_type=mixed&include_entities=1
```

在解析和转换为字典之后，我们可以使用它来获取底层标签的刷新数据。

如果`Hashtag`对象没有设置`refresh_url`属性，那么我们只需定义一个字典，其中`q`是标签名称，结果类型设置为`mixed`，告诉 Twitter API 它应该返回热门、最新和实时的推文。

在定义了搜索参数之后，我们使用上面创建的`prepare_request`函数来授权请求并对其进行签名；当我们得到 URL 后，我们使用从`prepare_request`函数得到的 URL 执行请求。

我们使用`json.loads`函数来解析 JSON 数据，并返回一个包含第一项，即标签本身的元组；第二项将是我们从请求中得到的结果。

最后一步，像往常一样，在核心模块的`__init__.py`文件中导入`execute_request`函数：

```py
from .request import execute_request
```

让我们看看这在 Python REPL 中是如何工作的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/4df954cf-1c1b-40f6-951d-3c6d7acaa55d.png)

上面的输出比这个要大得多，但其中很多都被省略了；我只是想演示一下这个函数是如何工作的。

# 增强我们的代码

我们还希望为我们的用户提供良好的体验，因此我们将添加一个命令行解析器，这样我们的应用程序的用户可以在开始投票过程之前指定一些参数。我们将只实现一个参数，即`--hashtags`，用户可以传递一个以空格分隔的标签列表。

说到这一点，我们将为这些参数定义一些规则。首先，我们将限制我们要监视的标签的最大数量，因此我们将添加一个规则，即不能使用超过四个标签。

如果用户指定了超过四个标签，我们将简单地在终端上显示一个警告，并选择前四个标签。我们还希望删除重复的标签。

在显示我们谈论过的这些警告消息时，我们可以简单地在终端上打印它们，这肯定会起作用；然而，我们想要让事情变得更有趣，所以我们将使用日志包来做这件事。除此之外，实现适当的日志记录将使我们对我们想要拥有的日志类型以及如何向用户呈现它有更多的控制。

在我们开始实现命令行解析器之前，让我们添加日志记录器。在`twittervotes/core`目录中创建一个名为`app_logger.py`的文件，内容如下：

```py
import os
import logging
from logging.config import fileConfig

def get_logger():
    core_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(core_dir, '..', 'logconfig.ini')
    fileConfig(file_path)
    return logging.getLogger('twitterVotesLogger')
```

这个函数并没有做太多事情，但首先我们导入`os`模块，然后导入日志包，最后导入`fileConfig`函数，它从配置文件中读取日志配置。这个配置文件必须是`configparser`格式的，你可以在[`docs.python.org/3.6/library/logging.config.html#logging-config-fileformat`](https://docs.python.org/3.6/library/logging.config.html#logging-config-fileformat)获取有关这种格式的更多信息。

在我们读取配置文件之后，我们只返回一个名为`twitterVotesLogger`的记录器。

让我们看看我们的应用程序的配置文件是什么样的。在`twittervotes`目录中创建一个名为`logconfig.ini`的文件，内容如下：

```py
[loggers]
keys=root,twitterVotesLogger

[handlers]
keys=consoleHandler

[formatters]
keys=simpleFormatter

[logger_root]
level=INFO
handlers=consoleHandler

[logger_twitterVotesLogger]
level=INFO
handlers=consoleHandler
qualname=twitterVotesLogger

[handler_consoleHandler]
class=StreamHandler
level=INFO
formatter=simpleFormatter
args=(sys.stdout,)

[formatter_simpleFormatter]
format=[%(levelname)s] %(asctime)s - %(message)s
datefmt=%Y-%m-%d %H:%M:%S
```

因此，我们在这里定义了两个记录器，`root`和`twitterVotesLogger`；记录器负责公开我们可以在运行时使用的记录消息的方法。也是通过记录器，我们可以设置严重程度的级别，例如`INFO`，`DEBUG`等。最后，记录器将日志消息传递给适当的处理程序。

在我们的`twitterVotesLogger`的定义中，我们将严重级别设置为`INFO`，将处理程序设置为`consoleHandler`（我们将很快描述这一点），并设置一个限定名称，以便在需要获取`twitterVotesLogger`时使用。

`twitterVotesLoggers`的最后一个选项是`propagate`。由于`twitterVotesLogger`是子记录器，我们不希望通过`twittersVotesLogger`发送的日志消息传播到其祖先。如果将`propagate`设置为`0`，则由于`twitterVotesLogger`的祖先是`root`记录器，每条日志消息都会显示两次。

日志配置中的下一个组件是处理程序。处理程序是将特定记录器的日志消息发送到目的地的组件。我们定义了一个名为`consoleHandler`的处理程序，类型为`StreamHandler`，这是日志模块的内置处理程序。`StreamHandler`将日志消息发送到诸如`sys.stdout`、`sys.stderr`或文件之类的流。这对我们来说非常完美，因为我们希望将消息发送到终端。

在`consoleHandler`中，我们还将严重级别设置为`INFO`，并设置了格式化程序，该格式化程序设置为`customFormatter`；然后我们将 args 的值设置为`(sys.stdout, )`。Args 指定日志消息将被发送到的位置；在这种情况下，我们只设置了`sys.stdout`，但如果需要，可以添加多个输出流。

此配置的最后一个组件是格式化程序`customFormatter`。格式化程序简单地定义了日志消息应该如何显示。在我们的`customFormatter`中，我们只定义了消息应该如何显示并显示日期格式。

现在我们已经设置好了日志记录，让我们添加解析命令行的函数。在`twittervotes/core`中创建一个名为`cmdline_parser.py`的文件，并添加一些导入：

```py
from argparse import ArgumentParser

from .app_logger import get_logger
```

然后我们需要添加一个函数来验证命令行参数：

```py
def validated_args(args):

    logger = get_logger()

    unique_hashtags = list(set(args.hashtags))

    if len(unique_hashtags) < len(args.hashtags):
        logger.info(('Some hashtags passed as arguments were '
                     'duplicated and are going to be ignored'))

        args.hashtags = unique_hashtags

    if len(args.hashtags) > 4:
        logger.error('Voting app accepts only 4 hashtags at the 
        time')
        args.hashtags = args.hashtags[:4]

    return args
```

`validate_args`函数只有一个参数，即由`ArgumentParser`解析的参数。在此函数中，我们首先获取刚刚创建的记录器，以便向用户发送日志消息，通知可能存在的命令行参数问题。

接下来，我们将标签列表转换为集合，以便删除所有重复的标签，然后将其转换回列表。之后，我们检查唯一标签的数量是否小于在命令行传递的原始标签数量。这意味着我们有重复，并记录一条消息通知用户。

我们进行的最后一个验证是确保我们的应用程序最多监视四个标签。如果标签列表中的项目数大于四，则我们对数组进行切片，仅获取前四个项目，并且我们还记录一条消息，通知用户只会显示四个标签。

让我们添加另一个函数`parse_commandline_args`：

```py
def parse_commandline_args():
    argparser = ArgumentParser(
        prog='twittervoting',
        description='Collect votes using twitter hashtags.')

    required = argparser.add_argument_group('require arguments')

    required.add_argument(
        '-ht', '--hashtags',
        nargs='+',
        required=True,
        dest='hashtags',
        help=('Space separated list specifying the '
 'hashtags that will be used for the voting.\n'
 'Type the hashtags without the hash symbol.'))

    args = argparser.parse_args()

    return validated_args(args)
```

当我们在第一章开发应用程序时，我们看到了`ArgumentParser`的工作原理，即天气应用程序。但是，我们仍然可以了解一下这个函数的作用。

首先，我们定义了一个`ArgumentParser`对象，定义了一个名称和描述，并创建了一个名为`required`的子组，正如其名称所示，它将包含所有必填字段。

请注意，我们实际上不需要创建这个额外的组；但是，我发现这有助于保持代码更有组织性，并且在将来有必要添加新选项时更容易维护。

我们只定义了一个参数`hashtags`。在`hashtags`参数的定义中，有一个名为`nargs`的参数，我们将其设置为`+`；这意味着我可以传递由空格分隔的无限数量的项目，如下所示：

```py
--hashtags item1 item2 item3
```

在这个函数中我们做的最后一件事是使用`parse_args`函数解析参数，并将参数通过之前展示的`validate_args`函数进行验证。

让我们在`twittervotes/core`目录中的`__init__.py`文件中导入`parse_commandline_args`函数：

```py
from .cmdline_parser import parse_commandline_args
```

现在我们需要创建一个类，帮助我们管理标签并执行诸如保持标签的得分计数、在每次请求后更新其值等任务。因此，让我们继续创建一个名为`HashtagStatsManager`的类。在`twittervotes/core/twitter`中创建一个名为`hashtagstats_manager.py`的文件，内容如下：

```py
from .hashtag import Hashtag

class HashtagStatsManager:

    def __init__(self, hashtags):

        if not hashtags:
            raise AttributeError('hashtags must be provided')

        self._hashtags = {hashtag: Hashtag(hashtag) for hashtag in 
         hashtags}

    def update(self, data):

        hashtag, results = data

        metadata = results.get('search_metadata')
        refresh_url = metadata.get('refresh_url')
        statuses = results.get('statuses')

        total = len(statuses)

        if total > 0:
            self._hashtags.get(hashtag.name).total += total
            self._hashtags.get(hashtag.name).refresh_url = 
            refresh_url

    @property
    def hashtags(self):
        return self._hashtags
```

这个类也非常简单：在构造函数中，我们获取一个标签列表并初始化一个属性`_hashtags`，它将是一个字典，其中键是标签的名称，值是`Hashtag`类的实例。

更新方法获取一个包含`Hashtag`对象和 Twitter API 返回结果的元组。首先，我们解包元组值并将其设置为`hashtag`和`results`变量。`results`字典对我们来说有两个有趣的项目。第一个是`search_metadata`；在这个项目中，我们将找到`refresh_url`，而`statuses`包含了使用我们搜索的标签的所有推文的列表。

因此，我们获得了`search_metadata`、`refresh_url`和最后`statuses`的值。然后我们计算`statuses`列表中有多少项。如果`statuses`列表中的项目数大于`0`，我们将更新底层标签的总计数以及其`refresh_url`。

然后我们在`twittervotes/core/twitter`目录中的`__init__.py`文件中导入了我们刚刚创建的`HashtagStatsManager`类：

```py
from .hashtagstats_manager import HashtagStatsManager
```

这个应用程序的核心是`Runner`类。这个类将执行一个函数并将其排入进程池。每个函数将在不同的进程中并行执行，这将使程序比我逐个执行这些函数要快得多。

让我们来看看`Runner`类是如何实现的：

```py
import concurrent.futures

from rx import Observable

class Runner:

    def __init__(self, on_success, on_error, on_complete):
        self._on_success = on_success
        self._on_error = on_error
        self._on_complete = on_complete

    def exec(self, func, items):

        observables = []

        with concurrent.futures.ProcessPoolExecutor() as executor:
            for item in items.values():
                _future = executor.submit(func, item)
                observables.append(Observable.from_future(_future))

        all_observables = Observable.merge(observables)

        all_observables.subscribe(self._on_success,
                                  self._on_error,
                                  self._on_complete)
```

`Runner`类有一个初始化器，接受三个参数；它们都是在执行的不同状态下将被调用的函数。当项目的执行成功时将调用`on_success`，当一个函数的执行由于某种原因失败时将调用`on_error`，最后当队列中的所有函数都执行完毕时将调用`on_complete`。

还有一个名为`exec`的方法，它以一个函数作为第一个参数，这个函数将被执行，第二个参数是一个`Hashtag`实例的列表。

`Runner`类中有一些有趣的东西。首先，我们使用了`concurrent.futures`模块，这是 Python 的一个非常好的补充，自 Python 3.2 以来一直存在；这个模块提供了异步执行可调用对象的方法。

`concurrent.futures`模块还提供了`ThreadPoolExecutor`，它将使用线程执行异步操作，以及`ProcessPollExecutor`，它使用进程。您可以根据自己的需求轻松切换这些执行策略。

经验法则是，如果您的函数是 CPU 绑定的，最好使用`ProcessPollExecutor`，否则，由于 Python 的**全局解释器锁**（**GIL**），您将遇到性能问题。对于 I/O 绑定的操作，我更喜欢使用`ThreadPoolExecutor`。

如果您想了解更多关于 GIL 的信息，可以查看以下维基页面：[`wiki.python.org/moin/GlobalInterpreterLock`](https://wiki.python.org/moin/GlobalInterpreterLock)。

由于我们没有进行任何 I/O 绑定的操作，我们使用`ProcessPoolExecutor`。然后，我们循环遍历项目的值，这是一个包含我们的应用程序正在监视的所有标签的字典。对于每个标签，我们将其传递给`ProcessPollExecutor`的`submit`函数，以及我们要执行的函数；在我们的情况下，它将是我们应用程序的核心模块中定义的`execute_request`函数。

`submit`函数不会返回`execute_request`函数返回的值，而是返回一个`future`对象，它封装了`execute_request`函数的异步执行。`future`对象提供了取消执行、检查执行状态、获取执行结果等方法。

现在，我们希望有一种方法在执行状态改变或完成时得到通知。这就是响应式编程派上用场的地方。

在这里，我们获取`future`对象并创建一个`Observable`。`Observables`是响应式编程的核心。`Observable`是一个可以被观察并在任何给定时间发出事件的对象。当`Observable`发出事件时，所有订阅该`Observable`的观察者都将得到通知并对这些变化做出反应。

这正是我们在这里要实现的：我们有一系列未来的执行，我们希望在这些执行状态改变时得到通知。这些状态将由我们作为`Runner`初始化器参数传递的函数处理——`_on_sucess`、`_on_error`和`_on_complete`。

完美！让我们在`twittervotes/core`目录的`__init__.py`中导入`Runner`类：

```py
from .runner import Runner
```

我们项目的最后一部分是添加应用程序的入口点。我们将使用标准库中的`Tkinter`包添加用户界面。所以让我们开始实现它。在`twittervotes`目录中创建一个名为`app.py`的文件，然后让我们从添加一些导入开始：

```py
from core import parse_commandline_args
from core import execute_request
from core import Runner

from core.twitter import HashtagStatsManager

from tkinter import Tk
from tkinter import Frame
from tkinter import Label
from tkinter import StringVar
from tkinter.ttk import Button
```

在这里，我们导入了我们创建的命令行参数解析器，`execute_request`来执行对 Twitter API 的请求，还有`Runner`类，它将帮助我们并行执行对 Twitter API 的请求。

我们还导入`HashtagStatsManager`来为我们管理标签投票结果。

最后，我们有与`tkinter`相关的所有导入。

在同一个文件中，让我们创建一个名为`Application`的类，如下所示：

```py
class Application(Frame):

    def __init__(self, hashtags=[], master=None):
        super().__init__(master)

        self._manager = HashtagStatsManager(hashtags)

        self._runner = Runner(self._on_success,
                              self._on_error,
                              self._on_complete)

        self._items = {hashtag: StringVar() for hashtag in hashtags}
        self.set_header()
        self.create_labels()
        self.pack()

        self.button = Button(self, style='start.TButton', 
                             text='Update',
                             command=self._fetch_data)
        self.button.pack(side="bottom")
```

因此，在这里，我们创建了一个名为`Application`的类，它继承自`Frame`。初始化器接受两个参数：标签，这些是我们将要监视的标签，以及 master 参数，它是一个`Tk`类型的对象。

然后我们创建一个`HashtagStatsManager`的实例，传递标签列表；我们还创建`Runner`类的一个实例，传递三个参数。这些参数是在一个执行成功时将被调用的函数，执行失败时将被调用的函数，以及所有执行完成时将被调用的函数。

然后我们有一个字典推导式，它将创建一个字典，其中键是标签，值是`Tkinter`的字符串变量，`Tkinter`世界中称为`StringVar`。我们这样做是为了以后更容易更新标签的结果。

我们调用即将实现的`set_header`和`create_labels`方法，最后调用`pack`。`pack`函数将组织小部件，如按钮和标签，并将它们放在父小部件中，本例中是`Application`。

然后我们定义一个按钮，当点击时将执行`_fetch_data`函数，并使用`pack`将按钮放在框架的底部：

```py
def set_header(self):
    title = Label(self,
                  text='Voting for hasthags',
                  font=("Helvetica", 24),
                  height=4)
    title.pack()
```

这是我之前提到的`set_header`方法；它只是创建`Label`对象并将它们放在框架的顶部。

现在我们可以添加`create_labels`方法：

```py
def create_labels(self):
    for key, value in self._items.items():
        label = Label(self,
                      textvariable=value,
                      font=("Helvetica", 20), height=3)
        label.pack()
        self._items[key].set(f'#{key}\nNumber of votes: 0')
```

`create_labels`方法循环遍历`self._items`，如果您记得的话，这是一个字典，其中键是标签的名称，值是一个字符串类型的`Tkinter`变量。

首先，我们创建一个`Label`，有趣的部分是`textvariable`参数；我们将其设置为`value`，这是与特定标签相关的`Tkinter`变量。然后我们将`Label`放在框架中，最后，我们使用`set`函数设置标签的值。

然后我们需要添加一个方法来为我们更新`Labels`：

```py
def _update_label(self, data):
    hashtag, result = data

    total = self._manager.hashtags.get(hashtag.name).total

    self._items[hashtag.name].set(
        f'#{hashtag.name}\nNumber of votes: {total}')
```

`_update_label`，顾名思义，更新特定标签的标签。数据参数是 Twitter API 返回的结果，我们从管理器中获取标签的总数。最后，我们再次使用`set`函数来更新标签。

让我们添加另一个函数，实际上会发送请求到 Twitter API 的工作：

```py
def _fetch_data(self):
    self._runner.exec(execute_request,
                      self._manager.hashtags)
```

这种方法将调用`Runner`的`exec`方法来执行执行请求 Twitter API 的函数。

然后我们需要定义处理`Runner`类中创建的`Observable`发出的事件的方法；我们首先添加处理执行错误的方法：

```py
def _on_error(self, error_message):
    raise Exception(error_message)
```

这是一个`helper`方法，只是为了在请求执行出现问题时引发异常。

然后我们添加另一个处理`Observable`执行成功的方法：

```py
def _on_success(self, data):
    hashtag, _ = data
    self._manager.update(data)
    self._update_label(data)
```

`_on_success`方法将在`Runner`的一个执行成功完成时被调用，它将只是更新管理器的新数据，并在 UI 中更新标签。

最后，我们定义一个处理所有执行完成的方法：

```py
def _on_complete(self):
    pass
```

`_on_complete`将在所有`Runner`的执行完成时被调用。我们不会使用它，所以我们只使用`pass`语句。

现在是时候实现设置应用程序并初始化 UI 的函数`start_app`了：

```py
def start_app(args):
    root = Tk()

    app = Application(hashtags=args.hashtags, master=root)
    app.master.title("Twitter votes")
    app.master.geometry("400x700+100+100")
    app.mainloop()
```

此函数创建根应用程序，设置标题，定义其尺寸，并调用`mainloop`函数，以便应用程序保持运行。

最后一步是定义`main`函数：

```py
def main():
    args = parse_commandline_args()
    start_app(args)

if __name__ == '__main__':
    main()
```

`main`函数非常简单。首先，我们解析命令行参数，然后启动应用程序，并将命令行参数传递给它。

让我们看看应用程序的运行情况！运行以下命令：

```py
python app.py --help
```

您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/c3d0e26c-fbeb-405e-9809-f6a8547098ef.png)

假设我们希望投票过程运行 3 分钟，并且它将监视`#debian`，`#ubuntu`和`#arch`这些标签：

```py
python app.py --hashtags debian ubuntu arch
```

然后您应该看到以下 UI：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/0b4368f8-3691-4d0c-b79d-48b2dcfb5bd2.png)

如果您点击更新按钮，每个标签的计数都将被更新。

# 总结

在本章中，我们开发了一个在 Twitter 上投票的应用程序，并学习了 Python 编程语言的不同概念和范式。

通过创建标签投票应用程序，您已经学会了如何创建和配置 Twitter 应用程序，以及如何实现三条腿的`OAuth`身份验证来消费 Twitter API 的数据。

我们还学会了如何使用日志记录模块向我们的应用程序用户显示信息消息。与之前的模块一样，我们还使用标准库中的`ArgumentParser`模块创建了一个命令行解析器。

我们还介绍了使用`Rx`（Python 的响应式扩展）模块进行响应式编程。然后我们使用`concurrent.futures`模块来增强我们应用程序的性能，以并行方式运行多个请求到 Twitter API。

最后，我们使用`Tkinter`模块构建了一个用户界面。

在下一章中，我们将构建一个应用程序，该应用程序将从网站[`fixer.io`](http://fixer.io)获取汇率数据以进行货币转换。


# 第四章：汇率和货币转换工具

在上一章中，我们构建了一个非常酷的应用程序，用于在 Twitter 上计算投票，并学习了如何使用 Python 进行身份验证和消费 Twitter API。我们还对如何在 Python 中使用响应式扩展有了很好的介绍。在本章中，我们将创建一个终端工具，该工具将从`fixer.io`获取当天的汇率，并使用这些信息来在不同货币之间进行价值转换。

`Fixer.io`是由[`github.com/hakanensari`](https://github.com/hakanensari)创建的一个非常好的项目；它每天从欧洲央行获取外汇汇率数据。他创建的 API 使用起来简单，并且运行得很好。

我们的项目首先通过创建围绕 API 的框架来开始；当框架就位后，我们将创建一个终端应用程序，可以在其中执行货币转换。我们从`fixer.io`获取的所有数据都将存储在 MongoDB 数据库中，因此我们可以在不一直请求`fixer.io`的情况下执行转换。这将提高我们应用程序的性能。

在本章中，我们将涵盖以下内容：

+   如何使用`pipenv`来安装和管理项目的依赖项

+   使用 PyMongo 模块与 MongoDB 一起工作

+   使用 Requests 消费 REST API

说了这么多，让我们开始吧！

# 设置环境

像往常一样，我们将从设置环境开始；我们需要做的第一件事是设置一个虚拟环境，这将允许我们轻松安装项目依赖项，而不会干扰 Python 的全局安装。

在之前的章节中，我们使用`virtualenv`来创建我们的虚拟环境；然而，Kenneth Reitz（流行包*requests*的创建者）创建了`pipenv`。

`pipenv`对于 Python 来说就像 NPM 对于 Node.js 一样。但是，`pipenv`用于远不止包管理，它还为您创建和管理虚拟环境。在我看来，旧的开发工作流有很多优势，但对我来说，有两个方面很突出：第一个是您不再需要两种不同的工具（`pip`，`virtualenv`），第二个是在一个地方拥有所有这些强大功能变得更加简单。

我非常喜欢`pipenv`的另一点是使用`Pipfile`。有时，使用要求文件真的很困难。我们的生产环境和开发环境具有相同的依赖关系，您最终需要维护两个不同的文件；而且，每次需要删除一个依赖项时，您都需要手动编辑要求文件。

使用`pipenv`，您无需担心有多个要求文件。开发和生产依赖项都放在同一个文件中，`pipenv`还负责更新`Pipfile`。

安装`pipenv`非常简单，只需运行：

```py
pip install pipenv
```

安装后，您可以运行：

```py
pipenv --help
```

您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/b92b58f8-cc44-4f22-9c04-0e761751af85.png)

我们不会详细介绍所有不同的选项，因为这超出了本书的范围，但在创建环境时，您将掌握基础知识。

第一步是为我们的项目创建一个目录。让我们创建一个名为`currency_converter`的目录：

```py
mkdir currency_converter && cd currency_converter
```

现在您在`currency_converter`目录中，我们将使用`pipenv`来创建我们的虚拟环境。运行以下命令：

```py
pipenv --python python3.6
```

这将为当前目录中的项目创建一个虚拟环境，并使用 Python 3.6。`--python`选项还接受您安装 Python 的路径。在我的情况下，我总是下载 Python 源代码，构建它，并将其安装在不同的位置，因此这对我非常有用。

您还可以使用`--three`选项，它将使用系统上默认的 Python3 安装。运行命令后，您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/8784ad3b-7ce3-4d9e-bc95-e01455d19615.png)

如果你查看`Pipfile`的内容，你应该会看到类似以下的内容：

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

这个文件开始定义从哪里获取包，而在这种情况下，它将从`pypi`下载包。然后，我们有一个地方用于项目的开发依赖项，在`packages`中是生产依赖项。最后，它说这个项目需要 Python 版本 3.6。

太棒了！现在你可以使用一些命令。例如，如果你想知道项目使用哪个虚拟环境，你可以运行`pipenv --venv`；你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/f729d03d-b885-4866-a3f1-f69689ba4168.png)

如果你想为项目激活虚拟环境，你可以使用`shell`命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/17b5e4d5-1962-4054-afd5-50748321d710.png)

完美！有了虚拟环境，我们可以开始添加项目的依赖项。

我们要添加的第一个依赖是`requests`。

运行以下命令：

```py
pipenv install requests
```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/fef2a704-9e32-4cd2-b6e1-21d2a29d20a7.png)

正如你所看到的，`pipenv`安装了`requests`以及它的所有依赖项。

`pipenv`的作者是创建流行的 requests 库的同一个开发者。在安装输出中，你可以看到一个彩蛋，上面写着`PS: You have excellent taste!`。

我们需要添加到我们的项目中的另一个依赖是`pymongo`，这样我们就可以连接和操作 MongoDB 数据库中的数据。

运行以下命令：

```py
pipenv install pymongo
```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/cd80273e-1faa-4667-835c-54d65e0bfdd6.png)

让我们来看看`Pipfile`，看看它现在是什么样子：

```py
[[source]]

url = "https://pypi.python.org/simple"
verify_ssl = true
name = "pypi"

[dev-packages]

[packages]

requests = "*"
pymongo = "*"

[requires]

python_version = "3.6"
```

正如你所看到的，在`packages`文件夹下，我们现在有了两个依赖项。

与使用`pip`安装包相比，没有太多改变。唯一的例外是现在安装和移除依赖项将自动更新`Pipfile`。

另一个非常有用的命令是`graph`命令。运行以下命令：

```py
pipenv graph
```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/4b513feb-d291-4c36-abce-6d7272159f16.png)

正如你所看到的，`graph`命令在你想知道你安装的包的依赖关系时非常有帮助。在我们的项目中，我们可以看到`pymongo`没有任何额外的依赖项。然而，`requests`有四个依赖项：`certifi`、`chardet`、`idna`和`urllib3`。

现在你已经对`pipenv`有了很好的介绍，让我们来看看这个项目的结构会是什么样子：

```py
currency_converter
└── currency_converter
    ├── config
    ├── core   
```

`currency_converter`的顶层是应用程序的`root`目录。然后，我们再往下一级，有另一个`currency_converter`，那就是我们将要创建的`currency_converter`模块。

在`currency_converter`模块目录中，我们有一个核心，其中包含应用程序的核心功能，例如命令行参数解析器，处理数据的辅助函数等。

我们还配置了，与其他项目一样，哪个项目将包含读取 YAML 配置文件的函数；最后，我们有 HTTP，其中包含所有将执行 HTTP 请求到`fixer.io` REST API 的函数。

现在我们已经学会了如何使用`pipenv`以及它如何帮助我们提高生产力，我们可以安装项目的初始依赖项。我们也创建了项目的目录结构。拼图的唯一缺失部分就是安装 MongoDB。

我正在使用 Linux Debian 9，我可以很容易地使用 Debian 的软件包管理工具来安装它：

```py
sudo apt install mongodb
```

你会在大多数流行的 Linux 发行版的软件包存储库中找到 MongoDB，如果你使用 Windows 或 macOS，你可以在以下链接中看到说明：

对于 macOS：[`docs.mongodb.com/manual/tutorial/install-mongodb-on-os-x/`](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-os-x/)

对于 Windows：[`docs.mongodb.com/manual/tutorial/install-mongodb-on-windows/`](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-windows/)

安装完成后，您可以使用 MongoDB 客户端验证一切是否正常工作。打开终端，然后运行`mongo`命令。

然后你应该进入 MongoDB shell：

```py
MongoDB shell version: 3.2.11
connecting to: test
```

要退出 MongoDB shell，只需键入*CTRL *+ *D.*

太棒了！现在我们准备开始编码！

# 创建 API 包装器

在这一部分，我们将创建一组函数，这些函数将包装`fixer.io` API，并帮助我们在项目中以简单的方式使用它。

让我们继续在`currency_converter/currency_converter/core`目录中创建一个名为`request.py`的新文件。首先，我们将包括一些`import`语句：

```py
import requests
from http import HTTPStatus
import json
```

显然，我们需要`requests`，以便我们可以向`fixer.io`端点发出请求，并且我们还从 HTTP 模块导入`HTTPStatus`，以便我们可以返回正确的 HTTP 状态码；在我们的代码中也更加详细。在代码中，`HTTPStatus.OK`的返回要比只有`200`更加清晰和易读。

最后，我们导入`json`包，以便我们可以将从`fixer.io`获取的 JSON 内容解析为 Python 对象。

接下来，我们将添加我们的第一个函数。这个函数将返回特定货币的当前汇率：

```py
def fetch_exchange_rates_by_currency(currency):
    response = requests.get(f'https://api.fixer.io/latest?base=
                            {currency}')

    if response.status_code == HTTPStatus.OK:
        return json.loads(response.text)
    elif response.status_code == HTTPStatus.NOT_FOUND:
        raise ValueError(f'Could not find the exchange rates for: 
                         {currency}.')
    elif response.status_code == HTTPStatus.BAD_REQUEST:
        raise ValueError(f'Invalid base currency value: {currency}')
    else:
        raise Exception((f'Something went wrong and we were unable 
                         to fetch'
                         f' the exchange rates for: {currency}'))
```

这个函数以货币作为参数，并通过向`fixer.io` API 发送请求来获取使用该货币作为基础的最新汇率信息，这是作为参数给出的。

如果响应是`HTTPStatus.OK`（`200`），我们使用 JSON 模块的 load 函数来解析 JSON 响应；否则，我们根据发生的错误引发异常。

我们还可以在`currency_converter/currency_converter/core`目录中创建一个名为`__init__.py`的文件，并导入我们刚刚创建的函数：

```py
from .request import fetch_exchange_rates_by_currency
```

太好了！让我们在 Python REPL 中试一下：

```py
Python 3.6.3 (default, Nov 21 2017, 06:53:07)
[GCC 6.3.0 20170516] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from currency_converter.core import fetch_exchange_rates_by_currency
>>> from pprint import pprint as pp
>>> exchange_rates = fetch_exchange_rates_by_currency('BRL')
>>> pp(exchange_rates)
{'base': 'BRL',
 'date': '2017-12-06',
 'rates': {'AUD': 0.40754,
 'BGN': 0.51208,
 'CAD': 0.39177,
 'CHF': 0.30576,
 'CNY': 2.0467,
 'CZK': 6.7122,
 'DKK': 1.9486,
 'EUR': 0.26183,
 'GBP': 0.23129,
 'HKD': 2.4173,
 'HRK': 1.9758,
 'HUF': 82.332,
 'IDR': 4191.1,
 'ILS': 1.0871,
 'INR': 19.963,
 'JPY': 34.697,
 'KRW': 338.15,
 'MXN': 5.8134,
 'MYR': 1.261,
 'NOK': 2.5548,
 'NZD': 0.4488,
 'PHP': 15.681,
 'PLN': 1.1034,
 'RON': 1.2128,
 'RUB': 18.273,
 'SEK': 2.599,
 'SGD': 0.41696,
 'THB': 10.096,
 'TRY': 1.191,
 'USD': 0.3094,
 'ZAR': 4.1853}}
```

太棒了！它的工作方式正如我们所期望的那样。

接下来，我们将开始构建数据库辅助类。

# 添加数据库辅助类

现在我们已经实现了从`fixer.io`获取汇率信息的函数，我们需要添加一个类，该类将检索并保存我们获取的信息到我们的 MongoDB 中。

那么，让我们继续在`currency_converter/currency_converter/core`目录中创建一个名为`db.py`的文件；让我们添加一些`import`语句：

```py
  from pymongo import MongoClient
```

我们唯一需要`import`的是`MongoClient`。`MongoClient`将负责与我们的数据库实例建立连接。

现在，我们需要添加`DbClient`类。这个类的想法是作为`pymongo`包函数的包装器，并提供一组更简单的函数，抽象出一些在使用`pymongo`时重复的样板代码。

```py
class DbClient:

    def __init__(self, db_name, default_collection):
        self._db_name = db_name
        self._default_collection = default_collection
        self._db = None
```

一个名为`DbClient`的类，它的构造函数有两个参数，`db_name`和`default_collection`。请注意，在 MongoDB 中，我们不需要在使用之前创建数据库和集合。当我们第一次尝试插入数据时，数据库和集合将被自动创建。

如果您习惯于使用 MySQL 或 MSSQL 等 SQL 数据库，这可能看起来有些奇怪，在那里您必须连接到服务器实例，创建数据库，并在使用之前创建所有表。

在这个例子中，我们不关心安全性，因为 MongoDB 超出了本书的范围，我们只关注 Python。

然后，我们将向数据库添加两个方法，`connect`和`disconnect`：

```py
    def connect(self):
        self._client = MongoClient('mongodb://127.0.0.1:27017/')
        self._db = self._client.get_database(self._db_name)

    def disconnect(self):
        self._client.close()
```

`connect`方法将使用`MongoClient`连接到我们的本地主机上的数据库实例，使用端口`27017`，这是 MongoDB 安装后默认运行的端口。这两个值可能在您的环境中有所不同。`disconnect`方法只是调用客户端的 close 方法，并且，顾名思义，它关闭连接。

现在，我们将添加两个特殊函数，`__enter__`和`__exit__`：

```py
    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exec_type, exec_value, traceback):
        self.disconnect()

        if exec_type:
            raise exec_type(exec_value)

        return self
```

我们希望`DbClient`类在其自己的上下文中使用，并且这是通过使用上下文管理器和`with`语句来实现的。上下文管理器的基本实现是通过实现这两个函数`__enter__`和`__exit__`。当我们进入`DbClient`正在运行的上下文时，将调用`__enter__`。在这种情况下，我们将调用`connect`方法来连接到我们的 MongoDB 实例。

另一方面，`__exit__`方法在当前上下文终止时被调用。上下文可以由正常原因或抛出的异常终止。在我们的情况下，我们从数据库断开连接，如果`exec_type`不等于`None`，这意味着如果发生了异常，我们会引发该异常。这是必要的，否则在`DbClient`上下文中发生的异常将被抑制。

现在，我们将添加一个名为`_get_collection`的私有方法：

```py
    def _get_collection(self):
        if self._default_collection is None:
            raise AttributeError('collection argument is required')

        return self._db[self._default_collection]
```

这个方法将简单地检查我们是否定义了`default_collection`。如果没有，它将抛出一个异常；否则，我们返回集合。

我们只需要两个方法来完成这个类，一个是在数据库中查找项目，另一个是插入或更新数据：

```py
    def find_one(self, filter=None):
        collection = self._get_collection()
        return collection.find_one(filter)

    def update(self, filter, document, upsert=True):
        collection = self._get_collection()

        collection.find_one_and_update(
            filter,
            {'$set': document},
            upsert=upsert)
```

`find_one`方法有一个可选参数叫做 filter，它是一个带有条件的字典，将用于执行搜索。如果省略，它将只返回集合中的第一项。

在 update 方法中还有一些其他事情。它有三个参数：`filter`，`document`，以及可选参数`upsert`。

`filter`参数与`find_one`方法完全相同；它是一个用于搜索我们想要更新的集合项的条件。

`document`参数是一个包含我们想要在集合项中更新或插入的字段的字典。

最后，可选参数`upsert`，当设置为`True`时，意味着如果我们要更新的项目在数据库的集合中不存在，那么我们将执行插入操作并将项目添加到集合中。

该方法首先获取默认集合，然后使用集合的`find_on_and_update`方法，将`filter`传递给包含我们要更新的字段的字典，还有`upsert`选项。

我们还需要使用以下内容更新`currency_converter/currency_converter/core`目录中的`__init__.py`文件：

```py
from .db import DbClient
```

太好了！现在，我们可以开始创建命令行解析器了。

# 创建命令行解析器

我必须坦白一件事：我是一个命令行类型的人。是的，我知道有些人认为它已经过时了，但我喜欢在终端上工作。我绝对更有生产力，如果你使用 Linux 或 macOS，你可以结合工具来获得你想要的结果。这就是我们要为这个项目添加命令行解析器的原因。

我们需要实现一些东西才能开始创建命令行解析器。我们要添加的一个功能是设置默认货币的可能性，这将避免我们的应用用户总是需要指定基础货币来执行货币转换。

为了做到这一点，我们将创建一个动作，我们已经在第一章中看到了动作是如何工作的，*实现天气应用程序*，但是为了提醒我们，动作是可以绑定到命令行参数以执行某个任务的类。当命令行中使用参数时，这些动作会自动调用。

在进行自定义操作的开发之前，我们需要创建一个函数，从数据库中获取我们应用程序的配置。首先，我们将创建一个自定义异常，用于在无法从数据库中检索配置时引发错误。在`currency_converter/currency_converter/config`目录中创建一个名为`config_error.py`的文件，内容如下：

```py
    class ConfigError(Exception):
      pass
```

完美！这就是我们创建自定义异常所需要的全部内容。我们本可以使用内置异常，但那对我们的应用程序来说太具体了。为您的应用程序创建自定义异常总是一个很好的做法；当排除错误时，它将使您和您的同事的生活变得更加轻松。

在`currency_converter/currency_converter/config/`目录中创建一个名为`config.py`的文件，内容如下：

```py
from .config_error import ConfigError
from currency_converter.core import DbClient

def get_config():
    config = None

    with DbClient('exchange_rates', 'config') as db:
        config = db.find_one()

    if config is None:
        error_message = ('It was not possible to get your base 
                        currency, that '
                       'probably happened because it have not been '
                         'set yet.\n Please, use the option '
                         '--setbasecurrency')
        raise ConfigError(error_message)

    return config
```

在这里，我们首先从`import`语句开始。我们开始导入我们刚刚创建的`ConfigError`自定义异常，还导入`DbClient`类，以便我们可以访问数据库来检索应用程序的配置。

然后，我们定义了`get_config`函数。这个函数不会接受任何参数，函数首先定义了一个值为`None`的变量 config。然后，我们使用`DbClient`连接到`exchange_rate`数据库，并使用名为`config`的集合。在`DbClient`上下文中，我们使用`find_one`方法，没有任何参数，这意味着将返回该配置集合中的第一项。

如果`config`变量仍然是`None`，我们会引发一个异常，告诉用户数据库中还没有配置，需要再次运行应用程序并使用`--setbasecurrency`参数。我们将很快实现命令行参数。如果我们有配置的值，我们只需返回它。

我们还需要在`currency_converter/currency_converter/config`目录中创建一个`__init__.py`文件，内容如下：

```py
from .config import get_config
```

现在，让我们开始添加我们的第一个操作，它将设置默认货币。在`currency_converter/currency_converter/core`目录中添加一个名为`actions.py`的文件：

```py
  import sys
  from argparse import Action
  from datetime import datetime

  from .db import DbClient
  from .request import fetch_exchange_rates_by_currency
  from currency_converter.config import get_config
```

首先，我们导入`sys`，这样我们就可以在程序出现问题时终止执行。然后，我们从`argparse`模块中导入`Action`。在创建自定义操作时，我们需要从`Action`继承一个类。我们还导入`datetime`，因为我们将添加功能来检查我们将要使用的汇率是否过时。

然后，我们导入了一些我们创建的类和函数。我们首先导入`DbClient`，这样我们就可以从 MongoDB 中获取和存储数据，然后导入`fetch_exchange_rates_by_currency`以在必要时从`fixer.io`获取最新数据。最后，我们导入一个名为`get_config`的辅助函数，这样我们就可以从数据库的配置集合中获取默认货币。

让我们首先添加`SetBaseCurrency`类：

```py
class SetBaseCurrency(Action):
    def __init__(self, option_strings, dest, args=None, **kwargs):
        super().__init__(option_strings, dest, **kwargs)
```

在这里，我们定义了`SetBaseCurrency`类，继承自`Action`，并添加了一个构造函数。它并没有做太多事情；它只是调用了基类的构造函数。

现在，我们需要实现一个特殊的方法叫做`__call__`。当解析绑定到操作的参数时，它将被调用：

```py
    def __call__(self, parser, namespace, value, option_string=None):
        self.dest = value

        try:
            with DbClient('exchange_rates', 'config') as db:
                db.update(
                    {'base_currency': {'$ne': None}},
                    {'base_currency': value})

            print(f'Base currency set to {value}')
        except Exception as e:
            print(e)
        finally:
            sys.exit(0)
```

这个方法有四个参数，解析器是我们即将创建的`ArgumentParser`的一个实例。`namespace`是参数解析器的结果的对象；我们在第一章中详细介绍了命名空间对象，*实现天气应用程序*。值是传递给基础参数的值，最后，`option_string`是操作绑定到的参数。

我们通过为参数设置值、目标变量和创建`DbClient`的实例来开始该方法。请注意，我们在这里使用`with`语句，因此我们在`DbClient`上下文中运行更新。

然后，我们调用`update`方法。在这里，我们向`update`方法传递了两个参数，第一个是`filter`。当我们有`{'base_currrency': {'$ne': None}}`时，这意味着我们将更新集合中基础货币不等于 None 的项目；否则，我们将插入一个新项目。这是`DbClient`类中`update`方法的默认行为，因为我们默认将`upsert`选项设置为`True`。

当我们完成更新时，我们向用户打印消息，说明默认货币已设置，并且当我们触发`finally`子句时，我们退出代码的执行。如果出现问题，由于某种原因，我们无法更新`config`集合，将显示错误并退出程序。

我们需要创建的另一个类是`UpdateForeignerExchangeRates`类：

```py
class UpdateForeignerExchangeRates(Action):
    def __init__(self, option_strings, dest, args=None, **kwargs):
        super().__init__(option_strings, dest, **kwargs)
```

与之前的类一样，我们定义类并从`Action`继承。构造函数只调用基类中的构造函数：

```py
def __call__(self, parser, namespace, value, option_string=None):

        setattr(namespace, self.dest, True)

        try:
            config = get_config()
            base_currency = config['base_currency']
            print(('Fetching exchange rates from fixer.io'
                   f' [base currency: {base_currency}]'))
            response = 
            fetch_exchange_rates_by_currency(base_currency)
            response['date'] = datetime.utcnow()

            with DbClient('exchange_rates', 'rates') as db:
                db.update(
                    {'base': base_currency},
                    response)
        except Exception as e:
            print(e)
        finally:
            sys.exit(0)
```

我们还需要实现`__call__`方法，当使用此操作绑定到的参数时将调用该方法。我们不会再次讨论方法参数，因为它与前一个方法完全相同。

该方法开始时将目标属性的值设置为`True`。我们将用于运行此操作的参数不需要参数，并且默认为`False`，因此如果我们使用参数，我们将其设置为`True`。这只是一种表明我们已经使用了该参数的方式。

然后，我们从数据库中获取配置并获取`base_currency`。我们向用户显示一条消息，告诉他们我们正在从`fixer.io`获取数据，然后我们使用我们的`fetch_exchange_rates_by_currency`函数，将`base_currency`传递给它。当我们得到响应时，我们将日期更改为 UTC 时间，这样我们就可以更容易地计算给定货币的汇率是否需要更新。

请记住，`fixer.io`在中欧时间下午 4 点左右更新其数据。

然后，我们创建`DbClient`的另一个实例，并使用带有两个参数的`update`方法。第一个是`filter`，因此它将更改与条件匹配的集合中的任何项目，第二个参数是我们从`fixer.io` API 获取的响应。

在所有事情都完成之后，我们触发`finally`子句并终止程序的执行。如果出现问题，我们会在终端向用户显示一条消息，并终止程序的执行。

# 创建货币枚举

在开始命令行解析器之前，我们还需要创建一个枚举，其中包含我们的应用程序用户可以选择的可能货币。让我们继续在`currency_converter/currency_converter/core`目录中创建一个名为`currency.py`的文件，其中包含以下内容：

```py
from enum import Enum

class Currency(Enum):
    AUD = 'Australia Dollar'
    BGN = 'Bulgaria Lev'
    BRL = 'Brazil Real'
    CAD = 'Canada Dollar'
    CHF = 'Switzerland Franc'
    CNY = 'China Yuan/Renminbi'
    CZK = 'Czech Koruna'
    DKK = 'Denmark Krone'
    GBP = 'Great Britain Pound'
    HKD = 'Hong Kong Dollar'
    HRK = 'Croatia Kuna'
    HUF = 'Hungary Forint'
    IDR = 'Indonesia Rupiah'
    ILS = 'Israel New Shekel'
    INR = 'India Rupee'
    JPY = 'Japan Yen'
    KRW = 'South Korea Won'
    MXN = 'Mexico Peso'
    MYR = 'Malaysia Ringgit'
    NOK = 'Norway Kroner'
    NZD = 'New Zealand Dollar'
    PHP = 'Philippines Peso'
    PLN = 'Poland Zloty'
    RON = 'Romania New Lei'
    RUB = 'Russia Rouble'
    SEK = 'Sweden Krona'
    SGD = 'Singapore Dollar'
    THB = 'Thailand Baht'
    TRY = 'Turkish New Lira'
    USD = 'USA Dollar'
    ZAR = 'South Africa Rand'
    EUR = 'Euro'
```

这非常简单。我们已经在之前的章节中介绍了 Python 中的枚举，但在这里，我们定义了枚举，其中键是货币的缩写，值是名称。这与`fixer.io`中可用的货币相匹配。

打开`currency_converter/currency_converter/core`目录中的`__init__.py`文件，并添加以下导入语句：

```py
from .currency import Currency
```

# 创建命令行解析器

完美！现在，我们已经准备好创建命令行解析器。让我们继续在`currency_converter/currency_converter/core`目录中创建一个名为`cmdline_parser.py`的文件，然后像往常一样，让我们开始导入我们需要的一切：

```py
import sys
from argparse import ArgumentParser

from .actions import UpdateForeignerExchangeRates
from .actions import SetBaseCurrency
from .currency import Currency
```

从顶部开始，我们导入`sys`，这样如果出现问题，我们可以退出程序。我们还包括`ArgumentParser`，这样我们就可以创建解析器；我们还导入了我们刚刚创建的`UpdateforeignerExchangeRates`和`SetBaseCurrency`动作。在`Currency`枚举中的最后一件事是，我们将使用它来在解析器中的某些参数中设置有效的选择。

创建一个名为`parse_commandline_args`的函数：

```py
def parse_commandline_args():

    currency_options = [currency.name for currency in Currency]

    argparser = ArgumentParser(
        prog='currency_converter',
        description=('Tool that shows exchange rated and perform '
                     'currency convertion, using http://fixer.io 
                       data.'))
```

这里我们要做的第一件事是只获取`Currency`枚举键的名称；这将返回一个类似这样的列表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/c9385f16-58d4-4ec9-94db-6905c05a5be3.png)

在这里，我们最终创建了`ArgumentParser`的一个实例，并传递了两个参数：`prog`，这是程序的名称，我们可以称之为`currency_converter`，第二个是`description`（当在命令行中传递`help`参数时，将显示给用户的描述）。

这是我们要在`--setbasecurrency`中添加的第一个参数：

```py
argparser.add_argument('--setbasecurrency',
                           type=str,
                           dest='base_currency',
                           choices=currency_options,
                           action=SetBaseCurrency,
                           help='Sets the base currency to be 
                           used.')
```

我们定义的第一个参数是`--setbasecurrency`。它将把货币存储在数据库中，这样我们就不需要在命令行中一直指定基础货币。我们指定这个参数将被存储为一个字符串，并且用户输入的值将被存储在一个名为`base_currency`的属性中。

我们还将参数选择设置为我们在前面的代码中定义的`currency_options`。这将确保我们只能传递与`Currency`枚举匹配的货币。

`action`指定了当使用此参数时将执行哪个动作，我们将其设置为我们在`actions.py`文件中定义的`SetBaseCurrency`自定义动作。最后一个选项`help`是在显示应用程序帮助时显示的文本。

让我们添加`--update`参数：

```py
 argparser.add_argument('--update',
                           metavar='',
                           dest='update',
                           nargs=0,
                           action=UpdateForeignerExchangeRates,
                           help=('Update the foreigner exchange 
                                  rates '
                                 'using as a reference the base  
                                  currency'))
```

`--update`参数，顾名思义，将更新默认货币的汇率。它在`--setbasecurrency`参数之后使用。

在这里，我们使用名称`--update`定义参数，然后设置`metavar`参数。当生成帮助时，`metavar`关键字`--update`将被引用。默认情况下，它与参数的名称相同，但是大写。由于我们没有任何需要传递给此参数的值，我们将`metavar`设置为无。下一个参数是`nargs`，它告诉`argparser`这个参数不需要传递值。最后，我们设置`action`为我们之前创建的另一个自定义动作，即`UpdateForeignExchangeRates`动作。最后一个参数是`help`，它指定了参数的帮助文本。

下一个参数是`--basecurrency`参数：

```py
argparser.add_argument('--basecurrency',
                           type=str,
                           dest='from_currency',
                           choices=currency_options,
                           help=('The base currency. If specified it 
                                  will '
                                 'override the default currency set 
                                  by'
                                 'the --setbasecurrency option'))
```

这个参数的想法是，我们希望允许用户在请求货币转换时覆盖他们使用`--setbasecurrency`参数设置的默认货币。

在这里，我们使用名称`--basecurrency`定义参数。使用`string`类型，我们将把传递给参数的值存储在一个名为`from_currency`的属性中；我们还在这里将选择设置为`currency_option`，这样我们就可以确保只有在`Currency`枚举中存在的货币才被允许。最后，我们设置了帮助文本。

我们要添加的下一个参数称为`--value`。这个参数将接收我们的应用程序用户想要转换为另一种货币的值。

这是我们将如何编写它的方式：

```py
argparser.add_argument('--value',
                           type=float,
                           dest='value',
                           help='The value to be converted')
```

在这里，我们将参数的名称设置为`--value`。请注意，类型与我们之前定义的参数不同。现在，我们将接收一个浮点值，并且参数解析器将把传递给`--value`参数的值存储到名为 value 的属性中。最后一个参数是`help`文本。

最后，我们要添加的最后一个参数是指定值将被转换为哪种货币的参数，将被称为`--to`：

```py
   argparser.add_argument('--to',
                           type=str,
                           dest='dest_currency',
                           choices=currency_options,
                           help=('Specify the currency that the value 
                                  will '
                                 'be converted to.'))
```

这个参数与我们在前面的代码中定义的`--basecurrency`参数非常相似。在这里，我们将参数的名称设置为`--to`，它将是`string`类型。传递给此参数的值将存储在名为`dest_currency`的属性中。在这里，我们还将参数的选择设置为我们从`Currency`枚举中提取的有效货币列表；最后，我们设置帮助文本。

# 基本验证

请注意，我们定义的许多参数是必需的。然而，有一些参数是相互依赖的，例如参数`--value`和`--to`。您不能尝试转换价值而不指定要转换的货币，反之亦然。

这里的另一个问题是，由于许多参数是必需的，如果我们在不传递任何参数的情况下运行应用程序，它将接受并崩溃；在这里应该做的正确的事情是，如果用户没有使用任何参数，我们应该显示帮助菜单。也就是说，我们需要添加一个函数来执行这种类型的验证，所以让我们继续添加一个名为`validate_args`的函数。您可以在`import`语句之后的顶部添加此函数：

```py
def validate_args(args):

    fields = [arg for arg in vars(args).items() if arg]

    if not fields:
        return False

    if args.value and not args.dest_currency:
        return False
    elif args.dest_currency and not args.value:
        return False

    return True
```

因此，`args`将被传递给这个函数。`args`实际上是`time`和`namespace`的对象。这个对象将包含与我们在参数定义中指定的相同名称的属性。在我们的情况下，`namespace`将包含这些属性：`base_currency`、`update`、`from_currency`、`value`和`dest_currency`。

我们使用一个理解来获取所有未设置为`None`的字段。在这个理解中，我们使用内置函数`vars`，它将返回`args`的`__dict__`属性的值，这是`Namespace`对象的一个实例。然后，我们使用`.items()`函数，这样我们就可以遍历字典项，并逐一测试其值是否为`None`。

如果在命令行中传递了任何参数，那么这个理解的结果将是一个空列表，在这种情况下，我们返回`False`。

然后，我们测试需要成对使用的参数：`--value`（value）和`--to`（`dest_currency`）。如果我们有一个值，但`dest_currency`等于`None`，反之亦然，它将返回`False`。

现在，我们可以完成`parse_commandline_args`。让我们转到此函数的末尾，并添加以下代码：

```py
      args = argparser.parse_args()

      if not validate_args(args):
          argparser.print_help()
          sys.exit()

      return args
```

在这里，我们解析参数并将它们设置为变量`args`，请记住`args`将是`namespace`类型。然后，我们将`args`传递给我们刚刚创建的函数，即`validate_args`函数。如果`validate_args`返回`False`，它将打印帮助信息并终止程序的执行；否则，它将返回`args`。

接下来，我们将开发应用程序的入口点，它将把我们到目前为止开发的所有部分粘合在一起。

# 添加应用程序的入口点

这是本章我们一直在等待的部分；我们将创建应用程序的入口点，并将迄今为止编写的所有代码粘合在一起。

让我们在`currency_converter/currency_converter`目录中创建一个名为`__main__.py`的文件。我们之前在第一章中已经使用过`__main__`文件，*实现天气应用程序*。当我们在模块的`root`目录中放置一个名为`__main__.py`的文件时，这意味着该文件是模块的入口脚本。因此，如果我们运行以下命令：

```py
python -m currency_converter 
```

这与运行以下命令相同：

```py
python currency_converter/__main__.py
```

太好了！让我们开始向这个文件添加内容。首先，添加一些`import`语句：

```py
import sys

from .core.cmdline_parser import parse_commandline_args
from .config import get_config
from .core import DbClient
from .core import fetch_exchange_rates_by_currency
```

我们像往常一样导入`sys`包，以防需要调用 exit 来终止代码的执行，然后导入到目前为止我们开发的所有类和实用函数。我们首先导入`parse_commandline_args`函数进行命令行解析，然后导入`get_config`以便我们可以获取用户设置的默认货币，导入`DbClient`类以便我们可以访问数据库并获取汇率；最后，我们还导入`fetch_exchange_rates_by_currency`函数，当我们选择尚未在我们的数据库中的货币时将使用它。我们将从`fixer.io` API 中获取这个。

现在，我们可以创建`main`函数：

```py
def main():
    args = parse_commandline_args()
    value = args.value
    dest_currency = args.dest_currency
    from_currency = args.from_currency

    config = get_config()
    base_currency = (from_currency
                     if from_currency
                     else config['base_currency'])
```

`main`函数首先通过解析命令行参数来开始。如果用户输入的一切都正确，我们应该收到一个包含所有参数及其值的`namespace`对象。在这个阶段，我们只关心三个参数：`value`，`dest_currency`和`from_currency`。如果你还记得之前的话，`value`是用户想要转换为另一种货币的值，`dest_currency`是用户想要转换为的货币，`from_currency`只有在用户希望覆盖数据库中设置的默认货币时才会传递。

获取所有这些值后，我们调用`get_config`从数据库中获取`base_currency`，然后立即检查是否有`from_currency`可以使用该值；否则，我们使用数据库中的`base_currency`。这将确保如果用户指定了`from_currency`值，那么该值将覆盖数据库中存储的默认货币。

接下来，我们实现将实际从数据库或`fixer.io` API 获取汇率的代码，如下所示：

```py
    with DbClient('exchange_rates', 'rates') as db:
        exchange_rates = db.find_one({'base': base_currency})

        if exchange_rates is None:
            print(('Fetching exchange rates from fixer.io'
                   f' [base currency: {base_currency}]'))

            try:
                response = 
                fetch_exchange_rates_by_currency(base_currency)
            except Exception as e:
                sys.exit(f'Error: {e}')

            dest_rate = response['rates'][dest_currency]
            db.update({'base': base_currency}, response)
        else:
            dest_rate = exchange_rates['rates'][dest_currency]

        total = round(dest_rate * value, 2)
        print(f'{value} {base_currency} = {total} {dest_currency}')
```

我们使用`DbClient`类创建与数据库的连接，并指定我们将访问汇率集合。在上下文中，我们首先尝试找到基础货币的汇率。如果它不在数据库中，我们尝试从`fixer.io`获取它。

之后，我们提取我们要转换为的货币的汇率值，并将结果插入数据库，这样，下次运行程序并想要使用这种货币作为基础货币时，我们就不需要再次发送请求到`fixer.io`。

如果我们找到了基础货币的汇率，我们只需获取该值并将其分配给`dest_rate`变量。

我们要做的最后一件事是执行转换，并使用内置的 round 函数将小数点后的位数限制为两位，并在终端中打印值。

在文件末尾，在`main()`函数之后，添加以下代码：

```py
if __name__ == '__main__':
    main()
```

我们都完成了！

# 测试我们的应用程序

让我们测试一下我们的应用程序。首先，我们将显示帮助消息，看看我们有哪些选项可用：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/b0f7d3ce-7807-4396-9065-ce200aabd67b.png)

很好！正如预期的那样。现在，我们可以使用`--setbasecurrency`参数来设置基础货币：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/ad6fb0bd-bcf1-49eb-a325-f9fc65accb57.png)

在这里，我已将基础货币设置为 SEK（瑞典克朗），每次我需要进行货币转换时，我都不需要指定我的基础货币是 SEK。让我们将 100 SEK 转换为 USD（美元）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/38bfab21-ab5d-4b56-b505-d51ebb2957ee.png)

正如你所看到的，我们在数据库中没有该货币的汇率，所以应用程序的第一件事就是从`fixer.io`获取并将其保存到数据库中。

由于我是一名居住在瑞典的巴西开发人员，我想将 SEK 转换为 BRL（巴西雷亚尔），这样我就知道下次去巴西看父母时需要带多少瑞典克朗：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/4666b921-54a0-4ed8-914d-96324ba2d6d6.png)

请注意，由于这是我们第二次运行应用程序，我们已经有了以 SEK 为基础货币的汇率，所以应用程序不会再次从`fixer.io`获取数据。

现在，我们要尝试的最后一件事是覆盖基础货币。目前，它被设置为 SEK。我们使用 MXN（墨西哥比索）并从 MXN 转换为 SEK：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/py-prog-bp/img/30e9fa97-c5a3-4c03-be9f-cf743813f5de.png)

# 总结

在本章中，我们涵盖了许多有趣的主题。在设置应用程序环境时，您学会了如何使用超级新的、流行的工具`pipenv`，它已成为[python.org](https://www.python.org/)推荐的用于创建虚拟环境和管理项目依赖项的工具。

您还学会了面向对象编程的基本概念，如何为命令行工具创建自定义操作，Python 语言中关于上下文管理器的基础知识，如何在 Python 中创建枚举，以及如何使用`Requests`执行 HTTP 请求，这是 Python 生态系统中最受欢迎的包之一。

最后但并非最不重要的是，您学会了如何使用`pymongo`包在 MongoDB 数据库中插入、更新和搜索数据。

在下一章中，我们将转变方向，使用出色且非常流行的 Django web 框架开发一个完整、非常实用的网络应用程序！
