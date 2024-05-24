# 写给 Python 开发者的 JavaScript 实用指南（四）

> 原文：[`zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446`](https://zh.annas-archive.org/md5/3cb5d18379244d57e9ec1c0b43934446)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：React 与 Django

到目前为止，我们已经使用了相当多的 Express，但 Django 提供了标准 Express 应用程序所没有的功能。它具有内置的脚手架、数据库集成和模板工具，提供了一种诱人的后端解决方案。然而，正如我们所学到的，JavaScript 在前端解决方案方面具有更强大的功能。那么，我们如何将这两者结合起来呢？

我们要做的是创建一个 Django 后端，为了将两种伟大的技术联系在一起，为 React 应用提供服务。

本章将涵盖以下主题：

+   Django 设置

+   创建 React 前端

+   将所有内容整合在一起

# 技术要求

准备好使用存储库中`chapter-14`目录中提供的代码，该存储库位于[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-14`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-14)。由于我们将使用命令行工具，还需要准备好终端或命令行 shell。我们需要一个现代浏览器和本地代码编辑器。

# Django 设置

有几种不同的方法可以结合 React 和 Django，复杂程度和集成级别各不相同。我们将采取的方法是将 React 编写为 Django 应用程序的前端，加载一个模板，让 React 处理前端。然后，我们将使用标准的 Ajax 调用与 Django 路由和数据存储逻辑进行交互。这是一种将这两种技术结合在一起的中间方法，略微保持它们完全分开，但也不为每个路由创建一个 React 应用程序。我们将保持简单。

## 请告诉我们我们将要劳作在什么上？说！

我们的应用将是一个聊天机器人，将使用大师剧作家莎士比亚的话语来回应输入！首先，我们将使用一个简单的 Django 实例的数据库加载莎士比亚的完整文本；接下来，我们将编写我们的路由来搜索匹配的文本；最后，我们将创建我们的 React 应用程序，成为用户和 Django 后端之间的桥梁。我们不会在我们的 Python 中使用复杂的机器学习或语言处理，尽管如果你愿意，你可以随时将我们的机器人推向更高一步！

请注意，我们将使用 Python 3。有关安装和设置 Django 的更详细信息，包括使用虚拟环境，请访问官方文档[`docs.djangoproject.com/en/3.0/topics/install/`](https://docs.djangoproject.com/en/3.0/topics/install/)。

首先，让我们使用以下步骤设置 Django：

1.  创建一个新的虚拟环境：`python -m venv shakespeare`。

1.  启动`venv`：`source shakespeare/bin/activate`。

1.  安装 Django：`python -m pip install Django`。

1.  使用`django-admin startproject shakespearebot`开始一个新项目。

1.  测试我们的 Django 设置：`cd shakespearebot ; python manage.py runserver`。

1.  如果我们访问[`127.0.0.1:8000/`](http://127.0.0.1:8000/)，我们应该看到默认的 Django 欢迎页面。

1.  我们需要一个应用程序来使用：`python manage.py startapp bot`。

1.  在`settings.py`中将 bot 应用添加到`INSTALLED_APPS`：`'bot.apps.BotConfig'`。

接下来，我们将需要我们的莎士比亚数据集：

1.  在书的 GitHub 存储库的`chapter-14`目录中包含一个名为`Shakespeare_data.csv.zip`的文件。解压缩此文件，你就可以随时查阅莎士比亚的所有作品。我们将使用一个基本模型将这个 CSV 导入 Django。

1.  在`bot`目录中编辑`models.py`如下：

```js
from django.db import models

class Text(models.Model):
  PlayerLine = models.CharField(max_length=1000)

   def __str__(self):
       return self.PlayerLine
```

我们将保持数据库简单，只摄取文本行，而不是行周围的任何其他数据。毕竟，我们只会对语料库进行简单的文本搜索，没有比这更复杂的操作。在导入数据的下一步之前，让我们包含一个 Django 模块，以使我们的生活更轻松：`pip install django-import-export`。这个模块将允许我们通过几次点击而不是命令行过程轻松导入我们的文本。

现在我们有一个模型，我们需要在`admin.py`中注册它：

```js
from import_export.admin import ImportExportModelAdmin
from django.contrib import admin
from .models import Text

@admin.register(Text)
class TextAdmin(ImportExportModelAdmin):
   pass
```

让我们登录到 Django 的管理部分，确保一切正常运行。我们首先必须运行我们的数据库命令：

1.  准备数据库命令：`python manage.py makemigrations`。

1.  接下来，使用`python manage.py migrate`执行更改。

1.  使用`python manage.py createsuperuser`创建一个管理用户，并按照提示操作。请注意，当您创建密码时，您将看不到输入，尽管它正在使用您的输入。

1.  重新启动 Django：`python manage.py runserver`。

1.  访问[`127.0.0.1/admin`](http://127.0.0.1/admin)，并使用刚刚创建的凭据登录。

我们将在我们的管理面板中看到我们的机器人应用程序：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/dd43540b-dc16-40e2-8b67-f1aa990af75c.png)

图 14.1 - Django 的站点管理面板

太好了，那只是一个检查点。我们还有更多的工作要做！因为我们有`django-import-export`，让我们把它连接起来：

在`settings.py`文件中进行以下操作：

1.  将`import_export`添加到`INSTALLED_APPS`。

1.  在设置部分的末尾加上这行代码，正确地设置我们的静态文件路径：`STATIC_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')`。

1.  运行`python manage.py collectstatic`。

现在，您可以继续在管理面板中点击“文本”，您将看到可用的“导入”和“导出”按钮：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/68edca26-422b-4ffa-8eae-e1e190982965.png)

图 14.2 - 是时候导入我们的文本了！

点击“导入”按钮，并按照步骤导入包含莎士比亚文本的 CSV 文件：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/1662e40f-135f-4e8d-afef-d932a9eb81e0.png)

图 14.3 - 导入完成**注意：**导入会花一些时间，但不会像威尔一开始写作那样长！请务必在预览后确认导入。

## 路由我们的请求

在我们开始 React 之前，我们需要构建的下一个部分是我们的 API，它将为我们的前端提供内容。让我们看看步骤：

1.  在`bot/views.py`中，设置我们将用于测试的索引路由，以及我们将用于提供信息的 API 路由：

```js
from django.http import HttpResponse
from django.template import Context, loader
from bot.models import Text
import random
import json

def index(request):
   template = loader.get_template("bot/index.html")
   return HttpResponse(template.render())

def api(request):
   if request.method == 'POST':
       data = json.loads(request.body.decode("utf8"))
       query = data['chattext']
       responses = Text.objects.filter(PlayerLine__contains=" %s " 
       % (query))

   if len(responses) > 0:
       return HttpResponse(responses[random.randint(0,
       len(responses))])

   else:
       return HttpResponse("Get thee to a nunnery!")
```

所有这些都应该是简单的 Python，所以我们不会详细介绍。基本上，当我们向 API 发送 POST 请求时，Django 将在数据库中搜索包含通过 Ajax 发送的单词的文本行。如果找到一个或多个，它将随机返回一个给前端。如果没有，我们总是希望处理我们的错误情况，因此它将以哈姆雷特著名的一句话作为回应：“去修道院吧！”

1.  创建一个文件`bot/urls.py`，并插入以下代码：

```js
from django.urls import path

from . import views

urlpatterns = [
 path('', views.index, name='index'),
 path('api', views.api, name='api'),
]
```

1.  编辑`shakespearebot/urls.py`如下：

```js
from django.contrib import admin
from django.urls import path, include
import bot

urlpatterns = [
   path('admin/', admin.site.urls),
   path('api/', include('bot.urls')),
   path('', include('bot.urls')),
]
```

1.  还有一件事：在`shakespearebot/settings.py`中，按照以下方式移除 CSRF 中间件：

```js
'django.middleware.csrf.CsrfViewMiddleware',
```

1.  现在是有趣的部分：我们用于测试的前端。创建一个名为`bot/`的文件

`templates/bot/index.html`并添加以下 HTML 设置：

```js
<!DOCTYPE html>

<html>

<head>
 <style>
 textarea {
 height: 500px;
 width: 300px;
 }
 </style>
</head>

<body>
 <form method="POST" type="" id="chat">
 <input type="text" id="chattext"></textarea>
 <button id="submit">Chat</button>
 <textarea id="chatresponse"></textarea>
 </form>

</body>

</html>
```

在这里，我们可以看到一些基本的表单和一些样式 - 没有太多内容，因为这只是一个用来测试我们对 API 理解是否正确的页面。

1.  在表单之后插入这个脚本：

```js
<script>
   document.getElementById('submit').addEventListener('click', (e) 
   => {
     e.preventDefault()

     let term = document.getElementById('chattext').value.split('
      ')
     term = term[term.length - 2] || term[0]

     fetch("/api", {
       method: "POST",
       headers: {
         'Content-Type': 'application/json'
       },
       body: JSON.stringify({ chattext: term })
     })
       .then(response => response.text())
       .then(data => document.querySelector('#chatresponse').value
        += `\n${data}\n`)
   })
 </script>
```

到目前为止，fetch 调用的结构应该很熟悉，所以让我们快速浏览一下：当点击按钮时，将文本按空格分割，选择倒数第二个单词（最后一个“单词”可能是标点符号），或者如果是一个单词条目，则是单词本身。将这个术语发送到 API，并等待响应。

如果一切正常工作，我们应该会看到一个非常激动人心的页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/60eda0bf-d4bd-4160-8c7d-37ac3cb6545e.png)

图 14.4 - 这是一个开始！

虽然不多，但这应该足以测试我们的后端。尝试在聊天框中输入几个单词，单击聊天，然后看看会发生什么。希望您能听到很久以前在阿文长听到的一些话。

# 创建 React 前端

如前所述，有几种不同的方法可以使用 Django 和 React。我们将分别设置我们的前端，并让 React 做自己的事情，让 Django 做自己的事情，并让它们在中间握手。正如我们将看到的，这种方法确实有其局限性，但这是一个基本介绍。我们以后会变得更加复杂。

让我们开始吧，首先创建一个新的 React 应用程序：

1.  切换到`shakespearebot`目录（而不是`bot`）并执行`npx create-react-app react-frontend`。

1.  继续执行`cd react-frontend && yarn start`并在`http://localhost:3000`访问开发服务器，以确保一切正常。您应该在前述 URL 收到 React 演示页面。使用*Ctrl* + *C*停止服务器。

1.  执行`yarn build`。

现在，这里的事情有点受限制。我们现在所做的是执行创建站点的生产优化构建。这是设计为发布代码，而不是开发代码，因此限制在于您无法编辑代码并在不再次运行构建的情况下反映出来。考虑到这一点，让我们构建并继续我们的设置。

在我们的`shakespearebot`目录中，我们将对`settings.py`和`urls.py`进行一些编辑：

1.  在`settings.py`的`TEMPLATES`数组中，将`DIRS`更改为`'DIRS': [os.path.join(BASE_DIR, 'react-frontend')],`。

1.  同样在`settings.py`中，修改`STATIC_URL`和`STATICFILES_DIRS`变量如下：

```js
STATIC_URL = '/static/'
STATICFILES_DIRS = (
 os.path.join(BASE_DIR, 'react-frontend', 'build', 'static'),

)
```

1.  在`urls.py`中添加一行，以便`urlpatterns`数组读取如下：

```js
urlpatterns = [
   path('admin/', admin.site.urls),
   path('api/', include('bot.urls')),
   path('', include('bot.urls')),
]
```

1.  在`bot`目录中，是时候将我们的前端指向我们的静态目录了。首先，编辑`urls.py`，创建一个`urlpatterns`部分如下：

```js
urlpatterns = [
    path('api', views.api, name='api'),
    path('', views.index, name='index'),
]
```

1.  接下来，我们的视图将需要我们静态目录的路径。`bot/views.py`需要更改`index`路由以使用我们的 React 前端：

```js
def index(request):
    return render(request, "../react-frontend/build/index.html")
```

那应该是我们需要的。继续通过运行`python manage.py runserver`在根级别启动服务器，然后访问`http://127.0.0.1:8000`并祈祷吧！您应该看到 React 欢迎页面！如果是这样的话，恭喜；我们已经准备好继续了。如果您遇到任何问题，请随时查阅 GitHub 存储库上的第二个航点目录。

完成我们的脚手架后，让我们看一个 React 与 Django 完整交互的示例。

# 将所有内容整合在一起

我们将使用一个完整的带有前端和后端的莎士比亚机器人。继续导航到`shakespearebot-complete`目录。在接下来的步骤中，我们将设置我们的应用程序，导入我们的数据，并与前端交互：

1.  首先，使用`python manage.py migrate`运行 Django 迁移并使用`python manage.py createsuperuser`创建用户。

1.  使用`python manage.py runserver`启动服务器。

1.  在`http://localhost:8000/admin`登录。

1.  转到`http://localhost:8000/admin/bot/text/`并导入`Shakespeare_text.csv`文件（这将需要一些时间）。

1.  在导入过程中，我们可以继续使用`cd react-frontend`命令检查我们的前端。

1.  使用`yarn install`安装我们的依赖项。

1.  使用`yarn start`启动服务器。

1.  现在，如果您导航到`http://localhost:3000`，我们应该看到我们的前端：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/4b67307b-ddfe-4785-a784-d076b90b4f79.png)

图 14.5 - 我们完整的 Shakespearebot

1.  使用*Ctrl* + *C*停止开发服务器。

1.  执行`yarn build`。

1.  导入完成后，我们可以访问我们的前端，然后我们应该能够通过在框中输入文本并单击“立即说话”按钮与莎士比亚互动。在[`localhost:8000/`](http://localhost:8000/)尝试一下。

有趣！它有点粗糙，肯定可以从前端的一些 CSS 工作和后端的智能方面通过自然语言处理中受益，但这并不是我们目前的目标。我们取得了什么成就？我们利用了我们的 Python 知识，并将其与 React 结合起来创建了一个完整的应用程序。在下一节中，我们将更仔细地研究应用程序的 React 部分。

## 调查 React 前端

我们的 React 前端目录结构非常简单：

```js
.
├── App.css
├── App.js
├── App.test.js
├── components
│   ├── bot
│   │ └── bot.jsx
│   ├── chatpanel
│   │ ├── chatpanel.css
│   │ └── chatpanel.jsx
│   └── talkinghead
│       ├── shakespeare.png
│       ├── talkinghead.css
│       └── talkinghead.jsx
├── css
│   ├── parchment.jpg
│   └── styles.css
├── index.css
├── index.js
├── logo.svg
├── serviceWorker.js
└── setupTests.js
```

就像任何其他 React 应用程序一样，我们将从我们的根组件开始，这种情况下是`App.js`：

```js
import React from 'react';
import Bot from './components/bot/bot';
import './App.css';
import './css/styles.css'

function App() {
 return (
   <>
     <h1>Banter with the Bard</h1>
     <Bot />
   </>
 );
}

export default App;
```

到目前为止很简单：一个组件。让我们看看`components/bot/bot.jsx`：

```js
import React from 'react'
import TalkingHeadLayout from '../talkinghead/talkinghead'
import ChatPanel from '../chatpanel/chatpanel'
import { Col, Row, Container } from 'reactstrap'

export default class Bot extends React.Component {
 constructor() {
   super()

   this.state = {
     text: [
       "Away, you starvelling, you elf-skin, you dried neat's-tongue, 
        bull's-pizzle, you stock-fish!",
       "Thou art a boil, a plague sore.",
       "Speak, knave!",
       "Away, you three-inch fool!",
       "I scorn you, scurvy companion.",
       "Thou sodden-witted lord! Thou hast no more brain than I have in 
        mine elbows",
       "I am sick when I do look on thee",
       "Methink'st thou art a general offence and every man should beat 
        thee."
     ]
   }

   this.captureInput = this.captureInput.bind(this)
 }
```

到目前为止，除了常规设置外，没有什么特别令人兴奋的事情：我们导入了`reactstrap`，我们将用它来进行一些布局帮助，并在状态中定义了一个包含一些莎士比亚式的侮辱的文本数组。我们的最后一行涉及`captureInput`方法。这是什么：

```js
captureInput(e) {
   const question = document.querySelector('#question').value
   fetch(`/api?chattext="${question}"`)
     .then((response) => response.text())
     .then((data) => {
       this.setState({
         text: `${data}`
       })
     })
 }
```

很棒！我们知道这在做什么：这是对同一服务器的标准 Ajax 调用，其中包含一个带有我们问题的 GET 请求。这与我们在 Python 中所做的有点不同，因为我们使用 GET 而不是 POST 来简化设置，但这只是一个微不足道的区别。

接下来的部分只是我们的渲染：

```js
render() {
   const { text } = this.state

   return (
     <div className="App">
       <Container>
         <Row>
           <Col>
             <ChatPanel speak={this.captureInput} />
           </Col>
           <Col>
             <TalkingHeadLayout response={text} />
           </Col>
         </Row>
       </Container>
     </div>
   )
 }
}
```

我们的说话头有一点动画效果，我们是通过`components/talkinghead/talkinghead.jsx`中的一个 Node.js 模块来实现的：

```js
import React from 'react'
import ReactTypingEffect from 'react-typing-effect';

import './talkinghead.css'
import TalkingHead from './shakespeare.png'

export default class TalkingHeadLayout extends React.Component {
 render() {
   return (
     <div id="talkinghead">
       <div className="text">
         <ReactTypingEffect text={this.props.response} speed="50" 
          typingDelay="0" />
       </div>
       <img src={TalkingHead} alt="Speak, knave!" />
     </div>
   )
 }
}
```

这基本上就是我们应用程序的全部内容了！

在本章中，我们玩得有点开心，让我们回顾一下我们学到了什么。

# 摘要

虽然我们的重点大多是通过选择 Node.js 和 Express 而不是 Python 和 Django 来摆脱 Python，但将它们整合起来是可行的。我们在这里使用了一个特定的范例：一个 React 应用程序作为静态构建的应用程序嵌入到 Django 应用程序中。Django 应用程序将 HTTP 请求路由到 API`bot`应用程序（如果 URL 中包含`/api`），或者对于其他所有内容，路由到 React`react-frontend`应用程序。

将 Django 与 React 整合起来并不是世界上最容易的事情，这只是如何将它们耦合在一起的一种可能的范例，我称之为*紧密耦合*的脚手架。如果我们的 React 和 Django 应用程序完全分开，并且只通过 Ajax 进行 XHR 调用进行交互，那可能是一个更贴近实际情况的场景。然而，这将涉及为两个部分分别设置，而今天我们构建的是一个整个应用程序的单一服务器。

在下一章中，我们将在一个更直接的互补技术应用中使用 Express 和 React。


# 第十五章：将 Node.js 与前端结合

现在我们知道了前端框架和 Node.js，让我们将两端连接起来。我们将构建三个小应用程序，以演示我们的知识几乎实现全栈功能。毕竟，前端和后端都想要彼此了解！这将是我们首次尝试同时使用这些技术，所以一定要给自己足够的空间和时间来学习，因为这些是重要但非常重的话题。

本章将涵盖以下主题：

+   理解架构握手

+   前端和 Node.js：React 和图像上传

+   使用 API 和 JSON 创建食谱书

+   使用 Yelp 和 Firebase 创建餐厅数据库

# 技术要求

准备好使用存储库的`Chapter-15`目录中提供的代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-15`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-15)。由于我们将使用命令行工具，还要准备好您的终端或命令行 shell。我们需要一个现代浏览器和一个本地代码编辑器。

# 理解架构握手

既然我们在前端和后端都有了 JavaScript 的经验，让我们讨论一下将这两个部分绑在一起到底意味着什么。我们知道前端的 JavaScript 非常适合用户交互、视觉、数据验证和其他与用户体验相关的部分。后端的 Node.js 是一个强大的服务器端语言，可以帮助我们做几乎任何其他服务器端语言需要做的事情。那么，理论上将这两端结合起来是什么样子呢？

也许你会想知道为什么一个应用程序会有*两端。我们知道 Python、Node.js 和 JavaScript 都执行不同的任务，并且在前端或后端执行，但背后的理论是什么？答案是：软件工程中有一个被称为*关注分离*的原则，基本上是指程序的每个部分应该做一项或几项任务，并且做得很好。与其使用单片应用程序，实际上，一个对规模有良好反应的模块化系统的概念更高效。在本章中，我们将创建三个应用程序来使用这个原则。

# 前端和 Node.js - React 和图像上传

让我们从将 React 和 Node 绑定在一起开始。准备好跟随解决方案代码一起进行，网址是[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-15/photo-album`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-15/photo-album)。我们将构建一个类似于这样的相册应用程序：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/56812bfe-0905-4732-8d60-6ba855c16ae1.png)

图 15.1 - 我们的相册

我们将首先探索架构布局，然后我们将审查 React 代码，最后我们将检查 Express 后端。

## 架构

这个应用程序将使用后端的 Node.js 来存储我们上传的文件，并在前端使用 React。但是我们该如何做呢？从概念上讲，我们需要告诉 React 使用 Express 应用程序来提供 React 信息并消耗我们发送的文件。为了实现这一点，我们在`package.json`文件中使用了一个*代理*。它基本上看起来像这样：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/c279a2d6-5c0c-49da-8b52-784590d62225.png)

图 15.2 - 代理

如果您对代理的概念不熟悉，基本上它在计算中的意思与英语中的意思相同：一个代理人代表另一个代理人执行操作。它本质上是一个中间人，正如这个图表所示，它可以被认为是我们目的的中间人。由于 React 和前端 JavaScript 无法与文件系统交互或执行我们在第十二章中学到的其他重要操作，*Node.js vs Python*，以及第十三章 *使用 Express*，我们需要使用我们的能力将前端和后端*连接*在一起。因此，代理的概念。

让我们看一下`package.json`中的一行：

```js
"proxy": "http://localhost:3001",
```

这告诉 React 将某些请求路由到我们的 Express 应用程序。如果您正在从 GitHub 上跟随代码，这意味着我们实际上需要执行一些不同的`npm`命令：

1.  首先，在`photo-album`目录中安装 Express 的包：`npm install`。

1.  启动 Express 服务器：`npm start`。

1.  在另一个终端窗口中，`cd`进入`client`目录并运行`npm install`。

1.  现在，使用`npm start`启动 React 应用程序。

当我们访问`http://localhost:3000`时，我们的相册应用程序已经准备好使用。尝试通过选择文件并点击上传来上传照片。UI 也会刷新并显示您刚刚上传的照片。恭喜！这是一个端到端的应用程序！

那么这段代码在做什么呢？让我们来分析一下。

首先，我们来看一下 JavaScript。

## 调查 React JSX

打开`client/src/components/upload/Upload.jsx`。我们将首先检查`render()`方法的内容：

```js
<p><button id="upload" onClick={this.upload}>Upload Photo</button></p>
<div id="uploadForm" className="w3-modal">   <form method="post"
 encType="multipart/form-data">
     <p><input type="file" name="filetoupload" /></p>
     <p><button type="submit" onClick={this.uploadForm}>Upload</button></p>
   </form>
</div>
```

太好了，这是一个基本的 HTML 表单。这个表单中唯一与 React 相关的部分是点击处理程序。让我们看一下表单的`onClick`方法：`this.uploadForm`。如果我们查看该方法，我们将看到我们上传表单的真正功能：

```js
 uploadForm(e) {
 e.preventDefault();
 const formData = new FormData()

 formData.append('file', document.querySelector('input').files[0]);

 fetch("http://localhost:3000/upload", {
   method: 'POST',
   body: formData
 })
   .then(() => {
     this.props.reload()
   })
}
```

您准备好查看 Node.js Express 路由了吗？

## 解密 Express 应用程序

打开`routes/upload.js`。它非常简单：

```js
const express = require('express');
const formidable = require('formidable');
const router = express.Router();
const fs = require('fs');

router.post('/', (req, res, next) => {
  const form = new formidable.IncomingForm().parse(req)
    .on('fileBegin', (name, file) => {
      file.path = __dirname + '/../public/images/' + file.name
    })
    .on('file', () => {
      res.sendStatus(200)
    })
});

module.exports = router;
```

为了让我们的生活变得更轻松，我们使用了一个名为 Formidable 的表单处理程序包。当通过 Ajax 收到 POST 请求到`/upload`端点时，它将运行此代码。当通过 Ajax 接收到表单时，我们的承诺会监听文件并触发`fileBegin`和`file`事件，这将把文件写入磁盘，然后发出成功信号。这是我们在`Upload.jsx`中使用的上传表单的方法，以及我们的应用程序的两个方面如何联系在一起，以执行前端 JavaScript 无法单独执行的操作——访问服务器的文件系统。

使用前端上传几张图片。您会注意到它们将存储在`public/images`中，就像我们在代码中读到的那样。请注意，这个系统非常简单：它不会检查是否是图像文件，而是盲目地接受我们发送的内容并将其存储在文件系统中。在实践中，**这是危险的**。在处理用户输入时，*始终*需要预防攻击和可能的恶意文件。虽然保护您的 Web 应用程序的方法有些超出了本书的范围，但需要牢记的一个基本原则是：*不要相信用户*。我们已经研究了在前端验证输入的方法，虽然这很有用，但在后端也检查它同样重要。一些可能的威胁减少方法包括列出某些文件扩展名，黑名单其他文件扩展名，并使用沙盒环境来运行上传文件的分析代码，以确定它是否是无害的图像文件。

现在我们已经上传了我们的图片，让我们继续进行应用程序的检索方面。打开`routes/gallery.js`：

```js
var express = require('express');
const fs = require('fs');

var router = express.Router();

router.get('/', (req, res, next) => {
 fs.readdir(`${__dirname}/../public/images`, (err, files) => {
     if (err) {
       res.json({
         path: '',
         files: []
       });
       return;
     }

     const data = {
       path: 'images/',
       files: files.splice(1,files.length) // remove the .gitignore
     };
     res.json(data);
 });
});

router.delete('/:name', (req, res) => {
 fs.unlink(`${__dirname}/../public/images/${req.params.name}`, (err) => {
   res.json(1)
 });
});

module.exports = router;
```

希望这不会太难解释。在我们的 GET 路由中，我们首先检查文件系统，看看我们是否可以访问文件。如果出现某种原因的错误，比如权限不正确，我们将向前端发送错误并中止。否则，我们将格式化我们的返回数据并发送！非常简单。

我们的下一个方法定义了 DELETE 功能，它是一个简单的文件系统 unlink 方法。这个功能的前端并不是很复杂：如果你点击我们画廊中的一张图片，它将删除这张照片。当然，在实践中，你可能希望有一些更好的用户界面和确认消息，但对于我们的目的来说，这已经足够了。

欢迎来到你的第一个端到端应用程序！

继续进行我们的下一个应用程序！

# 使用 API 和 JSON 创建食谱

使用后端的美妙之一是促进应用程序、文件系统和 API 之间的通信。以前，我们所做的所有工作都局限于前端，没有持久性。现在我们将制作一个食谱应用程序，以 JSON 格式保存我们的信息。别担心，我们将在第十八章中使用数据库，*Node.js 和 MongoDB*。现在，我们将使用本地文件。这是我们要构建的内容：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/9a54d97b-58a7-4f23-8ffa-b4afb26f54c3.png)

图 15.3 - 我们的食谱册

首先，我们将使用第三方 API 设置凭据，然后继续编写代码。

## 设置应用程序

在[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-15/recipe-book/`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-15/recipe-book/)上克隆起始代码。确保在该目录和`client`内执行`npm install`。我们还需要做一些设置来访问我们的 API。要访问 Edamam API，请在[`developer.edamam.com/`](https://developer.edamam.com/)注册免费 API 密钥以获取食谱搜索 API。

在我们项目的根目录，创建一个`.env`文件，并填写如下内容：

```js
APPLICATION_ID=<your id>
APPLICATION_KEY=<your key>
```

请注意，这些都是构造为环境变量，没有分号或空格。

我们接下来要做的一步是确保我们的应用程序可以读取这些变量。在`app.js`的末尾附近，你会看到这个：

```js
console.log(process.env.APPLICATION_ID, process.env.APPLICATION_KEY);
```

`process.env.<variable name>`的构造方式是我们如何访问`.env`中的环境变量的。提供这种访问的机制是`dotenv`包；你可以看到它包含在`package.json`中；文件中的环境变量默认情况下不包括在内。

为什么我们要使用环境文件？正如我们将在第十七章中学到的那样，*安全和密钥*，我们不希望在我们可能提交到 GitHub 或类似平台的代码中暴露我们的 API 密钥，因为那样会允许任何人使用（和滥用）我们的密钥。我们必须保持它们的安全性，如果你注意到`.gitignore`文件中，我已经列出了`.env`不要在 Git 中提交，这就是为什么你必须自己创建这个文件。这是敏感信息的最佳实践。虽然这可能会使开发人员之间共享代码变得有点棘手，但最好还是将敏感信息与我们的代码分开。

让我们测试我们的 API。

## 测试 API

如果你阅读`routes/tests.js`，你可以看到我们到底在做什么：

```js
const https = require('https');

require('dotenv').config();

https.get(`https://api.edamam.com/search?app_id=${process.env.APPLICATION_ID}&app_key=${process.env.APPLICATION_KEY}&q=cheesecake`, (res) => {
 console.log("Got response: " + res.statusCode)

 res.setEncoding('utf8')
  res.on("data", (chunk) => {
   console.log(chunk)
 })
}).on('error', (e) => {
 console.log("Got error: " + e.message);
})
```

我们的`fetch`调用是硬编码为搜索`cheesecake`（我最喜欢的甜点...问我食谱），如果我们用`node routes/tests.js`运行它，我们将在控制台中看到一堆 JSON 返回。如果你遇到任何问题，请确保检查你的 API 密钥。

## 深入代码

既然我们知道我们的 API 调用是有效的，让我们切换到我们的前端。看一下`client/src/components/search/Search.jsx`及其`render`函数：

```js
render() {
 return (
   <h2>Search for: <input type="text" id="searchTerm" />
     <button onClick={this.submitSearch}>Search!</button></h2>
 )
}
```

到目前为止，这是一个简单的表单。接下来，让我们看看`submitSearch`方法：

```js
 submitSearch(e) {
 e.preventDefault()

 fetch(`http://localhost:3000/search?q=${document.querySelector('#searchTerm').value}`)
   .then(data => data.json())
   .then((json) => {
     this.props.handleSearchResults(json)
   })
}
```

我们再次使用代理来从表单提交我们的搜索。在获得结果后，我们将 JSON 传递给来自父组件`RecipeBook`的`props`的`handleSearchResults`方法。我们稍后会看一下，但现在让我们切换回 Express 应用程序，看看我们的搜索路由在做什么。看一下`routes/search.js`。

GET 路由实际上非常简单：

```js
router.get('/', (req, res, next) => {
 https.get(`https://api.edamam.com/search?app_id=${process.env.APPLICATION_ID}&app_key=${process.env.APPLICATION_KEY}&q=${req.query.q}`, (data) => {

   let chunks = '';

   data.on("data", (chunk) => {
     chunks += chunk
   })

   data.on("end", () => {
     res.send(JSON.parse(chunks))
   })

   data.on('error', (e) => {
     console.log("Got error: " + e.message);
   })
 })
});
```

这应该看起来有点类似于我们的测试文件。我们再次使用我们的`.env`文件来进行搜索查询，但这次我们传递了查询字符串参数进行搜索并处理错误。我们的`data.on("end")`处理程序将我们的结果传递回 React，以便在`RecipeBook.jsx`中使用`handleSearchResults`方法：

```js
handleSearchResults(data) {
 const recipes = []

 data.hits.forEach( (item) => {
   const recipe = item.recipe

   recipes.push({
     "title": recipe.label,
     "url": recipe.url,
     "image": recipe.image
   })
 })

 this.setState({
   recipes: recipes
 })
}
```

我们正在解析出我们应用程序所需的数据，并将其分配给组件的状态。到目前为止一切顺利！

接下来是食谱书的`render`方法，用于显示我们的搜索结果：

```js
<Search handleSearchResults={this.handleSearchResults} />

{
 recipes.length > 0 ? (
   <>
     <p>Search Results</p>
     <div className="card-columns">
       {
         recipes.map((recipe, i) => (
           <Recipe recipe={recipe} key={i} search="true" 
            refresh={this.refresh} />
         ))
       }
     </div>
   </>
 ) : <p></p>
```

我们使用另一个三元运算符来有条件地呈现我们的结果，如果有的话，作为`<Recipe>`组件。我们的 key 属性只是 React 希望项目具有的唯一标识符，但`refresh`属性是一个有趣的属性。让我们看看它在`Recipe`组件中是如何使用的。

我们的`Recipe`组件的`render`方法相当标准：它使用一些 Bootstrap 组件来呈现我们漂亮的小卡片，但除此之外并不引人注目。`save`方法才是我们真正想要调查的内容：

```js
save(e) {
   e.preventDefault()

   const recipe = { [this.props.recipe.title]: this.props.recipe }

   fetch('http://localhost:3000/recipes', {
     method: 'POST',
     headers: {
       'Accept': 'application/json',
       'Content-Type': 'application/json'
     },
     body: JSON.stringify(recipe)
   })
   .then(json => json.json())
   .then( (data) => {
     this.props.refresh(data)
   })
 }
```

`const recipe`声明可能看起来有点奇怪，让我们来解开它。这是创建一个对象键/值对，对于键，我们使用了食谱的标题。因为它是一个变量，我们希望使用方括号来表示它应该被解释。我们不能使用点属性作为键，所以我们的标题将是一个字符串。

这是一个构造中食谱的示例可能是这样的：

```js
{"Strawberry Cheesecake Parfaits": {"title":"Strawberry Cheesecake Parfaits", "image":"https://www.edamam.com/web-img/d4c/d4c3a4f1db4e8c413301ae1f324cf32a.jpg", "url":"http://honestcooking.com/strawberry-cheesecake-parfaits/"}}
```

它包含了我们之前在`RecipeBook.jsx`中映射对象时指定的所有信息。我们过程的下一步是使用另一个`fetch`请求将食谱保存到文件系统中。

回到 Express，这次是到`routes/recipes.js`！

让我们逐部分查看文件。在我们的 Express 方法之外，我们有一个`readData`方法，它检查我们的`recipes.json`文件是否存在：

```js
const readData = () => {
 if (!fs.existsSync(__dirname + "/../data/recipes.json")) {
   fs.writeFileSync(__dirname + "/../data/recipes.json", '[]')
 }

 return JSON.parse(fs.readFileSync(__dirname + "/../data/recipes.json"))
}
```

如果没有，它将创建一个包含空数组的文件。然后将文件的内容（无论是空的还是非空的）返回给调用函数。

我们的 GET 方法从`readData`中消耗数据，并将其发送到响应中，这次是到`RecipeBook.jsx`：

```js
router.get('/', (req, res, next) => {
 const recipes = readData()
 res.json(recipes)
})
```

`RecipeBook.render`方法的第二部分（我们没有看到）类似于搜索结果的 JSX，并且消耗了这个 JSON。

我们的`save`方法与我们的`readData`方法有些相似：

```js
router.post('/', (req, res) => {
 let recipes = readData()
 const data = req.body
 recipes.push(data)
 fs.writeFileSync(__dirname + "/../data/recipes.json",JSON.stringify(recipes))
 res.json(recipes)
})
```

请注意，它还将 JSON 发送到响应，因此当项目保存时，它还会在`RecipeBook.jsx`中填充保存的食谱。可能不用说，但请注意我们再次使用`readData`方法，而不是重写相同的逻辑，使我们的代码保持 DRY。

这就是我们应用程序的逻辑！我们成功地将 API、Node.js、Express 和 React 组合成了一个端到端的应用程序。接下来，我们将创建一个更符合实际的应用程序：我们将创建一个餐厅搜索应用程序，将其保存到一个云数据库中，并通过 JavaScript 访问。

# 使用 Yelp 和 Firebase 创建餐厅数据库

到目前为止，我们的应用程序相当简单，只是在文件系统上存储信息。然而，在大多数情况下，您可能希望它是某种数据库，而不是静态文件。我们将使用 Firebase，这是一个与 JavaScript 兼容良好的基于云的 NoSQL 数据库，但首先让我们设置 React 脚手架。

## 开始行 - 创建一个 React 应用程序

我们之前已经进行了几次这样的设置，所以这应该不足为奇：

1.  使用`npx create-react-app restaurant-finder`创建一个新的 React 应用程序，我们准备好了！

1.  使用`npm start`测试您的设置，并访问`http://localhost:3000`。

## 使用 Firebase 进行设置

我们要做的第一件事是设置我们的 Firebase 帐户。

请记住，Firebase 的用户界面（与大多数网站一样）会定期更改，因此我不会为注册过程向您展示截图。如果您在设置过程中遇到任何问题，可以查阅文档。以下是步骤：

1.  转到[`firebase.google.com`](https://firebase.google.com)。

1.  如果您还没有 Google 帐户，您需要创建一个，然后访问控制台。

1.  创建一个名为`restaurant-database`的新项目。

1.  您可以选择为项目启用 Google Analytics；这取决于您。

1.  在项目概述页面上，我们将使用</>按钮访问网页应用程序的设置说明。

1.  在下一个屏幕上，创建一个应用程序昵称（您可以再次使用`restaurant-database`），您不需要设置 Firebase Hosting。

1.  下一个屏幕将向您显示包含您的 Firebase 配置的代码，但*我们不会完全按照说明进行*，因为我们可以使用 Node 模块来帮助我们！不过，请复制`firebaseConfig`变量中的信息：我们以后会用到它。

1.  当您的数据库创建好后，转到 UI 中的数据库选项卡，选择实时数据库，并在**测试模式**下启动它。

然后您应该看到类似于这样的屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/632bcc84-7961-490e-95f8-7b546c4edea7.png)

图 15.4 - Firebase 的基本测试模式视图

接下来，我们将返回到命令行，并准备好使用 Firebase。安装 Firebase 工具包：`npm install firebase`。

安装就是这样！接下来，在我们项目的根目录创建一个`.env`文件，并输入您之前从`firebaseConfig`中复制的凭据，类似于这样：

```js
REACT_APP_apiKey=<key>
REACT_APP_authDomain=restaurant-database-<id>.firebaseapp.com
REACT_APP_databaseURL=https://restaurant-database-<id>.firebaseio.com
REACT_APP_projectId=restaurant-database-<id>
REACT_APP_storageBucket=restaurant-database-<id>.appspot.com
REACT_APP_messagingSenderId=<id>
REACT_APP_appId=<id>
```

请注意`REACT_APP_`的前缀，等号，引号和缺少尾随逗号。填写您的配置类似。 

在我们进一步之前，让我们测试我们的数据库。

## 测试我们的数据库

现在我们将创建一些 React 组件。在`src`中创建一个`components`目录，在其中创建两个名为`database`和`finder`的目录。我们将首先创建我们的数据库引用：

1.  在数据库目录中，创建一个`database.js`文件。请注意，它是`js`，而不是`jsx`，因为我们实际上不会渲染任何数据。相反，我们将返回一个变量给`jsx`组件。您的文件应该如下所示：

```js
import * as firebase from 'firebase'

const app = firebase.initializeApp({
 apiKey: process.env.REACT_APP_apiKey,
 authDomain: process.env.REACT_APP_authDomain,
 databaseURL: process.env.REACT_APP_databaseURL,
 projectId: process.env.REACT_APP_projectId,
 storageBucket: process.env.REACT_APP_storageBucket,
 messagingSenderId: process.env.REACT_APP_messagingSenderId,
 appId: process.env.REACT_APP_appId
})

const Database = app.database()

export default Database
```

请注意每个变量上的`process.env`前缀以及尾随逗号。`process.env`指定应用程序应查看`dotenv`提供的环境变量。

1.  接下来，我们有`Finder.jsx`。在`finder`目录中创建此文件：

```js
import React from 'react'
import Database from '../database/database'

export default class Finder extends React.Component {
 constructor() {
   super()

   Database.ref('/test').set({
     helloworld: 'Hello, World'
   })
 }

 render() {
   return <h1>Let's find some restaurants!</h1>
 }
}
```

我们的`App.js`文件将如下所示：

```js
import React from 'react'
import Finder from './components/finder/Finder'
import './App.css'

function App() {
 return (
   <div className="App">
     <Finder />     
   </div>
 );
}

export default App;
```

1.  现在，由于我们刚刚创建了我们的环境变量，我们需要停止并重新启动我们的 React 应用程序。这对于我们大部分的 React 工作来说并不是必需的，但在这里是必需的。

1.  继续访问`http://localhost:3000`上的应用程序。我们应该只在页面上看到“让我们找一些餐馆”，但是如果我们转到 Firebase，我们会看到这个：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/960f56b9-f09c-454b-9771-c6634fc3f876.png)

图 15.5 - 我们在 Firebase 中有数据！

数据似乎被截断了，但您可以单击它并查看整个语句。

万岁！我们的 Firebase 正在运行。现在是我们应用程序的其余部分。

## 创建我们的应用程序

我们可以从`Finder.jsx`中删除测试插入。这就是我们要做的事情：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/9e9c5a56-053f-4a6d-a7c5-c970353ec85b.png)

图 15.6 - 餐厅查找器

为了实现这一点，我们将使用 Yelp API。首先，您需要转到[`www.yelp.com/developers`](https://www.yelp.com/developers)并注册 Yelp Fusion API 密钥。一旦您拥有它，我们将把它存储在一个新的`.env`文件中的新`api`目录中。

Yelp Fusion API 并不在所有国家/地区都可用，所以如果你无法访问它，请在 GitHub 的`Chapter-15`文件夹中寻找替代 API 使用示例。

Yelp API 是一个 REST API，不允许来自前端 JavaScript 的连接，以保护你的密钥。因此，就像我们的食谱书一样，我们将创建一个小的 API 层来处理我们的请求。不同于我们的食谱书，这将会相当简单，所以我们不会使用 Express。让我们看看步骤：

1.  在项目的根目录，我们将安装一些工具供我们使用：`npm install yelp-fusion dotenv react-bootstrap`。

1.  在项目的根目录创建一个名为`api`的目录，并在其中创建一个`api.js`文件。

1.  我们也将在我们的`api`目录中有一个`.env`文件：

```js
Yelp_Client_ID=<your client id>
YELP_API_Key=<your api key>
```

1.  如果你使用 Git，*不要忘记将这些添加到*`.gitignore`*条目*。

我们的`api.js`文件将会相当简单：

```js
const yelp = require('yelp-fusion');
const http = require('http');
const url = require('url');
require('dotenv').config();

const hostname = 'localhost';
const port = 3001;

const client = yelp.client(process.env.YELP_API_Key);

const server = http.createServer((req, res) => {
 const { lat, lng, value } = url.parse(req.url, true).query

 client.search({
   term: value,
   latitude: lat,
   longitude: lng,
   categories: 'Restaurants'
 }).then(response => {
   res.statusCode = 200;
   res.setHeader('Content-Type', 'application/json');

   res.write(response.body);
   res.end();
 })
   .catch(e => {
     console.error('error',e)
   })
 });

 server.listen(port, hostname, () => {
   console.log(`Server running at http://${hostname}:${port}/`);
 });
```

到目前为止，很多内容应该都很熟悉：我们将包括一些包，比如之前使用过的 Yelp API，我们将定义一些变量来帮助我们。接下来，我们将使用`http`的`createServer`方法创建一个非常简单的服务器来响应我们的 API 请求。在其中，我们将使用`url`的`parse`方法来获取我们的查询字符串参数，然后将其传递给我们的 API。

接下来的部分，`client.search`，可能会让人感到陌生。这是从 Yelp 文档中提取的，专门设计以符合他们 API 的要求。一旦我们有了异步响应，我们就将其发送回我们的请求应用程序。不要忘记处理错误！然后我们在端口`3001`上启动服务器。你可以使用`node api.js`启动这个服务器，然后你会看到关于它运行的控制台错误消息。

现在让我们把注意力转向我们应用程序的 React 部分：

1.  在我们的`src`目录中，当我们完成时，将会有这样的文件结构：

```js
.
├── App.css
├── App.js
├── App.test.js
├── components
│   ├── database
│   │ └── database.js
│   ├── finder
│   │ └── Finder.jsx
│   ├── restaurant
│   │ ├── Restaurant.css
│   │ └── Restaurant.jsx
│   └── search
│       └── Search.jsx
├── index.css
├── index.js
├── logo.svg
├── serviceWorker.js
└── setupTests.js
```

许多这些文件在我们之前搭建应用程序时已经创建好了，但`components`目录的一些部分是新的。

1.  创建这些文件，我们将从探索`Restaurant.jsx`开始：

```js
import React from 'react'
import { Button, Card } from 'react-bootstrap'
import Database from '../database/database'

import './Restaurant.css'

export default class Restaurant extends React.Component {
 constructor() {
   super();

   this.saveRestaurant = this.saveRestaurant.bind(this)
 }

 saveRestaurant(e) {
   const { restaurant } = this.props

   Database.ref(`/restaurants/${restaurant.id}`).set({
     ...restaurant
   })
 }

 render() {
   const { restaurant } = this.props

   return (
     <Card>
       <Card.Img variant="top" src={restaurant.image_url} 
        alt={restaurant.name} />
       <Card.Body>
         <Card.Title>{restaurant.name}</Card.Title>
         {!this.props.saved && <Button variant="primary" 
         onClick={this.saveRestaurant}>Save Restaurant</Button>}
      </Card.Body>
     </Card>
   )
 }
}
```

大部分内容都不是新的，我们的食谱书的结构可以帮助我们理清思路。不过，我们应该拆分`saveRestaurant`方法，因为它使用了一些有趣的部分：

```js
saveRestaurant(e) {
   const { restaurant } = this.props

   Database.ref(`/restaurants/${restaurant.id}`).set({
     ...restaurant
   })
 }
```

首先，我们可以推断出我们将从组件的`props`中获取餐厅的数据。这将直接来自我们的搜索结果。因此，我们需要稍微处理一下我们的数据。

这是我们从`props`中得到的搜索结果的样子：

```js
{id: "CO3lm5309asRY7XG5eXNgg", alias: "rahi-new-york", name: "Rahi", image_url: "https://s3-media1.fl.yelpcdn.com/bphoto/rPh_LboeIOiTVeXCuas5jA/o.jpg", is_closed: false, ...}
id: "CO3lm5309asRY7XG5eXNgg"
alias: "rahi-new-york"
name: "Rahi"
image_url: "https://s3-media1.fl.yelpcdn.com/bphoto/rPh_LboeIOiTVeXCuas5jA/o.jpg"
is_closed: false
url: "https://www.yelp.com/biz/rahi-new-york?adjust_creative=-YEyXjz9iO0W5ymAnPt6kA&utm_campaign=yelp_api_v3&utm_medium=api_v3_business_search&utm_source=-YEyXjz9iO0W5ymAnPt6kA"
review_count: 448
categories: (3) [{...}, {...}, {...}]
rating: 4.5
coordinates: {latitude: 40.7360271, longitude: -74.0005436}
transactions: (2) ["delivery", "pickup"]
price: "$$$"
location: {address1: "60 Greenwich Ave", address2: "", address3: null, city: "New York", zip_code: "10011", ...}
phone: "+12123738900"
display_phone: "(212) 373-8900"
distance: 1305.5181202902097
```

1.  我们将其保存到 Firebase 中：

```js
Database.ref(`/restaurants/${restaurant.id}`).set({
  ...restaurant
})
```

我们使用*展开运算符*（三个点）来将对象扩展为其组成的键/值对，以避免在我们的数据库中出现嵌套对象。我们还有一点点 CSS 来格式化我们的卡片。

让我们把注意力转向`Search`组件：

```js
import React from 'react'
import { Button } from 'react-bootstrap'
import Restaurant from '../restaurant/Restaurant'

export default class Search extends React.Component {
 constructor() {
   super()

   this.state = {
     businesses: []
   }
```

在我们的构造函数中，我们做了一些有趣的事情：*浏览器地理定位*。

你是否见过某些网站询问你的位置时弹出的小警告窗口？这就是这些网站的做法。如果浏览器支持地理定位，我们将使用它并从浏览器中设置我们的纬度和经度。否则，我们将简单地将其设置为`null`：

```js
   if (navigator.geolocation) {
     navigator.geolocation.getCurrentPosition((position) => {
       this.setState({
         lng: position.coords.longitude,
         lat: position.coords.latitude
       })
     })

   } else {
     this.setState({
       lng: null,
       lat: null
     })
   }

   this.search = this.search.bind(this)
   this.handleChange = this.handleChange.bind(this)
 }

 handleChange(e) {
   this.setState({
     val: e.target.value
   })
 }

```

搜索端点的构建应该看起来很熟悉：

```js
 search(event) {
   const { lng, lat, val } = this.state

   fetch(`http://localhost:3000/businesses/search?
   value=${val}&lat=${lat}&lng=${lng}`)
     .then(data => data.json())
     .then(data => this.handleSearchResults(data))
 }

 handleSearchResults(data) {
   this.setState({
     businesses: data.businesses
   })
 }

 render() {
   const { businesses } = this.state

   return (
     <>
       <h2>Enter a type of cuisine: <input type="text" onChange=
       {this.handleChange} /> <Button id="search" onClick={this.search}>
       Search!</Button></h2>
       <div className="card-columns">
         {
           businesses.length > 0 ? (
             businesses.map((restaurant, i) => (
               <Restaurant restaurant={restaurant} key={i} />
             ))
           ) : <p>No results</p>
         }
       </div>
     </>
   )
 }
}
```

当你在我们的代码中前进时，如果你得到纬度或经度的空值，你可能需要完全退出 React 应用程序并重新启动它。

类似于我们的食谱书通过代理调用我们的 Express 应用程序，不要忘记将这行添加到你的`package.json`文件中：`"proxy": "http://localhost:3001"`。这样我们就可以使用`fetch`。这些是我们传递给`api.js`的值，用于向 Yelp API 发送请求。

我们的应用程序快要完成了！接下来是我们开始的`Finder`组件：

1.  首先，我们有我们的导入：

```js
import React from 'react'
import Database from '../database/database'
import { Tabs, Tab } from 'react-bootstrap'
import Search from '../search/Search'
import Restaurant from '../restaurant/Restaurant'

```

1.  接下来，我们有一些非常标准的部分：

```js
export default class Finder extends React.Component {
 constructor() {
   super()

   this.state = {
     restaurants: []
   }

   this.getRestaurants = this.getRestaurants.bind(this)
 }

 componentDidMount() {
   this.getRestaurants()
 }
```

1.  作为一个新的部分，让我们来看看我们如何从 Firebase 中检索信息：

```js
 getRestaurants() {

   Database.ref('/restaurants').on('value', (snapshot) => {
     const restaurants = []

     const data = snapshot.val()

     for(let restaurant in data) {
       restaurants.push(data[restaurant])
     }
     this.setState({
       restaurants: restaurants
     })
   })
 }
```

关于 Firebase 的一个有趣之处是它是一个实时数据库；你不总是需要执行查询来检索最新的数据。在这个构造中，我们告诉数据库不断更新我们组件的状态，以反映`/restaurants`的值的变化。当我们保存一个新的餐馆并转到我们的“已保存！”选项卡时，我们将看到我们的新条目。

1.  我们在这里使用了其他组件，将其完整地呈现出来：

```js
 render() {

   const { restaurants } = this.state
   return (
     <>
       <h1>Let's find some restaurants!</h1>

       <Tabs defaultActiveKey="search" id="restaurantsearch">
         <Tab eventKey="search" title="Search!">
           <Search handleSearchResults={this.handleSearchResults} 
        />
         </Tab>
         <Tab eventKey="saved" title="Saved!">
           <div className="card-columns">
             {
               restaurants.length > 0 ? (
                 restaurants.map((restaurant, i) => (
                   <Restaurant restaurant={restaurant} saved={true} 
                    key={i} />
                 ))
               ) : <p>No saved restaurants</p>
             }
           </div>
         </Tab>
       </Tabs>
     </>
   )
 }
}
```

当一切都完成时，我们将保持我们的`api.js`文件运行，并使用`npm start`启动我们的 React 应用程序，我们的应用程序就完成了！

是时候结束本章了。

# 总结

在本章中，我们涵盖了很多内容。JavaScript 在前端和后端的强大功能向我们展示，我们确实可以用它来满足许多应用程序需求，不仅仅是 Python。我们使用了很多 React，但请记住，任何前端都可以在这里替代：Vue、Angular，甚至是无框架的 HTML、CSS 和 JavaScript 都可以用来创建强大的 Web 应用程序。

在使用 JavaScript 和 API 时需要注意的一点是，有些情况下我们需要一个中间件层，例如在保存文件或使用密钥访问 REST API 时。将 Express 与基本的 Node.js 脚本结合起来与 API 进行交互，这只是 JavaScript 和 Node.js 结合所能实现的开始。

在下一章中，我们将探讨 webpack，这是一个工具，允许我们将 JavaScript 应用逻辑地组合和打包以进行部署。


# 第十六章：进入 Webpack

所以，现在你有了漂亮的前端和后端代码。太棒了！它看起来在你的笔记本上如此漂亮……那么下一步是什么？将它发布到世界上！听起来很容易，但当我们有像 React 这样的高级 JavaScript 使用时，我们可能还想采取一些额外步骤，以确保我们的代码以最高效率运行，所有依赖项都得到解决，并且一切都与现代技术兼容。此外，下载大小是一个重要考虑因素，所以让我们探讨一下 webpack，这是一个帮助解决这些问题的工具。

在本章中，我们将涵盖以下几点：

+   捆绑和模块的需求

+   使用 webpack

+   部署

# 技术要求

准备好使用存储库的`Chapter-16`目录中提供的代码：[`github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-16`](https://github.com/PacktPublishing/Hands-on-JavaScript-for-Python-Developers/tree/master/chapter-16)。因为我们将使用命令行工具，还要准备好你的终端或命令行 shell。我们需要一个现代浏览器和一个本地代码编辑器。

# 捆绑和模块的需求

理想情况下，一切都会在网站上无缝运行，无需采取任何额外步骤。你拿起你的源文件，放在一个 web 服务器上，然后：一个网站。然而，情况并非总是如此。例如，对于 React，我们需要运行`npm run build`来为我们的项目生成一个输出分发目录。我们可能还有其他类型的非源文件，比如 SASS 或 TypeScript，需要转换成浏览器可以理解的原生文件格式。

那么，*模块*是什么？有**模块化编程**的概念，它将大型程序按照关注点和封装（作用域）分离成更小、更独立的模块。模块化编程背后的思想有很多：作用域、抽象、逻辑设计、测试和调试。同样，一个捆绑是浏览器可以轻松使用的一块代码，通常由一个或多个模块构成。

现在是有趣的部分：*我们已经使用过模块*！让我们来看看我们在第十一章中编写的一些 Node.js 代码，*什么是 Node.js？：*

```js
const readline = require('readline')
const randomNumber = Math.ceil(Math.random() * 10)

const rl = readline.createInterface({
 input: process.stdin,
 output: process.stdout
});

askQuestion()

function askQuestion() {
 rl.question('Enter a number from 1 to 10:\n', (answer) => {
   evaluateAnswer(answer)
 })
}

function evaluateAnswer(guess) {
 if (parseInt(guess) === randomNumber) {
   console.log("Correct!\n")
   rl.close()
   process.exit(1)
 } else {
   console.log("Incorrect!")
   askQuestion()
 }
}
```

在第一行，我们使用了一个叫做`readline`的模块，如果你还记得我们的程序，它将被用来从命令行接收用户输入。我们在 React 中也使用了它们——每当我们需要使用`npm install`时，我们都在使用模块的概念。那么这为什么重要呢？让我们考虑从头开始标准的`create-react-app`安装：

1.  使用`npx`创建一个新的 React 项目：`npx create-react-app sample-project`。

1.  进入目录并安装依赖项：`cd sample-project ; npm install`。

1.  使用`npm start`启动项目。

如果你还记得，这给我们一个非常有趣的起始页面：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/321bf6f9-5ab4-4f32-80a8-923a814c5cbd.png)

图 16.1 – React 起始页面

当我们运行`npm install`时，我们到底得到了什么？让我们看看我们的文件结构：

```js
.
├── README.md
├── package-lock.json
├── package.json
├── public
│   ├── favicon.ico
│   ├── index.html
│   ├── logo192.png
│   ├── logo512.png
│   ├── manifest.json
│   └── robots.txt
├── src
│   ├── App.css
│   ├── App.js
│   ├── App.test.js
│   ├── index.css
│   ├── index.js
│   ├── logo.svg
│   ├── serviceWorker.js
│   └── setupTests.js
└── yarn.lock
```

到目前为止还算简单。然而，在这个清单中，我故意排除了`node_modules`目录。这个目录有 18 个文件。尝试在我们项目的根目录运行这个命令，不排除那个目录：`tree`。享受观看繁忙的行数——32,418 个文件！这些都是从哪里来的？是我们的朋友`npm install`！

## package.json

我们的项目结构在一定程度上由我们的`package.json`文件控制以管理依赖项。大多数捆绑工具，比如 webpack，将利用这个文件中的信息来创建我们的依赖图和一小块一小块的模块。让我们来看看它：

*package.json*

```js
{
 "name": "sample-project",
 "version": "0.1.0",
 "private": true,
 "dependencies": {
   "@testing-library/jest-dom": "⁴.2.4",
   "@testing-library/react": "⁹.3.2",
   "@testing-library/user-event": "⁷.1.2",
   "react": "¹⁶.13.1",
   "react-dom": "¹⁶.13.1",
   "react-scripts": "3.4.1"
 },
 "scripts": {
   "start": "react-scripts start",
   "build": "react-scripts build",
   "test": "react-scripts test",
   "eject": "react-scripts eject"
 },
 "eslintConfig": {
   "extends": "react-app"
 },
 "browserslist": {
   "production": [
     ">0.2%",
     "not dead",
     "not op_mini all"
   ],
   "development": [
     "last 1 chrome version",
     "last 1 firefox version",
     "last 1 safari version"
   ]
 }
}
```

这是一个标准的基本包文件；它只包含六个依赖项：一半用于测试，一半用于 React。现在，有趣的部分是：每个依赖项又有自己的依赖项，这就是为什么我们在`node_modules`目录中单独有 32,400 个文件。通过使用模块，我们不必手动构建或管理依赖项；我们可以遵循 DRY 原则，并利用其他人（或我们自己）以模块形式编写的现有代码。正如我们在比较 Python 和 Node.js 时讨论的那样，`npm install`类似于 Python 中的`pip install`，我们在 Python 程序中使用`import`关键字来使用包，而在 Node.js 中我们使用`require`。

当我们使用`npm install`将一个新的包安装到我们的项目中时，它会在`package.json`中添加一个条目。这是一个文件，如果你进行任何编辑，你需要非常小心。一般来说，你不应该需要做太多更改，尤其是应该避免对依赖项进行实质性的更改。利用`install`命令来完成这些。

## 构建流水线

让我们看看当我们准备将 React 项目部署时会发生什么。运行`npm run build`并观察输出。你应该会看到类似以下的输出：

```js
Creating an optimized production build...
Compiled successfully.

File sizes after gzip:

  39.39 KB  build/static/js/2.deae54a5.chunk.js
  776 B     build/static/js/runtime-main.70500df8.js
  650 B     build/static/js/main.0fefaef6.chunk.js
  547 B     build/static/css/main.5f361e03.chunk.css

The project was built assuming it is hosted at /.
You can control this with the homepage field in your package.json.

The build folder is ready to be deployed.
You may serve it with a static server:

  yarn global add serve
  serve -s build

Find out more about deployment here:

  bit.ly/CRA-deploy
```

如果你查看构建目录，你会看到精简的 JavaScript 文件，打包好以便高效部署。有趣的部分在于：`create-react-app` *使用 webpack 进行构建*！`create-react-app`设置处理了这些部分。修改`create-react-app`的内部 webpack 设置有点棘手，所以现在让我们来看看如何在 React 的用例之外直接使用 webpack。

# 使用 webpack

现在，webpack 是许多模块化工具之一，可以在你的程序中使用。此外，与 React 脚本不同，它在 React 之外也有用途：它可以用作许多不同类型应用的打包工具。让我们动手创建一个小的、无用的示例项目：

1.  创建一个新的目录并进入其中：`mkdir webpack-example ; cd webpack-example`。

1.  我们将使用 NPM，所以我们需要初始化它。我们也会接受默认值：`npm init -y`。

1.  然后我们需要安装 webpack：`npm install webpack webpack-cli --save-dev`。

请注意，我们在这里使用`--save-dev`，因为我们不需要将 webpack 构建到我们的生产级文件中。通过使用开发依赖，我们可以帮助减少我们的捆绑大小，这是一个可能会拖慢应用程序的因素。

如果你在这里的`node_modules`目录中查看，你会看到我们已经从依赖中安装了超过 3.5 千个文件。我们的项目目前相当无聊：没有任何内容！让我们修复这个问题，创建一些文件，如下所示：

*src/index.html*

```js
<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <title>Webpack Example</title>
</head>
<body>
 <h1>Welcome to Webpack!</h1>
 <script src="index.js"></script>
</body>
</html>
```

*src/index.js*

```js
console.log('hello')
```

到目前为止，非常令人兴奋和有用，对吧？如果你在浏览器中打开我们的首页，你会看到控制台中的预期内容。现在，让我们将 webpack 引入其中：

1.  将`package.json`的`scripts`节点更改为以下内容：

```js
"scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "webpack --mode development",
    "build": "webpack --mode production"
  },
```

1.  运行`npm run dev`。你应该会看到类似这样的输出：

```js
> webpack --mode development

Hash: 21e0ae2cc4ae17d2754f
Version: webpack 4.43.0
Time: 53ms
Built at: 06/14/2020 1:37:27 PM
  Asset      Size  Chunks             Chunk Names
main.js  3.79 KiB    main  [emitted]  main
Entrypoint main = main.js
[./src/index.js] 20 bytes {main} [built]
```

现在去查看你新创建的`dist`目录：

```js
dist
└── main.js
```

如果你打开`main.js`，你会发现它看起来与我们的`index.js`*非常*不同！这是 webpack 在幕后做一些模块化的工作。

等等。我们从一行代码变成了 100 行。为什么这样做更好呢？对于这样简单的例子来说可能并不是，但请再给我一点时间。让我们尝试`npm run build`并比较输出：`main.js`现在是一行，被精简了。

查看我们的`package.json`文件，除了我们操作的脚本节点之外，还有一些值得注意的部分：

```js
{
 "name": "webpack-example",
 "version": "1.0.0",
 "description": "",
 "main": "index.js",
 "scripts": {
   "test": "echo \"Error: no test specified\" && exit 1",
   "dev": "webpack --mode development",
   "build": "webpack --mode production"
 },
 "keywords": [],
 "author": "",
 "license": "ISC",
 "devDependencies": {
   "webpack": "⁴.43.0",
   "webpack-cli": "³.3.11"
 }
}
```

我们看到一个`"main"`节点指定了一个`index.js`作为我们的主入口点，或者说 webpack 开始查找其依赖的地方。

在使用 webpack 时，有三个重要的概念需要理解：

+   **入口**：webpack 开始工作的地方。

+   **输出**：webpack 将输出其完成的产品的地方。如果我们查看前面测试的输出，我们会看到`main.js 3.79 KiB main [emitted] main`。webpack 更加优雅地将其定义为“emitting”其捆绑包，而不是“spits out”这个短语。

+   **加载器**：如前所述，webpack 可以用于各种不同的目的；然而，默认情况下，webpack 只处理 JavaScript 和 JSON 文件。因此，我们使用*加载器*来做更多的工作。我们将在一分钟内使用一个加载器来操作`index.html`文件。

模式和插件的概念也很重要，尽管有点更容易理解：模式，正如我们在`package.json`中添加脚本时所看到的，定义了我们是否希望对我们的环境进行开发、生产或“无”优化。模式比这更复杂，但现在我们不会变得疯狂——webpack 相当复杂，因此对其有一个表面理解是一个很好的开始。插件基本上做着加载器无法做的事情。尽管我们会保持简单，现在我们将添加一个能够理解 HTML 文件的加载器。准备好……输出并不是你所想象的那样：

1.  运行`npm install html-loader --save-dev`。

1.  现在我们已经到了需要一个配置文件的地步，所以创建`webpack.config.js`。

1.  在`webpack.config.js`中输入以下内容：

```js
module.exports = {
  module: {
    rules: [
      {
        test: /\.html$/i,
        loader: 'html-loader',
      },
    ],
  },
};
```

1.  修改`index.js`如下：

```js
import html from './index.html'

console.log(html)
```

1.  通过修改`index.html`，将脚本标签更改为以下内容：

1.  重新运行`npm run dev`，然后在浏览器中打开该页面。

如果我们查看控制台，我们会看到我们的 HTML！哇！几乎所有的东西都在那里，除了我们的`<script>`标签在`src`中显示为`"[Object object]"`。现在你应该问自己：“我们刚刚完成了什么？”。

事实证明，加载器*不是*我们想要的！当你想要插件时，却使用加载器，反之亦然，这是一个常见的错误。现在让我们撤销我们所做的，并安装一个*会*做我们期望的 HTML 插件：将`index.html`插入`dist`目录，并优化`main.js`文件：

1.  实际上，我们并不想要或需要 HTML 加载器来完成这个任务：`npm uninstall html-loader`。

1.  安装正确的插件：`npm install html-webpack-plugin --save-dev`。

1.  完全用这个配置替换`webpack.config.js`的内容：

```js
var HtmlWebpackPlugin = require('html-webpack-plugin');
var path = require('path');

module.exports = {
 entry: './src/index.js',
 output: {
   path: path.resolve(__dirname, './dist'),
   filename: 'index_bundle.js'
 },
 plugins: [new HtmlWebpackPlugin({
   template: './src/index.html'
 })]
};
```

1.  将`index.js`修改回原始的一行：`console.log('hello')`。

1.  从`src/index.html`中删除`<script>`标签。它将为我们构建。

1.  执行`npm run dev`。

1.  最后，在浏览器中打开`dist/index.html`。

这应该更符合你的喜好，也是你使用 webpack 所期望的。然而，这只是一个非常基本的例子，所以让我们看看是否可以做一些更花哨的事情。编辑文件如下：

*src/index.html*

```js
<!DOCTYPE html>
<html lang="en">
<head>
 <meta charset="UTF-8">
 <meta name="viewport" content="width=device-width, initial-scale=1.0">
 <title>Webpack Example</title>
</head>
<body>
 <h1>Welcome to Webpack!</h1>
<div id="container"></div>
</body>
</html>
```

*src/index.js*

```js
import Highcharts from 'highcharts'

// Create the chart
Highcharts.chart('container', {
 chart: {
   type: 'bar'
 },
 title: {
   text: 'Fruit Consumption'
 },
 xAxis: {
   categories: ['Apples', 'Bananas', 'Oranges']
 },
 yAxis: {
   title: {
     text: 'Fruit eaten'
   }
 },
 series: [{
   name: 'Jane',
   data: [1, 0, 4]
 }, {
   name: 'John',
   data: [5, 7, 3]
 }]
});
```

在这个例子中，我们使用了 Highcharts，一个图表库。这是他们的样板例子，直接从他们的网站上取出；我没有对它做任何花哨的事情，除了修改第一行为`import Highcharts from 'highcharts'`。这意味着我们将使用一个模块，所以让我们安装它——`npm install highcharts`：

1.  将此脚本添加到你的`package.json`的`scripts`节点中：`"watch": "webpack --watch -- mode development"`。

1.  运行`npm run watch`。

1.  在浏览器中加载`dist/index.html`：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-js-py-dev/img/545d6bee-e61b-4a14-9ece-2c6a2a77a748.png)

图 16.2 - 使用 Highcharts 的 Webpack

更有趣，不是吗？还有，花点时间看看`index_bundle.js`文件，并注意更大的文件和缩小的代码。如果你用`watch`编辑`src`中的文件，webpack 会即时为你重新打包文件。如果你使用支持热重载的实时服务器，比如 Visual Studio Code，它也会为你刷新页面——对于快速开发很方便！

现在是时候尝试我们一直在构建的东西了。让我们尝试为部署构建我们的项目。

# 部署我们的项目

到目前为止，我们已经做了很多开发工作，现在是时候尝试对我们的项目进行生产构建了。运行`npm run build`，嗯，它并不是那么开心，是吧？你应该会收到一些像这样的警告：

```js
WARNING in asset size limit: The following asset(s) exceed the recommended size limit (244 KiB).
This can impact web performance.
Assets: 
  index_bundle.js (263 KiB)

WARNING in entrypoint size limit: The following entrypoint(s) combined asset size exceeds the recommended limit (244 KiB). This can impact web performance.
Entrypoints:
  main (263 KiB)
      index_bundle.js

WARNING in webpack performance recommendations: 
You can limit the size of your bundles by using import() or require.ensure to lazy load some parts of your application.
For more info visit https://webpack.js.org/guides/code-splitting/
Child HtmlWebpackCompiler:
     1 asset
    Entrypoint HtmlWebpackPlugin_0 = __child-HtmlWebpackPlugin_0
    [0] ./node_modules/html-webpack-plugin/lib/loader.js!./src/index.html 522 bytes {0} [built]
```

那么，这是在告诉我们什么？还记得我说过捆绑大小会影响性能吗？让我们尝试优化一下，这样我们就不会再收到这些消息了。我们将研究一些开发技术来做到这一点。

## 块

简而言之，块是将大文件拆分成较小块的方法。我们可以通过在我们的`webpack.config.js`文件的插件节点之后添加这个部分来轻松完成这一部分：

```js
optimization: {
   splitChunks: {
     chunks: 'all',
   }
 }
```

现在，继续构建；它会*稍微*开心一点：

```js
Built at: 06/14/2020 3:46:38 PM
                 Asset       Size  Chunks                    Chunk Names
            index.html  321 bytes          [emitted]         
        main.bundle.js   1.74 KiB       0  [emitted]         main
vendors~main.bundle.js    262 KiB       1  [emitted]  [big]  vendors~main
Entrypoint main [big] = vendors~main.bundle.js main.bundle.js
```

不幸的是，它仍然会抱怨。我们将 1.74 KB 削减到一个单独的文件中，但我们仍然有一个 262 KB 的`vendors`捆绑包。如果你在`dist`中查看，现在你会看到两个`js`文件以及 HTML 中的两个`<script>`标签。

它之所以不进一步拆分是因为供应商（Highcharts）捆绑包已经相当自包含，所以我们需要探索其他方法来实现我们的需求。然而，如果我们有很多自己的代码，可能会进一步将其拆分为多个块。

那么，我们的下一个选择是什么？我们调整优化！

试试这个：

```js
optimization: {
   splitChunks: {
     chunks: 'async',
     minSize: 30000,
     maxSize: 244000,
     minChunks: 2,
     maxAsyncRequests: 6,
     maxInitialRequests: 4,
     automaticNameDelimiter: '~',
     cacheGroups: {
       defaultVendors: {
         test: /[\\/]node_modules[\\/]/,
         priority: -10
       },
       default: {
         minChunks: 2,
         priority: -20,
         reuseExistingChunk: true
       }
     }
   }
 }
```

如果你注意到，这里的选项更加明确，包括块的最大大小，重用现有的供应商块，以及最小数量的块。让我们试试看。

没有变化，对吧？

让我们尝试一些不同的东西：修改`index.js`以使用 promises 和**webpack 提示**来将 Highcharts 依赖项拆分为自己的捆绑包：

```js
import( /* webpackChunkName: "highcharts" */ 'highcharts').then(({ default: Highcharts }) => {
 // Create the chart
 Highcharts.chart('container', {
   chart: {
     type: 'bar'
   },
   title: {
     text: 'Fruit Consumption'
   },
   xAxis: {
     categories: ['Apples', 'Bananas', 'Oranges']
   },
   yAxis: {
     title: {
       text: 'Fruit eaten'
     }
   },
   series: [{
     name: 'Jane',
     data: [1, 0, 4]
   }, {
     name: 'John',
     data: [5, 7, 3]
   }
   ]
 });
})
```

我们从`npm run build`的输出现在应该更像这样：

```js
Version: webpack 4.43.0
Time: 610ms
Built at: 06/14/2020 4:38:41 PM
                        Asset       Size  Chunks                    Chunk Names
highcharts~c19dcf7a.bundle.js    262 KiB       0  [emitted]  [big]  highcharts~c19dcf7a
                   index.html  284 bytes          [emitted]         
      main~d1c01171.bundle.js   2.33 KiB       1  [emitted]         main~d1c01171
Entrypoint main = main~d1c01171.bundle.js
```

嗯...这*仍然*没有达到我们想要的效果！虽然我们为 Highcharts 有一个单独的块，但它仍然是一个庞大的、单一的文件。那么，我们该怎么办？

## 投降

举起白旗。承认失败。

几乎。

在这里，每个供应商包可能不同，每个导入都将是独特的；我们想做的是尝试找到适合我们需求的*最小块*的供应商库。在这种情况下，导入所有 Highcharts 正在创建一个庞大的文件。然而，让我们看看`node_modules/highcharts`。在`es-modules`目录中，有一个有趣的文件：`highcharts.src.js`。这是我们想要的更模块化的文件，所以让我们尝试导入它而不是一次导入整个库：

```js
import( /* webpackChunkName: "highcharts" */ 'highcharts/es-modules/highcharts.src.js').then(({ default: Highcharts }) => {

...
```

现在看看如果我们使用`npm run build`会发生什么：

```js
Version: webpack 4.43.0
Time: 411ms
Built at: 06/14/2020 4:48:43 PM
                        Asset       Size  Chunks             Chunk Names
highcharts~47c7b5d6.bundle.js    170 KiB       0  [emitted]  highcharts~47c7b5d6
                   index.html  284 bytes          [emitted]  
      main~d1c01171.bundle.js   2.33 KiB       1  [emitted]  main~d1c01171
Entrypoint main = main~d1c01171.bundle.js
```

啊哈！好多了！所以，在这种情况下，答案是晦涩的。Highcharts 捆绑可以被解开，以便只添加代码的特定部分。这在所有情况下*都不会*起作用，特别是在源代码未包含的情况下；然而，这是我们目前的一种方法：将包含的包裁减到最小需要的集合。还记得我们在 React 中有选择地包含库的部分吗？这里的想法也是一样的。

## 部署，完成

现在我们该怎么办？你真正需要做的就是将你的`dist`目录的内容放在一个 Web 服务器上供全世界查看！让你的辛勤工作展现出来。

# 总结

Webpack 是我们的朋友。它模块化，最小化，分块，并使我们的代码更有效，同时在某些部分没有得到适当优化时警告我们。有方法可以消除这些警报，但总的来说，倾听它们并至少*尝试*解决它们是一个好主意。

然而，一个仍然没有答案的燃烧问题是：增加下载文件的数量会增加加载时间吗？这是一个常见的误解，它始于互联网早期：更多的文件==更长的加载时间。然而，事实是，多个浏览器可以同时打开许多非阻塞流，从而比一个巨大的文件实现更高效的下载。这是所有多个文件的解决方案吗？不是：例如，CSS 图像精灵仍然是更有效地使用图像资源。为了性能，我们必须在提供最佳用户体验的同时，与最佳开发者体验相结合。整本书都是关于这个主题的，所以我不会试图给你所有的答案。我只会留下这个：

优化，优化，优化。

在下一章中，我们将处理编程的所有部分都非常重要的一个主题：安全性。
