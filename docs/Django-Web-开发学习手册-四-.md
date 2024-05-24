# Django Web 开发学习手册（四）

> 原文：[`zh.annas-archive.org/md5/C7E16835D8AC71A567CF7E772213E9F7`](https://zh.annas-archive.org/md5/C7E16835D8AC71A567CF7E772213E9F7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用第三方软件包

现在是时候将我们迄今学到的所有理论和原则结合起来，尝试理解我们如何利用第三方软件包来实现许多可能的项目，比如 Twitter API 的使用，Social Auth 等等。

在本章中，您将学习以下主题：

+   深入开源世界

+   在 Django 项目中使用 Social Auth

+   在 Django 中构建 REST API

除了使用 Django 和 Python 构建网站所需的核心模块之外，我们还需要一些第三方软件包。互联网上有许多免费的第三方软件包；您可以在[`www.djangopackages.com/`](https://www.djangopackages.com/)找到许多有用的软件包。我们将尝试为我们的项目使用开源第三方软件包。

# 深入开源世界

当我们看到开源这个词时，首先浮现在我们脑海中的问题是开源实际上是什么意思？

嗯，开源是一个指的是设计公开可访问并且可以根据任何人的需要进行修改，而无需事先获得任何许可的术语。

好的，那么，让我们继续，深入探讨开源世界的各个方面。

## 什么是开源软件？

开源软件意味着软件的源代码是公开可访问的，因此可以以任何可能的方式进行修改。此外，任何人都可以为源代码做出贡献，这通常会导致软件的增强。

现在，大多数软件用户从未看到源代码，程序员可以修改源代码以满足他们的需求；这基本上意味着程序员手中有源代码可以完全控制软件。

然后程序员可以通过修复任何错误或添加任何新功能来继续使用软件。

## 开源和其他软件有什么区别？

如果源代码没有公开访问，或者代码只对创建它的特定人群可访问，这种类型的软件称为**专有软件**或**闭源软件**。闭源软件的例子包括微软产品，如 Microsoft Windows，Word，Excel，PowerPoint，Adobe Photoshop 等。

要使用专有软件，用户必须同意（通常是通过签署许可证，该许可证在第一次运行该软件时显示）他们不会对软件进行任何软件作者未明确允许的操作。

而开源软件是不同的。开源软件的作者将其代码提供给其他人，希望他们可以查看代码，复制代码，从中学习，修改代码或分享代码。Python 和 Django 程序是开源软件的例子。

就像专有软件有许可证一样，开源软件也有许可证，但是有很大的不同。这些许可证促进了开源开发；它们允许修改和修复源代码。

开源难道不只是指某物是免费的吗？

“开源不仅意味着获得访问源代码。”正如**开源倡议**所解释的那样，这意味着任何人都应该能够修改源代码以满足程序员的需求。

对于开源生态系统可能会有一些误解。程序员可以对他们创建的开源软件收费，但这没有任何意义，因为购买者有权修改并免费分发它。程序员不是为开源软件收费，而是为他们围绕它构建的服务收费，比如支持或其他增值的次要组件。像 Red Hat 这样的公司通过为其开源 Red Hat 操作系统提供支持而收费。Elasticsearch 收费的是一个名为 marvel 的组件，用于监视 Elasticsearch，在 Elasticsearch 运行时非常有帮助。

很多人认为只有互联网上有名的摇滚明星程序员才能为开源项目做出贡献，但事实上，开源社区靠初学者到专家，甚至非程序员的贡献而蓬勃发展。

# 在 Django 项目中使用 SocialAuth

每个网站都需要存储用户数据，以给他们更好和独特的体验，但为了做到这一点，网站需要你通过填写用户详细信息表格进行注册，他们要求你输入基本信息。填写这些信息可能会很无聊和繁琐。这个问题的一个实际解决方案是**Social Auth**，通过单击即可从你已经注册的社交网站自动填写你的基本信息注册到网站上。

例如，你可能在浏览网页时看到许多网站提供了一些社交按钮的选项，比如 Google、Facebook、Twitter 等，用于在他们的网站上登录或注册。如果你使用这些社交按钮登录或注册，它们将从社交网站上拉取你的基本信息，比如电子邮件、性别等，这样你就不需要手动填写表格。

单独构建这个完整的端到端实现可能是 Django 中的一个项目，如果你希望你的网站具有相同的功能，你不需要重复造轮子。我们只需导入一个第三方库，在`settings.py`文件中进行最小的配置更改，就可以让用户通过他们现有的社交账户登录或注册。

## OAuth 的工作原理

要理解**OAuth**的工作原理，让我们考虑以下例子。

OAuth 就像是 Web 的代客泊车钥匙。大多数豪华车都配备了代客泊车钥匙，车主将其交给停车员。有了这把钥匙，车辆就不允许行驶更远的距离，其他功能，比如行李箱和豪华功能都被禁用了。

同样，你在网站上看到的登录按钮并不会给予网站对你社交账户的完全访问权限；它只会传递你授予的详细信息，或者默认信息，比如电子邮件、性别等。

为了访问这些信息，网站过去通常要求用户输入用户名和密码，这增加了个人信息泄露或账户被盗的风险。人们可能会在他们的银行账户上使用相同的用户名和密码，这使得情况更加危险。

因此，OAuth 的目的是为用户提供一种方法，让第三方访问他们的信息，而不用分享密码。通过遵循这种方法，也可以授予有限的访问权限（比如，电子邮件、创建帖子的权限等）。

例如，对于一个登录注册网站，如果他们要求访问你的个人照片，那将会非常奇怪。因此，在使用 OAuth 给予应用程序权限的时候，权限实际上是可以被审查的。

以下图表给出了 OAuth 机制的概述：

![OAuth 的工作原理](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00314.jpeg)

在上图中，你可以看到需要你的凭据的客户端应用程序要求你使用任何社交账户登录或注册。这在图的第一部分中显示，客户端要求用户进行社交账户授权。

一旦你决定通过社交账户登录，并授予客户端应用程序访问你的社交账户的权限，已经在同一社交网站上注册并拥有自己 API 密钥的客户端应用程序，会向社交网站请求你的用户详细信息。在这个阶段，你可能已经看到了客户端应用程序将访问的记录列表。一些网站也许会让你编辑这些访问权限。在服务器授权客户端应用程序之后，客户端会获得你的社交账户访问的访问令牌。

客户端应用程序可能会存储此访问令牌以供将来使用，或者，如它通常被称为的**离线访问**。

使用此社交 OAuth 方法注册和登录的区别在于，当您已经注册时，客户端应用程序可能会存储您的访问令牌，这样下次尝试登录时，您就不必再次通过相同的社交网站授权页面，因为您已经向他们提供了授权凭据。

## 实施社交 OAuth

在本节中，我们将学习如何在现有项目中实现社交 OAuth。为了为我们的应用程序实现社交认证，我们将使用一个名为`python-social-auth`的第三方库。我们将使用 Twitter 社交 Auth 来验证我们的用户。让我们来看一下以下步骤：

1.  首先，我们将安装名为**Python-Social-Auth**的第三方应用程序。可以使用以下命令简单地安装`python-social-auth`：

```py
$pip install python-social-auth

```

1.  完成安装此第三方库后，我们将转到我们的 mytweet 应用程序，并在`settings.py`文件中进行配置更改。

我们将此第三方库作为应用程序包含在我们的应用程序中，因此我们必须在`INSTALLED_APPS`变量中创建此应用程序的条目。

因此，将`'social.apps.django_app.default'`参数添加到`INSTALLED_APPS`变量中，如下所示：

```py
INSTALLED_APPS = (
'django.contrib.admin',
'django.contrib.auth',
'django.contrib.contenttypes',
'django.contrib.sessions',
'django.contrib.messages',
'django.contrib.staticfiles',
'user_profile',
'tweet',
'social.apps.django_app.default',
)
```

1.  接下来，我们需要在`settings.py`文件中添加`AUTHENTICATION_BACKEND`变量，列出我们想要支持的所有社交登录站点。对于此演示，我们将仅添加 Twitter 社交 Auth，但根据用例，您可以添加任何或尽可能多的 Twitter 社交 Auth。`AUTHENTICATION_BACKENDS`参数是 Python 类路径的列表，它知道如何验证用户。默认情况下指向`'django.contrib.auth.backends.ModelBackend'`参数。我们将`'social.backends.twitter.TwitterOAuth'`参数添加到`AUTHENTICATION_BACKENDS`变量中：

```py
AUTHENTICATION_BACKENDS = (
  'social.backends.twitter.TwitterOAuth',
  'django.contrib.auth.backends.ModelBackend',
)
```

1.  我们需要添加`TEMPLATE_CONTEXT_PROCESSORS`参数，它将在模板的上下文中添加后端和关联数据，这将反过来使用三个条目加载后端密钥，如下所示：

+   **关联**：如果用户已登录，则这将是 UserSocialAuth 实例的列表；否则，它将为空。

+   **未关联**：如果用户已登录，则这将是未关联后端的列表；否则，它将包含所有可用后端的列表。

+   **后端**：这是所有可用后端名称的列表。让我们来看一下以下代码片段：

```py
TEMPLATE_CONTEXT_PROCESSORS = (
'django.contrib.auth.context_processors.auth',
'django.core.context_processors.debug',
'django.core.context_processors.i18n',
'django.core.context_processors.media',
'django.contrib.messages.context_processors.messages',
'social.apps.django_app.context_processors.backends',
)
```

1.  我们的 mytweet 应用程序已经有一个用户模型，通过该模型用户可以登录并发布推文。我们将使用相同的模型类来从社交 Auth 创建用户。为此，我们需要添加此行，告诉`python-social-auth`使用现有的`user_profile`参数：

```py
SOCIAL_AUTH_USER_MODEL = 'user_profile.User'
```

1.  现在，我们将添加用于社交 Auth 的自定义 URL：

```py
SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/profile/'
SOCIAL_AUTH_LOGIN_ERROR_URL = '/login-error/'
SOCIAL_AUTH_LOGIN_URL = '/login/'
SOCIAL_AUTH_DISCONNECT_REDIRECT_URL = '/logout/'
```

将这些添加到`settings.py`文件中告诉社交 Auth 在以下情况下使用相应的 URL：

+   `SOCIAL_AUTH_LOGIN_REDIRECT_URL`：当社交认证成功时，将触发此 URL。我们将使用此 URL 向已登录用户发送他的个人资料页面。

+   `SOCIAL_AUTH_LOGIN_ERROR_URL`：在社交认证期间出现错误时，将触发此 URL。

+   `SOCIAL_AUTH_LOGIN_URL`：这是进行社交 Auth 的 URL。

+   `SOCIAL_AUTH_DISCONNECT_REDIRECT_URL`：用户注销后，将重定向到此 URL。

1.  由于我们在现有项目中添加了一个新应用程序，因此我们需要在数据库中创建相应的表，这是我们在之前章节中已经学习过的。

现在，我们需要迁移我们的数据库：

```py
$ python manage.py makemigrations
Migrations for 'default':
0002_auto_XXXX_XXXX.py:
- Alter field user on user_profile
$ python manage.py migrate
Operations to perform:
Apply all migrations: admin, default, contenttypes, auth, sessions
Running migrations:
Applying default.0001_initial... OK
Applying default.0002_auto_XXXX_XXXX... OK

```

1.  对于最后的配置更改，我们需要向社交 Auth URLs 添加一个条目：

```py
url('', include('social.apps.django_app.urls', namespace='social'))
```

更新后的 URL 模式将如下所示：

```py
urlpatterns = patterns('',
....
url('', include('social.apps.django_app.urls', namespace='social'))
)
```

## 创建 Twitter 应用程序

现在，我们将继续创建一个 Twitter 应用程序，该应用程序将为我们提供 API 密钥，以使这个社交认证工作：

1.  登录到您的 Twitter 账户并打开[`apps.twitter.com/app/new`](https://apps.twitter.com/app/new)。

页面将看起来有点像这样：

![创建 Twitter 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00315.jpeg)

1.  填写详细信息并创建您的 Twitter 应用程序。

由于我们正在本地测试我们的应用程序，请将`http://127.0.0.1:8000/complete/twitter`作为回调 URL，并检查**允许此应用程序用于使用 Twitter 登录**复选框。

当成功创建时，您的应用程序将如下所示：

![创建 Twitter 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00316.jpeg)

1.  继续使用**Keys and Access Tokens**选项卡，并复制**Consumer Key**（API 密钥）和**Consumer Secret**（API 密钥）密钥，如下截图所示：![创建 Twitter 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00317.jpeg)

1.  将以下行添加到`settings.py`文件中：

```py
SOCIAL_AUTH_TWITTER_KEY = 'your_key'
SOCIAL_AUTH_TWITTER_SECRET = 'your_secret'
```

1.  更新我们的用户类以适当地使用 Auth：

```py
class User(AbstractBaseUser, PermissionsMixin):
"""
Custom user class.
"""
  username = models.CharField('username', max_length=10, unique=True, db_index=True)
  email = models.EmailField('email address', unique=True)
  date_joined = models.DateTimeField(auto_now_add=True)
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)
  is_staff = models.BooleanField(default=False)

  USERNAME_FIELD = 'username'
  objects = UserManager()
  REQUIRED_FIELDS = ['email']
  class Meta:
    db_table = u'user'
    def __unicode__(self):
  return self.username 

importing the PermissionsMixin as from |django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
```

1.  现在，启动服务器或打开`http://127.0.0.1:8000/login/twitter/`。

这将带您到以下授权页面：

![创建 Twitter 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00318.jpeg)

1.  点击**登录**按钮，因为我们将使用这个 Twitter 应用程序来登录我们的应用程序。

完成后，它将将请求重定向回 mytweet 应用程序，并显示您的基本信息，如下截图所示：

![创建 Twitter 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00319.jpeg)

如果用户名在我们的数据库中不存在，它将使用 Twitter 用户名创建用户配置文件。

1.  让我们创建两条推文并保存它们。![创建 Twitter 应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00320.jpeg)

现在，只是为了检查社交认证是否有效，我们将注销并尝试再次打开 URL。重定向后，您将被重定向到相同的先前配置文件页面。

因此，我们学会了如何逐步创建 Twitter API，通过在 Twitter 注册您的应用程序来设置程序中的密钥。然后，我们看到我们的应用程序如何将您发送到 Twitter 网站进行身份验证，以及如何在 Twitter 网站完成身份验证后将您重定向到我们的网站。

# 在 Django 中构建 REST API

**表述性状态转移**（**REST**）是 Web 的基本架构原则。遵循 REST 原则的任何 API 都是设计成这样，即这里的浏览器客户端不需要了解 API 的结构。API 服务器只需要响应客户端发出的请求。

HTTP 的工作是应用于资源的动词。一些非常流行的动词是 GET 和 POST，但还有其他重要的动词，比如 PUT，DELETE 等。

例如，我们将使用由 Web 服务管理的 Twitter 数据库作为 REST API。对于所有 REST 通信，媒体类型是 API 服务器必须关心的主要内容，以及它必须响应客户端请求的格式。我们的 API 服务使用基于 JSON 的自定义超媒体，为此我们将分配/`json+tweetdb` MIME 类型应用程序。

对基本资源的请求将返回如下内容：

```py
Request
GET /
Accept: application/json+tweetdb
Response
200 OK
Content-Type: application/json+tweetdb
{
  "version": "1.0",
  "links": [
    {
      "href": "/tweets",
      "rel": "list",
      "method": "GET" 
    },
    {
      "href": "/tweet",
      "rel": "create",
      "method": "POST"
    }
  ]
}
```

我们可以通过引用`href`链接来观察输出，通过这些链接我们试图发送或检索信息，这些链接就是超媒体控制。我们可以通过`/user`命令和`GET`请求发送另一个请求来获取用户列表：

```py
Request
GET /user
Accept: application/json+tweetdb
  Response
  200 OK
  Content-Type: application/json+tweetdb

    {
      "users": [
      {
        "id": 1,
        "name": "Ratan",
        "country: "India",
        "links": [
          {
            "href": "/user/1",
            "rel": "self",
            "method": "GET"
          },
          {
            "href": "/user/1",
            "rel": "edit",
            "method": "PUT"
          },
          {
            "href": "/user/1",
            "rel": "delete",
            "method": "DELETE"
          }
        ]
      },
      {
        "id": 2,
        "name": "Sanjeev",
        "country: "India",
        "links": [
        {
          "href": "/user/2",
          "rel": "self",
          "method": "GET"
        },
        {
          "href": "/user/2",
          "rel": "edit",
          "method": "PUT"
        },
        {
          "href": "/user/2",
          "rel": "delete",
          "method": "DELETE"
        }
      ]
    }
  ],
  "links": [
    {
      "href": "/user",
      "rel": "create",
      "method": "POST"
    }
  ]
}
```

查看前面生成的输出，我们可以猜出所有用户是谁，以及我们可以发送哪些请求，比如`DELETE`或`PUT`请求。同样，我们甚至可以通过向`/user`发送`POST`请求来创建新用户，如下面的代码片段所示：

```py
Request
POST /user
Accept: application/json+tweetdb
  Content-Type: application/json+tweetdb
  {
    "name": "Zuke",
    "country": "United States"
  }
  Response
  201 Created
  Content-Type: application/json+tweetdb
  {
    "user": {
      "id": 3,
      "name": "Zuke",
      "country": "United States",
      "links": [
        {
          "href": "/user/3",
          "rel": "self",
          "method": "GET"
        },
        {
          "href": "/user/3",
          "rel": "edit",
          "method": "PUT"
        },
        {
          "href": "/user/3",
          "rel": "delete",
          "method": "DELETE"
        }
      ]
    },
    "links": {
      "href": "/user",
      "rel": "list",
      "method": "GET"
    }
  }
```

我们也可以更新现有的数据：

```py
Request
PUT /user/1
Accept: application/json+tweetdb
  Content-Type: application/json+tweetdb
  {
    "name": "Ratan Kumar",
    "country": "United States"
  }
  Response
  200 OK
  Content-Type: application/json+tweetdb
  {
    "user": {
      "id": 1,
      "name": "Ratan Kumar",
      "country": "United States",
      "links": [
        {
          "href": "/user/1",
          "rel": "self",
          "method": "GET"
        },
        {
          "href": "/user/1",
          "rel": "edit",
          "method": "PUT"
        },
        {
          "href": "/user/1",
          "rel": "delete",
          "method": "DELETE"
        }
      ]
    },
    "links": {
      "href": "/user",
      "rel": "list",
      "method": "GET"
    }
  }
```

正如您可以轻松注意到的那样，我们正在使用不同的`HTTP`动词（`GET`，`PUT`，`POST`，`DELETE`等）来操作这些资源。

现在，您已经对 REST 的工作原理有了基本的了解，所以我们将继续使用一个名为**Tastypie**的第三方库来操作我们的 mytweets 应用程序。

## 使用 Django Tastypie

Django Tastypie 使为 Web 应用程序开发 RESTful API 变得更加容易。

要安装 Tastypie，请运行以下命令：

```py
$pip install django-tastypie

```

在`settings.py`文件中的`INSTALLED_APPS`变量中添加`tastypie`参数。

API 需要许多其他可配置的设置，例如 API 调用的限制等，但默认情况下它们最初设置为默认值。您可以更改这一点，也可以保持不变。

一些您应该了解并根据需要修改的 API 设置如下：

+   `API_LIMIT_PER_PAGE`（可选）：此选项控制 Tastypie 在用户未指定 GET 参数的情况下在`view.applies`列表中返回的默认记录数。结果的数量不会被`resource`子类覆盖。

例如：

```py
API_LIMIT_PER_PAGE = 15
```

这里的默认限制是 20。

+   `TASTYPIE_FULL_DEBUG`（可选）：当发生异常时，此设置控制是否显示 REST 响应还是 500 错误页面。

如果设置为`True`并且`settings.DEBUG = True`，将显示**500 错误**页面。

如果未设置或设置为`False`，Tastypie 将返回序列化响应。

如果`settings.DEBUG`为`True`，您将获得实际的异常消息和跟踪。

如果`settings`.`DEBUG`为`False`，Tastypie 将调用`mail_admins()`函数并在响应中提供一个预定义的错误消息（您可以用`TASTYPIE_CANNED_ERROR`覆盖）。

例如：

```py
TASTYPIE_FULL_DEBUG = True
```

默认值为`False`。

+   `TASTYPIE_CANNED_ERROR`（可选）：当发生未处理的异常并且`settings.DEBUG`为`False`时，您可以编写自定义错误消息。

例如：

```py
TASTYPIE_CANNED_ERROR = "it's not your fault, it's our we will fix it soon."
```

这里的默认值是*“抱歉，无法处理此请求。请稍后重试。”*

+   `TASTYPIE_ALLOW_MISSING_SLASH`（可选）：您可以在不提供最终斜杠的情况下调用 REST API，这主要用于与其他系统迭代 API。

您还必须有`settings.APPEND_SLASH = False`，以便 Django 不发出 HTTP 302 重定向。

例如：

```py
TASTYPIE_ALLOW_MISSING_SLASH = True
```

这里的默认值是`False`。

+   `TASTYPIE_DATETIME_FORMATTING`（可选）：此设置配置 API 的全局日期/时间数据。

此设置的有效选项包括：

+   iso-8601

+   DateTime::ISO8601

+   ISO-8601（例如：2015-02-15T18:37:01+0000）

+   iso-8601-strict，与 iso-8601 相同，但会触发微秒

+   rfc-2822

+   DateTime::RFC2822

+   RFC 2822（例如，Sun, 15 Feb 2015 18:37:01 +0000）

```py
TASTYPIE_DATETIME_FORMATTING = 'rfc-2822'
```

以以下代码为例：

这里的默认值是 iso-8601。

+   `TASTYPIE_DEFAULT_FORMATS`（可选）：这个设置全局配置整个站点的序列化格式列表。

例如：

```py
TASTYPIE_DEFAULT_FORMATS = [json, xml]
```

默认为[`json, xml, yaml,html, plist`]。

### 实施简单的 JSON API

为了创建 REST 风格的架构，我们需要为我们的 tweets 定义资源类，所以让我们在`tweets`文件夹中创建一个`api.py`文件，内容如下：

```py
from tastypie.resources import ModelResource
from tweet.models import Tweet

class TweetResource(ModelResource):
class Meta:
queryset = Tweet.objects.all()
resource_name = 'tweet'
```

我们还需要一个 URL，用于所有 API 请求的 Tweet 资源，因此让我们在`urls.py`文件中添加一个条目：

```py
from tastypie.api import Api
from tweet.api import TweetResource

v1_api = Api(api_name='v1')
v1_api.register(TweetResource())

urlpatterns = patterns('',
...
url(r'^api/', include(v1_api.urls)),
)
```

这就是我们创建 tweets 的基本 REST API 所需的全部内容。

现在，我们将根据 REST URL 的变化来看各种输出。在浏览器中打开以下 URL，并观察`.json`格式的输出。

第一个 URL 将以`.json`格式显示 Tweet API 的详细信息：

`http://127.0.0.1:8000/api/v1/?format=json`

```py
{
  "tweet": {
    "list_endpoint": "/api/v1/tweet/",
    "schema": "/api/v1/tweet/schema/"
  }
}
```

根据第一个输出，我们将调用我们的 tweet API，这将给我们 tweet 信息和其他细节，如下所示：

`http://127.0.0.1:8000/api/v1/tweet/?format=json`

```py
{
  "meta": {
    "limit": 20,
    "next": null,
    "offset": 0,
    "previous": null,
    "total_count": 1
  },
  "objects": [
    {
      "country": "Global",
      "created_date": "2014-12-28T20:54:27",
      "id": 1,
      "is_active": true,
      "resource_uri": "/api/v1/tweet/1/",
      "text": "#Django is awesome"
    }
  ]
}
```

我们的基本 REST API 已经准备就绪，可以列出所有的 tweets。如果您查看架构，它会给我们很多关于 API 的细节，比如允许使用哪些 HTTP 方法，输出将是哪种格式，以及其他不同的字段。这实际上帮助我们了解我们可以使用我们的 API 做什么：

`http://127.0.0.1:8000/api/v1/tweet/schema/?format=json`

```py
{
  "allowed_detail_http_methods": [
    "get",
    "post",
    "put",
    "delete",
    "patch"
  ],
  "allowed_list_http_methods": [
    "get",
    "post",
    "put",
    "delete",
    "patch"
  ],
  "default_format": "application/json",
  "default_limit": 20,
  "fields": {
    "country": {
      "blank": false,
      "default": "Global",
      "help_text": "Unicode string data. Ex: \"Hello World\"",
      "nullable": false,
      "readonly": false,
      "type": "string",
      "unique": false
    },
    "created_date": {
      "blank": true,
      "default": true,
      "help_text": "A date & time as a string. Ex: \"2010-11- 10T03:07:43\"",
      "nullable": false,
      "readonly": false,
      "type": "datetime",
      "unique": false
    },
    "id": {
      "blank": true,
      "default": "",
      "help_text": "Integer data. Ex: 2673",
      "nullable": false,
      "readonly": false,
      "type": "integer",
      "unique": true
    },
    "is_active": {
      "blank": true,
      "default": true,
      "help_text": "Boolean data. Ex: True",
      "nullable": false,
      "readonly": false,
      "type": "boolean",
      "unique": false
    },
    "resource_uri": {
      "blank": false,
      "default": "No default provided.",
      "help_text": "Unicode string data. Ex: \"Hello World\"",
      "nullable": false,
      "readonly": true,
      "type": "string",
      "unique": false
    },
    "text": {
      "blank": false,
      "default": "No default provided.",
      "help_text": "Unicode string data. Ex: \"Hello World\"",
      "nullable": false,
      "readonly": false,
      "type": "string",
      "unique": false
    }
  }
}
```

一些 API 可能需要授权访问，比如用户资料、账户详情等等。只需添加一个基本授权行，就可以在 Tastypie API 中添加基本的 HTTP 授权：

```py
authentication = BasicAuthentication()
```

基本的 HTTP 授权可以通过头文件添加：

```py
from tastypie.authentication import BasicAuthentication
```

这将通过一个基本的 HTTP 请求来请求认证，看起来像下面的截图。一旦成功，当前会话中的所有请求都将得到认证。

![实现一个简单的 JSON API](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00321.jpeg)

这之后，通过演示，展示了如何使用 MongoDB 扩展 Django 系统的真实应用。

# 摘要

在本章中，您了解了开源以及如何在我们的项目中使用和实现开源的第三方包。现在，您将可以舒适地实现来自 Twitter 的社交认证。您也可以尝试自己实现 Facebook 和 Google+的相同功能。

在下一章中，您将学习更多关于调试技术的知识，当我们在代码中遇到任何错误或警告，或者一些配置问题时，我们需要使用这些技术。您还将学习产品开发工具，比如 Git，Sublime Text 编辑器等等。


# 第十三章：调试的艺术

在本章中，您将学习关于 Django 的 Web 开发的三个重要内容，每个程序员都应该了解。这些是您在代码出错时需要的概念和技术：

+   记录

+   调试

+   IPDB-消除错误的交互方式

# 记录

每个在生产环境中运行的应用程序都必须启用一些日志记录；如果没有启用，那么很难弄清楚出了什么问题以及问题出现在哪里。

Django 使用 Python 的基本日志记录，因此我们将在以下部分详细介绍 Python 日志记录，并看看我们如何在 Django 中使用日志记录服务。

日志的正式定义是软件中事件的跟踪。开发人员调用日志服务来说明事件已经发生或将要发生。日志可以包括需要跟踪的某些重要变量的描述或值。

Python 的`logging`模块带有五个基于事件严重性分类的日志函数。这些是`debug（）`，`info（）`，`warning（）`，`error（）`和`critical（）`。

这些按严重性分类在表格中，从最不严重到最严重：

+   `debug（）`：在修复错误时使用，通常包含数据的详细信息。

+   `info（）`：当事情按照预期进行时，会记录日志。这基本上告诉执行是否成功。

+   警告（）：当发生意外事件时会引发此警告。这实际上并不会停止执行，但可能会在将来停止执行。例如，“磁盘空间不足”。

+   `error（）`：这是警告的下一个级别，表示某个函数的执行可能已经停止。

+   `critical（）`：这是任何日志函数的最高级别。当发生非常严重的错误时，可能会停止整个程序的执行。

`logging`模块分为以下四个类别：

+   **记录器**：记录器是系统日志消息的入口点。程序将日志信息写入记录器，然后处理是否将其输出到控制台或写入文件。

每个记录器包括前面五个日志函数。写入记录器的每条消息称为日志记录。日志记录包含日志的严重性以及重要的日志变量或详细信息，例如错误代码或完整的堆栈跟踪。

记录器本身具有日志级别，其工作原理是：如果日志消息的日志级别大于或等于记录器的日志级别，则消息将进一步进行日志记录；否则，记录器将忽略该消息。

当记录器对日志的评估进行预处理并且需要处理生成的日志时，消息将传递给处理程序。

+   **处理程序**：处理程序实际上决定如何处理日志消息。它们负责对日志记录采取行动，例如写入控制台或文件，或通过网络发送。

与记录器一样，处理程序也有日志级别。如果日志记录的日志级别不大于或等于处理程序的级别，则处理程序将忽略日志消息。

可以将多个处理程序绑定到记录器，例如，可以为将 ERROR 和 CRITICAL 消息发送到电子邮件的记录器添加一个处理程序，而另一个处理程序可以将相同的日志写入文件以供以后调试分析。

+   **过滤器**：当日志记录从记录器传递到处理程序时，过滤器会添加额外的评估。默认行为是当日志消息级别达到处理程序级别时开始处理邮件。

此过程可以通过应用过滤器进一步中断进行额外评估。

例如，过滤器只允许一个来源将 ERROR 消息记录到处理程序。

过滤器还可以用于改变日志记录的优先级，以便相应地触发记录器和处理器。

+   **格式化程序**：在实际记录日志消息之前的最后一步是格式化程序实际格式化由 Python 格式化字符串组成的日志记录。

为了在我们的应用程序中启用日志记录，我们首先需要创建一个记录器。我们需要在`settings.py`文件中创建描述记录器、处理器、过滤器和格式化程序的 LOGGING 字典。

有关日志设置的完整文档可以在[`docs.python.org/2/library/logging.config.html`](https://docs.python.org/2/library/logging.config.html)找到。

以下是一个简单日志设置的示例：

```py
# settings.py
LOGGING = {
  'version': 1,
  'disable_existing_loggers': False,
  'formatters': {
    'simple': {
      'format': '%(levelname)s %(message)s'
    },
  },
  'handlers': {
    'file':{
      'level':'DEBUG',
      'class': 'logging.FileHandler',
      'formatter': 'simple',
      'filename': 'debug.log',
    }
  },
  'loggers': {
    'django': {
      'handlers':['file'],
      'propagate': True,
      'level':'INFO',
    },
  }
}
```

这个日志设置定义了一个用于 Django 请求的记录器（Django），以及一个写入日志文件的处理器（文件）和一个格式化程序。

我们将使用相同的方法来测试我们的`mytweet`项目的日志记录。

现在，我们需要将记录器的条目添加到我们想要跟踪事件的视图中。

为了测试项目，我们将更新我们的用户资料重定向类，以便在未经授权的用户尝试访问时进行日志记录，以及在注册用户尝试打开 URL 时也进行日志记录。

打开`tweet/view.py`文件，并将`UserRedirect`类更改为以下内容：

```py
class UserRedirect(View):
  def get(self, request):
    if request.user.is_authenticated():
      logger.info('authorized user')
      return HttpResponseRedirect('/user/'+request.user.username)
    else:
      logger.info('unauthorized user')
      return HttpResponseRedirect('/login/')
```

还要用`import`语句初始化记录器，并将以下代码添加到前面的代码中：

```py
import logging
logger = logging.getLogger('django')
```

就是这样。现在，打开浏览器，单击 URL `http://localhost:8000/profile`。

如果您尚未登录，将被重定向到登录页面。

现在，打开`debug.log`文件。它包含未经授权用户的`INFO`，这意味着我们的记录器工作正常：

```py
INFO unauthorized user
```

# 调试

调试是查找和消除错误（bug）的过程。当我们使用 Django 开发 Web 应用程序时，我们经常需要知道在 Ajax 请求中提交的变量。

调试工具有：

+   Django 调试工具栏

+   IPDB（交互式调试器）

## Django 调试工具栏

这是一组面板，用于显示当前页面请求/响应的各种信息，当单击面板时会显示更详细的信息。

与其简单地在 HTML 注释中显示调试信息，**Django 调试工具**以更高级的方式显示它。

### 安装 Django 调试工具栏

要安装 Django 调试工具栏，请运行以下命令：

```py
$ pip install django-debug-toolbar

```

安装后，我们需要进行基本配置更改以查看 Django 调试工具栏。

在`settings.py`文件的`INSTALLED_APPS`变量中添加`debug_toolbar`参数：

```py
# Application definition
INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'user_profile',
    'tweet',
    'social.apps.django_app.default',
    'tastypie',
    'debug_toolbar',
)
```

对于一个简单的 Django 项目来说，这已经足够了。当服务器运行在开发模式下时，Django 调试工具栏将自动调整自己。

重新启动服务器以查看 Django 调试工具栏，如下截图所示：

![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00322.jpeg)

如您所见，个人资料页面右侧有一个工具栏。Django 调试工具栏有许多面板，默认安装了一些，您可以在前面的截图中看到，还可以在此安装其他第三方面板。

现在，我们将讨论默认启用的面板：

+   **VersionPath**：`debug_toolbar.panels.versions.VersionsPanel`。该面板显示了基本信息，例如 Python、Django 的版本以及其他已安装应用的版本，如果信息可用：![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00323.jpeg)

+   **TimerPath**：`debug_toolbar.panels.timer.TimerPanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00324.jpeg)

该面板包含了 Django 开发的一些非常重要的统计信息。它显示了两个表，如前面的截图所示，分别是**资源使用**和**浏览器定时**。

+   **资源使用**：显示服务器机器上 Django 的资源消耗。

+   **浏览器时间**：这显示了客户端的详细信息。请求和响应时间对于了解代码是否可以优化至关重要，如果渲染过多导致页面加载缓慢，可以查看 domLoading。

+   **SettingsPath**：`debug_toolbar.panels.settings.SettingsPanel`。`settings.py`文件中定义的设置列表为**headers**

+   **路径**：`debug_toolbar.panels.headers.HeadersPanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00325.jpeg)

该面板显示 WSGI 环境中的 HTTP 请求和响应头和变量。

+   **请求路径**：`debug_toolbar.panels.request.RequestPanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00326.jpeg)

该面板显示了从框架中的变量，从视图变量开始，还有**ratancs**参数变量；然后是**Cookies**，**Session**，以及 GET 和 POST 变量，因为这些对调试表单提交非常有帮助。

+   **SQL 路径**：`debug_toolbar.panels.sql.SQLPanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00327.jpeg)

这个面板也非常重要，因为它显示了页面响应的数据库查询。这在应用程序扩展时非常有帮助，因为可以彻底检查查询并将其组合在一起，以减少数据库访问并改善页面响应性能。

这还显示了生成 SQL 调用的代码片段，这在调试应用程序时也非常有帮助。

+   **静态文件路径**：`debug_toolbar.panels.staticfiles.StaticFilesPanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00328.jpeg)

这将列出从我们在`settings.py`文件中设置的静态文件位置使用的所有静态文件。

+   **模板路径**：`debug_toolbar.panels.templates.TemplatesPanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00329.jpeg)

这将列出当前请求使用的模板和上下文。

+   **缓存路径**：`debug_toolbar.panels.cache.CachePanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00330.jpeg)

如果我们启用了缓存，那么这将显示给定 URL 的缓存命中的详细信息。

+   **信号路径**：`debug_toolbar.panels.signals.SignalsPanel`![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00331.jpeg)

该面板显示信号列表及其参数和接收器。

+   **日志路径**：`debug_toolbar.panels.logging.LoggingPanel`

如果启用了日志记录，那么该面板将显示日志消息，如下截图所示：

![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00332.jpeg)

+   **重定向路径**：`debug_toolbar.panels.redirects.RedirectsPanel`

当 URL 发生页面重定向时，启用此功能以调试中间页面。通常不调试重定向 URL，因此默认情况下此功能已禁用。

![安装 Django 调试工具栏](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00333.jpeg)

# IPDB - 消灭错误的交互方式

**Ipdb**是 Python 程序的交互式源代码调试器。

运行以下命令安装 Ipdb：

```py
$pip install ipdb

```

Ipdb 是调试 Python 应用程序的交互方式。安装 Ipdb 后，要在任何函数中使用它，只需编写以下代码：

```py
import ipdb;ipdb.set_trace()
```

这行神奇的代码将在代码出现的地方停止整个 Django 执行，并为您提供一个活动控制台，在那里您可以实时查找错误或检查变量的值。

在活动控制台中，Ipdb 的快捷键是：

+   `n`：这表示下一个

+   `ENTER`：这表示重复上一个

+   `q`：这表示退出

+   `p <variable>`：这是打印值

+   `c`：这表示继续

+   `l`：这是你所在的列表

+   `s`：这是进入子程序的步骤

+   `r`：这意味着继续执行子程序直到结束

+   `！<python 命令>`：在活动控制台中运行 Python 命令

# 总结

这一章涵盖的内容远不止这些。这些只是我们在 Django 项目中要使用的调试基础知识。你学会了如何记录和调试我们的代码，以便更好地进行高效编码实践。我们还看到了如何使用 Ipdb 进行更多的调试。

在下一章中，你将学习部署 Django 项目的各种方法。


# 第十四章：部署 Django 项目

因此，您在 Web 应用程序上做了很多工作，现在是时候让它上线了。为了确保从开发到生产的过渡顺利进行，必须对应用程序进行一些更改。本章涵盖了以下主题的更改，以帮助您成功启动 Web 应用程序：

+   生产 Web 服务器

+   生产数据库

+   关闭调试模式

+   更改配置变量

+   设置错误页面

+   云上的 Django

# 生产 Web 服务器

在本书中，我们一直在使用 Django 自带的开发 Web 服务器。虽然这个服务器非常适合开发过程，但绝对不适合作为生产 Web 服务器，因为它没有考虑安全性或性能。因此，它绝对不适合生产环境。

在选择 Web 服务器时有几个选项可供选择，但**Apache**是迄今为止最受欢迎的选择，Django 开发团队实际上推荐使用它。如何使用 Apache 设置 Django 取决于您的托管解决方案。一些托管计划提供预配置的 Django 托管解决方案，您只需将项目文件复制到服务器上，而其他托管计划则允许您自行配置一切。

如何设置 Apache 的详细信息因多种因素而异，超出了本书的范围。如果您想自己配置 Apache，请查阅 Django 在线文档[`docs.djangoproject.com/en/1.8/howto/deployment/wsgi/apache-auth/`](https://docs.djangoproject.com/en/1.8/howto/deployment/wsgi/apache-auth/)获取详细说明。

在本节中，我们将在 Apache 和`mod_wsgi`模块上部署我们的 Django 应用程序。因此，让我们首先安装这两个。

运行以下命令安装 Apache：

```py
$sudo apt-get install apache2

```

`mod_wsgi`参数是 Apache HTTP 服务器模块，提供符合**Web 服务器网关接口**（**WSGI**）标准的接口，用于在 Apache 下托管基于 Python 2.3+的 Web 应用程序。

运行以下命令安装`mod_wsgi`模块：

```py
$sudo aptitude install libapache2-mod-wsgi

```

使用 Apache 和`mod_wsgi`模块的 Django 是在生产中部署 Django 的最流行方式。

在大多数情况下，开发机器和部署机器是不同的。因此，建议您将项目文件夹复制到`/var/www/html/`文件夹，以便您的部署文件具有有限的权限和访问权限。

安装了 Apache 服务器后，请尝试在浏览器中访问`localhost`，即`127.0.0.1`。通过这样做，您应该会看到默认的 Apache 页面，如下截图所示：

![生产 Web 服务器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00334.jpeg)

我们必须将 Apache 服务器设置为我们的 Django 项目。为此，我们需要为 Apache 创建`configuration`文件。

为此，在`/etc/apache2/sites-available`导航到的`sites-available`文件夹中创建一个`mytweets.conf`文件，内容如下：

```py
<VirtualHost *:80>
  ServerAdmin mail@ratankumar.org
  ServerName mytweets.com
  ServerAlias www.mytweets.com
  WSGIScriptAlias / /var/www/html/mytweets/mytweets/wsgi.py
  Alias /static/ /var/www/html/mytweets/static/
  <Location "/static/">
    Options -Indexes
  </Location>
</VirtualHost>
```

让我们来看看以下术语列表，描述了前面代码片段中使用的各种参数：

+   `ServerAdmin`：如果您没有配置自定义错误页面，将显示此电子邮件地址，该页面将告诉用户联系此电子邮件地址。

+   `ServerName`：这是您想在其上运行项目的服务器的名称。

+   `ServerAlias`：这是您要在项目上运行的站点的名称。

+   `WSGIScriptAlias`：这是项目的`wsgi.py`文件的位置，在我们运行第一个命令创建 Django 项目时已经存在。

+   `Alias`：这是路径别名，磁盘上的文件夹的实际位置被映射为项目目录。

现在，我们需要使用`a2ensite`命令启用此站点配置，并使用`a2dissite`命令禁用现有站点配置。

让我们通过以下命令为 Apache 启用`mytweets.conf`文件：

```py
$a2ensite mytweets.conf

```

这将启用我们的`mytweets.conf`文件。你也可以使用以下命令禁用`default 000-default.conf`配置：

```py
$a2dissite 000-default.conf

```

### 注意

验证项目静态文件的文件权限。不要忘记在`settings.py`文件中允许主机的条目。

现在，重新启动服务器：

```py
$sudo service apache2 restart

```

这样，Django 现在运行在部署模式下，也就是说，它现在已经准备好投入生产。

# 生产数据库

到目前为止，我们一直在使用 SQLite 作为我们的数据库引擎。它简单，不需要常驻内存中的服务器。对于小型网站，SQLite 在生产模式下表现良好。然而，强烈建议您在生产中切换到使用客户端-服务器模型的数据库引擎。正如我们在前面的章节中看到的，Django 支持多种数据库引擎，包括所有流行的数据库引擎。Django 团队建议您使用 PostgreSQL，但 MySQL 也应该可以。无论你的选择是什么，你只需要在`settings.py`文件中更改数据库选项，就可以切换到不同的数据库引擎。

如果你想使用 MySQL，为 Django 创建一个数据库、用户名和密码。然后，相应地更改`DATABASE_*`变量。其他一切都应该保持不变。这就是 Django 数据库层的全部意义。

# 关闭调试模式

在开发过程中发生错误时，Django 会呈现一个详细的错误页面，提供大量有用的信息。然而，当应用进入生产阶段时，你不希望用户看到这样的信息。除了让用户感到困惑，如果让陌生人看到这样的信息，你还会面临网站安全问题的风险。

当我们使用`django-admin.py mytweets`命令时，它为项目创建了所有基本配置，我们在`settings.py`文件中使用了`debug=True`参数，当这个模式为`True`时。Django 会做一些额外的工作来帮助你更快地调试问题。Django 的内存使用更多，因为所有的查询都存储在数据库中的`django.db.connection.queries`中。

对于每个错误消息，都会显示消息的适当堆栈跟踪，这在生产模式下是不推荐的，因为这可能包含敏感信息，可能会削弱整个 Web 应用程序的安全性。

关闭调试模式非常简单。打开`settings.py`文件，将`DEBUG`变量更改为`False`：

`DEBUG = False`

禁用调试信息还有一个额外的好处；你可以提高网站的性能，因为 Django 不必跟踪调试数据以显示它。

# 更改配置变量

有许多需要为生产创建或更新的配置变量。生产环境是一个非常恶劣的环境。以下是你应该在部署过程中检查的清单。仔细检查`setting.py`文件，因为每个设置必须以正确的方式定义，以保持项目的安全。

设置可以是特定于环境的，比如在本地运行设置时。数据库凭据可能会改变，甚至数据库也可能会根据环境而改变。在进行部署过程时，启用可选的安全功能。

启用性能优化。第一步是禁用调试，这会提高网站的性能。如果有一个合适的错误报告机制，一旦`DEBUG`为`False`，就很难知道出了什么问题，所以最好在禁用调试模式后准备好你的日志。

在进行 Django 部署时，必须注意以下关键设置：

+   `SECRET_KEY`：此密钥必须选择大且随机，并且应保密。事实上，建议您永远不要将此信息保存在`settings.py`文件或版本控制存储库中。相反，将此信息保存在非版本控制文件中或环境路径中的安全位置：

```py
import os
SECRET_KEY = os.environ['SECRET_KEY']
```

这将从当前操作系统的环境中导入密钥。另一种建议的方法是从文件中导入，可以使用以下方法完成：

```py
with open('/etc/secret_key.txt') as f:
    SECRET_KEY = f.read().strip()
```

+   `ALLOWED_HOSTS`：这必须具有有效的主机配置。当调试模式关闭时，这用于保护 CSRF 攻击：

```py
ALLOWED_HOSTS = [
    '.example.com',  # Allow domain and subdomains
    '.example.com.',  # Also allow FQDN and subdomains
]
```

+   `ADMIN`：`ADMIN`键保存站点管理员的名称和电子邮件地址。您将在`settings.py`文件中找到它，注释如下：

```py
ADMINS = (
# ('Your Name', 'your_email@domain.com'),
)
```

在此处插入您的姓名和电子邮件地址，并删除`#`符号以取消注释，以便在发生代码错误时接收电子邮件通知。

当`DEBUG=False`并且视图引发异常时，Django 将通过电子邮件向这些人发送完整的异常信息。

+   `EMAIL`：由于您的生产服务器的电子邮件服务器很可能与您的开发机器不同，因此您可能需要更新电子邮件配置变量。在`settings.py`文件中查找以下变量并更新它们：

+   `EMAIL_HOST`

+   `EMAIL_PORT`

+   `EMAIL_HOST_USER`

+   `EMAIL_HOST_PASSWORD`

此外，您的 Web 应用程序现在有自己的域名，因此您需要更新以下设置以反映这一点：`SITE_HOST`和`DEFAULT_FROM_EMAIL`。

最后，如果您使用缓存，请确保在`CACHE_BACKEND`参数中设置正确的设置（理想情况下是`memcached`参数）；在生产环境中，您不希望开发后端出现在这里。

# 设置错误页面

在调试模式禁用时，您应该为错误页面创建模板，特别是这两个文件：

+   `404.html`：当请求的 URL 不存在时（换句话说，当页面未找到时，例如未捕获的异常时），将显示此模板。

创建两个文件，内容随意。例如，您可以在`404.html`模板中放置一个“页面未找到”的消息，或者一个搜索表单。

+   `500.html`：当发生内部服务器错误时，将显示此模板。

建议您通过从站点的基本模板派生它们，使这些模板具有一致的外观。将模板放在`templates`文件夹的顶部，Django 将自动使用它们。

这应涵盖对生产至关重要的配置更改。当然，此部分并非穷尽一切，还有其他您可能感兴趣的设置。例如，您可以配置 Django 在请求的页面未找到时通过电子邮件通知您，或者提供可以查看调试信息的 IP 地址列表。有关这些以及更多信息，请参阅`settings.py`文件中的 Django 文档。

希望本节能够帮助您使从开发到生产的过渡更加顺利。

# 云上的 Django

Web 开发中的部署方式随着时间的推移发生了变化。大多数初创公司正在转向云设置，远离传统的 VPS 托管方法，这是因为可靠性、性能和易于扩展性。

提供**基础设施即服务**（**IAS**）的最受欢迎的云平台是 Amazon EC2 和 Google Compute Engine。

然后，我们还有其他众所周知的选项，例如**平台即服务**（**PaaS**），在这种服务中，您可以像将代码推送到普通存储库一样将代码推送，以便自动部署。这些包括 Google App Engine、Heroku 等。

让我们逐一介绍它们。

## EC2

在**EC2**上部署很简单。按照给定的步骤在 EC2 上部署所需的设置：

1.  为 AWS 创建一个帐户。请访问[`aws.amazon.com`](http://aws.amazon.com)并单击**创建免费帐户**，如下面的屏幕截图所示：![EC2](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00335.jpeg)

1.  注册并添加信用卡以获取结算明细。完成后，登录，您将看到一个仪表板。为了部署，我们需要在 AWS 上创建一个名为 EC2 实例（它可以被视为服务器）的服务器。

1.  点击 EC2（在左上角），如下截图所示：![EC2](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00336.jpeg)

如前面的截图所示，我已经有一个正在运行的实例（**1 Running Instances**）。单击**启动实例**以创建新实例。这将显示可用的 AWS 映像（类似于 VMware 中的截图或上次备份的磁盘）：

![EC2](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00337.jpeg)

1.  向下滚动以选择 Ubuntu 64 位实例（Ubuntu 服务器）。

接下来，选择一个实例类型；最初，选择免费套餐，这是 AWS 为每个新帐户提供的**t2.micro**实例类型。检查其他设置，因为大多数设置都保持默认值。转到**标签**实例并为您的实例命名：

![EC2](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00338.jpeg)

1.  接下来要做的重要事情是选择安全组。AWS 具有此功能，可保护您的服务器免受攻击。在这里，您可以配置哪些特定端口将是公开可访问的。基本上，您需要打开两个端口以使推文公开可访问。

1.  您应该使用 SSH（端口 22）从本地机器连接系统以部署代码。

1.  HTTP（端口 80）用于运行您的 Django 服务器。

### 注意

由于我们将使用的数据库运行在同一实例上，因此我们不会将 MySQL 端口添加到安全组中。

确保您已经配置了类似以下内容：

![EC2](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00339.jpeg)

接下来，审查并启动实例。此外，您必须创建一个密钥对以通过 SSH 访问您的 AWS 机器。密钥是一个`.pem`文件，您将使用它与 SSH 远程登录到您的机器。创建一个密钥对并下载`.pem`文件。

### 注意

确保`PEM`文件具有特定的 400 权限。如果要使 SSH 工作，您的密钥文件不得公开可见。如有需要，请使用以下命令：`chmod 400 mykey.pem`。

这将需要一段时间，并且将作为正在运行的实例重新显示在您的仪表板上。

单击屏幕左侧的实例。然后，您可以看到正在运行的实例。单击实例行以在屏幕底部获取更多详细信息，如下图所示：

![EC2](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00340.jpeg)

在详细信息的右侧，您可以看到公共 DNS：<public DNS>和公共 IP：<public IP>。这就是您需要的一切（当然还有`.pem`文件）来登录到您的实例。

在您的机器上，转到终端中下载`PEM`文件的文件夹，并在终端上键入`$ssh -i <pemfilename>.pem ubuntu@<pubic IP>`。

否则，输入以下内容：

`$ssh -i <pemfilename>.pem ubuntu@<public Dns>`。

通过这样做，您将登录到远程服务器。

这是您从头开始的在线系统。如果要从本地机器部署网站，则可以转到以前的章节并安装虚拟环境所需的一切。Django 和 Apache 在此服务器上执行部署。

部署后，使用我们用于 SSH 的公共 IP，您应该看到已部署的服务器。

## 谷歌计算引擎

**谷歌计算引擎**的工作原理与 AWS EC2 相同。目前，谷歌计算引擎没有免费套餐。

谷歌服务器以其可靠性和性能而闻名。因此，如果您考虑具有此需求的项目，请选择它们。

谷歌云为您提供了一个云 SDK 来使用其实例，并且大部分初始配置可以从终端完成。

要在谷歌计算引擎上创建一个实例，请转到：

[`cloud.google.com/compute/docs/quickstart`](https://cloud.google.com/compute/docs/quickstart)。

此链接将帮助您设置在 Apache 服务器上运行的实例。

## 红帽开源混合云应用平台

红帽提供了另一种云部署解决方案，免费使用一定限额，名为 OpenShift 的服务。

您可以创建一个 OpenShift 帐户，并从[`www.openshift.com/app/account/new`](https://www.openshift.com/app/account/new)获取一个免费的基本 3 dynamo 云服务器。

创建帐户后，您可以转到[`openshift.redhat.com/app/console/applications`](https://openshift.redhat.com/app/console/applications)并添加您的帐户。

OpenShift 为您提供了一个已经设置好版本控制的 Django 存储库。

您只需要进行更改并推送代码。它将自动部署代码。

OpenShift 还提供 SSH 功能，可以登录到您的云服务器，并进行一些基本的故障排除。

## Heroku

这也是一个很好的平台，可以顺利地将您的 Django 代码部署到云端。与谷歌计算引擎一样，Heroku 还为您提供了一个 SDK 工具，可以从本地终端安装并执行配置更改。您需要获取一个工具包（Heroku 的 SDK）。

在[`signup.heroku.com`](https://signup.heroku.com)上创建一个 Heroku 帐户。

以下是从[`devcenter.heroku.com/articles/getting-started-with-python`](https://devcenter.heroku.com/articles/getting-started-with-python)中获取的步骤。查看最新更新。以下步骤解释了如何创建和使用 Heroku：

1.  首先，我们需要安装 Heroku Toolbelt。这为您提供了访问 Heroku 命令行实用程序的权限：

```py
$wget -qO- https://toolbelt.heroku.com/install-ubuntu.sh | sh

```

将出现以下屏幕：

![Heroku](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00341.jpeg)

1.  它将在本地机器上安装 Heroku Toolbelt。从命令行登录到 Heroku：

```py
$heroku login

```

1.  使用与 Web 登录相同的用户名和密码。让我们来看一下下面的截图：![Heroku](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00342.jpeg)

1.  现在，访问[`devcenter.heroku.com/articles/getting-started-with-django`](https://devcenter.heroku.com/articles/getting-started-with-django)来在 Heroku 上部署 Django。

## 谷歌应用引擎

谷歌应用引擎的工作方式不同，它不使用传统的数据库，而是有自己的数据库。因此，要在谷歌应用引擎上部署 Django，我们将使用一个名为 Django-nonrel 的单独项目。

Django-nonrel 是一个允许开发人员在非关系数据库上运行原生 Django 项目（包括 Django 的 ORM）的项目，其中之一就是谷歌应用引擎的数据存储。这是除了 Django 一直支持的标准传统 SQL 数据库之外的所有内容。谷歌应用引擎确实具有一些 Django 支持，但该支持主要涉及模板和视图。对于其他允许快速开发的工具，例如表单、内置管理界面或 Django 身份验证，这些都无法直接运行。Django-nonrel 改变了这一点，为 Django 开发人员提供了支持。

# 总结

本章涵盖了各种有趣的主题。您了解了几种在部署 Django 时有用的基于 Django 的部署选项。您还学会了如何将 Django 项目从开发环境迁移到生产环境。值得注意的是，您学到的这些框架都非常易于使用，因此您将能够在将来的项目中有效地利用它们。


# 第十五章：接下来是什么？

网络开发随着时间的推移发生了变化，用户消费信息的设备也发生了变化。网络最初是为大屏设备设计的，但最近的趋势表明，小屏设备和手持设备的使用量增加了。因此，有必要调整网络以适应小屏设备，但这些设备对功耗非常敏感。因此，在 Django 中有必要将后端功能与前端功能分开。

其中一个最广泛使用的解决方案是在 Django 后端使用启用了 API 的前端来使用它。对于这种情况，使用**AngularJS**是最合适的。

REST 一直是 Web 开发的未来，REST API 是现代 Web 的一个组成部分。随着设备之间的碎片化增加，出现了需要一个单一的最小端点的需求，该端点不执行任何呈现操作。例如，信息检索或通信可能尽可能快，也可能扩展，而这方面的呈现或业务逻辑则由现代浏览器使用前端框架来处理。

# AngularJS 满足 Django

AngularJS 是一个现代的 JavaScript 框架，用于在浏览器中创建复杂的 Web 应用程序。

自 2009 年以来，AngularJS 一直在快速发展，并被广泛接受为生产级前端框架。现在由 Google 维护。

AngularJS 有一个非常有趣的诞生故事。当 angular 的一位创始人在 3 周内重新创建了一个网页应用程序时，引起了很大的关注，而最初开发这个应用程序需要 6 个月的时间，通过将代码行数从 17,000 行减少到 1,000 行。

AngularJS 在传统 Web 开发框架上有许多特点。其中，一些独特和创新的特点是双向数据绑定、依赖注入、易于测试的代码以及使用指令扩展 HTML 方言。

对于服务器端，我们可以使用**Django REST 框架**或**Tastypie**来进行 REST 端点。然后，我们可以使用 AngularJS，它专注于 MVC 模型，以鼓励创建易于维护的模块。

Web 技术已经从同步发展到异步，也就是说，网站请求现在大量使用异步调用来刷新内容，而不重新加载页面，一个例子就是你的 Facebook 动态。

AngularJS 是 Django Web 开发中更好的异步需求解决方案之一。

在下面的示例中，我们将使用 AngularJS 创建一个单页面，该页面使用我们已经创建的推文 API。

我们将使用 AngulaJS 列出所有推文，但在此之前，我们需要熟悉 AngularJS 的关键术语：

+   **指令**：为此，HTML 文件使用自定义属性和元素进行扩展。AngularJS 使用**ng-directives**扩展 HTML。**ng-app**指令用于定义 AngularJS 的应用程序。**ng-model**指令将 HTML 控件（输入、复选框、单选按钮、选择和文本区域）的值绑定到应用程序。**data.ng-bind**指令将应用程序数据绑定到 HTML 视图。

+   **模型**：这是向用户显示的数据，用户与之交互。

+   **作用域**：这是存储模型的上下文，以便控制器、指令和表达式可以访问它。

+   **控制器**：这是视图背后的主要业务逻辑。

当我们设计基于 API 的 Web 应用程序时，很有可能（API 的后端和 Web 应用程序的前端）它们位于不同的服务器上。因此，有必要为**跨域资源共享**配置 Django。

根据维基百科上的定义：

> *跨域资源共享（CORS）是一种机制，允许从资源原始域之外的另一个域请求网页上的许多资源（例如字体、JavaScript 等）*

我们需要修改我们的 Django API，以允许来自其他服务器的请求。我们现在将更新`tweets`应用程序的`api.py`文件，以允许对服务器的跨站点请求：

```py
class CORSResource(object):
  """
  Adds CORS headers to resources that subclass this.
  """
  def create_response(self, *args, **kwargs):
    response = super(CORSResource, self).create_response(*args, **kwargs)
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

  def method_check(self, request, allowed=None):
    if allowed is None:
      allowed = []

    request_method = request.method.lower()
    allows = ','.join(map(unicode.upper, allowed))
    if request_method == 'options':
      response = HttpResponse(allows)
      response['Access-Control-Allow-Origin'] = '*'
      response['Access-Control-Allow-Headers'] = 'Content-Type'
      response['Allow'] = allows
      raise ImmediateHttpResponse(response=response)

    if not request_method in allowed:
      response = http.HttpMethodNotAllowed(allows)
      response['Allow'] = allows
      raise ImmediateHttpResponse(response=response)
    return request_method
```

添加了这个类之后，我们可以创建任何资源的子类，以便为跨域请求公开。我们现在将更改我们的`Tweet`类，以便可以跨站点访问。

让我们将`Tweet`类更新为以下内容：

```py
class TweetResource(CORSResource, ModelResource):
  class Meta:
    queryset = Tweet.objects.all()
    resource_name = 'tweet'
```

现在，推文资源已准备好从不同的域访问。

以下是一个基本的 AngularJS 示例：

创建一个名为`app.html`的单个 HTML 文件（由于此文件与我们现有的 Django 项目无关，因此可以在项目文件夹之外创建），内容如下。当前，此页面使用来自本地磁盘的 AngularJS，您也可以从 CDN 导入页面：

```py
<html ng-app="tweets">
  <head>
    <title>Tweets App</title>
    <script src="img/angular.min.js"></script>
  </head>
  <body>
    <div ng-controller="tweetController"> 
      <table>
        <tr ng-repeat="tweet in tweets">
          <td>{{ tweet.country }}</td>
          <td>{{ tweet.text }}</td>
        </tr>
      </table>
    </div>
    <script src="img/app.js"></script>
  </body>
</html>
```

在以下代码中，`ng-controller`指令在其渲染时触发，它处理任何业务逻辑，并将计算的模型注入作用域内。

`<div ng-controller="tweetController">`标签是一个例子，其中`tweetController`参数在其`div`呈现之前被处理。

我们的业务逻辑完全在`app.js`文件中的 JavaScript 中：

```py
var app = angular.module('tweets', []);
app.controller("tweetController", function($scope,$http) {
  $http({ headers: {'Content-Type': 'application/json; charset=utf-8'},
  method: 'GET',
  url: "http://127.0.0.1:8000/api/v1/tweet/?format=json"
  })
    .success(function (data) {
    $scope.tweets = data.objects;
  })
});
```

此`app.js`文件向推文的 API 端点发出请求，并将`tweets`对象注入到作用域中，由 AngularJS 在视图（`app.html`）中使用`ng-repeat`循环指令呈现：

```py
  <tr ng-repeat="tweet in tweets">
    <td>{{ tweet.country }}</td>
    <td>{{ tweet.text }}</td>
  </tr>
```

上述代码的输出如下图所示，显示了国家和推文：

![AngularJS meets Django](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00343.jpeg)

这只是一个基本的 AngularJS 应用程序，因为高级 Web 开发已完全从后端转移到前端。基于 AngularJS 的应用程序最适合完整的单页应用程序。

# 使用 Elasticsearch 的 Django 搜索

搜索已成为我们现在处理的大多数应用程序的一个组成部分。从 Facebook，搜索朋友，到 Google，在那里您搜索整个 Web，从博客到日志，一切都需要搜索功能来解锁网站上的隐藏信息。

Web 正以指数速度发展。现在，1GB 的数据已经过时，每天产生数百 TB 的结构化和非结构化数据。

**Elasticsearch**（**ES**）比其他替代方案更好，因为除了提供全文搜索外，它还提供有意义的实时数据分析，并且在集群数据基础设施方面具有高度可扩展性的强大支持。

Elasticsearch 还为您提供了一个简单的 REST API，可以轻松集成到任何自定义应用程序和 Django（更广泛地说，Python）开发环境中，提供了许多很酷的开箱即用的工具来实现 Elasticsearch。

Elasticsearch 网站（[`www.elasticsearch.org/`](http://www.elasticsearch.org/)）包含详尽的文档，网上还有很多很好的例子，这些例子将帮助您构建任何您需要的搜索。通过充分利用 Elasticsearch，您可能可以用它构建自己的“Google”。

## 安装 Elasticsearch 服务器

首先安装 Java。然后，下载并提取 Elasticsearch。您可以将 ES 作为服务运行，也可以使用以下 Shell 命令启动 ES 服务器（根据您的系统更改路径）：

```py
set JAVA_HOME=\absolute\path\to\Java
\absolute\path\to\ES\bin\elasticsearch

```

如果做得正确，您可以在浏览器中调用以下 URL：

`http://127.0.0.1:9200/`

它将以以下方式给出响应，但`build_hash`参数不同：

```py
{
  "status" : 200,
  "name" : "MN-E (Ultraverse)",
  "cluster_name" : "elasticsearch",
  "version" : {
    "number" : "1.4.1",
    "build_hash" : "89d3241d670db65f994242c8e8383b169779e2d4",
    "build_timestamp" : "2014-11-26T15:49:29Z",
    "build_snapshot" : false,
    "lucene_version" : "4.10.2"
  },
  "tagline" : "You Know, for Search"
}
```

Elasticsearch 带有基本的部署配置。但是，如果您想调整配置，那么请参考其在线文档，并在`elasticsearch.yml`文件中更改 Elasticsearch 配置。

### Elasticsearch 与 Django 之间的通信

Django 可以使用基本的 Python 编程与 Elasticsearch 无缝集成。在此示例中，我们将使用 Python 请求库从 Django 向 Elasticsearch 发出请求。我们可以通过输入以下代码来安装请求：

```py
$pip install requests

```

对于搜索功能，我们主要需要执行三个操作：

1.  创建一个 Elasticsearch 索引。

1.  向索引提供数据。

1.  检索搜索结果。

#### 创建 Elasticsearch 索引

在加载 Elasticsearch 索引并检索搜索结果之前，Elasticsearch 必须了解有关您的内容以及数据处理方式的一些详细信息。因此，我们创建了一个包含设置和映射的 ES 索引。**映射**是 ES 中 Django 模型的等价物-用于定义内容的数据字段。

虽然映射是完全可选的，因为 Elasticsearch 会根据其用于索引的信息动态创建映射，但建议您预定义用于索引的数据映射。

创建一个 ES 索引的 Python 示例如下：

```py
  data = {
    "settings": {
      "number_of_shards": 4,
      "number_of_replicas": 1
    },
    "mappings": {
      "contacts": {
        "properties": {
          "name": { "type": "string" },
          "email": { "type": "string" },
          "mobile": { "type": "string" }
        },
        "_source": {
          "enabled": "true"
        }
      }
    }
  }
}

import json, requests
response = requests.put('http://127.0.0.1:9200/contacts/', data=json.dumps(data))
print response.text
```

上述代码的输出如下图所示：

![创建 Elasticsearch 索引](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00344.jpeg)

对于使用 Elasticearch 进行的每个操作，它都会给出一个响应消息，例如`{"acknowledged":true}`，这意味着我们的索引已成功由 Elasticsearch 创建。

我们可以通过执行查询命令来检查映射是否实际已更新：

```py
mapping_response = requests.get('http://127.0.0.1:9200/contacts/_mappings')
print mapping_response.text

```

以下图显示了 Elasticsearch 已更新了新的映射：

![创建 Elasticsearch 索引](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00345.jpeg)

在创建了我们的第一个 Elasticsearch 索引之后，我们创建了包含信息的 JSON 字典，并通过 Python 请求将此信息转储到 Elasticsearch 中。**"contacts"**参数是我们选择的索引名称，我们将使用这个名称来向 Elasticsearch 服务器提供和检索数据。**"mappings"**键描述了您的索引将保存的数据。我们可以有尽可能多的不同映射。每个映射都包含一个字段，其中存储数据，就像 Django 模型一样。一些基本的核心字段是字符串、数字、日期、布尔值等等。完整的列表在 Elasticsearch 文档中给出。"shards"和"replicas"参数在 ES 术语表中有解释。没有"settings"键，ES 将简单地使用默认值-在大多数情况下这是完全可以的。

#### 向索引提供数据

现在您已经创建了一个索引，让我们将内容存储在其中。一个包含标题、描述和内容作为文本字段的虚构 BlogPost 模型的示例 Python 代码如下：

```py
import json, requests
data = json.dumps(
  {"name": "Ratan Kumar",
  "email": "mail@ratankumar.org",
  "mobile": "8892572775"})
response = requests.put('http://127.0.0.1:9200/contacts/contact/1', data=data)
print response.text
```

您将看到如下所示的输出：

![向索引提供数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00346.jpeg)

这个确认显示我们的联系人数据已被索引。当然，索引单个数据并搜索它并没有太多意义，所以在进行检索查询之前，我们将索引更多的联系人。

Elasticsearch 还提供了批量索引，可以按如下方式使用：

```py
import json, requests
contacts = [{"name": "Rahul Kumar",
  "email": "rahul@gmail.com",
  "mobile": "1234567890"},
  {"name": "Sanjeev Jaiswal",
  "email": "jassics@gmail.com",
  "mobile": "1122334455"},
  {"name": "Raj",
  "email": "raj@gmail.com",
  "mobile": "0071122334"},
  {"name": "Shamitabh",
  "email": "shabth@gmail.com",
  "mobile": "9988776655"}
]

for idx, contact in enumerate(contacts):
  data += '{"index": {"_id": "%s"}}\n' % idx
  data += json.dumps({
    "name": contact["name"],
    "email": contact["email"],
    "mobile": contact["mobile"]
  })+'\n'
```

让我们看一下以下的屏幕截图：

![向索引提供数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00347.jpeg)

正如您在前面的屏幕截图中所看到的，**"status": 201**参数在 HTTP 状态中表示记录已成功创建。Elasticsearch 逐行读取数据，因此我们在每个数据集的末尾使用了**"\n"**。批量操作比运行多个单个请求要快得多。

这个例子是一个简单的 JSON 例子。当我们在 Django 应用程序中使用 Elasticsearch 时，相同的 JSON 对象可以被 Django 模型替换，并且可以通过`ModelName.objects.all()`查询获取所有 Django 模型对象，然后解析并保存它。此外，在手动 ID 的情况下，正如我们在前面的例子中使用的那样，它是索引计数，如果您将主键用作 Elasticsearch ID 进行索引，那将更加方便。这将帮助我们直接查询结果对象，如果我们没有将对象信息作为有效负载传递。

#### 从索引中检索搜索结果

搜索索引相当简单。同样，我们使用 Python 请求将 JSON 编码的数据字符串发送到我们的 ES 端点：

```py
data = {
  "query": {
    "query_string": { "query": "raj" }
  }
}

response = requests.post('http://127.0.0.1:9200/contacts/contact/_search', data=json.dumps(data))
print response.json()
```

这给出了如下图所示的结果：

![从索引中检索搜索结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00348.jpeg)

在示例中，我们正在搜索我们的联系人索引中的术语**"raj"**。ES 以 JSON 编码格式返回所有按相关性排序的命中。每个命中都包含一个**"_id"**字段，该字段提供了所关联博客文章的主键。使用 Django 的 ORM，现在可以简单地从数据库中检索实际对象。

### 注意

ES 搜索端点提供了无限的选项和过滤器；从大型数据集中快速检索、分页以及构建强大搜索引擎所需的一切。

这只是冰山一角。当您使用 Elasticsearch 构建 Django 应用程序时，您将探索许多有趣的功能，例如聚合，可以在前面的示例中使用。它列出了 Ratan 的所有联系信息和自动完成，该功能将用于建议用户在搜索联系人的搜索框中开始输入时从 Elasticsearch 中完整地名称。

# 摘要

在本章中，我们了解了在涉及 Django 项目时最常用的两个重要组件，即 AngularJS 和 Elasticsearch。作为前端框架，AngularJS 不仅通过将渲染逻辑推送到浏览器来减少服务器的负载，还为用户在使用基于 AngularJS 的应用程序时提供丰富的体验。

另一方面，Elasticsearch 是最流行的搜索引擎之一，也是开源的。设置和扩展 Elasticsearch 的便利性使其成为任何搜索引擎需求的选择。您也学到了一些关于 Django 的知识。正如本章开始时所说，我们相信您的目标是学习一项技能并成为其中的专家。好吧，这只是开始；还有更多的事情需要您去探索，以达到本章讨论的每个主题的专家级水平。我们已经到达了本书的结尾。在本书中，我们从头开始构建了一个微型博客应用程序的过程，使用 Django 作为我们的框架。我们涵盖了许多与 Web 2.0 和社交应用程序相关的主题，以及许多 Django 组件。您可以随时参考 Django 的在线文档。如果您想了解特定功能或组件的更多信息，请访问[`docs.djangoproject.com`](https://docs.djangoproject.com)。

感谢选择本书来学习 Django Web 开发基础知识。我们祝愿您在职业生涯中取得成功。
