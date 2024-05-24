# Django Web 开发学习手册（三）

> 原文：[`zh.annas-archive.org/md5/C7E16835D8AC71A567CF7E772213E9F7`](https://zh.annas-archive.org/md5/C7E16835D8AC71A567CF7E772213E9F7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：创建管理界面

在本章中，我们将学习使用 Django 的内置功能的管理员界面的特性。我们还将介绍如何以自定义方式显示推文，包括侧边栏或启用分页。本章将涉及以下主题：

+   自定义管理界面

+   自定义列表页面

+   覆盖管理模板

+   用户、组和权限

+   用户权限

+   组权限

+   在视图中使用权限

+   将内容组织成页面（分页）

# 自定义管理界面

Django 提供的管理界面非常强大和灵活，从 1.6 版本开始，默认情况下就已激活。这将为您的站点提供一个功能齐全的管理工具包。尽管管理应用程序对大多数需求应该足够了，但 Django 提供了几种自定义和增强它的方法。除了指定哪些模型可用于管理界面外，您还可以指定如何呈现列表页面，甚至覆盖用于呈现管理页面的模板。因此，让我们了解这些功能。

# 自定义列表页面

正如我们在上一章中看到的，我们使用以下方法将我们的模型类注册到管理界面：

+   `admin.site.register` (`Tweet`)

+   `admin.site.register` (`Hashtag`)

+   `admin.site.register` (`UserFollower`)

我们还可以自定义管理页面的几个方面。让我们通过示例来了解这一点。推文列表页面显示每条推文的字符串表示，如下面的屏幕截图所示：

![自定义列表页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00306.jpeg)

如果此页面能够显示发布推文的用户的名称以及发布时间，那不是更有用吗？事实证明，实现这个功能只需要添加几行代码。

编辑`tweet/admin.py`文件中的推文模型如下：

```py
  from django.contrib import admin
  from models import Tweet, HashTag
  from user_profile.models import UserFollower
  # Register your models here.
  admin.site.register(Tweet)
  admin.site.register(HashTag)
  admin.site.register(UserFollower)
```

在“＃在此注册您的模型”上方添加新的代码行，更新后的代码将如下所示：

```py
  from django.contrib import admin
  from models import Tweet, HashTag
  from user_profile.models import UserFollower
 class TweetAdmin(admin.ModelAdmin):
 list_display = ('user', 'text', 'created_date')
  # Register your models here.
  admin.site.register(Tweet, TweetAdmin)))
  admin.site.register(HashTag)
  admin.site.register(UserFollower)
```

此代码为`TweetAdmin()`类的管理员视图添加了额外的列：

```py
  class TweetAdmin(admin.ModelAdmin):
    list_display = ('user', 'text', 'created_date')
```

此外，我们为管理员推文传递了一个额外的参数；即`admin.site.register(Tweet)`现在变成了`admin.site.register(Tweet, TweetAdmin)`。刷新同一页面，注意变化，如下面的屏幕截图所示：

![自定义列表页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00307.jpeg)

表现得更有条理了！我们只需在`Tweet`模型的`TweetAdmin()`类中定义一个名为`list_display`的元组属性。该元组包含要在列表页面中使用的字段的名称。

在 Admin 类中还有其他属性可以定义；每个属性应该定义为一个或多个字段名称的元组。

+   `list_filter`：如果定义了，这将创建一个侧边栏，其中包含可以根据模型中一个或多个字段来过滤对象的链接。

+   `ordering`：用于在列表页面中对对象进行排序的字段。

+   `search_fields`：如果定义了，它将创建一个可用于搜索的搜索字段。字段名称前面加上减号，并且根据一个或多个字段的数据模型中的可用对象，使用降序而不是升序。

让我们在推文列表页面中利用前述每个属性。再次编辑`tweet/admin.py`文件中的推文模型，并追加以下突出显示的行：

```py
  from django.contrib import admin
  from models import Tweet, HashTag
  from user_profile.models import UserFollower

  class TweetAdmin(admin.ModelAdmin):
    list_display = ('user', 'text', 'created_date')
 list_filter = ('user', )
 ordering = ('-created_date', )
 search_fields = ('text', )

  # Register your models here.
  admin.site.register(Tweet, TweetAdmin)
  admin.site.register(HashTag)
  admin.site.register(UserFollower)
```

使用这些属性后的效果如下：

![自定义列表页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00308.jpeg)

正如您所看到的，我们能够只用几行代码来自定义和增强推文列表页面。接下来，我们将学习如何自定义用于呈现管理页面的模板，这将使我们对管理界面有更大的控制权。

# 覆盖管理模板

有时您想要更改管理界面的外观或移动各种管理页面上的元素并重新排列它们。幸运的是，管理界面足够灵活，可以通过允许我们覆盖其模板来执行所有这些操作及更多操作。自定义管理模板的过程很简单。首先，您将模板从管理应用程序文件夹复制到项目的模板文件夹中，然后编辑此模板并根据您的喜好进行自定义。管理模板的位置取决于 Django 的安装位置。以下是 Django 在主要操作系统下的默认安装路径列表：

+   Windows：`C:\PythonXX\Lib\site-packages\django`

+   UNIX 和 Linux：`/usr/lib/pythonX.X/site-packages/django`

+   Mac OS X：`/Library/Python/X.X/site-packages/django`

（这里，**X.X**是您系统上 Python 的版本。`site-packages`文件夹也可以被称为`dist-packages`。）

如果您在操作系统的默认安装路径中找不到 Django，请执行文件系统搜索`django-admin.py`。您会得到多个结果，但您想要的结果将在 Django 安装路径下，位于名为`bin`的文件夹内。

找到 Django 安装路径后，打开`django/contrib/admin/templates/`，您将找到管理应用程序使用的模板。

此目录中有许多文件，但最重要的文件是这些：

+   `admin/base_site.html`：这是管理的基本模板。此模板生成界面。所有页面都继承自以下模板。

+   `admin/change_list.html`：此模板生成可用对象的列表。

+   `admin/change_form.html`：此模板生成用于添加或编辑对象的表单。

+   `admin/delete_confirmation.html`：此模板在删除对象时生成确认页面。

让我们尝试自定义其中一个模板。假设我们想要更改所有管理页面顶部的字符串**Django administration**。为此，在我们项目的`templates`文件夹内创建一个名为`admin`的文件夹，并将`admin/base_site.html`文件复制到其中。然后，编辑文件以将所有`Django`的实例更改为`Django Tweet`：

```py
  {% extends "admin/base.html" %}
  {% load i18n %}
  {% block title %}{{ title|escape }} |
  {% trans 'Django Tweet site admin' %}{% endblock %}
  {% block branding %}
  <h1 id="site-name">{% trans 'Django Tweet administration' %}</h1>
  {% endblock %}
  {% block nav-global %}{% endblock %}
```

结果将如下所示：

![覆盖管理模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00309.jpeg)

由于管理模板的模块化设计，通常不需要也不建议替换整个模板。通常最好只覆盖您需要更改的模板部分。

这个过程非常简单，不是吗？随意尝试其他模板。例如，您可能想要向列表或编辑页面添加帮助消息。

管理模板利用了 Django 模板系统的许多高级功能，因此如果您看到一个您不熟悉的模板标签，可以参考 Django 文档。

# 用户、组和权限

到目前为止，我们一直使用`manage.py syncdb`命令创建的超级用户帐户登录到管理界面。但实际上，您可能有其他受信任的用户需要访问管理页面。在本节中，我们将看到如何允许其他用户使用管理界面，并在此过程中了解更多关于 Django 权限系统的信息。

但在我们继续之前，我想强调一点：只有受信任的用户应该被授予对管理页面的访问权限。管理界面是一个非常强大的工具，所以只有你熟悉的人才应该被授予访问权限。

## 用户权限

如果数据库中除了超级用户之外没有其他用户，请使用我们在第七章中构建的注册表单创建一个新用户帐户，*关注和评论*。或者，您可以通过单击**用户**，然后单击**添加用户**来使用管理界面本身。

接下来，返回用户列表，然后单击新创建的用户的名称。您将获得一个表单，可用于编辑用户帐户的各个方面，例如姓名和电子邮件信息。在编辑表单的**权限**部分下，您将找到一个名为**员工状态**的复选框。启用此复选框将允许新用户进入管理界面。但是，他们登录后将无法做太多事情，因为此复选框仅授予对管理区域的访问权限；它不会赋予查看或更改数据的能力。

为了给新用户足够的权限来更改数据模型，您可以启用**超级用户状态**复选框，这将授予新用户执行任何所需功能的完全权限。此选项使帐户与`manage.py syncdb`命令创建的超级用户帐户一样强大。

然而，总的来说，不希望将用户对所有内容都授予完全访问权限。因此，Django 允许您通过权限系统对用户的操作进行精细控制。在**超级用户状态**复选框下方，您将找到可以授予用户的权限列表。如果您查看此列表，您将发现每个数据模型都有三种类型的权限：

+   向数据模型添加对象

+   更改数据模型中的对象

+   从数据模型中删除对象

这些权限是由 Django 自动生成的，用于包含 Admin 类的数据模型。使用箭头按钮向我们正在编辑的帐户授予一些权限。例如，给予帐户添加、编辑和删除推文和主题标签的能力。接下来，注销然后使用新帐户再次登录到管理界面。您会注意到您只能管理推文和主题标签数据模型。

用户编辑页面的权限部分还包含一个名为**活跃**的复选框。此复选框可用作全局开关，用于启用或禁用帐户。取消选中时，用户将无法登录到主站点或管理区域。

## 组权限

如果您有大量共享相同权限的用户，编辑每个用户帐户并为他们分配相同权限将是一项繁琐且容易出错的任务。因此，Django 提供了另一个用户管理设施：组。简单来说，组是对共享相同权限的用户进行分类的一种方式。您可以创建一个组并为其分配权限。当您将用户添加到组时，该用户将被授予组的所有权限。

创建组与创建其他数据模型并没有太大的不同。在管理界面的主页上点击**组**，然后点击**添加组**。接下来，输入组名并为组分配一些权限；最后，点击**保存**。

要将用户添加到组中，请编辑用户帐户，滚动到编辑表单中的**组**部分，然后选择要将用户添加到的任何组。

## 在视图中使用权限

尽管到目前为止我们只在管理界面中使用了权限，但 Django 还允许我们在编写视图时利用权限系统。在编写视图时，可以使用权限来授予一组用户对特定功能或页面的访问权限，例如私人内容。我们将在本节中了解可以用来实现此目的的方法。我们不会实际更改应用程序的代码，但如果您想尝试解释的方法，请随意这样做。

如果您想要检查用户是否具有特定权限，可以在`User`对象上使用`has_perm()`方法。该方法采用表示权限的字符串，格式如下：

```py
app.operation_model
```

`app`参数指定了模型所在的应用程序的名称；`operation`参数可以是`add`、`change`或`delete`；`model`参数指定了模型的名称。

例如，要检查用户是否可以添加推文，使用以下代码：

```py
  user.has_perm('tweets.add_tweet')
```

要检查用户是否可以更改推文，使用以下代码：

```py
  user.has_perm('tweets.change_tweet')
```

此外，Django 提供了一个名为`decorator`的函数，可以用来限制只有特定权限的用户才能访问视图。这个装饰器叫做`permission_required`，位于`django.contrib.auth.decorators`包中。

使用这个装饰器类似于我们使用`login_required`函数的方式。这个装饰器函数是为了限制页面只对已登录用户开放。假设我们想要将`tweet_save_page`视图（在`tweets/views.py`文件中）限制为具有`tweet.add_tweet`权限的用户。为此，我们可以使用以下代码：

```py
from django.contrib.auth.decorators import permission_required
@permission_required('tweets.add_tweet', login_url="/login/")
def tweet_save_page(request):
  # [...]
```

这个装饰器接受两个参数：要检查的权限以及如果用户没有所需权限时要重定向用户的位置。

使用`has_perm`方法还是`permission_required`装饰器取决于您想要的控制级别。如果您需要控制对整个视图的访问权限，请使用`permission_required`装饰器。但是，如果您需要对视图内的权限进行更精细的控制，请使用`has_perm`方法。这两种方法应该足够满足任何权限相关的需求。

# 将内容组织成页面 - 分页

在之前的章节中，我们已经涵盖了列出用户的推文和列出最多关注的用户等内容，但是考虑到当这些小数字扩大并且我们开始获得大量结果时的使用情况。为了应对这种情况，我们应该调整我们的代码以支持分页。

页面的大小会增加，而在页面中找到项目将变得困难。幸运的是，这有一个简单直观的解决方案：分页。**分页**是将内容分成页面的过程。而且，正如以往一样，Django 已经有一个实现这个功能的组件，可以供我们使用！

如果我们有一大堆推文，我们将这些推文分成每页十个（左右）项目的页面，并向用户呈现第一页，并提供链接以浏览其他页面。

Django 分页功能封装在一个名为`Paginator`的类中，该类位于`django.core.paginator`包中。让我们使用交互式控制台来学习这个类的接口：

```py
  from tweet.models import *
  from django.core.paginator import Paginator
  query_set = Tweet.objects.all()
  paginator = Paginator(query_set, 10)
```

### 注意

使用`python manage.py shell`命令打开 Django shell。

在这里，我们导入一些类，构建一个包含所有书签的查询集，并实例化一个名为`Paginator`的对象。这个类的构造函数接受要分页的查询集，以及每页的项目数。

让我们看看如何从`Paginator`对象中检索信息（当然，结果会根据您拥有的书签数量而有所不同）：

```py
>>> paginator.num_pages # Number of pages
1
>>> paginator.count # Total number of items
5
# Items in first page (index is zero-based)
>>> paginator.object_list
[<Tweet: #django is awesome.>, <Tweet: I love Django too.>, <Tweet: Django makes my day.>, <Tweet: #Django is fun.>, <Tweet: #Django is fun.>]

# Does the first page have a previous page?
>>> page1 = paginator.page(1)
# Stores the first page object to page1
>>> page1.has_previous()
False
# Does the first page have a next page?
>>> page1.has_next()
True

```

正如您所看到的，`Paginator`为我们做了大部分的工作。它接受一个查询集，将其分成页面，并使我们能够将查询集呈现为多个页面。

让我们将分页功能实现到我们的一个视图中，例如推文页面。打开`tweet/views.py`并修改`user_page`视图如下：

我们有我们的用户个人资料页面列表，其中包含以下类：

```py
  class Profile(LoginRequiredMixin, View):
    """User Profile page reachable from /user/<username> URL"""
    def get(self, request, username):
      params = dict()
      userProfile = User.objects.get(username=username)
      userFollower = UserFollower.objects.get(user=userProfile)
      if userFollower.followers.filter(username=request.user.username).exists():
        params["following"] = True
      else:
        params["following"] = False
        form = TweetForm(initial={'country': 'Global'})
        search_form = SearchForm()
        tweets = Tweet.objects.filter(user=userProfile).order_by('-created_date')
        params["tweets"] = tweets
        params["profile"] = userProfile
        params["form"] = form
        params["search"] = search_form
        return render(request, 'profile.html', params)
```

我们需要修改前面的代码以使用分页：

```py
  class Profile(LoginRequiredMixin, View):
    """User Profile page reachable from /user/<username> URL"""
    def get(self, request, username):
      params = dict()
      userProfile = User.objects.get(username=username)
      userFollower = UserFollower.objects.get(user=userProfile)
      if userFollower.followers.filter(username=request.user.username).exists():
        params["following"] = True
      else:
        params["following"] = False
        form = TweetForm(initial={'country': 'Global'})
        search_form = SearchForm()
        tweets = Tweet.objects.filter(user=userProfile).order_by('-created_date')
        paginator = Paginator(tweets, TWEET_PER_PAGE)
        page = request.GET.get('page')
      try:
        tweets = paginator.page(page)
        except PageNotAnInteger:
          # If page is not an integer, deliver first page.
          tweets = paginator.page(1)
      except EmptyPage:
        # If page is out of range (e.g. 9999), deliver last page of results.
        tweets = paginator.page(paginator.num_pages)
        params["tweets"] = tweets
        params["profile"] = userProfile
        params["form"] = form
        params["search"] = search_form
        return render(request, 'profile.html', params)
```

以下代码片段主要在前面的代码中实现了分页的魔法：

```py
        tweets = Tweet.objects.filter(user=userProfile).order_by('-created_date')
        paginator = Paginator(tweets, TWEET_PER_PAGE)
        page = request.GET.get('page')
        try:
          tweets = paginator.page(page)
        except PageNotAnInteger:
          # If page is not an integer, deliver first page.
          tweets = paginator.page(1)
        except EmptyPage:
          # If page is out of range (e.g. 9999), deliver last page of results.
          tweets = paginator.page(paginator.num_pages)
```

为了使这段代码工作，需要在`settings.py`文件中添加`TWEET_PER_PAGE = 5`参数，并在前面的代码中，只需在代码顶部添加`import settings.py`语句。

我们从请求中读取了一个名为`page`的`get`变量，告诉 Django 请求了哪个页面。我们还在`settings.py`文件中设置了`TWEET_PER_PAGE`参数，以显示单个页面上的推文数量。对于这种特定情况，我们选择了`5`。

`paginator = Paginator(tweets, TWEET_PER_PAGE)`方法创建一个分页对象，其中包含有关查询的所有信息。

现在，只需使用 URL `user/<username>/?page=<page_numer>`，页面将如下截图所示。第一张图片显示了带有 URL 中页面编号的用户推文。

![将内容组织成页面-分页](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00310.jpeg)

以下截图显示了用户主页上的推文列表：

![将内容组织成页面-分页](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00311.jpeg)

# 总结

尽管本章相对较短，但我们学会了如何实现许多事情。这强调了 Django 让您只需几行代码就能做很多事情的事实。您学会了如何利用 Django 强大的管理界面，如何自定义它，以及如何利用 Django 提供的全面权限系统。

在下一章中，您将了解到几乎每个 Web 2.0 应用程序中都有的一些令人兴奋的功能。


# 第九章：扩展和部署

在本章中，我们将通过利用各种 Django 框架功能来准备我们的应用程序以在生产中部署。我们将添加对多种语言的支持，通过缓存和自动化测试来提高性能，并为生产环境配置项目。本章中有很多有趣和有用的信息，因此在将应用程序发布到网上之前，请确保您仔细阅读！

在本章中，您将学习以下主题：

+   向朋友发送邀请电子邮件

+   国际化（i18n）-提供多种语言的站点

+   缓存-在高流量期间提高站点性能

+   单元测试-自动化测试应用程序的过程

# 向朋友发送邀请电子邮件

使我们的用户邀请他们的朋友具有许多好处。如果他们的朋友已经使用我们的网站，那么他们更有可能加入我们的网站。加入后，他们还会邀请他们的朋友，依此类推，这意味着我们的应用程序会有越来越多的用户。因此，在我们的应用程序中包含“邀请朋友”的功能是一个好主意。

构建此功能需要以下组件：

+   一个邀请数据模型，用于在数据库中存储邀请

+   用户可以在其中输入他们朋友的电子邮件 ID 并发送邀请的表单

+   带有激活链接的邀请电子邮件

+   处理电子邮件中发送的激活链接的机制

在本节中，我们将实现这些组件中的每一个。但是，因为本节涉及发送电子邮件，我们首先需要通过向`settings.py`文件添加一些选项来配置 Django 发送电子邮件。因此，打开`settings.py`文件并添加以下行：

```py
  SITE_HOST = '127.0.0.1:8000'
  DEFAULT_FROM_EMAIL = 'MyTwitter <noreply@mytwitter.com>'
  EMAIL_HOST = 'mail.yourisp.com'
  EMAIL_PORT = ''
  EMAIL_HOST_USER = 'username+mail.yourisp.com'
  EMAIL_HOST_PASSWORD = ''
```

让我们看看前面代码中的每个变量都做了什么：

+   `SITE_HOST`：这是您服务器的主机名。现在将其保留为`127.0.0.1:8000`。在下一章中部署服务器时，我们将更改此设置。

+   `DEFAULT_FROM_EMAIL`：这是出站电子邮件服务器**From**字段中显示的电子邮件地址。对于主机用户名，请输入您的用户名加上您的电子邮件服务器，如前面的代码片段所示。如果您的 ISP 不需要这些字段，请将其留空。

+   `EMAIL_HOST`：这是您的电子邮件服务器的主机名。

+   `EMAIL_PORT`：这是出站电子邮件服务器的端口号。如果将其留空，则将使用默认值（25）。您还需要从 ISP 那里获取此信息。

+   `EMAIL_HOST_USER`和`EMAIL_HOST_PASSWORD`：这是 Django 发送的电子邮件的用户名和密码。

如果您的开发计算机没有运行邮件服务器，很可能是这种情况，那么您需要输入 ISP 的出站电子邮件服务器。联系您的 ISP 以获取更多信息。

要验证您的设置是否正确，请启动交互式 shell 并输入以下内容：

```py
>>> from django.core.mail import EmailMessage
>>> email = EmailMessage('Hello', 'World', to=['your_email@example.com'])
>>> email.send()

```

将`your_email@example.com`参数替换为您的实际电子邮件地址。如果前面的发送邮件调用没有引发异常并且您收到了邮件，那么一切都设置好了。否则，您需要与 ISP 验证您的设置并重试。

但是，如果您没有从 ISP 那里获得任何信息怎么办？然后我们尝试另一种方式：使用 Gmail 发送邮件（当然，不是作为`noreply@mytweet.com`，而是从您的真实电子邮件 ID）。让我们看看您需要对`MyTweeets`项目的`settings.py`文件进行哪些更改。

完全删除以前的`settings.py`文件条目，并添加以下内容：

```py
  EMAIL_USE_TLS = True
  EMAIL_HOST = 'smtp.gmail.com'
  EMAIL_HOST_USER = 'your-gmail-email-id'
  EMAIL_HOST_PASSWORD = 'your-gmail-application-password'
  EMAIL_PORT = 587
  SITE_HOST = '127.0.0.1:8000'
```

如果您遇到错误，例如：

```py
 (534, '5.7.9 Application-specific password required. Learn more at\n5.7.9 http://support.google.com/accounts/bin/answer.py?answer=185833 zr2sm8629305pbb.83 - gsmtp')

```

这意味着`EMAIL_HOST_PASSWORD`参数需要一个应用程序授权密码，而不是您的电子邮件密码。请按照主机部分中提到的链接获取有关如何创建的更多详细信息。

设置好这些东西后，尝试使用以下命令从 shell 再次发送邮件：

```py
>>> from django.core.mail import EmailMessage
>>> email = EmailMessage('Hello', 'World', to=['your_email@example.com'])
>>> email.send()

```

在这里，`your_email@example.com`参数是您想发送邮件的任何电子邮件地址。邮件的发件人地址将是我们传递给以下变量的 Gmail 电子邮件地址：

```py
 EMAIL_HOST_USER = 'your-gmail-email-id'

```

现在，一旦设置正确，使用 Django 发送邮件就像小菜一碟！我们将使用`EmailMessage`函数发送邀请邮件，但首先，让我们创建一个数据模型来存储邀请。

## 邀请数据模型

邀请包括以下信息：

+   收件人姓名

+   收件人邮箱

+   发件人的用户对象

我们还需要为邀请存储一个激活码。该代码将在邀请邮件中发送。该代码将有两个目的：

+   在接受邀请之前，我们可以使用该代码验证邀请是否实际存在于数据库中

+   接受邀请后，我们可以使用该代码从数据库中检索邀请信息，并跟踪发件人和收件人之间的关系

考虑到上述信息，让我们创建邀请数据模型。打开`user_profile/models.py`文件，并将以下代码追加到其中：

```py
  class Invitation(models.Model):
    name = models.CharField(maxlength=50)
    email = models.EmailField()
    code = models.CharField(maxlength=20)
    sender = models.ForeignKey(User)
    def __unicode__(self):
        return u'%s, %s' % (self.sender.username, self.email)
```

在这个模型中没有什么新的或难以理解的。我们只是为收件人姓名、收件人电子邮件、激活码和邀请发件人定义了字段。我们还为调试创建了一个`__unicode__`方法，并在管理界面中启用了该模型。不要忘记运行`python manage.py syncdb`命令来在数据库中创建新模型的表。

我们还将为此创建邀请表单。在`user_profile`目录中创建一个名为`forms.py`的文件，并使用以下代码进行更新：

```py
from django import forms

class InvitationForm(forms.Form):
  email = forms.CharField(widget=forms.TextInput(attrs={'size': 32, 'placeholder': 'Email Address of Friend to invite.', 'class':'form-control search-query'}))
```

创建发送邀请的视图页面类似于创建我们为搜索和推文表单创建的其他页面，通过创建一个名为`template/invite.html`的新文件：

```py
  {% extends "base.html" %}
  {% load staticfiles %}
  {% block content %}
  <div class="row clearfix">
    <div class="col-md-6 col-md-offset-3 column">
      {% if success == "1" %}
        <div class="alert alert-success" role="alert">Invitation Email was successfully sent to {{ email }}</div>
      {% endif %}
      {% if success == "0" %}
        <div class="alert alert-danger" role="alert">Failed to send Invitation Email to {{ email }}</div>
      {% endif %}
      <form id="search-form" action="" method="post">{% csrf_token %}
        <div class="input-group input-group-sm">
        {{ invite.email.errors }}
        {{ invite.email }}
          <span class="input-group-btn">
            <button class="btn btn-search" type="submit">Invite</button>
          </span>
        </div>
      </form>
    </div>
  </div>
  {% endblock %}
```

此方法的 URL 输入如下：

```py
  url(r'^invite/$', Invite.as_view()),
```

现在，我们需要创建`get`和`post`方法来使用此表单发送邀请邮件。

由于发送邮件比推文更具体于用户，我们将在`user_profile`视图中创建此方法，而不是之前使用的推文视图。

使用以下代码更新`user_profile/views.py`文件：

```py
from django.views.generic import View
from django.conf import settings
from django.shortcuts import render
from django.template import Context
from django.template.loader import render_to_string
from user_profile.forms import InvitationForm
from django.core.mail import EmailMultiAlternatives
from user_profile.models import Invitation, User
from django.http import HttpResponseRedirect
import hashlib

class Invite(View):
  def get(self, request):
    params = dict()
    success = request.GET.get('success')
    email = request.GET.get('email')
    invite = InvitationForm()
    params["invite"] = invite
    params["success"] = success
    params["email"] = email
    return render(request, 'invite.html', params)

  def post(self, request):
    form = InvitationForm(self.request.POST)
    if form.is_valid():
      email = form.cleaned_data['email']
      subject = 'Invitation to join MyTweet App'
      sender_name = request.user.username
      sender_email = request.user.email
      invite_code = Invite.generate_invite_code(email)
      link = 'http://%s/invite/accept/%s/' % (settings.SITE_HOST, invite_code)
      context = Context({"sender_name": sender_name, "sender_email": sender_email, "email": email, "link": link})
      invite_email_template = render_to_string('partials/_invite_email_template.html', context)
      msg = EmailMultiAlternatives(subject, invite_email_template, settings.EMAIL_HOST_USER, [email], cc=[settings.EMAIL_HOST_USER])
      user = User.objects.get(username=request.user.username)
      invitation = Invitation()
      invitation.email = email
      invitation.code = invite_code
      invitation.sender = user
      invitation.save()
      success = msg.send()
      return HttpResponseRedirect('/invite?success='+str(success)+'&email='+email)

  @staticmethod
  def generate_invite_code(email):
    secret = settings.SECRET_KEY
    if isinstance(email, unicode):
      email = email.encode('utf-8')
      activation_key = hashlib.sha1(secret+email).hexdigest()
      return activation_key
```

在这里，`get()`方法就像使用`invite.html`文件渲染邀请表单一样简单，并且初始未设置`success`和`email`变量。

`post()`方法使用通常的表单检查和变量提取概念；您将首次看到的代码如下：

```py
  invite_code = Invite.generate_invite_code(email)
```

这实际上是一个静态函数调用，为每个受邀用户生成具有唯一密钥的激活令牌。当您加载名为`_invite_email_template.html`的模板并将以下变量传递给它时，`render_to_string()`方法将起作用：

+   `sender_name`：这是邀请或发件人的姓名

+   `sender_email`：这是发件人的电子邮件地址

+   `email`：这是被邀请人的电子邮件地址

+   `link`：这是邀请接受链接

然后使用该模板来渲染邀请邮件的正文。之后，我们使用`EmailMultiAlternatives()`方法发送邮件，就像我们在上一节的交互式会话中所做的那样。

这里有几点需要注意：

+   激活链接的格式为`http://SITE_HOST/invite/accept/CODE/`。我们将在本节后面编写一个视图来处理此类 URL。

+   这是我们第一次使用模板来渲染除网页以外的其他内容。正如您所见，模板系统非常灵活，允许我们构建电子邮件，以及网页或任何其他文本。

+   我们使用`render_to_string()`和`render()`方法构建消息正文，而不是通常的`render_to_response`调用。如果你还记得，这就是我们在本书早期渲染模板的方式。我们这样做是因为我们不是在渲染网页。

由于`send`方法加载名为`_invite_email_template.html`的模板，请在模板文件夹中创建一个同名文件并插入以下内容：

```py
  Hi,
    {{ sender_name }}({{ sender_email }}) has invited you to join Mytweet.
    Please click {{ link }} to join.
This email was sent to {{ email }}. If you think this is a mistake Please ignore.
```

我们已经完成了“邀请朋友”功能的一半实现。目前，点击激活链接会产生 404 页面未找到错误，因此，接下来，我们将编写一个视图来处理它。

## 处理激活链接

我们取得了良好的进展；用户现在能够通过电子邮件邀请他们的朋友。下一步是构建一个处理邀请中激活链接的机制。以下是我们将要做的概述。

我们将构建一个视图来处理激活链接。此视图验证邀请码实际上是否存在于数据库中，并且注册的用户自动关注发送链接的用户并被重定向到注册页面。

让我们从为视图编写 URL 条目开始。打开`urls.py`文件并添加以下突出显示的行：

```py
 url(r'^invite/accept/(\w+)/$', InviteAccept.as_view()),

```

在`user_profile/view.py`文件中创建一个名为`InviteAccept()`的类。

从逻辑上讲，邀请接受将起作用，因为用户将被要求注册应用程序，如果他们已经注册，他们将被要求关注邀请他们的用户。

为了简单起见，我们将用户重定向到带有激活码的注册页面，这样当他们注册时，他们将自动成为关注者。让我们看一下以下代码：

```py
class InviteAccept(View):
  def get(self, request, code):
    return HttpResponseRedirect('/register?code='+code)
```

然后，我们将用以下代码编写注册页面：

```py
class Register(View):
  def get(self, request):
    params = dict()
    registration_form = RegisterForm()
    code = request.GET.get('code')
    params['code'] = code
    params['register'] = registration_form
    return render(request, 'registration/register.html', params)

  def post(self, request):
    form = RegisterForm(request.POST)
    if form.is_valid():
      username = form.cleaned_data['username']
      email = form.cleaned_data['email']
      password = form.cleaned_data['password']
      try:
        user = User.objects.get(username=username)                
      except:
        user = User()
        user.username = username
        user.email = email
        commit = True
        user = super(user, self).save(commit=False)
        user.set_password(password)
        if commit:
          user.save()
        return HttpResponseRedirect('/login')
```

如你所见，视图遵循邀请电子邮件中发送的 URL 格式。激活码是使用正则表达式从 URL 中捕获的，然后作为参数传递给视图。

这有点耗时，但我们能够充分利用我们的 Django 知识来实现它。您现在可以点击通过电子邮件收到的邀请链接，看看会发生什么。您将被重定向到注册页面；您可以在那里创建一个新账户，登录，并注意新账户和您的原始账户如何成为发送者的关注者。

# 国际化（i18n）-提供多种语言的网站

如果人们无法阅读我们应用的页面，他们就不会使用我们的应用。到目前为止，我们只关注说英语的用户。然而，全世界有许多人不懂英语或更喜欢使用他们的母语。为了吸引这些人，将我们应用的界面提供多种语言是个好主意。这将克服语言障碍，并为我们的应用打开新的前沿，特别是在英语不常用的地区。

正如你可能已经猜到的那样，Django 提供了将项目翻译成多种语言所需的所有组件。负责提供此功能的系统称为**国际化系统**（**i18n**）。翻译 Django 项目的过程非常简单。

按照以下三个步骤进行：

1.  指定应用程序中应翻译的字符串，例如，状态和错误消息是可翻译的，而用户名则不是。

1.  为要支持的每种语言创建一个翻译文件。

1.  启用和配置 i18n 系统。

我们将在以下各小节中详细介绍每个步骤。在本章节的最后，我们的应用将支持多种语言，您将能够轻松翻译任何其他 Django 项目。

## 将字符串标记为可翻译的

翻译应用程序的第一步是告诉 Django 哪些字符串应该被翻译。一般来说，视图和模板中的字符串需要被翻译，而用户输入的字符串则不需要。将字符串标记为可翻译是通过函数调用完成的。函数的名称以及调用方式取决于字符串的位置：在视图、模板、模型或表单中。

这一步比起一开始看起来要容易得多。让我们通过一个例子来了解它。我们将翻译应用程序中的“邀请关注者”功能。翻译应用程序的其余部分的过程将完全相同。打开`user_profile/views.py`文件，并对邀请视图进行突出显示的更改：

```py
from django.utils.translation import ugettext as _
from django.views.generic import View
from django.conf import settings
from django.shortcuts import render
from django.template import Context
from django.template.loader import render_to_string
from user_profile.forms import InvitationForm
from django.core.mail import EmailMultiAlternatives
from user_profile.models import Invitation, User
from django.http import HttpResponseRedirect
import hashlib

class Invite(View):
  def get(self, request):
    params = dict()
    success = request.GET.get('success')
    email = request.GET.get('email')
    invite = InvitationForm()
    params["invite"] = invite
    params["success"] = success
    params["email"] = email
    return render(request, 'invite.html', params)

  def post(self, request):
    form = InvitationForm(self.request.POST)
    if form.is_valid():
      email = form.cleaned_data['email']
      subject = _('Invitation to join MyTweet App')
      sender_name = request.user.username
      sender_email = request.user.email
      invite_code = Invite.generate_invite_code(email)
      link = 'http://%s/invite/accept/%s/' % (settings.SITE_HOST, invite_code)
      context = Context({"sender_name": sender_name, "sender_email": sender_email, "email": email, "link": link})
      invite_email_template = render_to_string('partials/_invite_email_template.html', context)
      msg = EmailMultiAlternatives(subject, invite_email_template, settings.EMAIL_HOST_USER, [email], cc=[settings.EMAIL_HOST_USER])
      user = User.objects.get(username=request.user.username)
      invitation = Invitation()
      invitation.email = email
      invitation.code = invite_code
      invitation.sender = user
      invitation.save()
      success = msg.send()
    return HttpResponseRedirect('/invite?success='+str(success)+'&email='+email)

  @staticmethod
  def generate_invite_code(email):
    secret = settings.SECRET_KEY
    if isinstance(email, unicode):
      email = email.encode('utf-8')
      activation_key = hashlib.sha1(secret+email).hexdigest()
    return activation_key
```

请注意，主题字符串以“`_`”开头；或者，您也可以这样写：

```py
from django.utils.translation import ugettext
  subject = ugettext('Invitation to join MyTweet App')
```

无论哪种方式，它都运行良好。

正如您所看到的，更改是微不足道的：

+   我们从`django.utils.translation`中导入了一个名为`ugettext`的函数。

+   我们使用了`as`关键字为函数（下划线字符）分配了一个更短的名称。我们这样做是因为这个函数将用于在视图中标记字符串为可翻译的，而且由于这是一个非常常见的任务，给函数一个更短的名称是个好主意。

+   我们只需将一个字符串传递给`_`函数即可将其标记为可翻译。

这很简单，不是吗？然而，这里有一个小观察需要做。第一条消息使用了字符串格式化，并且在调用`_()`函数后应用了`%`运算符。这是为了避免翻译电子邮件地址。最好使用命名格式，这样在实际翻译时可以更好地控制。因此，您可能想要定义以下代码：

```py
message= \
_('An invitation was sent to %(email)s.') % {
'email': invitation.email}
```

既然我们知道如何在视图中标记字符串为可翻译的，让我们转到模板。在模板文件夹中打开`invite.html`文件，并修改如下：

```py
{% extends "base.html" %}
{% load staticfiles %}
{% load i18n %}
{% block content %}
<div class="row clearfix">
  <div class="col-md-6 col-md-offset-3 column">
    {% if success == "1" %}
    <div class="alert alert-success" role="alert">
      {% trans Invitation Email was successfully sent to  %}{{ email }}
    </div>
    {% endif %}
    {% if success == "0" %}
    <div class="alert alert-danger" role="alert">Failed to send Invitation Email to {{ email }}</div>
    {% endif %}
      <form id="search-form" action="" method="post">{% csrf_token %}
        <div class="input-group input-group-sm">
        {{ invite.email.errors }}
        {{ invite.email }}
          <span class="input-group-btn">
            <button class="btn btn-search" type="submit">Invite</button>
          </span>
        </div>
      </form>
    </div>
  </div>
  {% endblock %}
```

在这里，我们在模板的开头放置了`{% load i18n %}`参数，以便让它可以访问翻译标签。`<load>`标签通常用于启用默认情况下不可用的额外模板标签。您需要在使用翻译标签的每个模板的顶部放置它。i18n 是国际化的缩写，这是 Django 框架的名称，它提供了翻译功能。

接下来，我们使用了一个名为`trans`的模板标签来标记字符串为可翻译的。这个模板标签与视图中的`gettext`函数完全相同。值得注意的是，如果字符串包含模板变量，`trans`标签将不起作用。在这种情况下，您需要使用`blocktrans`标签，如下所示：

```py
{% blocktrans %} 
```

您可以在`{% endblocktrans %}`块中传递一个变量块，即`{{ variable }}`，以使其对读者更有意义。

现在您知道如何在模板中处理可翻译的字符串了。那么，让我们转到表单和模型。在表单或模型中标记字符串为可翻译与在视图中略有不同。要了解如何完成这一点，请打开`user_profile/forms.py`文件，并修改邀请表单如下：

```py
from django.utils.translation import gettext_lazy as _
class InvitationForm(forms.Form):
  email = forms.CharField(widget=forms.TextInput(attrs={'size': 32, 'placeholder': _('Email Address of Friend to invite.'), 'class':'form-control'}))
```

唯一的区别是我们导入了`gettext_lazy`函数而不是`gettext`。`gettext_lazy`会延迟直到访问其返回值时才翻译字符串。这在这里是必要的，因为表单的属性只在应用程序启动时创建一次。如果我们使用普通的`gettext`函数，翻译后的标签将以默认语言（通常是英语）存储在表单属性中，并且永远不会再次翻译。但是，如果我们使用`gettext_lazy`函数，该函数将返回一个特殊对象，每次访问时都会翻译字符串，因此翻译将正确进行。这使得`gettext_lazy`函数非常适合表单和模型属性。

有了这个，我们完成了为“邀请朋友”视图标记字符串以进行翻译。为了帮助您记住本小节涵盖的内容，这里是标记可翻译字符串所使用的技术的快速总结：

+   在视图中，使用`gettext`函数标记可翻译的字符串（通常导入为`_`）

+   在模板中，使用`trans`模板标记标记不包含变量的可翻译字符串，使用`blocktrans`标记标记包含变量的字符串。

+   在表单和模型中，使用`gettext_lazy`函数标记可翻译的字符串（通常导入为`_`）

当然，也有一些特殊情况可能需要单独处理。例如，您可能希望使用`gettext_lazy`函数而不是`gettext`函数来翻译视图中的默认参数值。只要您理解这两个函数之间的区别，您就应该能够决定何时需要这样做。

## 创建翻译文件

现在我们已经完成了标记要翻译的字符串，下一步是为我们想要支持的每种语言创建一个翻译文件。这个文件包含所有可翻译的字符串及其翻译，并使用 Django 提供的实用程序创建。

让我们创建一个翻译文件。首先，您需要在 Django 安装文件夹内的`bin`目录中找到一个名为`make-messages.py`的文件。找到它的最简单方法是使用操作系统中的搜索功能。找到它后，将其复制到系统路径（在 Linux 和 Mac OS X 中为`/usr/bin/`，在 Windows 中为`c:\windows\`）。

此外，确保在 Linux 和 Mac OS X 中运行以下命令使其可执行（对 Windows 用户来说，这一步是不需要的）：

```py
$ sudo chmod +x /usr/bin/make-messages.py

```

`make-messages.py`实用程序使用一个名为 GNU gettext 的软件包从源代码中提取可翻译的字符串。因此，您需要安装这个软件包。对于 Linux，搜索您的软件包管理器中的软件包并安装它。Windows 用户可以在[`gnuwin32.sourceforge.net/packages/gettext.htm`](http://gnuwin32.sourceforge.net/packages/gettext.htm)找到该软件包的安装程序。

最后，Mac OS X 用户将在[`gettext.darwinports.com/`](http://gettext.darwinports.com/)找到适用于其操作系统的软件包版本以及安装说明。

安装 GNU gettext 软件包后，打开终端，转到您的项目文件夹，在那里创建一个名为`locale`的文件夹，然后运行以下命令：

```py
$ make-messages.py -l de

```

这个命令为德语语言创建了一个翻译文件。`de`变量是德语的语言代码。如果您想要翻译其他语言，将其语言代码放在`de`的位置，并继续为本章的其余部分执行相同的操作。除此之外，如果您想要支持多种语言，为每种语言运行上一个命令，并将说明应用到本节的所有语言。 

一旦您运行了上述命令，它将在`locale/de/LC_MESSAGES/`下创建一个名为`django.po`的文件。这是德语语言的翻译文件。在文本编辑器中打开它，看看它是什么样子的。文件以一些元数据开头，比如创建日期和字符集。之后，您会发现每个可翻译字符串的条目。每个条目包括字符串的文件名和行号，字符串本身，以及下面的空字符串，用于放置翻译。以下是文件中的一个示例条目：

```py
#: user_profile/forms.py
msgid "Friend's Name"
msgstr ""
```

要翻译字符串，只需使用文本编辑器在第三行的空字符串中输入翻译。您也可以使用专门的翻译编辑器，比如`Poedit`（在[`www.poedit.net/`](http://www.poedit.net/)上提供所有主要操作系统的版本），但对于我们的简单文件，普通文本编辑器就足够了。确保在文件的元数据部分设置一个有效的字符。我建议您使用**UTF-8**：

```py
"Content-Type: text/plain; charset=UTF-8\n"
```

您可能会注意到翻译文件包含一些来自管理界面的字符串。这是因为`admin/base_site.html`管理模板使用`trans`模板标记将其字符串标记为可翻译的。无需翻译这些字符串；Django 已经为它们提供了翻译文件。

翻译完成后，您需要将翻译文件编译为 Django 可以使用的格式。这是使用 Django 提供的另一个实用程序`compile-messages.py`命令完成的。找到并将此文件移动到系统路径，并确保它是可执行的，方法与我们使用`make-messages.py`命令相同。

接下来，在项目文件夹中运行以下命令：

```py
$ compile-messages.py

```

如果实用程序报告文件中的错误（例如缺少引号），请更正错误并重试。一旦成功，实用程序将在同一文件夹中创建一个名为`django.mo`的已编译翻译文件，并为本节的下一步做好一切准备。

## 启用和配置 i18n 系统

Django 默认启用了 i18n 系统。您可以通过在`settings.py`文件中搜索以下行来验证这一点：

```py
USE_I18N = True
```

有两种配置 i18n 系统的方法。您可以为所有用户全局设置语言，也可以让用户单独指定其首选语言。我们将在本小节中看到如何同时进行这两种配置。

要全局设置活动语言，请在`settings.py`文件中找到名为`LANGUAGE_CODE`的变量，并将您喜欢的语言代码分配给它。例如，如果您想将德语设置为项目的默认语言，请将语言代码更改如下：

```py
LANGUAGE_CODE = 'de'
```

现在，如果开发服务器尚未运行，请启动它，并转到“邀请朋友”页面。在那里，您会发现字符串已根据您在德语翻译文件中输入的内容进行了更改。现在，将`LANGUAGE_CODE`变量的值更改为'`en`'，并注意页面如何恢复为英语。

第二种配置方法是让用户选择语言。为此，我们应该启用一个名为`LocaleMiddleware`的类。简而言之，中间件是处理请求或响应对象的类。Django 的许多组件都使用中间件类来实现功能。要查看这一点，请打开`settings.py`文件并搜索`MIDDLEWARE_CLASSES`变量。您会在那里找到一个字符串列表，其中一个是`django.contrib.sessions.middleware.SessionMiddleware`，它将会话数据附加到请求对象上。在使用中间件之前，我们不需要了解中间件类是如何实现的。要启用`LocaleMiddleware`，只需将其类路径添加到`MIDDLEWARE_CLASSES`列表中。确保将`LocaleMiddleware`放在`SessionMiddleware`之后，因为区域设置中间件利用会话 API，我们将在下面看到。打开`settings.py`文件并按照以下代码片段中的突出显示的内容修改文件：

```py
MIDDLEWARE_CLASSES = (
'django.middleware.common.CommonMiddleware',
'django.contrib.sessions.middleware.SessionMiddleware',
'django.contrib.auth.middleware.AuthenticationMiddleware',
'django.middleware.doc.XViewMiddleware',
'django.middleware.locale.LocaleMiddleware',
)

```

区域设置中间件通过以下步骤确定用户的活动语言：

1.  它在会话数据中查找名为`django_language`的键。

1.  如果键不存在，则查找名为`django_language`的 cookie。

1.  如果 cookie 不存在，则查看 Accept-Language HTTP 标头中的语言代码。此标头由浏览器发送到 Web 服务器，指示您希望以哪种语言接收内容。

1.  如果一切都失败了，将使用`settings.py`文件中的`LANGUAGE_CODE`变量。

在所有前面的步骤中，Django 会寻找与可用翻译文件匹配的语言代码。为了有效地利用区域设置中间件，我们需要一个视图，使用户能够选择语言并相应地更新会话数据。幸运的是，Django 已经为我们提供了这样的视图。该视图称为**setlanguage**，并且它期望在名为 language 的 GET 变量中包含语言代码。它使用此变量更新会话数据，并将用户重定向到原始页面。要启用此视图，请编辑`urls.py`文件，并向其中添加以下突出显示的行：

```py
urlpatterns = patterns('',
# i18n
(r'^i18n/', include('django.conf.urls.i18n')),
)
```

添加上述行类似于我们为管理界面添加 URL 条目的方式。如果您还记得之前的章节，`include()`函数可以用于在特定路径下包含来自另一个应用程序的 URL 条目。现在，我们可以通过提供链接（例如`/i18n/setlang/language=de`）让用户将语言更改为德语。我们将修改基本模板以在所有页面上添加此类链接。打开`templates/base.html`文件，并向其中添加以下突出显示的行：

```py
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    [...]
  </head>
  <body>
    [...]
    <div id="footer">
    Django Mytweets <br />
    Languages:
      <a href="/i18n/setlang/?language=en">en</a>
      <a href="/i18n/setlang/?language=de">de</a>
      [ 218 ]Chapter 11
    </div>
  </body>
</html>
```

此外，我们将通过将以下 CSS 代码附加到`site_media/style.css`文件来为新的页脚设置样式：

```py
#footer {
margin-top: 2em;
text-align: center;
}
```

现在，我们的应用程序的 i18n 功能已经准备就绪。将浏览器指向“邀请朋友”页面，并尝试页面底部的新语言链接。语言应该根据点击的链接而改变。

在我们结束本节之前，这里有一些观察结果：

+   您可以在视图中使用请求`LANGUAGE_CODE`属性访问当前活动的语言。

+   Django 本身被翻译成多种语言。您可以通过在激活英语以外的语言时触发表单错误来查看这一点。错误消息将以所选语言显示，即使您自己没有进行翻译。

+   在模板中，当使用`RequestContext`变量时，可以使用`LANGUAGE_CODE`模板变量访问当前活动的语言。

这一部分有点长，但您从中学到了一个非常重要的功能。通过以多种语言提供我们的应用程序，我们使其能够吸引更广泛的受众，从而具有吸引更多用户的潜力。这实际上适用于任何 Web 应用程序，现在，我们将能够轻松地将任何 Django 项目翻译成多种语言。

在下一节中，我们将转移到另一个主题。当您的应用程序用户基数增长时，服务器的负载将增加，您将开始寻找改进应用程序性能的方法。这就是缓存发挥作用的地方。

因此，请继续阅读以了解这个非常有用的技术！

# 缓存-在高流量期间提高站点性能

Web 应用程序的页面是动态生成的。每次请求页面时，都会执行代码来处理用户输入并生成输出。生成动态页面涉及许多开销，特别是与提供静态 HTML 文件相比。代码可能会连接到数据库，执行昂贵的计算，处理文件等等。同时，能够使用代码生成页面正是使网站动态和交互的原因。

如果我们能同时获得两全其美岂不是太好了？这就是缓存所做的，这是大多数中高流量网站上实现的功能。当请求页面时，缓存会存储页面的生成 HTML，并在以后再次请求相同页面时重用它。这样可以通过避免一遍又一遍地生成相同页面来减少很多开销。当然，缓存页面并不是永久存储的。当页面被缓存时，会为缓存设置一个过期时间。当缓存页面过期时，它会被删除，页面会被重新生成并缓存。过期时间通常在几秒到几分钟之间，取决于网站的流量。过期时间确保缓存定期更新，并且用户接收内容更新的同时，减少生成页面的开销。

尽管缓存对于中高流量网站特别有用，低流量网站也可以从中受益。如果网站突然接收到大量高流量，可能是因为它被主要新闻网站报道，您可以启用缓存以减少服务器负载，并帮助您的网站度过高流量的冲击。稍后，当流量平息时，您可以关闭缓存。因此，缓存对小型网站也很有用。您永远不知道何时会需要它，所以最好提前准备好这些信息。

## 启用缓存

我们将从启用缓存系统开始这一部分。要使用缓存，您首先需要选择一个缓存后端，并在 `settings.py` 文件中的一个名为 `CACHE_BACKEND` 的变量中指定您的选择。此变量的内容取决于您选择的缓存后端。一些可用的选项包括：

+   **简单缓存**：对于这种情况，缓存数据存储在进程内存中。这只对开发过程中测试缓存系统有用，不应在生产中使用。要启用它，请在 `settings.py` 文件中添加以下内容：

```py
CACHE_BACKEND = 'simple:///'
```

+   **数据库缓存**：对于这种情况，缓存数据存储在数据库表中。要创建缓存表，请运行以下命令：

```py
$ python manage.py createcachetable cache_table

```

然后，在 `settings.py` 文件中添加以下内容：

```py
CACHE_BACKEND = 'db://cache_table'
```

在这里，缓存表被称为 `cache_table`。只要不与现有表冲突，您可以随意命名它。

+   **文件系统缓存**：在这里，缓存数据存储在本地文件系统中。要使用它，请在 `settings.py` 文件中添加以下内容：

```py
CACHE_BACKEND = 'file:///tmp/django_cache'
```

在这里，`/tmp/django_cache` 变量用于存储缓存文件。如果需要，您可以指定另一个路径。

+   **Memcached**：Memcached 是一个先进、高效和快速的缓存框架。安装和配置它超出了本书的范围，但如果您已经有一个可用的 Memcached 服务器，可以在 `settings.py` 文件中指定其 IP 和端口，如下所示：

```py
CACHE_BACKEND = 'memcached://ip:port/'
```

如果您不确定在本节中选择哪个后端，请选择简单缓存。然而，实际上，如果您突然遇到高流量并希望提高服务器性能，可以选择 Memcached 或数据库缓存，具体取决于服务器上可用的选项。另一方面，如果您有一个中高流量的网站，我强烈建议您使用 Memcached，因为它绝对是 Django 可用的最快的缓存解决方案。本节中提供的信息无论您选择哪种缓存后端都是一样的。

因此，决定一个缓存后端，并在 `settings.py` 文件中插入相应的 `CACHE_BACKEND` 变量。接下来，您应该指定缓存页面的过期持续时间（以秒为单位）。在 `settings.py` 文件中添加以下内容，以便将页面缓存五分钟：

```py
CACHE_MIDDLEWARE_SECONDS = 60 * 5
```

现在，我们已经完成了启用缓存系统。继续阅读，了解如何利用缓存来提高应用程序的性能。

## 配置缓存

您可以配置 Django 缓存整个站点或特定视图。我们将在本小节中学习如何做到这两点。

### 缓存整个站点

要缓存整个网站，请将`CacheMiddleware`类添加到`settings.py`文件中的`MIDDLEWARE_CLASSES`类中：

```py
MIDDLEWARE_CLASSES = (
'django.middleware.common.CommonMiddleware',
'django.contrib.sessions.middleware.SessionMiddleware',
'django.contrib.auth.middleware.AuthenticationMiddleware',
'django.middleware.cache.CacheMiddleware',
'django.middleware.doc.XViewMiddleware',
'django.middleware.locale.LocaleMiddleware',
)

```

在这里顺序很重要，就像我们添加区域设置中间件时一样。缓存中间件类应该在会话和身份验证中间件类之后添加，在区域设置中间件类之前添加。

这就是您需要缓存 Django 网站的全部内容。从现在开始，每当请求页面时，Django 都会存储生成的 HTML 并在以后重复使用。重要的是要意识到，缓存系统只缓存没有`GET`和`POST`变量的页面。因此，我们的用户仍然可以发布推文和关注朋友，因为这些页面的视图期望 GET 或 POST 变量。另一方面，推文和标签列表等页面将被缓存。

### 缓存特定视图

有时，您可能只想缓存网站的特定页面-可能是一个与您的页面链接的高流量网站，因此大部分流量将被引导到这个特定页面。在这种情况下，只缓存此页面是有意义的。另一个适合缓存的好候选者是生成成本高昂的页面，因此您只希望每五分钟生成一次。我们应用程序中的标签云页面符合后一种情况。每次请求页面时，Django 都会遍历数据库中的所有标签，并计算每个标签的推文数量。这是一个昂贵的操作，因为它需要大量的数据库查询。因此，缓存这个视图是一个好主意。

要根据标签类缓存视图，只需应用一个名为`cache_page`的方法和与之相关的缓存参数。通过编辑`mytweets/urls.py`文件中的以下代码来尝试这一点：

```py
from django.views.decorators.cache import cache_page
...
...
url(r'^search/hashTag$',  cache_page(60 * 15)(SearchHashTag.as_view())),
...
...

```

使用`cache_page()`方法很简单。它允许您指定要缓存的视图。站点缓存中提到的规则也适用于视图缓存。如果视图接收 GET 或 POST 参数，Django 将不会对其进行缓存。

有了这些信息，我们完成了本节。当您首次将网站发布到公众时，缓存是不必要的。然而，当您的网站增长，或者突然接收到大量高流量时，缓存系统肯定会派上用场。因此，在监视应用程序性能时要牢记这一点。

接下来，我们将学习 Django 测试框架。测试有时可能是一项乏味的任务。如果您可以运行一个命令来处理测试您的网站，那不是很好吗？Django 允许您这样做，我们将在下一节中学习。

模板片段可以以以下方式进行缓存：

```py
 % load cache %}
 {% cache 500 sidebar %}
 .. sidebar ..
 {% endcache %}

```

# 单元测试-自动化测试应用程序的过程

在本书的过程中，我们有时修改了先前编写的视图。这在软件开发过程中经常发生。一个人可能会修改甚至重写一个函数来改变实现细节，因为需求已经改变，或者只是为了重构代码，使其更易读。

当您修改一个函数时，您必须再次测试它，以确保您的更改没有引入错误。然而，如果您不断重复相同的测试，测试将变得乏味。如果函数的各个方面没有很好地记录，您可能会忘记测试所有方面。显然，这不是一个理想的情况；我们绝对需要一个更好的机制来处理测试。

幸运的是，已经有了一个解决方案。它被称为单元测试。其思想是编写代码来测试您的代码。测试代码调用您的函数并验证它们的行为是否符合预期，然后打印出结果报告。您只需要编写一次测试代码。以后，每当您想要测试时，只需运行测试代码并检查生成的报告即可。

Python 自带了一个用于单元测试的框架。它位于单元测试模块中。Django 扩展了这个框架，以添加对视图测试的支持。我们将在本节中学习如何使用 Django 单元测试框架。

## 测试客户端

为了与视图交互，Django 提供了一个模拟浏览器功能的类。您可以使用它向应用程序发送请求并接收响应。让我们使用交互式控制台来学习。使用以下命令启动控制台：

```py
$ python manage.py shell

```

导入`Client()`类，创建一个`Client`对象，并使用 GET 请求检索应用程序的主页：

```py
>>>from django.test.client import Client
client = Client()
>>> response = client.get('/')
>>> print response

X-Frame-Options: SAMEORIGIN
Content-Type: text/html; charset=utf-8

<html>
 <head>
 <link href="/static/css/bootstrap.min.css"
 rel="stylesheet" media="screen">
 </head>
 <body>
 <nav class="navbar navbar-default" role="navigation">
 <a class="navbar-brand" href="#">MyTweets</a>
 </nav>
 <div class="container">
 </div>
 <nav class="navbar navbar-default navbar-fixed-bottom" role="navigation">
 <p class="navbar-text navbar-right">Footer </p>
 </nav>
 <script src="img/jquery-2.1.1.min.js"></script>
 <script src="img/bootstrap.min.js"></script>
 <script src="img/base.js"></script>
 </body>
</html>
>>> 

```

尝试向登录视图发送 POST 请求。输出将根据您是否提供正确的凭据而有所不同：

```py
>>> print client.post('/login/',{'username': 'your_username', 'password': 'your_password'})

```

最后，如果有一个只允许已登录用户访问的视图，您可以像这样发送一个请求：

```py
>>> print client.login('/friend/invite/', 'your_username', 'your_password')

```

如您从交互式会话中看到的，`Client()`类提供了三种方法：

+   `get`：这个方法向视图发送一个 GET 请求。它将视图的 URL 作为参数。您可以向该方法传递一个可选的 GET 变量字典。

+   `post`：这个方法向视图发送一个 POST 请求。它将视图的 URL 和一个 POST 变量字典作为参数。

+   `login`：这个方法向一个只允许已登录用户访问的视图发送一个 GET 请求。它将视图的 URL、用户名和密码作为参数。

`Client()`类是有状态的，这意味着它在请求之间保留其状态。一旦您登录，后续的请求将在您登录的状态下处理。`Client()`类的方法返回的响应对象包含以下属性：

+   `status_code`：这是响应的 HTTP 状态

+   `content`：这是响应页面的主体

+   `template`：这是用于渲染页面的`Template`实例；如果使用了多个模板，这个属性将是一个`Template`对象的列表

+   `context`：这是用于渲染模板的`Context`对象

这些字段对于检查测试是否成功或失败非常有用，接下来我们将看到。请随意尝试更多`Client()`类的用法。在继续下一小节之前，了解它的工作原理是很重要的，我们将在下一小节中创建第一个单元测试。

## 测试注册视图

现在您对`Client()`类感到满意了，让我们编写我们的第一个测试。单元测试应该位于应用程序文件夹内名为`tests.py`的模块中。每个测试应该是从`django.test.TestCase`模块派生的类中的一个方法。方法的名称必须以单词 test 开头。有了这个想法，我们将编写一个测试方法，试图注册一个新的用户帐户。因此，在`bookmarks`文件夹内创建一个名为`tests.py`的文件，并在其中输入以下内容：

```py
from django.test import TestCase
from django.test.client import Client
class ViewTest(TestCase):
def setUp(self):
self.client = Client()
def test_register_page(self):
data = {
'username': 'test_user',
'email': 'test_user@example.com',
'password1': 'pass123',
'password2': 'pass123'
}
response = self.client.post('/register/', data)
self.assertEqual(response.status_code, 302)

```

让我们逐行查看代码：

+   首先，我们导入了`TestCase`和`Client`类。

+   接下来，我们定义了一个名为`ViewTest()`的类，它是从`TestCase`类派生的。正如我之前所说，所有测试类都必须从这个基类派生。

+   之后，我们定义了一个名为`setUp()`的方法。当测试过程开始时，将调用这个方法。在这里，我们创建了一个`Client`对象。

+   最后，我们定义了一个名为`test_register_page`的方法。方法的名称以单词 test 开头，表示它是一个测试方法。该方法向注册视图发送一个 POST 请求，并检查状态码是否等于数字`302`。这个数字是重定向的 HTTP 状态。

如果您回忆一下前面的章节，注册视图在请求成功时会重定向用户。

我们使用一个名为`assertEqual()`的方法来检查响应对象。这个方法是从`TestCase`类继承的。如果两个传递的参数不相等，它会引发一个异常。如果引发了异常，测试框架就知道测试失败了；否则，如果没有引发异常，它就认为测试成功了。

`TestCase`类提供了一组方法供测试使用。以下是一些重要的方法列表：

+   `assertEqual`：这期望两个值相等

+   `assertNotEquals`：这期望两个值不相等

+   `assertTrue`：这期望一个值为`True`

+   `assertFalse`：这期望一个值为`False`

现在您了解了测试类，让我们通过发出命令来运行实际测试：

```py
$ python manage.py test

```

输出将类似于以下内容：

```py
Creating test database...
Creating table auth_message
Creating table auth_group
Creating table auth_user
Creating table auth_permission
[...]
Loading 'initial_data' fixtures...
No fixtures found.
.
-------------------------------------------------------------
Ran 1 test in 0.170s
OK
Destroying test database...

```

那么，这里发生了什么？测试框架首先通过创建一个类似于真实数据库中的表的测试数据库来开始。接下来，它运行在测试模块中找到的测试。最后，它打印出结果的报告并销毁测试数据库。

在这里，我们的单个测试成功了。如果测试失败，输出会是什么样子，请修改`tests.py`文件中的`test_register_page`视图，删除一个必需的表单字段：

```py
def test_register_page(self):
data = {
'username': 'test_user',
'email': 'test_user@example.com',
'password1': '1',
# 'password2': '1'
}
response = self.client.post('/register/', data)
self.assertEqual(response.status_code, 302)
```

现在，再次运行`python manage.py test`命令以查看结果：

```py
=============================================================
FAIL: test_register_page (mytweets.user_profile.tests.ViewTest)
-------------------------------------------------------------
Traceback (most recent call last):
File "mytweets/user_profile/tests.py", line 19, in test_
register_page
self.assertEqual(response.status_code, 302)
AssertionError: 200 != 302
-------------------------------------------------------------
Ran 1 test in 0.170s
FAILED (failures=1)

```

我们的测试有效！Django 检测到错误并给了我们发生的确切细节。完成后不要忘记将测试恢复到原始形式。现在，让我们编写另一个测试，一个稍微更高级的测试，以更好地了解测试框架。

还有许多其他情景可以编写单元测试：

+   检查注册是否失败，如果两个密码字段不匹配

+   测试“添加朋友”和“邀请朋友”视图

+   测试“编辑书签”功能

+   测试搜索返回正确结果

上面的列表只是一些例子。编写单元测试以覆盖尽可能多的用例对于保持应用程序的健康和减少错误和回归非常重要。你编写的单元测试越多，当你的应用程序通过所有测试时，你就越有信心。Django 使单元测试变得非常容易，所以要充分利用这一点。

在应用程序的生命周期中的某个时刻，它将从开发模式转移到生产模式。下一节将解释如何为生产环境准备您的 Django 项目。

# 部署 Django

所以，你在你的 Web 应用程序上做了很多工作，现在是时候上线了。为了确保从开发到生产的过渡顺利进行，必须在应用程序上线之前进行一些更改。本节涵盖了这些更改，以帮助您成功上线您的 Web 应用程序。

## 生产 Web 服务器

在本书中，我们一直在使用 Django 自带的开发 Web 服务器。虽然这个服务器非常适合开发过程，但绝对不适合作为生产 Web 服务器，因为它并没有考虑安全性或性能。因此，它绝对不适合生产环境。

在选择 Web 服务器时，有几个选项可供选择，但**Apache**是迄今为止最受欢迎的选择，Django 开发团队实际上也推荐使用它。如何在 Apache 上设置 Django 的详细信息取决于您的托管解决方案。一些托管计划提供预配置的 Django 托管，您只需将项目文件复制到服务器上，而其他托管计划则允许您自己配置一切。

设置 Apache 的详细信息可能会因多种因素而有所不同，超出了本书的范围。如果最终需要自己配置 Apache，请参考 Django 文档[`www.djangoproject.com/documentation/apache_auth/`](http://www.djangoproject.com/documentation/apache_auth/)以获取详细说明。

# 总结

本章涵盖了各种有趣的主题。在本章中，我们为项目开发了一组重要的功能。追随者的网络对于帮助用户社交和共享兴趣非常重要。我们了解了几个在部署 Django 时有用的 Django 框架。我们还学会了如何将 Django 项目从开发环境迁移到生产环境。值得注意的是，我们学到的这些框架都非常易于使用，因此您将能够在未来的项目中有效地利用它们。这些功能在 Web 2.0 应用程序中很常见，现在，您将能够将它们整合到任何 Django 网站中。

在下一章中，我们将学习如何改进应用程序的各个方面，主要是性能和本地化。我们还将学习如何在生产服务器上部署我们的项目。下一章将提供大量有用的信息，所以请继续阅读！


# 第十章：扩展 Django

到目前为止，我们已经走了很长的路，涉及了大量与 Django 功能相关的代码和基本概念。在本章中，我们将更多地讨论 Django，但我们将简要讨论不同的参数，例如自定义标签、过滤器、子框架、消息系统等。以下是本章将涉及的主题：

+   自定义模板标签和过滤器

+   基于类的通用视图

+   贡献的子框架

+   消息系统

+   订阅系统

+   用户分数

# 自定义模板标签和过滤器

Django 模板系统配备了许多模板标签和过滤器，使编写模板变得简单灵活。但是，有时您可能希望使用自己的标签和过滤器扩展模板系统。当您发现自己多次重复相同的标签结构时，希望将结构包装在单个标签中，甚至希望添加到模板系统中的过滤器时，通常会发生这种情况。

猜猜？Django 已经允许您这样做，而且这也很容易！您基本上只需向应用程序添加一个名为**templatetags**的新包，并将包含标签和过滤器的模块放入其中。让我们通过添加一个将字符串大写的过滤器来学习这一点。在`mytweets`父文件夹中添加一个`templatetags`文件夹，并在其中放置一个名为`__init__.py`的空文件，以便 Python 将该文件夹视为包。现在，在其中创建一个名为`mytweet_filters`的模块。我们将在此模块中编写我们的过滤器。以下是目录结构的示例：

```py
templatetags/
  |-- __init__.py
  -- mytweet_filters.py
```

现在，将以下代码添加到`mytweet_filters.py`文件中：

```py
  from django import template
  register = template.Library()

  @register.filter
  def capitalize(value):
    return value.capitalize()
```

`register`变量是一个对象，可用于向模板系统引入新的标签和过滤器。在这里，我们使用`register.filter`装饰器将 capitalize 函数添加为过滤器。

要在模板中使用新的过滤器，请在模板文件的开头放入以下行：

```py
{% load mytweet_filters %}
```

然后，您可以像使用 Django 提供的任何其他过滤器一样使用新的过滤器：

```py
Hi {{ name|capitalize }}!
```

添加自定义模板标签的工作方式与过滤器类似。基本上，您定义方法来处理标签，然后注册标签以使其可用于模板。这个过程稍微复杂一些，因为标签可能比过滤器更复杂。有关自定义模板标签的更多信息，请参阅 Django 在线文档。

在编写自定义过滤器时，您必须注意 Django 的自动转义行为。可以传递给过滤器的字符串有三种类型：

+   **原始字符串**：此字符串是通过`str`命令准备的，或者是用 unicode 形成的。如果启用了自动转义，它们将自动转义。

+   **安全字符串**：这些字符串是标记为免受进一步转义的字符串。它们不需要进一步转义。要将输出标记为安全字符串，请使用`django.utils.safestring.mark_safe()`模块。

+   **标记为“需要转义”的字符串**：顾名思义，它们始终需要转义。

# 基于类的通用视图

在使用 Django 时，您会注意到无论您正在处理哪个项目，总是需要某些类型的视图。因此，Django 配备了一组可在任何项目中使用的视图。这些视图称为**通用视图**。

Django 为以下目的提供了通用视图：

+   为任务创建简单的视图，例如重定向到另一个 URL 或呈现模板

+   列出和形成详细视图以显示数据模型中的对象-这些视图类似于管理页面显示数据模型的列表和详细页面

+   生成基于日期的存档页面；这对博客特别有用

+   创建，编辑和删除数据模型中的对象

Django 的基于类的视图可以通过定义子类或直接在 URL 配置中传递参数来配置。

子类充满了消除重写常见情况模板的约定。当您使用子类时，实际上可以通过提供新值来覆盖主类的属性或方法：

```py
# app_name/views.py
from django.views.generic import TemplateView

class ContactView(TemplateView):
  template_name = "contact.html"
```

我们还将在`urls.py`文件中添加其条目以进行重定向：

```py
# project/urls.py
from django.conf.urls.defaults import *
from some_app.views import ContactView

urlpatterns = patterns('',
  (r'^connect/', ContactView.as_view()),
)
```

有趣的是，我们可以通过文件更改来实现相同的效果，并且只需在`urls.py`文件中添加以下内容即可：

```py
from django.conf.urls.defaults import *
from django.views.generic import TemplateView

urlpatterns = patterns('',
  (r'^contact/', TemplateView.as_view(template_name="contact.html")),
)
```

# 贡献的子框架

`django.contrib`包含 Django 的标准库。我们在本书的前几章中使用了该软件包中的以下子框架：

+   `admin`: 这是 Django 管理界面

+   `auth`: 这是用户认证系统

+   `sessions`: 这是 Django 会话框架

+   `syndication`: 这是提要生成框架

这些子框架极大地简化了我们的工作，无论我们是创建注册和认证功能，构建管理页面，还是为我们的内容提供提要。`django.contrib`包是 Django 的一个非常重要的部分。了解其子包及如何使用它们将为您节省大量时间和精力。

本节将为您提供有关此软件包中其他框架的简要介绍。您不会深入了解如何使用每个框架，但您将学到足够的知识以了解何时使用框架。一旦您想在项目中使用框架，您可以阅读在线文档以了解更多信息。

# Flatpages

Web 应用程序可能包含静态页面。例如，您的网站可能包括一组很少更改的帮助页面。Django 提供了一个名为**flatpages**的应用程序来提供静态页面。该应用程序非常简单；它为您提供了一个数据模型，用于存储有关每个页面的各种信息，包括以下内容：

+   URL

+   标题

+   内容

+   模板名称

+   查看页面是否需要注册

要使用该应用程序，您只需在`settings.py`文件中的`INSTALLED_APPS`变量中启用它，并将其中间件添加到`MIDDLEWARE_CLASSES`变量中。之后，您可以使用 flatpages 应用程序提供的数据模型存储和管理静态页面。

## 人性化

**humanize**应用程序提供了一组过滤器，以为您的页面增添人性化的触感。

以下是可用过滤器的列表：

+   **apnumber**: 对于 1-9 的数字，它返回拼写的数字。否则，它返回数字。换句话说，1 变成'one'，9 变成'nine'，以此类推，而 10 保持为 10。

+   **intcomma**: 这接受一个整数并将其转换为带有逗号的字符串，例如：

```py
4500 becomes 4,500.
45000 becomes 45,000.
450000 becomes 450,000.
4500000 becomes 4,500,000.
```

+   **intword**: 这将整数转换为易于阅读的形式，例如：

1000000 变成 1.0 百万。

```py
1200000 becomes 1.2 million.
1200000000 becomes 1.2 billion.
```

+   **naturalday**: 基于日期所在的范围，如果给定日期在*(+1,0,-1)*范围内，则分别显示日期为"明天"，"今天"和"昨天"，例如，（如果今天是 2007 年 1 月 26 日）：

```py
25 Jan 2007 becomes yesterday.
26 Jan 2007 becomes today.
27 Jan 2007 becomes tomorrow.
```

+   **naturaltime**: 这返回一个表示事件日期发生多少秒、分钟或小时前的字符串，例如，（如果现在是 2007 年 1 月 26 日 16:30:00）：

```py
26 Jan 2007 16:30:00 becomes now.
26 Jan 2007 16:29:31 becomes 29 seconds ago.
26 Jan 2007 16:29:00 becomes a minute ago.
26 Jan 2007 16:25:35 becomes 4 minutes ago.
26 Jan 2007 15:30:29 becomes 59 minutes ago.
26 Jan 2007 15:30:01 becomes 59 minutes ago.
26 Jan 2007 15:30:00 becomes an hour ago.
26 Jan 2007 13:31:29 becomes 2 hours ago.
25 Jan 2007 13:31:29 becomes 1 day, 2 hours ago.
25 Jan 2007 13:30:01 becomes 1 day, 2 hours ago.
25 Jan 2007 13:30:00 becomes 1 day, 3 hours ago.
26 Jan 2007 16:30:30 becomes 30 seconds from now.
26 Jan 2007 16:30:29 becomes 29 seconds from now.
26 Jan 2007 16:31:00 becomes a minute from now.
26 Jan 2007 16:34:35 becomes 4 minutes from now.
26 Jan 2007 17:30:29 becomes an hour from now.
26 Jan 2007 18:31:29 becomes 2 hours from now.
27 Jan 2007 16:31:29 becomes 1 day from now.
```

+   **ordinal**: 这将整数转换为序数形式。例如，1 变成'1st'，以此类推，每三个数字之间。

## Sitemap

**Sitemap**是一个生成站点地图的框架，这些站点地图是帮助搜索引擎索引器在您的站点上找到动态页面的 XML 文件。它告诉索引器页面的重要性以及更改频率。这些信息使索引过程更准确和高效。

站点地图框架允许您用 Python 代码表示上述信息，然后生成代表您网站站点地图的 XML 文档。这涵盖了`django.contrib`包中最常用的子框架。该包包含一些不像前面那些重要的附加应用程序，并且会不时地更新新的应用程序。要了解`django.contrib`包中的任何应用程序，您可以随时阅读其在线文档。 

## 跨站点请求伪造保护

我们在第五章中讨论了如何防止两种类型的 Web 攻击，即 SQL 注入和跨站点脚本。Django 提供了对抗另一种称为跨站点请求伪造的攻击的保护。在这种攻击中，恶意站点试图通过欺骗在您网站上登录的用户来操纵您的应用程序，使其打开一个特制的页面。该页面通常包含 JavaScript 代码，试图向您的网站提交表单。CSRF 保护通过将一个令牌（即秘密代码）嵌入到所有表单中，并在提交表单时验证该令牌来工作。这有效地使 CSRF 攻击变得不可行。

要激活 CSRF 保护，您只需要将`'django.contrib.csrf.middleware.CsrfMiddleware'`参数添加到`MIDDLEWARE_CLASSES`变量中，这将透明地工作，以防止 CSRF 攻击。

# 消息系统

我们的应用允许用户将彼此添加为好友并监视好友的书签。虽然这两种形式的通信与我们的书签应用程序的性质有关，但有时用户希望灵活地向彼此发送私人消息。这个功能对于增强我们网站的社交方面特别有用。

消息系统可以以多种方式实现。它可以简单到为每个用户提供一个联系表单，当提交时，通过发送其内容到用户的电子邮件来工作。您已经拥有构建此功能组件所需的所有信息：

+   一个消息表单，其中包含主题的文本字段和消息正文的文本区域

+   显示用户消息表单的视图，并通过`send_mail()`函数将表单内容发送给用户

当允许用户通过您的网站发送电子邮件时，您需要小心以防止滥用该功能。在这里，您可以将联系表单限制为仅限已登录的用户或仅限好友。

实现消息系统的另一种方法是在数据库中存储和管理消息。这样，用户可以使用我们的应用程序发送和查看消息，而不是使用电子邮件。虽然这种方法更加与我们的应用程序绑定，因此可以使用户留在我们的网站上，但需要更多的工作来实现。然而，与之前的方法一样，您已经拥有实现这种方法所需的所有信息。这里需要的组件如下：

+   存储消息的数据模型。它应该包含发送者、接收者、主题和正文的字段。您还可以添加日期、阅读状态等字段。

+   创建消息的表单。需要主题和正文的字段。

+   列出可用消息的视图。

+   显示消息的视图。

上述列表只是实现消息系统的一种方式。例如，您可以将列表和消息视图合并为一个视图，或者提供一个视图来显示已发送的消息以及已接收的消息。可能性很多，取决于您希望该功能有多高级。

# 订阅系统

我们提供了几种 Web 订阅，使用户能够监视我们网站的更新。然而，一些用户可能仍然更喜欢通过电子邮件监视更新的旧方式。对于这些用户，您可能希望将电子邮件订阅系统实施到应用程序中。例如，您可以让用户在朋友发布书签时收到通知，或者在特定标签下发布书签时收到通知。

此外，您可以将这些通知分组并批量发送，以避免发送大量的电子邮件。此功能的实现细节在很大程度上取决于您希望它如何工作。它可以是一个简单的数据模型，用于存储每个用户订阅的标签。它将循环遍历所有订阅特定标签的用户，并在此标签下发布书签时向他们发送通知。然而，这种方法太基础，会产生大量的电子邮件。更复杂的方法可能涉及将通知存储在数据模型中，并在每天发送一封电子邮件。

# 用户评分

一些网站（如[Slashdot.org](http://Slashdot.org)和[reddit.com](http://reddit.com)）通过为每个用户分配一个分数来跟踪用户的活动。每当用户以某种方式为网站做出贡献时，该分数就会增加。用户的分数可以以各种方式利用。例如，您可以首先向最活跃的用户发布新功能，或者为活跃用户提供其他优势，这将激励其他用户更多地为您的网站做出贡献。

实施用户评分非常简单。您需要一个数据模型来在数据库中维护评分。之后，您可以使用 Django 模型 API 从视图中访问和操作评分。

# 总结

本章的目的是为您准备本书未涵盖的任务。它向您介绍了许多主题。当需要某种功能时，您现在知道在哪里寻找框架，以帮助您快速而干净地实施该功能。

本章还为您提供了一些想法，您可能希望将其实施到我们的书签应用程序中。致力于这些功能将为您提供更多的机会来尝试 Django 并扩展您对其框架和内部工作原理的了解。

在下一章中，我们将介绍各种数据库连接的方式，如 MySQL、NoSQL、PostgreSQL 等，这对于任何基于数据库的应用程序都是必需的。


# 第十一章：数据库连接

Django 是一个数据库无关的框架，这意味着 Django 提供的数据库字段被设计为在不同的数据库中工作，比如 SQLite、Oracle、MySQL 和 PostgreSQL。事实上，它们也可以在几个第三方数据库后端上工作。PostgreSQL 是 Django 在生产中的一个很好的数据库，而 SQLite 用于开发环境，如果你不想为项目使用关系数据库管理系统（RDBMS），你将需要做很多工作。本章将详细介绍这两种类型的区别，并向您展示哪种更适合 Django，以及我们如何在 Django 项目中实际实现它们。

以下是本章将涉及的主题：

+   SQL 与 NoSQL

+   Django 与关系数据库

+   Django 与 NoSQL

+   建立数据库系统

+   单页应用项目 - URL 缩短器

首先，让我们看看 SQL 和 NoSQL 之间的区别。

# SQL 与 NoSQL

SQL 数据库或关系数据库已经存在很长时间；事实上，直到新术语被创造出来之前，数据库大致被假定为 SQL 数据库，这个新术语就是 NoSQL。

好吧，我们正在谈论 SQL 和 NoSQL 之间的高级区别。以下是它们之间的区别：

| SQL 数据库（RDBMS） | NoSQL 数据库 |
| --- | --- |
| SQL 数据库是关系数据库（RDBMS） | NoSQL 数据库是非关系或分布式数据库 |
| SQL 数据库基于表及其与其他表的关系 | NoSQL 基于文档、键值对、图数据库或宽列存储 |
| SQL 数据库将数据存储在表的行中 | NoSQL 是一组键值对、文档、图数据库或宽列存储 |
| SQL 数据库有预定义的模式 | NoSQL 有动态模式 |
| SQL 数据库是纵向可扩展的 | NoSQL 数据库是横向可扩展的 |
| SQL 数据库的例子有 MySQL、Oracle、SQLite、PostgreSQL 和 MS SQL | NoSQL 数据库的例子有 MongoDB、BigTable、Redis、RavenDB、Cassandra、HBase、Neo4j 和 CouchDB |

让我们试着了解一些著名的 SQL 和 NoSQL 数据库的基本特性。

## SQL 数据库

以下部分涉及不同的 SQL 数据库及其用法。

### MySQL - 开源

作为世界上最流行的数据库之一，MySQL 具有一些优点，使其适用于各种业务问题。以下是 MySQL 的一些重要优点：

+   **复制**：MySQL 支持复制，通过复制 MySQL 数据库，可以显著减少一台机器的工作负载，并且可以轻松扩展应用程序

+   **分片**：当写操作数量非常高时，分片通过将应用服务器分区来将数据库分成小块，有助于减轻负载

### PostgreSQL

如前所述，PostgreSQL 是 Django 社区中最受欢迎的数据库。它也拥有核心支持的数据库中最广泛的功能集。

进化的 PostgresSQL 的高级查询和功能使得将复杂的传统 SQL 查询转换为更简单的查询变得可能。然而，使用传统的 SQL 数据库实现数组、hstore、JSON 等功能有点棘手。

## NoSQL 数据库

这个概念是在水平扩展困难且基于 RDBMS 的数据库无法像预期的那样扩展时引入的。它通常被称为 Not only SQL。它提供了一种存储和检索数据的机制，而不是传统的 SQL 方法。

### MongoDB

MongoDB 是最受欢迎的基于文档的 NoSQL 数据库之一，它以类似 JSON 的文档存储数据。它是一个非关系数据库，具有动态模式。它是由**DoubleClick**的创始人开发的。它是用**C++**编写的，目前被一些大公司使用，如纽约时报、Craigslist 和 MTV Networks。以下是 MongoDB 的一些优点和优势：

+   **速度**：对于简单的查询，它具有良好的性能，因为所有相关数据都在一个单个文档中，消除了连接操作

+   **可扩展性**：它是水平可扩展的，也就是说，您可以通过增加资源池中服务器的数量来减少工作负载，而不是依赖独立的资源

+   **易管理**：对开发人员和管理员都很容易使用。这也使得 MondoDB 具有共享数据库的能力

+   **动态模式**：它为您提供了在不修改现有数据的情况下演变数据模式的灵活性

### CouchDB

CouchDB 也是一种基于文档的 NoSQL 数据库。它以 JSON 文档的形式存储数据。以下是 CouchDB 的一些优点和优势：

+   **无模式**：作为 NoSQL 家族的一员，它也具有无模式的特性，使其更加灵活，因为它具有存储数据的 JSON 文档形式

+   **HTTP 查询**：您可以使用 Web 浏览器访问数据库文档

+   **冲突解决**：它具有自动冲突，当您要使用分布式数据库时非常有用

+   **易复制**：复制相当简单

### Redis

Redis 是另一个开源的 NoSQL 数据库，主要因其闪电般的速度而被广泛使用。它是用 ANSI C 语言编写的。以下是 Redis 的一些优点和优势：

+   **数据结构**：Redis 提供了高效的数据结构，有时被称为数据结构服务器。存储在数据库中的键可以是哈希、列表和字符串，并且可以是排序或无序集合。

+   **Redis 作为缓存**：您可以使用 Redis 作为缓存，通过实现具有有限时间的键来提高性能。

+   **非常快**：它被认为是最快的 NoSQL 服务器之一，因为它使用内存数据集。

# 设置数据库系统

Django 支持多种数据库引擎。然而有趣的是，您只需要学习一个 API 就可以使用任何这些数据库系统。

这可能是因为 Django 的数据库层抽象了对数据库系统的访问。

稍后您将了解这一点，但是现在，您只需要知道无论您选择哪种数据库系统，都可以在不修改的情况下运行本书（或其他地方）开发的 Django 应用程序。

与客户端-服务器数据库系统不同，SQLite 不需要在内存中保留进程，并且将数据库存储在单个文件中，使其非常适合我们的开发环境。这就是为什么我们在整个项目中一直使用这个数据库，直到现在。当然，您可以自由选择使用您喜欢的数据库管理系统。我们可以通过编辑配置文件告诉 Django 使用哪个数据库系统。值得注意的是，如果您想使用 MySQL，您需要安装 MySQL，这是 Python 的 MySQL 驱动程序。

在 Django 中安装数据库系统非常简单；您只需要先安装要配置的数据库，然后在`settings.py`文件中添加几行配置，数据库设置就完成了。

## 设置 MySQL

我们将在接下来的几节中逐步安装和配置 MySQL 及其相关插件。

### 在 Linux - Debian 中安装 MySQL

在 Linux 中执行以下命令安装 MySQL（这里是 Debian）：

```py
sudo apt-get install mysql-server 

```

执行此命令后，将要求您设置 MySQL 并使用用户名和密码配置数据库。

### 安装 Python 的 MySQL 插件

要安装所需的与 MySQL 相关的插件，请使用以下命令：

```py
pip install MySQL-python 

```

现在，打开`settings.py`文件，并添加以下行以使 Django 连接到 MySQL：

```py
DATABASES = {
  'default': {
  'ENGINE': 'django.db.backends.mysql',
  'NAME': 'django_db',
  'USER': 'your_username',
  'PASSWORD': 'your_password',
  }
}
```

就是这样，现在你需要做的就是在新配置的数据库中重新创建所有表，并运行以下命令：

```py
python manage.py syncdb 

```

### 注意

如果您尝试访问未定义的数据库，将会收到`django.db.utils.ConnectionDoesNotExist`异常。

Django 的优势在于您可以同时在多个数据库中使用它。

然而，您可能会想，为什么在同一个项目中需要多个数据库？

直到 NoSQL 数据库出现之前，在大多数情况下，通常使用同一个数据库来保存所有类型的数据记录，从关键数据（如用户详细信息）到转储数据（如日志）；所有这些都保存在同一个数据库中，系统在扩展系统时面临挑战。

对于多数据库系统，一个理想的解决方案可能是将关系信息（例如用户、角色和其他帐户信息）存储在 SQL 数据库（如 MySQL）中。独立的应用程序数据可以存储在 NoSQL 数据库（如 MongoDB）中。

我们需要通过配置文件定义多个数据库。当您想要使用多个数据库与您使用的数据库服务器时，Django 需要告诉您。因此，在`settings.py`文件中，您需要使用数据库别名映射更改`DATABASES`设置。

多数据库配置的一个适当示例可以写成如下形式：

```py
DATABASES = {
  'default': {
    'NAME': 'app_data',
    'ENGINE': 'django.db.backends.postgresql_psycopg2',
    'USER': 'postgres_user',
    'PASSWORD': 's3krit'
  },
  'users': {
    'NAME': 'user_data',
    'ENGINE': 'django.db.backends.mysql',
    'USER': 'mysql_user',
    'PASSWORD': 'priv4te'
  }
}
```

上述示例使用了两个数据库，分别是 PostgreSQL 和 MySQL，具有所需的凭据。

## 迁移和迁移的需求

迁移允许您通过创建代表模型更改的迁移文件来更新、更改和删除模型，并且可以在任何开发、暂存或生产数据库上运行。

Django 的模式迁移经历了漫长而复杂的历史；在过去的几年里，第三方应用**South**是唯一的选择。如果您考虑迁移的重要性，Django 1.7 发布时内置了迁移支持。

我们还需要了解 South 与 Django 迁移的区别。对于熟悉 South 的人来说，这应该感觉相当熟悉，可能会更清晰一些。为了方便参考，以下表格比较了旧的 South 工作流程和新的 Django 迁移工作流程：

| 步骤 | South | Django 迁移 |
| --- | --- | --- |
| 初始迁移 | 运行 `syncdb` 然后 `./manage.py schemamigration <appname> --initial` | `./manage.py makemigrations <appname>` |
| 应用迁移 | `./manage.py migrate <appname>` | `./manage.py migrate <appname>` |
| 非首次迁移 | `./manage.py schemamigration <appname> --auto` | `./manage.py makemigration <appname>` |

因此，从表中我们可以看出，Django 迁移基本上遵循与 South 相同的流程，至少对于标准迁移流程来说，这只是简化了一些事情。

### Django 迁移中的新功能

新的迁移代码将是 South 的改进版本，但将基于相同的概念，如下所示：

+   每个应用程序的迁移

+   自动检测变化

+   数据迁移与模式迁移同时进行

让我们看一下以下术语列表，以了解 Django 迁移的优势：

+   **改进的迁移格式**：改进的迁移格式可读性更强，因此可以在不实际执行的情况下进行优化或检查

+   **重置基线**：在这种情况下，不需要每次保留或执行整个迁移历史，因为现在可以随着项目的增长创建新的第一次迁移

+   **改进的自动检测**：新的和自定义字段更改将更容易被检测到，因为迁移将与改进的字段 API 一起构建

+   **更好的合并检测**：新的迁移格式将自动解决不同版本控制系统分支之间的合并，如果我们能够合并这些更改，就不再需要任何工作

一旦您设置好项目并启动应用程序，也就是说，您的应用程序已经在数据库中生成了必要的表，您不应该对 Django 模型进行复杂的更改，也就是说，您不应该从一个类中删除属性。然而，在实际情况下，这是不可能的，因为您可能需要相应地更改您的模型类。在这种情况下，我们有一个解决这些问题的方法。这个过程被称为**迁移**，在 Django 中，这些迁移是通过一个叫做 South 的模块来完成的。

直到 Django 的 1.7 版本，即最新版本，您必须单独安装 south 模块。然而，自 Django 的 1.7 迁移以来，south 模块是一个内置模块。您可能一直在这样做，例如，当您使用以下命令更改（例如添加新属性）您的模型类时：

```py
$python manage.py syncdb 

```

使用更新版本，`manage.py syncdb`已经被弃用以进行迁移，但如果您仍然喜欢旧的方式，现在可以使用。

## 后端支持

这对于任何用于生产的 Django 应用程序来说都是非常重要的，以获得迁移支持。因此，选择一个主要受迁移模块支持的数据库总是一个更好的决定。

一些最兼容的数据库如下：

+   **PostgreSQL**：在迁移或模式支持方面，PostgresSQL 是最兼容的数据库。

### 注意

您可以使用`null=True`初始化新列，因为这样可以更快地添加。

+   **MySQL**：MySQL 是一个广泛使用的数据库，因为 Django 无缝支持它。这里的问题是，在进行模式更改操作时，没有事务支持，也就是说，如果一个操作失败，您将不得不手动回滚更改。此外，对于每个模式更新，所有表都将被重写，这可能需要很长时间，重新启动应用程序可能需要很长时间。

+   **SQLite**：这是 Django 默认的数据库，主要用于开发目的。因此，它对以下情况的模式更改支持有限：

+   创建新表

+   数据复制

+   删除旧表

+   重命名表

## 如何进行迁移？

迁移主要是通过以下三个命令完成的，如下所示：

+   `makemigrations`：这是基于您对准备迁移查询的模型所做的更改

+   `migrate`：这将应用`makemigrations`查询准备的更改并列出它们的状态。

+   `sqlmigrate`：这显示了`makemigrations`查询准备的 SQL 查询

因此，Django 的模式迁移流程可以如下所述：

```py
$python manage.py makemigrations 'app_name'

```

这将准备迁移文件，其外观类似于以下内容：

```py
Migrations for 'app_name':
  0003_auto.py:
    - Alter field name on app_name
```

然后，在文件创建后，您可以检查目录结构。您将在`migration`文件夹下看到一个名为`0003_auto.py`的文件；您可以使用以下命令应用更改：

```py
$ python manage.py migrate app_name

```

以下是您需要执行的操作：

```py
Synchronize non migrated apps: sessions, admin, messages, auth, staticfiles, contenttypes
Apply all migrations: app_name
Synchronizing apps without migrations:
Creating tables...
Installing custom SQL...
Installing indexes...
Installed 0 object(s) from 0 fixture(s)
Running migrations:
Applying app_name.0003_auto... OK

```

`OK`消息表示迁移已成功应用。

为了使它更容易理解，迁移可以用以下图表来解释：

![如何进行迁移？](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00312.jpeg)

有三个独立的实体：

+   源代码

+   迁移文件

+   数据库

开发人员在源代码中进行更改，主要是在`models.py`文件中，并修改先前定义的模式。例如，当他们根据业务需求创建一个新字段，或者将 max_length 从 50 更新为 100。

我们将完成项目的适当迁移，以查看这个迁移实际上是如何工作的。

首先，我们必须创建应用程序的初始迁移：

```py
$ python manage.py makemigrations tweet

```

其输出如下：

```py
Migrations for 'tweet': 
0001_initial.py: 
- Create model HashTag 
- Create model Tweet 
- Add field tweet to hashtag 

```

这表明初始迁移已经创建。

现在，让我们改变我们的推文模态，现在如下所示：

`text = models.CharField(max_length=160, null=False, blank=False)`

我们将更改之前的推文模态为：

`text = models.CharField(max_length=140, null=False, blank=False)`

由于我们已经更改了我们的模式，现在我们必须进行迁移以正确运行应用程序。

从迁移流程中，我们了解到，现在我们必须运行`makemigrations`命令，如下所示：

```py
$python manage.py makemigrations tweet

```

其输出如下：

```py
Migrations for 'tweet': 
0002_auto_20141215_0808.py: 
- Alter field text on tweet 

```

正如你所看到的，它已经检测到了我们字段的更改。

为了验证，我们将打开我们的 SQL 数据库并检查 tweet 表的当前模式。

登录到 MySQL：

```py
$mysql -u mysql_username -pmysql_password mytweets 

```

在 MySQL 控制台中，写入：

```py
$mysql> desc tweet_tweet;

```

这将显示 tweet 表的模式，如下所示：

```py
+-------------------+-------------+------+-----+---------+----------------+
| Field | Type | Null | Key | Default | Extra |
+--------------+--------------+------+-----+---------+----------------+
| id | int(11) | NO | PRI | NULL | auto_increment |
| user_id | int(11) | NO | MUL | NULL | |
| text | varchar(160) | NO | | NULL | |
| created_date | datetime | NO | | NULL | |
| country | varchar(30) | NO | | NULL | |
| is_active | tinyint(1) | NO | | NULL | |
+--------------+--------------+------+-----+---------+----------------+
6 rows in set (0.00 sec)

```

由于我们还没有应用我们的迁移，数据库中明显显示字符字段中的文本为 160：

```py
text | varchar(160) | NO | | NULL

```

我们在应用我们的迁移后将做完全相同的事情：

```py
$python manage.py migrate tweet

```

以下是我们需要执行的操作：

```py
Apply all migrations: tweet
Running migrations:
Applying tweet.0002_auto_20141215_0808... OK

```

我们的迁移已成功应用；让我们从数据库中验证一下。

要在`tweet_tweet`表上运行相同的 MySQL `desc`命令，请使用以下命令：

```py
mysql> desc tweet_tweet;
+--------------+--------------+------+-----+---------+----------------+
| Field | Type | Null | Key | Default | Extra |
+--------------+--------------+------+-----+---------+----------------+
| id | int(11) | NO | PRI | NULL | auto_increment |
| user_id | int(11) | NO | MUL | NULL | |
| text | varchar(140) | YES | | NULL | |
| created_date | datetime | NO | | NULL | |
| country | varchar(30) | NO | | NULL | |
| is_active | tinyint(1) | NO | | NULL | |
+--------------+--------------+------+-----+---------+----------------+
6 rows in set (0.00 sec)

```

确实！我们的迁移已成功应用：

```py
| text | varchar(140) | YES | | NULL | |

```

### 迁移如何知道要迁移什么

Django 永远不会在同一个数据库上运行两次迁移，这意味着它会保留这些信息。这些信息由一个名为`django_migrations`的表管理，它是在第一次启动 Django 应用程序时创建的，之后每次迁移都会插入一行新数据。

例如，运行我们的迁移后，表格可能会看起来像这样：

```py
mysql> select * from django_migrations;
+----+-------+-------------------------+---------------------+
| id | app | name | applied |
+----+-------+-------------------------+---------------------+
| 1 | tweet | 0001_initial | 2014-12-15 08:02:34 |
| 2 | tweet | 0002_auto_20141215_0808 | 2014-12-15 08:13:19 |
+----+-------+-------------------------+---------------------+

```

前面的表格显示了有两个带有标记信息的迁移，并且每次迁移时，它都会跳过这些更改，因为这个表中已经有了对应于该迁移文件的条目。

这意味着即使你手动更改迁移文件，它也会被跳过。

这是有道理的，因为通常你不希望运行两次迁移。

然而，如果出于某种原因你真的想要应用两次迁移，你可以简单地删除表格条目中的*"THIS IS NOT A OFFICIALLY RECOMMENDED WAY"*，它将正常工作。

相反，如果你想要撤消特定应用的所有迁移，你可以迁移到一个名为 zero 的特殊迁移。

例如，如果你键入，tweet 应用的所有迁移将被撤销：

```py
$python manage.py migrate tweet zero

```

除了使用 zero，你还可以使用任意的迁移，如果那个迁移在过去，那么数据库将回滚到那个迁移的状态，或者如果还没有运行该迁移，那么数据库将向前滚动。

## 迁移文件

那么，迁移文件包含什么，当我们运行以下命令时到底发生了什么？

```py
$python manage.py migrate tweet 

```

运行完这个命令后，你会看到一个名为`migrations`的目录，里面存储着所有的迁移文件。让我们来看看它们。由于它们是 Python 文件，可能很容易理解。

打开`tweet/migrations/0001_initial.py`文件，因为这是初始迁移代码创建的文件。它应该看起来类似于以下内容：

```py
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.db import models, migrations

class Migration(migrations.Migration):
dependencies = [
  ('user_profile', '__first__'),
]

operations = [
  migrations.CreateModel(
  name='HashTag',
  fields=[
    ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
    ('name', models.CharField(unique=True, max_length=64)),
  ],
  options = {
  },
  bases=(models.Model,),
  ),
  migrations.CreateModel(
  name='Tweet',
  fields=[
    ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
    ('text', models.CharField(max_length=160)),
    ('created_date', models.DateTimeField(auto_now_add=True)),
    ('country', models.CharField(default=b'Global', max_length=30)),
    ('is_active', models.BooleanField(default=True)),
    ('user', models.ForeignKey(to='user_profile.User')),
  ],
  options = {
  },
  bases=(models.Model,),
  ),
  migrations.AddField(
    model_name='hashtag',
    name='tweet',
    field=models.ManyToManyField(to='tweet.Tweet'),
    preserve_default=True,
  ),
]
```

要使迁移实际工作，必须有一个名为`Migration()`的类，它继承自`django.db.migrations.Migration`模块。这是用于迁移框架的主要类，这个迁移类包含两个主要列表，如下所示：

+   **依赖项**：这是必须在迁移开始之前运行的其他迁移的列表。在存在依赖关系的情况下，比如外键关系的情况下，外键模型必须在其键被添加到这里之前存在。在前面的情况下，我们对`user_profile`参数有这样的依赖。

+   **操作**：这个列表包含要应用的迁移列表，整个迁移操作可以属于以下类别：

+   `CreateModel`：从名称本身，很明显这将创建一个新模型。从前面的模型文件中，你可以看到这样的行：

```py
migrations.CreateModel(
name='HashTag',....
migrations.CreateModel(
name='Tweet',..
```

这些迁移行创建了具有定义属性的新模型。

+   `DeleteModel`：这将包含从数据库中删除模型的语句。这些与`CreateModel`方法相反。

+   `RenameModel`：这将使用给定的新名称从旧名称重命名模型。

+   `AlterModelTable`：这将更改与模型关联的表的名称。

+   `AlterUniqueTogether`：这是更改的表的唯一约束。

+   `AlteIndexTogether`：这将更改模型的自定义索引集。

+   `AddField`：这只是向现有模型添加新字段。

+   `RemoveField`：这将从模型中删除字段。

+   `RenameField`：这将为模型将字段名称从旧名称重命名为新名称。

在更新应用程序时，模式的迁移不是唯一需要迁移的事情；还有另一件重要的事情叫做**数据迁移**。这是由先前操作已经存储在数据库中的数据，因此也需要迁移。

数据迁移可以在许多情况下使用。其中，最合乎逻辑的情况是：

+   将外部数据加载到应用程序中

+   当模型架构发生变化并且数据集也需要更新时

让我们通过从`username.txt`文件中加载推文来玩耍我们的项目。使用以下命令为我们的项目创建一个空迁移：

```py
$python manage.py makemigrations --empty tweet

```

这将生成一个名为`mytweets/migrations/003_auto<date_time_stamp>.py`的迁移文件。

打开这个文件；它看起来像下面这样：

```py
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

class Migration(migrations.Migration):

dependencies = [
  ('tweet', '0002_auto_20141215_0808'),
]

operations = [
]
```

这只是 Django 迁移工具的基本结构，要进行数据迁移，我们必须在操作中添加`RunPython()`函数，如下所示：

```py
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations

def load_data(apps, schema_editor):
  Tweet(text='This is sample Tweet',
    created_date=date(2013,11,29),
    country='India',
    is_active=True,
  ).save()

class Migration(migrations.Migration):

dependencies = [
  ('tweet', '0002_auto_20141215_0808'),
]

operations = [
  migrations.RunPython(load_data)
]
```

就这些了。现在，运行迁移命令：

```py
$python manage.py migrate

```

这些是您需要执行的操作：

```py
Synchronize unmigrated apps: user_profile
Apply all migrations: admin, contenttypes, tweet, auth, sessions
Synchronizing apps without migrations:
Creating tables...
Installing custom SQL...
Installing indexes...
Running migrations:
Applying contenttypes.0001_initial... FAKED
Applying auth.0001_initial... FAKED
Applying admin.0001_initial... FAKED
Applying sessions.0001_initial... FAKED
Applying tweet.0003_auto_20141215_1349... OK

```

执行上述命令后，该命令迁移了所有应用程序，并最终应用了我们创建新推文的迁移，从加载的数据中创建了新推文：

```py
mysql> select * from tweet_tweet;
+----+---------+---------------------------------------------+---------------------+---------+-----------+
| id | user_id | text | created_date | country | is_active |
+----+---------+---------------------------------------------+---------------------+---------+-----------+
| 1 | 1 | This Tweet was uploaded from the file. | 2014-12-15 14:17:42 | India | 1 |
+----+---------+---------------------------------------------+---------------------+---------+-----------+
2 rows in set (0.00 sec)

```

很棒，对吧？

当您有以 JSON 或 XML 文件形式的外部数据时，这种解决方案非常必要。

理想的解决方案是使用命令行参数来获取文件路径并加载数据，如下所示：

```py
$python load data tweet/initial_data.json

```

不要忘记将迁移文件夹添加到 Git 中，因为它们与源代码一样重要。

## Django 与 NoSQL

Django 并不正式支持 NoSQL 数据库，但是在有这么多开发者的伟大社区的支持下，Django 有一个支持**MongoDB**作为后端数据库的分支。

为了说明问题，我们将使用 Django-Norel 项目来配置 Django 与 MongoDB 数据库。

您可以在[`django-nonrel.org/`](http://django-nonrel.org/)找到关于此的详细信息。

可以按照[`docs.mongodb.org/manual/installation/`](http://docs.mongodb.org/manual/installation/)中提到的步骤安装 MongoDB，根据您的配置。

在这里，我们将为 Linux 的 Debian 版本（具体来说是 Ubuntu）设置 MongoDB。

导入 MongoDB 公共 GPG 密钥：

```py
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10

```

为 MongoDB 创建一个列表文件：

```py
echo 'deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen' | sudo tee /etc/apt/sources.list.d/mongodb.list

```

重新加载本地软件包数据库：

```py
sudo apt-get update

```

安装 MongoDB 软件包：

```py
sudo apt-get install -y mongodb-org

```

启动 MongoDB：

```py
sudo service mongod start

```

# 单页面应用项目 - URL 缩短器

MongoDB 可以与 Django 一起使用的两种方式如下：

+   **MongoEngine**：这是一个**文档对象映射器**（类似于 ORM，但用于文档数据库），用于从 Python 与 MongoDB 一起使用。

+   **Django non-rel**：这是一个支持 Django 在非关系型（NoSQL）数据库上的项目；目前支持 MongoDB。

## MongoEngine

在我们继续展示如何配置 MongoEngine 与 Django 之前，需要安装 MongoEngine。通过输入以下命令来安装 MongoEngine：

```py
sudo pip install mongoengine 

```

为了保护我们之前创建的项目，并更好地理解，我们将创建一个单独的新项目来配置 MongoDB，并且我们将使用现有项目来配置 MySQL：

```py
$django-admin.py startproject url_shortner
$cd url_shortner
$python manage.py startapp url

```

这将创建项目的基本结构，我们非常了解。

### 将 MongoDB 连接到 Django

我们将不得不修改`settings.py`文件，如果我们只在项目中使用 MognoDB，这在这种情况下是正确的，那么我们可以忽略标准数据库设置。我们所要做的就是在`settings.py`文件上调用`connect()`方法。

我们将为 MongoDB 放置一个虚拟后端。只需在`settings.py`文件中替换以下代码，如下所示：

```py
DATABASES = {
  'default': {
  'ENGINE': 'django.db.backends.sqlite3',
  'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
  }
}
```

用以下内容替换上述代码：

```py
DATABASES = {
  'default': {
  'ENGINE': 'django.db.backends.dummy'
  }
}
```

### Django 中的身份验证

MongoEngine 的优势在于它包括了 Django 身份验证后端。

用户模型成为 MongoDB 文档，并实现了大部分普通 Django 用户模型的方法和属性，这使得 MongoEngine 与 Django 兼容。我们还可以使用身份验证基础设施和装饰器，例如`login_required()`和`authentication()`方法。`auth`模块还包含`get_user()`方法，它接受用户 ID 作为参数并返回用户对象。

要为 MognoEngine 启用此后端，请在`settings.py`文件中添加以下内容：

```py
AUTHENTICATION_BACKENDS = (
  'mongoengine.django.auth.MongoEngineBackend',
)
```

### 存储会话

在 Django 中，您可以使用不同的数据库来存储应用程序的会话。要启用存储在 MongoDB 中的 MongoEngine 会话，`settings.py`文件中的`MIDDLEWARE_CLASSES`必须有`django.contrib.sessions.middleware.SessionMiddleware`参数的条目。还必须在`INSTALLED_APPS`中有`django.contrib.sessions`的条目，因为我们是从 Django 的基本结构开始的。

现在，您只需要在`settings.py`文件中添加以下行：

```py
SESSION_ENGINE = 'mongoengine.django.sessions'
SESSION_SERIALIZER = 'mongoengine.django.sessions.BSONSerializer'
```

我们现在已经准备好开始一个小型演示项目，在其中我们将在 MongoDB 中实现 URL 缩短项目。

让我们首先创建一个 URL 模型，我们将在其中存储所有长 URL 及其对应的短 URL。

转到以下`url/models.py`文件：

```py
from django.db import models
from mongoengine import *
connect('urlShortener')
```

您已经熟悉了上述代码的前两行，它们导入了模块。

第三行，即`connect('urlShortener')`，将 Django 连接到名为`urlShortener`的 MongoDB 数据库。

MongoDB 提供了许多连接机制供您选择，它们如下：

```py
from mongoengine import connect
connect('project1')
```

我们正在使用的方法将 MongoDB 从其默认端口（27017）中获取；如果您在其他端口上运行 MongoDB，请使用`connect()`方法进行连接：

```py
connect('project1', host='192.168.1.35', port=12345)
```

如果您为 MongoDB 配置了密码，可以传递参数如下：

```py
connect('project1', username='webapp', password='pwd123')
```

像 Django 的默认模型字段一样，MongoDB 也为您提供了不同的字段，它们是：

+   `BinaryField`：此字段用于存储原始二进制数据。

+   `BooleanField`：这是一个布尔字段类型。

+   `DateTimeField`：这是一个日期时间字段。

+   `ComplexDateTimeField`：这样处理微秒，而不是像`DateTimeField`那样将它们四舍五入。

+   `DecimalField`：这是一个固定小数点十进制数字段。

+   `DictField`：这是一个包装了标准 Python 字典的字典字段。这类似于嵌入式文档，但结构未定义。

+   `DynamicField`：这是一种真正动态的字段类型，能够处理不同和多样化的数据类型。

+   `EmailField`：这是一个验证输入为电子邮件地址的字段。

+   `FileField`：这是一个 GridFS 存储字段。

+   `FloatField`：这是一个浮点数字段。

+   `GeoPointField`：这是一个存储经度和纬度坐标的列表。

+   `ImageField`：这是图像文件存储字段。

+   `IntField`：这是一个 32 位整数字段。

+   `ListField`：这是一个列表字段，它包装了一个标准字段，允许在数据库中使用字段的多个实例作为列表。

+   `MapField`：这是一个将名称映射到指定字段类型的字段。这类似于`DictField`，只是每个项目的“值”必须与指定的字段类型匹配。

+   `ObjectIdField`：这是 MongoDB 对象 ID 的字段包装器。

+   `StringField`：这是一个 Unicode 字符串字段。

+   `URLField`：这是一个验证输入为 URL 等的字段。

### 注意

默认情况下，字段不是必需的。要使字段成为必需字段，请将字段的 required 关键字参数设置为`True`。字段还可以具有可用的验证约束（例如，前面示例中的 max_length）。字段还可以采用默认值，如果未提供值，则将使用默认值。默认值可以选择是可调用的，将调用以检索值（如前面的示例）。

可以在[`docs.mongoengine.org/en/latest/apireference.html`](http://docs.mongoengine.org/en/latest/apireference.html)上看到完整的不同字段列表。

现在，我们将创建我们的`Url()`类，它将类似于我们迄今为止创建的其他模型，比如推文等等：

```py
class Url(Document):
full_url = URLField(required=True)
short_url = StringField(max_length=50, primary_key=True, unique=True)
date = models.DateTimeField(auto_now_add=True)
```

让我们来看一下以下术语列表：

+   `full_url`：这是一个 URL 字段，将存储完整的 URL，以及触发其短 URL 时请求将重定向的相同 URL

+   `short_url`：这是相应长 URL 的短 URL

+   `date`：这将存储`Url`对象创建的日期。

现在，我们将转到视图并创建两个类：

+   **索引**：在这里，用户可以生成短链接。这也将有一个`post()`方法，保存每个长 URL。

+   **链接**：这是短 URL 重定向控制器。当查询短 URL 时，此控制器将请求重定向到长 URL，如下面的代码片段所示：

```py
class Index(View):
def get(self, request):
return render(request, 'base.html')

def post(self, request):
long_url = request.POST['longurl']
short_id = str(Url.objects.count() + 1)
url = Url()
url.full_url = long_url
url.short_url = short_id
url.save()
params = dict()
params["short_url"] = short_id
params['path'] = request.META['HTTP_REFERER']
return render(request, 'base.html', params)
```

让我们来看一下以下术语列表：

+   `get()`方法很简单：它将请求转发到`base.html`文件（我们将很快创建）

+   `post()`方法从请求的 POST 变量中获取长 URL 并设置对象计数，就像短 URL 保存`Url`对象到数据库一样：

```py
params['path'] = request.META['HTTP_REFERER'] 
```

这用于将当前路径传递给视图，以便可以使用锚标记使短 URL 可点击。

这就是这个 URL 对象在数据库中保存的方式：

```py
{ "_id" : ObjectId("548d6ec8e389a24f5ea44258"), "full_url" : "http://sample_long_url", "short_url" : "short_url" } 
```

现在，我们将继续创建`Link()`类，它将接受短 URL 请求并重定向到长 URL：

```py
class Link(View):
def get(self, request, short_url):
url = Url.objects(short_url=short_url)
result = url[0]
return HttpResponseRedirect(result.full_url)
```

`short_url`参数是来自请求 URL 的`short_url`代码：

```py
url = Url.objects(short_url=short_url)
```

前一行查询数据库，检查给定短 URL 的匹配长 URL 是否存在：

```py
return HttpResponseRedirect(result.full_url) 
```

这将重定向请求以从数据库中查找长 URL。

对于视图，我们需要创建的只是`base.html`文件。

由于这个项目的目的不是教你用户界面，我们不会包含任何库，并且会尽可能少地使用 HTML 来制作页面。

`base.html`文件的代码如下：

```py
<!DOCTYPE html>
  <html>
    <head lang="en">
      <meta charset="UTF-8">
      <title>URL Shortner</title>
    </head>
    <body>
      <form action="" method="post">
        {% csrf_token %}
        Long Url:<br>
        <textarea rows="3" cols="80" name="longurl"></textarea>
        <br>
        <input type="submit" value="Get short Url">
      </form>

      <div id="short_url">
      {% if short_url %}
        <span>
          <a href="{{ path }}link/{{ short_url }}" target="_blank">{{ path }}link/{{ short_url }}</a>
        </span>
        {% endif %}
      </div>
    </body>
  </html>
```

这显示了一个带有表单的文本区域，并在提交表单后，在长 URL 下方显示了短链接。

这就是极简主义 URL 缩短器主页的样子：

![存储会话](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-dj-webdev/img/image00313.jpeg)

为了使这个工作，我们现在需要做的就是创建所需的 URL 映射，如下所示：

```py
url_shortner/urlmapping.py

from django.conf.urls import patterns, url
from url.views import Index, Link
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
url(r'^$', Index.as_view()),
url(r'^link/(\w+)/$', Link.as_view()),
)
```

# 摘要

本章的目的是为您准备使用不同数据库创建项目，并为您提供有关数据库迁移以及这些迁移如何工作的基本概念。这不仅将帮助您调试迁移，还可以创建自己的数据迁移脚本，将数据从 JSON 文件或任何其他文件格式直接加载到 Django 应用程序中进行初始化。

本章还为您提供了如何使用 Django 和 MongoDB 设置的基本概念，并且我们还看到了一个小项目演示，随后是在这里使用 MongoDB 扩展 Django 系统的实际应用。
