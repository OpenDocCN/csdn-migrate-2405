# Django2 Web 应用构建指南（二）

> 原文：[`zh.annas-archive.org/md5/18689E1989723338A1936B680A71254B`](https://zh.annas-archive.org/md5/18689E1989723338A1936B680A71254B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：海报、头像和安全性

电影是一种视觉媒体，所以电影数据库至少应该有图片。让用户上传文件可能会带来很大的安全隐患；因此，在本章中，我们将一起讨论这两个主题。

在本章中，我们将做以下事情：

+   为每部电影添加一个允许用户上传图像的文件上传功能

+   检查**开放式 Web 应用安全项目**（**OWASP**）风险前 10 名清单

我们将在进行文件上传时检查安全性的影响。此外，我们将看看 Django 在哪些方面可以帮助我们，在哪些方面我们必须做出谨慎的设计决策。

让我们从向 MyMDB 添加文件上传开始。

# 将文件上传到我们的应用程序

在本节中，我们将创建一个模型，用于表示和管理用户上传到我们网站的文件；然后，我们将构建一个表单和视图来验证和处理这些上传。

# 配置文件上传设置

在我们开始实现文件上传之前，我们需要了解文件上传取决于一些必须在生产和开发中不同的设置。这些设置会影响文件的存储和提供方式。

Django 有两组文件设置：`STATIC_*`和`MEDIA_*`。**静态文件**是我们项目的一部分，由我们开发的文件（例如 CSS 和 JavaScript）。**媒体文件**是用户上传到我们系统的文件。媒体文件不应该受信任，绝对*不*应该被执行。

我们需要在我们的`django/conf/settings.py`中设置两个新的设置：

```py
MEDIA_URL = '/uploaded/'
MEDIA_ROOT = os.path.join(BASE_DIR, '../media_root')
```

`MEDIA_URL`是将提供上传文件的 URL。在开发中，这个值并不太重要，只要它不与我们的视图之一的 URL 冲突即可。在生产中，上传的文件应该从与提供我们应用程序的域名（而不是子域名）不同的域名提供。一个用户的浏览器如果被欺骗执行了来自与我们应用程序相同的域名（或子域名）的文件，那么它将信任该文件的 cookie（包括用户的会话 ID）。所有浏览器的默认策略称为**同源策略**。我们将在第五章 *使用 Docker 部署*中再次讨论这个问题。

`MEDIA_ROOT`是 Django 应该保存代码的目录路径。我们希望确保这个目录不在我们的代码目录下，这样它就不会意外地被检入版本控制，也不会意外地被授予任何慷慨的权限（例如执行权限），我们授予我们的代码库。

在生产中，我们还有其他设置需要配置，比如限制请求体的大小，但这些将作为第五章 *使用 Docker 部署*的一部分来完成。

接下来，让我们创建`media_root`目录：

```py
$ mkdir media_root
$ ls
django                 media_root              requirements.dev.txt
```

太好了！接下来，让我们创建我们的`MovieImage`模型。

# 创建 MovieImage 模型

我们的`MovieImage`模型将使用一个名为`ImageField`的新字段来保存文件，并*尝试*验证文件是否为图像。尽管`ImageField`确实尝试验证字段，但这并不足以阻止一个恶意用户制作一个故意恶意的文件（但会帮助一个意外点击了`.zip`而不是`.png`的用户）。Django 使用`Pillow`库来进行此验证；因此，让我们将`Pillow`添加到我们的要求文件`requirements.dev.txt`中：

```py
Pillow<4.4.0
```

然后，使用`pip`安装我们的依赖项：

```py
$ pip install -r requirements.dev.txt
```

现在，我们可以创建我们的模型：

```py
from uuid import uuid4

from django.conf import settings
from django.db import models

def movie_directory_path_with_uuid(
        instance, filename):
    return '{}/{}'.format(
        instance.movie_id, uuid4())

class MovieImage(models.Model):
    image = models.ImageField(
        upload_to=movie_directory_path_with_uuid)
    uploaded = models.DateTimeField(
        auto_now_add=True)
    movie = models.ForeignKey(
        'Movie', on_delete=models.CASCADE)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE)
```

`ImageField`是`FileField`的一个专门版本，它使用`Pillow`来确认文件是否为图像。`ImageField`和`FileField`与 Django 的文件存储 API 一起工作，该 API 提供了一种存储和检索文件以及读写文件的方式。默认情况下，Django 使用`FileSystemStorage`，它实现了存储 API 以在本地文件系统上存储数据。这对于开发来说已经足够了，但我们将在第五章中探讨替代方案，*使用 Docker 部署*。

我们使用了`ImageField`的`upload_to`参数来指定一个函数来生成上传文件的名称。我们不希望用户能够指定系统中文件的名称，因为他们可能会选择滥用我们用户的信任并让我们看起来很糟糕的名称。我们使用一个函数来将给定电影的所有图片存储在同一个目录中，并使用`uuid4`为每个文件生成一个通用唯一名称（这也避免了名称冲突和处理文件互相覆盖）。

我们还记录了谁上传了文件，这样如果我们发现了一个坏文件，我们就有线索可以找到其他坏文件。

现在让我们进行迁移并应用它：

```py
$ python manage.py makemigrations core
Migrations for 'core':
  core/migrations/0004_movieimage.py
    - Create model MovieImage
$ python manage.py migrate core
Operations to perform:
  Apply all migrations: core
Running migrations:
  Applying core.0004_movieimage... OK
```

接下来，让我们为我们的`MovieImage`模型构建一个表单，并在我们的`MovieDetail`视图中使用它。

# 创建和使用 MovieImageForm

我们的表单将与我们的`VoteForm`非常相似，它将隐藏和禁用`movie`和`user`字段，这些字段对于我们的模型是必要的，但是从客户端信任是危险的。让我们将它添加到`django/core/forms.py`中：

```py
from django import forms

from core.models import MovieImage

class MovieImageForm(forms.ModelForm):

    movie = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=Movie.objects.all(),
        disabled=True
    )

    user = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=get_user_model().
            objects.all(),
        disabled=True,
    )

    class Meta:
        model = MovieImage
        fields = ('image', 'user', 'movie')
```

我们不会用自定义字段或小部件覆盖`image`字段，因为`ModelForm`类将自动提供正确的`<input type="file">`。

现在，我们可以在`MovieDetail`视图中使用它：

```py
from django.views.generic import DetailView

from core.forms import (VoteForm, 
    MovieImageForm,)
from core.models import Movie

class MovieDetail(DetailView):
    queryset = Movie.objects.all_with_related_persons_and_score()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['image_form'] = self.movie_image_form()
        if self.request.user.is_authenticated:
            # omitting VoteForm code.
        return ctx

 def movie_image_form(self):
        if self.request.user.is_authenticated:
            return MovieImageForm()
        return None
```

这次，我们的代码更简单，因为用户*只能*上传新图片，不支持其他操作，这样我们可以始终提供一个空表单。然而，使用这种方法，我们仍然不显示错误消息。丢失错误消息不应被视为最佳实践。

接下来，我们将更新我们的模板以使用我们的新表单和上传的图片。

# 更新`movie_detail.html`以显示和上传图片

我们将需要对`movie_detail.html`模板进行两次更新。首先，我们需要更新我们的`main`模板块，以显示图片列表。其次，我们需要更新我们的`sidebar`模板块，以包含我们的上传表单。

首先让我们更新我们的`main`块：

```py
{% block main %}
  <div class="col" >
    <h1 >{{ object }}</h1 >
    <p class="lead" >
      {{ object.plot }}
    </p >
  </div >
  <ul class="movie-image list-inline" >
    {% for i in object.movieimage_set.all %}
      <li class="list-inline-item" >
          <img src="img/{{ i.image.url }}" >
      </li >
    {% endfor %}
  </ul >
  <p >Directed
    by {{ object.director }}</p >
 {# writers and actors html omitted #}
{% end block %}
```

我们在前面的代码中使用了`image`字段的`url`属性，它返回了`MEDIA_URL`设置与计算出的文件名连接在一起，这样我们的`img`标签就可以正确显示图片。

在`sidebar`块中，我们将添加一个上传新图片的表单：

```py
{% block sidebar %}
  {# rating div omitted #}
  {% if image_form %}
    <div >
      <h2 >Upload New Image</h2 >
      <form method="post"
            enctype="multipart/form-data"
            action="{% url 'core:MovieImageUpload' movie_id=object.id %}" >
        {% csrf_token %}
        {{ image_form.as_p }}
        <p >
          <button
              class="btn btn-primary" >
            Upload
          </button >
        </p >
      </form >
    </div >
  {% endif %}
  {# score and voting divs omitted #}
{% endblock %}
```

这与我们之前的表单非常相似。但是，我们*必须*记得在我们的`form`标签中包含`enctype`属性，以便上传的文件能够正确附加到请求中。

现在我们完成了我们的模板，我们可以创建我们的`MovieImageUpload`视图来保存我们上传的文件。

# 编写 MovieImageUpload 视图

我们倒数第二步将是在`django/core/views.py`中添加一个视图来处理上传的文件：

```py
from django.contrib.auth.mixins import (
    LoginRequiredMixin) 
from django.views.generic import CreateView

from core.forms import MovieImageForm

class MovieImageUpload(LoginRequiredMixin, CreateView):
    form_class = MovieImageForm

    def get_initial(self):
        initial = super().get_initial()
        initial['user'] = self.request.user.id
        initial['movie'] = self.kwargs['movie_id']
        return initial

    def render_to_response(self, context, **response_kwargs):
        movie_id = self.kwargs['movie_id']
        movie_detail_url = reverse(
            'core:MovieDetail',
            kwargs={'pk': movie_id})
        return redirect(
            to=movie_detail_url)

    def get_success_url(self):
        movie_id = self.kwargs['movie_id']
        movie_detail_url = reverse(
            'core:MovieDetail',
            kwargs={'pk': movie_id})
        return movie_detail_url
```

我们的视图再次将所有验证和保存模型的工作委托给`CreateView`和我们的表单。我们从请求的`user`属性中检索`user.id`属性（因为`LoginRequiredMixin`类的存在，我们可以确定用户已登录），并从 URL 中获取电影 ID，然后将它们作为初始参数传递给表单，因为`MovieImageForm`的`user`和`movie`字段是禁用的（因此它们会忽略请求体中的值）。保存和重命名文件的工作都由 Django 的`ImageField`完成。

最后，我们可以更新我们的项目，将请求路由到我们的`MovieImageUpload`视图并提供我们上传的文件。

# 将请求路由到视图和文件

在这一部分，我们将更新`core`的`URLConf`，将请求路由到我们的新`MovieImageUpload`视图，并看看我们如何在开发中提供我们上传的图片。我们将看看如何在生产中提供上传的图片第五章，*使用 Docker 部署*。

为了将请求路由到我们的`MovieImageUpload`视图，我们将更新`django/core/urls.py`：

```py
from django.urls import path

from . import views

app_name = 'core'
urlpatterns = [
    # omitted existing paths
    path('movie/<int:movie_id>/image/upload',
         views.MovieImageUpload.as_view(),
         name='MovieImageUpload'),
    # omitted existing paths
]
```

我们像往常一样添加我们的`path()`函数，并确保我们记得它需要一个名为`movie_id`的参数。

现在，Django 将知道如何路由到我们的视图，但它不知道如何提供上传的文件。

在开发中为了提供上传的文件，我们将更新`django/config/urls.py`：

```py
from django.conf import settings
from django.conf.urls.static import (
    static, )
from django.contrib import admin
from django.urls import path, include

import core.urls
import user.urls

MEDIA_FILE_PATHS = static(
    settings.MEDIA_URL,
    document_root=settings.MEDIA_ROOT)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/', include(
        user.urls, namespace='user')),
    path('', include(
        core.urls, namespace='core')),
] + MEDIA_FILE_PATHS
```

Django 提供了`static()`函数，它将返回一个包含单个`path`对象的列表，该对象将路由以`MEDIA_URL`开头的任何请求到`document_root`内的文件。这将为我们在开发中提供一种服务上传的图像文件的方法。这个功能不适合生产环境，如果`settings.DEBUG`为`False`，`static()`将返回一个空列表。

现在我们已经看到了 Django 核心功能的大部分，让我们讨论它如何与**开放 Web 应用程序安全项目**（**OWASP**）的十大最关键安全风险（OWASP Top 10）列表相关。

# OWASP Top 10

OWASP 是一个专注于通过为 Web 应用程序提供公正的实用安全建议来使*安全可见*的非营利慈善组织。OWASP 的所有材料都是免费和开源的。自 2010 年以来，OWASP 征求信息安全专业人员的数据，并用它来开发 Web 应用程序安全中最关键的十大安全风险的列表（OWASP Top 10）。尽管这个列表并不声称列举所有问题（它只是前十名），但它是基于安全专业人员在野外进行渗透测试和对全球公司的生产或开发中的真实代码进行代码审计时所看到的情况。

Django 被开发为尽可能地减少和避免这些风险，并在可能的情况下，为开发人员提供工具来最小化风险。

让我们列举 2013 年的 OWASP Top 10（撰写时的最新版本，2017 RC1 已被拒绝），并看看 Django 如何帮助我们减轻每个风险。

# A1 注入

自 OWASP Top 10 创建以来，这一直是头号问题。**注入**意味着用户能够注入由我们的系统或我们使用的系统执行的代码。例如，SQL 注入漏洞让攻击者在我们的数据库中执行任意 SQL 代码，这可能导致他们绕过我们几乎所有的控制和安全措施（例如，让他们作为管理员用户进行身份验证；SQL 注入漏洞可能导致 shell 访问）。对于这个问题，特别是对于 SQL 注入，最好的解决方案是使用参数化查询。

Django 通过提供`QuerySet`类来保护我们免受 SQL 注入的侵害。`QuerySet`确保它发送的所有查询都是参数化的，以便数据库能够区分我们的 SQL 代码和查询中的值。使用参数化查询将防止 SQL 注入。

然而，Django 允许使用`QuerySet.raw()`和`QuerySet.extra()`进行原始 SQL 查询。这两种方法都支持参数化查询，但开发人员必须确保他们**永远不要**使用来自用户的值通过字符串格式化（例如`str.format`）放入 SQL 查询，而是**始终**使用参数。

# A2 破坏身份验证和会话管理

**破坏身份验证**和**会话管理**指的是攻击者能够身份验证为另一个用户或接管另一个用户的会话的风险。

Django 在这里以几种方式保护我们，如下：

+   Django 的`auth`应用程序始终对密码进行哈希和盐处理，因此即使数据库被破坏，用户密码也无法被合理地破解。

+   Django 支持多种*慢速*哈希算法（例如 Argon2 和 Bcrypt），这使得暴力攻击变得不切实际。这些算法并不是默认提供的（Django 默认使用`PBDKDF2`），因为它们依赖于第三方库，但可以使用`PASSWORD_HASHERS`设置进行配置。

+   Django 会话 ID 默认情况下不会在 URL 中公开，并且登录后会更改会话 ID。

然而，Django 的加密功能始终以`settings.SECRET_KEY`字符串为种子。将`SECRET_KEY`的生产值检入版本控制应被视为安全问题。该值不应以明文形式共享，我们将在第五章 *使用 Docker 部署*中讨论。

# A3 跨站脚本攻击

**跨站脚本攻击**（**XSS**）是指攻击者能够让 Web 应用显示攻击者创建的 HTML 或 JavaScript，而不是开发者创建的 HTML 或 JavaScript。这种攻击非常强大，因为如果攻击者可以执行任意 JavaScript，那么他们可以发送请求，这些请求看起来与用户的真实请求无法区分。

Django 默认情况下会对模板中的所有变量进行 HTML 编码保护。

然而，Django 确实提供了将文本标记为安全的实用程序，这将导致值不被编码。这些应该谨慎使用，并充分了解如果滥用会造成严重安全后果。

# A4 不安全的直接对象引用

**不安全的直接对象引用**是指我们在资源引用中不安全地暴露实现细节，而没有保护资源免受非法访问/利用。例如，我们电影详细页面的`<img>`标签的`src`属性中的路径直接映射到文件系统中的文件。如果用户操纵 URL，他们可能访问他们本不应访问的图片，从而利用漏洞。或者，使用在 URL 中向用户公开的自动递增主键可以让恶意用户遍历数据库中的所有项目。这种风险的影响高度取决于暴露的资源。

Django 通过不将路由路径与视图耦合来帮助我们。我们可以根据主键进行模型查找，但并不是必须这样做，我们可以向我们的模型添加额外的字段（例如`UUIDField`）来将表的主键与 URL 中使用的 ID 解耦。在第三部分的 Mail Ape 项目中，我们将看到如何使用`UUIDField`类作为模型的主键。

# A5 安全配置错误

**安全配置错误**指的是当适当的安全机制被不当部署时所产生的风险。这种风险处于开发和运营的边界，并需要两个团队合作。例如，如果我们在生产环境中以`DEBUG`设置为`True`运行我们的 Django 应用，我们将面临在没有任何错误的情况下向公众暴露过多信息的风险。

Django 通过合理的默认设置以及 Django 项目网站上的技术和主题指南来帮助我们。Django 社区也很有帮助——他们在邮件列表和在线博客上发布信息，尽管在线博客文章应该持怀疑态度，直到你验证了它们的声明。

# A6 敏感数据暴露

**敏感数据暴露**是指敏感数据可能在没有适当授权的情况下被访问的风险。这种风险不仅仅是攻击者劫持用户会话，还包括备份存储方式、加密密钥轮换方式，以及最重要的是哪些数据实际上被视为*敏感*。这些问题的答案是项目/业务特定的。

Django 可以通过配置为仅通过 HTTPS 提供页面来帮助减少来自攻击者使用网络嗅探的意外暴露风险。

然而，Django 并不直接提供加密，也不管理密钥轮换、日志、备份和数据库本身。有许多因素会影响这种风险，这些因素超出了 Django 的范围。

# A7 缺少功能级别的访问控制

虽然 A6 指的是数据被暴露，但缺少功能级别的访问控制是指功能受到不充分保护的风险。考虑我们的`UpdateVote`视图——如果我们忘记了`LoginRequiredMixin`类，那么任何人都可以发送 HTTP 请求并更改我们用户的投票。

Django 的`auth`应用程序提供了许多有用的功能来减轻这些问题，包括超出本项目范围的权限系统，以及混合和实用程序，使使用这些权限变得简单（例如，`LoginRequiredMixin`和`PermissionRequiredMixin`）。

然而，我们需要适当地使用 Django 的工具来完成手头的工作。

# A8 跨站点请求伪造（CSRF）

**CSRF**（发音为*see surf*）是 OWASP 十大中技术上最复杂的风险。CSRF 依赖于一个事实，即每当浏览器从服务器请求任何资源时，它都会自动发送与该域关联的所有 cookie。恶意攻击者可能会欺骗我们已登录的用户之一，让其查看第三方网站上的页面（例如`malicious.example.org`），例如，带有指向我们网站的 URL 的`img`标签的`src`属性（例如，`mymdb.example.com`）。当用户的浏览器看到`src`时，它将向该 URL 发出`GET`请求，并发送与我们网站相关的所有 cookie（包括会话 ID）。

风险在于，如果我们的 Web 应用程序收到`GET`请求，它将进行用户未打算的修改。减轻此风险的方法是确保进行任何进行修改的操作（例如，`UpdateVote`）都具有唯一且不可预测的值（CSRF 令牌），只有我们的系统知道，这确认了用户有意使用我们的应用程序执行此操作。

Django 在很大程度上帮助我们减轻这种风险。Django 提供了`csrf_token`标签，使向表单添加 CSRF 令牌变得容易。Django 负责添加匹配的 cookie（用于验证令牌），并确保任何使用的动词不是`GET`、`HEAD`、`OPTIONS`或`TRACE`的请求都有有效的 CSRF 令牌进行处理。Django 进一步通过使其所有的通用编辑视图（`EditView`、`CreateView`、`DeleteView`和`FormView`）仅在`POST`上执行修改操作，而不是在`GET`上，来帮助我们做正确的事情。

然而，Django 不能拯救我们免受自身的伤害。如果我们决定禁用此功能或编写具有`GET`副作用的视图，Django 无法帮助我们。

# A9 使用已知漏洞的组件

一条链只有其最薄弱的一环那么强，有时，项目可能在其依赖的框架和库中存在漏洞。

Django 项目有一个安全团队，接受安全问题的机密报告，并有安全披露政策，以使社区了解影响其项目的问题。一般来说，Django 发布后会在首次发布后的 16 个月内获得支持（包括安全更新），但**长期支持**（**LTS**）发布将获得 3 年的支持（下一个 LTS 发布将是 Django 2.2）。

然而，Django 不会自动更新自身，也不会强制我们运行最新版本。每个部署都必须自行管理这一点。

# A10 未经验证的重定向和转发

如果我们的网站可以自动将用户重定向/转发到第三方网站，那么我们的网站就有可能被用来欺骗用户被转发到恶意网站。

Django 通过确保`LoginView`的`next`参数只会转发用户的 URL，这些 URL 是我们项目的一部分，来保护我们。

然而，Django 不能保护我们免受自身的伤害。我们必须确保我们从不使用用户提供的未经验证的数据作为 HTTP 重定向或转发的基础。

# 总结

在本节中，我们已更新我们的应用程序，以便用户上传与电影相关的图像，并审查了 OWASP 十大。我们介绍了 Django 如何保护我们，以及我们需要保护自己的地方。

接下来，我们将构建一个前十名电影列表，并看看如何使用缓存来避免每次扫描整个数据库。


# 第四章：在前 10 部电影中进行缓存

在本章中，我们将使用我们的用户投票的票数来构建 MyMDB 中前 10 部电影的列表。为了确保这个受欢迎的页面保持快速加载，我们将看看帮助我们优化网站的工具。最后，我们将看看 Django 的缓存 API 以及如何使用它来优化我们的项目。

在本章中，我们将做以下事情：

+   使用聚合查询创建一个前 10 部电影列表

+   了解 Django 的工具来衡量优化

+   使用 Django 的缓存 API 来缓存昂贵操作的结果

让我们从制作我们的前 10 部电影列表页面开始。

# 创建前 10 部电影列表

为了构建我们的前 10 部电影列表，我们将首先创建一个新的`MovieManager`方法，然后在新的视图和模板中使用它。我们还将更新基本模板中的顶部标题，以便从每个页面轻松访问列表。

# 创建 MovieManager.top_movies()

我们的`MovieManager`类需要能够返回一个由我们的用户投票选出的最受欢迎电影的`QuerySet`对象。我们使用了一个天真的受欢迎度公式，即![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-dj20-webapp/img/e7400a23-0fe5-4725-8751-68f43e1455d2.png)票数减去![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-dj20-webapp/img/933b0552-c3d0-4633-bbf3-87a483749b81.png)票数的总和。就像在第二章*将用户添加到 MyMDB*中一样，我们将使用`QuerySet.annotate()`方法来进行聚合查询以计算投票数。

让我们将我们的新方法添加到`django/core/models.py`：

```py
from django.db.models.aggregates import (
    Sum
)

class MovieManager(models.Manager):

    # other methods omitted

    def top_movies(self, limit=10):
        qs = self.get_queryset()
        qs = qs.annotate(
            vote_sum=Sum('vote__value'))
        qs = qs.exclude(
            vote_sum=None)
        qs = qs.order_by('-vote_sum')
        qs = qs[:limit]
        return qs
```

我们按照它们的票数总和（降序）对结果进行排序，以获得我们的前 10 部电影列表。然而，我们面临的问题是，一些电影没有投票，因此它们的`vote_sum`值将为`NULL`。不幸的是，`NULL`将首先被 Postgres 排序。我们将通过添加一个约束来解决这个问题，即没有投票的电影，根据定义，不会成为前 10 部电影之一。我们使用`QuerySet.exclude`（与`QuerySet.filter`相反）来删除没有投票的电影。

这是我们第一次看到一个`QuerySet`对象被切片。除非提供步长，否则`QuerySet`对象不会被切片评估（例如，`qs [10:20:2]`会使`QuerySet`对象立即被评估并返回第 10、12、14、16 和 18 行）。

现在我们有了一个合适的`Movie`模型实例的`QuerySet`对象，我们可以在视图中使用`QuerySet`对象。

# 创建 TopMovies 视图

由于我们的`TopMovies`视图需要显示一个列表，我们可以像以前一样使用 Django 的`ListView`。让我们更新`django/core/views.py`：

```py
from django.views.generic import ListView
from core.models import Movie

class TopMovies(ListView):
    template_name = 'core/top_movies_list.html'
    queryset = Movie.objects.top_movies(
        limit=10)
```

与以前的`ListView`类不同，我们需要指定一个`template_name`属性。否则，`ListView`将尝试使用`core/movie_list.html`，这是`MovieList`视图使用的。

接下来，让我们创建我们的模板。

# 创建 top_movies_list.html 模板

我们的前 10 部电影页面不需要分页，所以模板非常简单。让我们创建`django/core/templates/core/top_movies_list.html`：

```py
{% extends "base.html" %}

{% block title %}
  Top 10 Movies
{% endblock %}

{% block main %}
  <h1 >Top 10 Movies</h1 >
  <ol >
    {% for movie in object_list %}
      <li >
        <a href="{% url "core:MovieDetail" pk=movie.id %}" >
          {{ movie }}
        </a >
      </li >
    {% endfor %}
  </ol >
{% endblock %}
```

扩展`base.html`，我们将重新定义两个模板`block`标签。新的`title`模板`block`有我们的新标题。`main`模板`block`列出了`object_list`中的电影，包括每部电影的链接。

最后，让我们更新`django/templates/base.html`，以包括一个链接到我们的前 10 部电影页面：

```py
{# rest of template omitted #}
<div class="mymdb-masthead">
  <div class="container">
    <nav class="nav">
       {# skipping other nav items #}
       <a
          class="nav-link"
          href="{% url 'core:TopMovies' %}"
        >
        Top 10 Movies
       </a>
       {# skipping other nav items #}
      </nav>
   </div>
</div>
{# rest of template omitted #}
```

现在，让我们在我们的 URLConf 中添加一个`path()`对象，这样 Django 就可以将请求路由到我们的`TopMovies`视图。

# 添加到 TopMovies 的路径

像往常一样，我们需要添加一个`path()`来帮助 Django 将请求路由到我们的视图。让我们更新`django/core/urls.py`：

```py
from django.urls import path

from . import views

app_name = 'core'
urlpatterns = [
    path('movies',
         views.MovieList.as_view(),
         name='MovieList'),
    path('movies/top',
         views.TopMovies.as_view(),
         name="TopMovies"),
    # other paths omitted
 ]
```

有了这个，我们就完成了。现在我们在 MyMDB 上有了一个前 10 部电影页面。

然而，浏览所有的投票意味着扫描项目中最大的表。让我们看看如何优化我们的项目。

# 优化 Django 项目

如何优化 Django 项目没有单一正确答案，因为不同的项目有不同的约束。要成功，重要的是要清楚你要优化什么，以及在硬数据中使用什么，而不是直觉。

清楚地了解我们要进行优化的内容很重要，因为优化通常涉及权衡。您可能希望进行优化的一些约束条件如下：

+   响应时间

+   Web 服务器内存

+   Web 服务器 CPU

+   数据库内存

一旦您知道要进行优化的内容，您将需要一种方法来测量当前性能和优化代码的性能。优化代码通常比未优化代码更复杂。在承担复杂性之前，您应始终确认优化是否有效。

Django 只是 Python，因此您可以使用 Python 分析器来测量性能。这是一种有用但复杂的技术。讨论 Python 分析的细节超出了本书的范围。然而，重要的是要记住 Python 分析是我们可以使用的有用工具。

让我们看看一些特定于 Django 的测量性能的方法。

# 使用 Django 调试工具栏

Django 调试工具栏是一个第三方包，可以在浏览器中提供大量有用的调试信息。工具栏由一系列面板组成。每个面板提供不同的信息集。

一些最有用的面板（默认情况下启用）如下：

+   请求面板：它显示与请求相关的信息，包括处理请求的视图、接收到的参数（从路径中解析出来）、cookie、会话数据以及请求中的 GET/POST 数据。

+   SQL 面板：显示进行了多少查询，它们的执行时间线以及在查询上运行`EXPLAIN`的按钮。数据驱动的 Web 应用程序通常会因其数据库查询而变慢。

+   模板面板：显示已呈现的模板及其上下文。

+   日志面板：它显示视图产生的任何日志消息。我们将在下一节讨论更多关于日志记录的内容。

配置文件面板是一个高级面板，默认情况下不启用。该面板在您的视图上运行分析器并显示结果。该面板带有一些注意事项，这些注意事项在 Django 调试工具栏在线文档中有解释（[`django-debug-toolbar.readthedocs.io/en/stable/panels.html#profiling`](https://django-debug-toolbar.readthedocs.io/en/stable/panels.html#profiling)）。

Django 调试工具栏在开发中很有用，但不应在生产中运行。默认情况下，只有在`DEBUG = True`时才能工作（这是您在生产中绝对不能使用的设置）。

# 使用日志记录

Django 使用 Python 的内置日志系统，您可以使用`settings.LOGGING`进行配置。它使用`DictConfig`进行配置，如 Python 文档中所述。

作为一个复习，这是 Python 的日志系统的工作原理。该系统由*记录器*组成，它们从我们的代码接收*消息*和*日志级别*（例如`DEBUG`和`INFO`）。如果记录器被配置为不过滤掉该日志级别（或更高级别）的消息，它将创建一个*日志记录*，并将其传递给所有其*处理程序*。处理程序将检查它是否与处理程序的日志级别匹配，然后它将格式化日志记录（使用*格式化程序*）并发出消息。不同的处理程序将以不同的方式发出消息。`StreamHandler`将写入流（默认为`sys.stderr`），`SysLogHandler`写入`SysLog`，`SMTPHandler`发送电子邮件。

通过记录操作所需的时间，您可以对需要进行优化的内容有一个有意义的了解。使用正确的日志级别和处理程序，您可以在生产中测量资源消耗。

# 应用性能管理

应用性能管理（APM）是指作为应用服务器一部分运行并跟踪执行操作的服务。跟踪结果被发送到报告服务器，该服务器将所有跟踪结果合并，并可以为您提供对生产服务器性能的代码行级洞察。这对于大型和复杂的部署可能有所帮助，但对于较小、较简单的 Web 应用程序可能过于复杂。

# 本节的快速回顾

在本节中，我们回顾了在实际开始优化之前知道要优化什么的重要性。我们还看了一些工具，帮助我们衡量我们的优化是否成功。

接下来，我们将看看如何使用 Django 的缓存 API 解决一些常见的性能问题。

# 使用 Django 的缓存 API

Django 提供了一个开箱即用的缓存 API。在`settings.py`中，您可以配置一个或多个缓存。缓存可用于存储整个站点、单个页面的响应、模板片段或任何可 pickle 的对象。Django 提供了一个可以配置多种后端的单一 API。

在本节中，我们将执行以下功能：

+   查看 Django 缓存 API 的不同后端

+   使用 Django 缓存页面

+   使用 Django 缓存模板片段

+   使用 Django 缓存`QuerySet`

我们不会研究*下游*缓存，例如**内容交付网络**（**CDN**）或代理缓存。这些不是 Django 特有的，有各种各样的选择。一般来说，这些类型的缓存将依赖于 Django 已发送的相同`VARY`标头。

接下来，让我们看看如何配置缓存 API 的后端。

# 检查 Django 缓存后端之间的权衡

不同的后端可能适用于不同的情况。但是，缓存的黄金法则是它们必须比它们缓存的源*更快*，否则您会使应用程序变慢。决定哪个后端适合哪个任务最好是通过对项目进行仪器化来完成的，如前一节所讨论的。不同的后端有不同的权衡。

# 检查 Memcached 的权衡

**Memcached**是最受欢迎的缓存后端，但仍然存在需要评估的权衡。Memcached 是一个用于小数据的内存键值存储，可以由多个客户端（例如 Django 进程）使用一个或多个 Memcached 主机进行共享。但是，Memcached 不适合缓存大块数据（默认情况下为 1 MB 的数据）。另外，由于 Memcached 全部在内存中，如果进程重新启动，则整个缓存将被清除。另一方面，Memcached 因为快速和简单而保持受欢迎。

Django 带有两个 Memcached 后端，取决于您想要使用的`Memcached`库：

+   `django.core.cache.backends.memcached.MemcachedCache`

+   `django.core.cache.backends.memcached.PyLibMCCache`

您还必须安装适当的库（`python-memcached`或`pylibmc`）。要将您的 Memcached 服务器的地址设置为`LOCATION`，请将其设置为格式为`address:PORT`的列表（例如，`['memcached.example.com:11211',]`）。示例配置在本节末尾列出。

在*开发*和*测试*中使用 Memcached 可能不会很有用，除非您有相反的证据（例如，您需要复制一个复杂的错误）。

Memcached 在生产环境中很受欢迎，因为它快速且易于设置。它通过让所有 Django 进程连接到相同的主机来避免数据重复。但是，它使用大量内存（并且在可用内存用尽时会迅速且不良地降级）。另外，注意运行另一个服务的操作成本是很重要的。

以下是使用`memcached`的示例配置：

```py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.memcached.PyLibMCCache',
        'LOCATION':  [
            '127.0.0.1:11211',
        ],
    }
}
```

# 检查虚拟缓存的权衡

**虚拟缓存**（`django.core.cache.backends.dummy.DummyCache`）将检查密钥是否有效，但否则不执行任何操作。

当您想确保您确实看到代码更改的结果而不是缓存时，此缓存在*开发*和*测试*中可能很有用。

不要在*生产*中使用此缓存，因为它没有效果。

以下是一个虚拟缓存的示例配置：

```py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}
```

# 检查本地内存缓存的权衡

**本地内存缓存**（`django.core.cache.backends.locmem.LocMemCache`）使用 Python 字典作为全局内存缓存。如果要使用多个单独的本地内存缓存，请在`LOCATION`中给出每个唯一的字符串。它被称为本地缓存，因为它是每个进程的本地缓存。如果您正在启动多个进程（就像在生产中一样），那么不同进程处理请求时可能会多次缓存相同的值。这种低效可能更简单，因为它不需要另一个服务。

这是一个在*开发*和*测试*中使用的有用缓存，以确认您的代码是否正确缓存。

您可能想在*生产*中使用这个，但要记住不同进程缓存相同数据的潜在低效性。

以下是本地内存缓存的示例配置：

```py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'defaultcache',

    },
    'otherCache': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'othercache',
    }
}
```

# 检查基于文件的缓存权衡

Django 的**基于文件的缓存**（`django.core.cache.backends.filebased.FileBasedCache`）使用指定的`LOCATION`目录中的压缩文件来缓存数据。使用文件可能看起来很奇怪；缓存不应该是*快速*的，而文件是*慢*的吗？答案再次取决于您要缓存的内容。例如，对外部 API 的网络请求可能比本地磁盘慢。请记住，每个服务器都将有一个单独的磁盘，因此如果您运行一个集群，数据将会有一些重复。

除非内存受限，否则您可能不想在*开发*或*测试*中使用这个。

您可能想在生产中缓存特别大或请求速度慢的资源。请记住，您应该给服务器进程写入`LOCATION`目录的权限。此外，请确保为缓存给服务器提供足够的磁盘空间。

以下是使用基于文件的缓存的示例配置：

```py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': os.path.join(BASE_DIR, '../file_cache'),
    }
}
```

# 检查数据库缓存权衡

**数据库缓存**后端（`django.core.cache.backends.db.DatabaseCache`）使用数据库表（在`LOCATION`中命名）来存储缓存。显然，如果您的数据库速度很快，这将效果最佳。根据情况，即使在缓存数据库查询结果时，这也可能有所帮助，如果查询复杂但单行查找很快。这有其优势，因为缓存不像内存缓存那样是短暂的，可以很容易地在进程和服务器之间共享（如 Memcached）。

数据库缓存表不是由迁移管理的，而是由`manage.py`命令管理，如下所示：

```py
$ cd django
$ python manage.py createcachetable
```

除非您想在*开发*或*测试*中复制您的生产环境，否则您可能不想使用这个。

如果您的测试证明它是合适的，您可能想在*生产*中使用这个。请记住考虑增加的数据库负载对性能的影响。

以下是使用数据库缓存的示例配置：

```py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.db.DatabaseCache',
        'LOCATION': 'django_cache_table',
    }
}
```

# 配置本地内存缓存

在我们的情况下，我们将使用一个具有非常低超时的本地内存缓存。这意味着我们在编写代码时大多数请求将跳过缓存（旧值（如果有）将已过期），但如果我们快速点击刷新，我们将能够确认我们的缓存正在工作。

让我们更新`django/config/settings.py`以使用本地内存缓存：

```py
 CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'default-locmemcache',
        'TIMEOUT': 5, # 5 seconds
    }
 }
```

尽管我们可以有多个配置不同的缓存，但默认缓存的名称应为`'default'`。

`Timeout`是值在被清除（移除/忽略）之前在缓存中保留的时间（以秒为单位）。如果`Timeout`为`None`，则该值将被视为永不过期。

现在我们已经配置了缓存，让我们缓存`MovieList`页面。

# 缓存电影列表页面

我们将假设`MovieList`页面对我们来说非常受欢迎且昂贵。为了降低提供这些请求的成本，我们将使用 Django 来缓存整个页面。

Django 提供了装饰器（函数）`django.views.decorators.cache.cache_page`，它可以用来缓存单个页面。这是一个装饰器而不是一个 mixin，可能看起来有点奇怪。当 Django 最初发布时，它没有 **基于类的视图**（**CBVs**），只有 **基于函数的视图**（**FBVs**）。随着 Django 的成熟，很多代码切换到使用 CBVs，但仍然有一些功能实现为 FBV 装饰器。

在 CBVs 中，有几种不同的使用函数装饰器的方式。我们的方法是构建我们自己的 mixin。CBVs 的很多功能来自于能够将新行为混入到现有类中的能力。了解如何做到这一点是一项有用的技能。

# 创建我们的第一个 mixin – CachePageVaryOnCookieMixin

让我们在 `django/core/mixins.py` 中创建一个新的类：

```py
from django.core.cache import caches
from django.views.decorators.cache import (
    cache_page)

class CachePageVaryOnCookieMixin:
    """
    Mixin caching a single page.

    Subclasses can provide these attributes:

    `cache_name` - name of cache to use.
    `timeout` - cache timeout for this
    page. When not provided, the default
    cache timeout is used. 
    """
    cache_name = 'default'

    @classmethod
    def get_timeout(cls):
        if hasattr(cls, 'timeout'):
            return cls.timeout
        cache = caches[cls.cache_name]
        return cache.default_timeout

    @classmethod
    def as_view(cls, *args, **kwargs):
        view = super().as_view(
            *args, **kwargs)
        view = vary_on_cookie(view)
        view = cache_page(
            timeout=cls.get_timeout(),
            cache=cls.cache_name,
        )(view)
        return view
```

我们的新 mixin 覆盖了我们在 URLConfs 中使用的 `as_view()` 类方法，并使用 `vary_on_cookie()` 和 `cache_page()` 装饰器装饰视图。这实际上就像我们在 `as_view()` 方法上使用我们的函数装饰器一样。

让我们先看看 `cache_page()` 装饰器。`cache_page()` 需要一个 `timeout` 参数，并且可以选择接受一个 `cache` 参数。`timeout` 是缓存页面应该过期并且必须重新缓存之前的时间（以秒为单位）。我们的默认超时值是我们正在使用的缓存的默认值。子类化 `CachePageVaryOnCookieMixin` 的类可以提供一个新的 `timeout` 属性，就像我们的 `MovieList` 类提供了一个 `model` 属性一样。`cache` 参数期望所需缓存的字符串名称。我们的 mixin 被设置为使用 `default` 缓存，但通过引用一个类属性，这也可以被子类更改。

当缓存一个页面，比如 `MoveList`，我们必须记住，对于不同的用户，生成的页面是不同的。在我们的情况下，`MovieList` 的头对已登录用户（显示 *注销* 链接）和已注销用户（显示 *登录* 和 *注册* 链接）是不同的。Django 再次为我们提供了 `vary_on_cookie()` 装饰器。

`vary_on_cookie()` 装饰器将一个 `VARY cookie` 头添加到响应中。`VARY` 头被缓存（包括下游缓存和 Django 的缓存）用来告诉它们有关该资源的变体。`VARY cookie` 告诉缓存，每个不同的 cookie/URL 对都是不同的资源，应该分别缓存。这意味着已登录用户和已注销用户将看到不同的页面，因为它们将有不同的 cookie。

这对我们的命中率（缓存被 *命中* 而不是重新生成资源的比例）有重要影响。命中率低的缓存将几乎没有效果，因为大多数请求将 *未命中* 缓存，并导致处理请求。

在我们的情况下，我们还使用 cookie 进行 CSRF 保护。虽然会话 cookie 可能会降低命中率一点，具体取决于情况（查看用户的活动以确认），但 CSRF cookie 几乎是致命的。CSRF cookie 的性质是经常变化，以便攻击者无法预测。如果那个不断变化的值与许多请求一起发送，那么很少能被缓存。幸运的是，我们可以将我们的 CSRF 值从 cookie 移出，并将其存储在服务器端会话中，只需通过 `settings.py` 进行更改。

为您的应用程序决定正确的 CSRF 策略可能是复杂的。例如，AJAX 应用程序将希望通过标头添加 CSRF 令牌。对于大多数站点，默认的 Django 配置（使用 cookie）是可以的。如果您需要更改它，值得查看 Django 的 CSRF 保护文档（[`docs.djangoproject.com/en/2.0/ref/csrf/`](https://docs.djangoproject.com/en/2.0/ref/csrf/)）。

在 `django/conf/settings.py` 中，添加以下代码：

```py
CSRF_USE_SESSIONS = True
```

现在，Django 不会将 CSRF 令牌发送到 cookie 中，而是将其存储在用户的会话中（存储在服务器上）。

如果用户已经有 CSRF cookie，它们将被忽略；但是，它仍然会对命中率产生抑制作用。在生产环境中，您可能希望考虑添加一些代码来删除这些 CSRF cookie。

现在我们有了一种轻松混合缓存行为的方法，让我们在`MovieList`视图中使用它。

# 使用 CachePageVaryOnCookieMixin 与 MovieList

让我们在`django/core/views.py`中更新我们的视图：

```py
from django.views.generic import ListView
from core.mixins import (
    VaryCacheOnCookieMixin)

class MovieList(VaryCacheOnCookieMixin, ListView):
    model = Movie
    paginate_by = 10

    def get_context_data(self, **kwargs):
        # omitted due to no change
```

现在，当`MovieList`收到路由请求时，`cache_page`将检查它是否已被缓存。如果已经被缓存，Django 将返回缓存的响应，而不做任何其他工作。如果没有被缓存，我们常规的`MovieList`视图将创建一个新的响应。新的响应将添加一个`VARY cookie`头，然后被缓存。

接下来，让我们尝试在模板中缓存我们的前 10 部电影列表的一部分。

# 使用`{% cache %}`缓存模板片段

有时，页面加载缓慢是因为我们模板的某个部分很慢。在本节中，我们将看看如何通过缓存模板的片段来解决这个问题。例如，如果您使用的标签需要很长时间才能解析（比如，因为它发出了网络请求），那么它将减慢使用该标签的任何页面。如果无法优化标签本身，将模板中的结果缓存可能就足够了。

通过编辑`django/core/templates/core/top_movies.html`来缓存我们渲染的前 10 部电影列表：

```py
{% extends "base.html" %}
{% load cache %}

{% block title %}
  Top 10 Movies
{% endblock %}

{% block main %}
  <h1 >Top 10 Movies</h1 >
  {% cache 300 top10 %}
  <ol >
    {% for movie in object_list %}
      <li >
        <a href="{% url "core:MovieDetail" pk=movie.id %}" >
          {{ movie }}
        </a >
      </li >
    {% endfor %}
  </ol >
  {% endcache %}
{% endblock %}
```

这个块向我们介绍了`{% load %}`标签和`{% cache %}`标签。

`{% load %}`标签用于加载标签和过滤器的库，并使它们可用于模板中使用。一个库可以提供一个或多个标签和/或过滤器。例如，`{% load humanize %}`加载标签和过滤器，使值看起来更人性化。在我们的情况下，`{% load cache %}`只提供了`{% cache %}`标签。

`{% cache 300 top10 %}`将在提供的秒数下缓存标签的主体，并使用提供的键。第二个参数必须是一个硬编码的字符串（而不是一个变量），但如果片段需要有变体，我们可以提供更多的参数（例如，`{% cache 300 mykey request.user.id %}`为每个用户缓存一个单独的片段）。该标签将使用`default`缓存，除非最后一个参数是`using='cachename'`，在这种情况下，将使用命名缓存。

使用`{% cache %}`进行缓存发生在不同的级别，而不是使用`cache_page`和`vary_on_cookie`。视图中的所有代码仍将被执行。视图中的任何缓慢代码仍将减慢我们的速度。缓存模板片段只解决了我们模板代码中一个非常特定的缓慢片段的问题。

由于`QuerySets`是懒惰的，通过将我们的`for`循环放在`{% cache %}`中，我们避免了评估`QuerySet`。如果我们想缓存一个值以避免查询它，如果我们在视图中这样做，我们的代码会更清晰。

接下来，让我们看看如何使用 Django 的缓存 API 缓存对象。

# 使用对象的缓存 API

Django 的缓存 API 最精细的用法是存储与 Python 的`pickle`序列化模块兼容的对象。我们将在这里看到的`cache.get()`/`cache.set()`方法在`cache_page()`装饰器和`{% cache %}`标签内部使用。在本节中，我们将使用这些方法来缓存`Movie.objects.top_movies()`返回的`QuerySet`。

方便的是，`QuerySet`对象是可 pickle 的。当`QuerySets`被 pickled 时，它将立即被评估，并且生成的模型将存储在`QuerySet`的内置缓存中。在 unpickling 一个`QuerySet`时，我们可以迭代它而不会引起新的查询。如果`QuerySet`有`select_related`或`prefetch_related`，那些查询将在 pickling 时执行，而在 unpickling 时不会重新运行。

让我们从`top_movies_list.html`中删除`{% cache %}`标签，而是更新`django/core/views.py`：

```py
import django
from django.core.cache import cache
from django.views.generic import ListView

from core.models import Movie

class TopMovies(ListView):
    template_name = 'core/top_movies_list.html'

    def get_queryset(self):
        limit = 10
        key = 'top_movies_%s' % limit
        cached_qs = cache.get(key)
        if cached_qs:
            same_django = cached_qs._django_version == django.get_version()
            if same_django:
                return cached_qs
        qs = Movie.objects.top_movies(
            limit=limit)
        cache.set(key, qs)
        return qs
```

我们的新`TopMovies`视图重写了`get_queryset`方法，并在使用`MovieManger.top_movies()`之前检查缓存。对`QuerySet`对象进行 pickling 确实有一个警告——不能保证在不同的 Django 版本中兼容，因此在继续之前应该检查所使用的版本。

`TopMovies`还展示了一种访问默认缓存的不同方式，而不是`VaryOnCookieCache`使用的方式。在这里，我们导入并使用`django.core.cache.cache`，它是`django.core.cache.caches['default']`的代理。

在使用低级 API 进行缓存时，记住一致的键的重要性是很重要的。在大型代码库中，很容易在不同的键下存储相同的数据，导致效率低下。将缓存代码放入管理器或实用程序模块中可能很方便。

# 总结

在本章中，我们创建了一个 Top 10 电影视图，审查了用于检测 Django 代码的工具，并介绍了如何使用 Django 的缓存 API。Django 和 Django 社区提供了帮助您发现在哪里优化代码的工具，包括使用分析器、Django 调试工具栏和日志记录。Django 的缓存 API 通过`cache_page`缓存整个页面，通过模板标签`{% cache %}`缓存模板片段，以及通过`cache.set`/`cache.get`缓存任何可 picklable 对象，为我们提供了丰富的 API。

接下来，我们将使用 Docker 部署 MyMDB。


# 第五章：使用 Docker 部署

在本章中，我们将看看如何使用托管在亚马逊的**电子计算云**（**EC2**）上的 Docker 容器将 MyMDB 部署到生产环境。我们还将使用**亚马逊网络服务**（**AWS**）的**简单存储服务**（**S3**）来存储用户上传的文件。

我们将做以下事情：

+   将我们的要求和设置文件拆分为单独的开发和生产设置

+   为 MyMDB 构建一个 Docker 容器

+   构建数据库容器

+   使用 Docker Compose 启动两个容器

+   在云中的 Linux 服务器上将 MyMDB 启动到生产环境

首先，让我们拆分我们的要求和设置，以便保持开发和生产值分开。

# 为生产和开发组织配置

到目前为止，我们保留了一个要求文件和一个`settings.py`文件。这使得开发变得方便。但是，我们不能在生产中使用我们的开发设置。

当前的最佳实践是为每个环境使用单独的文件。然后，每个环境的文件都导入具有共享值的公共文件。我们将使用此模式进行要求和设置文件。

让我们首先拆分我们的要求文件。

# 拆分要求文件

让我们在项目的根目录下创建`requirements.common.txt`：

```py
django<2.1
psycopg2
Pillow<4.4.0
```

无论我们处于哪种环境，我们始终需要 Django、Postgres 驱动程序和 Pillow（用于`ImageField`类）。但是，此要求文件永远不会直接使用。

接下来，让我们在`requirements.dev.txt`中列出我们的开发要求：

```py
-r requirements.common.txt
django-debug-toolbar==1.8
```

上述文件将安装来自`requirements.common.txt`（感谢`-r`）和 Django 调试工具栏的所有内容。

对于我们的生产软件包，我们将使用`requirements.production.txt`：

```py
-r requirements.common.txt
django-storages==1.6.5
boto3==1.4.7
uwsgi==2.0.15
```

这也将安装来自`requirements.common.txt`的软件包。它还将安装`boto3`和`django-storages`软件包，以帮助我们轻松地将文件上传到 S3。`uwsgi`软件包将提供我们用于提供 Django 的服务器。

要为生产环境安装软件包，我们现在可以执行以下命令：

```py
$ pip install -r requirements.production.txt
```

接下来，让我们按类似的方式拆分设置文件。

# 拆分设置文件

再次，我们将遵循当前的 Django 最佳实践，将我们的设置文件分成以下三个文件：`common_settings.py`，`production_settings.py`和`dev_settings.py`。

# 创建 common_settings.py

我们将通过将当前的`settings.py`文件重命名为`common_settings.py`，然后进行本节中提到的更改来创建`common_settings.py`。

让我们将`DEBUG = False`更改为不会*意外*处于调试模式的新设置文件。然后，让我们更改`SECRET_KEY`设置，以便通过更改其行来从环境变量获取其值：

```py
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')
```

让我们还添加一个新的设置`STATIC_ROOT`。`STATIC_ROOT`是 Django 将从已安装的应用程序中收集所有静态文件的目录，以便更容易地提供它们：

```py
STATIC_ROOT = os.path.join(BASE_DIR, 'gathered_static_files')
```

在数据库配置中，我们可以删除所有凭据，但保留`ENGINE`值（为了明确起见，我们打算在任何地方都使用 Postgres）：

```py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
    }
}
```

最后，让我们删除`CACHES`设置。这将在每个环境中以不同的方式配置。

接下来，让我们创建一个开发设置文件。

# 创建 dev_settings.py

我们的开发设置将在`django/config/dev_settings.py`中。我们将逐步构建它。

首先，我们将从`common_settings`中导入所有内容：

```py
from config.common_settings import *
```

然后，我们将覆盖`DEBUG`和`SECRET_KEY`设置：

```py
DEBUG = True
SECRET_KEY = 'some secret'
```

在开发中，我们希望以调试模式运行。我们还会感到安全，硬编码一个秘密密钥，因为我们知道它不会在生产中使用。

接下来，让我们更新`INSTALLED_APPS`列表：

```py
INSTALLED_APPS += [
    'debug_toolbar',
]
```

在开发中，我们可以通过将一系列仅用于开发的应用程序附加到`INSTALLED_APPS`列表中来运行额外的应用程序（例如 Django 调试工具栏）。

然后，让我们更新数据库配置：

```py
DATABASES['default'].update({
    'NAME': 'mymdb',
    'USER': 'mymdb',
    'PASSWORD': 'development',
    'HOST': 'localhost',
    'PORT': '5432',
})
```

由于我们的开发数据库是本地的，我们可以在设置中硬编码值，使文件更简单。如果您的数据库不是本地的，请避免将密码检入版本控制，并在生产中使用`os.getenv()`。

接下来，让我们更新缓存配置：

```py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'default-locmemcache',
        'TIMEOUT': 5,
    }
}
```

在我们的开发缓存中，我们将使用非常短的超时时间。

最后，我们需要设置文件上传目录：

```py
# file uploads
MEDIA_ROOT = os.path.join(BASE_DIR, '../media_root')
```

在开发中，我们将在本地文件系统中存储上传的文件。我们将使用`MEDIA_ROOT`指定要上传到的目录。

Django Debug Toolbar 也需要一些配置：

```py
# Django Debug Toolbar
INTERNAL_IPS = [
    '127.0.0.1',
]
```

Django Debug Toolbar 只会在预定义的 IP 上呈现，所以我们会给它我们的本地 IP，这样我们就可以在本地使用它。

我们还可以添加我们的开发专用应用程序可能需要的更多设置。

接下来，让我们添加生产设置。

# 创建 production_settings.py

让我们在`django/config/production_settings.py`中创建我们的生产设置。

`production_settings.py`类似于`dev_settings.py`，但通常使用`os.getenv()`从环境变量中获取值。这有助于我们将秘密信息（例如密码、API 令牌等）排除在版本控制之外，并将设置与特定服务器解耦：

```py
from config.common_settings import * 
DEBUG = False
assert SECRET_KEY is not None, (
    'Please provide DJANGO_SECRET_KEY '
    'environment variable with a value')
ALLOWED_HOSTS += [
    os.getenv('DJANGO_ALLOWED_HOSTS'),
]
```

首先，我们导入通用设置。出于谨慎起见，我们确保调试模式已关闭。

设置`SECRET_KEY`对于我们的系统保持安全至关重要。我们使用`assert`来防止 Django 在没有`SECRET_KEY`的情况下启动。`common_settings`模块应该已经从环境变量中设置了它。

生产网站将从除`localhost`之外的域访问。然后我们通过将`DJANGO_ALLOWED_HOSTS`环境变量附加到`ALLOWED_HOSTS`列表来告诉 Django 我们正在服务的其他域。

接下来，我们将更新数据库配置：

```py
DATABASES['default'].update({
    'NAME': os.getenv('DJANGO_DB_NAME'),
    'USER': os.getenv('DJANGO_DB_USER'),
    'PASSWORD': os.getenv('DJANGO_DB_PASSWORD'),
    'HOST': os.getenv('DJANGO_DB_HOST'),
    'PORT': os.getenv('DJANGO_DB_PORT'),
})
```

我们使用来自环境变量的值更新数据库配置。

然后，需要设置缓存配置。

```py
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'default-locmemcache',
        'TIMEOUT': int(os.getenv('DJANGO_CACHE_TIMEOUT'), ),
    }
}
```

在生产中，我们将接受本地内存缓存的权衡。我们使用另一个环境变量在运行时配置超时时间。

接下来，需要设置文件上传配置设置。

```py
# file uploads
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY_ID')
AWS_STORAGE_BUCKET_NAME = os.getenv('DJANGO_UPLOAD_S3_BUCKET')
```

在生产中，我们不会将上传的图像存储在容器的本地文件系统上。Docker 的一个核心概念是容器是短暂的。停止和删除容器并用另一个替换应该是可以接受的。如果我们将上传的图像存储在本地，我们将违背这一理念。

不将上传的文件存储在本地的另一个原因是，它们也应该从不同的域提供服务（我们在第三章中讨论过这个问题，*海报、头像和安全性*）。我们将使用 S3 存储，因为它便宜且易于使用。

`django-storages`应用程序为许多 CDN 提供文件存储后端，包括 S3。我们告诉 Django 使用 S3，方法是更改`DEFAULT_FILE_STORAGE`设置。`S3Boto3Storage`后端需要一些额外的设置才能与 AWS 一起工作，包括 AWS 访问密钥、AWS 秘密访问密钥和目标存储桶的名称。我们将在 AWS 部分稍后讨论这两个访问密钥。

现在我们的设置已经组织好了，我们可以创建我们的 MyMDB `Dockerfile`。

# 创建 MyMDB Dockerfile

在本节中，我们将为 MyMDB 创建一个 Dockerfile。Docker 基于镜像运行容器。镜像由 Dockerfile 定义。Dockerfile 必须扩展另一个 Dockerfile（保留的`scratch`镜像是这个周期的结束）。

Docker 的理念是每个容器应该只有一个关注点（目的）。这可能意味着它运行一个单一进程，或者它可能运行多个一起工作的进程。在我们的情况下，它将运行 uWSGI 和 Nginx 进程来提供 MyMDB。

令人困惑的是，Dockerfile 既指预期的*文件名*，也指*文件类型*。所以`Dockerfile`是一个 Dockerfile。

让我们在项目的根目录中创建一个名为`Dockerfile`的文件。 Dockerfile 使用自己的语言来定义图像中的文件/目录，以及在制作图像时需要运行的任何命令。编写 Dockerfile 的完整指南超出了本章的范围。相反，我们将逐步构建我们的`Dockerfile`，仅讨论最相关的元素。

我们将通过以下六个步骤构建我们的`Dockerfile`：

1.  初始化基础镜像并将源代码添加到镜像中

1.  安装软件包

1.  收集静态文件

1.  配置 Nginx

1.  配置 uWSGI

1.  清理不必要的资源

# 启动我们的 Dockerfile

我们的`Dockerfile`的第一部分告诉 Docker 要使用哪个镜像作为基础，添加我们的代码，并创建一些常见的目录：

```py
FROM phusion/baseimage

# add code and directories
RUN mkdir /mymdb
WORKDIR /mymdb
COPY requirements* /mymdb/
COPY django/ /mymdb/django
COPY scripts/ /mymdb/scripts
RUN mkdir /var/log/mymdb/
RUN touch /var/log/mymdb/mymdb.log
```

让我们更详细地看看这些说明：

+   `FROM`：Dockerfile 中需要这个。`FROM`告诉 Docker 我们的镜像要使用哪个基础镜像。我们将使用`phusion/baseimage`，因为它提供了许多方便的设施并且占用的内存很少。它是一个专为 Docker 定制的 Ubuntu 镜像，具有一个更小、易于使用的 init 服务管理器，称为 runit（而不是 Ubuntu 的 upstart）。

+   `RUN`：这在构建图像的过程中执行命令。`RUN mkdir /mymdb`创建我们将存储文件的目录。

+   `WORKDIR`：这为我们所有未来的`RUN`命令设置了工作目录。

+   `COPY`：这将文件（或目录）从我们的文件系统添加到图像中。源路径是相对于包含我们的`Dockerfile`的目录的。最好将目标路径设置为绝对路径。

我们还将引用一个名为`scripts`的新目录。让我们在项目目录的根目录中创建它：

```py
$ mkdir scripts
```

作为配置和构建新镜像的一部分，我们将创建一些小的 bash 脚本，我们将保存在`scripts`目录中。

# 在 Dockerfile 中安装软件包

接下来，我们将告诉我们的`Dockerfile`安装我们将需要的所有软件包：

```py
RUN apt-get -y update
RUN apt-get install -y \
    nginx \
    postgresql-client \
    python3 \
    python3-pip
RUN pip3 install virtualenv
RUN virtualenv /mymdb/venv
RUN bash /mymdb/scripts/pip_install.sh /mymdb
```

我们使用`RUN`语句来安装 Ubuntu 软件包并创建虚拟环境。要将我们的 Python 软件包安装到虚拟环境中，我们将在`scripts/pip_install.sh`中创建一个小脚本：

```py
#!/usr/bin/env bash

root=$1
source $root/venv/bin/activate

pip3 install -r $root/requirements.production.txt
```

上述脚本只是激活虚拟环境并在我们的生产需求文件上运行`pip3 install`。

在 Dockerfile 的中间调试长命令通常很困难。将命令包装在脚本中可以使它们更容易调试。如果某些内容不起作用，您可以使用`docker exec -it bash -l`命令连接到容器并像平常一样调试脚本。

# 在 Dockerfile 中收集静态文件

静态文件是支持我们网站的 CSS、JavaScript 和图像。静态文件可能并非总是由我们创建。一些静态文件来自安装的 Django 应用程序（例如 Django 管理）。让我们更新我们的`Dockerfile`以收集静态文件：

```py
# collect the static files
RUN bash /mymdb/scripts/collect_static.sh /mymdb
```

再次，我们将命令包装在脚本中。让我们将以下脚本添加到`scripts/collect_static.sh`中：

```py
#!/usr/bin/env bash

root=$1
source $root/venv/bin/activate

export DJANGO_CACHE_TIMEOUT=100
export DJANGO_SECRET_KEY=FAKE_KEY
export DJANGO_SETTINGS_MODULE=config.production_settings

cd $root/django/

python manage.py collectstatic
```

上述脚本激活了我们在前面的代码中创建的虚拟环境，并设置了所需的环境变量。在这种情况下，大多数这些值都不重要，只要变量存在即可。但是，`DJANGO_SETTINGS_MODULE`环境变量非常重要。`DJANGO_SETTINGS_MODULE`环境变量用于 Django 查找设置模块。如果我们不设置它并且没有`config/settings.py`，那么 Django 将无法启动（甚至`manage.py`命令也会失败）。

# 将 Nginx 添加到 Dockerfile

要配置 Nginx，我们将添加一个配置文件和一个 runit 服务脚本：

```py
COPY nginx/mymdb.conf /etc/nginx/sites-available/mymdb.conf
RUN rm /etc/nginx/sites-enabled/*
RUN ln -s /etc/nginx/sites-available/mymdb.conf /etc/nginx/sites-enabled/mymdb.conf

COPY runit/nginx /etc/service/nginx
RUN chmod +x /etc/service/nginx/run
```

# 配置 Nginx

让我们将一个 Nginx 配置文件添加到`nginx/mymdb.conf`中：

```py
# the upstream component nginx needs
# to connect to
upstream django {
    server 127.0.0.1:3031;
}

# configuration of the server
server {

    # listen on all IPs on port 80
    server_name 0.0.0.0;
    listen      80;
    charset     utf-8;

    # max upload size
    client_max_body_size 2M;

    location /static {
        alias /mymdb/django/gathered_static_files;
    }

    location / {
        uwsgi_pass  django;
        include     /etc/nginx/uwsgi_params;
    }

}
```

Nginx 将负责以下两件事：

+   提供静态文件（以`/static`开头的 URL）

+   将所有其他请求传递给 uWSGI

`upstream`块描述了我们 Django（uWSGI）服务器的位置。在`location /`块中，nginx 被指示使用 uWSGI 协议将请求传递给上游服务器。`include /etc/nginx/uwsgi_params`文件描述了如何映射标头，以便 uWSGI 理解它们。

`client_max_body_size`是一个重要的设置。它描述了文件上传的最大大小。将这个值设置得太大可能会暴露漏洞，因为攻击者可以用巨大的请求压倒服务器。

# 创建 Nginx runit 服务

为了让`runit`知道如何启动 Nginx，我们需要提供一个`run`脚本。我们的`Dockerfile`希望它在`runit/nginx/run`中：

```py
#!/usr/bin/env bash

exec /usr/sbin/nginx \
    -c /etc/nginx/nginx.conf \
    -g "daemon off;"
```

`runit`不希望其服务分叉出一个单独的进程，因此我们使用`daemon off`来运行 Nginx。此外，`runit`希望我们使用`exec`来替换我们脚本的进程，新的 Nginx 进程。

# 将 uWSGI 添加到 Dockerfile

我们使用 uWSGI，因为它通常被评为最快的 WSGI 应用服务器。让我们通过添加以下代码到我们的`Dockerfile`中来设置它：

```py
# configure uwsgi
COPY uwsgi/mymdb.ini /etc/uwsgi/apps-enabled/mymdb.ini
RUN mkdir -p /var/log/uwsgi/
RUN touch /var/log/uwsgi/mymdb.log
RUN chown www-data /var/log/uwsgi/mymdb.log
RUN chown www-data /var/log/mymdb/mymdb.log

COPY runit/uwsgi /etc/service/uwsgi
RUN chmod +x /etc/service/uwsgi/run
```

这指示 Docker 使用`mymdb.ini`文件配置 uWSGI，创建日志目录，并添加 uWSGI runit 服务。为了让 runit 启动 uWSGI 服务，我们使用`chmod`命令给予 runit 脚本执行权限。

# 配置 uWSGI 运行 MyMDB

让我们在`uwsgi/mymdb.ini`中创建 uWSGI 配置：

```py
[uwsgi]
socket = 127.0.0.1:3031
chdir = /mymdb/django/
virtualenv = /mymdb/venv
wsgi-file = config/wsgi.py
env = DJANGO_SECRET_KEY=$(DJANGO_SECRET_KEY)
env = DJANGO_LOG_LEVEL=$(DJANGO_LOG_LEVEL)
env = DJANGO_ALLOWED_HOSTS=$(DJANGO_ALLOWED_HOSTS)
env = DJANGO_DB_NAME=$(DJANGO_DB_NAME)
env = DJANGO_DB_USER=$(DJANGO_DB_USER)
env = DJANGO_DB_PASSWORD=$(DJANGO_DB_PASSWORD)
env = DJANGO_DB_HOST=$(DJANGO_DB_HOST)
env = DJANGO_DB_PORT=$(DJANGO_DB_PORT)
env = DJANGO_CACHE_TIMEOUT=$(DJANGO_CACHE_TIMEOUT)
env = AWS_ACCESS_KEY_ID=$(AWS_ACCESS_KEY_ID)
env = AWS_SECRET_ACCESS_KEY_ID=$(AWS_SECRET_ACCESS_KEY_ID)
env = DJANGO_UPLOAD_S3_BUCKET=$(DJANGO_UPLOAD_S3_BUCKET)
env = DJANGO_LOG_FILE=$(DJANGO_LOG_FILE)
processes = 4
threads = 4
```

让我们更仔细地看一下其中一些设置：

+   `socket`告诉 uWSGI 在`127.0.0.1:3031`上使用其自定义的`uwsgi`协议打开一个套接字（令人困惑的是，协议和服务器的名称相同）。

+   `chdir`改变了进程的工作目录。所有路径都需要相对于这个位置。

+   `virtualenv`告诉 uWSGI 项目虚拟环境的路径。

+   每个`env`指令为我们的进程设置一个环境变量。我们可以在我们的代码中使用`os.getenv()`访问这些变量（例如，`production_settings.py`）。

+   `$(...)`是从 uWSGI 进程自己的环境中引用的环境变量（例如，`$(DJANGO_SECRET_KEY )`）。

+   `proccesses`设置我们应该运行多少个进程。

+   `threads`设置每个进程应该有多少线程。

`processes`和`threads`设置将根据生产性能进行微调。

# 创建 uWSGI runit 服务

为了让 runit 知道如何启动 uWSGI，我们需要提供一个`run`脚本。我们的`Dockerfile`希望它在`runit/uwsgi/run`中。这个脚本比我们用于 Nginx 的要复杂：

```py
#!/usr/bin/env bash

source /mymdb/venv/bin/activate

export PGPASSWORD="$DJANGO_DB_PASSWORD"
psql \
    -h "$DJANGO_DB_HOST" \
    -p "$DJANGO_DB_PORT" \
    -U "$DJANGO_DB_USER" \
    -d "$DJANGO_DB_NAME"

if [[ $? != 0 ]]; then
    echo "no db server"
    exit 1
fi

pushd /mymdb/django

python manage.py migrate

if [[ $? != 0 ]]; then
    echo "can't migrate"
    exit 2
fi
popd

exec /sbin/setuser www-data \
    uwsgi \
    --ini /etc/uwsgi/apps-enabled/mymdb.ini \
    >> /var/log/uwsgi/mymdb.log \
    2>&1
```

这个脚本做了以下三件事：

+   检查是否可以连接到数据库，否则退出

+   运行所有迁移或失败时退出

+   启动 uWSGI

runit 要求我们使用`exec`来启动我们的进程，以便 uWSGI 将替换`run`脚本的进程。

# 完成我们的 Dockerfile

作为最后一步，我们将清理并记录我们正在使用的端口：

```py
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

EXPOSE 80
```

`EXPOSE`语句记录了我们正在使用的端口。重要的是，它实际上并不打开任何端口。当我们运行容器时，我们将不得不这样做。

接下来，让我们为我们的数据库创建一个容器。

# 创建数据库容器

我们需要一个数据库来在生产中运行 Django。PostgreSQL Docker 社区为我们提供了一个非常强大的 Postgres 镜像，我们可以扩展使用。

让我们在`docker/psql/Dockerfile`中为我们的数据库创建另一个容器：

```py
FROM postgres:10.1

ADD make_database.sh /docker-entrypoint-initdb.d/make_database.sh
```

这个`Dockerfile`的基本镜像将使用 Postgres 10.1。它还有一个方便的设施，它将执行`/docker-entrypoint-initdb.d`中的任何 shell 或 SQL 脚本作为 DB 初始化的一部分。我们将利用这一点来创建我们的 MyMDB 数据库和用户。

让我们在`docker/psql/make_database.sh`中创建我们的数据库初始化脚本：

```py
#!/usr/bin/env bash

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE $DJANGO_DB_NAME;
    CREATE USER $DJANGO_DB_USER;
    GRANT ALL ON DATABASE $DJANGO_DB_NAME TO "$DJANGO_DB_USER";
    ALTER USER $DJANGO_DB_USER PASSWORD '$DJANGO_DB_PASSWORD';
    ALTER USER $DJANGO_DB_USER CREATEDB;
EOSQL
```

我们在前面的代码中使用了一个 shell 脚本，以便我们可以使用环境变量来填充我们的 SQL。

现在我们的两个容器都准备好了，让我们确保我们实际上可以通过注册并配置 AWS 来启动它们。

# 在 AWS S3 上存储上传的文件

我们期望我们的 MyMDB 将文件保存到 S3。为了实现这一点，我们需要注册 AWS，然后配置我们的 shell 以便能够使用 AWS。

# 注册 AWS

要注册，请转到[`aws.amazon.com`](https://aws.amazon.com)并按照其说明操作。请注意，注册是免费的。

我们将使用的资源在撰写本书时都在 AWS 免费层中。免费层的一些元素仅在第一年对新帐户可用。在执行任何 AWS 命令之前，请检查您的帐户的资格。

# 设置 AWS 环境

为了与 AWS API 交互，我们将需要以下两个令牌——访问密钥和秘密访问密钥。这对密钥定义了对帐户的访问。

要生成一对令牌，转到[`console.aws.amazon.com/iam/home?region=us-west-2#/security_credential_`](https://console.aws.amazon.com/iam/home?region=us-west-2#/security_credential)，单击访问密钥，然后单击创建新的访问密钥按钮。如果您丢失了秘密访问密钥，将无法检索它，因此请确保将其保存在安全的地方。

上述的 AWS 控制台链接将为您的根帐户生成令牌。在我们测试时这没问题。将来，您应该使用 AWS IAM 权限系统创建具有有限权限的用户。

接下来，让我们安装 AWS 命令行界面（CLI）：

```py
$ pip install awscli
```

然后，我们需要使用我们的密钥和区域配置 AWS 命令行工具。`aws`命令提供一个交互式`configure`子命令来执行此操作。让我们在命令行上运行它：

```py
$ aws configure
 AWS Access Key ID [None]: <Your ACCESS key>
 AWS Secret Access Key [None]: <Your secret key>
 Default region name [None]: us-west-2
 Default output format [None]: json
```

`aws configure`命令将存储您在家目录中的`.aws`目录中输入的值。

要确认您的新帐户是否设置正确，请请求 EC2 实例的列表（不应该有）：

```py
$ aws ec2 describe-instances
{
    "Reservations": []
}
```

# 创建文件上传存储桶

S3 被组织成存储桶。每个存储桶必须有一个唯一的名称（在整个 AWS 中唯一）。每个存储桶还将有一个控制访问的策略。

通过执行以下命令来创建我们的文件上传存储桶（将`BUCKET_NAME`更改为您自己的唯一名称）：

```py
$ export AWS_ACCESS_KEY=#your value
$ export AWS_SECRET_ACCESS_KEY=#yourvalue
$ aws s3 mb s3://BUCKET_NAME
```

为了让未经身份验证的用户访问我们存储桶中的文件，我们必须设置一个策略。让我们在`AWS/mymdb-bucket-policy.json`中创建策略：

```py
{
    "Version": "2012-10-17",
    "Id": "mymdb-bucket-policy",
    "Statement": [
        {
            "Sid": "allow-file-download-stmt",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::BUCKET_NAME/*"
        }
    ]
}
```

确保将`BUCKET_NAME`更新为您的存储桶的名称。

现在，我们可以使用 AWS CLI 在您的存储桶上应用策略：

```py
$ aws s3api put-bucket-policy --bucket BUCKET_NAME --policy "$(cat AWS/mymdb-bucket-policy.json)"
```

确保您记住您的存储桶名称，AWS 访问密钥和 AWS 秘密访问密钥，因为我们将在下一节中使用它们。

# 使用 Docker Compose

我们现在已经准备好生产部署的所有部分。 Docker Compose 是 Docker 让多个容器一起工作的方式。 Docker Compose 由一个命令行工具`docker-compose`，一个配置文件`docker-compose.yml`和一个环境变量文件`.env`组成。我们将在项目目录的根目录中创建这两个文件。

永远不要将您的`.env`文件检入版本控制。那里是您的秘密所在。不要让它们泄漏。

首先，让我们在`.env`中列出我们的环境变量：

```py
# Django settings
DJANGO_SETTINGS_MODULE=config.production_settings
DJANGO_SECRET_KEY=#put your secret key here
DJANGO_LOG_LEVEL=DEBUG
DJANGO_LOG_FILE=/var/log/mymdb/mymdb.log
DJANGO_ALLOWED_HOSTS=# put your domain here
DJANGO_DB_NAME=mymdb
DJANGO_DB_USER=mymdb
DJANGO_DB_PASSWORD=#put your password here
DJANGO_DB_HOST=db
DJANGO_DB_PORT=5432
DJANGO_CACHE_TIMEOUT=200

AWS_ACCESS_KEY_ID=# put aws key here
AWS_SECRET_ACCESS_KEY_ID=# put your secret key here
DJANGO_UPLOAD_S3_BUCKET=# put BUCKET_NAME here

# Postgres settings
POSTGRES_PASSWORD=# put your postgress admin password here
```

这些值中的许多值都可以硬编码，但有一些值需要为您的项目设置：

+   `DJANGO_SECRET_KEY`：Django 秘密密钥用作 Django 加密种子的一部分

+   `DJANGO_DB_PASSWORD`：这是 Django 的 MyMDB 数据库用户的密码

+   `AWS_ACCESS_KEY_ID`：您的 AWS 访问密钥

+   `AWS_SECRET_ACCESS_KEY_ID`：您的 AWS 秘密访问密钥

+   `DJANGO_UPLOAD_S3_BUCKET`：您的存储桶名称

+   `POSTGRES_PASSWORD`：Postgres 数据库超级用户的密码（与 MyMDB 数据库用户不同）

+   `DJANGO_ALLOWED_HOSTS`：我们将提供服务的域（一旦我们启动 EC2 实例，我们将填写这个）

接下来，我们在`docker-compose.yml`中定义我们的容器如何一起工作：

```py
version: '3'

services:
  db:
    build: docker/psql
    restart: always
    ports:
      - "5432:5432"
    environment:
      - DJANGO_DB_USER
      - DJANGO_DB_NAME
      - DJANGO_DB_PASSWORD
  web:
    build: .
    restart: always
    ports:
      - "80:80"
    depends_on:
      - db
    environment:
      - DJANGO_SETTINGS_MODULE
      - DJANGO_SECRET_KEY
      - DJANGO_LOG_LEVEL
      - DJANGO_LOG_FILE
      - DJANGO_ALLOWED_HOSTS
      - DJANGO_DB_NAME
      - DJANGO_DB_USER
      - DJANGO_DB_PASSWORD
      - DJANGO_DB_HOST
      - DJANGO_DB_PORT
      - DJANGO_CACHE_TIMEOUT
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY_ID
      - DJANGO_UPLOAD_S3_BUCKET
```

此 Compose 文件描述了构成 MyMDB 的两个服务（`db`和`web`）。让我们回顾一下我们使用的配置选项：

+   `build`：构建上下文的路径。一般来说，构建上下文是一个带有`Dockerfile`的目录。因此，`db`使用`psql`目录，`web`使用`.`目录（项目根目录，其中有一个`Dockerfile`）。

+   `ports`：端口映射列表，描述如何将主机端口上的连接路由到容器上的端口。在我们的情况下，我们不会更改任何端口。

+   `environment`：每个服务的环境变量。我们使用的格式意味着我们从我们的`.env`文件中获取值。但是，您也可以使用`MYVAR=123`语法硬编码值。

+   `restart`：这是容器的重启策略。`always`表示如果容器因任何原因停止，Docker 应该始终尝试重新启动容器。

+   `depends_on`：这告诉 Docker 在启动`web`容器之前启动`db`容器。然而，我们仍然不能确定 Postgres 是否能在 uWSGI 之前成功启动，因此我们需要在我们的 runit 脚本中检查数据库是否已经启动。

# 跟踪环境变量

我们的生产配置严重依赖于环境变量。让我们回顾一下在 Django 中使用`os.getenv()`之前必须遵循的步骤：

1.  在`.env`中列出变量

1.  在`docker-compose.yml`中的`environment`选项下包括变量

1.  在`env`中包括 uWSGI ini 文件变量

1.  使用`os.getenv`访问变量

# 在本地运行 Docker Compose

现在我们已经配置了我们的 Docker 容器和 Docker Compose，我们可以运行这些容器。Docker Compose 的一个优点是它可以在任何地方提供相同的环境。这意味着我们可以在本地运行 Docker Compose，并获得与我们在生产环境中获得的完全相同的环境。不必担心在不同环境中有额外的进程或不同的分发。让我们在本地运行 Docker Compose。

# 安装 Docker

要继续阅读本章的其余部分，您必须在您的机器上安装 Docker。Docker, Inc.提供免费的 Docker 社区版，可以从其网站上获得：[`docker.com`](https://docker.com)。Docker 社区版安装程序在 Windows 和 Mac 上是一个易于使用的向导。Docker, Inc.还为大多数主要的 Linux 发行版提供官方软件包。

安装完成后，您将能够按照接下来的所有步骤进行操作。

# 使用 Docker Compose

要在本地启动我们的容器，请运行以下命令：

```py
$ docker-compose up -d 
```

`docker-compose up`构建然后启动我们的容器。`-d`选项将 Compose 与我们的 shell 分离。

要检查我们的容器是否正在运行，我们可以使用`docker ps`：

```py
$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS                          NAMES
0bd7f7203ea0        mymdb_web           "/sbin/my_init"          52 seconds ago      Up 51 seconds       0.0.0.0:80->80/tcp, 8031/tcp   mymdb_web_1
3b9ecdcf1031        mymdb_db            "docker-entrypoint..."   46 hours ago        Up 52 seconds       0.0.0.0:5432->5432/tcp         mymdb_db_1
```

要检查 Docker 日志，您可以使用`docker logs`命令来记录启动脚本的输出：

```py
$ docker logs mymdb_web_1
```

要访问容器内部的 shell（以便您可以检查文件或查看应用程序日志），请使用此`docker exec`命令启动 bash：

```py
$ docker exec -it mymdb_web_1 bash -l
```

要停止容器，请使用以下命令：

```py
$ docker-compose stop
```

要停止容器并*删除*它们，请使用以下命令：

```py
$ docker-compose down
```

当您删除一个容器时，您会删除其中的所有数据。对于 Django 容器来说这不是问题，因为它不保存数据。然而，如果您删除 db 容器，您将*丢失数据库的数据*。在生产环境中要小心。

# 通过容器注册表共享您的容器

现在我们有一个可工作的容器，我们可能希望使其更广泛地可访问。Docker 有一个容器注册表的概念。您可以将您的容器推送到容器注册表，以便将其公开或仅提供给您的团队。

最受欢迎的 Docker 容器注册表是 Docker Hub（[`hub.docker.com`](https://hub.docker.com)）。您可以免费创建一个帐户，并且在撰写本书时，每个帐户都附带一个免费的私有存储库和无限的公共存储库。大多数云提供商也提供 docker 存储库托管设施（尽管价格可能有所不同）。

本节的其余部分假设您已配置了主机。我们将以 Docker Hub 为例，但无论谁托管您的容器存储库，所有步骤都是相同的。

要共享您的容器，您需要做以下事情：

1.  登录到 Docker 注册表

1.  标记我们的容器

1.  推送到 Docker 注册表

让我们首先登录到 Docker 注册表：

```py
$ docker login -u USERNAME -p PASSWORD docker.io
```

`USERNAME` 和 `PASSWORD` 的值需要与您在 Docker Hub 帐户上使用的相同。 `docker.io` 是 Docker Hub 容器注册表的域。如果您使用不同的容器注册表主机，则需要更改域。

现在我们已经登录，让我们重新构建并标记我们的容器：

```py
$ docker build . -t USERNAME/REPOSITORY:latest
```

其中 `USERNAME` 和 `REPOSITORY` 的值将被替换为您的值。 `:latest` 后缀是构建的标签。我们可以在同一个存储库中有许多不同的标签（例如 `development`，`stable` 和 `1.x`）。Docker 中的标签很像版本控制中的标签；它们帮助我们快速轻松地找到特定的项目。 `:latest` 是给最新构建的常见标签（尽管它可能不稳定）。

最后，让我们将标记的构建推送到我们的存储库：

```py
$ docker push USERNAME/REPOSITORY:latest
```

Docker 将显示其上传的进度，然后在成功时显示 SHA256 摘要。

当我们将 Docker 镜像推送到远程存储库时，我们需要注意镜像中存储的任何私人数据。我们在 `Dockerfile` 中创建或添加的所有文件都包含在推送的镜像中。就像我们不希望在存储在远程存储库中的代码中硬编码密码一样，我们也不希望在可能存储在远程服务器上的 Docker 镜像中存储敏感数据（如密码）。这是我们强调将密码存储在环境变量而不是硬编码它们的另一个原因。

太好了！现在你可以与其他团队成员分享存储库，以运行你的 Docker 容器。

接下来，让我们启动我们的容器。

# 在云中的 Linux 服务器上启动容器

现在我们已经让一切运转起来，我们可以将其部署到互联网上。我们可以使用 Docker 将我们的容器部署到任何 Linux 服务器上。大多数使用 Docker 的人都在使用云提供商来提供 Linux 服务器主机。在我们的情况下，我们将使用 AWS。

在前面的部分中，当我们使用 `docker-compose` 时，实际上是在向运行在我们的机器上的 Docker 服务发送命令。Docker Machine 提供了一种管理运行 Docker 的远程服务器的方法。我们将使用 `docker-machine` 来启动一个 EC2 实例，该实例将托管我们的 Docker 容器。

启动 EC2 实例可能会产生费用。在撰写本书时，我们将使用符合 AWS 免费套餐资格的实例 `t2.micro`。但是，您有责任检查 AWS 免费套餐的条款。

# 启动 Docker EC2 VM

我们将在我们的帐户的**虚拟私有云**（**VPC**）中启动我们的 EC2 VM（称为 EC2 实例）。但是，每个帐户都有一个唯一的 VPC ID。要获取您的 VPC ID，请运行以下命令：

```py
$ export AWS_ACCESS_KEY=#your value
$ export AWS_SECRET_ACCESS_KEY=#yourvalue
$ export AWS_DEFAULT_REGION=us-west-2
$ aws ec2 describe-vpcs | grep VpcId
            "VpcId": "vpc-a1b2c3d4",
```

上述代码中使用的值不是真实值。

现在我们知道我们的 VPC ID，我们可以使用 `docker-machine` 来启动一个 EC2 实例：

```py
$ docker-machine create \
     --driver amazonec2 \
     --amazonec2-instance-type t2.micro \
     --amazonec2-vpc-id vpc-a1b2c3d4 \
     --amazonec2-region us-west-2 \
     mymdb-host
```

这告诉 Docker Machine 在`us-west-2`地区和提供的 VPC 中启动一个 EC2 `t2.micro`实例。Docker Machine 负责确保服务器上安装并启动了 Docker 守护程序。在 Docker Machine 中引用此 EC2 实例时，我们使用名称 `mymdb-host`。

当实例启动时，我们可以向 AWS 请求我们实例的公共 DNS 名称：

```py
$ aws ec2 describe-instances | grep -i publicDnsName
```

即使只有一个实例运行，上述命令可能会返回相同值的多个副本。将结果放入 `.env` 文件中作为 `DJANGO_ALLOWED_HOSTS`。

所有 EC2 实例都受其安全组确定的防火墙保护。Docker Machine 在启动我们的实例时自动为我们的服务器创建了一个安全组。为了使我们的 HTTP 请求到达我们的机器，我们需要在 `docker-machine` 安全组中打开端口 `80`，如下所示：

```py
$ aws ec2 authorize-security-group-ingress \
    --group-name docker-machine \
    --protocol tcp \
    --port 80 \
    --cidr 0.0.0.0/0
```

现在一切都设置好了，我们可以配置`docker-compose`与我们的远程服务器通信，并启动我们的容器：

```py
$ eval $(docker-machine env mymdb-host)
$ docker-compose up -d
```

恭喜！MyMDB 已经在生产环境中运行起来了。通过导航到`DJANGO_ALLOWED_HOSTS`中使用的地址来查看它。

这里的说明重点是启动 AWS Linux 服务器。然而，所有的 Docker 命令都有等效的选项适用于 Google Cloud、Azure 和其他主要的云服务提供商。甚至还有一个*通用*选项，可以与任何 Linux 服务器配合使用，尽管根据 Linux 发行版和 Docker 版本的不同，效果可能有所不同。

# 关闭 Docker EC2 虚拟机

Docker Machine 也可以用于停止运行 Docker 的虚拟机，如下面的代码片段所示：

```py
$ export AWS_ACCESS_KEY=#your value
$ export AWS_SECRET_ACCESS_KEY=#yourvalue
$ export AWS_DEFAULT_REGION=us-west-2
$ eval $(docker-machine env mymdb-host)
$ docker-machine stop mymdb-host 
```

这将停止 EC2 实例并销毁其中的所有容器。如果您希望保留您的数据库，请确保通过运行前面的`eval`命令来备份您的数据库，然后使用`docker exec -it mymdb_db_1 bash -l`打开一个 shell。

# 总结

在这一章中，我们已经将 MyMDB 部署到了互联网上的生产 Docker 环境中。我们使用 Dockerfile 为 MyMDB 创建了一个 Docker 容器。我们使用 Docker Compose 使 MyMDB 与 PostgreSQL 数据库（也在 Docker 容器中）配合工作。最后，我们使用 Docker Machine 在 AWS 云上启动了这些容器。

恭喜！你现在已经让 MyMDB 运行起来了。

在下一章中，我们将实现 Stack Overflow。


# 第六章：开始 Answerly

我们将构建的第二个项目是一个名为 Answerly 的 Stack Overflow 克隆。 注册 Answerly 的用户将能够提问和回答问题。 提问者还将能够接受答案以标记它们为有用。

在本章中，我们将做以下事情：

+   创建我们的新 Django 项目 Answerly，一个 Stack Overflow 克隆

+   为 Answerly 创建模型（`Question`和`Answer`）

+   让用户注册

+   创建表单，视图和模板，让用户与我们的模型进行交互

+   运行我们的代码

该项目的代码可在[`github.com/tomaratyn/Answerly`](https://github.com/tomaratyn/Answerly)上找到。

本章不会深入讨论已在第一章中涵盖的主题，尽管它将涉及许多相同的要点。 相反，本章将重点放在更进一步并引入新视图和第三方库上。

让我们开始我们的项目！

# 创建 Answerly Django 项目

首先，让我们为我们的项目创建一个目录：

```py
$ mkdir answerly
$ cd answerly
```

我们未来的所有命令和路径都将相对于这个项目目录。 一个 Django 项目由多个 Django 应用程序组成。

我们将使用`pip`安装 Django，Python 的首选软件包管理器。 我们还将在`requirements.txt`文件中跟踪我们安装的软件包：

```py
django<2.1
psycopg2<2.8
```

现在，让我们安装软件包：

```py
$ pip install -r requirements.txt
```

接下来，让我们使用`django-admin`生成实际的 Django 项目：

```py
$ django-admin startproject config
$ mv config django
```

默认情况下，Django 创建一个将使用 SQLite 的项目，但这对于生产来说是不可用的； 因此，我们将遵循在开发和生产中使用相同数据库的最佳实践。

让我们打开`django/config/settings.py`并更新它以使用我们的 Postgres 服务器。 找到以`DATABASES`开头的`settings.py`中的行； 要使用 Postgres，请将`DATABASES`的值更改为以下代码：

```py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'answerly',
        'USER': 'answerly',
        'PASSWORD': 'development',
        'HOST': '127.0.0.1',
        'PORT': '5432',
    }
}
```

现在我们已经开始并配置了我们的项目，我们可以创建并安装我们将作为项目一部分制作的两个 Django 应用程序：

```py
$ cd django
$ python manage.py startapp user
$ python manage.py startapp qanda
```

Django 项目由应用程序组成。 Django 应用程序是所有功能和代码所在的地方。 模型，表单和模板都属于 Django 应用程序。 应用程序，就像其他 Python 模块一样，应该有一个明确定义的范围。 在我们的情况下，我们有两个应用程序，每个应用程序都有不同的角色。 `qanda`应用程序将负责我们应用程序的问题和答案功能。 `user`应用程序将负责我们应用程序的用户管理。 它们每个都将依赖其他应用程序和 Django 的核心功能以有效地工作。

现在，让我们通过更新`django/config/settings.py`在我们的项目中安装我们的应用程序：

```py
INSTALLED_APPS = [
    'user',
    'qanda',

    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]
```

既然 Django 知道我们的应用程序，让我们从`qanda`的模型开始安装。

# 创建 Answerly 模型

Django 在创建数据驱动的应用程序方面特别有帮助。 模型代表应用程序中的数据，通常是这些应用程序的核心。 Django 通过*fat models, thin views, dumb templates*的最佳实践鼓励这一点。 这些建议鼓励我们将业务逻辑放在我们的模型中，而不是我们的视图中。

让我们从`Question`模型开始构建我们的`qanda`模型。

# 创建 Question 模型

我们将在`django/qanda/models.py`中创建我们的`Question`模型：

```py
from django.conf import settings
from django.db import models
from django.urls.base import reverse

class Question(models.Model):
    title = models.CharField(max_length=140)
    question = models.TextField()
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse('questions:question_detail', kwargs={'pk': self.id})

    def can_accept_answers(self, user):
        return user == self.user
```

`Question`模型，像所有 Django 模型一样，派生自`django.db.models.Model`。 它具有以下四个字段，这些字段将成为`questions_question`表中的列：

+   `title`：一个字符字段，将成为最多 140 个字符的`VARCHAR`列。

+   `question`：这是问题的主体。 由于我们无法预测这将有多长，我们使用`TextField`，它将成为`TEXT`列。`TEXT`列没有大小限制。

+   `user`：这将创建一个外键到项目配置的用户模型。 在我们的情况下，我们将使用 Django 提供的默认`django.contrib.auth.models.User`。 但是，建议我们尽量避免硬编码这一点。

+   `created`：这将自动设置为创建`Question`模型的日期和时间。

`Question`还实现了 Django 模型上常见的两种方法（`__str__`和`get_absolute_url`）：

+   `__str__()`：这告诉 Python 如何将我们的模型转换为字符串。这在管理后端、我们自己的模板和调试中非常有用。

+   `get_absolute_url()`：这是一个常见的实现方法，让模型返回查看此模型的 URL 路径。并非所有模型都需要此方法。Django 的内置视图，如`CreateView`，将使用此方法在创建模型后将用户重定向到视图。

最后，在“fat models”的精神下，我们还有`can_accept_answers()`。谁可以接受对`Question`的`Answer`的决定取决于`Question`。目前，只有提问问题的用户可以接受答案。

现在我们有了`Question`，自然需要`Answer`。

# 创建`Answer`模型

我们将在`django/questions/models.py`文件中创建`Answer`模型，如下所示：

```py
from django.conf import settings
from django.db import models

class Question(model.Models):
    # skipped

class Answer(models.Model):
    answer = models.TextField()
    user = models.ForeignKey(to=settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    question = models.ForeignKey(to=Question,
                                 on_delete=models.CASCADE)
    accepted = models.BooleanField(default=False)

    class Meta:
        ordering = ('-created', )
```

`Answer`模型有五个字段和一个`Meta`类。让我们先看看这些字段：

+   `answer`：这是用户答案的无限文本字段。`answer`将成为一个`TEXT`列。

+   `user`：这将创建一个到我们项目配置为使用的用户模型的外键。用户模型将获得一个名为`answer_set`的新`RelatedManager`，它将能够查询用户的所有`Answer`。

+   `question`：这将创建一个到我们的`Question`模型的外键。`Question`还将获得一个名为`answer_set`的新`RelatedManager`，它将能够查询所有`Question`的`Answer`。

+   `created`：这将设置为创建`Answer`的日期和时间。

+   `accepted`：这是一个默认设置为`False`的布尔值。我们将用它来标记已接受的答案。

模型的`Meta`类让我们为我们的模型和表设置元数据。对于`Answer`，我们使用`ordering`选项来确保所有查询都将按`created`的降序排序。通过这种方式，我们确保最新的答案将首先列出，默认情况下。

现在我们有了`Question`和`Answer`模型，我们需要创建迁移以在数据库中创建它们的表。

# 创建迁移

Django 自带一个内置的迁移库。这是 Django“一揽子”哲学的一部分。迁移提供了一种管理我们需要对模式进行的更改的方法。每当我们对模型进行更改时，我们可以使用 Django 生成一个迁移，其中包含了如何创建或更改模式以适应新模型定义的指令。要对数据库进行更改，我们将应用模式。

与我们在项目上执行的许多操作一样，我们将使用 Django 为我们的项目提供的`manage.py`脚本：

```py
$ python manage.py makemigrations
 Migrations for 'qanda':
  qanda/migrations/0001_initial.py
    - Create model Answer
    - Create model Question
    - Add field question to answer
    - Add field user to answer
$ python manage.py migrate
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, qanda, sessions
Running migrations:
  Applying qanda.0001_initial... OK
```

现在我们已经创建了迁移并应用了它们，让我们为我们的项目设置一个基础模板，以便我们的代码能够正常工作。

# 添加基础模板

在创建视图之前，让我们创建一个基础模板。Django 的模板语言允许模板相互继承。基础模板是所有其他项目模板都将扩展的模板。这将给我们整个项目一个共同的外观和感觉。

由于项目由多个应用程序组成，它们都将使用相同的基础模板，因此基础模板属于项目，而不属于任何特定的应用程序。这是一个罕见的例外，违反了一切都在应用程序中的规则。

要添加一个项目范围的模板目录，请更新`django/config/settings.py`。检查`TEMPLATES`设置并将其更新为以下内容：

```py
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates')
        ],
        'APP_DIRS': True,
        'OPTIONS': {
                # skipping rest of options.
        },
    },
]
```

特别是，`django.template.backends.django.DjangoTemplates`设置的`DIRS`选项设置了一个项目范围的模板目录，将被搜索。`'APP_DIRS': True`意味着每个安装的应用程序的`templates`目录也将被搜索。为了让 Django 搜索`django/templates`，我们必须将`os.path.join(BASE_DIR, 'templates')`添加到`DIRS`列表中。

# 创建 base.html

Django 自带了自己的模板语言，名为 Django 模板语言。Django 模板是文本文件，使用字典（称为上下文）进行渲染以查找值。模板还可以包括标签（使用`{% tag argument %}`语法）。模板可以使用`{{ variableName }}`语法从其上下文中打印值。值可以发送到过滤器进行调整，然后显示（例如，`{{ user.username | uppercase }}`将打印用户的用户名，所有字符都是大写）。最后，`{# ignored #}`语法可以注释掉多行文本。

我们将在`django/templates/base.html`中创建我们的基本模板：

```py
{% load static %}
<!DOCTYPE html>
<html lang="en" >
<head >
  <meta charset="UTF-8" >
  <title >{% block title %}Answerly{% endblock %}</title >
  <link
      href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.2/css/bootstrap.min.css"
      rel="stylesheet">
  <link
      href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css"
      rel="stylesheet">
  <link rel="stylesheet" href="{% static "base.css" %}" >
</head >
<body >
<nav class="navbar navbar-expand-lg  bg-light" >
  <div class="container" >
    <a class="navbar-brand" href="/" >Answerly</a >
    <ul class="navbar-nav" >
    </ul >
  </div >
</nav >
<div class="container" >
  {% block body %}{% endblock %}
</div >
</body >
</html >
```

我们不会详细介绍这个 HTML，但值得回顾涉及的 Django 模板标签：

+   `{% load static %}`：`load`让我们加载默认情况下不可用的模板标签库。在这种情况下，我们加载了静态库，它提供了`static`标签。该库和标签并不总是共享它们的名称。这是由`django.contrib.static`应用程序提供的 Django。

+   `{% block title %}Answerly{% endblock %}`：块让我们定义模板在扩展此模板时可以覆盖的区域。

+   `{% static 'base.css' %}`：`static`标签（从前面加载的`static`库中加载）使用`STATIC_URL`设置来创建对静态文件的引用。在这种情况下，它将返回`/static/base.css`。只要文件在`settings.STATICFILES_DIRS`列出的目录中，并且 Django 处于调试模式，Django 就会为我们提供该文件。对于生产环境，请参阅第九章，*部署 Answerly*。

这就足够我们的`base.html`文件开始了。我们将在*更新 base.html 导航*部分中稍后更新`base.html`中的导航。

接下来，让我们配置 Django 知道如何找到我们的`base.css`文件，通过配置静态文件。

# 配置静态文件

接下来，让我们在`django/config/settings.py`中配置一个项目范围的静态文件目录：

```py
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]
```

这将告诉 Django，在调试模式下应该提供`django/static/`中的任何文件。对于生产环境，请参阅第九章，*部署 Answerly*。

让我们在`django/static/base.css`中放一些基本的 CSS：

```py
nav.navbar {
  margin-bottom: 1em;
}
```

现在我们已经创建了基础，让我们创建`AskQuestionView`。

# 让用户发布问题

现在我们将创建一个视图，让用户发布他们需要回答的问题。

Django 遵循**模型-视图-模板**（**MVT**）模式，将模型、控制和表示逻辑分开，并鼓励可重用性。模型代表我们将在数据库中存储的数据。视图负责处理请求并返回响应。视图不应该包含 HTML。模板负责响应的主体和定义 HTML。这种责任的分离已被证明使编写代码变得容易。

为了让用户发布问题，我们将执行以下步骤：

1.  创建一个处理问题的表单

1.  创建一个使用 Django 表单创建问题的视图

1.  创建一个在 HTML 中渲染表单的模板

1.  在视图中添加一个`path`

首先，让我们创建`QuestionForm`类。

# 提问表单

Django 表单有两个目的。它们使得渲染表单主体以接收用户输入变得容易。它们还验证用户输入。当一个表单被实例化时，它可以通过`intial`参数给出初始值，并且通过`data`参数给出要验证的数据。提供了数据的表单被称为绑定的。

Django 的许多强大之处在于将模型、表单和视图轻松地结合在一起构建功能。

我们将在`django/qanda/forms.py`中创建我们的表单：

```py
from django import forms
from django.contrib.auth import get_user_model

from qanda.models import Question

class QuestionForm(forms.ModelForm):
    user = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=get_user_model().objects.all(),
        disabled=True,
    )

    class Meta:
        model = Question
        fields = ['title', 'question', 'user', ]
```

`ModelForm`使得从 Django 模型创建表单更容易。我们使用`QuestionForm`的内部`Meta`类来指定表单的模型和字段。

通过添加一个`user`字段，我们能够覆盖 Django 如何呈现`user`字段。我们告诉 Django 使用`HiddenInput`小部件，它将把字段呈现为`<input type='hidden'>`。`queryset`参数让我们限制有效值的用户（在我们的情况下，所有用户都是有效的）。最后，`disabled`参数表示我们将忽略由`data`（即来自请求的）提供的任何值，并依赖于我们提供给表单的`initial`值。

现在我们知道如何呈现和验证问题表单，让我们创建我们的视图。

# 创建 AskQuestionView

我们将在`django/qanda/views.py`中创建我们的`AskQuestionView`类：

```py
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import CreateView

from qanda.forms import QuestionForm
from qanda.models import Question

class AskQuestionView(LoginRequiredMixin, CreateView):
    form_class = QuestionForm
    template_name = 'qanda/ask.html'

    def get_initial(self):
        return {
            'user': self.request.user.id
        }

    def form_valid(self, form):
        action = self.request.POST.get('action')
        if action == 'SAVE':
            # save and redirect as usual.
            return super().form_valid(form)
        elif action == 'PREVIEW':
            preview = Question(
                question=form.cleaned_data['question'],
                title=form.cleaned_data['title'])
            ctx = self.get_context_data(preview=preview)
            return self.render_to_response(context=ctx)
        return HttpResponseBadRequest()
```

`AskQuestionView`派生自`CreateView`并使用`LoginRequiredMixin`。`LoginRequiredMixin`确保任何未登录用户发出的请求都将被重定向到登录页面。`CreateView`知道如何为`GET`请求呈现模板，并在`POST`请求上验证表单。如果表单有效，`CreateView`将调用`form_valid`。如果表单无效，`CreateView`将重新呈现模板。

我们的`form_valid`方法覆盖了原始的`CreateView`方法，以支持保存和预览模式。当我们想要保存时，我们将调用原始的`form_valid`方法。原始方法保存新问题并返回一个 HTTP 响应，将用户重定向到新问题（使用`Question.get_absolute_url()`）。当我们想要预览问题时，我们将在我们模板的上下文中重新呈现我们的模板，其中包含新的`preview`变量。

当我们的视图实例化表单时，它将把`get_initial()`的结果作为`initial`参数传递，并将`POST`数据作为`data`参数传递。

现在我们有了我们的视图，让我们创建`ask.html`。

# 创建 ask.html

让我们在`django/qanda/ask.html`中创建我们的模板：

```py
{% extends "base.html" %}

{% load markdownify %}
{% load crispy_forms_tags %}

{% block title %} Ask a question {% endblock %}

{% block body %}
  <div class="col-md-12" >
    <h1 >Ask a question</h1 >
    {% if preview %}
      <div class="card question-preview" >
        <div class="card-header" >
          Question Preview
        </div >
        <div class="card-body" >
          <h1 class="card-title" >{{ preview.title }}</h1>
          {{ preview.question |  markdownify }}
        </div >
      </div >
    {% endif %}

    <form method="post" >
      {{ form | crispy }}
      {% csrf_token %}
      <button class="btn btn-primary" type="submit" name="action"
              value="PREVIEW" >
        Preview
      </button >
      <button class="btn btn-primary" type="submit" name="action"
              value="SAVE" >
        Ask!
      </button >
    </form >
  </div >
{% endblock %}
```

此模板使用我们的`base.html`模板，并将所有 HTML 放在那里定义的`blocks`中。当我们呈现模板时，Django 会呈现`base.html`，然后用在`ask.html`中定义的内容填充块的值。

`ask.html`还加载了两个第三方标签库，`markdownify`和`crispy_forms_tags`。`markdownify`提供了用于预览卡正文的`markdownify`过滤器（`{{preview.question | markdownify}}`）。`crispy_forms_tags`库提供了`crispy`过滤器，它应用 Bootstrap 4 CSS 类以帮助 Django 表单呈现得很好。

这些库中的每一个都需要安装和配置，我们将在接下来的部分中进行（*安装和配置 Markdownify*和*安装和配置 Django Crispy Forms*）。

以下是`ask.html`向我们展示的一些新标记：

+   `{% if preview %}`：这演示了如何在 Django 模板语言中使用`if`语句。我们只想在我们的上下文中有一个`preview`变量时才呈现`Question`的预览。

+   `{% csrf_token %}`：此标记将预期的 CSRF 令牌添加到我们的表单中。 CSRF 令牌有助于保护我们免受恶意脚本试图代表一个无辜但已登录的用户提交数据的攻击；有关更多信息，请参阅第三章，*海报、头像和安全性*。在 Django 中，CSRF 令牌是不可选的，缺少 CSRF 令牌的`POST`请求将不会被处理。

让我们更仔细地看看那些第三方库，从 Markdownify 开始。

# 安装和配置 Markdownify

Markdownify 是由 R Moelker 和 Erwin Matijsen 创建的 Django 应用程序，可在**Python Package Index**（**PyPI**）上找到，并根据 MIT 许可证（一种流行的开源许可证）进行许可。Markdownify 提供了 Django 模板过滤器`markdownify`，它将 Markdown 转换为 HTML。

Markdownify 通过使用**python-markdown**包将 Markdown 转换为 HTML 来工作。然后，Marodwnify 使用 Mozilla 的`bleach`库来清理结果 HTML，以防止跨站脚本（**XSS**）攻击。然后将结果返回到模板进行输出。

要安装 Markdownify，让我们将其添加到我们的`requirements.txt`文件中：

```py
django-markdownify==0.2.2
```

然后，运行`pip`进行安装：

```py
$ pip install -r requirements.txt
```

现在，我们需要在`django/config/settings.py`中将`markdownify`添加到我们的`INSTALLED_APPS`列表中。

最后一步是配置 Markdownify，让它知道要对哪些 HTML 标签进行白名单。将以下设置添加到`settings.py`中：

```py
MARKDOWNIFY_STRIP = False
MARKDOWNIFY_WHITELIST_TAGS = [
    'a', 'blockquote', 'code', 'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 
    'h7', 'li', 'ol', 'p', 'strong', 'ul',
]
```

这将使我们的用户可以使用所有文本、列表和标题标签。将`MARKDOWNIFY_STRIP`设置为`False`告诉 Markdownify 对其他 HTML 标签进行 HTML 编码（而不是剥离）。

现在我们已经配置了 Markdownify，让我们安装和配置 Django Crispy Forms。

# 安装和配置 Django Crispy Forms

Django Crispy Forms 是 PyPI 上可用的第三方 Django 应用程序。Miguel Araujo 是开发负责人。它是根据 MIT 许可证许可的。Django Crispy Forms 是最受欢迎的 Django 库之一，因为它使得渲染漂亮（清晰）的表单变得如此容易。

在 Django 中遇到的问题之一是，当 Django 渲染字段时，它会呈现为这样：

```py
<label for="id_title">Title:</label>
<input 
      type="text" name="title" maxlength="140" required id="id_title" />
```

然而，为了漂亮地设计该表单，例如使用 Bootstrap 4，我们希望呈现类似于这样的内容：

```py
<div class="form-group"> 
<label for="id_title" class="form-control-label  requiredField">
   Title
</label> 
<input type="text" name="title" maxlength="140" 
  class="textinput textInput form-control" required="" id="id_title">  
</div>
```

遗憾的是，Django 没有提供钩子，让我们轻松地将字段包装在具有类`form-group`的`div`中，或者添加 CSS 类，如`form-control`或`form-control-label`。

Django Crispy Forms 通过其`crispy`过滤器解决了这个问题。如果我们通过执行`{{ form | crispy}}`将一个表单发送到它，Django Crispy Forms 将正确地转换表单的 HTML 和 CSS，以适应各种 CSS 框架（包括 Zurb Foundation，Bootstrap 3 和 Bootstrap 4）。您可以通过更高级的使用 Django Crispy Forms 进一步自定义表单的渲染，但在本章中我们不会这样做。

要安装 Django Crispy Forms，让我们将其添加到我们的`requirements.txt`并使用`pip`进行安装：

```py
$ echo "django-crispy-forms==1.7.0" >> requirements.txt
$ pip install -r requirements.txt
```

现在，我们需要通过编辑`django/config/settings.py`并将`'crispy_forms'`添加到我们的`INSTALLED_APPS`列表中，将其安装为我们项目中的 Django 应用程序。

接下来，我们需要配置我们的项目，以便 Django Crispy Forms 知道使用 Bootstrap 4 模板包。更新`django/config/settings.py`以进行新的配置：

```py
CRISPY_TEMPLATE_PACK = 'bootstrap4'
```

现在我们已经安装了模板所依赖的所有库，我们可以配置 Django 将请求路由到我们的`AskQuestionView`。

# 将请求路由到 AskQuestionView

Django 使用 URLConf 路由请求。这是一个`path()`对象的列表，用于匹配请求的路径。第一个匹配的`path()`的视图将处理请求。URLConf 可以包含另一个 URLConf。项目的设置定义了其根 URLConf（在我们的情况下是`django/config/urls.py`）。

在根 URLConf 中为项目中所有视图的所有`path()`对象定义可以变得混乱，并使应用程序不太可重用。通常方便的做法是在每个应用程序中放置一个 URLConf（通常在`urls.py`文件中）。然后，根 URLConf 可以使用`include()`函数来包含其他应用程序的 URLConfs 以路由请求。

让我们在`django/qanda/urls.py`中为我们的`qanda`应用程序创建一个 URLConf：

```py
from django.urls.conf import path

from qanda import views

app_name = 'qanda'
urlpatterns = [
    path('ask', views.AskQuestionView.as_view(), name='ask'),
]
```

路径至少有两个组件：

+   首先，是定义匹配路径的字符串。这可能有命名参数，将传递给视图。稍后我们将在*将请求路由到 QuestionDetail 视图*部分看到一个例子。

+   其次，是一个接受请求并返回响应的可调用对象。如果您的视图是一个函数（也称为**基于函数的视图**（**FBV**）），那么您可以直接传递对函数的引用。如果您使用的是**基于类的视图**（**CBV**），那么您可以使用其`as_view()`类方法来返回所需的可调用对象。

+   可选的`name`参数，我们可以在视图或模板中引用这个`path()`对象（例如，就像`Question`模型在其`get_absolute_url()`方法中所做的那样）。

强烈建议为所有的`path()`对象命名。

现在，让我们更新我们的根 URLConf 以包括`qanda`的 URLConf：

```py
from django.contrib import admin
from django.urls import path, include

import qanda.urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include(qanda.urls, namespace='qanda')),
]
```

这意味着对`answerly.example.com/ask`的请求将路由到我们的`AskQuestionView`。

# 本节的快速回顾

在本节中，我们执行了以下操作：

+   创建了我们的第一个表单，`QuestionForm`

+   创建了使用`QuestionForm`创建`Question`的`AskQuestionView`

+   创建了一个模板来渲染`AskQuestionView`和`QuestionForm`

+   安装和配置了为我们的模板提供过滤器的第三方库

现在，让我们允许我们的用户使用`QuestionDetailView`类查看问题。

# 创建 QuestionDetailView

`QuestionDetailView`必须提供相当多的功能。它必须能够执行以下操作：

+   显示问题

+   显示所有答案

+   让用户发布额外的答案

+   让提问者接受答案

+   让提问者拒绝先前接受的答案

尽管`QuestionDetailView`不会处理任何表单，但它必须显示许多表单，导致一个复杂的模板。这种复杂性将给我们一个机会来注意如何将模板分割成单独的子模板，以使我们的代码更易读。

# 创建答案表单

我们需要制作两个表单，以使`QuestionDetailView`按照前一节的描述工作：

+   `AnswerForm`：供用户发布他们的答案

+   `AnswerAcceptanceForm`：供问题的提问者接受或拒绝答案

# 创建 AnswerForm

`AnswerForm`将需要引用一个`Question`模型实例和一个用户，因为这两者都是创建`Answer`模型实例所必需的。

让我们将我们的`AnswerForm`添加到`django/qanda/forms.py`中：

```py
from django import forms
from django.contrib.auth import get_user_model

from qanda.models import Answers

class AnswerForm(forms.ModelForm):
    user = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=get_user_model().objects.all(),
        disabled=True,
    )
    question = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=Question.objects.all(),
        disabled=True,
    )

    class Meta:
        model = Answer
        fields = ['answer', 'user', 'question', ]
```

`AnswerForm`类看起来很像`QuestionForm`类，尽管字段的命名略有不同。它使用了与`QuestionForm`相同的技术，防止用户篡改与`Answer`相关联的`Question`，就像`QuestionForm`用于防止篡改`Question`的用户一样。

接下来，我们将创建一个接受`Answer`的表单。

# 创建 AnswerAcceptanceForm

如果`accepted`字段为`True`，则`Answer`被接受。我们将使用一个简单的表单来编辑这个字段：

```py
class AnswerAcceptanceForm(forms.ModelForm):
    accepted = forms.BooleanField(
        widget=forms.HiddenInput,
        required=False,
    )

    class Meta:
        model = Answer
        fields = ['accepted', ]
```

使用`BooleanField`会有一个小问题。如果我们希望`BooleanField`接受`False`值以及`True`值，我们必须设置`required=False`。否则，`BooleanField`在接收到`False`值时会感到困惑，认为它实际上没有收到值。

我们使用了一个隐藏的输入，因为我们不希望用户勾选复选框然后再点击提交。相反，对于每个答案，我们将生成一个接受表单和一个拒绝表单，用户只需点击一次即可提交。

接下来，让我们编写`QuestionDetailView`类。

# 创建 QuestionDetailView

现在我们有了要使用的表单，我们可以在`django/qanda/views.py`中创建`QuestionDetailView`：

```py
from django.views.generic import DetailView

from qanda.forms import AnswerForm, AnswerAcceptanceForm
from qanda.models import Question

class QuestionDetailView(DetailView):
    model = Question

    ACCEPT_FORM = AnswerAcceptanceForm(initial={'accepted': True})
    REJECT_FORM = AnswerAcceptanceForm(initial={'accepted': False})

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx.update({
            'answer_form': AnswerForm(initial={
                'user': self.request.user.id,
                'question': self.object.id,
            })
        })
        if self.object.can_accept_answers(self.request.user):
            ctx.update({
                'accept_form': self.ACCEPT_FORM,
                'reject_form': self.REJECT_FORM,
            })
        return ctx
```

`QuestionDetailView`让 Django 的`DetailView`完成大部分工作。`DetailView`从`Question`的默认管理器（`Question.objects`）中获取一个`Question`的`QuerySet`。然后，`DetailView`使用`QuerySet`根据 URL 路径中收到的`pk`获取一个`Question`。`DetailView`还根据我们的应用程序和模型名称（`appname/modelname_detail.html`）知道要渲染哪个模板。

我们唯一需要自定义`DetailView`行为的地方是`get_context_data（）`。`get_context_data（）`提供用于呈现模板的上下文。在我们的情况下，我们使用该方法将要呈现的表单添加到上下文中。

接下来，让我们为`QuestionDetailView`创建模板。

# 创建 question_detail.html

我们的`QuestionDetailView`模板将与我们以前的模板略有不同。

以下是我们将放入`django/qanda/templates/qanda/question_detail.html`中的内容：

```py
{% extends "base.html" %}

{% block title %}{{ question.title }} - {{ block.super }}{% endblock %}

{% block body %}
  {% include "qanda/common/display_question.html" %}
  {% include "qanda/common/list_answers.html" %}
  {% if user.is_authenticated %}
    {% include "qanda/common/question_post_answer.html" %}
  {% else %}
    <div >Login to post answers.</div >
  {% endif %}
{% endblock %}
```

前面的模板似乎并没有做任何事情。相反，我们使用`{% include %}`标签将其他模板包含在此模板中，以使我们的代码组织更简单。`{% include %}`将当前上下文传递给新模板，呈现它，并将其插入到指定位置。

让我们依次查看这些子模板，从`dispaly_question.html`开始。

# 创建 display_question.html 通用模板

我们已经将显示问题的 HTML 放入了自己的子模板中。然后其他模板可以包含此模板，以呈现问题。

让我们在`django/qanda/templates/qanda/common/display_question.html`中创建它：

```py
{% load markdownify %}
<div class="question" >
  <div class="meta col-sm-12" >
    <h1 >{{ question.title }}</h1 >
    Asked by {{ question.user }} on {{ question.created }}
  </div >
  <div class="body col-sm-12" >
    {{ question.question|markdownify }}
  </div >
</div >
```

HTML 本身非常简单，在这里没有新标签。我们重用了之前配置的`markdownify`标签和库。

接下来，让我们看一下答案列表模板。

# 创建 list_answers.html

答案列表模板必须列出问题的所有答案，并渲染答案是否被接受。如果用户可以接受（或拒绝）答案，那么这些表单也会被呈现。

让我们在`django/qanda/templates/qanda/view_questions/question_answers.html`中创建模板：

```py
{% load markdownify %}
<h3 >Answers</h3 >
<ul class="list-unstyled answers" >
  {% for answer in question.answer_set.all %}
    <li class="answer row" >
      <div class="col-sm-3 col-md-2 text-center" >
        {% if answer.accepted %}
          <span class="badge badge-pill badge-success" >Accepted</span >
        {% endif %}
        {% if answer.accepted and reject_form %}
          <form method="post"
                action="{% url "qanda:update_answer_acceptance" pk=answer.id %}" >
            {% csrf_token %}
            {{ reject_form }}
            <button type="submit" class="btn btn-link" >
              <i class="fa fa-times" aria-hidden="true" ></i>
              Reject
            </button >
          </form >
        {% elif accept_form %}
          <form method="post"
                action="{% url "qanda:update_answer_acceptance" pk=answer.id %}" >
            {% csrf_token %}
            {{ accept_form }}
            <button type="submit" class="btn btn-link" title="Accept answer" >
              <i class="fa fa-check-circle" aria-hidden="true"></i >
              Accept
            </button >
          </form >
        {% endif %}
      </div >
      <div class="col-sm-9 col-md-10" >
        <div class="body" >{{ answer.answer|markdownify }}</div >
        <div class="meta font-weight-light" >
          Answered by {{ answer.user }} on {{ answer.created }}
        </div >
      </div >
    </li >
  {% empty %}
    <li class="answer" >No answers yet!</li >
  {% endfor %}
</ul >
```

关于这个模板有两件事需要注意：

+   模板中有一个罕见的逻辑，`{% if answer.accepted and reject_form %}`。通常，模板应该是简单的，避免了解业务逻辑。然而，避免这种情况会创建一个更复杂的视图。这是我们必须始终根据具体情况评估的权衡。

+   `{% empty %}`标签与我们的`{% for answer in question.answer_set.all %}`循环有关。`{% empty %}`在列表为空的情况下使用，就像 Python 的`for ... else`语法一样。

接下来，让我们看一下发布答案模板。

# 创建 post_answer.html 模板

在接下来要创建的模板中，用户可以发布和预览他们的答案。

让我们在`django/qanda/templates/qanda/common/post_answer.html`中创建我们的下一个模板：

```py
{% load crispy_forms_tags %}

<div class="col-sm-12" >
  <h3 >Post your answer</h3 >
  <form method="post"
        action="{% url "qanda:answer_question" pk=question.id %}" >
    {{ answer_form | crispy }}
    {% csrf_token %}
    <button class="btn btn-primary" type="submit" name="action"
            value="PREVIEW" >Preview
    </button >
    <button class="btn btn-primary" type="submit" name="action"
            value="SAVE" >Answer
    </button >
  </form >
</div >
```

这个模板非常简单，使用`crispy`过滤器对`answer_form`进行渲染。

现在我们所有的子模板都完成了，让我们创建一个`path`来将请求路由到`QuestionDetailView`。

# 将请求路由到 QuestionDetail 视图

为了能够将请求路由到我们的`QuestionDetailView`，我们需要将其添加到`django/qanda/urls.py`中的 URLConf：

```py
    path('q/<int:pk>', views.QuestionDetailView.as_view(),
         name='question_detail'),
```

在上述代码中，我们看到`path`使用了一个名为`pk`的参数，它必须是一个整数。这将传递给`QuestionDetailView`并在`kwargs`字典中可用。`DetailView`将依赖于此参数的存在来知道要检索哪个`Question`。

接下来，我们将创建一些我们在模板中引用的与表单相关的视图。让我们从`CreateAnswerView`类开始。

# 创建 CreateAnswerView

`CreateAnswerView`类将用于为`Question`模型实例创建和预览`Answer`模型实例。

让我们在`django/qanda/views.py`中创建它：

```py
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import CreateView

from qanda.forms import AnswerForm

class CreateAnswerView(LoginRequiredMixin, CreateView):
    form_class = AnswerForm
    template_name = 'qanda/create_answer.html'

    def get_initial(self):
        return {
            'question': self.get_question().id,
            'user': self.request.user.id,
        }

    def get_context_data(self, **kwargs):
        return super().get_context_data(question=self.get_question(),
                                        **kwargs)

    def get_success_url(self):
        return self.object.question.get_absolute_url()

    def form_valid(self, form):
        action = self.request.POST.get('action')
        if action == 'SAVE':
            # save and redirect as usual.
            return super().form_valid(form)
        elif action == 'PREVIEW':
            ctx = self.get_context_data(preview=form.cleaned_data['answer'])
            return self.render_to_response(context=ctx)
        return HttpResponseBadRequest()

    def get_question(self):
        return Question.objects.get(pk=self.kwargs['pk'])
```

`CreateAnswerView`类遵循与`AskQuestionView`类类似的模式：

+   这是一个`CreateView`

+   它受`LoginRequiredMixin`保护

+   它使用`get_initial（）`为其表单提供初始参数，以便恶意用户无法篡改与答案相关的问题或用户

+   它使用`form_valid（）`来执行预览或保存操作

主要的区别是我们需要在 `CreateAnswerView` 中添加一个 `get_question()` 方法来检索我们要回答的问题。`kwargs['pk']` 将由我们将创建的 `path` 填充（就像我们为 `QuestionDetailView` 做的那样）。

接下来，让我们创建模板。

# 创建 create_answer.html

这个模板将能够利用我们已经创建的常见模板元素，使渲染问题和答案表单更容易。

让我们在 `django/qanda/templates/qanda/create_answer.html` 中创建它：

```py
{% extends "base.html" %}
{% load markdownify %}

{% block body %}
  {% include 'qanda/common/display_question.html' %}
  {% if preview %}
    <div class="card question-preview" >
      <div class="card-header" >
        Answer Preview
      </div >
      <div class="card-body" >
        {{ preview|markdownify }}
      </div >
    </div >
  {% endif %}
  {% include 'qanda/common/post_answer.html' with answer_form=form %}
{% endblock %}
```

前面的模板介绍了 `{% include %}` 的新用法。当我们使用 `with` 参数时，我们可以传递一系列新名称，这些值应该在子模板的上下文中具有。在我们的情况下，我们只会将 `answer_form` 添加到 `post_answer.html` 的上下文中。其余的上下文仍然被传递给 `{% include %}`。如果我们在 `{% include %}` 的最后一个参数中添加 `only`，我们可以阻止其余的上下文被传递。

# 将请求路由到 CreateAnswerView

最后一步是通过在 `qanda/urls.py` 的 `urlpatterns` 列表中添加一个新的 `path` 来将 `CreateAnswerView` 连接到 `qanda` URLConf 中：

```py
   path('q/<int:pk>/answer', views.CreateAnswerView.as_view(),
         name='answer_question'),
```

接下来，我们将创建一个视图来处理 `AnswerAcceptanceForm`。

# 创建 UpdateAnswerAcceptanceView

我们在 `list_answers.html` 模板中使用的 `accept_form` 和 `reject_form` 变量需要一个视图来处理它们的表单提交。让我们将其添加到 `django/qanda/views.py` 中：

```py
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import UpdateView

from qanda.forms import AnswerAcceptanceForm
from qanda.models import Answer

class UpdateAnswerAcceptance(LoginRequiredMixin, UpdateView):
    form_class = AnswerAcceptanceForm
    queryset = Answer.objects.all()

    def get_success_url(self):
        return self.object.question.get_absolute_url()

    def form_invalid(self, form):
        return HttpResponseRedirect(
            redirect_to=self.object.question.get_absolute_url())
```

`UpdateView` 的工作方式类似于 `DetailView`（因为它在单个模型上工作）和 `CreateView`（因为它处理一个表单）。`CreateView` 和 `UpdateView` 共享一个共同的祖先：`ModelFormMixin`。`ModelFormMixin` 为我们提供了我们过去经常使用的钩子：`form_valid()`、`get_success_url()` 和 `form_invalid()`。

由于这个表单的简单性，我们将通过将用户重定向到问题来响应无效的表单。

接下来，让我们将其添加到我们的 URLConf 中的 `django/qanda/urls.py` 文件中：

```py
   path('a/<int:pk>/accept', views.UpdateAnswerAcceptance.as_view(),
         name='update_answer_acceptance'),
```

记得在你的 `path()` 对象的第一个参数中有一个名为 `pk` 的参数，这样 `UpdateView` 就可以检索到正确的 `Answer`。

接下来，让我们创建一个每日问题列表。

# 创建每日问题页面

为了帮助人们找到问题，我们将创建每天问题的列表。

Django 提供了创建年度、月度、周度和每日归档视图的视图。在我们的情况下，我们将使用 `DailyArchiveView`，但它们基本上都是一样的。它们从 URL 的路径中获取一个日期，并在该期间搜索所有相关内容。

让我们使用 Django 的 `DailyArchiveView` 来构建一个每日问题列表。

# 创建 DailyQuestionList 视图

让我们将我们的 `DailyQuestionList` 视图添加到 `django/qanda/views.py` 中：

```py
from django.views.generic import DayArchiveView

from qanda.models import Question

class DailyQuestionList(DayArchiveView):
    queryset = Question.objects.all()
    date_field = 'created'
    month_format = '%m'
    allow_empty = True
```

`DailyQuestionList` 不需要覆盖 `DayArchiveView` 的任何方法，只需让 Django 做这项工作。让我们看看它是如何做到的。

`DayArchiveView` 期望在 URL 的路径中获取一个日期、月份和年份。我们可以使用 `day_format`、`month_format` 和 `year_format` 来指定这些的格式。在我们的情况下，我们将期望的格式更改为 `'%m'`，这样月份就会被解析为一个数字，而不是默认的 `'%b'`，这是月份的简称。这些格式与 Python 的标准 `datetime.datetime.strftime` 相同。一旦 `DayArchiveView` 有了日期，它就会使用该日期来过滤提供的 `queryset`，使用在 `date_field` 属性中命名的字段。`queryset` 按日期排序。如果 `allow_empty` 为 `True`，那么结果将被渲染，否则将抛出 404 异常，对于没有要列出的项目的日期。为了渲染模板，对象列表被传递到模板中，就像 `ListView` 一样。默认模板假定遵循 `appname/modelname_archive_day.html` 的格式。

接下来，让我们为这个视图创建模板。

# 创建每日问题列表模板

让我们将我们的模板添加到 `django/qanda/templates/qanda/question_archive_day.html` 中：

```py
{% extends "base.html" %}

{% block title %} Questions on {{ day }} {% endblock %}

{% block body %}
  <div class="col-sm-12" >
    <h1 >Highest Voted Questions of {{ day }}</h1 >
    <ul >
      {% for question in object_list %}
        <li >
          {{ question.votes }}
          <a href="{{ question.get_absolute_url }}" >
            {{ question }}
          </a >
          by
            {{ question.user }}
          on {{ question.created }}
        </li >
      {% empty %}
        <li>Hmm... Everyone thinks they know everything today.</li>
      {% endfor %}
    </ul >
    <div>
      {% if previous_day %}
        <a href="{% url "qanda:daily_questions" year=previous_day.year month=previous_day.month day=previous_day.day %}" >
           << Previous Day
        </a >
      {% endif %}
      {% if next_day %}
        <a href="{% url "qanda:daily_questions" year=next_day.year month=next_day.month day=next_day.day %}" >
          Next Day >>
        </a >
      {% endif %}
    </div >
  </div >
{% endblock %}
```

问题列表就像人们所期望的那样，即一个带有 `{% for %}` 循环创建 `<li>` 标签和链接的 `<ul>` 标签。

`DailyArchiveView`（以及所有日期存档视图）的一个便利之处是它们提供其模板的上下文，包括下一个和上一个日期。这些日期让我们在日期之间创建一种分页。

# 将请求路由到 DailyQuestionLists

最后，我们将创建一个`path`到我们的`DailyQuestionList`视图，以便我们可以将请求路由到它：

```py
    path('daily/<int:year>/<int:month>/<int:day>/',
         views.DailyQuestionList.as_view(),
         name='daily_questions'),
```

接下来，让我们创建一个视图来代表*今天*的问题。

# 获取今天的问题列表

拥有每日存档是很好的，但我们希望提供一种方便的方式来访问今天的存档。我们将使用`RedirectView`来始终将用户重定向到今天日期的`DailyQuestionList`。

让我们将其添加到`django/qanda/views.py`中：

```py
class TodaysQuestionList(RedirectView):
    def get_redirect_url(self, *args, **kwargs):
        today = timezone.now()
        return reverse(
            'questions:daily_questions',
            kwargs={
                'day': today.day,
                'month': today.month,
                'year': today.year,
            }
        )
```

`RedirectView`是一个简单的视图，返回 301 或 302 重定向响应。我们使用 Django 的`django.util.timezone`根据 Django 的配置获取今天的日期。默认情况下，Django 使用**协调世界时**（**UTC**）进行配置。由于时区的复杂性，通常最简单的方法是在 UTC 中跟踪所有内容，然后在客户端上调整显示。

我们现在已经为我们的初始`qanda`应用程序创建了所有的视图，让用户提问和回答问题。提问者还可以接受问题的答案。

接下来，让我们让用户实际上可以使用`user`应用程序登录、注销和注册。

# 创建用户应用程序

正如我们之前提到的，Django 应用程序应该有一个明确的范围。为此，我们将创建一个单独的 Django 应用程序来管理用户，我们将其称为`user`。我们不应该将我们的用户管理代码放在`qanda`或者`user`应用程序中的`Question`模型。

让我们使用`manage.py`创建应用：

```py
$ python manage.py startapp user
```

然后，将其添加到`django/config/settings.py`的`INSTALLED_APPS`列表中：

```py
INSTALLED_APPS = [
    'user',
    'qanda',

    'markdownify',
    'crispy_forms',

    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]
```

特别重要的是要将`user`应用程序*放在*`admin`应用程序之前，因为它们都将定义登录模板。先到达的应用程序将首先解析其登录模板。我们不希望我们的用户被重定向到管理员应用程序。

接下来，让我们在`django/user/urls.py`中为我们的`user`应用程序创建一个 URLConf：

```py
from django.urls import path

import user.views

app_name = 'user'
urlpatterns = [
]
```

现在，我们将在`django/config/urls.py`中的主 URLConf 中包含`user`应用程序的 URLConf：

```py
from django.contrib import admin
from django.urls import path, include

import qanda.urls
import user.urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/', include(user.urls, namespace='user')),
    path('', include(qanda.urls, namespace='questions')),
]
```

现在我们已经配置了我们的应用程序，我们可以添加我们的登录和注销视图。

# 使用 Django 的 LoginView 和 LogoutView

为了提供登录和注销功能，我们将使用`django.contrib.auth`应用提供的视图。让我们更新`django/users/urls.py`来引用它们：

```py
from django.urls import path

import user.views

app_name = 'user'
urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),
]
```

这些视图负责登录和注销用户。然而，登录视图需要一个模板来渲染得漂亮。`LoginView`期望它在`registration/login.html`名称下。

我们将模板放在`django/user/templates/registration/login.html`中：

```py
{% extends "base.html" %}
{% load crispy_forms_tags %}

{% block title %} Login - {{ block.super }} {% endblock %}

{% block body %}
  <h1>Login</h1>
  <form method="post" class="col-sm-6">
    {% csrf_token %}
    {{ form|crispy }}
    <button type="submit" class="btn btn-primary">Login</button>
  </form>
{% endblock %}
```

`LogoutView`不需要一个模板。

现在，我们需要通知我们 Django 项目的`settings.py`关于登录视图的位置以及用户登录和注销时应执行的功能。让我们在`django/config/settings.py`中添加一些设置：

```py
LOGIN_URL = 'user:login'
LOGIN_REDIRECT_URL = 'questions:index'
LOGOUT_REDIRECT_URL = 'questions:index'
```

这样，`LoginRequiredMixin`就可以知道我们需要将未经身份验证的用户重定向到哪个视图。我们还通知了`django.contrib.auth`的`LoginView`和`LogoutView`在用户登录和注销时分别将用户重定向到哪里。

接下来，让我们为用户提供一种注册网站的方式。

# 创建 RegisterView

Django 不提供用户注册视图，但如果我们使用`django.conrib.auth.models.User`作为用户模型，它确实提供了一个`UserCreationForm`。由于我们使用`django.conrib.auth.models.User`，我们可以为我们的注册视图使用一个简单的`CreateView`：

```py
from django.contrib.auth.forms import UserCreationForm
from django.views.generic.edit import CreateView

class RegisterView(CreateView):
    template_name = 'user/register.html'
    form_class = UserCreationForm
```

现在，我们只需要在`django/user/templates/register.html`中创建一个模板：

```py
{% extends "base.html" %}
{% load crispy_forms_tags %}
{% block body %}
  <div class="col-sm-12">
    <h1 >Register for MyQA</h1 >
    <form method="post" >
      {% csrf_token %}
      {{ form | crispy }}
      <button type="submit" class="btn btn-primary" >
        Register
      </button >
    </form >
  </div >
{% endblock %}
```

同样，我们的模板遵循了一个熟悉的模式，类似于我们在过去的视图中看到的。我们使用我们的基本模板、块和 Django Crispy Form 来快速简单地创建我们的页面。

最后，我们可以在`user` URLConf 的`urlpatterns`列表中添加一个`path`到该视图：

```py
path('register', user.views.RegisterView.as_view(), name='register'),
```

# 更新 base.html 导航

现在我们已经创建了所有的视图，我们可以更新我们基础模板的`<nav>`来列出所有我们的 URL：

```py
{% load static %}
<!DOCTYPE html>
<html lang="en" >
<head >
{# skipping unchanged head contents #}
</head >
<body >
<nav class="navbar navbar-expand-lg  bg-light" >
  <div class="container" >
    <a class="navbar-brand" href="/" >Answerly</a >
    <ul class="navbar-nav" >
      <li class="nav-item" >
        <a class="nav-link" href="{% url "qanda:ask" %}" >Ask</a >
      </li >
      <li class="nav-item" >
        <a
            class="nav-link"
            href="{% url "qanda:index" %}" >
          Today's  Questions
        </a >
      </li >
      {% if user.is_authenticated %}
        <li class="nav-item" >
          <a class="nav-link" href="{% url "user:logout" %}" >Logout</a >
        </li >
      {% else %}
        <li class="nav-item" >
          <a class="nav-link" href="{% url "user:login" %}" >Login</a >
        </li >
        <li class="nav-item" >
          <a class="nav-link" href="{% url "user:register" %}" >Register</a >
        </li >
      {% endif %}
    </ul >
  </div >
</nav >
<div class="container" >
  {% block body %}{% endblock %}
</div >
</body >
</html >
```

太好了！现在我们的用户可以随时访问我们网站上最重要的页面。

# 运行开发服务器

最后，我们可以使用以下命令访问我们的开发服务器：

```py
$ cd django
$ python manage.py runserver
```

现在我们可以在浏览器中打开网站 [`localhost:8000/`](http://localhost::8000/)。

# 总结

在本章中，我们开始了 Answerly 项目。Answerly 由两个应用程序（`user`和`qanda`）组成，通过 PyPI 安装了两个第三方应用程序（Markdownify 和 Django Crispy Forms），以及一些 Django 内置应用程序（`django.contrib.auth`被直接使用）。

已登录用户现在可以提问，回答问题，并接受答案。我们还可以看到每天投票最高的问题。

接下来，我们将通过使用 ElasticSearch 添加搜索功能，帮助用户更轻松地发现问题。
