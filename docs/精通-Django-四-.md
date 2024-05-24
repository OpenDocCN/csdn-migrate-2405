# 精通 Django（四）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：通用视图

这里再次出现了本书的一个重要主题：在最糟糕的情况下，Web 开发是乏味和单调的。到目前为止，我们已经介绍了 Django 如何在模型和模板层减轻了一些单调，但 Web 开发人员在视图层也会经历这种乏味。

Django 的*通用视图*是为了减轻这种痛苦而开发的。

它们采用了在视图开发中发现的某些常见习语和模式，并对它们进行抽象，以便您可以快速编写常见的数据视图，而无需编写太多代码。我们可以识别出某些常见任务，比如显示对象列表，并编写显示任何对象列表的代码。

然后，可以将相关模型作为 URLconf 的额外参数传递。Django 附带了用于执行以下操作的通用显示视图：

+   显示单个对象的列表和详细页面。如果我们正在创建一个管理会议的应用程序，那么`TalkListView`和`RegisteredUserListView`将是列表视图的示例。单个讲话页面是我们称之为详细视图的示例。

+   在年/月/日归档页面、相关详细信息和最新页面中呈现基于日期的对象。

+   允许用户创建、更新和删除对象-无论是否授权。

这些视图一起提供了执行开发人员在视图中显示数据库数据时遇到的最常见任务的简单界面。最后，显示视图只是 Django 全面基于类的视图系统的一部分。有关 Django 提供的其他基于类的视图的完整介绍和详细描述，请参阅附录 C，*通用视图参考*。

# 对象的通用视图

当涉及呈现数据库内容的视图时，Django 的通用视图确实表现出色。因为这是一个常见的任务，Django 附带了一些内置的通用视图，使生成对象的列表和详细视图变得非常容易。

让我们从一些显示对象列表或单个对象的示例开始。我们将使用这些模型：

```py
# models.py 
from django.db import models 

class Publisher(models.Model): 
    name = models.CharField(max_length=30) 
    address = models.CharField(max_length=50) 
    city = models.CharField(max_length=60) 
    state_province = models.CharField(max_length=30) 
    country = models.CharField(max_length=50) 
    website = models.URLField() 

    class Meta: 
        ordering = ["-name"] 

    def __str__(self): 
        return self.name 

class Author(models.Model): 
    salutation = models.CharField(max_length=10) 
    name = models.CharField(max_length=200) 
    email = models.EmailField() 
    headshot = models.ImageField(upload_to='author_headshots') 

    def __str__(self): 
        return self.name 

class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField('Author') 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField() 

```

现在我们需要定义一个视图：

```py
# views.py 
from django.views.generic import ListView 
from books.models import Publisher 

class PublisherList(ListView): 
    model = Publisher 

```

最后将该视图挂接到您的 URL 中：

```py
# urls.py 
from django.conf.urls import url 
from books.views import PublisherList 

urlpatterns = [ 
    url(r'^publishers/$', PublisherList.as_view()), 
] 

```

这是我们需要编写的所有 Python 代码。但是，我们仍然需要编写一个模板。但是，我们可以通过向视图添加`template_name`属性来明确告诉视图使用哪个模板，但在没有显式模板的情况下，Django 将从对象的名称中推断一个模板。在这种情况下，推断的模板将是`books/publisher_list.html`-books 部分来自定义模型的定义应用程序的名称，而“publisher”部分只是模型名称的小写版本。

因此，当（例如）在`TEMPLATES`中将`DjangoTemplates`后端的`APP_DIRS`选项设置为 True 时，模板位置可以是：`/path/to/project/books/templates/books/publisher_list.html`

这个模板将根据包含名为`object_list`的变量的上下文进行渲染，该变量包含所有发布者对象。一个非常简单的模板可能如下所示：

```py
{% extends "base.html" %} 

{% block content %} 
    <h2>Publishers</h2> 
    <ul> 
        {% for publisher in object_list %} 
            <li>{{ publisher.name }}</li> 
        {% endfor %} 
    </ul> 
{% endblock %} 

```

这就是全部。通用视图的所有很酷的功能都来自于更改通用视图上设置的属性。附录 C，*通用视图参考*，详细记录了所有通用视图及其选项；本文档的其余部分将考虑您可能定制和扩展通用视图的一些常见方法。

# 创建“友好”的模板上下文

您可能已经注意到我们的示例发布者列表模板将所有发布者存储在名为`object_list`的变量中。虽然这样做完全没问题，但对于模板作者来说并不是很“友好”：他们必须“知道”他们在这里处理的是发布者。

在 Django 中，如果您正在处理模型对象，则已为您完成此操作。 当您处理对象或查询集时，Django 使用模型类名称的小写版本填充上下文。 除了默认的`object_list`条目之外，这是额外提供的，但包含完全相同的数据，即`publisher_list`。

如果这仍然不是一个很好的匹配，您可以手动设置上下文变量的名称。 通用视图上的`context_object_name`属性指定要使用的上下文变量：

```py
# views.py 
from django.views.generic import ListView 
from books.models import Publisher 

class PublisherList(ListView): 
    model = Publisher 
 context_object_name = 'my_favorite_publishers'

```

提供有用的`context_object_name`始终是一个好主意。 设计模板的同事会感谢您。

# 添加额外的上下文

通常，您只需要提供一些通用视图提供的信息之外的额外信息。 例如，考虑在每个出版商详细页面上显示所有书籍的列表。 `DetailView`通用视图提供了出版商的上下文，但是我们如何在模板中获取额外的信息呢？

答案是子类化`DetailView`并提供您自己的`get_context_data`方法的实现。 默认实现只是将要显示的对象添加到模板中，但您可以重写它以发送更多内容：

```py
from django.views.generic import DetailView 
from books.models import Publisher, Book 

class PublisherDetail(DetailView): 

    model = Publisher 

    def get_context_data(self, **kwargs): 
        # Call the base implementation first to get a context 
        context = super(PublisherDetail, self).get_context_data(**kwargs) 
        # Add in a QuerySet of all the books 
        context['book_list'] = Book.objects.all() 
        return context 

```

### 注意

通常，`get_context_data`将合并当前类的所有父类的上下文数据。 要在您自己的类中保留此行为，其中您想要更改上下文，您应该确保在超类上调用`get_context_data`。 当没有两个类尝试定义相同的键时，这将产生预期的结果。

但是，如果任何类尝试在父类设置它之后覆盖键（在调用 super 之后），那么该类的任何子类在 super 之后也需要显式设置它，如果他们想确保覆盖所有父类。 如果您遇到问题，请查看视图的方法解析顺序。

# 查看对象的子集

现在让我们更仔细地看看我们一直在使用的`model`参数。 `model`参数指定视图将操作的数据库模型，在操作单个对象或一组对象的所有通用视图上都可用。 但是，`model`参数不是指定视图将操作的对象的唯一方法-您还可以使用`queryset`参数指定对象的列表：

```py
from django.views.generic import DetailView 
from books.models import Publisher 

class PublisherDetail(DetailView): 

    context_object_name = 'publisher' 
    queryset = Publisher.objects.all() 

```

指定`model = Publisher`实际上只是简写为`queryset = Publisher.objects.all()`。 但是，通过使用`queryset`来定义对象的过滤列表，您可以更具体地了解视图中将可见的对象。 举个简单的例子，我们可能想要按出版日期对书籍列表进行排序，最新的排在前面：

```py
from django.views.generic import ListView 
from books.models import Book 

class BookList(ListView): 
    queryset = Book.objects.order_by('-publication_date') 
    context_object_name = 'book_list' 

```

这是一个非常简单的例子，但它很好地说明了这个想法。 当然，您通常希望做的不仅仅是重新排序对象。 如果要显示特定出版商的书籍列表，可以使用相同的技术：

```py
from django.views.generic import ListView 
from books.models import Book 

class AcmeBookList(ListView): 

    context_object_name = 'book_list' 
    queryset = Book.objects.filter(publisher__name='Acme Publishing') 
    template_name = 'books/acme_list.html' 

```

请注意，除了过滤的`queryset`之外，我们还使用了自定义模板名称。 如果没有，通用视图将使用与“普通”对象列表相同的模板，这可能不是我们想要的。

还要注意，这不是一个非常优雅的处理特定出版商书籍的方法。 如果我们想要添加另一个出版商页面，我们需要在 URLconf 中添加另外几行，而且超过几个出版商将变得不合理。 我们将在下一节中解决这个问题。

### 注意

如果在请求`/books/acme/`时收到 404 错误，请检查确保您实际上有一个名称为'ACME Publishing'的出版商。 通用视图具有`allow_empty`参数用于此情况。

# 动态过滤

另一个常见的需求是通过 URL 中的某个键来过滤列表页面中给定的对象。 早些时候，我们在 URLconf 中硬编码了出版商的名称，但是如果我们想编写一个视图，显示某个任意出版商的所有书籍怎么办？

方便的是，`ListView` 有一个我们可以重写的 `get_queryset()` 方法。以前，它只是返回 `queryset` 属性的值，但现在我们可以添加更多逻辑。使这项工作的关键部分是，当调用基于类的视图时，各种有用的东西都存储在 `self` 上；除了请求（`self.request`）之外，还包括根据 URLconf 捕获的位置参数（`self.args`）和基于名称的参数（`self.kwargs`）。

在这里，我们有一个带有单个捕获组的 URLconf：

```py
# urls.py 
from django.conf.urls import url 
from books.views import PublisherBookList 

urlpatterns = [ 
    url(r'^books/([\w-]+)/$', PublisherBookList.as_view()), 
] 

```

接下来，我们将编写 `PublisherBookList` 视图本身：

```py
# views.py 
from django.shortcuts import get_object_or_404 
from django.views.generic import ListView 
from books.models import Book, Publisher 

class PublisherBookList(ListView): 

    template_name = 'books/books_by_publisher.html' 

    def get_queryset(self): 
        self.publisher = get_object_or_404(Publisher name=self.args[0]) 
        return Book.objects.filter(publisher=self.publisher) 

```

正如你所看到的，向查询集选择添加更多逻辑非常容易；如果我们想的话，我们可以使用 `self.request.user` 来使用当前用户进行过滤，或者其他更复杂的逻辑。我们还可以同时将发布者添加到上下文中，这样我们可以在模板中使用它：

```py
# ... 

def get_context_data(self, **kwargs): 
    # Call the base implementation first to get a context 
    context = super(PublisherBookList, self).get_context_data(**kwargs) 

    # Add in the publisher 
    context['publisher'] = self.publisher 
    return context 

```

# 执行额外的工作

我们将看一下最后一个常见模式，它涉及在调用通用视图之前或之后做一些额外的工作。想象一下，我们在我们的 `Author` 模型上有一个 `last_accessed` 字段，我们正在使用它来跟踪任何人最后一次查看该作者的时间：

```py
# models.py 
from django.db import models 

class Author(models.Model): 
    salutation = models.CharField(max_length=10) 
    name = models.CharField(max_length=200) 
    email = models.EmailField() 
    headshot = models.ImageField(upload_to='author_headshots') 
    last_accessed = models.DateTimeField() 

```

当然，通用的 `DetailView` 类不会知道这个字段，但我们可以再次轻松地编写一个自定义视图来保持该字段更新。首先，我们需要在 URLconf 中添加一个作者详细信息，指向一个自定义视图：

```py
from django.conf.urls import url 
from books.views import AuthorDetailView 

urlpatterns = [ 
    #... 
    url(r'^authors/(?P<pk>[0-9]+)/$', AuthorDetailView.as_view(), name='author-detail'), 
] 

```

然后我们会编写我们的新视图 - `get_object` 是检索对象的方法 - 所以我们只需重写它并包装调用：

```py
from django.views.generic import DetailView 
from django.utils import timezone 
from books.models import Author 

class AuthorDetailView(DetailView): 

    queryset = Author.objects.all() 

    def get_object(self): 
        # Call the superclass 
        object = super(AuthorDetailView, self).get_object() 

        # Record the last accessed date 
        object.last_accessed = timezone.now() 
        object.save() 
        # Return the object 
        return object 

```

这里的 URLconf 使用了命名组 `pk` - 这个名称是 `DetailView` 用来查找用于过滤查询集的主键值的默认名称。

如果你想给组起一个别的名字，你可以在视图上设置 `pk_url_kwarg`。更多细节可以在 `DetailView` 的参考中找到。

# 接下来呢？

在这一章中，我们只看了 Django 预装的一些通用视图，但这里提出的一般思想几乎适用于任何通用视图。附录 C，通用视图参考，详细介绍了所有可用的视图，如果你想充分利用这一强大功能，建议阅读。

这结束了本书专门讨论模型、模板和视图的高级用法的部分。接下来的章节涵盖了现代商业网站中非常常见的一系列功能。我们将从构建交互式网站至关重要的主题开始 - 用户管理。


# 第十一章：Django 中的用户身份验证

现代互动网站的重要百分比允许某种形式的用户交互-从在博客上允许简单评论，到在新闻网站上完全控制文章的编辑。如果网站提供任何形式的电子商务，对付费客户进行身份验证和授权是必不可少的。

仅仅管理用户-忘记用户名、忘记密码和保持信息更新可能会是一个真正的痛苦。作为程序员，编写身份验证系统甚至可能更糟。

幸运的是，Django 提供了默认实现来管理用户帐户、组、权限和基于 cookie 的用户会话。

与 Django 中的大多数内容一样，默认实现是完全可扩展和可定制的，以满足项目的需求。所以让我们开始吧。

# 概述

Django 身份验证系统处理身份验证和授权。简而言之，身份验证验证用户是否是他们声称的人，授权确定经过身份验证的用户被允许做什么。这里使用身份验证一词来指代这两个任务。

身份验证系统包括：

+   用户

+   权限：二进制（是/否）标志，指示用户是否可以执行某项任务

+   组：一种将标签和权限应用于多个用户的通用方法

+   可配置的密码哈希系统

+   用于管理用户身份验证和授权的表单。

+   用于登录用户或限制内容的视图工具

+   可插拔的后端系统

Django 中的身份验证系统旨在非常通用，并且不提供一些常见的 Web 身份验证系统中常见的功能。这些常见问题的解决方案已经在第三方软件包中实现：

+   密码强度检查

+   登录尝试的限制

+   针对第三方的身份验证（例如 OAuth）

# 使用 Django 身份验证系统

Django 的身份验证系统在其默认配置中已经发展到满足最常见的项目需求，处理了相当广泛的任务，并且对密码和权限进行了谨慎的实现。对于身份验证需求与默认设置不同的项目，Django 还支持对身份验证进行广泛的扩展和定制。

# 用户对象

`User`对象是身份验证系统的核心。它们通常代表与您的站点交互的人，并用于启用诸如限制访问、注册用户配置文件、将内容与创建者关联等功能。在 Django 的身份验证框架中只存在一类用户，即`superusers`或管理员`staff`用户只是具有特殊属性设置的用户对象，而不是不同类别的用户对象。默认用户的主要属性是：

+   “用户名”

+   “密码”

+   “电子邮件”

+   “名”

+   “姓”

## 创建超级用户

使用`createsuperuser`命令创建超级用户：

```py
python manage.py createsuperuser -username=joe -email=joe@example.com 

```

系统将提示您输入密码。输入密码后，用户将立即创建。如果省略`-username`或`-email`选项，系统将提示您输入这些值。

## 创建用户

创建和管理用户的最简单、最不容易出错的方法是通过 Django 管理员。Django 还提供了内置的视图和表单，允许用户登录、退出和更改自己的密码。我们稍后将在本章中查看通过管理员和通用用户表单进行用户管理，但首先，让我们看看如何直接处理用户身份验证。

创建用户的最直接方法是使用包含的`create_user()`辅助函数：

```py
>>> from Django.contrib.auth.models import User 
>>> user = User.objects.create_user('john', 'lennon@thebeatles.com', 'johnpassword') 

# At this point, user is a User object that has already been saved 
# to the database. You can continue to change its attributes 
# if you want to change other fields. 
>>> user.last_name = 'Lennon' 
>>> user.save() 

```

## 更改密码

Django 不会在用户模型上存储原始（明文）密码，而只会存储哈希值。因此，不要尝试直接操作用户的密码属性。这就是为什么在创建用户时使用辅助函数的原因。要更改用户的密码，您有两个选项：

+   `manage.py changepassword username`提供了一种从命令行更改用户密码的方法。它会提示您更改给定用户的密码，您必须输入两次。如果两者匹配，新密码将立即更改。如果您没有提供用户，命令将尝试更改与当前系统用户匹配的用户的密码。

+   您还可以使用`set_password()`以编程方式更改密码：

```py
        >>> from Django.contrib.auth.models import User 
        >>> u = User.objects.get(username='john') 
        >>> u.set_password('new password') 
        >>> u.save() 

```

更改用户的密码将注销其所有会话，如果启用了`SessionAuthenticationMiddleware`。

# 权限和授权

Django 带有一个简单的权限系统。它提供了一种将权限分配给特定用户和用户组的方法。它被 Django 管理站点使用，但欢迎您在自己的代码中使用它。Django 管理站点使用权限如下：

+   查看*add*表单和添加对象的访问权限仅限于具有该类型对象的*add*权限的用户。

+   查看更改列表，查看*change*表单和更改对象的访问权限仅限于具有该类型对象的*change*权限的用户。

+   删除对象的访问权限仅限于具有该类型对象的*delete*权限的用户。

权限不仅可以针对对象类型设置，还可以针对特定对象实例设置。通过使用`ModelAdmin`类提供的`has_add_permission()`、`has_change_permission()`和`has_delete_permission()`方法，可以为同一类型的不同对象实例自定义权限。`User`对象有两个多对多字段：`groups`和`user_permissions`。`User`对象可以像任何其他 Django 模型一样访问其相关对象。

## 默认权限

当在您的`INSTALLED_APPS`设置中列出`Django.contrib.auth`时，它将确保为您安装的应用程序中定义的每个 Django 模型创建三个默认权限-添加、更改和删除。每次运行`manage.py migrate`时，这些权限将为所有新模型创建。

## 用户组

`Django.contrib.auth.models.Group`模型是一种通用的方式，可以对用户进行分类，以便为这些用户应用权限或其他标签。用户可以属于任意数量的组。组中的用户将自动获得该组授予的权限。例如，如果组`站点编辑`具有权限`can_edit_home_page`，则该组中的任何用户都将具有该权限。

除了权限之外，用户组是一种方便的方式，可以对用户进行分类，给他们一些标签或扩展功能。例如，您可以创建一个名为`特殊用户`的用户组，并编写代码，例如，让他们访问站点的仅限会员部分，或者发送他们仅限会员的电子邮件。

## 以编程方式创建权限

虽然可以在模型的`Meta`类中定义自定义权限，但也可以直接创建权限。例如，您可以在`books`中的`BookReview`模型中创建`can_publish`权限：

```py
from books.models import BookReview 
from Django.contrib.auth.models import Group, Permission 
from Django.contrib.contenttypes.models import ContentType 

content_type = ContentType.objects.get_for_model(BookReview) 
permission = Permission.objects.create(codename='can_publish', 
                                       name='Can Publish Reviews', 
                                       content_type=content_type) 

```

然后可以通过其`user_permissions`属性将权限分配给`User`，或者通过其`permissions`属性将权限分配给`Group`。

## 权限缓存

`ModelBackend`在首次需要获取权限进行权限检查后，会在`User`对象上缓存权限。这通常对于请求-响应周期来说是可以的，因为权限通常不会在添加后立即进行检查（例如在管理站点中）。

如果您正在添加权限并立即进行检查，例如在测试或视图中，最简单的解决方案是重新从数据库中获取`User`。例如：

```py
from Django.contrib.auth.models import Permission, User 
from Django.shortcuts import get_object_or_404 

def user_gains_perms(request, user_id): 
    user = get_object_or_404(User, pk=user_id) 
    # any permission check will cache the current set of permissions 
    user.has_perm('books.change_bar') 

    permission = Permission.objects.get(codename='change_bar') 
    user.user_permissions.add(permission) 

    # Checking the cached permission set 
    user.has_perm('books.change_bar')  # False 

    # Request new instance of User 
    user = get_object_or_404(User, pk=user_id) 

    # Permission cache is repopulated from the database 
    user.has_perm('books.change_bar')  # True 

    # ... 

```

# Web 请求中的身份验证

Django 使用会话和中间件将认证系统连接到`request`对象。这些为每个请求提供了一个`request.user`属性，表示当前用户。如果当前用户没有登录，这个属性将被设置为`AnonymousUser`的一个实例，否则它将是`User`的一个实例。你可以用`is_authenticated()`来区分它们，就像这样：

```py
if request.user.is_authenticated(): 
    # Do something for authenticated users. 
else: 
    # Do something for anonymous users. 

```

## 如何登录用户

要登录用户，从视图中使用`login()`。它接受一个`HttpRequest`对象和一个`User`对象。`login()`使用 Django 的会话框架在会话中保存用户的 ID。请注意，匿名会话期间设置的任何数据在用户登录后仍保留在会话中。这个例子展示了你可能如何同时使用`authenticate()`和`login()`：

```py
from Django.contrib.auth import authenticate, login 

def my_view(request): 
    username = request.POST['username'] 
    password = request.POST['password'] 
    user = authenticate(username=username, password=password) 
    if user is not None: 
        if user.is_active: 
            login(request, user) 
            # Redirect to a success page. 
        else: 
            # Return a 'disabled account' error message 
    else: 
        # Return an 'invalid login' error message. 

```

### 注意

**首先调用**`authenticate()` 

当你手动登录用户时，你必须在调用`login()`之前调用`authenticate()`。`authenticate()`设置了一个属性，指示哪个认证后端成功地认证了该用户，这些信息在登录过程中稍后是需要的。如果你尝试直接从数据库中检索用户对象登录，将会引发错误。

## 如何注销用户

要注销通过`login()`登录的用户，使用`logout()`在你的视图中。它接受一个`HttpRequest`对象，没有返回值。例如：

```py
from Django.contrib.auth import logout 

def logout_view(request): 
    logout(request) 
    # Redirect to a success page. 

```

请注意，如果用户未登录，`logout()`不会抛出任何错误。当你调用`logout()`时，当前请求的会话数据将被完全清除。所有现有的数据都将被删除。这是为了防止另一个人使用相同的网络浏览器登录并访问先前用户的会话数据。

如果你想把任何东西放到会话中，用户在注销后立即可用，那就在调用`logout()`后这样做。

## 限制已登录用户的访问

### 原始方法

限制访问页面的简单、原始方法是检查`request.user.is_authenticated()`，并重定向到登录页面：

```py
from Django.shortcuts import redirect 

def my_view(request): 
    if not request.user.is_authenticated(): 
        return redirect('/login/?next=%s' % request.path) 
    # ... 

```

...或显示错误消息：

```py
from Django.shortcuts import render 

def my_view(request): 
    if not request.user.is_authenticated(): 
        return render(request, 'books/login_error.html') 
    # ... 

```

### login_required 装饰器

作为快捷方式，你可以使用方便的`login_required()`装饰器：

```py
from Django.contrib.auth.decorators import login_required 

@login_required 
def my_view(request): 
    ... 

```

`login_required()`做了以下事情：

+   如果用户未登录，重定向到`LOGIN_URL`，在查询字符串中传递当前的绝对路径。例如：`/accounts/login/?next=/reviews/3/`。

+   如果用户已登录，正常执行视图。视图代码可以自由假设用户已登录。

默认情况下，用户在成功验证后应重定向到的路径存储在一个名为`next`的查询字符串参数中。如果你想使用不同的名称来使用这个参数，`login_required()`接受一个可选的`redirect_field_name`参数：

```py
from Django.contrib.auth.decorators import login_required 

@login_required(redirect_field_name='my_redirect_field') 
def my_view(request): 
    ... 

```

请注意，如果你为`redirect_field_name`提供一个值，你很可能需要自定义你的登录模板，因为模板上下文变量存储重定向路径将使用`redirect_field_name`的值作为其键，而不是`next`（默认值）。`login_required()`还接受一个可选的`login_url`参数。例如：

```py
from Django.contrib.auth.decorators import login_required 

@login_required(login_url='/accounts/login/') 
def my_view(request): 
    ... 

```

请注意，如果你没有指定`login_url`参数，你需要确保`LOGIN_URL`和你的登录视图正确关联。例如，使用默认值，将以下行添加到你的 URLconf 中：

```py
from Django.contrib.auth import views as auth_views 

url(r'^accounts/login/$', auth_views.login), 

```

`LOGIN_URL`也接受视图函数名称和命名的 URL 模式。这允许你在 URLconf 中自由重新映射你的登录视图，而不必更新设置。

**注意：**`login_required`装饰器不会检查用户的`is_active`标志。

### 限制已登录用户的访问，通过测试

基于某些权限或其他测试来限制访问，你需要做的基本上与前一节描述的一样。简单的方法是直接在视图中对`request.user`运行你的测试。例如，这个视图检查用户是否在所需的域中有电子邮件：

```py
def my_view(request): 
    if not request.user.email.endswith('@example.com'): 
        return HttpResponse("You can't leave a review for this book.") 
    # ... 

```

作为快捷方式，你可以使用方便的`user_passes_test`装饰器：

```py
from Django.contrib.auth.decorators import user_passes_test 

def email_check(user): 
    return user.email.endswith('@example.com') 

@user_passes_test(email_check) 
def my_view(request): 
    ... 

```

`user_passes_test()`需要一个必需的参数：一个接受`User`对象并在用户被允许查看页面时返回`True`的可调用对象。请注意，`user_passes_test()`不会自动检查`User`是否匿名。`user_passes_test()`接受两个可选参数：

+   `login_url`。允许您指定未通过测试的用户将被重定向到的 URL。如果您不指定，则可能是登录页面，默认为`LOGIN_URL`。

+   `redirect_field_name`。与`login_required()`相同。将其设置为`None`会将其从 URL 中删除，如果您将未通过测试的用户重定向到没有*下一页*的非登录页面，则可能需要这样做。

例如：

```py
@user_passes_test(email_check, login_url='/login/') 
def my_view(request): 
    ... 

```

### `permission_required()`装饰器

检查用户是否具有特定权限是一个相对常见的任务。因此，Django 为这种情况提供了一个快捷方式-`permission_required()`装饰器：

```py
from Django.contrib.auth.decorators import permission_required 

@permission_required('reviews.can_vote') 
def my_view(request): 
    ... 

```

就像`has_perm()`方法一样，权限名称采用`<app label>.<permission codename>`的形式（例如，`reviews.can_vote`表示`reviews`应用程序中模型的权限）。装饰器也可以接受一系列权限。请注意，`permission_required()`还接受一个可选的`login_url`参数。例如：

```py
from Django.contrib.auth.decorators import permission_required 

@permission_required('reviews.can_vote', login_url='/loginpage/') 
def my_view(request): 
    ... 

```

与`login_required()`装饰器一样，`login_url`默认为`LOGIN_URL`。如果给出了`raise_exception`参数，装饰器将引发`PermissionDenied`，提示 403（HTTP 禁止）视图，而不是重定向到登录页面。

### 密码更改时会话失效

如果您的`AUTH_USER_MODEL`继承自`AbstractBaseUser`，或者实现了自己的`get_session_auth_hash()`方法，经过身份验证的会话将包括此函数返回的哈希值。在`AbstractBaseUser`的情况下，这是密码字段的**哈希消息认证码**（**HMAC**）。

如果启用了`SessionAuthenticationMiddleware`，Django 会验证每个请求中发送的哈希值是否与服务器端计算的哈希值匹配。这允许用户通过更改密码注销所有会话。

Django 默认包含的密码更改视图，`Django.contrib.auth.views.password_change()`和`Django.contrib.auth`管理中的`user_change_password`视图，会使用新密码哈希更新会话，以便用户更改自己的密码时不会注销自己。如果您有自定义的密码更改视图，并希望具有类似的行为，请使用此函数：

```py
Django.contrib.auth.decorators.update_session_auth_hash (request, user) 

```

此函数接受当前请求和更新的用户对象，从中派生新会话哈希，并适当更新会话哈希。例如用法：

```py
from Django.contrib.auth import update_session_auth_hash 

def password_change(request): 
    if request.method == 'POST': 
        form = PasswordChangeForm(user=request.user, data=request.POST) 
        if form.is_valid(): 
            form.save() 
            update_session_auth_hash(request, form.user) 
    else: 
        ... 

```

由于`get_session_auth_hash()`基于`SECRET_KEY`，更新站点以使用新的密钥将使所有现有会话无效。

# 认证视图

Django 提供了几个视图，您可以用来处理登录、注销和密码管理。这些视图使用内置的认证表单，但您也可以传入自己的表单。Django 没有为认证视图提供默认模板-但是，每个视图的文档化模板上下文如下。

在项目中实现这些视图的方法有很多种，但是，最简单和最常见的方法是在您自己的 URLconf 中包含`Django.contrib.auth.urls`中提供的 URLconf，例如：

```py
urlpatterns = [url('^', include('Django.contrib.auth.urls'))] 

```

这将使每个视图都可以在默认 URL 上使用（在下一节中详细说明）。

所有内置视图都返回一个`TemplateResponse`实例，这使您可以在渲染之前轻松自定义响应数据。大多数内置认证视图都提供了 URL 名称，以便更容易地引用。

## 登录

登录用户。

**默认 URL：** `/login/`

**可选参数：**

+   `template_name`：用于显示用户登录视图的模板的名称。默认为`registration/login.html`。

+   `redirect_field_name`：包含登录后要重定向到的 URL 的`GET`字段的名称。默认为`next`。

+   `authentication_form`：用于身份验证的可调用对象（通常只是一个表单类）。默认为`AuthenticationForm`。

+   `current_app`：指示包含当前视图的应用程序的提示。有关更多信息，请参见命名空间 URL 解析策略。

+   `extra_context`：一个上下文数据的字典，将被添加到传递给模板的默认上下文数据中。

以下是`login`的功能：

+   如果通过`GET`调用，它将显示一个登录表单，该表单提交到相同的 URL。稍后会详细介绍。

+   如果通过用户提交的凭据调用`POST`，它尝试登录用户。如果登录成功，视图将重定向到`next`参数指定的 URL。如果未提供`next`，它将重定向到`LOGIN_REDIRECT_URL`（默认为`/accounts/profile/`）。如果登录不成功，它重新显示登录表单。

这是您的责任为登录模板提供 HTML，默认情况下称为`registration/login.html`。

**模板上下文**

+   `form`：代表`AuthenticationForm`的`Form`对象。

+   `next`：成功登录后要重定向到的 URL。这也可能包含查询字符串。

+   `site`：根据`SITE_ID`设置，当前的`Site`。如果您没有安装站点框架，这将被设置为`RequestSite`的一个实例，它从当前的`HttpRequest`中派生站点名称和域。

+   `site_name`：`site.name`的别名。如果您没有安装站点框架，这将被设置为`request.META['SERVER_NAME']`的值。

如果您不希望将模板称为`registration/login.html`，可以通过 URLconf 中视图的额外参数传递`template_name`参数。

## 注销

注销用户。

**默认 URL：** `/logout/`

**可选参数：**

+   `next_page`：注销后重定向的 URL。

+   `template_name`：在用户注销后显示的模板的完整名称。如果未提供参数，则默认为`registration/logged_out.html`。

+   `redirect_field_name`：包含注销后要重定向到的 URL 的`GET`字段的名称。默认为`next`。如果传递了给定的`GET`参数，则覆盖`next_page` URL。

+   `current_app`：指示包含当前视图的应用程序的提示。有关更多信息，请参见命名空间 URL 解析策略。

+   `extra_context`：一个上下文数据的字典，将被添加到传递给模板的默认上下文数据中。

**模板上下文：**

+   `title`：字符串*已注销*，已本地化。

+   `site`：根据`SITE_ID`设置，当前的`Site`。如果您没有安装站点框架，这将被设置为`RequestSite`的一个实例，它从当前的`HttpRequest`中派生站点名称和域。

+   `site_name`：`site.name`的别名。如果您没有安装站点框架，这将被设置为`request.META['SERVER_NAME']`的值。

+   `current_app`：指示包含当前视图的应用程序的提示。有关更多信息，请参见命名空间 URL 解析策略。

+   `extra_context`：一个上下文数据的字典，将被添加到传递给模板的默认上下文数据中。

## 注销然后登录

注销用户，然后重定向到登录页面。

默认 URL：未提供。

**可选参数：**

+   `login_url`：要重定向到的登录页面的 URL。如果未提供，则默认为`LOGIN_URL`。

+   `current_app`：指示包含当前视图的应用程序的提示。有关更多信息，请参见命名空间 URL 解析策略。

+   `extra_context`：一个上下文数据的字典，将被添加到传递给模板的默认上下文数据中。

## 更改密码

允许用户更改他们的密码。

**默认 URL：** `/password_change/`

**可选参数：**

+   `template_name`：用于显示更改密码表单的模板的完整名称。如果未提供，则默认为`registration/password_change_form.html`。

+   `post_change_redirect`：成功更改密码后要重定向到的 URL。

+   `password_change_form`：必须接受`user`关键字参数的自定义*更改密码*表单。该表单负责实际更改用户的密码。默认为`PasswordChangeForm`。

+   `current_app`：指示包含当前视图的应用程序的提示。有关更多信息，请参阅命名空间 URL 解析策略。

+   `extra_context`：要添加到传递给模板的默认上下文数据的上下文数据字典。

**模板上下文：**

+   `form`：密码更改表单（请参阅上面列表中的`password_change_form`）。

## Password_change_done

用户更改密码后显示的页面。

**默认 URL：** `/password_change_done/`

**可选参数：**

+   `template_name`：要使用的模板的完整名称。如果未提供，默认为`registration/password_change_done.html`。

+   `current_app`：指示包含当前视图的应用程序的提示。有关更多信息，请参阅命名空间 URL 解析策略。

+   `extra_context`：要添加到传递给模板的默认上下文数据的上下文数据字典。

## Password_reset

允许用户通过生成一次性使用链接来重置其密码，并将该链接发送到用户注册的电子邮件地址。

如果提供的电子邮件地址在系统中不存在，此视图不会发送电子邮件，但用户也不会收到任何错误消息。这可以防止信息泄霏给潜在的攻击者。如果您想在这种情况下提供错误消息，可以对`PasswordResetForm`进行子类化并使用`password_reset_form`参数。

标记为不可用密码的用户不允许请求密码重置，以防止在使用外部身份验证源（如 LDAP）时被滥用。请注意，他们不会收到任何错误消息，因为这会暴露其帐户的存在，但也不会发送任何邮件。

默认 URL：`/password_reset/`

**可选参数：**

+   `template_name`：用于显示密码重置表单的模板的完整名称。如果未提供，默认为`registration/password_reset_form.html`。

+   `email_template_name`：用于生成带有重置密码链接的电子邮件的模板的完整名称。如果未提供，默认为`registration/password_reset_email.html`。

+   `subject_template_name`：用于重置密码链接电子邮件主题的模板的完整名称。如果未提供，默认为`registration/password_reset_subject.txt`。

+   `password_reset_form`：将用于获取要重置密码的用户的电子邮件的表单。默认为`PasswordResetForm`。

+   `token_generator`：用于检查一次性链接的类的实例。默认为`default_token_generator`，它是`Django.contrib.auth.tokens.PasswordResetTokenGenerator`的实例。

+   `post_reset_redirect`：成功重置密码请求后要重定向到的 URL。

+   `from_email`：有效的电子邮件地址。默认情况下，Django 使用`DEFAULT_FROM_EMAIL`。

+   `current_app`：指示包含当前视图的应用程序的提示。有关更多信息，请参阅命名空间 URL 解析策略。

+   `extra_context`：要添加到传递给模板的默认上下文数据的上下文数据字典。

+   `html_email_template_name`：用于生成带有重置密码链接的`text/html`多部分电子邮件的模板的完整名称。默认情况下，不发送 HTML 电子邮件。

**模板上下文：**

+   `form`：用于重置用户密码的表单（请参阅`password_reset_form`）。

**电子邮件模板上下文：**

+   `email`：`user.email`的别名

+   `user`：根据`email`表单字段，当前的`User`。只有活动用户才能重置他们的密码（`User.is_active is True`）。

+   `site_name`：`site.name`的别名。如果没有安装站点框架，这将设置为`request.META['SERVER_NAME']`的值。

+   `domain`：`site.domain`的别名。如果未安装站点框架，则将设置为`request.get_host()`的值。

+   `protocol`：http 或 https

+   `uid`：用户的 base 64 编码的主键。

+   `token`：用于检查重置链接是否有效的令牌。

示例`registration/password_reset_email.html`（电子邮件正文模板）：

```py
Someone asked for password reset for email {{ email }}. Follow the link below: 
{{ protocol}}://{{ domain }}{% url 'password_reset_confirm' uidb64=uid token=token %} 

```

主题模板使用相同的模板上下文。主题必须是单行纯文本字符串。

## Password_reset_done

用户收到重置密码链接的电子邮件后显示的页面。如果`password_reset()`视图没有显式设置`post_reset_redirect` URL，则默认调用此视图。**默认 URL：** `/password_reset_done/`

### 注意

如果提供的电子邮件地址在系统中不存在，用户处于非活动状态，或者密码无法使用，则用户仍将被重定向到此视图，但不会发送电子邮件。

**可选参数：**

+   `template_name`：要使用的模板的完整名称。如果未提供，则默认为`registration/password_reset_done.html`。

+   `current_app`：提示当前视图所在的应用程序。有关更多信息，请参阅命名空间 URL 解析策略。

+   `extra_context`：要添加到模板传递的默认上下文数据的上下文数据字典。

## Password_reset_confirm

提供一个输入新密码的表单。

**默认 URL：** `/password_reset_confirm/`

**可选参数：**

+   `uidb64`：用户 ID 以 base 64 编码。默认为`None`。

+   `token`：用于检查密码是否有效的令牌。默认为`None`。

+   `template_name`：要显示确认密码视图的模板的完整名称。默认值为`registration/password_reset_confirm.html`。

+   `token_generator`：用于检查密码的类的实例。这将默认为`default_token_generator`，它是`Django.contrib.auth.tokens.PasswordResetTokenGenerator`的实例。

+   `set_password_form`：将用于设置密码的表单。默认为`SetPasswordForm`

+   `post_reset_redirect`：密码重置完成后要重定向的 URL。默认为`None`。

+   `current_app`：提示当前视图所在的应用程序。有关更多信息，请参阅命名空间 URL 解析策略。

+   `extra_context`：要添加到模板传递的默认上下文数据的上下文数据字典。

**模板上下文：**

+   `form`：用于设置新用户密码的表单（参见`set_password_form`）。

+   `validlink`：布尔值，如果链接（`uidb64`和`token`的组合）有效或尚未使用，则为 True。

## Password_reset_complete

显示一个视图，通知用户密码已成功更改。

**默认 URL：** `/password_reset_complete/`

**可选参数：**

+   `template_name`：要显示视图的模板的完整名称。默认为`registration/password_reset_complete.html`。

+   `current_app`：提示当前视图所在的应用程序。有关更多信息，请参阅命名空间 URL 解析策略。

+   `extra_context`：要添加到模板传递的默认上下文数据的上下文数据字典。

## `redirect_to_login`辅助函数

Django 提供了一个方便的函数`redirect_to_login`，可用于在视图中实现自定义访问控制。它重定向到登录页面，然后在成功登录后返回到另一个 URL。

**必需参数：**

+   `next`：成功登录后要重定向到的 URL。

**可选参数：**

+   `login_url`：要重定向到的登录页面的 URL。如果未提供，则默认为`LOGIN_URL`。

+   `redirect_field_name`：包含注销后要重定向到的 URL 的`GET`字段的名称。如果传递了给定的`GET`参数，则覆盖`next`。

## 内置表单

如果您不想使用内置视图，但希望方便地不必为此功能编写表单，认证系统提供了位于`Django.contrib.auth.forms`中的几个内置表单（*表 11-1*）。

内置的身份验证表单对其正在使用的用户模型做出了某些假设。如果您使用自定义用户模型，则可能需要为身份验证系统定义自己的表单。 

| 表单名称 | 描述 |
| --- | --- |
| `AdminPasswordChangeForm` | 用于在管理员界面更改用户密码的表单。以`user`作为第一个位置参数。 |
| `AuthenticationForm` | 用于登录用户的表单。以`request`作为其第一个位置参数，存储在子类中供使用。 |
| `PasswordChangeForm` | 允许用户更改密码的表单。 |
| `PasswordResetForm` | 用于生成和发送一次性使用链接以重置用户密码的表单。 |
| `SetPasswordForm` | 允许用户在不输入旧密码的情况下更改密码的表单。 |
| `UserChangeForm` | 用于在管理员界面更改用户信息和权限的表单。 |
| `UserCreationForm` | 用于创建新用户的表单。 |

表 11.1：Django 内置的身份验证表单

# 在模板中验证数据

当您使用`RequestContext`时，当前登录的用户及其权限将在模板上下文中提供。

## 用户

在渲染模板`RequestContext`时，当前登录的用户，即`User`实例或`AnonymousUser`实例，存储在模板变量中

`{{ user }}`：

```py
{% if user.is_authenticated %} 
    <p>Welcome, {{ user.username }}. Thanks for logging in.</p> 
{% else %} 
    <p>Welcome, new user. Please log in.</p> 
{% endif %} 

```

如果未使用`RequestContext`，则此模板上下文变量不可用。

## 权限

当前登录用户的权限存储在模板变量中

`{{ perms }}`。这是`Django.contrib.auth.context_processors.PermWrapper`的实例，它是权限的模板友好代理。在`{{ perms }}`对象中，单属性查找是`User.has_module_perms`的代理。如果已登录用户在`foo`应用程序中具有任何权限，则此示例将显示`True`：

```py
{{ perms.foo }} 

```

两级属性查找是`User.has_perm`的代理。如果已登录用户具有权限`foo.can_vote`，则此示例将显示`True`：

```py
{{ perms.foo.can_vote }} 

```

因此，您可以在模板中使用`{% if %}`语句检查权限：

```py
{% if perms.foo %} 
    <p>You have permission to do something in the foo app.</p> 
    {% if perms.foo.can_vote %} 
        <p>You can vote!</p> 
    {% endif %} 
    {% if perms.foo.can_drive %} 
        <p>You can drive!</p> 
    {% endif %} 
{% else %} 
    <p>You don't have permission to do anything in the foo app.</p> 
{% endif %} 

```

也可以通过`{% if in %}`语句查找权限。例如：

```py
{% if 'foo' in perms %} 
    {% if 'foo.can_vote' in perms %} 
        <p>In lookup works, too.</p> 
    {% endif %} 
{% endif %} 

```

# 在管理员中管理用户

当您安装了`Django.contrib.admin`和`Django.contrib.auth`时，管理员提供了一种方便的方式来查看和管理用户、组和权限。用户可以像任何 Django 模型一样创建和删除。可以创建组，并且可以将权限分配给用户或组。还会存储和显示在管理员中对模型的用户编辑的日志。

## 创建用户

您应该在主管理员索引页面的*Auth*部分中看到*Users*的链接。如果单击此链接，您应该看到用户管理屏幕（*图 11.1*）。

![创建用户](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_11_001.jpg)

图 11.1：Django 管理员用户管理屏幕

*添加用户*管理员页面与标准管理员页面不同，它要求您在允许编辑用户其余字段之前选择用户名和密码（*图 11.2*）。

### 注意

如果要求用户帐户能够使用 Django 管理员网站创建用户，则需要给他们添加用户和更改用户的权限（即*添加用户*和*更改用户*权限）。如果帐户有添加用户的权限但没有更改用户的权限，则该帐户将无法添加用户。

为什么？因为如果您有添加用户的权限，您就有创建超级用户的权限，然后可以改变其他用户。因此，Django 要求添加和更改权限作为一种轻微的安全措施。

![创建用户](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_11_002.jpg)

图 11.2：Django 管理员添加用户屏幕

## 更改密码

用户密码不会在管理员界面中显示（也不会存储在数据库中），但密码存储细节会显示出来。在这些信息的显示中包括一个链接到一个密码更改表单，允许管理员更改用户密码（*图 11.3*）。

![更改密码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_11_003.jpg)

图 11.3：更改密码的链接（已圈出）

点击链接后，您将进入更改密码表单（*图 11.4*）。

![更改密码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/ms-dj/img/image_11_004.jpg)

图 11.4：Django 管理员更改密码表单

# Django 中的密码管理

密码管理通常不应该被不必要地重新发明，Django 致力于为管理用户密码提供安全和灵活的工具集。本文档描述了 Django 如何存储密码，如何配置存储哈希，以及一些用于处理哈希密码的实用工具。

## Django 如何存储密码

Django 提供了灵活的密码存储系统，并默认使用**PBKDF2**（更多信息请访问[`en.wikipedia.org/wiki/PBKDF2`](http://en.wikipedia.org/wiki/PBKDF2)）。`User`对象的`password`属性是以这种格式的字符串：

```py
<algorithm>$<iterations>$<salt>$<hash> 

```

这些是用于存储用户密码的组件，由美元符号分隔，并包括：哈希算法、算法迭代次数（工作因子）、随机盐和生成的密码哈希。

该算法是 Django 可以使用的一系列单向哈希或密码存储算法之一（请参阅以下代码）。迭代描述了算法在哈希上运行的次数。盐是使用的随机种子，哈希是单向函数的结果。默认情况下，Django 使用带有 SHA256 哈希的 PBKDF2 算法，这是 NIST 推荐的密码拉伸机制（更多信息请访问[`csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf`](http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf)）。这对大多数用户来说应该足够了：它非常安全，需要大量的计算时间才能破解。但是，根据您的要求，您可以选择不同的算法，甚至使用自定义算法来匹配您特定的安全情况。再次强调，大多数用户不应该需要这样做-如果您不确定，您可能不需要。

如果您这样做，请继续阅读：Django 通过查询`PASSWORD_HASHERS`设置来选择要使用的算法。这是一个哈希算法类的列表，该 Django 安装支持。此列表中的第一个条目（即`settings.PASSWORD_HASHERS[0]`）将用于存储密码，而所有其他条目都是可以用于检查现有密码的有效哈希算法。

这意味着如果您想使用不同的算法，您需要修改`PASSWORD_HASHERS`，将您首选的算法列在列表的第一位。`PASSWORD_HASHERS`的默认值是：

```py
PASSWORD_HASHERS = [
'Django.contrib.auth.hashers.PBKDF2PasswordHasher',
'Django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
'Django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
'Django.contrib.auth.hashers.BCryptPasswordHasher',
'Django.contrib.auth.hashers.SHA1PasswordHasher',
'Django.contrib.auth.hashers.MD5PasswordHasher',
'Django.contrib.auth.hashers.CryptPasswordHasher',
]
```

这意味着 Django 将使用 PBKDF2 来存储所有密码，但将支持检查使用 PBKDF2SHA1、Bcrypt、SHA1 等存储的密码。接下来的几节描述了高级用户可能希望修改此设置的一些常见方法。

## 使用 Django 的 Bcrypt

Bcrypt（更多信息请访问[`en.wikipedia.org/wiki/Bcrypt`](http://en.wikipedia.org/wiki/Bcrypt)）是一种流行的密码存储算法，专门设计用于长期密码存储。它不是 Django 的默认算法，因为它需要使用第三方库，但由于许多人可能想要使用它，Django 支持 Bcrypt，而且只需很少的努力。

要将 Bcrypt 作为默认存储算法，请执行以下操作：

1.  安装`bcrypt`库。可以通过运行`pip install Django[bcrypt]`来完成，或者通过下载该库并使用`python setup.py install`进行安装。

1.  修改`PASSWORD_HASHERS`，将`BCryptSHA256PasswordHasher`列在第一位。也就是说，在您的设置文件中，您需要添加：

```py
    PASSWORD_HASHERS = [ 
        'Django.contrib.auth.hashers.BCryptSHA256PasswordHasher', 
        'Django.contrib.auth.hashers.BCryptPasswordHasher', 
        'Django.contrib.auth.hashers.PBKDF2PasswordHasher', 
        'Django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher', 
        'Django.contrib.auth.hashers.SHA1PasswordHasher', 
        'Django.contrib.auth.hashers.MD5PasswordHasher', 
        'Django.contrib.auth.hashers.CryptPasswordHasher', 
] 

```

（您需要保留此列表中的其他条目，否则 Django 将无法升级密码；请参阅以下部分）。

就是这样-现在您的 Django 安装将使用 Bcrypt 作为默认存储算法。

### BCryptPasswordHasher 的密码截断

Bcrypt 的设计者将所有密码截断为 72 个字符，这意味着`bcrypt（具有 100 个字符的密码）== bcrypt（具有 100 个字符的密码[:72]）`。 原始的`BCryptPasswordHasher`没有任何特殊处理，因此也受到此隐藏密码长度限制的影响。 `BCryptSHA256PasswordHasher`通过首先使用 sha256 对密码进行哈希来修复此问题。 这可以防止密码截断，因此应优先于`BCryptPasswordHasher`。

这种截断的实际影响非常小，因为普通用户的密码长度不超过 72 个字符，即使在 72 个字符处被截断，以任何有用的时间内暴力破解 Bcrypt 所需的计算能力仍然是天文数字。 尽管如此，我们仍建议您出于*宁愿安全也不要抱歉*的原则使用`BCryptSHA256PasswordHasher`。

### 其他 Bcrypt 实现

有几种其他实现允许 Bcrypt 与 Django 一起使用。 Django 的 Bcrypt 支持与这些实现不兼容。 要升级，您需要修改数据库中的哈希值，使其形式为`bcrypt$（原始 bcrypt 输出）`。

### 增加工作因素

PBKDF2 和 Bcrypt 算法使用多个迭代或哈希轮。 这故意减慢攻击者的速度，使攻击哈希密码变得更加困难。 但是，随着计算能力的增加，迭代次数需要增加。

Django 开发团队选择了一个合理的默认值（并将在每个 Django 版本发布时增加），但您可能希望根据安全需求和可用处理能力进行调整。 要这样做，您将对适当的算法进行子类化，并覆盖`iterations`参数。

例如，要增加默认 PBKDF2 算法使用的迭代次数：

1.  创建`Django.contrib.auth.hashers.PBKDF2PasswordHasher`的子类：

```py
    from Django.contrib.auth.hashers
        import PBKDF2PasswordHasher 

    class MyPBKDF2PasswordHasher(PBKDF2PasswordHasher):  
        iterations = PBKDF2PasswordHasher.iterations * 100 

```

1.  将此保存在项目的某个位置。 例如，您可以将其放在类似`myproject/hashers.py`的文件中。

1.  将新的哈希器添加为`PASSWORD_HASHERS`中的第一个条目：

```py
    PASSWORD_HASHERS = [ 
      'myproject.hashers.MyPBKDF2PasswordHasher', 
      'Django.contrib.auth.hashers.PBKDF2PasswordHasher', 

      # ... # 
      ] 

```

就是这样-现在您的 Django 安装将在使用 PBKDF2 存储密码时使用更多迭代。

## 密码升级

当用户登录时，如果他们的密码存储使用的算法与首选算法不同，Django 将自动升级算法为首选算法。 这意味着旧版 Django 将随着用户登录自动变得更安全，也意味着您可以在发明新的（更好的）存储算法时切换到新的存储算法。

但是，Django 只能升级使用`PASSWORD_HASHERS`中提到的算法的密码，因此在升级到新系统时，您应确保永远不要*删除*此列表中的条目。 如果这样做，使用未提及算法的用户将无法升级。 更改 PBKDF2 迭代计数时将升级密码。

## 手动管理用户的密码

`Django.contrib.auth.hashers`模块提供了一组函数来创建和验证哈希密码。 您可以独立于`User`模型使用它们。

如果您想要通过比较数据库中的哈希密码和明文密码手动验证用户，请使用`check_password()`函数。 它接受两个参数：要检查的明文密码和要检查的数据库中用户`password`字段的完整值，并在它们匹配时返回`True`，否则返回`False`。

`make_password()`创建了一个使用此应用程序的格式的哈希密码。 它接受一个必需参数：明文密码。

如果您不想使用默认值（`PASSWORD_HASHERS`设置的第一个条目），可以选择提供盐和哈希算法来使用。当前支持的算法有：`'pbkdf2_sha256'`、`'pbkdf2_sha1'`、`'bcrypt_sha256'`、`'bcrypt'`、`'sha1'`、`'md5'`、`'unsalted_md5'`（仅用于向后兼容）和`'crypt'`（如果已安装`crypt`库）。

如果密码参数为`None`，则返回一个不可用的密码（永远不会被`check_password()`接受的密码）。

`is_password_usable()`检查给定的字符串是否是一个经过哈希处理的密码，有可能通过`check_password()`进行验证。

# 在 Django 中自定义身份验证

Django 自带的身份验证对于大多数常见情况已经足够好，但您可能有一些默认设置无法满足的需求。要根据项目的需求自定义身份验证，需要了解所提供系统的哪些部分是可扩展或可替换的。

身份验证后端提供了一个可扩展的系统，用于当需要对与用户模型中存储的用户名和密码进行身份验证的服务进行不同于 Django 默认的身份验证时。您可以为您的模型提供自定义权限，可以通过 Django 的授权系统进行检查。您可以扩展默认的用户模型，或者替换完全自定义的模型。

## 其他身份验证源

有时您可能需要连接到另一个身份验证源，即另一个用户名和密码或身份验证方法的源。

例如，您的公司可能已经设置了一个 LDAP，用于存储每个员工的用户名和密码。如果用户在 LDAP 和基于 Django 的应用程序中有单独的帐户，这对网络管理员和用户本身都是一种麻烦。

因此，为了处理这样的情况，Django 身份验证系统允许您插入其他身份验证源。您可以覆盖 Django 的默认基于数据库的方案，或者您可以与其他系统一起使用默认系统。

## 指定身份验证后端

在幕后，Django 维护一个身份验证后端列表，用于进行身份验证检查。当有人调用`authenticate()`时（如前一节中描述的登录用户），Django 尝试在所有身份验证后端上进行身份验证。如果第一种身份验证方法失败，Django 尝试第二种方法，依此类推，直到尝试了所有后端。

要使用的身份验证后端列表在`AUTHENTICATION_BACKENDS`设置中指定。这应该是一个指向知道如何进行身份验证的 Python 类的 Python 路径名称列表。这些类可以位于 Python 路径的任何位置。默认情况下，`AUTHENTICATION_BACKENDS`设置为：

```py
['Django.contrib.auth.backends.ModelBackend'] 

```

这是基本的身份验证后端，它检查 Django 用户数据库并查询内置权限。它不提供通过任何速率限制机制防止暴力攻击。您可以在自定义授权后端中实现自己的速率限制机制，或者使用大多数 Web 服务器提供的机制。`AUTHENTICATION_BACKENDS`的顺序很重要，因此如果相同的用户名和密码在多个后端中有效，Django 将在第一个正面匹配时停止处理。如果后端引发`PermissionDenied`异常，身份验证将立即失败。Django 不会检查后续的后端。

用户经过身份验证后，Django 会在用户的会话中存储用于对用户进行身份验证的后端，并在需要访问当前经过身份验证的用户时重复使用相同的后端。这实际上意味着身份验证源是基于每个会话进行缓存的，因此如果您更改了`AUTHENTICATION_BACKENDS`，则需要清除会话数据，以便强制用户使用不同的方法重新进行身份验证。一个简单的方法就是执行`Session.objects.all().delete()`。

## 编写认证后端

认证后端是实现两个必需方法的类：`get_user(user_id)`和`authenticate(**credentials)`，以及一组可选的与权限相关的授权方法。`get_user`方法接受一个`user_id`（可以是用户名、数据库 ID 或其他任何内容，但必须是`User`对象的主键）并返回一个`User`对象。`authenticate`方法以关键字参数的形式接受凭据。大多数情况下，它看起来会像这样：

```py
class MyBackend(object): 
    def authenticate(self, username=None, password=None): 
        # Check the username/password and return a User. 
        ... 

```

但它也可以验证令牌，如下所示：

```py
class MyBackend(object): 
    def authenticate(self, token=None): 
        # Check the token and return a User. 
        ... 

```

无论哪种方式，`authenticate`都应该检查它收到的凭据，并且如果凭据有效，它应该返回与这些凭据匹配的`User`对象。如果它们无效，它应该返回`None`。Django 管理系统与本章开头描述的 Django `User`对象紧密耦合。

目前，处理这个问题的最佳方法是为后端中存在的每个用户创建一个 Django `User`对象（例如，在 LDAP 目录中，外部 SQL 数据库中等）。您可以提前编写一个脚本来执行此操作，或者您的`authenticate`方法可以在用户首次登录时执行此操作。

以下是一个示例后端，它根据`settings.py`文件中定义的用户名和密码变量进行身份验证，并在用户首次进行身份验证时创建一个 Django `User`对象：

```py
from Django.conf import settings 
from Django.contrib.auth.models import User, check_password 

class SettingsBackend(object): 
    """ 
    Authenticate against the settings ADMIN_LOGIN and ADMIN_PASSWORD. 

    Use the login name, and a hash of the password. For example: 

    ADMIN_LOGIN = 'admin' 
    ADMIN_PASSWORD = 'sha1$4e987$afbcf42e21bd417fb71db8c66b321e9fc33051de' 
    """ 

    def authenticate(self, username=None, password=None): 
        login_valid = (settings.ADMIN_LOGIN == username) 
        pwd_valid = check_password(password, settings.ADMIN_PASSWORD) 
        if login_valid and pwd_valid: 
            try: 
                user = User.objects.get(username=username) 
            except User.DoesNotExist: 
                # Create a new user. Note that we can set password 
                # to anything, because it won't be checked; the password 
                # from settings.py will. 
                user = User(username=username, password='password') 
                user.is_staff = True 
                user.is_superuser = True 
                user.save() 
            return user 
        return None 

    def get_user(self, user_id): 
        try: 
            return User.objects.get(pk=user_id) 
        except User.DoesNotExist: 
            return None 

```

## 处理自定义后端中的授权

自定义授权后端可以提供自己的权限。用户模型将权限查找功能（`get_group_permissions()`，`get_all_permissions()`，`has_perm()`和`has_module_perms()`）委托给实现这些功能的任何认证后端。用户获得的权限将是所有后端返回的权限的超集。换句话说，Django 授予用户任何一个后端授予的权限。

如果后端在`has_perm()`或`has_module_perms()`中引发`PermissionDenied`异常，授权将立即失败，Django 将不会检查后续的后端。前面提到的简单后端可以相当简单地为管理员实现权限：

```py
class SettingsBackend(object): 
    ... 
    def has_perm(self, user_obj, perm, obj=None): 
        if user_obj.username == settings.ADMIN_LOGIN: 
            return True 
        else: 
            return False 

```

这为在前面的示例中获得访问权限的用户提供了完全的权限。请注意，除了与相关的`User`函数给出的相同参数之外，后端授权函数都将匿名用户作为参数。

完整的授权实现可以在`Django/contrib/auth/backends.py`中的`ModelBackend`类中找到，这是默认的后端，大部分时间查询`auth_permission`表。如果您希望仅为后端 API 的部分提供自定义行为，可以利用 Python 继承并子类化`ModelBackend`，而不是在自定义后端中实现完整的 API。

## 匿名用户的授权

匿名用户是未经认证的用户，也就是说他们没有提供有效的认证详细信息。但是，这并不一定意味着他们没有获得任何授权。在最基本的级别上，大多数网站允许匿名用户浏览大部分网站，并且许多网站允许匿名发布评论等。

Django 的权限框架没有存储匿名用户的权限的地方。但是，传递给认证后端的用户对象可能是`Django.contrib.auth.models.AnonymousUser`对象，允许后端为匿名用户指定自定义授权行为。

这对于可重用应用程序的作者特别有用，他们可以将所有授权问题委托给认证后端，而不需要设置来控制匿名访问。

## 未激活用户的授权

未激活用户是已经认证但其属性`is_active`设置为`False`的用户。但是，这并不意味着他们没有获得任何授权。例如，他们被允许激活他们的帐户。

权限系统中对匿名用户的支持允许匿名用户执行某些操作，而未激活的经过身份验证的用户则不行。不要忘记在自己的后端权限方法中测试用户的`is_active`属性。

## 处理对象权限

Django 的权限框架为对象权限奠定了基础，尽管核心中没有对其进行实现。这意味着检查对象权限将始终返回`False`或空列表（取决于所执行的检查）。身份验证后端将为每个对象相关的授权方法接收关键字参数`obj`和`user_obj`，并根据需要返回对象级别的权限。

# 自定义权限

要为给定模型对象创建自定义权限，请使用`permissions`模型 Meta 属性。这个示例任务模型创建了三个自定义权限，即用户可以或不可以对任务实例执行的操作，特定于您的应用程序：

```py
class Task(models.Model): 
    ... 
    class Meta: 
        permissions = ( 
            ("view_task", "Can see available tasks"), 
            ("change_task_status", "Can change the status of tasks"), 
            ("close_task", "Can remove a task by setting its status as   
              closed"), 
        ) 

```

这样做的唯一作用是在运行`manage.py migrate`时创建这些额外的权限。当用户尝试访问应用程序提供的功能（查看任务，更改任务状态，关闭任务）时，您的代码负责检查这些权限的值。继续上面的示例，以下检查用户是否可以查看任务：

```py
user.has_perm('app.view_task') 

```

# 扩展现有的用户模型

有两种方法可以扩展默认的`User`模型，而不替换自己的模型。如果您需要的更改纯粹是行为上的，并且不需要对数据库中存储的内容进行任何更改，可以创建一个基于`User`的代理模型。这允许使用代理模型提供的任何功能，包括默认排序、自定义管理器或自定义模型方法。

如果您希望存储与“用户”相关的信息，可以使用一个一对一的关系到一个包含额外信息字段的模型。这个一对一模型通常被称为配置文件模型，因为它可能存储有关站点用户的非认证相关信息。例如，您可以创建一个员工模型：

```py
from Django.contrib.auth.models import User 

class Employee(models.Model): 
    user = models.OneToOneField(User) 
    department = models.CharField(max_length=100) 

```

假设已经存在一个名为 Fred Smith 的员工，他既有一个用户模型又有一个员工模型，您可以使用 Django 的标准相关模型约定访问相关信息：

```py
>>> u = User.objects.get(username='fsmith') 
>>> freds_department = u.employee.department 

```

要将配置文件模型的字段添加到管理员中的用户页面中，可以在应用程序的`admin.py`中定义一个`InlineModelAdmin`（在本例中，我们将使用`StackedInline`），并将其添加到注册了`User`类的`UserAdmin`类中：

```py
from Django.contrib import admin 
from Django.contrib.auth.admin import UserAdmin 
from Django.contrib.auth.models import User 

from my_user_profile_app.models import Employee 

# Define an inline admin descriptor for Employee model 
# which acts a bit like a singleton 
class EmployeeInline(admin.StackedInline): 
    model = Employee 
    can_delete = False 
    verbose_name_plural = 'employee' 

# Define a new User admin 
class UserAdmin(UserAdmin): 
    inlines = (EmployeeInline, ) 

# Re-register UserAdmin 
admin.site.unregister(User) 
admin.site.register(User, UserAdmin)
```

这些配置文件模型在任何方面都不特殊-它们只是恰好与用户模型有一对一的链接的 Django 模型。因此，它们在创建用户时不会自动创建，但可以使用`Django.db.models.signals.post_save`来创建或更新相关模型。

请注意，使用相关模型会导致额外的查询或连接以检索相关数据，并且根据您的需求，替换用户模型并添加相关字段可能是更好的选择。但是，项目应用程序中对默认用户模型的现有链接可能会证明额外的数据库负载是合理的。

# 替换自定义用户模型

某些类型的项目可能对 Django 内置的`User`模型的身份验证要求不太合适。例如，在某些站点上，使用电子邮件地址作为您的标识令牌可能更有意义，而不是使用用户名。Django 允许您通过为`AUTH_USER_MODEL`设置提供引用自定义模型的值来覆盖默认的用户模型：

```py
AUTH_USER_MODEL = 'books.MyUser' 

```

这个点对描述了 Django 应用的名称（必须在`INSTALLED_APPS`中），以及您希望用作用户模型的 Django 模型的名称。

### 注意

更改`AUTH_USER_MODEL`对您的 Django 项目有很大影响，特别是对数据库结构。例如，如果在运行迁移后更改了`AUTH_USER_MODEL`，您将不得不手动更新数据库，因为它会影响许多数据库表关系的构建。除非有非常充分的理由这样做，否则不应更改您的`AUTH_USER_MODEL`。

尽管前面的警告，Django 确实完全支持自定义用户模型，但是完整的解释超出了本书的范围。关于符合管理员标准的自定义用户应用的完整示例，以及关于自定义用户模型的全面文档可以在 Django 项目网站上找到（[`docs.Djangoproject.com/en/1.8/topics/auth/customizing/`](https://docs.Djangoproject.com/en/1.8/topics/auth/customizing/)）。

# 接下来呢？

在本章中，我们已经了解了 Django 中的用户认证，内置的认证工具，以及可用的广泛定制。在下一章中，我们将涵盖创建和维护健壮应用程序的可能是最重要的工具-自动化测试。


# 第十二章：Django 中的测试

# 测试简介

像所有成熟的编程语言一样，Django 提供了内置的*单元测试*功能。单元测试是一种软件测试过程，其中测试软件应用程序的各个单元，以确保它们执行预期的操作。

单元测试可以在多个级别进行-从测试单个方法以查看它是否返回正确的值以及如何处理无效数据，到测试整套方法以确保一系列用户输入导致期望的结果。

单元测试基于四个基本概念：

1.  **测试装置**是执行测试所需的设置。这可能包括数据库、样本数据集和服务器设置。测试装置还可能包括在测试执行后需要进行的任何清理操作。

1.  **测试用例**是测试的基本单元。测试用例检查给定的输入是否导致预期的结果。

1.  **测试套件**是一些测试用例或其他测试套件，作为一个组执行。

1.  **测试运行器**是控制测试执行并将测试结果反馈给用户的软件程序。

软件测试是一个深入而详细的主题，本章应被视为对单元测试的简要介绍。互联网上有大量关于软件测试理论和方法的资源，我鼓励你就这个重要主题进行自己的研究。有关 Django 对单元测试方法的更详细讨论，请参阅 Django 项目网站。

# 引入自动化测试

## 什么是自动化测试？

在本书中，你一直在测试代码；也许甚至没有意识到。每当你使用 Django shell 来查看一个函数是否有效，或者查看给定输入的输出时，你都在测试你的代码。例如，在第二章中，*视图和 URLconfs*，我们向一个期望整数的视图传递了一个字符串，以生成`TypeError`异常。

测试是应用程序开发的正常部分，但自动化测试的不同之处在于系统为你完成了测试工作。你只需创建一组测试，然后在对应用程序进行更改时，可以检查你的代码是否仍然按照最初的意图工作，而无需进行耗时的手动测试。

## 那么为什么要创建测试？

如果创建像本书中那样简单的应用程序是你在 Django 编程中的最后一步，那么确实，你不需要知道如何创建自动化测试。但是，如果你希望成为一名专业程序员和/或在更复杂的项目上工作，你需要知道如何创建自动化测试。

创建自动化测试将会：

+   **节省时间**：手动测试大型应用程序组件之间的复杂交互是耗时且容易出错的。自动化测试可以节省时间，让你专注于编程。

+   **预防问题**：测试突出显示了代码的内部工作原理，因此你可以看到哪里出了问题。

+   **看起来专业**：专业人士编写测试。Django 的原始开发人员之一 Jacob Kaplan-Moss 说：“没有测试的代码从设计上就是有问题的。”

+   **改善团队合作**：测试可以确保同事们不会无意中破坏你的代码（而你也不会在不知情的情况下破坏他们的代码）。

# 基本测试策略

有许多方法可以用来编写测试。一些程序员遵循一种称为**测试驱动开发**的纪律；他们实际上是在编写代码之前编写他们的测试。这可能看起来有些反直觉，但事实上，这与大多数人通常会做的事情相似：他们描述一个问题，然后创建一些代码来解决它。

测试驱动开发只是在 Python 测试用例中正式化了问题。更常见的是，测试的新手会创建一些代码，然后决定它应该有一些测试。也许更好的做法是早些时候编写一些测试，但现在开始也不算太晚。

# 编写一个测试

要创建您的第一个测试，让我们在您的 Book 模型中引入一个错误。

假设您已经决定在您的 Book 模型上创建一个自定义方法，以指示书籍是否最近出版。您的 Book 模型可能如下所示：

```py
import datetime 
from django.utils import timezone 

from django.db import models 

# ... # 

class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField(Author) 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField() 

    def recent_publication(self): 
        return self.publication_date >= timezone.now().date() 
datetime.timedelta(weeks=8) 

    # ... # 

```

首先，我们导入了两个新模块：Python 的`datetime`和`django.utils`中的`timezone`。我们需要这些模块来进行日期计算。然后，我们在`Book`模型中添加了一个名为`recent_publication`的自定义方法，该方法计算出八周前的日期，并在书籍的出版日期更近时返回 true。

所以让我们跳到交互式 shell 并测试我们的新方法：

```py
python manage.py shell 

>>> from books.models import Book 
>>> import datetime 
>>> from django.utils import timezone 
>>> book = Book.objects.get(id=1) 
>>> book.title 
'Mastering Django: Core' 
>>> book.publication_date 
datetime.date(2016, 5, 1) 
>>>book.publication_date >= timezone.now().date()-datetime.timedelta(weeks=8) 
True 

```

到目前为止，一切都很顺利，我们已经导入了我们的书籍模型并检索到了一本书。今天是 2016 年 6 月 11 日，我已经在数据库中输入了我的书的出版日期为 5 月 1 日，这比八周前还要早，所以函数正确地返回了`True`。

显然，您将不得不修改数据中的出版日期，以便在您完成这个练习时，这个练习仍然对您有效。

现在让我们看看如果我们将出版日期设置为未来的某个时间，比如说 9 月 1 日会发生什么：

```py
>>> book.publication_date 
datetime.date(2016, 9, 1) 
>>>book.publication_date >= timezone.now().date()-datetime.timedelta(weeks=8) 
True 

```

哎呀！这里显然有些问题。您应该能够很快地看到逻辑上的错误-八周前之后的任何日期都将返回 true，包括未来的日期。

所以，暂且不管这是一个相当牵强的例子，现在让我们创建一个暴露我们错误逻辑的测试。

# 创建一个测试

当您使用 Django 的`startapp`命令创建了您的 books 应用程序时，它在您的应用程序目录中创建了一个名为`tests.py`的文件。这就是 books 应用程序的任何测试应该放置的地方。所以让我们马上开始编写一个测试：

```py
import datetime 
from django.utils import timezone 
from django.test import TestCase 
from .models import Book 

class BookMethodTests(TestCase): 

    def test_recent_pub(self): 
""" 
        recent_publication() should return False for future publication  
        dates. 
        """ 

        futuredate = timezone.now().date() + datetime.timedelta(days=5) 
        future_pub = Book(publication_date=futuredate) 
        self.assertEqual(future_pub.recent_publication(), False) 

```

这应该非常简单明了，因为它几乎与我们在 Django shell 中所做的一样，唯一的真正区别是我们现在将我们的测试代码封装在一个类中，并创建了一个断言，用于测试我们的`recent_publication()`方法是否与未来日期相匹配。

我们将在本章后面更详细地介绍测试类和`assertEqual`方法-现在，我们只想在进入更复杂的主题之前，看一下测试是如何在非常基本的水平上工作的。

# 运行测试

现在我们已经创建了我们的测试，我们需要运行它。幸运的是，这非常容易做到，只需跳转到您的终端并键入：

```py
python manage.py test books 

```

片刻之后，Django 应该打印出类似于这样的内容：

```py
Creating test database for alias 'default'... 
F 
====================================================================== 
FAIL: test_recent_pub (books.tests.BookMethodTests) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
  File "C:\Users\Nigel\ ... mysite\books\tests.py", line 25, in test_recent_pub 
    self.assertEqual(future_pub.recent_publication(), False) 
AssertionError: True != False 

---------------------------------------------------------------------- 
Ran 1 test in 0.000s 

FAILED (failures=1) 
Destroying test database for alias 'default'... 

```

发生的事情是这样的：

+   Python `manage.py test books`在 books 应用程序中查找测试。

+   它找到了`django.test.TestCase`类的一个子类

+   它为测试目的创建了一个特殊的数据库

+   它寻找以“test”开头的方法

+   在`test_recent_pub`中，它创建了一个`Book`实例，其`publication_date`字段是未来的 5 天；而

+   使用`assertEqual()`方法，它发现它的`recent_publication()`返回`True`，而应该返回`False`。

测试告诉我们哪个测试失败了，甚至还告诉了失败发生的行。还要注意，如果您使用的是*nix 系统或 Mac，文件路径将会有所不同。

这就是 Django 中测试的非常基本的介绍。正如我在本章开头所说的，测试是一个深入而详细的主题，对于您作为程序员的职业非常重要。我不可能在一个章节中涵盖所有测试的方面，所以我鼓励您深入研究本章中提到的一些资源以及 Django 文档。

在本章的其余部分，我将介绍 Django 为您提供的各种测试工具。

# 测试工具

Django 提供了一套在编写测试时非常方便的工具。

## 测试客户端

测试客户端是一个 Python 类，充当虚拟网络浏览器，允许您以编程方式测试视图并与 Django 应用程序进行交互。测试客户端可以做的一些事情包括：

+   模拟 URL 上的`GET`和`POST`请求，并观察响应-从低级 HTTP（结果标头和状态代码）到页面内容的一切。

+   查看重定向链（如果有）并检查每一步的 URL 和状态代码。

+   测试给定请求是否由给定的 Django 模板呈现，并且模板上下文包含某些值。

请注意，测试客户端并不打算替代 Selenium（有关更多信息，请访问[`seleniumhq.org/`](http://seleniumhq.org/)）或其他浏览器框架。Django 的测试客户端有不同的重点。简而言之：

+   使用 Django 的测试客户端来确保正确的模板被渲染，并且模板传递了正确的上下文数据。

+   使用浏览器框架（如 Selenium）测试呈现的 HTML 和网页的行为，即 JavaScript 功能。Django 还为这些框架提供了特殊的支持；有关更多详细信息，请参阅`LiveServerTestCase`部分。

全面的测试套件应该结合使用这两种测试类型。

有关 Django 测试客户端的更详细信息和示例，请参阅 Django 项目网站。

## 提供的 TestCase 类

普通的 Python 单元测试类扩展了`unittest.TestCase`的基类。Django 提供了一些这个基类的扩展：

### 简单的 TestCase

扩展`unittest.TestCase`，具有一些基本功能，如：

+   保存和恢复 Python 警告机制的状态。

+   添加了一些有用的断言，包括：

+   检查可调用对象是否引发了特定异常。

+   测试表单字段的呈现和错误处理。

+   测试 HTML 响应中是否存在/缺少给定的片段。

+   验证模板是否已/未用于生成给定的响应内容。

+   验证应用程序执行了 HTTP 重定向。

+   强大地测试两个 HTML 片段的相等性/不相等性或包含关系。

+   强大地测试两个 XML 片段的相等性/不相等性。

+   强大地测试两个 JSON 片段的相等性。

+   使用修改后的设置运行测试的能力。

+   使用测试`Client`。

+   自定义测试时间 URL 映射。

### Transaction TestCase

Django 的`TestCase`类（在下一段中描述）利用数据库事务设施来加快在每个测试开始时将数据库重置为已知状态的过程。然而，这样做的一个后果是，一些数据库行为无法在 Django 的`TestCase`类中进行测试。

在这些情况下，您应该使用`TransactionTestCase`。`TransactionTestCase`和`TestCase`除了数据库重置到已知状态的方式和测试代码测试提交和回滚的效果外，两者是相同的：

+   `TransactionTestCase`通过截断所有表在测试运行后重置数据库。`TransactionTestCase`可以调用提交和回滚，并观察这些调用对数据库的影响。

+   另一方面，`TestCase`在测试后不会截断表。相反，它将测试代码封装在数据库事务中，在测试结束时回滚。这保证了测试结束时的回滚将数据库恢复到其初始状态。

`TransactionTestCase`继承自`SimpleTestCase`。

### TestCase

这个类提供了一些对于测试网站有用的额外功能。将普通的`unittest.TestCase`转换为 Django 的`TestCase`很容易：只需将测试的基类从`unittest.TestCase`更改为`django.test.TestCase`。所有标准的 Python 单元测试功能仍然可用，但它将增加一些有用的附加功能，包括：

+   自动加载 fixture。

+   将测试包装在两个嵌套的`atomic`块中：一个用于整个类，一个用于每个测试。

+   创建一个`TestClient`实例。

+   用于测试重定向和表单错误等内容的 Django 特定断言。

`TestCase`继承自`TransactionTestCase`。

### LiveServerTestCase

`LiveServerTestCase`基本上与`TransactionTestCase`相同，只是多了一个功能：它在设置时在后台启动一个实时的 Django 服务器，并在拆卸时关闭它。这允许使用除 Django 虚拟客户端之外的自动化测试客户端，例如 Selenium 客户端，来在浏览器中执行一系列功能测试并模拟真实用户的操作。

## 测试用例特性

### 默认测试客户端

`*TestCase`实例中的每个测试用例都可以访问 Django 测试客户端的一个实例。可以将此客户端访问为`self.client`。每个测试都会重新创建此客户端，因此您不必担心状态（例如 cookies）从一个测试传递到另一个测试。这意味着，而不是在每个测试中实例化`Client`：

```py
import unittest 
from django.test import Client 

class SimpleTest(unittest.TestCase): 
    def test_details(self): 
        client = Client() 
        response = client.get('/customer/details/') 
        self.assertEqual(response.status_code, 200) 

    def test_index(self): 
        client = Client() 
        response = client.get('/customer/index/') 
        self.assertEqual(response.status_code, 200) 

```

...您可以像这样引用`self.client`：

```py
from django.test import TestCase 

class SimpleTest(TestCase): 
    def test_details(self): 
        response = self.client.get('/customer/details/') 
        self.assertEqual(response.status_code, 200) 

    def test_index(self): 
        response = self.client.get('/customer/index/') 
        self.assertEqual(response.status_code, 200) 

```

### fixture 加载

如果数据库支持的网站的测试用例没有任何数据，则没有多大用处。为了方便地将测试数据放入数据库，Django 的自定义`TransactionTestCase`类提供了一种加载 fixtures 的方法。fixture 是 Django 知道如何导入到数据库中的数据集合。例如，如果您的网站有用户帐户，您可能会设置一个虚假用户帐户的 fixture，以便在测试期间填充数据库。

创建 fixture 的最直接方法是使用`manage.pydumpdata`命令。这假设您的数据库中已经有一些数据。有关更多详细信息，请参阅`dumpdata`文档。创建 fixture 并将其放置在`INSTALLED_APPS`中的`fixtures`目录中后，您可以通过在`django.test.TestCase`子类的`fixtures`类属性上指定它来在单元测试中使用它：

```py
from django.test import TestCase 
from myapp.models import Animal 

class AnimalTestCase(TestCase): 
    fixtures = ['mammals.json', 'birds'] 

    def setUp(self): 
        # Test definitions as before. 
        call_setup_methods() 

    def testFluffyAnimals(self): 
        # A test that uses the fixtures. 
        call_some_test_code() 

```

具体来说，将发生以下情况：

+   在每个测试用例开始之前，在运行`setUp()`之前，Django 将刷新数据库，将数据库返回到直接在调用`migrate`之后的状态。

+   然后，所有命名的 fixtures 都将被安装。在此示例中，Django 将安装名为`mammals`的任何 JSON fixture，然后是名为`birds`的任何 fixture。有关定义和安装 fixtures 的更多详细信息，请参阅`loaddata`文档。

这个刷新/加载过程对测试用例中的每个测试都会重复进行，因此您可以确保一个测试的结果不会受到另一个测试或测试执行顺序的影响。默认情况下，fixture 只加载到`default`数据库中。如果您使用多个数据库并设置`multi_db=True`，fixture 将加载到所有数据库中。

### 覆盖设置

### 注意

使用函数在测试中临时更改设置的值。不要直接操作`django.conf.settings`，因为 Django 不会在此类操作后恢复原始值。

#### settings()

为了测试目的，通常在运行测试代码后临时更改设置并恢复到原始值是很有用的。对于这种用例，Django 提供了一个标准的 Python 上下文管理器（参见 PEP 343at [`www.python.org/dev/peps/pep-0343`](https://www.python.org/dev/peps/pep-0343)）称为`settings()`，可以像这样使用：

```py
from django.test import TestCase 

class LoginTestCase(TestCase): 

    def test_login(self): 

        # First check for the default behavior 
        response = self.client.get('/sekrit/') 
        self.assertRedirects(response, '/accounts/login/?next=/sekrit/') 

        # Then override the LOGIN_URL setting 
        with self.settings(LOGIN_URL='/other/login/'): 
            response = self.client.get('/sekrit/') 
            self.assertRedirects(response, '/other/login/?next=/sekrit/') 

```

此示例将在`with`块中覆盖`LOGIN_URL`设置，并在之后将其值重置为先前的状态。

#### modify_settings()

重新定义包含值列表的设置可能会变得难以处理。实际上，添加或删除值通常就足够了。`modify_settings()`上下文管理器使这变得很容易：

```py
from django.test import TestCase 

class MiddlewareTestCase(TestCase): 

    def test_cache_middleware(self): 
        with self.modify_settings(MIDDLEWARE_CLASSES={ 
'append': 'django.middleware.cache.FetchFromCacheMiddleware', 
'prepend': 'django.middleware.cache.UpdateCacheMiddleware', 
'remove': [ 
 'django.contrib.sessions.middleware.SessionMiddleware', 
 'django.contrib.auth.middleware.AuthenticationMiddleware',  
 'django.contrib.messages.middleware.MessageMiddleware', 
            ], 
        }): 
            response = self.client.get('/') 
            # ... 

```

对于每个操作，您可以提供一个值列表或一个字符串。当值已经存在于列表中时，`append`和`prepend`没有效果；当值不存在时，`remove`也没有效果。

#### override_settings()

如果要为测试方法覆盖设置，Django 提供了`override_settings()`装饰器（请参阅[`www.python.org/dev/peps/pep-0318`](https://www.python.org/dev/peps/pep-0318)的 PEP 318）。用法如下：

```py
from django.test import TestCase, override_settings 

class LoginTestCase(TestCase): 

    @override_settings(LOGIN_URL='/other/login/') 
    def test_login(self): 
        response = self.client.get('/sekrit/') 
        self.assertRedirects(response, '/other/login/?next=/sekrit/') 

```

装饰器也可以应用于`TestCase`类：

```py
from django.test import TestCase, override_settings 

@override_settings(LOGIN_URL='/other/login/') 
class LoginTestCase(TestCase): 

    def test_login(self): 
        response = self.client.get('/sekrit/') 
        self.assertRedirects(response, '/other/login/?next=/sekrit/') 

```

#### modify_settings()

同样，Django 还提供了`modify_settings()`装饰器：

```py
from django.test import TestCase, modify_settings 

class MiddlewareTestCase(TestCase): 

    @modify_settings(MIDDLEWARE_CLASSES={ 
'append': 'django.middleware.cache.FetchFromCacheMiddleware', 
'prepend': 'django.middleware.cache.UpdateCacheMiddleware', 
    }) 
    def test_cache_middleware(self): 
        response = self.client.get('/') 
        # ... 

```

装饰器也可以应用于测试用例类：

```py
from django.test import TestCase, modify_settings 

@modify_settings(MIDDLEWARE_CLASSES={ 
'append': 'django.middleware.cache.FetchFromCacheMiddleware', 
'prepend': 'django.middleware.cache.UpdateCacheMiddleware', 
}) 
class MiddlewareTestCase(TestCase): 

    def test_cache_middleware(self): 
        response = self.client.get('/') 
        # ... 

```

在覆盖设置时，请确保处理应用程序代码使用缓存或类似功能保留状态的情况，即使更改了设置。Django 提供了`django.test.signals.setting_changed`信号，让您注册回调以在更改设置时清理和重置状态。

### 断言

由于 Python 的普通`unittest.TestCase`类实现了`assertTrue()`和`assertEqual()`等断言方法，Django 的自定义`TestCase`类提供了许多对测试 Web 应用程序有用的自定义断言方法：

+   `assertRaisesMessage`：断言可调用对象的执行引发了带有`expected_message`表示的异常。

+   `assertFieldOutput`：断言表单字段对各种输入的行为是否正确。

+   `assertFormError`：断言表单上的字段在表单上呈现时引发提供的错误列表。

+   `assertFormsetError`：断言`formset`在呈现时引发提供的错误列表。

+   `assertContains`：断言`Response`实例产生了给定的`status_code`，并且`text`出现在响应内容中。

+   `assertNotContains`：断言`Response`实例产生了给定的`status_code`，并且`text`不出现在响应内容中。

+   `assertTemplateUsed`：断言在呈现响应时使用了给定名称的模板。名称是一个字符串，例如`'admin/index.html'`。

+   `assertTemplateNotUsed`：断言在呈现响应时未使用给定名称的模板。

+   `assertRedirects`：断言响应返回了`status_code`重定向状态，重定向到`expected_url`（包括任何`GET`数据），并且最终页面以`target_status_code`接收到。

+   `assertHTMLEqual`：断言字符串`html1`和`html2`相等。比较基于 HTML 语义。比较考虑以下内容：

+   HTML 标签前后的空白会被忽略。

+   所有类型的空白都被视为等效。

+   所有未关闭的标签都会被隐式关闭，例如，当周围的标签关闭或 HTML 文档结束时。

+   空标签等同于它们的自关闭版本。

+   HTML 元素的属性排序不重要。

+   没有参数的属性等同于名称和值相等的属性（请参阅示例）。

+   `assertHTMLNotEqual`：断言字符串`html1`和`html2`*不*相等。比较基于 HTML 语义。详情请参阅`assertHTMLEqual()`。

+   `assertXMLEqual`：断言字符串`xml1`和`xml2`相等。比较基于 XML 语义。与`assertHTMLEqual()`类似，比较是基于解析内容的，因此只考虑语义差异，而不考虑语法差异。

+   `assertXMLNotEqual`：断言字符串`xml1`和`xml2`*不*相等。比较基于 XML 语义。详情请参阅`assertXMLEqual()`。

+   `assertInHTML`：断言 HTML 片段`needle`包含在`haystack`中。

+   `assertJSONEqual`：断言 JSON 片段`raw`和`expected_data`相等。

+   `assertJSONNotEqual`：断言 JSON 片段`raw`和`expected_data`不相等。

+   `assertQuerysetEqual`：断言查询集`qs`返回特定的值列表`values`。使用`transform`函数执行`qs`和`values`的内容比较；默认情况下，这意味着比较每个值的`repr()`。

+   `assertNumQueries`：断言当使用`*args`和`**kwargs`调用`func`时，将执行`num`个数据库查询。

## 电子邮件服务

如果您的 Django 视图使用 Django 的电子邮件功能发送电子邮件，您可能不希望每次使用该视图运行测试时都发送电子邮件。因此，Django 的测试运行器会自动将所有 Django 发送的电子邮件重定向到一个虚拟的 outbox。这样，您可以测试发送电子邮件的每个方面，从发送的消息数量到每个消息的内容，而无需实际发送消息。测试运行器通过透明地将正常的电子邮件后端替换为测试后端来实现这一点。（不用担心-这不会对 Django 之外的任何其他电子邮件发送者产生影响，比如您的机器邮件服务器，如果您正在运行的话。）

在测试运行期间，每封发送的电子邮件都会保存在`django.core.mail.outbox`中。这是所有已发送的`EmailMessage`实例的简单列表。`outbox`属性是仅在使用`locmem`电子邮件后端时才会创建的特殊属性。它通常不作为`django.core.mail`模块的一部分存在，也不能直接导入。以下代码显示了如何正确访问此属性。以下是一个检查`django.core.mail.outbox`长度和内容的示例测试：

```py
from django.core import mail 
from django.test import TestCase 

class EmailTest(TestCase): 
    def test_send_email(self): 
        # Send message. 
        mail.send_mail('Subject here', 'Here is the message.', 
'from@example.com', ['to@example.com'], 
            fail_silently=False) 

        # Test that one message has been sent. 
        self.assertEqual(len(mail.outbox), 1) 

        # Verify that the subject of the first message is correct. 
        self.assertEqual(mail.outbox[0].subject, 'Subject here') 

```

如前所述，在 Django 的`*TestCase`中，测试 outbox 在每个测试开始时都会被清空。要手动清空 outbox，请将空列表分配给`mail.outbox`：

```py
from django.core import mail 

# Empty the test outbox 
mail.outbox = [] 

```

## 管理命令

可以使用`call_command()`函数测试管理命令。输出可以重定向到`StringIO`实例中：

```py
from django.core.management import call_command 
from django.test import TestCase 
from django.utils.six import StringIO 

class ClosepollTest(TestCase): 
    def test_command_output(self): 
        out = StringIO() 
        call_command('closepoll', stdout=out) 
        self.assertIn('Expected output', out.getvalue()) 

```

## 跳过测试

`unittest`库提供了`@skipIf`和`@skipUnless`装饰器，允许您在预先知道这些测试在特定条件下会失败时跳过测试。例如，如果您的测试需要特定的可选库才能成功，您可以使用`@skipIf`装饰测试用例。然后，测试运行器将报告该测试未被执行以及原因，而不是失败测试或完全省略测试。

# 测试数据库

需要数据库的测试（即模型测试）不会使用生产数据库；测试时会为其创建单独的空白数据库。无论测试是否通过，测试数据库在所有测试执行完毕时都会被销毁。您可以通过在测试命令中添加`-keepdb`标志来阻止测试数据库被销毁。这将在运行之间保留测试数据库。

如果数据库不存在，将首先创建它。任何迁移也将被应用以保持数据库的最新状态。默认情况下，测试数据库的名称是在`DATABASES`中定义的数据库的`NAME`设置值前加上`test_`。在使用 SQLite 数据库引擎时，默认情况下测试将使用内存数据库（即，数据库将在内存中创建，完全绕过文件系统！）。

如果要使用不同的数据库名称，请在`DATABASES`中为任何给定数据库的`TEST`字典中指定`NAME`。在 PostgreSQL 上，`USER`还需要对内置的`postgres`数据库具有读取权限。除了使用单独的数据库外，测试运行器将使用与设置文件中相同的数据库设置：`ENGINE`、`USER`、`HOST`等。测试数据库由`USER`指定的用户创建，因此您需要确保给定的用户帐户具有在系统上创建新数据库的足够权限。

# 使用不同的测试框架

显然，`unittest`并不是唯一的 Python 测试框架。虽然 Django 不提供对替代框架的显式支持，但它提供了一种调用为替代框架构建的测试的方式，就像它们是普通的 Django 测试一样。

当您运行`./manage.py test`时，Django 会查看`TEST_RUNNER`设置以确定要执行的操作。默认情况下，`TEST_RUNNER`指向`django.test.runner.DiscoverRunner`。这个类定义了默认的 Django 测试行为。这种行为包括：

1.  执行全局的测试前设置。

1.  在当前目录中查找任何以下文件中的测试，其名称与模式`test*.py`匹配。

1.  创建测试数据库。

1.  运行迁移以将模型和初始数据安装到测试数据库中。

1.  运行找到的测试。

1.  销毁测试数据库。

1.  执行全局的测试后拆卸。

如果您定义自己的测试运行器类并将`TEST_RUNNER`指向该类，Django 将在运行`./manage.py test`时执行您的测试运行器。

通过这种方式，可以使用任何可以从 Python 代码执行的测试框架，或者修改 Django 测试执行过程以满足您可能有的任何测试要求。

请查看 Django 项目网站，了解更多关于使用不同测试框架的信息。

# 接下来呢？

现在您已经知道如何为您的 Django 项目编写测试，一旦您准备将项目变成一个真正的网站，我们将继续讨论一个非常重要的话题-将 Django 部署到 Web 服务器。
