# 精通 Django（三）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：高级视图和 URLconfs

在第二章*视图和 URLconfs*中，我们解释了 Django 的视图函数和 URLconfs 的基础知识。本章将更详细地介绍框架中这两个部分的高级功能。

# URLconf 提示和技巧

URLconfs 没有什么特别的-就像 Django 中的其他任何东西一样，它们只是 Python 代码。您可以以几种方式利用这一点，如下面的部分所述。

## 简化函数导入

考虑这个 URLconf，它基于第二章*视图和 URLconfs*中的示例构建：

```py
from django.conf.urls import include, url 
from django.contrib import admin 
from mysite.views import hello, current_datetime, hours_ahead 

urlpatterns = [ 
      url(r'^admin/', include(admin.site.urls)), 
      url(r'^hello/$', hello), 
      url(r'^time/$', current_datetime), 
      url(r'^time/plus/(\d{1,2})/$', hours_ahead), 
      ] 

```

如第二章*视图和 URLconfs*中所述，URLconf 中的每个条目都包括其关联的视图函数，直接作为函数对象传递。这意味着需要在模块顶部导入视图函数。

但是随着 Django 应用程序的复杂性增加，其 URLconf 也会增加，并且保持这些导入可能很繁琐。 （对于每个新的视图函数，您必须记住导入它，并且如果使用这种方法，导入语句往往会变得过长。）

可以通过导入`views`模块本身来避免这种单调。这个示例 URLconf 等同于前一个：

```py
from django.conf.urls import include, url 
from . import views 

urlpatterns = [ 
         url(r'^hello/$', views.hello), 
         url(r'^time/$', views.current_datetime), 
         url(r'^time/plus/(d{1,2})/$', views.hours_ahead), 
] 

```

## 在调试模式下特殊处理 URL

说到动态构建`urlpatterns`，您可能希望利用这种技术来在 Django 的调试模式下更改 URLconf 的行为。为此，只需在运行时检查`DEBUG`设置的值，如下所示：

```py
from django.conf import settings 
from django.conf.urls import url 
from . import views 

urlpatterns = [ 
    url(r'^$', views.homepage), 
    url(r'^(\d{4})/([a-z]{3})/$', views.archive_month), 
] 

if settings.DEBUG: 
 urlpatterns += [url(r'^debuginfo/$', views.debug),]

```

在这个例子中，只有当您的`DEBUG`设置为`True`时，URL`/debuginfo/`才可用。

## 命名组预览

上面的示例使用简单的非命名正则表达式组（通过括号）来捕获 URL 的部分并将它们作为位置参数传递给视图。

在更高级的用法中，可以使用命名的正则表达式组来捕获 URL 部分并将它们作为关键字参数传递给视图。

在 Python 正则表达式中，命名正则表达式组的语法是`(?P<name>pattern)`，其中`name`是组的名称，`pattern`是要匹配的某个模式。

例如，假设我们在我们的书籍网站上有一系列书评，并且我们想要检索特定日期或日期范围的书评。

这是一个示例 URLconf：

```py
from django.conf.urls import url 

from . import views 

urlpatterns = [ 
    url(r'^reviews/2003/$', views.special_case_2003), 
    url(r'^reviews/([0-9]{4})/$', views.year_archive), 
    url(r'^reviews/([0-9]{4})/([0-9]{2})/$', views.month_archive), 
    url(r'^reviews/([0-9]{4})/([0-9]{2})/([0-9]+)/$', views.review_detail), 
] 

```

### 提示

**注意：**

要从 URL 中捕获一个值，只需在其周围加括号。不需要添加一个前导斜杠，因为每个 URL 都有。例如，它是`^reviews`，而不是`^/reviews`。

每个正则表达式字符串前面的`'r'`是可选的，但建议使用。它告诉 Python 字符串是原始的，字符串中的任何内容都不应该被转义。

**示例请求：**

+   对`/reviews/2005/03/`的请求将匹配列表中的第三个条目。Django 将调用函数`views.month_archive(request,``'2005',``'03')`。

+   `/reviews/2005/3/`不会匹配任何 URL 模式，因为列表中的第三个条目要求月份需要两位数字。

+   `/reviews/2003/`将匹配列表中的第一个模式，而不是第二个模式，因为模式是按顺序测试的，第一个模式是第一个通过的测试。可以随意利用排序来插入这样的特殊情况。

+   `/reviews/2003`不会匹配这些模式中的任何一个，因为每个模式都要求 URL 以斜杠结尾。

+   `/reviews/2003/03/03/`将匹配最终模式。Django 将调用函数`views.review_detail(request,``'2003',``'03',``'03')`。

以下是上面的示例 URLconf，重写以使用命名组：

```py
from django.conf.urls import url 

from . import views 

urlpatterns = [ 
    url(r'^reviews/2003/$', views.special_case_2003), 
    url(r'^reviews/(?P<year>[0-9]{4})/$', views.year_archive), 
    url(r'^reviews/(?P<year>[0-9]{4})/(?P<month>[0-9]{2})/$', views.month_archive), 
    url(r'^reviews/(?P<year>[0-9]{4})/(?P<month>[0-9]{2})/(?P<day>[0-9]{2})/$', views.review_detail), 
] 

```

这与前面的示例完全相同，只有一个细微的区别：捕获的值作为关键字参数传递给视图函数，而不是作为位置参数。例如：

+   对`/reviews/2005/03/`的请求将调用函数`views.month_archive(request,``year='2005',``month='03')`，而不是`views.month_archive(request,``'2005',``'03')`。

+   对`/reviews/2003/03/03/`的请求将调用函数`views.review_detail(request,``year='2003',``month='03',``day='03')`。

实际上，这意味着您的 URLconf 更加明确，不太容易出现参数顺序错误-您可以重新排列视图函数定义中的参数。当然，这些好处是以简洁为代价的；一些开发人员认为命名组语法难看且过于冗长。

### 匹配/分组算法

以下是 URLconf 解析器遵循的算法，关于正则表达式中的命名组与非命名组：

1.  如果有任何命名参数，它将使用这些参数，忽略非命名参数。

1.  否则，它将把所有非命名参数作为位置参数传递。

在这两种情况下，任何给定的额外关键字参数也将传递给视图。

## URLconf 搜索的内容

URLconf 会针对请求的 URL 进行搜索，作为普通的 Python 字符串。这不包括`GET`或`POST`参数，也不包括域名。例如，在对`http://www.example.com/myapp/`的请求中，URLconf 将查找`myapp/`。在对`http://www.example.com/myapp/?page=3`的请求中，URLconf 将查找`myapp/`。URLconf 不会查看请求方法。换句话说，所有请求方法-`POST`、`GET`、`HEAD`等等-都将被路由到相同的函数以处理相同的 URL。

## 捕获的参数始终是字符串

每个捕获的参数都作为普通的 Python 字符串发送到视图中，无论正则表达式的匹配类型如何。例如，在这个 URLconf 行中：

```py
url(r'^reviews/(?P<year>[0-9]{4})/$', views.year_archive), 

```

...`views.year_archive()`的`year`参数将是一个字符串，而不是一个整数，即使`[0-9]{4}`只匹配整数字符串。

## 指定视图参数的默认值

一个方便的技巧是为视图的参数指定默认参数。以下是一个示例 URLconf：

```py
# URLconf 
from django.conf.urls import url 

from . import views 

urlpatterns = [ 
    url(r'^reviews/$', views.page), 
    url(r'^reviews/page(?P<num>[0-9]+)/$', views.page), 
] 

# View (in reviews/views.py) 
def page(request, num="1"): 
    # Output the appropriate page of review entries, according to num. 
    ... 

```

在上面的示例中，两个 URL 模式都指向相同的视图-`views.page`-但第一个模式不会从 URL 中捕获任何内容。如果第一个模式匹配，`page()`函数将使用其默认参数`num`，即`"1"`。如果第二个模式匹配，`page()`将使用正则表达式捕获的`num`值。

### 注意

**关键字参数 vs. 位置参数**

Python 函数可以使用关键字参数或位置参数调用-在某些情况下，两者同时使用。在关键字参数调用中，您指定要传递的参数的名称以及值。在位置参数调用中，您只需传递参数，而不明确指定哪个参数匹配哪个值；关联是在参数的顺序中隐含的。例如，考虑这个简单的函数：

`def sell(item, price, quantity): print "以%s 的价格出售%s 个单位的%s" % (quantity, item, price)`

要使用位置参数调用它，您需要按照函数定义中列出的顺序指定参数：`sell('Socks', '$2.50', 6)`

要使用关键字参数调用它，您需要指定参数的名称以及值。以下语句是等效的：`sell(item='Socks', price='$2.50', quantity=6)` `sell(item='Socks', quantity=6, price='$2.50')` `sell(price='$2.50', item='Socks', quantity=6)` `sell(price='$2.50', quantity=6, item='Socks')` `sell(quantity=6, item='Socks', price='$2.50')` `sell(quantity=6, price='$2.50', item='Socks')`

最后，您可以混合使用关键字和位置参数，只要所有位置参数在关键字参数之前列出。以下语句与前面的示例等效：`sell('Socks', '$2.50', quantity=6)` `sell('Socks', price='$2.50', quantity=6)` `sell('Socks', quantity=6, price='$2.50')`

# 性能

`urlpatterns`中的每个正则表达式在第一次访问时都会被编译。这使得系统运行非常快。

# 错误处理

当 Django 找不到与请求的 URL 匹配的正则表达式，或者当引发异常时，Django 将调用一个错误处理视图。用于这些情况的视图由四个变量指定。这些变量是：

+   `handler404`

+   `handler500`

+   `handler403`

+   `handler400`

它们的默认值对于大多数项目应该足够了，但可以通过为它们分配值来进一步定制。这些值可以在您的根 URLconf 中设置。在任何其他 URLconf 中设置这些变量都不会产生效果。值必须是可调用的，或者是表示应该被调用以处理当前错误条件的视图的完整 Python 导入路径的字符串。

# 包含其他 URLconfs

在任何时候，您的 `urlpatterns` 可以包括其他 URLconf 模块。这实质上将一组 URL 根据其他 URL 的下方。例如，这是 Django 网站本身的 URLconf 的摘录。它包括许多其他 URLconfs：

```py
from django.conf.urls import include, url 

urlpatterns = [ 
    # ... 
    url(r'^community/', include('django_website.aggregator.urls')), 
    url(r'^contact/', include('django_website.contact.urls')), 
    # ... 
] 

```

请注意，此示例中的正则表达式没有 `$`（字符串结束匹配字符），但包括一个尾随斜杠。每当 Django 遇到 `include()` 时，它会截掉到目前为止匹配的 URL 的任何部分，并将剩余的字符串发送到包含的 URLconf 进行进一步处理。另一个可能性是通过使用 `url()` 实例的列表来包含其他 URL 模式。例如，考虑这个 URLconf：

```py
from django.conf.urls import include, url 
from apps.main import views as main_views 
from credit import views as credit_views 

extra_patterns = [ 
    url(r'^reports/(?P<id>[0-9]+)/$', credit_views.report), 
    url(r'^charge/$', credit_views.charge), 
] 

urlpatterns = [ 
    url(r'^$', main_views.homepage), 
    url(r'^help/', include('apps.help.urls')), 
    url(r'^credit/', include(extra_patterns)), 
] 

```

在这个例子中，`/credit/reports/` URL 将由 `credit.views.report()` Django 视图处理。这可以用来消除 URLconfs 中重复使用单个模式前缀的冗余。例如，考虑这个 URLconf：

```py
from django.conf.urls import url 
from . import views 

urlpatterns = [ 
    url(r'^(?P<page_slug>\w+)-(?P<page_id>\w+)/history/$',   
        views.history), 
    url(r'^(?P<page_slug>\w+)-(?P<page_id>\w+)/edit/$', views.edit), 
    url(r'^(?P<page_slug>\w+)-(?P<page_id>\w+)/discuss/$',   
        views.discuss), 
    url(r'^(?P<page_slug>\w+)-(?P<page_id>\w+)/permissions/$',  
        views.permissions), 
] 

```

我们可以通过仅声明共同的路径前缀一次并分组不同的后缀来改进这一点：

```py
from django.conf.urls import include, url 
from . import views 

urlpatterns = [ 
    url(r'^(?P<page_slug>\w+)-(?P<page_id>\w+)/',  
        include([ 
        url(r'^history/$', views.history), 
        url(r'^edit/$', views.edit), 
        url(r'^discuss/$', views.discuss), 
        url(r'^permissions/$', views.permissions), 
        ])), 
] 

```

## 捕获的参数

包含的 URLconf 会接收来自父 URLconfs 的任何捕获的参数，因此以下示例是有效的：

```py
# In settings/urls/main.py 
from django.conf.urls import include, url 

urlpatterns = [ 
    url(r'^(?P<username>\w+)/reviews/', include('foo.urls.reviews')), 
] 

# In foo/urls/reviews.py 
from django.conf.urls import url 
from . import views 

urlpatterns = [ 
    url(r'^$', views.reviews.index), 
    url(r'^archive/$', views.reviews.archive), 
] 

```

在上面的示例中，捕获的 `"username"` 变量如预期地传递给了包含的 URLconf。

# 向视图函数传递额外选项

URLconfs 具有一个钩子，可以让您将额外的参数作为 Python 字典传递给视图函数。`django.conf.urls.url()` 函数可以接受一个可选的第三个参数，应该是一个额外关键字参数的字典，用于传递给视图函数。例如：

```py
from django.conf.urls import url 
from . import views 

urlpatterns = [ 
    url(r'^reviews/(?P<year>[0-9]{4})/$',  
        views.year_archive,  
        {'foo': 'bar'}), 
] 

```

在这个例子中，对于对 `/reviews/2005/` 的请求，Django 将调用 `views.year_archive(request,` `year='2005',` `foo='bar')`。这种技术在辅助框架中用于向视图传递元数据和选项（参见第十四章，“生成非 HTML 内容”）。

### 注意

**处理冲突**

可能会有一个 URL 模式，它捕获了命名的关键字参数，并且还在其额外参数的字典中传递了相同名称的参数。当这种情况发生时，字典中的参数将被用于替代 URL 中捕获的参数。

## 向 include() 传递额外的选项

同样，您可以向 `include()` 传递额外的选项。当您向 `include()` 传递额外的选项时，包含的 URLconf 中的每一行都将传递额外的选项。例如，这两个 URLconf 集是功能上相同的：集合一：

```py
# main.py 
from django.conf.urls import include, url 

urlpatterns = [ 
    url(r'^reviews/', include('inner'), {'reviewid': 3}), 
] 

# inner.py 
from django.conf.urls import url 
from mysite import views 

urlpatterns = [ 
    url(r'^archive/$', views.archive), 
    url(r'^about/$', views.about), 
] 

```

集合二：

```py
# main.py 
from django.conf.urls import include, url 
from mysite import views 

urlpatterns = [ 
    url(r'^reviews/', include('inner')), 
] 

# inner.py 
from django.conf.urls import url 

urlpatterns = [ 
    url(r'^archive/$', views.archive, {'reviewid': 3}), 
    url(r'^about/$', views.about, {'reviewid': 3}), 
] 

```

请注意，无论包含的 URLconf 中的视图是否实际接受这些选项作为有效选项，额外的选项都将始终传递给包含的 URLconf 中的每一行。因此，只有在您确定包含的 URLconf 中的每个视图都接受您传递的额外选项时，这种技术才有用。

# URL 的反向解析

在开发 Django 项目时通常需要的是获取 URL 的最终形式，无论是用于嵌入生成的内容（视图和资源 URL，向用户显示的 URL 等）还是用于服务器端的导航流程处理（重定向等）

强烈建议避免硬编码这些 URL（一种费力、不可扩展和容易出错的策略）或者不得不设计专门的机制来生成与 URLconf 描述的设计并行的 URL，因此有可能在某个时刻产生过时的 URL。换句话说，需要的是一种 DRY 机制。

除了其他优点，它还允许 URL 设计的演变，而无需在整个项目源代码中搜索和替换过时的 URL。我们可以作为获取 URL 的起点的信息是处理它的视图的标识（例如名称），必须参与查找正确 URL 的其他信息是视图参数的类型（位置，关键字）和值。

Django 提供了一种解决方案，即 URL 映射器是 URL 设计的唯一存储库。您可以用 URLconf 提供给它，然后可以在两个方向上使用它： 

+   从用户/浏览器请求的 URL 开始，它调用正确的 Django 视图，并提供可能需要的任何参数及其值，这些值是从 URL 中提取的。

+   从对应的 Django 视图的标识开始，以及将传递给它的参数的值，获取相关联的 URL。

第一个是我们在前几节中讨论的用法。第二个是所谓的**URL 的反向解析**，**反向 URL 匹配**，**反向 URL 查找**或简称**URL 反转**。

Django 提供了执行 URL 反转的工具，这些工具与需要 URL 的不同层次匹配：

+   在模板中：使用`url`模板标签。

+   在 Python 代码中：使用`django.core.urlresolvers.reverse()`函数。

+   与 Django 模型实例的 URL 处理相关的高级代码：`get_absolute_url()`方法。

## 示例

再次考虑这个 URLconf 条目：

```py
from django.conf.urls import url 
from . import views 

urlpatterns = [ 
    #... 
    url(r'^reviews/([0-9]{4})/$', views.year_archive,  
        name='reviews-year-archive'), 
    #... 
] 

```

根据这个设计，对应于年份**nnnn**的存档的 URL 是`/reviews/nnnn/`。您可以通过在模板代码中使用以下方式来获取这些：

```py
<a href="{% url 'reviews-year-archive' 2012 %}">2012 Archive</a> 
{# Or with the year in a template context variable: #} 

<ul> 
{% for yearvar in year_list %} 
<li><a href="{% url 'reviews-year-archive' yearvar %}">{{ yearvar }} Archive</a></li> 
{% endfor %} 
</ul> 

```

或者在 Python 代码中：

```py
from django.core.urlresolvers import reverse 
from django.http import HttpResponseRedirect 

def redirect_to_year(request): 
    # ... 
    year = 2012 
    # ... 
    return HttpResponseRedirect(reverse('reviews-year-archive', args=(year,))) 

```

如果出于某种原因，决定更改发布年度审查存档内容的 URL，则只需要更改 URLconf 中的条目。在某些情况下，如果视图具有通用性质，则 URL 和视图之间可能存在多对一的关系。对于这些情况，当需要反转 URL 时，视图名称并不是足够好的标识符。阅读下一节以了解 Django 为此提供的解决方案。

# 命名 URL 模式

为了执行 URL 反转，您需要使用上面示例中所做的命名 URL 模式。用于 URL 名称的字符串可以包含任何您喜欢的字符。您不受限于有效的 Python 名称。当您命名您的 URL 模式时，请确保使用不太可能与任何其他应用程序选择的名称冲突的名称。如果您称呼您的 URL 模式为`comment`，另一个应用程序也这样做，那么当您使用这个名称时，无法保证将插入哪个 URL 到您的模板中。在您的 URL 名称上加上前缀，可能来自应用程序名称，将减少冲突的机会。我们建议使用`myapp-comment`而不是`comment`之类的东西。

# URL 命名空间

URL 命名空间允许您唯一地反转命名的 URL 模式，即使不同的应用程序使用相同的 URL 名称。对于第三方应用程序来说，始终使用命名空间 URL 是一个好习惯。同样，它还允许您在部署多个应用程序实例时反转 URL。换句话说，由于单个应用程序的多个实例将共享命名的 URL，命名空间提供了一种区分这些命名的 URL 的方法。

正确使用 URL 命名空间的 Django 应用程序可以针对特定站点部署多次。例如，`django.contrib.admin`有一个`AdminSite`类，允许您轻松部署多个管理员实例。URL 命名空间由两部分组成，两者都是字符串：

1.  **应用程序命名空间**：描述正在部署的应用程序的名称。单个应用程序的每个实例都将具有相同的应用程序命名空间。例如，Django 的管理员应用程序具有相对可预测的应用程序命名空间`admin`。

1.  **实例命名空间**：标识应用程序的特定实例。实例命名空间应该在整个项目中是唯一的。但是，实例命名空间可以与应用程序命名空间相同。这用于指定应用程序的默认实例。例如，默认的 Django 管理员实例具有`admin`的实例命名空间。

使用`:`运算符指定命名空间 URL。例如，管理员应用程序的主索引页面使用"`admin:index`"引用。这表示命名空间为"`admin`"，命名为"`index`"。

命名空间也可以是嵌套的。命名为`members:reviews:index`的 URL 将在顶级命名空间`members`中查找名为"`index`"的模式。

## 反转命名空间 URL

在给定要解析的命名空间 URL（例如"`reviews:index`"）时，Django 将完全限定的名称分成部分，然后尝试以下查找：

1.  首先，Django 会查找匹配的应用程序命名空间（在本例中为`reviews`）。这将产生该应用程序的实例列表。

1.  如果定义了当前应用程序，Django 会查找并返回该实例的 URL 解析器。当前应用程序可以作为请求的属性指定。期望有多个部署的应用程序应该在正在处理的请求上设置`current_app`属性。

1.  当前应用程序也可以作为`reverse()`函数的参数手动指定。

1.  如果没有当前应用程序。 Django 将寻找默认的应用程序实例。默认的应用程序实例是具有与应用程序命名空间匹配的实例命名空间的实例（在本例中，称为"`reviews`"的 reviews 的实例）。

1.  如果没有默认的应用程序实例，Django 将选择应用程序的最后部署实例，无论其实例名称是什么。

1.  如果提供的命名空间与第 1 步中的应用程序命名空间不匹配，Django 将尝试直接查找该命名空间作为实例命名空间。

如果有嵌套的命名空间，这些步骤将针对命名空间的每个部分重复，直到只剩下视图名称未解析。然后，视图名称将被解析为在找到的命名空间中的 URL。

## URL 命名空间和包含的 URLconfs

包含的 URLconfs 的 URL 命名空间可以通过两种方式指定。首先，当构建 URL 模式时，您可以将应用程序和实例命名空间作为参数提供给`include()`。例如：

```py
url(r'^reviews/', include('reviews.urls', namespace='author-reviews', 
    app_name='reviews')), 

```

这将包括在应用程序命名空间'reviews'中定义的 URL，实例命名空间为'author-reviews'。其次，您可以包含包含嵌入式命名空间数据的对象。如果您包含一个`url()`实例列表，那么该对象中包含的 URL 将被添加到全局命名空间中。但是，您也可以包含一个包含 3 个元素的元组：

```py
(<list of url() instances>, <application namespace>, <instance namespace>) 

```

例如：

```py
from django.conf.urls import include, url 

from . import views 

reviews_patterns = [ 
    url(r'^$', views.IndexView.as_view(), name='index'), 
    url(r'^(?P<pk>\d+)/$', views.DetailView.as_view(), name='detail'),  
] 

url(r'^reviews/', include((reviews_patterns, 'reviews', 
    'author-reviews'))), 

```

这将把提名的 URL 模式包含到给定的应用程序和实例命名空间中。例如，Django 管理界面被部署为`AdminSite`的实例。`AdminSite`对象有一个`urls`属性：一个包含相应管理站点中所有模式的 3 元组，加上应用程序命名空间"`admin`"和管理实例的名称。当你部署一个管理实例时，就是这个`urls`属性被`include()`到你的项目`urlpatterns`中。

一定要向`include()`传递一个元组。如果你只是简单地传递三个参数：`include(reviews_patterns`,`'reviews'`,`'author-reviews')`，Django 不会报错，但由于`include()`的签名，`'reviews'`将成为实例命名空间，`'author-reviews'`将成为应用程序命名空间，而不是相反。

# 接下来呢？

本章提供了许多关于视图和 URLconfs 的高级技巧。接下来，在第八章*高级模板*中，我们将对 Django 的模板系统进行高级处理。


# 第八章：高级模板

尽管你与 Django 的模板语言的大部分交互将是作为模板作者的角色，但你可能想要自定义和扩展模板引擎-要么使其执行一些它尚未执行的操作，要么以其他方式使你的工作更轻松。

本章深入探讨了 Django 模板系统的内部。它涵盖了如果你计划扩展系统或者只是对它的工作方式感到好奇，你需要了解的内容。它还涵盖了自动转义功能，这是一项安全措施，随着你继续使用 Django，你肯定会注意到它。

# 模板语言回顾

首先，让我们快速回顾一些在第三章*模板*中引入的术语：

+   **模板**是一个文本文档，或者是一个普通的 Python 字符串，使用 Django 模板语言进行标记。模板可以包含模板标签和变量。

+   **模板标签**是模板中的一个符号，它执行某些操作。这个定义是故意模糊的。例如，模板标签可以生成内容，充当控制结构（`if`语句或`for`循环），从数据库中获取内容，或者启用对其他模板标签的访问。

模板标签用`{%`和`%}`括起来：

```py
        {% if is_logged_in %} 
            Thanks for logging in! 
        {% else %} 
            Please log in. 
        {% endif %} 

```

+   **变量**是模板中输出值的符号。

+   变量标签用`{{`和`}}`括起来：

+   **上下文**是传递给模板的`name->value`映射（类似于 Python 字典）。

+   模板通过用上下文中的值替换变量“洞”并执行所有模板标签来**渲染**上下文。

有关这些术语的基础知识的更多细节，请参考第三章*模板*。本章的其余部分讨论了扩展模板引擎的方法。不过，首先让我们简要地看一下第三章*模板*中省略的一些内部内容，以简化。

# RequestContext 和上下文处理器

在渲染模板时，你需要一个上下文。这可以是`django.template.Context`的一个实例，但 Django 也带有一个子类`django.template.RequestContext`，它的行为略有不同。

`RequestContext`默认情况下向您的模板上下文添加了一堆变量-诸如`HttpRequest`对象或有关当前登录用户的信息。

`render()`快捷方式会创建一个`RequestContext`，除非显式传递了不同的上下文实例。例如，考虑这两个视图：

```py
from django.template import loader, Context 

def view_1(request): 
    # ... 
    t = loader.get_template('template1.html') 
    c = Context({ 
        'app': 'My app', 
        'user': request.user, 
        'ip_address': request.META['REMOTE_ADDR'], 
        'message': 'I am view 1.' 
    }) 
    return t.render(c) 

def view_2(request): 
    # ... 
    t = loader.get_template('template2.html') 
    c = Context({ 
        'app': 'My app', 
        'user': request.user, 
        'ip_address': request.META['REMOTE_ADDR'], 
        'message': 'I am the second view.' 
    }) 
    return t.render(c) 

```

（请注意，在这些示例中，我们故意没有使用`render()`的快捷方式-我们手动加载模板，构建上下文对象并渲染模板。我们为了清晰起见，详细说明了所有步骤。）

每个视图都传递相同的三个变量-`app`，`user`和`ip_address`-到它的模板。如果我们能够消除这种冗余，那不是很好吗？`RequestContext`和上下文处理器被创建来解决这个问题。上下文处理器允许您指定一些变量，这些变量在每个上下文中自动设置-而无需在每个`render()`调用中指定这些变量。

问题在于，当你渲染模板时，你必须使用`RequestContext`而不是`Context`。使用上下文处理器的最低级别方法是创建一些处理器并将它们传递给`RequestContext`。以下是如何使用上下文处理器编写上面的示例：

```py
from django.template import loader, RequestContext 

def custom_proc(request): 
    # A context processor that provides 'app', 'user' and 'ip_address'. 
    return { 
        'app': 'My app', 
        'user': request.user, 
        'ip_address': request.META['REMOTE_ADDR'] 
    } 

def view_1(request): 
    # ... 
    t = loader.get_template('template1.html') 
    c = RequestContext(request,  
                       {'message': 'I am view 1.'},   
                       processors=[custom_proc]) 
    return t.render(c) 

def view_2(request): 
    # ... 
    t = loader.get_template('template2.html') 
    c = RequestContext(request,  
                       {'message': 'I am the second view.'},   
                       processors=[custom_proc]) 
    return t.render(c) 

```

让我们逐步了解这段代码：

+   首先，我们定义一个函数`custom_proc`。这是一个上下文处理器-它接受一个`HttpRequest`对象，并返回一个要在模板上下文中使用的变量字典。就是这样。

+   我们已将两个视图函数更改为使用`RequestContext`而不是`Context`。上下文构造方式有两个不同之处。首先，`RequestContext`要求第一个参数是一个`HttpRequest`对象-首先传递到视图函数中的对象（`request`）。其次，`RequestContext`需要一个可选的`processors`参数，它是要使用的上下文处理器函数的列表或元组。在这里，我们传入`custom_proc`，我们上面定义的自定义处理器。

+   每个视图不再必须在其上下文构造中包含`app`，`user`或`ip_address`，因为这些由`custom_proc`提供。

+   每个视图仍然具有灵活性，可以引入任何可能需要的自定义模板变量。在此示例中，`message`模板变量在每个视图中设置不同。

在第三章*模板*中，我介绍了`render()`快捷方式，它使您无需调用`loader.get_template()`，然后创建一个`Context`，然后在模板上调用`render()`方法。

为了演示上下文处理器的较低级别工作，上面的示例没有使用`render()`。但是，使用`render()`与上下文处理器是可能的，也是更好的。可以使用`context_instance`参数来实现这一点，如下所示：

```py
from django.shortcuts import render 
from django.template import RequestContext 

def custom_proc(request): 
    # A context processor that provides 'app', 'user' and 'ip_address'. 
    return { 
        'app': 'My app', 
        'user': request.user, 
        'ip_address': request.META['REMOTE_ADDR'] 
    } 

def view_1(request): 
    # ... 
    return render(request, 'template1.html', 
                  {'message': 'I am view 1.'}, 
                  context_instance=RequestContext( 
                  request, processors=[custom_proc] 
                  ) 
    ) 

def view_2(request): 
    # ... 
    return render(request, 'template2.html',                  {'message': 'I am the second view.'}, 
                  context_instance=RequestContext( 
                  request, processors=[custom_proc] 
                  ) 
) 

```

在这里，我们已将每个视图的模板渲染代码简化为单个（包装）行。这是一个改进，但是，评估这段代码的简洁性时，我们必须承认我们现在几乎过度使用了另一端的频谱。我们消除了数据中的冗余（我们的模板变量），但增加了代码中的冗余（在`processors`调用中）。

如果您必须一直输入`processors`，使用上下文处理器并不能节省太多输入。因此，Django 提供了全局上下文处理器的支持。`context_processors`设置（在您的`settings.py`中）指定应始终应用于`RequestContext`的上下文处理器。这样可以避免每次使用`RequestContext`时都需要指定`processors`。

默认情况下，`context_processors`设置如下：

```py
'context_processors': [ 
            'django.template.context_processors.debug', 
            'django.template.context_processors.request', 
            'django.contrib.auth.context_processors.auth', 
'django.contrib.messages.context_processors.messages', 
        ], 

```

此设置是一个可调用对象的列表，其接口与上面的`custom_proc`函数相同-接受请求对象作为其参数，并返回要合并到上下文中的项目的字典。请注意，`context_processors`中的值被指定为**字符串**，这意味着处理器必须在 Python 路径的某个位置（因此您可以从设置中引用它们）。

每个处理器都按顺序应用。也就是说，如果一个处理器向上下文添加一个变量，并且第二个处理器使用相同的名称添加一个变量，则第二个处理器将覆盖第一个处理器。Django 提供了许多简单的上下文处理器，包括默认启用的处理器：

## auth

`django.contrib.auth.context_processors.auth`

如果启用了此处理器，则每个`RequestContext`都将包含这些变量：

+   `user`：表示当前登录用户的`auth.User`实例（或`AnonymousUser`实例，如果客户端未登录）。

+   `perms`：表示当前登录用户具有的权限的`django.contrib.auth.context_processors.PermWrapper`实例。

## DEBUG

`django.template.context_processors.debug`

如果启用了此处理器，则每个`RequestContext`都将包含这两个变量-但仅当您的`DEBUG`设置为`True`并且请求的 IP 地址（`request.META['REMOTE_ADDR']`）在`INTERNAL_IPS`设置中时：

+   `debug`-`True`：您可以在模板中使用此选项来测试是否处于`DEBUG`模式。

+   `sql_queries`：一个`{'sql': ..., 'time': ...}`字典的列表，表示请求期间发生的每个 SQL 查询及其所花费的时间。列表按查询顺序生成，并在访问时惰性生成。

## i18n

`django.template.context_processors.i18n`

如果启用了此处理器，则每个`RequestContext`都将包含这两个变量：

+   `LANGUAGES`：`LANGUAGES`设置的值。

+   `LANGUAGE_CODE`：`request.LANGUAGE_CODE`，如果存在的话。否则，为`LANGUAGE_CODE`设置的值。

## 媒体

`django.template.context_processors.media`

如果启用了此处理器，每个`RequestContext`都将包含一个名为`MEDIA_URL`的变量，该变量提供`MEDIA_URL`设置的值。

## 静态

`django.template.context_processors.static`

如果启用了此处理器，每个`RequestContext`都将包含一个名为`STATIC_URL`的变量，该变量提供`STATIC_URL`设置的值。

## csrf

`django.template.context_processors.csrf`

此处理器添加了一个`csrf_token`模板标记所需的令牌，以防止跨站点请求伪造（请参见第十九章，“Django 中的安全性”）。

## 请求

`django.template.context_processors.request`

如果启用了此处理器，每个`RequestContext`都将包含一个名为`request`的变量，该变量是当前的`HttpRequest`。

## 消息

`django.contrib.messages.context_processors.messages`

如果启用了此处理器，每个`RequestContext`都将包含这两个变量：

+   `messages`：已通过消息框架设置的消息（作为字符串）的列表。

+   `DEFAULT_MESSAGE_LEVELS`：消息级别名称与其数值的映射。

# 编写自己的上下文处理器指南

上下文处理器具有非常简单的接口：它只是一个接受一个`HttpRequest`对象的 Python 函数，并返回一个添加到模板上下文中的字典。每个上下文处理器必须返回一个字典。以下是一些编写自己上下文处理器的提示：

+   使每个上下文处理器负责尽可能小的功能子集。使用多个处理器很容易，因此最好将功能拆分为将来重用的逻辑片段。

+   请记住，`TEMPLATE_CONTEXT_PROCESSORS`中的任何上下文处理器都将在由该设置文件提供动力的每个模板中可用，因此请尝试选择与模板可能独立使用的变量名不太可能发生冲突的变量名。由于变量名区分大小写，因此最好使用所有大写字母来表示处理器提供的变量。

+   自定义上下文处理器可以存在于代码库中的任何位置。Django 关心的是您的自定义上下文处理器是否由`TEMPLATES`设置中的`'context_processors'`选项指向，或者如果直接使用`Engine`，则由`Engine`的`context_processors`参数指向。话虽如此，惯例是将它们保存在应用程序或项目中名为`context_processors.py`的文件中。

# 自动 HTML 转义

在从模板生成 HTML 时，总是存在一个变量包含影响生成的 HTML 的字符的风险。例如，考虑这个模板片段：

```py
Hello, {{ name }}. 

```

起初，这似乎是一种无害的显示用户姓名的方式，但请考虑如果用户将他的名字输入为这样会发生什么：

```py
<script>alert('hello')</script> 

```

使用这个名称值，模板将被渲染为：

```py
Hello, <script>alert('hello')</script> 

```

……这意味着浏览器将弹出一个 JavaScript 警报框！同样，如果名称包含`'<'`符号，会怎么样？

```py
<b>username 

```

这将导致渲染的模板如下：

```py
Hello, <b>username 

```

……这将导致网页的其余部分变粗！显然，不应盲目信任用户提交的数据并直接插入到您的网页中，因为恶意用户可能利用这种漏洞做出潜在的坏事。

这种安全漏洞称为跨站脚本（XSS）攻击。（有关安全性的更多信息，请参见第十九章，“Django 中的安全性”）。为了避免这个问题，您有两个选择：

+   首先，您可以确保通过`escape`过滤器运行每个不受信任的变量，该过滤器将潜在有害的 HTML 字符转换为无害的字符。这是 Django 最初几年的默认解决方案，但问题在于它把责任放在了*您*，开发者/模板作者身上，确保您转义了所有内容。很容易忘记转义数据。

+   其次，您可以利用 Django 的自动 HTML 转义。本节的其余部分将描述自动转义的工作原理。

+   在 Django 中，默认情况下，每个模板都会自动转义每个变量标签的输出。具体来说，这五个字符会被转义：

+   `<` 被转换为 `&lt;`

+   `>` 被转换为 `&gt;`

+   `'`（单引号）被转换为`'`

+   `"`（双引号）被转换为`&quot;`

+   `&` 被转换为 `&amp;`

再次强调，这种行为默认情况下是开启的。如果您使用 Django 的模板系统，您就受到了保护。

## 如何关闭它

如果您不希望数据在每个站点、每个模板级别或每个变量级别自动转义，可以通过多种方式关闭它。为什么要关闭它？因为有时模板变量包含您希望呈现为原始 HTML 的数据，这种情况下您不希望它们的内容被转义。

例如，您可能会在数据库中存储一大段受信任的 HTML，并希望直接将其嵌入到模板中。或者，您可能正在使用 Django 的模板系统来生成非 HTML 文本-例如电子邮件消息。

## 对于单个变量

要为单个变量禁用自动转义，请使用`safe`过滤器：

```py
This will be escaped: {{ data }} 
This will not be escaped: {{ data|safe }} 

```

将*safe*视为*免受进一步转义*或*可以安全解释为 HTML*的简写。在这个例子中，如果`data`包含`<b>`，输出将是：

```py
This will be escaped: &lt;b&gt; 
This will not be escaped: <b> 

```

## 对于模板块

要控制模板的自动转义，可以将模板（或模板的特定部分）包装在`autoescape`标签中，如下所示：

```py
{% autoescape off %} 
    Hello {{ name }} 
{% endautoescape %} 

```

`autoescape`标签接受`on`或`off`作为参数。有时，您可能希望在本来被禁用自动转义的情况下强制进行自动转义。以下是一个示例模板：

```py
Auto-escaping is on by default. Hello {{ name }} 

{% autoescape off %} 
    This will not be auto-escaped: {{ data }}. 

    Nor this: {{ other_data }} 
    {% autoescape on %} 
        Auto-escaping applies again: {{ name }} 
    {% endautoescape %} 
{% endautoescape %} 

```

自动转义标签会将其效果传递给扩展当前模板以及通过`include`标签包含的模板，就像所有块标签一样。例如：

```py
# base.html 

{% autoescape off %} 
<h1>{% block title %}{% endblock %}</h1> 
{% block content %} 
{% endblock %} 
{% endautoescape %} 

# child.html 

{% extends "base.html" %} 
{% block title %}This & that{% endblock %} 
{% block content %}{{ greeting }}{% endblock %} 

```

因为基础模板中关闭了自动转义，所以在子模板中也会关闭自动转义，当`greeting`变量包含字符串`<b>Hello!</b>`时，将会产生以下渲染的 HTML：

```py
<h1>This & that</h1> 
<b>Hello!</b> 

```

一般来说，模板作者不需要太担心自动转义。Python 端的开发人员（编写视图和自定义过滤器的人）需要考虑数据不应该被转义的情况，并适当标记数据，以便在模板中正常工作。

如果您正在创建一个可能在您不确定自动转义是否启用的情况下使用的模板，那么请为任何需要转义的变量添加`escape`过滤器。当自动转义开启时，`escape`过滤器不会导致数据双重转义-`escape`过滤器不会影响自动转义的变量。

## 在过滤器参数中自动转义字符串文字

正如我们之前提到的，过滤器参数可以是字符串：

```py
{{ data|default:"This is a string literal." }} 

```

所有字符串文字都会被插入到模板中，而不会进行任何自动转义-它们的行为就好像它们都通过了`safe`过滤器。背后的原因是模板作者控制着字符串文字的内容，因此他们可以确保在编写模板时正确地转义文本。

这意味着您应该这样写

```py
{{ data|default:"3 &lt; 2" }} 

```

...而不是

```py
{{ data|default:"3 < 2" }} <== Bad! Don't do this. 

```

这不会影响来自变量本身的数据。变量的内容仍然会在必要时自动转义，因为它们超出了模板作者的控制。

# 模板加载内部

通常，您会将模板存储在文件系统中，而不是自己使用低级别的`Template` API。将模板保存在指定为模板目录的目录中。 Django 根据您的模板加载设置在许多地方搜索模板目录（请参阅下面的*Loader 类型*），但指定模板目录的最基本方法是使用`DIRS`选项。

## DIRS 选项

通过在设置文件中的`TEMPLATES`设置中使用`DIRS`选项或在`Engine`的`dirs`参数中使用`DIRS`选项，告诉 Django 您的模板目录是什么。这应设置为包含完整路径的字符串列表，以包含模板目录：

```py
TEMPLATES = [ 
    { 
        'BACKEND': 'django.template.backends.django.DjangoTemplates', 
        'DIRS': [ 
            '/home/html/templates/lawrence.com', 
            '/home/html/templates/default', 
        ], 
    }, 
] 

```

您的模板可以放在任何您想要的地方，只要目录和模板对 Web 服务器可读。它们可以具有任何您想要的扩展名，例如`.html`或`.txt`，或者它们可以根本没有扩展名。请注意，这些路径应使用 Unix 样式的正斜杠，即使在 Windows 上也是如此。

## 加载程序类型

默认情况下，Django 使用基于文件系统的模板加载程序，但 Django 还配备了其他几个模板加载程序，它们知道如何从其他来源加载模板；其中最常用的应用程序加载程序将在下面进行描述。

### 文件系统加载程序

`filesystem.Loader`从文件系统加载模板，根据`DIRS <TEMPLATES-DIRS>`。此加载程序默认启用。但是，直到您将`DIRS <TEMPLATES-DIRS>`设置为非空列表之前，它才能找到任何模板：

```py
TEMPLATES = [{ 
    'BACKEND': 'django.template.backends.django.DjangoTemplates', 
    'DIRS': [os.path.join(BASE_DIR, 'templates')], 
}] 

```

### 应用程序目录加载程序

`app_directories.Loader`从文件系统加载 Django 应用程序的模板。对于`INSTALLED_APPS`中的每个应用程序，加载程序都会查找`templates`子目录。如果目录存在，Django 将在其中查找模板。这意味着您可以将模板与各个应用程序一起存储。这也使得很容易使用默认模板分发 Django 应用程序。例如，对于此设置：

```py
INSTALLED_APPS = ['myproject.reviews', 'myproject.music'] 

```

`get_template('foo.html')`将按照这些顺序在这些目录中查找`foo.html`：

+   `/path/to/myproject/reviews/templates/`

+   `/path/to/myproject/music/templates/`

并使用它找到的第一个。

**INSTALLED_APPS 的顺序很重要！**

例如，如果您想要自定义 Django 管理界面，您可能会选择使用自己的`myproject.reviews`中的`admin/base_site.html`覆盖标准的`admin/base_site.html`模板，而不是使用`django.contrib.admin`。

然后，您必须确保`myproject.reviews`在`INSTALLED_APPS`中出现在`django.contrib.admin`之前，否则将首先加载`django.contrib.admin`，并且您的将被忽略。

请注意，加载程序在首次运行时执行优化：它缓存了具有`templates`子目录的`INSTALLED_APPS`包的列表。

您只需将`APP_DIRS`设置为`True`即可启用此加载程序：

```py
TEMPLATES = [{ 
    'BACKEND': 'django.template.backends.django.DjangoTemplates', 
    'APP_DIRS': True, 
}] 

```

### 其他加载程序

其余的模板加载程序是：

+   `django.template.loaders.eggs.Loader`

+   `django.template.loaders.cached.Loader`

+   `django.template.loaders.locmem.Loader`

这些加载程序默认情况下是禁用的，但是您可以通过在`TEMPLATES`设置中的`DjangoTemplates`后端中添加`loaders`选项或将`loaders`参数传递给`Engine`来激活它们。有关这些高级加载程序的详细信息，以及构建自己的自定义加载程序，可以在 Django 项目网站上找到。

# 扩展模板系统

现在您对模板系统的内部工作有了更多了解，让我们看看如何使用自定义代码扩展系统。大多数模板定制以自定义模板标签和/或过滤器的形式出现。尽管 Django 模板语言带有许多内置标签和过滤器，但您可能会组装自己的标签和过滤器库，以满足自己的需求。幸运的是，定义自己的功能非常容易。

## 代码布局

自定义模板标签和过滤器必须位于 Django 应用程序中。如果它们与现有应用程序相关，将它们捆绑在那里是有意义的；否则，您应该创建一个新的应用程序来保存它们。该应用程序应该包含一个`templatetags`目录，与`models.py`、`views.py`等文件处于同一级别。如果这个目录还不存在，请创建它-不要忘记`__init__.py`文件，以确保该目录被视为 Python 包。

添加此模块后，您需要在使用模板中的标签或过滤器之前重新启动服务器。您的自定义标签和过滤器将位于`templatetags`目录中的一个模块中。

模块文件的名称是您以后将用来加载标签的名称，因此要小心选择一个不会与另一个应用程序中的自定义标签和过滤器冲突的名称。

例如，如果您的自定义标签/过滤器在名为`review_extras.py`的文件中，您的应用程序布局可能如下所示：

```py
reviews/ 
    __init__.py 
    models.py 
    templatetags/ 
        __init__.py 
        review_extras.py 
    views.py 

```

在您的模板中，您将使用以下内容：

```py
{% load review_extras %} 

```

包含自定义标签的应用程序必须在`INSTALLED_APPS`中，以便`{% load %}`标签能够工作。

### 注意

**幕后**

要获取大量示例，请阅读 Django 默认过滤器和标签的源代码。它们分别位于`django/template/defaultfilters.py`和`django/template/defaulttags.py`中。有关`load`标签的更多信息，请阅读其文档。

## 创建模板库

无论您是编写自定义标签还是过滤器，首先要做的是创建一个**模板库**-这是 Django 可以连接到的一小部分基础设施。

创建模板库是一个两步过程：

+   首先，决定哪个 Django 应用程序应该包含模板库。如果您通过`manage.py startapp`创建了一个应用程序，您可以将其放在那里，或者您可以创建另一个仅用于模板库的应用程序。我们建议选择后者，因为您的过滤器可能对将来的项目有用。无论您选择哪种路线，请确保将应用程序添加到您的`INSTALLED_APPS`设置中。我马上会解释这一点。

+   其次，在适当的 Django 应用程序包中创建一个`templatetags`目录。它应该与`models.py`、`views.py`等文件处于同一级别。例如：

```py
        books/
        __init__.py
        models.py
        templatetags/
        views.py
```

在`templatetags`目录中创建两个空文件：一个`__init__.py`文件（表示这是一个包含 Python 代码的包）和一个包含自定义标签/过滤器定义的文件。后者的文件名是您以后将用来加载标签的名称。例如，如果您的自定义标签/过滤器在名为`review_extras.py`的文件中，您可以在模板中写入以下内容：

```py
{% load review_extras %} 

```

`{% load %}`标签查看您的`INSTALLED_APPS`设置，并且只允许加载已安装的 Django 应用程序中的模板库。这是一个安全功能；它允许您在单台计算机上托管许多模板库的 Python 代码，而不会为每个 Django 安装启用对所有模板库的访问。

如果您编写的模板库与任何特定的模型/视图无关，那么拥有一个仅包含`templatetags`包的 Django 应用程序包是有效的和非常正常的。

在`templatetags`包中放置多少模块都没有限制。只需记住，`{% load %}`语句将加载给定 Python 模块名称的标签/过滤器，而不是应用程序的名称。

创建了该 Python 模块后，您只需根据您是编写过滤器还是标签来编写一些 Python 代码。要成为有效的标签库，模块必须包含一个名为`register`的模块级变量，它是`template.Library`的实例。

这是所有标签和过滤器注册的数据结构。因此，在您的模块顶部附近，插入以下内容：

```py
from django import template 
register = template.Library() 

```

# 自定义模板标签和过滤器

Django 的模板语言配备了各种内置标签和过滤器，旨在满足应用程序的呈现逻辑需求。尽管如此，您可能会发现自己需要的功能不在核心模板原语集中。

您可以通过使用 Python 定义自定义标签和过滤器来扩展模板引擎，然后使用`{% load %}`标签将其提供给模板。

## 编写自定义模板过滤器

自定义过滤器只是接受一个或两个参数的 Python 函数：

+   变量的值（输入）-不一定是一个字符串。

+   参数的值-这可以有一个默认值，或者完全省略。

例如，在过滤器`{{ var|foo:"bar" }}`中，过滤器`foo`将接收变量`var`和参数`"bar"`。由于模板语言不提供异常处理，从模板过滤器引发的任何异常都将暴露为服务器错误。

因此，如果有一个合理的回退值可以返回，过滤函数应该避免引发异常。在模板中表示明显错误的输入情况下，引发异常可能仍然比隐藏错误的静默失败更好。这是一个示例过滤器定义：

```py
def cut(value, arg): 
    """Removes all values of arg from the given string""" 
    return value.replace(arg, '') 

```

以下是该过滤器的使用示例：

```py
{{ somevariable|cut:"0" }} 

```

大多数过滤器不带参数。在这种情况下，只需在函数中省略参数。例如：

```py
def lower(value): # Only one argument. 
    """Converts a string into all lowercase""" 
    return value.lower() 

```

### 注册自定义过滤器

编写完过滤器定义后，您需要将其注册到您的`Library`实例中，以使其可用于 Django 的模板语言：

```py
register.filter('cut', cut) 
register.filter('lower', lower) 

```

`Library.filter()`方法接受两个参数：

1.  过滤器的名称-一个字符串。

1.  编译函数-一个 Python 函数（而不是函数的名称作为字符串）。

您可以将`register.filter()`用作装饰器：

```py
@register.filter(name='cut') 
def cut(value, arg): 
    return value.replace(arg, '') 

@register.filter 
def lower(value): 
    return value.lower() 

```

如果省略`name`参数，就像上面的第二个示例一样，Django 将使用函数的名称作为过滤器名称。最后，`register.filter()`还接受三个关键字参数，`is_safe`，`needs_autoescape`和`expects_localtime`。这些参数在下面的过滤器和自动转义以及过滤器和时区中进行了描述。

### 期望字符串的模板过滤器

如果您正在编写一个模板过滤器，只期望第一个参数是字符串，您应该使用装饰器`stringfilter`。这将在将对象传递给您的函数之前将其转换为其字符串值：

```py
from django import template 
from django.template.defaultfilters import stringfilter 

register = template.Library() 

@register.filter 
@stringfilter 
def lower(value): 
    return value.lower() 

```

这样，您就可以将一个整数传递给这个过滤器，它不会引起`AttributeError`（因为整数没有`lower()`方法）。

### 过滤器和自动转义

在编写自定义过滤器时，要考虑过滤器将如何与 Django 的自动转义行为交互。请注意，在模板代码中可以传递三种类型的字符串：

+   **原始字符串**是本机 Python `str`或`unicode`类型。在输出时，如果自动转义生效，它们会被转义并保持不变，否则。

+   **安全字符串**是在输出时已标记为免受进一步转义的字符串。任何必要的转义已经完成。它们通常用于包含原始 HTML 的输出，该 HTML 旨在在客户端上按原样解释。

+   在内部，这些字符串的类型是`SafeBytes`或`SafeText`。它们共享一个名为`SafeData`的基类，因此您可以使用类似的代码对它们进行测试：

+   如果`value`是`SafeData`的实例：

```py
        # Do something with the "safe" string.
        ...
```

+   **标记为“需要转义”的字符串**在输出时始终会被转义，无论它们是否在`autoescape`块中。但是，这些字符串只会被转义一次，即使自动转义适用。

在内部，这些字符串的类型是`EscapeBytes`或`EscapeText`。通常，您不必担心这些问题；它们存在是为了实现`escape`过滤器。

模板过滤器代码分为两种情况：

1.  您的过滤器不会在结果中引入任何 HTML 不安全的字符（`<`，`>`，`'`，`"`或`&`），这些字符在结果中本来就存在；或

1.  或者，您的过滤器代码可以手动处理任何必要的转义。当您将新的 HTML 标记引入结果时，这是必要的。

在第一种情况下，您可以让 Django 为您处理所有自动转义处理。您只需要在注册过滤器函数时将`is_safe`标志设置为`True`，如下所示：

```py
@register.filter(is_safe=True)
def myfilter(value):
    return value

```

这个标志告诉 Django，如果将安全字符串传递到您的过滤器中，则结果仍将是安全的，如果传递了不安全的字符串，则 Django 将自动转义它（如果需要的话）。您可以将其视为意味着“此过滤器是安全的-它不会引入任何不安全的 HTML 可能性。”

`is_safe`之所以必要是因为有很多普通的字符串操作会将`SafeData`对象转换回普通的`str`或`unicode`对象，而不是尝试捕获它们所有，这将非常困难，Django 会在过滤器完成后修复损坏。

例如，假设您有一个过滤器，它将字符串`xx`添加到任何输入的末尾。由于这不会向结果引入危险的 HTML 字符（除了已经存在的字符），因此应该使用`is_safe`标记过滤器：

```py
@register.filter(is_safe=True) 
def add_xx(value): 
    return '%sxx' % value 

```

当在启用自动转义的模板中使用此过滤器时，Django 将在输入未标记为安全时转义输出。默认情况下，`is_safe`为`False`，并且您可以在任何不需要的过滤器中省略它。在决定您的过滤器是否确实将安全字符串保持为安全时要小心。如果您删除字符，可能会无意中在结果中留下不平衡的 HTML 标记或实体。

例如，从输入中删除`>`可能会将`<a>`变为`<a`，这需要在输出时进行转义，以避免引起问题。同样，删除分号（`;`）可能会将`&amp;`变为`&amp`，这不再是一个有效的实体，因此需要进一步转义。大多数情况下不会有这么棘手，但是在审查代码时要注意任何类似的问题。

标记过滤器`is_safe`将强制过滤器的返回值为字符串。如果您的过滤器应返回布尔值或其他非字符串值，则将其标记为`is_safe`可能会产生意想不到的后果（例如将布尔值`False`转换为字符串`False`）。

在第二种情况下，您希望标记输出为安全，以免进一步转义您的 HTML 标记，因此您需要自己处理输入。要将输出标记为安全字符串，请使用`django.utils.safestring.mark_safe()`。

不过要小心。您需要做的不仅仅是标记输出为安全。您需要确保它确实是安全的，您的操作取决于自动转义是否生效。

这个想法是编写可以在模板中运行的过滤器，无论自动转义是打开还是关闭，以便为模板作者简化事情。

为了使您的过滤器知道当前的自动转义状态，请在注册过滤器函数时将`needs_autoescape`标志设置为`True`。（如果您不指定此标志，它将默认为`False`）。这个标志告诉 Django，您的过滤器函数希望传递一个额外的关键字参数，称为`autoescape`，如果自动转义生效，则为`True`，否则为`False`。

例如，让我们编写一个过滤器，强调字符串的第一个字符：

```py
from django import template 
from django.utils.html import conditional_escape 
from django.utils.safestring import mark_safe 

register = template.Library() 

@register.filter(needs_autoescape=True) 
def initial_letter_filter(text, autoescape=None): 
    first, other = text[0], text[1:] 
    if autoescape: 
        esc = conditional_escape 
    else: 
        esc = lambda x: x 
    result = '<strong>%s</strong>%s' % (esc(first), esc(other)) 
    return mark_safe(result) 

```

`needs_autoescape`标志和`autoescape`关键字参数意味着我们的函数将知道在调用过滤器时是否自动转义。我们使用`autoescape`来决定输入数据是否需要通过`django.utils.html.conditional_escape`传递。 （在后一种情况下，我们只使用身份函数作为“转义”函数。）

`conditional_escape()`函数类似于`escape()`，只是它只转义**不是**`SafeData`实例的输入。如果将`SafeData`实例传递给`conditional_escape()`，则数据将保持不变。

最后，在上面的例子中，我们记得将结果标记为安全，以便我们的 HTML 直接插入模板而不需要进一步转义。在这种情况下，不需要担心 `is_safe` 标志（尽管包含它也不会有什么坏处）。每当您手动处理自动转义问题并返回安全字符串时，`is_safe` 标志也不会改变任何东西。

### 过滤器和时区

如果您编写一个在 `datetime` 对象上操作的自定义过滤器，通常会将其注册为 `expects_localtime` 标志设置为 `True`：

```py
@register.filter(expects_localtime=True) 
def businesshours(value): 
    try: 
        return 9 <= value.hour < 17 
    except AttributeError: 
        return '' 

```

当设置了此标志时，如果您的过滤器的第一个参数是时区感知的日期时间，则 Django 会根据模板中的时区转换规则在适当时将其转换为当前时区后传递给您的过滤器。

### 注意

**在重用内置过滤器时避免 XSS 漏洞**

在重用 Django 的内置过滤器时要小心。您需要向过滤器传递 `autoescape=True` 以获得正确的自动转义行为，并避免跨站脚本漏洞。例如，如果您想编写一个名为 `urlize_and_linebreaks` 的自定义过滤器，该过滤器结合了 `urlize` 和 `linebreaksbr` 过滤器，那么过滤器将如下所示：

`from django.template.defaultfilters import linebreaksbr, urlize` `@register.filter` `def urlize_and_linebreaks(text):` `return linebreaksbr(` `urlize(text, autoescape=True),autoescape=True)` `然后：` `{{ comment|urlize_and_linebreaks }}` `等同于：` `{{ comment|urlize|linebreaksbr }}`

## 编写自定义模板标签

标签比过滤器更复杂，因为标签可以做任何事情。Django 提供了许多快捷方式，使编写大多数类型的标签更容易。首先我们将探讨这些快捷方式，然后解释如何为那些快捷方式不够强大的情况下从头编写标签。

### 简单标签

许多模板标签需要一些参数-字符串或模板变量-并且在仅基于输入参数和一些外部信息进行一些处理后返回结果。

例如，`current_time` 标签可能接受一个格式字符串，并根据格式化返回时间字符串。为了简化这些类型的标签的创建，Django 提供了一个辅助函数 `simple_tag`。这个函数是 `django.template.Library` 的一个方法，它接受一个接受任意数量参数的函数，将其包装在一个 `render` 函数和其他必要的部分中，并将其注册到模板系统中。

我们的 `current_time` 函数可以这样编写：

```py
import datetime 
from django import template 

register = template.Library() 

@register.simple_tag 
def current_time(format_string): 
    return datetime.datetime.now().strftime(format_string) 

```

关于 `simple_tag` 辅助函数的一些注意事项：

+   在我们的函数被调用时，已经检查了所需数量的参数等，所以我们不需要再做这些。

+   参数（如果有）周围的引号已经被剥离，所以我们只收到一个普通字符串。

+   如果参数是模板变量，则我们的函数会传递变量的当前值，而不是变量本身。

如果您的模板标签需要访问当前上下文，可以在注册标签时使用 `takes_context` 参数：

```py
@register.simple_tag(takes_context=True) 
def current_time(context, format_string): 
    timezone = context['timezone'] 
    return your_get_current_time_method(timezone, format_string) 

```

请注意，第一个参数必须称为 `context`。有关 `takes_context` 选项的工作原理的更多信息，请参阅包含标签部分。如果您需要重命名标签，可以为其提供自定义名称：

```py
register.simple_tag(lambda x: x-1, name='minusone') 

@register.simple_tag(name='minustwo') 
def some_function(value): 
    return value-2 

```

`simple_tag` 函数可以接受任意数量的位置参数或关键字参数。例如：

```py
@register.simple_tag 
def my_tag(a, b, *args, **kwargs): 
    warning = kwargs['warning'] 
    profile = kwargs['profile'] 
    ... 
    return ... 

```

然后在模板中，可以传递任意数量的参数，用空格分隔，到模板标签。就像在 Python 中一样，关键字参数的值使用等号（“=`”）设置，并且必须在位置参数之后提供。例如：

```py
{% my_tag 123 "abcd" book.title warning=message|lower profile=user.profile %} 

```

### 包含标签

另一种常见的模板标签类型是通过呈现另一个模板来显示一些数据的类型。例如，Django 的管理界面使用自定义模板标签来显示“添加/更改”表单页面底部的按钮。这些按钮始终看起来相同，但链接目标会根据正在编辑的对象而变化-因此它们是使用填充了当前对象详细信息的小模板的完美案例。（在管理界面的情况下，这是`submit_row`标签。）

这些类型的标签被称为包含标签。编写包含标签最好通过示例来演示。让我们编写一个为给定的`Author`对象生成书籍列表的标签。我们将像这样使用该标签：

```py
{% books_for_author author %} 

```

结果将会是这样的：

```py
<ul> 
    <li>The Cat In The Hat</li> 
    <li>Hop On Pop</li> 
    <li>Green Eggs And Ham</li> 
</ul> 

```

首先，我们定义一个接受参数并生成结果数据字典的函数。请注意，我们只需要返回一个字典，而不是更复杂的内容。这将用作模板片段的上下文：

```py
def books_for_author(author): 
    books = Book.objects.filter(authors__id=author.id) 
    return {'books': books} 

```

接下来，我们创建用于呈现标签输出的模板。根据我们的示例，模板非常简单：

```py
<ul> 
{% for book in books %}<li>{{ book.title }}</li> 
{% endfor %} 
</ul> 

```

最后，我们通过在`Library`对象上调用`inclusion_tag()`方法来创建和注册包含标签。根据我们的示例，如果前面的模板在模板加载器搜索的目录中的名为`book_snippet.html`的文件中，我们可以像这样注册标签：

```py
# Here, register is a django.template.Library instance, as before 
@register.inclusion_tag('book_snippet.html') 
def show_reviews(review): 
    ... 

```

或者，可以在首次创建函数时使用`django.template.Template`实例注册包含标签：

```py
from django.template.loader import get_template 
t = get_template('book_snippet.html') 
register.inclusion_tag(t)(show_reviews) 

```

有时，你的包含标签可能需要大量的参数，这使得模板作者很难传递所有参数并记住它们的顺序。为了解决这个问题，Django 为包含标签提供了一个`takes_context`选项。如果在创建包含标签时指定了`takes_context`，则该标签将不需要必需的参数，而底层的 Python 函数将有一个参数：调用标签时的模板上下文。例如，假设你正在编写一个包含标签，它将始终在包含`home_link`和`home_title`变量指向主页的上下文中使用。下面是 Python 函数的样子：

```py
@register.inclusion_tag('link.html', takes_context=True) 
def jump_link(context): 
    return { 
        'link': context['home_link'], 
        'title': context['home_title'], 
    } 

```

（请注意，函数的第一个参数必须称为`context`。）模板`link.html`可能包含以下内容：

```py
Jump directly to <a href="{{ link }}">{{ title }}</a>. 

```

然后，每当你想要使用该自定义标签时，加载它的库并在没有任何参数的情况下调用它，就像这样：

```py
{% jump_link %} 

```

请注意，当使用`takes_context=True`时，无需向模板标签传递参数。它会自动访问上下文。`takes_context`参数默认为`False`。当设置为`True`时，标签将传递上下文对象，就像这个例子一样。这是这种情况和之前的`inclusion_tag`示例之间的唯一区别。像`simple_tag`一样，`inclusion_tag`函数也可以接受任意数量的位置或关键字参数。

### 分配标签

为了简化设置上下文变量的标签创建，Django 提供了一个辅助函数`assignment_tag`。这个函数的工作方式与`simple_tag()`相同，只是它将标签的结果存储在指定的上下文变量中，而不是直接输出它。因此，我们之前的`current_time`函数可以这样编写：

```py
@register.assignment_tag 
def get_current_time(format_string): 
    return datetime.datetime.now().strftime(format_string) 

```

然后，你可以使用`as`参数将结果存储在模板变量中，并在适当的位置输出它：

```py
{% get_current_time "%Y-%m-%d %I:%M %p" as the_time %} 
<p>The time is {{ the_time }}.</p> 

```

# 高级自定义模板标签

有时，创建自定义模板标签的基本功能不够。别担心，Django 让你完全访问所需的内部部分，从头开始构建模板标签。

## 快速概述

模板系统以两步过程工作：编译和渲染。要定义自定义模板标签，您需要指定编译如何工作以及渲染如何工作。当 Django 编译模板时，它将原始模板文本分割为节点。每个节点都是`django.template.Node`的一个实例，并且具有`render()`方法。编译的模板就是`Node`对象的列表。

当您在编译的模板对象上调用`render()`时，模板会在其节点列表中的每个`Node`上调用`render()`，并提供给定的上下文。结果都被连接在一起形成模板的输出。因此，要定义一个自定义模板标签，您需要指定原始模板标签如何转换为`Node`（编译函数），以及节点的`render()`方法的作用。

## 编写编译函数

对于模板解析器遇到的每个模板标签，它都会调用一个 Python 函数，该函数具有标签内容和解析器对象本身。此函数负责根据标签的内容返回一个基于`Node`的实例。例如，让我们编写一个我们简单模板标签`{% current_time %}`的完整实现，它显示当前日期/时间，根据标签中给定的参数以`strftime()`语法格式化。在任何其他事情之前，决定标签语法是一个好主意。在我们的情况下，让我们说标签应该像这样使用：

```py
<p>The time is {% current_time "%Y-%m-%d %I:%M %p" %}.</p> 

```

此函数的解析器应该抓取参数并创建一个`Node`对象：

```py
from django import template 

def do_current_time(parser, token): 
    try: 

      tag_name, format_string = token.split_contents() 

    except ValueError: 

      raise template.TemplateSyntaxError("%r tag requires a single  argument" % token.contents.split()[0]) 

   if not (format_string[0] == format_string[-1] and format_string[0]  in ('"', "'")): 
        raise template.TemplateSyntaxError("%r tag's argument should  be in quotes" % tag_name) 
   return CurrentTimeNode(format_string[1:-1]) 

```

**注意：**

+   `parser`是模板解析器对象。在这个例子中我们不需要它。

+   `token.contents`是标签的原始内容的字符串。在我们的例子中，它是`'current_time "%Y-%m-%d %I:%M %p"'`。

+   `token.split_contents()`方法将参数在空格上分开，同时保持引号括起的字符串在一起。更直接的`token.contents.split()`不会那么健壮，因为它会简单地在所有空格上分割，包括引号括起的字符串中的空格。始终使用`token.split_contents()`是一个好主意。

+   此函数负责为任何语法错误引发`django.template.TemplateSyntaxError`，并提供有用的消息。

+   `TemplateSyntaxError`异常使用`tag_name`变量。不要在错误消息中硬编码标签的名称，因为这会将标签的名称与您的函数耦合在一起。`token.contents.split()[0]`将始终是您的标签的名称-即使标签没有参数。

+   该函数返回一个`CurrentTimeNode`，其中包含有关此标签的所有节点需要知道的信息。在这种情况下，它只传递参数`"%Y-%m-%d %I:%M %p"`。模板标签中的前导和尾随引号在`format_string[1:-1]`中被移除。

+   解析是非常低级的。Django 开发人员尝试使用诸如 EBNF 语法之类的技术在此解析系统之上编写小型框架，但这些实验使模板引擎变得太慢。它是低级的，因为这是最快的。

## 编写渲染器

编写自定义标签的第二步是定义一个具有`render()`方法的`Node`子类。继续上面的例子，我们需要定义`CurrentTimeNode`：

```py
import datetime 
from django import template 

class CurrentTimeNode(template.Node): 
    def __init__(self, format_string): 
        self.format_string = format_string 

    def render(self, context): 
        return datetime.datetime.now().strftime(self.format_string) 

```

**注意：**

+   `__init__()`从`do_current_time()`获取`format_string`。始终通过`__init__()`向`Node`传递任何选项/参数/参数。

+   `render()`方法是实际工作发生的地方。

+   `render()`通常应该在生产环境中静默失败，特别是在`DEBUG`和`TEMPLATE_DEBUG`为`False`的情况下。然而，在某些情况下，特别是如果`TEMPLATE_DEBUG`为`True`，此方法可能会引发异常以便更容易进行调试。例如，如果几个核心标签接收到错误数量或类型的参数，它们会引发`django.template.TemplateSyntaxError`。

最终，编译和渲染的解耦导致了一个高效的模板系统，因为一个模板可以渲染多个上下文而不必多次解析。

## 自动转义注意事项

模板标签的输出**不会**自动通过自动转义过滤器运行。但是，在编写模板标签时，仍然有一些事项需要牢记。如果模板的`render()`函数将结果存储在上下文变量中（而不是以字符串返回结果），则应在适当时调用`mark_safe()`。最终呈现变量时，它将受到当时生效的自动转义设置的影响，因此需要将应该免受进一步转义的内容标记为这样。

此外，如果模板标签为执行某些子呈现创建新的上下文，请将自动转义属性设置为当前上下文的值。`Context`类的`__init__`方法接受一个名为`autoescape`的参数，您可以用于此目的。例如：

```py
from django.template import Context 

def render(self, context): 
    # ... 
    new_context = Context({'var': obj}, autoescape=context.autoescape) 
    # ... Do something with new_context ... 

```

这不是一个非常常见的情况，但如果您自己呈现模板，则会很有用。例如：

```py
def render(self, context): 
    t = context.template.engine.get_template('small_fragment.html') 
    return t.render(Context({'var': obj}, autoescape=context.autoescape)) 

```

如果在此示例中忽略了将当前`context.autoescape`值传递给我们的新`Context`，则结果将始终自动转义，这可能不是在模板标签用于内部时所期望的行为。

`{% autoescape off %}`块。

## 线程安全考虑

一旦解析了节点，就可以调用其`render`方法任意次数。由于 Django 有时在多线程环境中运行，单个节点可能会同时响应两个独立请求的不同上下文进行呈现。

因此，确保模板标签是线程安全的非常重要。为确保模板标签是线程安全的，不应在节点本身上存储状态信息。例如，Django 提供了内置的`cycle`模板标签，每次呈现时在给定字符串列表中循环：

```py
{% for o in some_list %} 
    <tr class="{% cycle 'row1' 'row2' %}> 
        ... 
    </tr> 
{% endfor %} 

```

`CycleNode`的一个天真的实现可能如下所示：

```py
import itertools 
from django import template 

class CycleNode(template.Node): 
    def __init__(self, cyclevars): 
        self.cycle_iter = itertools.cycle(cyclevars) 

    def render(self, context): 
        return next(self.cycle_iter) 

Thread 1 performs its first loop iteration, `CycleNode.render()` returns 'row1'Thread 2 performs its first loop iteration, `CycleNode.render()` returns 'row2'Thread 1 performs its second loop iteration, `CycleNode.render()` returns 'row1'Thread 2 performs its second loop iteration, `CycleNode.render()` returns 'row2'
```

CycleNode 正在迭代，但它是全局迭代的。就线程 1 和线程 2 而言，它总是返回相同的值。这显然不是我们想要的！

为了解决这个问题，Django 提供了一个`render_context`，它与当前正在呈现的模板的`context`相关联。`render_context`的行为类似于 Python 字典，并且应该用于在`render`方法的调用之间存储`Node`状态。让我们重构我们的`CycleNode`实现以使用`render_context`：

```py
class CycleNode(template.Node): 
    def __init__(self, cyclevars): 
        self.cyclevars = cyclevars 

    def render(self, context): 
        if self not in context.render_context: 
            context.render_context[self] =  itertools.cycle(self.cyclevars) 
        cycle_iter = context.render_context[self] 
        return next(cycle_iter) 

```

请注意，将全局信息存储为`Node`生命周期内不会更改的属性是完全安全的。

在`CycleNode`的情况下，`cyclevars`参数在`Node`实例化后不会改变，因此我们不需要将其放入`render_context`中。但是，特定于当前正在呈现的模板的状态信息，例如`CycleNode`的当前迭代，应存储在`render_context`中。

## 注册标签

最后，按照上面“编写自定义模板过滤器”的说明，使用模块的`Library`实例注册标签。例如：

```py
register.tag('current_time', do_current_time) 

```

`tag()`方法接受两个参数：

+   模板标签的名称-一个字符串。如果不写，将使用编译函数的名称。

+   编译函数-一个 Python 函数（而不是函数的名称作为字符串）。

与过滤器注册一样，也可以将其用作装饰器：

```py
@register.tag(name="current_time") 
def do_current_time(parser, token): 
    ... 

@register.tag 
def shout(parser, token): 
    ... 

```

如果省略`name`参数，就像上面的第二个示例一样，Django 将使用函数的名称作为标签名称。

## 将模板变量传递给标签

尽管可以使用`token.split_contents()`将任意数量的参数传递给模板标签，但这些参数都会被解包为字符串文字。为了将动态内容（模板变量）作为参数传递给模板标签，需要进行更多的工作。

虽然前面的示例已将当前时间格式化为字符串并返回字符串，但假设您想要传递来自对象的`DateTimeField`并使模板标签格式化该日期时间：

```py
<p>This post was last updated at {% format_time blog_entry.date_updated "%Y-%m-%d %I:%M %p" %}.</p> 

```

最初，`token.split_contents()`将返回三个值：

1.  标签名称`format_time`。

1.  字符串`'blog_entry.date_updated'`（不包括周围的引号）。

1.  格式化字符串`'"%Y-%m-%d %I:%M %p"'`。`split_contents()`的返回值将包括字符串字面量的前导和尾随引号。

现在您的标签应该开始看起来像这样：

```py
from django import template 

def do_format_time(parser, token): 
    try: 
        # split_contents() knows not to split quoted strings. 
        tag_name, date_to_be_formatted, format_string =    
        token.split_contents() 
    except ValueError: 
        raise template.TemplateSyntaxError("%r tag requires exactly  
          two arguments" % token.contents.split()[0]) 
    if not (format_string[0] == format_string[-1] and   
          format_string[0] in ('"', "'")): 
        raise template.TemplateSyntaxError("%r tag's argument should  
          be in quotes" % tag_name) 
    return FormatTimeNode(date_to_be_formatted, format_string[1:-1]) 

```

您还需要更改渲染器以检索`blog_entry`对象的`date_updated`属性的实际内容。这可以通过在`django.template`中使用`Variable()`类来实现。

要使用`Variable`类，只需使用要解析的变量的名称对其进行实例化，然后调用`variable.resolve(context)`。例如：

```py
class FormatTimeNode(template.Node): 
    def __init__(self, date_to_be_formatted, format_string): 
        self.date_to_be_formatted =   
          template.Variable(date_to_be_formatted) 
        self.format_string = format_string 

    def render(self, context): 
        try: 
            actual_date = self.date_to_be_formatted.resolve(context) 
            return actual_date.strftime(self.format_string) 
        except template.VariableDoesNotExist: 
            return '' 

```

如果无法在页面的当前上下文中解析传递给它的字符串，变量解析将抛出`VariableDoesNotExist`异常。

## 在上下文中设置一个变量

上述示例只是简单地输出一个值。通常，如果您的模板标签设置模板变量而不是输出值，那么它会更灵活。这样，模板作者可以重用模板标签创建的值。要在上下文中设置一个变量，只需在`render()`方法中对上下文对象进行字典赋值。这是一个更新后的`CurrentTimeNode`版本，它设置了一个模板变量`current_time`而不是输出它：

```py
import datetime 
from django import template 

class CurrentTimeNode2(template.Node): 
    def __init__(self, format_string): 
        self.format_string = format_string 
    def render(self, context): 
        context['current_time'] = 
 datetime.datetime.now().strftime(self.format_string)
 return ''

```

请注意，`render()`返回空字符串。`render()`应始终返回字符串输出。如果模板标签所做的只是设置一个变量，`render()`应返回空字符串。以下是如何使用标签的新版本：

```py
{% current_time "%Y-%M-%d %I:%M %p" %} 
<p>The time is {{ current_time }}.</p> 

```

### 上下文中的变量范围

上下文中设置的任何变量只能在分配它的模板的相同`block`中使用。这种行为是有意的；它为变量提供了一个作用域，使它们不会与其他块中的上下文发生冲突。

但是，`CurrentTimeNode2`存在一个问题：变量名`current_time`是硬编码的。这意味着您需要确保您的模板不使用

`{{ current_time }}`在其他任何地方，因为`{% current_time %}`将盲目地覆盖该变量的值。

更清晰的解决方案是让模板标签指定输出变量的名称，如下所示：

```py
{% current_time "%Y-%M-%d %I:%M %p" as my_current_time %} 
<p>The current time is {{ my_current_time }}.</p> 

```

为此，您需要重构编译函数和`Node`类，如下所示：

```py
import re 

class CurrentTimeNode3(template.Node): 
    def __init__(self, format_string, var_name): 
        self.format_string = format_string 
        self.var_name = var_name 
    def render(self, context): 
        context[self.var_name] =    
          datetime.datetime.now().strftime(self.format_string) 
        return '' 

def do_current_time(parser, token): 
    # This version uses a regular expression to parse tag contents. 
    try: 
        # Splitting by None == splitting by spaces. 
        tag_name, arg = token.contents.split(None, 1) 
    except ValueError: 
        raise template.TemplateSyntaxError("%r tag requires arguments"    
          % token.contents.split()[0]) 
    m = re.search(r'(.*?) as (\w+)', arg) 
    if not m: 
        raise template.TemplateSyntaxError
          ("%r tag had invalid arguments"% tag_name) 
    format_string, var_name = m.groups() 
    if not (format_string[0] == format_string[-1] and format_string[0]   
       in ('"', "'")): 
        raise template.TemplateSyntaxError("%r tag's argument should be  
            in quotes" % tag_name) 
    return CurrentTimeNode3(format_string[1:-1], var_name) 

```

这里的区别在于`do_current_time()`获取格式字符串和变量名，并将两者都传递给`CurrentTimeNode3`。最后，如果您只需要为自定义上下文更新模板标签使用简单的语法，您可能希望考虑使用我们上面介绍的赋值标签快捷方式。

## 解析直到另一个块标签

模板标签可以协同工作。例如，标准的`{% comment %}`标签隐藏直到`{% endcomment %}`。要创建这样一个模板标签，可以在编译函数中使用`parser.parse()`。以下是一个简化的示例

`{% comment %}`标签可能被实现：

```py
def do_comment(parser, token): 
    nodelist = parser.parse(('endcomment',)) 
    parser.delete_first_token() 
    return CommentNode() 

class CommentNode(template.Node): 
    def render(self, context): 
        return '' 

```

### 注意

`{% comment %}`的实际实现略有不同，它允许在`{% comment %}`和`{% endcomment %}`之间出现损坏的模板标签。它通过调用`parser.skip_past('endcomment')`而不是`parser.parse(('endcomment',))`，然后是`parser.delete_first_token()`来实现这一点，从而避免生成节点列表。

`parser.parse()`接受一个块标签名称的元组''直到解析''。它返回`django.template.NodeList`的一个实例，这是解析器在遇到元组中命名的任何标签之前''遇到''的所有`Node`对象的列表。在上面的示例中的"`nodelist = parser.parse(('endcomment',))`"中，`nodelist`是`{% comment %}`和`{% endcomment %}`之间的所有节点的列表，不包括

`{% comment %}`和`{% endcomment %}`本身。

在调用`parser.parse()`之后，解析器尚未“消耗”

`{% endcomment %}`标签，所以代码需要显式调用`parser.delete_first_token()`。`CommentNode.render()`只是返回一个空字符串。`{% comment %}`和`{% endcomment %}`之间的任何内容都会被忽略。

## 解析直到另一个块标签，并保存内容

在前面的例子中，`do_comment()`丢弃了`{% comment %}`和`{% endcomment %}`之间的所有内容

`{% comment %}`和`{% endcomment %}`。而不是这样做，可以对块标签之间的代码进行操作。例如，这里有一个自定义模板标签`{% upper %}`，它会将其自身和之间的所有内容都大写

`{% endupper %}`。用法：

```py
{% upper %}This will appear in uppercase, {{ your_name }}.{% endupper %} 

```

与前面的例子一样，我们将使用`parser.parse()`。但是这次，我们将将结果的`nodelist`传递给`Node`：

```py
def do_upper(parser, token): 
    nodelist = parser.parse(('endupper',)) 
    parser.delete_first_token() 
    return UpperNode(nodelist) 

class UpperNode(template.Node): 
    def __init__(self, nodelist): 
        self.nodelist = nodelist 
    def render(self, context): 
        output = self.nodelist.render(context) 
        return output.upper() 

```

这里唯一的新概念是`UpperNode.render()`中的`self.nodelist.render(context)`。有关复杂渲染的更多示例，请参阅`django/template/defaulttags.py`中的`{% for %}`和`django/template/smartif.py`中的`{% if %}`的源代码。

# 接下来是什么

继续本节关于高级主题的主题，下一章涵盖了 Django 模型的高级用法。


# 第九章：高级模型

在第四章: 
    name = models.CharField(max_length=30) 
    address = models.CharField(max_length=50) 
    city = models.CharField(max_length=60) 
    state_province = models.CharField(max_length=30) 
    country = models.CharField(max_length=50) 
    website = models.URLField() 

    def __str__(self): 
        return self.name 

class Author(models.Model): 
    first_name = models.CharField(max_length=30) 
    last_name = models.CharField(max_length=40) 
    email = models.EmailField() 

    def __str__(self): 
        return '%s %s' % (self.first_name, self.last_name) 

class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField(Author) 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField() 

    def __str__(self): 
        return self.title 

```

正如我们在第四章 
>>> b.title 
'The Django Book' 

```

但我们之前没有提到的一件事是，相关对象-表达为`ForeignKey`或`ManyToManyField`的字段-的行为略有不同。

## 访问 ForeignKey 值

当您访问一个`ForeignKey`字段时，您将获得相关的模型对象。例如：

```py
>>> b = Book.objects.get(id=50) 
>>> b.publisher 
<Publisher: Apress Publishing> 
>>> b.publisher.website 
'http://www.apress.com/' 

```

对于`ForeignKey`字段，它也可以反向工作，但由于关系的非对称性，它略有不同。要获取给定出版商的书籍列表，请使用“publisher.book_set.all（）”，如下所示：

```py
>>> p = Publisher.objects.get(name='Apress Publishing') 
>>> p.book_set.all() 
[<Book: The Django Book>, <Book: Dive Into Python>, ...] 

```

在幕后，`book_set`只是一个`QuerySet`（如第四章 
>>> p.book_set.filter(title__icontains='django') 
[<Book: The Django Book>, <Book: Pro Django>] 

```

属性名称`book_set`是通过将小写模型名称附加到`_set`而生成的。

## 访问多对多值

多对多值的工作方式与外键值相似，只是我们处理的是`QuerySet`值而不是模型实例。例如，以下是如何查看书籍的作者：

```py
>>> b = Book.objects.get(id=50) 
>>> b.authors.all() 
[<Author: Adrian Holovaty>, <Author: Jacob Kaplan-Moss>] 
>>> b.authors.filter(first_name='Adrian') 
[<Author: Adrian Holovaty>] 
>>> b.authors.filter(first_name='Adam') 
[] 

```

它也可以反向工作。要查看作者的所有书籍，请使用`author.book_set`，如下所示：

```py
>>> a = Author.objects.get(first_name='Adrian', last_name='Holovaty') 
>>> a.book_set.all() 
[<Book: The Django Book>, <Book: Adrian's Other Book>] 

```

在这里，与`ForeignKey`字段一样，`book_set`属性名称是通过将小写模型名称附加到`_set`而生成的。

# 管理器

在语句“Book.objects.all（）”中，`objects`是一个特殊的属性，通过它您可以查询您的数据库。在第四章: 
    def title_count(self, keyword): 
        return self.filter(title__icontains=keyword).count() 

class Book(models.Model): 
    title = models.CharField(max_length=100) 
    authors = models.ManyToManyField(Author) 
    publisher = models.ForeignKey(Publisher) 
    publication_date = models.DateField() 
    num_pages = models.IntegerField(blank=True, null=True) 
    objects = BookManager() 

    def __str__(self): 
        return self.title 

```

以下是有关代码的一些说明：

+   我们创建了一个扩展了`django.db.models.Manager`的`BookManager`类。这有一个名为“title_count（）”的方法，用于进行计算。请注意，该方法使用“self.filter（）”，其中`self`是指管理器本身。

+   我们将“BookManager（）”分配给模型上的`objects`属性。这会替换模型的默认管理器，称为`objects`，如果您没有指定自定义管理器，则会自动创建。我们将其称为`objects`而不是其他名称，以便与自动创建的管理器保持一致。

有了这个管理器，我们现在可以这样做：

```py
>>> Book.objects.title_count('django') 
4 
>>> Book.objects.title_count('python') 
18 

```

显然，这只是一个例子-如果您在交互式提示符中键入此内容，您可能会得到不同的返回值。

为什么我们想要添加一个像 `title_count()` 这样的方法？为了封装常用的执行查询，这样我们就不必重复代码。

## 修改初始管理器查询集

管理器的基本 `QuerySet` 返回系统中的所有对象。例如，`Book.objects.all()` 返回书数据库中的所有书籍。你可以通过覆盖 `Manager.get_queryset()` 方法来覆盖管理器的基本 `QuerySet`。`get_queryset()` 应该返回一个具有你需要的属性的 `QuerySet`。

例如，以下模型有两个管理器-一个返回所有对象，一个只返回罗尔德·达尔的书。

```py
from django.db import models 

# First, define the Manager subclass. 
class DahlBookManager(models.Manager): 
    def get_queryset(self): 
        return super(DahlBookManager, self).get_queryset().filter(author='Roald Dahl') 

# Then hook it into the Book model explicitly. 
class Book(models.Model): 
    title = models.CharField(max_length=100) 
    author = models.CharField(max_length=50) 
    # ... 

    objects = models.Manager() # The default manager. 
    dahl_objects = DahlBookManager() # The Dahl-specific manager. 

```

使用这个示例模型，`Book.objects.all()` 将返回数据库中的所有书籍，但 `Book.dahl_objects.all()` 只会返回罗尔德·达尔写的书。请注意，我们明确将 `objects` 设置为一个普通的 `Manager` 实例，因为如果我们没有这样做，唯一可用的管理器将是 `dahl_objects`。当然，因为 `get_queryset()` 返回一个 `QuerySet` 对象，你可以在其上使用 `filter()`、`exclude()` 和所有其他 `QuerySet` 方法。因此，这些语句都是合法的：

```py
Book.dahl_objects.all() 
Book.dahl_objects.filter(title='Matilda') 
Book.dahl_objects.count() 

```

这个例子还指出了另一个有趣的技术：在同一个模型上使用多个管理器。你可以将多个 `Manager()` 实例附加到一个模型上。这是定义模型的常见过滤器的简单方法。例如：

```py
class MaleManager(models.Manager): 
    def get_queryset(self): 
        return super(MaleManager, self).get_queryset().filter(sex='M') 

class FemaleManager(models.Manager): 
    def get_queryset(self): 
        return super(FemaleManager, self).get_queryset().filter(sex='F') 

class Person(models.Model): 
    first_name = models.CharField(max_length=50) 
    last_name = models.CharField(max_length=50) 
    sex = models.CharField(max_length=1,  
                           choices=( 
                                    ('M', 'Male'),   
                                    ('F', 'Female') 
                           ) 
                           ) 
    people = models.Manager() 
    men = MaleManager() 
    women = FemaleManager() 

```

这个例子允许你请求 `Person.men.all()`, `Person.women.all()`, 和 `Person.people.all()`, 产生可预测的结果。如果你使用自定义的 `Manager` 对象，请注意 Django 遇到的第一个 `Manager`（按照模型中定义的顺序）具有特殊状态。Django 将在类中定义的第一个 `Manager` 解释为默认的 `Manager`，并且 Django 的几个部分（尽管不包括管理应用程序）将专门使用该 `Manager` 来管理该模型。

因此，在选择默认管理器时要小心，以避免覆盖 `get_queryset()` 导致无法检索到你想要处理的对象的情况。

# 模型方法

在模型上定义自定义方法，为对象添加自定义的行级功能。而管理器旨在对整个表执行操作，模型方法应该作用于特定的模型实例。这是将业务逻辑集中在一个地方-模型中的一个有价值的技术。

举例是最容易解释这个问题的方法。下面是一个带有一些自定义方法的模型：

```py
from django.db import models 

class Person(models.Model): 
    first_name = models.CharField(max_length=50) 
    last_name = models.CharField(max_length=50) 
    birth_date = models.DateField() 

    def baby_boomer_status(self): 
        # Returns the person's baby-boomer status. 
        import datetime 
        if self.birth_date < datetime.date(1945, 8, 1): 
            return "Pre-boomer" 
        elif self.birth_date < datetime.date(1965, 1, 1): 
            return "Baby boomer" 
        else: 
            return "Post-boomer" 

    def _get_full_name(self): 
        # Returns the person's full name." 
        return '%s %s' % (self.first_name, self.last_name) 
    full_name = property(_get_full_name) 

```

附录 A 中的模型实例引用，*模型定义参考*，列出了自动赋予每个模型的完整方法列表。你可以覆盖大部分方法（见下文），但有一些你几乎总是想要定义的：

+   `__str__()`: 一个 Python *魔术方法*，返回任何对象的 Unicode 表示。这是 Python 和 Django 在需要将模型实例强制转换并显示为普通字符串时使用的方法。特别是，当你在交互式控制台或管理界面中显示对象时，就会发生这种情况。

+   你总是希望定义这个方法；默认情况下并不是很有用。

+   `get_absolute_url()`: 这告诉 Django 如何计算对象的 URL。Django 在其管理界面中使用这个方法，以及任何时候它需要为对象计算 URL。

任何具有唯一标识 URL 的对象都应该定义这个方法。

## 覆盖预定义的模型方法

还有一组模型方法，封装了一堆你想要自定义的数据库行为。特别是，你经常会想要改变 `save()` 和 `delete()` 的工作方式。你可以自由地覆盖这些方法（以及任何其他模型方法）来改变行为。覆盖内置方法的一个经典用例是，如果你想要在保存对象时发生某些事情。例如，（参见 `save()` 以获取它接受的参数的文档）：

```py
from django.db import models 

class Blog(models.Model): 
    name = models.CharField(max_length=100) 
    tagline = models.TextField() 

    def save(self, *args, **kwargs): 
        do_something() 
        super(Blog, self).save(*args, **kwargs) # Call the "real" save() method. 
        do_something_else() 

```

你也可以阻止保存：

```py
from django.db import models 

class Blog(models.Model): 
    name = models.CharField(max_length=100) 
    tagline = models.TextField() 

    def save(self, *args, **kwargs): 
        if self.name == "Yoko Ono's blog": 
            return # Yoko shall never have her own blog! 
        else: 
            super(Blog, self).save(*args, **kwargs) # Call the "real" save() method. 

```

重要的是要记住调用超类方法-也就是`super(Blog, self).save(*args, **kwargs)`，以确保对象仍然被保存到数据库中。如果忘记调用超类方法，就不会发生默认行为，数据库也不会被触及。

还要确保通过可以传递给模型方法的参数-这就是`*args, **kwargs`的作用。Django 会不时地扩展内置模型方法的功能，添加新的参数。如果在方法定义中使用`*args, **kwargs`，则可以确保在添加这些参数时，您的代码将自动支持这些参数。

# 执行原始 SQL 查询

当模型查询 API 不够用时，可以退而使用原始 SQL。Django 提供了两种执行原始 SQL 查询的方法：您可以使用`Manager.raw()`执行原始查询并返回模型实例，或者完全避开模型层并直接执行自定义 SQL。

### 注意

每次使用原始 SQL 时，都应该非常小心。您应该使用`params`正确转义用户可以控制的任何参数，以防止 SQL 注入攻击。

# 执行原始 SQL 查询

`raw()`管理器方法可用于执行返回模型实例的原始 SQL 查询：

```py
Manager.raw(raw_query, params=None, translations=None)
```

此方法接受原始 SQL 查询，执行它，并返回一个`django.db.models.query.RawQuerySet`实例。这个`RawQuerySet`实例可以像普通的`QuerySet`一样进行迭代，以提供对象实例。这最好用一个例子来说明。假设您有以下模型：

```py
class Person(models.Model): 
    first_name = models.CharField(...) 
    last_name = models.CharField(...) 
    birth_date = models.DateField(...) 

```

然后，您可以执行自定义的 SQL，就像这样：

```py
>>> for p in Person.objects.raw('SELECT * FROM myapp_person'): 
...     print(p) 
John Smith 
Jane Jones 

```

当然，这个例子并不是很令人兴奋-它与运行`Person.objects.all()`完全相同。但是，`raw()`有很多其他选项，使其非常强大。

## 模型表名称

在前面的例子中，`Person`表的名称是从哪里来的？默认情况下，Django 通过将模型的应用程序标签（您在`manage.py startapp`中使用的名称）与模型的类名结合起来，它们之间用下划线连接来确定数据库表名称。在我们的例子中，假设`Person`模型位于名为`myapp`的应用程序中，因此其表将是`myapp_person`。

有关`db_table`选项的更多详细信息，请查看文档，该选项还允许您手动设置数据库表名称。

### 注意

对传递给`raw()`的 SQL 语句不进行检查。Django 期望该语句将从数据库返回一组行，但不执行任何强制性操作。如果查询不返回行，将导致（可能是晦涩的）错误。

## 将查询字段映射到模型字段

`raw()`会自动将查询中的字段映射到模型中的字段。查询中字段的顺序并不重要。换句话说，以下两个查询的工作方式是相同的：

```py
>>> Person.objects.raw('SELECT id, first_name, last_name, birth_date FROM myapp_person') 
... 
>>> Person.objects.raw('SELECT last_name, birth_date, first_name, id FROM myapp_person') 
... 

```

匹配是通过名称完成的。这意味着您可以使用 SQL 的`AS`子句将查询中的字段映射到模型字段。因此，如果您有其他表中有`Person`数据，您可以轻松地将其映射到`Person`实例中：

```py
>>> Person.objects.raw('''SELECT first AS first_name, 
...                              last AS last_name, 
...                              bd AS birth_date, 
...                              pk AS id, 
...                       FROM some_other_table''') 

```

只要名称匹配，模型实例就会被正确创建。或者，您可以使用`raw()`的`translations`参数将查询中的字段映射到模型字段。这是一个将查询中的字段名称映射到模型字段名称的字典。例如，前面的查询也可以这样写：

```py
>>> name_map = {'first': 'first_name', 'last': 'last_name', 'bd': 'birth_date', 'pk': 'id'} 
>>> Person.objects.raw('SELECT * FROM some_other_table', translations=name_map) 

```

## 索引查找

`raw()`支持索引，因此如果只需要第一个结果，可以这样写：

```py
>>> first_person = Person.objects.raw('SELECT * FROM myapp_person')[0] 

```

但是，索引和切片不是在数据库级别执行的。如果数据库中有大量的`Person`对象，限制 SQL 级别的查询效率更高：

```py
>>> first_person = Person.objects.raw('SELECT * FROM myapp_person LIMIT 1')[0] 

```

## 延迟加载模型字段

字段也可以被省略：

```py
>>> people = Person.objects.raw('SELECT id, first_name FROM myapp_person') 

```

此查询返回的`Person`对象将是延迟加载的模型实例（参见`defer()`）。这意味着从查询中省略的字段将按需加载。例如：

```py
>>> for p in Person.objects.raw('SELECT id, first_name FROM myapp_person'): 
...     print(p.first_name, # This will be retrieved by the original query 
...           p.last_name) # This will be retrieved on demand 
... 
John Smith 
Jane Jones 

```

从外观上看，这似乎是查询已检索了名字和姓氏。但是，这个例子实际上发出了 3 个查询。只有第一个名字是由`raw()`查询检索到的-当打印它们时，姓氏是按需检索的。

只有一个字段是不能省略的-主键字段。Django 使用主键来标识模型实例，因此它必须始终包含在原始查询中。如果您忘记包括主键，将会引发`InvalidQuery`异常。

## 添加注释

您还可以执行包含模型上未定义的字段的查询。例如，我们可以使用 PostgreSQL 的`age()`函数来获取一个人的年龄列表，其年龄由数据库计算得出：

```py
>>> people = Person.objects.raw('SELECT *, age(birth_date) AS age FROM myapp_person') 
>>> for p in people: 
...     print("%s is %s." % (p.first_name, p.age)) 
John is 37\. 
Jane is 42\. 
... 

```

## 将参数传递给原始查询

如果您需要执行参数化查询，可以将`params`参数传递给`raw()`：

```py
>>> lname = 'Doe' 
>>> Person.objects.raw('SELECT * FROM myapp_person WHERE last_name = %s', [lname]) 

```

`params`是参数的列表或字典。您将在查询字符串中使用`%s`占位符来表示列表，或者使用`%(key)s`占位符来表示字典（其中`key`当然会被字典键替换），而不管您的数据库引擎如何。这些占位符将被`params`参数中的参数替换。

### 注意

**不要在原始查询上使用字符串格式化！**

很容易将前面的查询写成：

`>>> query = 'SELECT * FROM myapp_person WHERE last_name = %s' % lname` `Person.objects.raw(query)`

**不要这样做。**

使用`params`参数完全保护您免受 SQL 注入攻击，这是一种常见的攻击方式，攻击者会将任意 SQL 注入到您的数据库中。如果您使用字符串插值，迟早会成为 SQL 注入的受害者。只要记住始终使用`params`参数，您就会得到保护。

# 直接执行自定义 SQL

有时甚至`Manager.raw()`还不够：您可能需要执行与模型不太匹配的查询，或者直接执行`UPDATE`、`INSERT`或`DELETE`查询。在这些情况下，您可以始终直接访问数据库，完全绕过模型层。对象`django.db.connection`表示默认数据库连接。要使用数据库连接，调用`connection.cursor()`以获取游标对象。然后，调用`cursor.execute(sql, [params])`来执行 SQL，`cursor.fetchone()`或`cursor.fetchall()`来返回结果行。例如：

```py
from django.db import connection 

def my_custom_sql(self): 
    cursor = connection.cursor() 
    cursor.execute("UPDATE bar SET foo = 1 WHERE baz = %s", [self.baz]) 
    cursor.execute("SELECT foo FROM bar WHERE baz = %s", [self.baz]) 
    row = cursor.fetchone() 

    return row 

```

请注意，如果您想在查询中包含百分号，您必须在传递参数的情况下将其加倍：

```py
cursor.execute("SELECT foo FROM bar WHERE baz = '30%'") 
cursor.execute("SELECT foo FROM bar WHERE baz = '30%%' AND  
  id = %s", [self.id]) 

```

如果您使用多个数据库，可以使用`django.db.connections`来获取特定数据库的连接（和游标）。`django.db.connections`是一个类似字典的对象，允许您使用其别名检索特定连接：

```py
from django.db import connections 
cursor = connections['my_db_alias'].cursor() 
# Your code here... 

```

默认情况下，Python DB API 将返回结果而不带有它们的字段名称，这意味着您最终会得到一个值的`list`，而不是一个`dict`。以较小的性能成本，您可以通过类似以下的方式返回结果作为`dict`：

```py
def dictfetchall(cursor): 
    # Returns all rows from a cursor as a dict 
    desc = cursor.description 
    return [ 
        dict(zip([col[0] for col in desc], row)) 
        for row in cursor.fetchall() 
    ] 

```

以下是两者之间差异的示例：

```py
>>> cursor.execute("SELECT id, parent_id FROM test LIMIT 2"); 
>>> cursor.fetchall() 
((54360982L, None), (54360880L, None)) 

>>> cursor.execute("SELECT id, parent_id FROM test LIMIT 2"); 
>>> dictfetchall(cursor) 
[{'parent_id': None, 'id': 54360982L}, {'parent_id': None, 'id': 54360880L}] 

```

## 连接和游标

`connection`和`cursor`大多实现了 PEP 249 中描述的标准 Python DB-API（有关更多信息，请访问[`www.python.org/dev/peps/pep-0249`](https://www.python.org/dev/peps/pep-0249)），除了在处理事务时。如果您不熟悉 Python DB-API，请注意`cursor.execute()`中的 SQL 语句使用占位符"`%s`"，而不是直接在 SQL 中添加参数。

如果您使用这种技术，底层数据库库将根据需要自动转义参数。还要注意，Django 期望"`%s`"占位符，而不是 SQLite Python 绑定使用的`?`占位符。这是为了一致性和健全性。使用游标作为上下文管理器：

```py
with connection.cursor() as c: 
    c.execute(...) 

```

等同于：

```py
c = connection.cursor() 
try: 
    c.execute(...) 
finally: 
    c.close() 

```

## 添加额外的 Manager 方法

添加额外的`Manager`方法是向模型添加表级功能的首选方式。（对于行级功能，即对模型对象的单个实例进行操作的函数，请使用模型方法，而不是自定义的`Manager`方法。）自定义的`Manager`方法可以返回任何你想要的东西。它不一定要返回一个`QuerySet`。

例如，这个自定义的`Manager`提供了一个名为`with_counts()`的方法，它返回所有`OpinionPoll`对象的列表，每个对象都有一个额外的`num_responses`属性，这是聚合查询的结果。

```py
from django.db import models 

class PollManager(models.Manager): 
    def with_counts(self): 
        from django.db import connection 
        cursor = connection.cursor() 
        cursor.execute(""" 
            SELECT p.id, p.question, p.poll_date, COUNT(*) 
            FROM polls_opinionpoll p, polls_response r 
            WHERE p.id = r.poll_id 
            GROUP BY p.id, p.question, p.poll_date 
            ORDER BY p.poll_date DESC""") 
        result_list = [] 
        for row in cursor.fetchall(): 
            p = self.model(id=row[0], question=row[1], poll_date=row[2]) 
            p.num_responses = row[3] 
            result_list.append(p) 
        return result_list 

class OpinionPoll(models.Model): 
    question = models.CharField(max_length=200) 
    poll_date = models.DateField() 
    objects = PollManager() 

class Response(models.Model): 
    poll = models.ForeignKey(OpinionPoll) 
    person_name = models.CharField(max_length=50) 
    response = models.TextField() 

```

使用这个例子，您可以使用`OpinionPoll.objects.with_counts()`来返回带有`num_responses`属性的`OpinionPoll`对象列表。关于这个例子的另一点要注意的是，`Manager`方法可以访问`self.model`来获取它们所附加的模型类。

# 接下来呢？

在下一章中，我们将向您展示 Django 的通用视图框架，它可以帮助您节省时间，构建遵循常见模式的网站。
