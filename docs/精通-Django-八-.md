# 精通 Django（八）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 C. 通用视图参考

第十章 *通用视图*介绍了通用视图，但略去了一些细节。本附录描述了每个通用视图以及每个视图可以采用的选项摘要。在尝试理解接下来的参考资料之前，请务必阅读第十章 *通用视图*。您可能希望参考该章中定义的`Book`、`Publisher`和`Author`对象；后面的示例使用这些模型。如果您想深入了解更高级的通用视图主题（例如在基于类的视图中使用混合），请参阅 Django 项目网站[`docs.djangoproject.com/en/1.8/topics/class-based-views/`](https://docs.djangoproject.com/en/1.8/topics/class-based-views/)。

# 通用视图的常见参数

这些视图大多需要大量的参数，可以改变通用视图的行为。这些参数中的许多在多个视图中起着相同的作用。*表 C.1*描述了每个这些常见参数；每当您在通用视图的参数列表中看到这些参数时，它将按照表中描述的方式工作。 

| **参数** | **描述** |
| --- | --- |
| `allow_empty` | 一个布尔值，指定是否在没有可用对象时显示页面。如果这是`False`并且没有可用对象，则视图将引发 404 错误，而不是显示空页面。默认情况下，这是`True`。 |
| `context_processors` | 要应用于视图模板的附加模板上下文处理器（除了默认值）的列表。有关模板上下文处理器的信息，请参见第九章 *高级模型*。 |
| `extra_context` | 要添加到模板上下文中的值的字典。默认情况下，这是一个空字典。如果字典中的值是可调用的，则通用视图将在呈现模板之前调用它。 |
| `mimetype` | 用于生成文档的 MIME 类型。如果您没有更改它，默认为`DEFAULT_MIME_TYPE`设置的值，即`text/html`。 |
| `queryset` | 从中读取对象的`QuerySet`（例如`Author.objects.all()`）。有关`QuerySet`对象的更多信息，请参见附录 B。大多数通用视图都需要此参数。 |
| `template_loader` | 加载模板时要使用的模板加载程序。默认情况下是`django.template.loader`。有关模板加载程序的信息，请参见第九章 *高级模型*。 |
| `template_name` | 用于呈现页面的模板的完整名称。这使您可以覆盖从`QuerySet`派生的默认模板名称。 |
| `template_object_name` | 模板上下文中要使用的模板变量的名称。默认情况下，这是`'object'`。列出多个对象的视图（即`object_list`视图和各种日期对象视图）将在此参数的值后附加`'_list'`。 |

表 C.1：常见的通用视图参数

# 简单的通用视图

模块`django.views.generic.base`包含处理一些常见情况的简单视图：在不需要视图逻辑时呈现模板和发出重定向。

## 呈现模板-TemplateView

此视图呈现给定模板，传递一个包含在 URL 中捕获的关键字参数的上下文。

**示例：**

给定以下 URLconf：

```py
from django.conf.urls import url 

    from myapp.views import HomePageView 

    urlpatterns = [ 
        url(r'^$', HomePageView.as_view(), name='home'), 
    ] 

```

和一个示例`views.py`：

```py
from django.views.generic.base import TemplateView 
from articles.models import Article 

class HomePageView(TemplateView): 

    template_name = "home.html" 

    def get_context_data(self, **kwargs): 
        context = super(HomePageView, self).get_context_data(**kwargs) 
        context['latest_articles'] = Article.objects.all()[:5] 
        return context 

```

对`/`的请求将呈现模板`home.html`，返回一个包含前 5 篇文章列表的上下文。

## 重定向到另一个 URL

`django.views.generic.base.RedirectView()`将重定向到给定的 URL。

给定的 URL 可能包含类似字典的字符串格式，它将根据在 URL 中捕获的参数进行插值。因为关键字插值*总是*会执行（即使没有传入参数），所以 URL 中的任何"`%`"字符必须写为"`%%`"，以便 Python 将它们转换为输出的单个百分号。

如果给定的 URL 为`None`，Django 将返回一个`HttpResponseGone`（410）。

**示例** **views.py**：

```py
from django.shortcuts import get_object_or_404 

from django.views.generic.base import RedirectView 

from articles.models import Article 

class ArticleCounterRedirectView(RedirectView): 

    permanent = False 
    query_string = True 
    pattern_name = 'article-detail' 

    def get_redirect_url(self, *args, **kwargs): 
        article = get_object_or_404(Article, pk=kwargs['pk']) 
        article.update_counter() 
        return super(ArticleCounterRedirectView,  
                     self).get_redirect_url(*args, **kwargs) 

```

**示例 urls.py**：

```py
from django.conf.urls import url 
from django.views.generic.base import RedirectView 

from article.views import ArticleCounterRedirectView, ArticleDetail 

urlpatterns = [ 
    url(r'^counter/(?P<pk>[0-9]+)/$',  
        ArticleCounterRedirectView.as_view(),  
        name='article-counter'), 
    url(r'^details/(?P<pk>[0-9]+)/$',  
        ArticleDetail.as_view(), 
        name='article-detail'), 
    url(r'^go-to-django/$',  
        RedirectView.as_view(url='http://djangoproject.com'),  
        name='go-to-django'), 
] 

```

### 属性

#### url

要重定向的 URL，作为字符串。或者`None`以引发 410（已消失）HTTP 错误。

#### pattern_name

要重定向到的 URL 模式的名称。将使用与此视图传递的相同的`*args`和`**kwargs`进行反转。

#### 永久

重定向是否应该是永久的。这里唯一的区别是返回的 HTTP 状态代码。如果为`True`，则重定向将使用状态码 301。如果为`False`，则重定向将使用状态码 302。默认情况下，`permanent`为`True`。

#### query_string

是否将 GET 查询字符串传递到新位置。如果为`True`，则查询字符串将附加到 URL。如果为`False`，则查询字符串将被丢弃。默认情况下，`query_string`为`False`。

### 方法

`get_redirect_url(*args, **kwargs)`构造重定向的目标 URL。

默认实现使用`url`作为起始字符串，并使用在 URL 中捕获的命名组执行`%`命名参数的扩展。

如果未设置`url`，`get_redirect_url()`将尝试使用在 URL 中捕获的内容（命名和未命名组都将被使用）来反转`pattern_name`。

如果由`query_string`请求，则还将查询字符串附加到生成的 URL。子类可以实现任何他们希望的行为，只要该方法返回一个准备好的重定向 URL 字符串。

# 列表/详细通用视图

列表/详细通用视图处理在一个视图中显示项目列表的常见情况，并在另一个视图中显示这些项目的单独详细视图。

## 对象列表

```py
django.views.generic.list.ListView 

```

使用此视图显示代表对象列表的页面。

**示例 views.py**：

```py
from django.views.generic.list import ListView 
from django.utils import timezone 

from articles.models import Article 

class ArticleListView(ListView): 

    model = Article 

    def get_context_data(self, **kwargs): 
        context = super(ArticleListView, self).get_context_data(**kwargs) 
        context['now'] = timezone.now() 
        return context 

```

**示例 myapp/urls.py**：

```py
from django.conf.urls import url 

from article.views import ArticleListView 

urlpatterns = [ 
    url(r'^$', ArticleListView.as_view(), name='article-list'), 
] 

```

**示例 myapp/article_list.html**：

```py
<h1>Articles</h1> 
<ul> 
{% for article in object_list %} 
    <li>{{ article.pub_date|date }}-{{ article.headline }}</li> 
{% empty %} 
    <li>No articles yet.</li> 
{% endfor %} 
</ul> 

```

## 详细视图

django.views.generic.detail.DetailView

此视图提供单个对象的详细视图。

**示例 myapp/views.py**：

```py
from django.views.generic.detail import DetailView 
from django.utils import timezone 

from articles.models import Article 

class ArticleDetailView(DetailView): 

    model = Article 

    def get_context_data(self, **kwargs): 
        context = super(ArticleDetailView,  
                        self).get_context_data(**kwargs) 
        context['now'] = timezone.now() 
        return context 

```

**示例 myapp/urls.py**：

```py
from django.conf.urls import url 

from article.views import ArticleDetailView 

urlpatterns = [ 
    url(r'^(?P<slug>[-_\w]+)/$',  
        ArticleDetailView.as_view(),  
        name='article-detail'), 
] 

```

**示例 myapp/article_detail.html**：

```py
<h1>{{ object.headline }}</h1> 
<p>{{ object.content }}</p> 
<p>Reporter: {{ object.reporter }}</p> 
<p>Published: {{ object.pub_date|date }}</p> 
<p>Date: {{ now|date }}</p> 

```

# 基于日期的通用视图

提供在`django.views.generic.dates`中的基于日期的通用视图，用于显示基于日期的数据的钻取页面。

## 存档索引视图

顶级索引页面显示最新的对象，按日期。除非将`allow_future`设置为`True`，否则不包括*未来*日期的对象。

**上下文**

除了`django.views.generic.list.MultipleObjectMixin`提供的上下文（通过`django.views.generic.dates.BaseDateListView`），模板的上下文将是：

+   `date_list`：包含根据`queryset`可用的所有年份的`DateQuerySet`对象，以降序表示为`datetime.datetime`对象

**注意**

+   使用默认的`context_object_name`为`latest`。

+   使用默认的`template_name_suffix`为`_archive`。

+   默认提供`date_list`按年份，但可以使用属性`date_list_period`更改为按月或日。这也适用于所有子类视图：

```py
Example myapp/urls.py: 
from django.conf.urls import url 
from django.views.generic.dates import ArchiveIndexView 

from myapp.models import Article 

urlpatterns = [ 
    url(r'^archive/$', 
        ArchiveIndexView.as_view(model=Article, date_field="pub_date"), 
        name="article_archive"), 
] 

```

**示例 myapp/article_archive.html**：

```py
<ul> 
    {% for article in latest %} 
        <li>{{ article.pub_date }}: {{ article.title }}</li> 
    {% endfor %} 
</ul> 

```

这将输出所有文章。

## YearArchiveView

年度存档页面显示给定年份中所有可用月份。除非将`allow_future`设置为`True`，否则不显示*未来*日期的对象。

**上下文**

除了`django.views.generic.list.MultipleObjectMixin`提供的上下文（通过`django.views.generic.dates.BaseDateListView`），模板的上下文将是：

+   `date_list`：包含根据`queryset`可用的所有月份的`DateQuerySet`对象，以升序表示为`datetime.datetime`对象

+   `year`：表示给定年份的`date`对象

+   `next_year`：表示下一年第一天的`date`对象，根据`allow_empty`和`allow_future`

+   `previous_year`：表示上一年第一天的`date`对象，根据`allow_empty`和`allow_future`

**注释**

+   使用默认的`template_name_suffix`为`_archive_year`

**示例 myapp/views.py**：

```py
from django.views.generic.dates import YearArchiveView 

from myapp.models import Article 

class ArticleYearArchiveView(YearArchiveView): 
    queryset = Article.objects.all() 
    date_field = "pub_date" 
    make_object_list = True 
    allow_future = True 

```

**示例 myapp/urls.py**：

```py
from django.conf.urls import url 

from myapp.views import ArticleYearArchiveView 

urlpatterns = [ 
    url(r'^(?P<year>[0-9]{4})/$', 
        ArticleYearArchiveView.as_view(), 
        name="article_year_archive"), 
] 

```

**示例 myapp/article_archive_year.html**：

```py
<ul> 
    {% for date in date_list %} 
        <li>{{ date|date }}</li> 
    {% endfor %} 
</ul> 
<div> 
    <h1>All Articles for {{ year|date:"Y" }}</h1> 
    {% for obj in object_list %} 
        <p> 
            {{ obj.title }}-{{ obj.pub_date|date:"F j, Y" }} 
        </p> 
    {% endfor %} 
</div> 

```

## 月存档视图

显示给定月份内所有对象的月度存档页面。具有*未来*日期的对象不会显示，除非您将`allow_future`设置为`True`。

**上下文**

除了`MultipleObjectMixin`（通过`BaseDateListView`）提供的上下文之外，模板的上下文将是：

+   `date_list`：包含给定月份中具有可用对象的所有日期的`DateQuerySet`对象，根据`queryset`表示为`datetime.datetime`对象，按升序排列

+   `month`：表示给定月份的`date`对象

+   `next_month`：表示下个月第一天的`date`对象，根据`allow_empty`和`allow_future`

+   `previous_month`：表示上个月第一天的`date`对象，根据`allow_empty`和`allow_future`

**注释**

+   使用默认的`template_name_suffix`为`_archive_month`

**示例 myapp/views.py**：

```py
from django.views.generic.dates import MonthArchiveView 

from myapp.models import Article 

class ArticleMonthArchiveView(MonthArchiveView): 
    queryset = Article.objects.all() 
    date_field = "pub_date" 
    make_object_list = True 
    allow_future = True 

```

**示例 myapp/urls.py**：

```py
from django.conf.urls import url 

from myapp.views import ArticleMonthArchiveView 

urlpatterns = [ 
    # Example: /2012/aug/ 
    url(r'^(?P<year>[0-9]{4})/(?P<month>[-\w]+)/$', 
        ArticleMonthArchiveView.as_view(), 
        name="archive_month"), 
    # Example: /2012/08/ 
    url(r'^(?P<year>[0-9]{4})/(?P<month>[0-9]+)/$', 
        ArticleMonthArchiveView.as_view(month_format='%m'), 
        name="archive_month_numeric"), 
] 

```

**示例 myapp/article_archive_month.html**：

```py
<ul> 
    {% for article in object_list %} 
        <li>{{ article.pub_date|date:"F j, Y" }}:  
            {{ article.title }} 
        </li> 
    {% endfor %} 
</ul> 

<p> 
    {% if previous_month %} 
        Previous Month: {{ previous_month|date:"F Y" }} 
    {% endif %} 
    {% if next_month %} 
        Next Month: {{ next_month|date:"F Y" }} 
    {% endif %} 
</p> 

```

## 周存档视图

显示给定周内所有对象的周存档页面。具有*未来*日期的对象不会显示，除非您将`allow_future`设置为`True`。

**上下文**

除了`MultipleObjectMixin`（通过`BaseDateListView`）提供的上下文之外，模板的上下文将是：

+   `week`：表示给定周的第一天的`date`对象

+   `next_week`：表示下周第一天的`date`对象，根据`allow_empty`和`allow_future`

+   `previous_week`：表示上周第一天的`date`对象，根据`allow_empty`和`allow_future`

**注释**

+   使用默认的`template_name_suffix`为`_archive_week`

**示例 myapp/views.py**：

```py
from django.views.generic.dates import WeekArchiveView 

from myapp.models import Article 

class ArticleWeekArchiveView(WeekArchiveView): 
    queryset = Article.objects.all() 
    date_field = "pub_date" 
    make_object_list = True 
    week_format = "%W" 
    allow_future = True 

```

**示例 myapp/urls.py**：

```py
from django.conf.urls import url 

from myapp.views import ArticleWeekArchiveView 

urlpatterns = [ 
    # Example: /2012/week/23/ 
    url(r'^(?P<year>[0-9]{4})/week/(?P<week>[0-9]+)/$', 
        ArticleWeekArchiveView.as_view(), 
        name="archive_week"), 
] 

```

**示例 myapp/article_archive_week.html**：

```py
<h1>Week {{ week|date:'W' }}</h1> 

<ul> 
    {% for article in object_list %} 
        <li>{{ article.pub_date|date:"F j, Y" }}: {{ article.title }}</li> 
    {% endfor %} 
</ul> 

<p> 
    {% if previous_week %} 
        Previous Week: {{ previous_week|date:"F Y" }} 
    {% endif %} 
    {% if previous_week and next_week %}--{% endif %} 
    {% if next_week %} 
        Next week: {{ next_week|date:"F Y" }} 
    {% endif %} 
</p> 

```

在这个例子中，您正在输出周数。`WeekArchiveView`中的默认`week_format`使用基于美国周系统的周格式"`%U`"，其中周从星期日开始。"`%W`"格式使用 ISO 周格式，其周从星期一开始。"`%W`"格式在`strftime()`和`date`中是相同的。

但是，`date`模板过滤器没有支持基于美国周系统的等效输出格式。`date`过滤器"`%U`"输出自 Unix 纪元以来的秒数。

## 日存档视图

显示给定日期内所有对象的日存档页面。未来的日期会抛出 404 错误，无论未来日期是否存在任何对象，除非您将`allow_future`设置为`True`。

**上下文**

除了`MultipleObjectMixin`（通过`BaseDateListView`）提供的上下文之外，模板的上下文将是：

+   `day`：表示给定日期的`date`对象

+   `next_day`：表示下一天的`date`对象，根据`allow_empty`和`allow_future`

+   `previous_day`：表示前一天的`date`对象，根据`allow_empty`和`allow_future`

+   `next_month`：表示下个月第一天的`date`对象，根据`allow_empty`和`allow_future`

+   `previous_month`：表示上个月第一天的`date`对象，根据`allow_empty`和`allow_future`

**注释**

+   使用默认的`template_name_suffix`为`_archive_day`

**示例 myapp/views.py**：

```py
from django.views.generic.dates import DayArchiveView 

from myapp.models import Article 

class ArticleDayArchiveView(DayArchiveView): 
    queryset = Article.objects.all() 
    date_field = "pub_date" 
    make_object_list = True 
    allow_future = True 

```

**示例 myapp/urls.py**：

```py
from django.conf.urls import url 

from myapp.views import ArticleDayArchiveView 

urlpatterns = [ 
    # Example: /2012/nov/10/ 
    url(r'^(?P<year>[0-9]{4})/(?P<month>[-\w]+)/(?P<day>[0-9]+)/$', 
        ArticleDayArchiveView.as_view(), 
        name="archive_day"), 
] 

```

**示例 myapp/article_archive_day.html**：

```py
<h1>{{ day }}</h1> 

<ul> 
    {% for article in object_list %} 
        <li> 
        {{ article.pub_date|date:"F j, Y" }}: {{ article.title }} 
        </li> 
    {% endfor %} 
</ul> 

<p> 
    {% if previous_day %} 
        Previous Day: {{ previous_day }} 
    {% endif %} 
    {% if previous_day and next_day %}--{% endif %} 
    {% if next_day %} 
        Next Day: {{ next_day }} 
    {% endif %} 
</p> 

```

## 今天存档视图

显示*今天*的所有对象的日存档页面。这与`django.views.generic.dates.DayArchiveView`完全相同，只是使用今天的日期而不是`year`/`month`/`day`参数。

**注释**

+   使用默认的`template_name_suffix`为`_archive_today`

**示例 myapp/views.py**：

```py
from django.views.generic.dates import TodayArchiveView 

from myapp.models import Article 

class ArticleTodayArchiveView(TodayArchiveView): 
    queryset = Article.objects.all() 
    date_field = "pub_date" 
    make_object_list = True 
    allow_future = True 

```

**示例 myapp/urls.py**：

```py
from django.conf.urls import url 

from myapp.views import ArticleTodayArchiveView 

urlpatterns = [ 
    url(r'^today/$', 
        ArticleTodayArchiveView.as_view(), 
        name="archive_today"), 
] 

```

`TodayArchiveView`的示例模板在哪里？

此视图默认使用与上一个示例中的`DayArchiveView`相同的模板。如果需要不同的模板，请将`template_name`属性设置为新模板的名称。

## DateDetailView

表示单个对象的页面。如果对象具有未来的日期值，默认情况下视图将抛出 404 错误，除非您将`allow_future`设置为`True`。

**上下文**

+   包括与`DateDetailView`中指定的`model`相关联的单个对象

**注**

+   使用默认的`template_name_suffix`为`_detail`

```py
Example myapp/urls.py: 
from django.conf.urls import url 
from django.views.generic.dates import DateDetailView 

urlpatterns = [ 
    url(r'^(?P<year>[0-9]+)/(?P<month>[-\w]+)/(?P<day>[0-9]+)/ 
      (?P<pk>[0-9]+)/$', 
        DateDetailView.as_view(model=Article, date_field="pub_date"), 
        name="archive_date_detail"), 
] 

```

**示例 myapp/article_detail.html**：

```py
<h1>{{ object.title }}</h1> 

```

# 使用基于类的视图处理表单

表单处理通常有 3 条路径：

+   初始`GET`（空白或预填充表单）

+   `POST`无效数据（通常重新显示带有错误的表单）

+   `POST`有效数据（处理数据并通常重定向）

自己实现这个通常会导致大量重复的样板代码（请参见在视图中使用表单）。为了避免这种情况，Django 提供了一组用于表单处理的通用基于类的视图。

## 基本表单

给定一个简单的联系表单：

```py
# forms.py 

from django import forms 

class ContactForm(forms.Form): 
   name = forms.CharField() 
   message = forms.CharField(widget=forms.Textarea) 

   def send_email(self): 
       # send email using the self.cleaned_data dictionary 
       pass 

```

可以使用`FormView`构建视图：

```py
# views.py 

from myapp.forms import ContactForm 
from django.views.generic.edit import FormView 

class ContactView(FormView): 
   template_name = 'contact.html' 
   form_class = ContactForm 
   success_url = '/thanks/' 

   def form_valid(self, form): 
       # This method is called when valid form data has been POSTed. 
       # It should return an HttpResponse. 
       form.send_email() 
       return super(ContactView, self).form_valid(form) 

```

注：

+   `FormView`继承了`TemplateResponseMixin`，因此`template_name`可以在这里使用

+   `form_valid()`的默认实现只是重定向到`success_url`

## 模型表单

与模型一起工作时，通用视图真正发挥作用。这些通用视图将自动创建`ModelForm`，只要它们可以确定要使用哪个模型类：

+   如果给定了`model`属性，将使用该模型类

+   如果`get_object()`返回一个对象，将使用该对象的类

+   如果给定了`queryset`，将使用该查询集的模型

模型表单视图提供了一个`form_valid()`实现，可以自动保存模型。如果有特殊要求，可以覆盖此功能；请参阅下面的示例。

对于`CreateView`或`UpdateView`，甚至不需要提供`success_url`-如果可用，它们将使用模型对象上的`get_absolute_url()`。

如果要使用自定义的`ModelForm`（例如添加额外的验证），只需在视图上设置`form_class`。

### 注意

在指定自定义表单类时，仍然必须指定模型，即使`form_class`可能是一个 ModelForm。

首先，我们需要在我们的`Author`类中添加`get_absolute_url()`：

```py
# models.py 

from django.core.urlresolvers import reverse 
from django.db import models 

class Author(models.Model): 
    name = models.CharField(max_length=200) 

    def get_absolute_url(self): 
        return reverse('author-detail', kwargs={'pk': self.pk}) 

```

然后我们可以使用`CreateView`和其他视图来执行实际工作。请注意，我们只是在这里配置通用基于类的视图；我们不必自己编写任何逻辑：

```py
# views.py 

from django.views.generic.edit import CreateView, UpdateView, DeleteView 
from django.core.urlresolvers import reverse_lazy 
from myapp.models import Author 

class AuthorCreate(CreateView): 
    model = Author 
    fields = ['name'] 

class AuthorUpdate(UpdateView): 
    model = Author 
    fields = ['name'] 

class AuthorDelete(DeleteView): 
    model = Author 
    success_url = reverse_lazy('author-list') 

```

我们必须在这里使用`reverse_lazy()`，而不仅仅是`reverse`，因为在导入文件时未加载 URL。

`fields`属性的工作方式与`ModelForm`上内部`Meta`类的`fields`属性相同。除非以其他方式定义表单类，否则该属性是必需的，如果没有，视图将引发`ImproperlyConfigured`异常。

如果同时指定了`fields`和`form_class`属性，将引发`ImproperlyConfigured`异常。

最后，我们将这些新视图挂接到 URLconf 中：

```py
# urls.py 

from django.conf.urls import url 
from myapp.views import AuthorCreate, AuthorUpdate, AuthorDelete 

urlpatterns = [ 
    # ... 
    url(r'author/add/$', AuthorCreate.as_view(), name='author_add'), 
    url(r'author/(?P<pk>[0-9]+)/$', AuthorUpdate.as_view(),   
        name='author_update'), 
    url(r'author/(?P<pk>[0-9]+)/delete/$', AuthorDelete.as_view(),  
        name='author_delete'), 
] 

```

在这个例子中：

+   `CreateView`和`UpdateView`使用`myapp/author_form.html`

+   `DeleteView`使用`myapp/author_confirm_delete.html`

如果您希望为`CreateView`和`UpdateView`设置单独的模板，可以在视图类上设置`template_name`或`template_name_suffix`。

## 模型和 request.user

要跟踪使用`CreateView`创建对象的用户，可以使用自定义的`ModelForm`来实现。首先，将外键关系添加到模型中：

```py
# models.py 

from django.contrib.auth.models import User 
from django.db import models 

class Author(models.Model): 
    name = models.CharField(max_length=200) 
    created_by = models.ForeignKey(User) 

    # ... 

```

在视图中，确保不要在要编辑的字段列表中包含`created_by`，并覆盖`form_valid()`以添加用户：

```py
# views.py 

from django.views.generic.edit import CreateView 
from myapp.models import Author 

class AuthorCreate(CreateView): 
    model = Author 
    fields = ['name'] 

    def form_valid(self, form): 
        form.instance.created_by = self.request.user 
        return super(AuthorCreate, self).form_valid(form) 

```

请注意，您需要使用`login_required()`装饰此视图，或者在`form_valid()`中处理未经授权的用户。

## AJAX 示例

这里是一个简单的示例，展示了如何实现一个既适用于 AJAX 请求又适用于*普通*表单`POST`的表单。

```py
from django.http import JsonResponse 
from django.views.generic.edit import CreateView 
from myapp.models import Author 

class AjaxableResponseMixin(object): 
    def form_invalid(self, form): 
        response = super(AjaxableResponseMixin, self).form_invalid(form) 
        if self.request.is_ajax(): 
            return JsonResponse(form.errors, status=400) 
        else: 
            return response 

    def form_valid(self, form): 
        # We make sure to call the parent's form_valid() method because 
        # it might do some processing (in the case of CreateView, it will 
        # call form.save() for example). 
        response = super(AjaxableResponseMixin, self).form_valid(form) 
        if self.request.is_ajax(): 
            data = { 
                'pk': self.object.pk, 
            } 
            return JsonResponse(data) 
        else: 
            return response 

class AuthorCreate(AjaxableResponseMixin, CreateView): 
    model = Author 
    fields = ['name'] 

```


# 附录 D。设置

你的 Django 设置文件包含了你的 Django 安装的所有配置。本附录解释了设置的工作原理以及可用的设置。

# 什么是设置文件？

设置文件只是一个具有模块级变量的 Python 模块。以下是一些示例设置：

```py
ALLOWED_HOSTS = ['www.example.com'] DEBUG = False DEFAULT_FROM_EMAIL = 'webmaster@example.com' 

```

### 注意

如果将`DEBUG`设置为`False`，还需要正确设置`ALLOWED_HOSTS`设置。

因为设置文件是一个 Python 模块，所以以下规则适用：

+   它不允许有 Python 语法错误

+   它可以使用常规的 Python 语法动态分配设置，例如：

```py
        MY_SETTING = [str(i) for i in range(30)] 

```

+   它可以从其他设置文件中导入值

## 默认设置

如果不需要，Django 设置文件不必定义任何设置。每个设置都有一个合理的默认值。这些默认值存储在模块`django/conf/global_settings.py`中。以下是 Django 在编译设置时使用的算法：

+   从`global_settings.py`加载设置

+   从指定的设置文件中加载设置，必要时覆盖全局设置

请注意，设置文件不应该从`global_settings`导入，因为那是多余的。

## 查看您已更改的设置

有一种简单的方法来查看您的设置中有哪些与默认设置不同。命令`python manage.py diffsettings`显示当前设置文件与 Django 默认设置之间的差异。有关更多信息，请参阅`diffsettings`文档。

# 在 Python 代码中使用设置

在 Django 应用程序中，通过导入对象`django.conf.settings`来使用设置。例如：

```py
from django.conf import settings
if settings.DEBUG:
     # Do something 

```

请注意，`django.conf.settings`不是一个模块-它是一个对象。因此，无法导入单个设置：

```py
from django.conf.settings import DEBUG  # This won't work. 

```

还要注意，您的代码不应该从`global_settings`或您自己的设置文件中导入。`django.conf.settings`抽象了默认设置和站点特定设置的概念；它提供了一个单一的接口。它还将使用设置的代码与设置的位置解耦。

# 在运行时更改设置

您不应该在应用程序中在运行时更改设置。例如，在视图中不要这样做：

```py
from django.conf import settings
settings.DEBUG = True   # Don't do this! 

```

唯一应该分配设置的地方是在设置文件中。

# 安全

由于设置文件包含敏感信息，例如数据库密码，您应该尽一切努力限制对其的访问。例如，更改文件权限，以便只有您和您的 Web 服务器用户可以读取它。这在共享托管环境中尤为重要。

# 创建自己的设置

没有什么能阻止您为自己的 Django 应用程序创建自己的设置。只需遵循这些约定：

+   设置名称全部大写

+   不要重新发明已经存在的设置

对于序列的设置，Django 本身使用元组，而不是列表，但这只是一种约定。

# DJANGO_SETTINGS_MODULE

当您使用 Django 时，您必须告诉它您正在使用哪些设置。通过使用环境变量`DJANGO_SETTINGS_MODULE`来实现。`DJANGO_SETTINGS_MODULE`的值应该是 Python 路径语法，例如`mysite.settings`。

## django-admin 实用程序

在使用`django-admin`时，您可以设置环境变量一次，或者每次运行实用程序时显式传递设置模块。示例（Unix Bash shell）：

```py
export DJANGO_SETTINGS_MODULE=mysite.settings 
django-admin runserver

```

示例（Windows shell）：

```py
set DJANGO_SETTINGS_MODULE=mysite.settings 
django-admin runserver

```

使用`--settings`命令行参数手动指定设置：

```py
django-admin runserver --settings=mysite.settings

```

## 在服务器上（mod_wsgi）

在您的生产服务器环境中，您需要告诉您的 WSGI 应用程序使用哪个设置文件。使用`os.environ`来实现：

```py
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'

```

阅读第十三章，“部署 Django”，了解有关 Django WSGI 应用程序的更多信息和其他常见元素。

# 在没有设置 DJANGO_SETTINGS_MODULE 的情况下使用设置

在某些情况下，您可能希望绕过`DJANGO_SETTINGS_MODULE`环境变量。例如，如果您仅使用模板系统，您可能不希望设置一个指向设置模块的环境变量。在这些情况下，可以手动配置 Django 的设置。通过调用：

```py
django.conf.settings.configure(default_settings, **settings) 

```

例子：

```py
from django.conf import settings 
settings.configure(DEBUG=True, TEMPLATE_DEBUG=True) 

```

可以将`configure()`作为许多关键字参数传递，每个关键字参数表示一个设置及其值。每个参数名称应全部大写，与上述描述的设置名称相同。如果没有将特定设置传递给`configure()`并且在以后的某个时刻需要，Django 将使用默认设置值。

以这种方式配置 Django 在使用框架的一部分时通常是必要的，而且是推荐的。因此，当通过`settings.configure()`配置时，Django 不会对进程环境变量进行任何修改（请参阅`TIME_ZONE`的文档，了解为什么通常会发生这种情况）。在这些情况下，假设您已经完全控制了您的环境。

## 自定义默认设置

如果您希望默认值来自于`django.conf.global_settings`之外的某个地方，可以将提供默认设置的模块或类作为`configure()`调用中的`default_settings`参数（或作为第一个位置参数）传递。在此示例中，默认设置来自`myapp_defaults`，并且`DEBUG`设置为`True`，而不管它在`myapp_defaults`中的值是什么：

```py
from django.conf import settings 
from myapp import myapp_defaults 

settings.configure(default_settings=myapp_defaults, DEBUG=True) 

```

使用`myapp_defaults`作为位置参数的以下示例是等效的：

```py
settings.configure(myapp_defaults, DEBUG=True) 

```

通常，您不需要以这种方式覆盖默认设置。Django 的默认设置足够温和，您可以放心使用它们。请注意，如果您传入一个新的默认模块，它将完全*替换* Django 的默认设置，因此您必须为可能在导入的代码中使用的每个可能的设置指定一个值。在`django.conf.settings.global_settings`中查看完整列表。

## 要么 configure()，要么 DJANGO_SETTINGS_MODULE 是必需的

如果您没有设置`DJANGO_SETTINGS_MODULE`环境变量，则在使用读取设置的任何代码之前*必须*在某个时刻调用`configure()`。如果您没有设置`DJANGO_SETTINGS_MODULE`并且没有调用`configure()`，Django 将在第一次访问设置时引发`ImportError`异常。如果您设置了`DJANGO_SETTINGS_MODULE`，以某种方式访问设置值，*然后*调用`configure()`，Django 将引发`RuntimeError`，指示已经配置了设置。有一个专门用于此目的的属性：

```py
django.conf.settings.configured 

```

例如：

```py
from django.conf import settings 
if not settings.configured:
     settings.configure(myapp_defaults, DEBUG=True) 

```

此外，多次调用`configure()`或在访问任何设置之后调用`configure()`都是错误的。归根结底：只使用`configure()`或`DJANGO_SETTINGS_MODULE`中的一个。既不是两者，也不是两者都不是。

# 可用设置

Django 有大量可用的设置。为了方便参考，我将它们分成了六个部分，每个部分在本附录中都有相应的表。

+   核心设置（*表 D.1*）

+   身份验证设置（*表 D.2*）

+   消息设置（*表 D.3*）

+   会话设置（*表 D.4*）

+   Django 站点设置（*表 D.5*）

+   静态文件设置（*表 D.6*）

每个表列出了可用设置及其默认值。有关每个设置的附加信息和用例，请参阅 Django 项目网站[`docs.djangoproject.com/en/1.8/ref/settings/`](https://docs.djangoproject.com/en/1.8/ref/settings/)。

### 注意

在覆盖设置时要小心，特别是当默认值是非空列表或字典时，例如`MIDDLEWARE_CLASSES`和`STATICFILES_FINDERS`。确保保留 Django 所需的组件，以便使用您希望使用的 Django 功能。

## 核心设置

| **设置** | **默认值** |
| --- | --- |
| `ABSOLUTE_URL_OVERRIDES` | `{}` (空字典) |
| `ADMINS` | `[]` (空列表) |
| `ALLOWED_HOSTS` | `[]`（空列表） |
| `APPEND_SLASH` | `True` |
| `CACHE_MIDDLEWARE_ALIAS` | `default` |
| `CACHES` | `{ 'default': { 'BACKEND': 'django.core.cache.backends.locmem.LocMemCache', } }` |
| `CACHE_MIDDLEWARE_KEY_PREFIX` | `''`（空字符串） |
| `CACHE_MIDDLEWARE_SECONDS` | `600` |
| `CSRF_COOKIE_AGE` | `31449600 (1 年，以秒计)` |
| `CSRF_COOKIE_DOMAIN` | `None` |
| `CSRF_COOKIE_HTTPONLY` | `False` |
| `CSRF_COOKIE_NAME` | `Csrftoken` |
| `CSRF_COOKIE_PATH` | `'/'` |
| `CSRF_COOKIE_SECURE` | `False` |
| `DATE_INPUT_FORMATS` | `[ '%Y-%m-%d', '%m/%d/%Y', '%m/%d/%y', '%b %d %Y', '%b %d, %Y', '%d %b %Y','%d %b, %Y', '%B %d %Y', '%B %d, %Y', '%d %B %Y', '%d %B, %Y', ]` |
| `DATETIME_FORMAT` | `'N j, Y, P'（例如，Feb. 4, 2003, 4 p.m.）` |
| `DATETIME_INPUT_FORMATS` | `[ '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M', '%Y-%m-%d', '%m/%d/%Y %H:%M:%S', '%m/%d/%Y %H:%M:%S.%f', '%m/%d/%Y %H:%M', '%m/%d/%Y', '%m/%d/%y %H:%M:%S',``'%m/%d/%y %H:%M:%S.%f', '%m/%d/%y %H:%M', '%m/%d/%y',``]` |
| `DEBUG` | `False` |
| `DEBUG_PROPAGATE_EXCEPTIONS` | `False` |
| `DECIMAL_SEPARATOR` | `'.'`（点） |
| `DEFAULT_CHARSET` | `'utf-8'` |
| `DEFAULT_CONTENT_TYPE` | `'text/html'` |
| `DEFAULT_EXCEPTION_REPORTER_FILTER` | `django.views.debug. SafeExceptionReporterFilter` |
| `DEFAULT_FILE_STORAGE` | `django.core.files.storage. FileSystemStorage` |
| `DEFAULT_FROM_EMAIL` | `'webmaster@localhost'.` |
| `DEFAULT_INDEX_TABLESPACE` | `''`（空字符串） |
| `DEFAULT_TABLESPACE` | `''`（空字符串） |
| `DISALLOWED_USER_AGENTS` | `[]`（空列表） |
| `EMAIL_BACKEND` | `django.core.mail.backends.smtp. EmailBackend` |
| `EMAIL_HOST` | `'localhost'` |
| `EMAIL_HOST_PASSWORD` | `''`（空字符串） |
| `EMAIL_HOST_USER` | `''`（空字符串） |
| `EMAIL_PORT` | `25` |
| `EMAIL_SUBJECT_PREFIX` | `'[Django] '` |
| `EMAIL_USE_TLS` | `False` |
| `EMAIL_USE_SSL` | `False` |
| `EMAIL_SSL_CERTFILE` | `None` |
| `EMAIL_SSL_KEYFILE` | `None` |
| `EMAIL_TIMEOUT` | `None` |
| `FILE_CHARSET` | `'utf-8'` |
| `FILE_UPLOAD_HANDLERS` | `[ 'django.core.files.uploadhandler.` `MemoryFileUploadHandler', 'django.core.files.uploadhandler. TemporaryFileUploadHandler' ]` |
| `FILE_UPLOAD_MAX_MEMORY_SIZE` | `2621440（即 2.5 MB）` |
| `FILE_UPLOAD_DIRECTORY_PERMISSIONS` | `None` |
| `FILE_UPLOAD_PERMISSIONS` | `None` |
| `FILE_UPLOAD_TEMP_DIR` | `None` |
| `FIRST_DAY_OF_WEEK` | `0`（星期日） |
| `FIXTURE_DIRS` | `[]`（空列表） |
| `FORCE_SCRIPT_NAME` | `None` |
| `FORMAT_MODULE_PATH` | `None` |
| `IGNORABLE_404_URLS` | `[]`（空列表） |
| `INSTALLED_APPS` | `[]`（空列表） |
| `INTERNAL_IPS` | `[]`（空列表） |
| `LANGUAGE_CODE` | `'en-us'` |
| `LANGUAGE_COOKIE_AGE` | `None`（在浏览器关闭时过期） |
| `LANGUAGE_COOKIE_DOMAIN` | `None` |
| `LANGUAGE_COOKIE_NAME` | `'django_language'` |
| `LANGUAGES` | 所有可用语言的列表 |
| `LOCALE_PATHS` | `[]`（空列表） |
| `LOGGING` | `一个日志配置字典` |
| `LOGGING_CONFIG` | `'logging.config.dictConfig'` |
| `MANAGERS` | `[]`（空列表） |
| `MEDIA_ROOT` | `''`（空字符串） |
| `MEDIA_URL` | `''`（空字符串） |
| `MIDDLEWARE_CLASSES` | `[ 'django.middleware.common. CommonMiddleware', 'django.middleware.csrf.  CsrfViewMiddleware' ]` |
| `MIGRATION_MODULES` | `{}`（空字典） |
| `MONTH_DAY_FORMAT` | `'F j'` |
| `NUMBER_GROUPING` | `0` |
| `PREPEND_WWW` | `False` |
| `ROOT_URLCONF` | 未定义 |
| `SECRET_KEY` | `''`（空字符串） |
| `SECURE_BROWSER_XSS_FILTER` | `False` |
| `SECURE_CONTENT_TYPE_NOSNIFF` | `False` |
| `SECURE_HSTS_INCLUDE_SUBDOMAINS` | `False` |
| `SECURE_HSTS_SECONDS` | `0` |
| `SECURE_PROXY_SSL_HEADER` | `None` |
| `SECURE_REDIRECT_EXEMPT` | `[]`（空列表） |
| `SECURE_SSL_HOST` | `None` |
| `SECURE_SSL_REDIRECT` | `False` |
| `SERIALIZATION_MODULES` | 未定义 |
| `SERVER_EMAIL` | `'root@localhost'` |
| `SHORT_DATE_FORMAT` | `m/d/Y`（例如，12/31/2003） |
| `SHORT_DATETIME_FORMAT` | `m/d/Y P`（例如，12/31/2003 4 p.m.） |
| `SIGNING_BACKEND` | `'django.core.signing.TimestampSigner'` |
| `SILENCED_SYSTEM_CHECKS` | `[]`（空列表） |
| `TEMPLATES` | `[]`（空列表） |
| `TEMPLATE_DEBUG` | `False` |
| `TEST_RUNNER` | `'django.test.runner.DiscoverRunner'` |
| `TEST_NON_SERIALIZED_APPS` | `[]`（空列表） |
| `THOUSAND_SEPARATOR` | `,（逗号）` |
| `TIME_FORMAT` | `'P'`（例如，下午 4 点） |
| `TIME_INPUT_FORMATS` | `[ '%H:%M:%S',``'%H:%M:%S.%f', '%H:%M',``]` |
| `TIME_ZONE` | `'America/Chicago'` |
| `USE_ETAGS` | `False` |
| `USE_I18N` | `True` |
| `USE_L10N` | `False` |
| `USE_THOUSAND_SEPARATOR` | `False` |
| `USE_TZ` | `False` |
| `USE_X_FORWARDED_HOST` | `False` |
| `WSGI_APPLICATION` | `None` |
| `YEAR_MONTH_FORMAT` | `'F Y'` |
| `X_FRAME_OPTIONS` | `'SAMEORIGIN'` |

表 D.1：Django 核心设置

## 认证

| **设置** | **默认值** |
| --- | --- |
| `AUTHENTICATION_BACKENDS` | `'django.contrib.auth.backends.ModelBackend'` |
| `AUTH_USER_MODEL` | `'auth.User'` |
| `LOGIN_REDIRECT_URL` | `'/accounts/profile/'` |
| `LOGIN_URL` | `'/accounts/login/'` |
| `LOGOUT_URL` | `'/accounts/logout/'` |
| `PASSWORD_RESET_TIMEOUT_DAYS` | `3` |
| `PASSWORD_HASHERS` | `[ 'django.contrib.auth.hashers.PBKDF2PasswordHasher', 'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher', 'django.contrib.auth.hashers.BCryptPasswordHasher', 'django.contrib.auth.hashers.SHA1PasswordHasher', 'django.contrib.auth.hashers.MD5PasswordHasher', 'django.contrib.auth.hashers.UnsaltedMD5PasswordHasher', 'django.contrib.auth.hashers.CryptPasswordHasher' ]` |

表 D.2：Django 身份验证设置

## 消息

| **设置** | **默认值** |
| --- | --- |
| `MESSAGE_LEVEL` | `messages` |
| `MESSAGE_STORAGE` | `'django.contrib.messages.storage.fallback.FallbackStorage'` |
| `MESSAGE_TAGS` | `{ messages.DEBUG: 'debug', messages.INFO: 'info', messages.SUCCESS: 'success', messages.WARNING: 'warning', messages.ERROR: 'error' }` |

表 D.3：Django 消息设置

## 会话

| **设置** | **默认值** |
| --- | --- |
| `SESSION_CACHE_ALIAS` | `default` |
| `SESSION_COOKIE_AGE` | `1209600`（2 周，以秒计）。 |
| `SESSION_COOKIE_DOMAIN` | `None` |
| `SESSION_COOKIE_HTTPONLY` | `True.` |
| `SESSION_COOKIE_NAME` | `'sessionid'` |
| `SESSION_COOKIE_PATH` | `'/'` |
| `SESSION_COOKIE_SECURE` | `False` |
| `SESSION_ENGINE` | `'django.contrib.sessions.backends.db'` |
| `SESSION_EXPIRE_AT_BROWSER_CLOSE` | `False` |
| `SESSION_FILE_PATH` | `None` |
| `SESSION_SAVE_EVERY_REQUEST` | `False` |
| `SESSION_SERIALIZER` | `'django.contrib.sessions.serializers. JSONSerializer'` |

表 D.4：Django 会话设置

## 站点

| **设置** | **默认值** |
| --- | --- |
| `SITE_ID` | `Not defined` |

表 D.5：Django 站点设置

## 静态文件

| **设置** | **默认值** |
| --- | --- |
| `STATIC_ROOT` | `None` |
| `STATIC_URL` | `None` |
| `STATICFILES_DIRS` | `[]`（空列表） |
| `STATICFILES_STORAGE` | `'django.contrib.staticfiles.storage.StaticFilesStorage'` |
| `STATICFILES_FINDERS` | `[``"django.contrib.staticfiles.finders.FileSystemFinder", "django.contrib.staticfiles.finders. AppDirectoriesFinder"``]` |

表 D.6：Django 静态文件设置


# 附录 E. 内置模板标签和过滤器

第三章, *模板*, 列出了一些最有用的内置模板标签和过滤器。但是，Django 还附带了许多其他内置标签和过滤器。本附录提供了 Django 中所有模板标签和过滤器的摘要。有关更详细的信息和用例，请参见 Django 项目网站 [`docs.djangoproject.com/en/1.8/ref/templates/builtins/`](https://docs.djangoproject.com/en/1.8/ref/templates/builtins/)。

# 内置标签

## autoescape

控制当前自动转义行为。此标签接受 `on` 或 `off` 作为参数，决定块内是否生效自动转义。块以 `endautoescape` 结束标签关闭。

当自动转义生效时，所有变量内容在放入输出结果之前都会应用 HTML 转义（但在应用任何过滤器之后）。这相当于手动对每个变量应用 `escape` 过滤器。

唯一的例外是已经标记为不需要转义的变量，要么是由填充变量的代码标记的，要么是因为已经应用了 `safe` 或 `escape` 过滤器。示例用法：

```py
{% autoescape on %} 
    {{ body }} 
{% endautoescape %} 

```

## block

定义一个可以被子模板覆盖的块。有关更多信息，请参见 第三章, *模板*, 中的 "模板继承"。

## comment

忽略 `{% comment %}` 和 `{% endcomment %}` 之间的所有内容。第一个标签中可以插入一个可选的注释。例如，当注释掉代码以记录为什么禁用代码时，这是有用的。

`Comment` 标签不能嵌套。

## csrf_token

此标签用于 CSRF 保护。有关 **跨站点请求伪造** (**CSRF**) 的更多信息，请参见 第三章, *模板*, 和 第十九章, *Django 中的安全性*。

## cycle

每次遇到此标签时，产生其中的一个参数。第一次遇到时产生第一个参数，第二次遇到时产生第二个参数，依此类推。一旦所有参数用完，标签就会循环到第一个参数并再次产生它。这个标签在循环中特别有用：

```py
{% for o in some_list %} 
    <tr class="{% cycle 'row1' 'row2' %}"> 
        ... 
    </tr> 
{% endfor %} 

```

第一次迭代生成引用 `row1` 类的 HTML，第二次生成 `row2`，第三次再次生成 `row1`，依此类推。您也可以使用变量。例如，如果有两个模板变量 `rowvalue1` 和 `rowvalue2`，您可以像这样在它们的值之间交替：

```py
{% for o in some_list %} 
    <tr class="{% cycle rowvalue1 rowvalue2 %}"> 
        ... 
    </tr> 
{% endfor %} 

```

您还可以混合变量和字符串：

```py
{% for o in some_list %} 
    <tr class="{% cycle 'row1' rowvalue2 'row3' %}"> 
        ... 
    </tr> 
{% endfor %} 

```

您可以在 `cycle` 标签中使用任意数量的值，用空格分隔。用单引号 (`'`) 或双引号 (`"`) 括起来的值被视为字符串字面量，而没有引号的值被视为模板变量。

## debug

输出大量的调试信息，包括当前上下文和导入的模块。

## extends

表示此模板扩展了父模板。此标签可以以两种方式使用：

+   `{% extends "base.html" %}`（带引号）使用字面值 `"base.html"` 作为要扩展的父模板的名称。

+   `{% extends variable %}` 使用 `variable` 的值。如果变量求值为字符串，Django 将使用该字符串作为父模板的名称。如果变量求值为 `Template` 对象，Django 将使用该对象作为父模板。

## filter

通过一个或多个过滤器过滤块的内容。有关 Django 中过滤器的列表，请参见附录后面的内置过滤器部分。

## firstof

输出第一个不是 `False` 的参数变量。如果所有传递的变量都是 `False`，则不输出任何内容。示例用法：

```py
{% firstof var1 var2 var3 %} 

```

这相当于：

```py
{% if var1 %} 
    {{ var1 }} 
{% elif var2 %} 
    {{ var2 }} 
{% elif var3 %} 
    {{ var3 }} 
{% endif %} 

```

## for

在数组中循环每个项目，使项目在上下文变量中可用。例如，要显示提供的 `athlete_list` 中的运动员列表：

```py
<ul> 
{% for athlete in athlete_list %} 
    <li>{{ athlete.name }}</li> 
{% endfor %} 
</ul> 

```

您可以通过使用`{% for obj in list reversed %}`在列表上进行反向循环。如果需要循环遍历一个列表的列表，可以将每个子列表中的值解压缩为单独的变量。如果需要访问字典中的项目，这也可能很有用。例如，如果您的上下文包含一个名为`data`的字典，则以下内容将显示字典的键和值：

```py
{% for key, value in data.items %} 
    {{ key }}: {{ value }} 
{% endfor %} 

```

## for... empty

`for`标签可以带一个可选的`{% empty %}`子句，如果给定的数组为空或找不到，则显示其文本：

```py
<ul> 
{% for athlete in athlete_list %} 
    <li>{{ athlete.name }}</li> 
{% empty %} 
    <li>Sorry, no athletes in this list.</li> 
{% endfor %} 
</ul> 

```

## 如果

`{% if %}`标签评估一个变量，如果该变量为真（即存在，不为空，并且不是 false 布尔值），则输出块的内容：

```py
{% if athlete_list %} 
    Number of athletes: {{ athlete_list|length }} 
{% elif athlete_in_locker_room_list %} 
    Athletes should be out of the locker room soon! 
{% else %} 
    No athletes. 
{% endif %} 

```

在上面的例子中，如果`athlete_list`不为空，则将通过`{{ athlete_list|length }}`变量显示运动员的数量。正如您所看到的，`if`标签可以带一个或多个`{% elif %}`子句，以及一个`{% else %}`子句，如果所有先前的条件都失败，则将显示该子句。这些子句是可选的。

### 布尔运算符

`if`标签可以使用`and`、`or`或`not`来测试多个变量或否定给定变量：

```py
{% if athlete_list and coach_list %} 
    Both athletes and coaches are available. 
{% endif %} 

{% if not athlete_list %} 
    There are no athletes. 
{% endif %} 

{% if athlete_list or coach_list %} 
    There are some athletes or some coaches. 
{% endif %} 

```

在同一个标签中使用`and`和`or`子句是允许的，例如，`and`的优先级高于`or`：

```py
{% if athlete_list and coach_list or cheerleader_list %} 

```

将被解释为：

```py
if (athlete_list and coach_list) or cheerleader_list 

```

在`if`标签中使用实际括号是无效的语法。如果需要它们来表示优先级，应该使用嵌套的`if`标签。

`if`标签也可以使用`==`、`!=`、`<`、`>`、`<=`、`>=`和`in`运算符，其工作方式如*表 E.1*中所列。

| 运算符 | 示例 |
| --- | --- |
| == | {% if somevar == "x" %} ... |
| != | {% if somevar != "x" %} ... |
| < | {% if somevar < 100 %} ... |
| > | {% if somevar > 10 %} ... |
| <= | {% if somevar <= 100 %} ... |
| >= | {% if somevar >= 10 %} ... |
| In | {% if "bc" in "abcdef" %} |

表 E.1：模板标签中的布尔运算符

### 复杂表达式

所有上述内容都可以组合成复杂的表达式。对于这样的表达式，了解在评估表达式时运算符是如何分组的可能很重要，即优先级规则。运算符的优先级从低到高依次为：

+   `or`

+   `and`

+   `not`

+   `in`

+   `==`、`!=`、`<`、`>`、`<=`和`>=`

这个优先顺序与 Python 完全一致。

### 过滤器

您还可以在`if`表达式中使用过滤器。例如：

```py
{% if messages|length >= 100 %} 
   You have lots of messages today! 
{% endif %} 

```

## ifchanged

检查值是否与循环的上一次迭代不同。

`{% ifchanged %}`块标签在循环内使用。它有两种可能的用法：

+   检查其自身的渲染内容与其先前状态是否不同，仅在内容发生变化时显示内容

+   如果给定一个或多个变量，检查任何变量是否发生了变化

## ifequal

如果两个参数相等，则输出块的内容。示例：

```py
{% ifequal user.pk comment.user_id %} 
    ... 
{% endifequal %} 

```

`ifequal`标签的替代方法是使用`if`标签和`==`运算符。

## ifnotequal

与`ifequal`类似，只是它测试两个参数是否不相等。使用`ifnotequal`标签的替代方法是使用`if`标签和`!=`运算符。

## 包括

加载模板并使用当前上下文进行渲染。这是在模板中包含其他模板的一种方式。模板名称可以是一个变量：

```py
{% include template_name %} 

```

或硬编码（带引号）的字符串：

```py
{% include "foo/bar.html" %} 

```

## 加载

加载自定义模板标签集。例如，以下模板将加载`somelibrary`和`otherlibrary`中注册的所有标签和过滤器，这些库位于`package`包中：

```py
{% load somelibrary package.otherlibrary %} 

```

您还可以使用`from`参数从库中选择性地加载单个过滤器或标签。

在这个例子中，模板标签/过滤器`foo`和`bar`将从`somelibrary`中加载：

```py
{% load foo bar from somelibrary %} 

```

有关更多信息，请参阅*自定义标签*和*过滤器库*。

## lorem

显示随机的 lorem ipsum 拉丁文。这对于在模板中提供示例数据很有用。用法：

```py
{% lorem [count] [method] [random] %} 

```

`{% lorem %}`标签可以使用零个、一个、两个或三个参数。这些参数是：

+   **计数：**生成段落或单词的数量（默认为 1）的数字（或变量）。

+   **方法：**单词的 w，HTML 段落的 p 或纯文本段落块的 b（默认为 b）。

+   **随机：**单词随机，如果给定，则在生成文本时不使用常见段落（Lorem ipsum dolor sit amet...）。

例如，`{% lorem 2 w random %}`将输出两个随机拉丁单词。

## now

显示当前日期和/或时间，使用与给定字符串相符的格式。该字符串可以包含格式说明符字符，如`date`过滤器部分所述。例如：

```py
It is {% now "jS F Y H:i" %} 

```

传递的格式也可以是预定义的格式之一`DATE_FORMAT`、`DATETIME_FORMAT`、`SHORT_DATE_FORMAT`或`SHORT_DATETIME_FORMAT`。预定义的格式可能会根据当前区域设置和格式本地化的启用情况而有所不同，例如：

```py
It is {% now "SHORT_DATETIME_FORMAT" %} 

```

## regroup

通过共同属性对类似对象的列表进行重新分组。

`{% regroup %}`生成*组对象*的列表。每个组对象有两个属性：

+   `grouper`：按其共同属性进行分组的项目（例如，字符串 India 或 Japan）

+   `list`：此组中所有项目的列表（例如，所有`country = "India"`的城市列表）

请注意，`{% regroup %}`不会对其输入进行排序！

任何有效的模板查找都是`regroup`标记的合法分组属性，包括方法、属性、字典键和列表项。

## spaceless

删除 HTML 标签之间的空格。这包括制表符和换行符。例如用法：

```py
{% spaceless %} 
    <p> 
        <a href="foo/">Foo</a> 
    </p> 
{% endspaceless %} 

```

此示例将返回此 HTML：

```py
<p><a href="foo/">Foo</a></p> 

```

## templatetag

输出用于组成模板标记的语法字符之一。由于模板系统没有转义的概念，因此要显示模板标记中使用的位之一，必须使用`{% templatetag %}`标记。参数告诉要输出哪个模板位：

+   `openblock`输出：`{%`

+   `closeblock`输出：`%}`

+   `openvariable`输出：`{{`

+   `closevariable`输出：`}}`

+   `openbrace`输出：`{`

+   `closebrace`输出：`}`

+   `opencomment`输出：`{#`

+   `closecomment`输出：`#}`

示例用法：

```py
{% templatetag openblock %} url 'entry_list' {% templatetag closeblock %} 

```

## url

返回与给定视图函数和可选参数匹配的绝对路径引用（不包括域名的 URL）。结果路径中的任何特殊字符都将使用`iri_to_uri()`进行编码。这是一种在模板中输出链接的方法，而不违反 DRY 原则，因为不必在模板中硬编码 URL：

```py
{% url 'some-url-name' v1 v2 %} 

```

第一个参数是视图函数的路径，格式为`package.package.module.function`。它可以是带引号的文字或任何其他上下文变量。其他参数是可选的，应该是用空格分隔的值，这些值将用作 URL 中的参数。

## verbatim

阻止模板引擎渲染此块标记的内容。常见用途是允许与 Django 语法冲突的 JavaScript 模板层。

## widthratio

用于创建条形图等，此标记计算给定值与最大值的比率，然后将该比率应用于常数。例如：

```py
<img src="img/bar.png" alt="Bar" 
     height="10" width="{% widthratio this_value max_value max_width %}" /> 

```

## with

将复杂变量缓存到更简单的名称下。在多次访问昂贵的方法（例如，多次访问数据库的方法）时很有用。例如：

```py
{% with total=business.employees.count %} 
    {{ total }} employee{{ total|pluralize }} 
{% endwith %} 

```

# 内置过滤器

## add

将参数添加到值。例如：

```py
{{ value|add:"2" }} 

```

如果`value`是`4`，则输出将是`6`。

## addslashes

在引号前添加斜杠。例如，在 CSV 中转义字符串很有用。例如：

```py
{{ value|addslashes }} 

```

如果`value`是`I'm using Django`，输出将是`I'm using Django`。

## capfirst

将值的第一个字符大写。如果第一个字符不是字母，则此过滤器无效。

## center

将值居中在给定宽度的字段中。例如：

```py
"{{ value|center:"14" }}" 

```

如果`value`是`Django`，输出将是`Django`。

## cut

从给定字符串中删除所有`arg`的值。

## date

根据给定的格式格式化日期。使用与 PHP 的`date()`函数类似的格式，但有一些不同之处。

### 注意

这些格式字符在 Django 模板之外不使用。它们旨在与 PHP 兼容，以便设计人员更轻松地过渡。有关格式字符串的完整列表，请参见 Django 项目网站[`docs.djangoproject.com/en/dev/ref/templates/builtins/#date`](https://docs.djangoproject.com/en/dev/ref/templates/builtins/#date)。

例如：

```py
{{ value|date:"D d M Y" }} 

```

如果`value`是`datetime`对象（例如，`datetime.datetime.now()`的结果），输出将是字符串`Fri 01 Jul 2016`。传递的格式可以是预定义的`DATE_FORMAT`、`DATETIME_FORMAT`、`SHORT_DATE_FORMAT`或`SHORT_DATETIME_FORMAT`之一，也可以是使用日期格式说明符的自定义格式。

## 默认

如果值评估为`False`，则使用给定的默认值。否则，使用该值。例如：

```py
{{ value|default:"nothing" }}     

```

## default_if_none

如果（且仅当）值为`None`，则使用给定的默认值。否则，使用该值。

## dictsort

接受一个字典列表并返回按参数中给定的键排序的列表。例如：

```py
{{ value|dictsort:"name" }} 

```

## dictsortreversed

接受一个字典列表并返回按参数中给定的键的相反顺序排序的列表。

## 可被整除

如果值可以被参数整除，则返回`True`。例如：

```py
{{ value|divisibleby:"3" }} 

```

如果`value`是`21`，输出将是`True`。

## 转义

转义字符串的 HTML。具体来说，它进行以下替换：

+   `<`转换为`&lt;`

+   `>`转换为`&gt;`

+   `'`（单引号）转换为`'`

+   `"`（双引号）转换为`&quot;`

+   `&`转换为`&amp;`

转义仅在输出字符串时应用，因此不管在过滤器的链式序列中放置`escape`的位置如何：它始终会被应用，就好像它是最后一个过滤器一样。

## escapejs

转义用于 JavaScript 字符串。这并*不*使字符串在 HTML 中安全使用，但可以保护您免受在使用模板生成 JavaScript/JSON 时的语法错误。

## filesizeformat

格式化值，如“人类可读”的文件大小（即`'13 KB'`、`'4.1 MB'`、`'102 bytes'`等）。例如：

```py
{{ value|filesizeformat }} 

```

如果`value`是`123456789`，输出将是`117.7 MB`。

## 第一

返回列表中的第一项。

## floatformat

在没有参数的情况下使用时，将浮点数四舍五入到小数点后一位，但只有在有小数部分要显示时才会这样做。如果与数字整数参数一起使用，`floatformat`将将数字四舍五入到该小数位数。

例如，如果`value`是`34.23234`，`{{ value|floatformat:3 }}`将输出`34.232`。

## get_digit

给定一个整数，返回请求的数字，其中 1 是最右边的数字。

## iriencode

将**国际化资源标识符**（**IRI**）转换为适合包含在 URL 中的字符串。

## join

使用字符串将列表连接起来，就像 Python 的`str.join(list)`一样。

## 最后

返回列表中的最后一项。

## 长度

返回值的长度。这适用于字符串和列表。

## length_is

如果值的长度是参数，则返回`True`，否则返回`False`。例如：

```py
{{ value|length_is:"4" }} 

```

## linebreaks

用适当的 HTML 替换纯文本中的换行符；单个换行符变成 HTML 换行符（`<br />`），换行符后面跟着一个空行变成段落换行符（`</p>`）。

## linebreaksbr

将纯文本中的所有换行符转换为 HTML 换行符（`<br />`）。

## 行号

显示带有行号的文本。

## ljust

将值左对齐在给定宽度的字段中。例如：

```py
{{ value|ljust:"10" }} 

```

如果`value`是`Django`，输出将是`Django`。

## lower

将字符串转换为全部小写。

## make_list

返回转换为列表的值。对于字符串，它是一个字符列表。对于整数，在创建列表之前，参数被转换为 Unicode 字符串。

## phone2numeric

将电话号码（可能包含字母）转换为其数字等价物。输入不一定是有效的电话号码。这将愉快地转换任何字符串。例如：

```py
{{ value|phone2numeric }} 

```

如果`value`是`800-COLLECT`，输出将是`800-2655328`。

## pluralize

如果值不是`1`，则返回复数后缀。默认情况下，此后缀为`s`。

对于不通过简单后缀复数化的单词，可以指定由逗号分隔的单数和复数后缀。例如：

```py
You have {{ num_cherries }} cherr{{ num_cherries|pluralize:"y,ies" }}. 

```

## 漂亮打印

`pprint.pprint()`的包装器-用于调试。

## 随机

从给定列表返回一个随机项。

## rjust

将值右对齐到给定宽度的字段。例如：

```py
{{ value|rjust:"10" }} 

```

如果`value`是`Django`，输出将是`Django`。

## 安全

将字符串标记为在输出之前不需要进一步的 HTML 转义。当自动转义关闭时，此过滤器没有效果。

## safeseq

将`safe`过滤器应用于序列的每个元素。与操作序列的其他过滤器（如`join`）一起使用时很有用。例如：

```py
{{ some_list|safeseq|join:", " }} 

```

在这种情况下，您不能直接使用`safe`过滤器，因为它首先会将变量转换为字符串，而不是处理序列的各个元素。

## 切片

返回列表的一个切片。使用与 Python 列表切片相同的语法。

## slugify

转换为 ASCII。将空格转换为连字符。删除非字母数字、下划线或连字符的字符。转换为小写。还会去除前导和尾随空格。

## stringformat

根据参数格式化变量，一个字符串格式化说明符。此说明符使用 Python 字符串格式化语法，唯一的例外是省略了前导%。

## 去除标签

尽一切可能去除所有[X]HTML 标记。例如：

```py
{{ value|striptags }} 

```

## 时间

根据给定的格式格式化时间。给定的格式可以是预定义的`TIME_FORMAT`，也可以是与`date`过滤器相同的自定义格式。

## timesince

将日期格式化为自那日期以来的时间（例如，4 天，6 小时）。接受一个可选参数，该参数是包含要用作比较点的日期的变量（没有参数，则比较点是`now`）。

## timeuntil

从现在起测量到给定日期或`datetime`的时间。

## 标题

通过使单词以大写字母开头并将其余字符转换为小写，将字符串转换为标题大小写。

## truncatechars

如果字符串长度超过指定的字符数，则截断字符串。截断的字符串将以可翻译的省略号序列（...）结尾。例如：

```py
{{ value|truncatechars:9 }} 

```

## truncatechars_html

类似于`truncatechars`，只是它知道 HTML 标记。

## truncatewords

在一定数量的单词后截断字符串。

## truncatewords_html

类似于`truncatewords`，只是它知道 HTML 标记。

## unordered_list

递归地获取自我嵌套列表并返回一个不带开放和关闭标签的 HTML 无序列表。

## 上限

将字符串转换为大写。

## urlencode

为在 URL 中使用而转义值。

## urlize

将文本中的 URL 和电子邮件地址转换为可点击的链接。此模板标签适用于以`http://`、`https://`或`www.`为前缀的链接。

## urlizetrunc

将 URL 和电子邮件地址转换为可点击的链接，就像`urlize`一样，但截断超过给定字符限制的 URL。例如：

```py
{{ value|urlizetrunc:15 }} 

```

如果`value`是`Check out www.djangoproject.com`，输出将是`Check out <a href="http://www.djangoproject.com" rel="nofollow">www.djangopr...</a>`。与`urlize`一样，此过滤器只应用于纯文本。

## wordcount

返回单词数。

## wordwrap

在指定的行长度处包装单词。

## yesno

将真、假和（可选）无映射值为字符串 yes、no、maybe，或作为逗号分隔列表传递的自定义映射之一，并根据值返回其中之一：例如：

```py
{{ value|yesno:"yeah,no,maybe" }} 

```

# 国际化标签和过滤器

Django 提供模板标签和过滤器来控制模板中国际化的每个方面。它们允许对翻译、格式化和时区转换进行细粒度控制。

## i18n

此库允许在模板中指定可翻译的文本。要启用它，请将`USE_I18N`设置为`True`，然后使用`{% load i18n %}`加载它。

## l10n

这个库提供了对模板中数值本地化的控制。你只需要使用`{% load l10n %}`加载库，但通常会将`USE_L10N`设置为`True`，以便默认情况下启用本地化。

## tz

这个库提供了对模板中时区转换的控制。像`l10n`一样，你只需要使用`{% load tz %}`加载库，但通常也会将`USE_TZ`设置为`True`，以便默认情况下进行本地时间转换。请参阅模板中的时区。

# 其他标签和过滤器库

## static

要链接到保存在`STATIC_ROOT`中的静态文件，Django 附带了一个`static`模板标签。无论你是否使用`RequestContext`，你都可以使用它。

```py
{% load static %} 
<img src="img/{% static "images/hi.jpg" %}" alt="Hi!" /> 

```

它还能够使用标准上下文变量，例如，假设一个`user_stylesheet`变量被传递给模板：

```py
{% load static %} 
<link rel="stylesheet" href="{% static user_stylesheet %}" type="text/css" media="screen" /> 

```

如果你想要检索静态 URL 而不显示它，你可以使用稍微不同的调用：

```py
{% load static %} 
{% static "images/hi.jpg" as myphoto %} 
<img src="img/{{ myphoto }}"></img> 

```

`staticfiles` contrib 应用程序还附带了一个`static 模板标签`，它使用`staticfiles` `STATICFILES_STORAGE`来构建给定路径的 URL（而不仅仅是使用`STATIC_URL`设置和给定路径的`urllib.parse.urljoin()`）。如果你有高级用例，比如使用云服务来提供静态文件，那就使用它：

```py
{% load static from staticfiles %} 
<img src="img/{% static "images/hi.jpg" %}" alt="Hi!" /> 

```

## get_static_prefix

你应该优先使用`static`模板标签，但如果你需要更多控制`STATIC_URL`被注入到模板的位置和方式，你可以使用`get_static_prefix`模板标签：

```py
{% load static %} 
<img src="img/hi.jpg" alt="Hi!" /> 

```

还有第二种形式，如果你需要多次使用该值，可以避免额外的处理：

```py
{% load static %} 
{% get_static_prefix as STATIC_PREFIX %} 

<img src="img/hi.jpg" alt="Hi!" /> 
<img src="img/hi2.jpg" alt="Hello!" /> 

```

## get_media_prefix

类似于`get_static_prefix`，`get_media_prefix`会用媒体前缀`MEDIA_URL`填充模板变量，例如：

```py
<script type="text/javascript" charset="utf-8"> 
var media_path = '{% get_media_prefix %}'; 
</script> 

```

Django 还附带了一些其他模板标签库，你必须在`INSTALLED_APPS`设置中显式启用它们，并在模板中使用`{% load %}`标签启用它们。
