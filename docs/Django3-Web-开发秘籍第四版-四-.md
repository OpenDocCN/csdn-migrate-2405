# Django3 Web 开发秘籍第四版（四）

> 原文：[`zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200`](https://zh.annas-archive.org/md5/49CC5D4E5506D0966D8746F9F4B56200)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：自定义模板过滤器和标签

在本章中，我们将涵盖以下配方：

+   遵循自己的模板过滤器和标签的约定

+   创建一个模板过滤器以显示自发布以来经过了多少天

+   创建一个模板过滤器来提取第一个媒体对象

+   创建一个模板过滤器以使 URL 更加人性化

+   创建一个模板标签以包含模板（如果存在）

+   创建一个模板标签以在模板中加载 QuerySet

+   创建一个模板标签以将内容解析为模板

+   创建模板标签以修改请求查询参数

# 介绍

Django 具有功能丰富的模板系统，包括模板继承、更改值表示的过滤器和用于表现逻辑的标签等功能。此外，Django 允许您向应用程序添加自定义模板过滤器和标签。自定义过滤器或标签应位于您的应用程序中的`templatetags` Python 包下的模板标签库文件中。然后可以使用`{% load %}`模板标签在任何模板中加载您的模板标签库。在本章中，我们将创建几个有用的过滤器和标签，以便更多地控制模板编辑者。 

# 技术要求

要使用本章的代码，您将需要最新稳定版本的 Python 3，MySQL 或 PostgreSQL 数据库，以及带有虚拟环境的 Django 项目。

您可以在 GitHub 存储库的`ch05`目录中找到本章的所有代码：[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)。

# 遵循自己的模板过滤器和标签的约定

如果没有遵循指南，自定义模板过滤器和标签可能会令人困惑和不一致。拥有方便灵活的模板过滤器和标签对于模板编辑者来说非常重要。在本篇中，我们将看一些增强 Django 模板系统功能时应该使用的约定：

1.  当页面的逻辑更适合于视图、上下文处理器或模型方法时，不要创建或使用自定义模板过滤器或标签。当您的内容是特定于上下文的，例如对象列表或对象详细视图时，在视图中加载对象。如果您需要在几乎每个页面上显示一些内容，请创建上下文处理器。当您需要获取与模板上下文无关的对象的一些属性时，请使用模型的自定义方法而不是模板过滤器。

1.  使用`_tags`后缀命名模板标签库。当您的模板标签库与您的应用程序命名不同时，您可以避免模糊的包导入问题。

1.  在新创建的库中，将过滤器与标签分开，例如使用注释，如下面的代码所示：

```py
# myproject/apps/core/templatetags/utility_tags.py from django import template 

register = template.Library()

""" TAGS """

# Your tags go here…

""" FILTERS """

# Your filters go here…
```

1.  在创建高级自定义模板标签时，确保其语法易于记忆，包括以下可以跟随标签名称的构造：

+   `for [app_name.model_name]`：包括此构造以使用特定模型。

+   `using [template_name]`：包括此构造以使用模板作为模板标签的输出。

+   `limit [count]`：包括此构造以将结果限制为特定数量。

+   `as [context_variable]`：包括此构造以将结果存储在可以多次重用的上下文变量中。

1.  尽量避免在模板标签中定义多个按位置定义的值，除非它们是不言自明的。否则，这可能会使模板开发人员感到困惑。

1.  尽可能使可解析的参数多。没有引号的字符串应被视为需要解析的上下文变量，或者作为提醒模板标签组件结构的简短单词。

# 创建一个模板过滤器以显示自发布以来经过了多少天

在谈论创建或修改日期时，方便阅读更加人性化的时间差异，例如，博客条目是 3 天前发布的，新闻文章是今天发布的，用户上次登录是昨天。在这个示例中，我们将创建一个名为`date_since`的模板过滤器，它将根据天、周、月或年将日期转换为人性化的时间差异。

# 准备工作

如果尚未完成，请创建`core`应用程序，并将其放置在设置中的`INSTALLED_APPS`中。然后，在此应用程序中创建一个`templatetags` Python 包（Python 包是带有空的`__init__.py`文件的目录）。

# 如何做...

创建一个`utility_tags.py`文件，其中包含以下内容：

```py
# myproject/apps/core/templatetags/utility_tags.py from datetime import datetime
from django import template
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

register = template.Library()

""" FILTERS """

DAYS_PER_YEAR = 365
DAYS_PER_MONTH = 30
DAYS_PER_WEEK = 7

@register.filter(is_safe=True)
def date_since(specific_date):
    """
    Returns a human-friendly difference between today and past_date
    (adapted from https://www.djangosnippets.org/snippets/116/)
    """
    today = timezone.now().date()
    if isinstance(specific_date, datetime):
        specific_date = specific_date.date()
    diff = today - specific_date
    diff_years = int(diff.days / DAYS_PER_YEAR)
    diff_months = int(diff.days / DAYS_PER_MONTH)
    diff_weeks = int(diff.days / DAYS_PER_WEEK)
    diff_map = [
        ("year", "years", diff_years,),
        ("month", "months", diff_months,),
        ("week", "weeks", diff_weeks,),
        ("day", "days", diff.days,),
    ]
    for parts in diff_map:
        (interval, intervals, count,) = parts
        if count > 1:
            return _(f"{count} {intervals} ago")
        elif count == 1:
            return _("yesterday") \
                if interval == "day" \
                else _(f"last {interval}")
    if diff.days == 0:
        return _("today")
    else:
        # Date is in the future; return formatted date.
        return f"{specific_date:%B %d, %Y}"

```

# 它是如何工作的...

在模板中使用此过滤器，如下所示的代码将呈现类似于昨天、上周或 5 个月前的内容：

```py
{% load utility_tags %}
{{ object.published|date_since }}
```

您可以将此过滤器应用于`date`和`datetime`类型的值。

每个模板标签库都有一个`template.Library`类型的注册表，其中收集了过滤器和标签。 Django 过滤器是由`@register.filter`装饰器注册的函数。在这种情况下，我们传递了`is_safe=True`参数，以指示我们的过滤器不会引入任何不安全的 HTML 标记。

默认情况下，模板系统中的过滤器将与函数或其他可调用对象的名称相同。如果需要，可以通过将名称传递给装饰器来为过滤器设置不同的名称，如下所示：

```py
@register.filter(name="humanized_date_since", is_safe=True)
def date_since(value):
    # …
```

过滤器本身相当不言自明。首先读取当前日期。如果过滤器的给定值是`datetime`类型，则提取其`date`。然后，根据`DAYS_PER_YEAR`、`DAYS_PER_MONTH`、`DAYS_PER_WEEK`或天数间隔计算今天和提取值之间的差异。根据计数，返回不同的字符串结果，如果值在未来，则返回格式化日期。

# 还有更多...

如果需要，我们也可以覆盖其他时间段，例如 20 分钟前、5 小时前，甚至是 10 年前。为此，我们将在现有的`diff_map`集合中添加更多的间隔，并且为了显示时间差异，我们需要对`datetime`值进行操作，而不是`date`值。

# 另请参阅

+   提取第一个媒体对象的模板过滤器的方法

+   创建一个模板过滤器以使 URL 更加人性化的方法

# 创建一个模板过滤器来提取第一个媒体对象

想象一下，您正在开发一个博客概述页面，对于每篇文章，您希望从内容中显示图像、音乐或视频，这些内容来自内容。在这种情况下，您需要从帖子模型的字段中存储的 HTML 内容中提取`<figure>`、`<img>`、`<object>`、`<embed>`、`<video>`、`<audio>`和`<iframe>`标签。在这个示例中，我们将看到如何使用`first_media`过滤器来执行此操作。

# 准备工作

我们将从`core`应用程序开始，在设置中应设置为`INSTALLED_APPS`，并且应该包含此应用程序中的`templatetags`包。

# 如何做...

在`utility_tags.py`文件中，添加以下内容：

```py
# myproject/apps/core/templatetags/utility_tags.py import re
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

""" FILTERS """

MEDIA_CLOSED_TAGS = "|".join([
    "figure", "object", "video", "audio", "iframe"])
MEDIA_SINGLE_TAGS = "|".join(["img", "embed"])
MEDIA_TAGS_REGEX = re.compile(
    r"<(?P<tag>" + MEDIA_CLOSED_TAGS + ")[\S\s]+?</(?P=tag)>|" +
    r"<(" + MEDIA_SINGLE_TAGS + ")[^>]+>",
    re.MULTILINE)

@register.filter
def first_media(content):
    """
    Returns the chunk of media-related markup from the html content
    """
    tag_match = MEDIA_TAGS_REGEX.search(content)
    media_tag = ""
    if tag_match:
        media_tag = tag_match.group()
    return mark_safe(media_tag)
```

# 它是如何工作的...

如果数据库中的 HTML 内容有效，并且将以下代码放入模板中，则将从对象的内容字段中检索媒体标签；否则，如果未找到媒体，则将返回空字符串：

```py
{% load utility_tags %}
{{ object.content|first_media }} 
```

正则表达式是搜索或替换文本模式的强大功能。首先，我们定义了所有支持的媒体标签名称的列表，将它们分成具有开放和关闭标签（`MEDIA_CLOSED_TAGS`）和自关闭标签（`MEDIA_SINGLE_TAGS`）的组。从这些列表中，我们生成了编译后的正则表达式`MEDIA_TAGS_REGEX`。在这种情况下，我们搜索所有可能的媒体标签，允许它们跨越多行出现。

让我们看看这个正则表达式是如何工作的，如下所示：

+   交替模式由管道（`|`）符号分隔。

+   模式中有两组——首先是那些具有开放和关闭普通标签（`<figure>`，`<object>`，`<video>`，`<audio>`，`<iframe>`和`<picture>`）的标签，然后是最后一个模式，用于所谓的自关闭

或空标签（`<img>`和`<embed>`）。

+   对于可能是多行的普通标签，我们将使用`[\S\s]+?`模式，该模式至少匹配任何符号一次；但是，我们尽可能少地执行这个操作，直到找到它后面的字符串。

+   因此，`<figure[\S\s]+?</figure>`搜索`<figure>`标签的开始以及它后面的所有内容，直到找到`</figure>`标签的闭合。

+   类似地，对于自关闭标签的`[^>]+`模式，我们搜索除右尖括号（可能更为人所知的是大于号符号，即`>`）之外的任何符号，至少一次，尽可能多次，直到遇到指示标签关闭的尖括号。

`re.MULTILINE`标志确保可以找到匹配项，即使它们跨越内容中的多行。然后，在过滤器中，我们使用这个正则表达式模式进行搜索。默认情况下，在 Django 中，任何过滤器的结果都会显示为`<`，`>`和`&`符号转义为`&lt;`，`&gt;`和`&amp;`实体。然而，在这种情况下，我们使用`mark_safe()`函数来指示结果是安全的并且已准备好用于 HTML，以便任何内容都将被呈现而不进行转义。因为原始内容是用户输入，所以我们这样做，而不是在注册过滤器时传递`is_safe=True`，因为我们需要明确证明标记是安全的。

# 还有更多...

如果您对正则表达式感兴趣，可以在官方 Python 文档中了解更多信息[`docs.python.org/3/library/re.html`](https://docs.python.org/3/library/re.html)。

# 另请参阅

+   *创建一个模板过滤器以显示发布后经过多少天*食谱

+   *创建一个模板过滤器以使 URL 更加人性化*食谱

# 创建一个模板过滤器以使 URL 更加人性化

Web 用户通常在地址字段中以不带协议（`http://`）或斜杠（`/`）的方式识别 URL，并且以类似的方式输入 URL。在这个食谱中，我们将创建一个`humanize_url`过滤器，用于以更短的格式向用户呈现 URL，截断非常长的地址，类似于 Twitter 在推文中对链接所做的操作。

# 准备工作

与之前的食谱类似，我们将从`core`应用程序开始，在设置中应该设置`INSTALLED_APPS`，其中包含应用程序中的`templatetags`包。

# 如何做...

在`core`应用程序的`utility_tags.py`模板库的`FILTERS`部分中，让我们添加`humanize_url`过滤器并注册它，如下所示：

```py
# myproject/apps/core/templatetags/utility_tags.py import re
from django import template

register = template.Library()

""" FILTERS """

@register.filter
def humanize_url(url, letter_count=40):
    """
    Returns a shortened human-readable URL
    """
    letter_count = int(letter_count)
    re_start = re.compile(r"^https?://")
    re_end = re.compile(r"/$")
    url = re_end.sub("", re_start.sub("", url))
    if len(url) > letter_count:
        url = f"{url[:letter_count - 1]}…"
    return url
```

# 工作原理...

我们可以在任何模板中使用`humanize_url`过滤器，如下所示：

```py
{% load utility_tags %}
<a href="{{ object.website }}" target="_blank">
    {{ object.website|humanize_url }}
</a>
<a href="{{ object.website }}" target="_blank">
    {{ object.website|humanize_url:30 }}
</a>
```

该过滤器使用正则表达式来删除前导协议和尾部斜杠，将 URL 缩短到给定的字母数量（默认为 40），并在截断后添加省略号，如果完整的 URL 不符合指定的字母数量。例如，对于`https://docs.djangoproject.com/en/3.0/howto/custom-template-tags/`的 URL，40 个字符的人性化版本将是`docs.djangoproject.com/en/3.0/howto/cus…`。

# 另请参阅

+   *创建一个模板过滤器以显示发布后经过多少天*食谱

+   *创建一个模板过滤器以提取第一个媒体对象*食谱

+   *创建一个模板标签以包含模板（如果存在）*食谱

# 创建一个模板标签以包含模板（如果存在）

Django 提供了`{% include %}`模板标签，允许一个模板呈现和包含另一个模板。但是，如果您尝试包含文件系统中不存在的模板，则此模板标签会引发错误。在此食谱中，我们将创建一个`{% try_to_include %}`模板标签，如果存在，则包含另一个模板，并通过渲染为空字符串来静默失败。

# 准备工作

我们将从已安装并准备好自定义模板标签的`core`应用程序开始。

# 如何做...

执行以下步骤创建`{% try_to_include %}`模板标签：

1.  首先，让我们创建解析模板标签参数的函数，如下所示：

```py
# myproject/apps/core/templatetags/utility_tags.py from django import template
from django.template.loader import get_template

register = template.Library()

""" TAGS """

@register.tag
def try_to_include(parser, token):
    """
    Usage: {% try_to_include "some_template.html" %}

    This will fail silently if the template doesn't exist.
    If it does exist, it will be rendered with the current context.
    """
    try:
        tag_name, template_name = token.split_contents()
    except ValueError:
        tag_name = token.contents.split()[0]
        raise template.TemplateSyntaxError(
            f"{tag_name} tag requires a single argument")
    return IncludeNode(template_name)
```

1.  然后，我们需要在同一文件中创建一个自定义的`IncludeNode`类，该类从基本的`template.Node`扩展。让我们在`try_to_include()`函数之前插入它，如下所示：

```py
class IncludeNode(template.Node):
    def __init__(self, template_name):
        self.template_name = template.Variable(template_name)

    def render(self, context):
        try:
            # Loading the template and rendering it
            included_template = self.template_name.resolve(context)
            if isinstance(included_template, str):
                included_template = get_template(included_template)
            rendered_template = included_template.render(
                context.flatten()
            )
        except (template.TemplateDoesNotExist,
                template.VariableDoesNotExist,
                AttributeError):
            rendered_template = ""
        return rendered_template

@register.tag
def try_to_include(parser, token):
    # …
```

# 它是如何工作的...

高级自定义模板标签由两部分组成：

+   解析模板标签参数的函数

+   负责模板标签逻辑和输出的`Node`类

`{% try_to_include %}`模板标签期望一个参数——即`template_name`。因此，在`try_to_include()`函数中，我们尝试将令牌的拆分内容仅分配给`tag_name`变量（即`try_to_include`）和`template_name`变量。如果这不起作用，将引发`TemplateSyntaxError`。该函数返回`IncludeNode`对象，该对象获取`template_name`字段并将其存储在模板`Variable`对象中以供以后使用。

在`IncludeNode`的`render()`方法中，我们解析`template_name`变量。如果上下文变量被传递给模板标签，则其值将在此处用于`template_name`。如果引用的字符串被传递给模板标签，那么引号内的内容将用于`included_template`，而与上下文变量对应的字符串将被解析为其相应的字符串等效。

最后，我们将尝试加载模板，使用解析的`included_template`字符串，并在当前模板上下文中呈现它。如果这不起作用，则返回空字符串。

至少有两种情况可以使用此模板标签：

+   在包含路径在模型中定义的模板时，如下所示：

```py
{% load utility_tags %}
{% try_to_include object.template_path %}
```

+   在模板上下文变量的范围中的某个地方使用`{% with %}`模板标签定义路径的模板。当您需要为 Django CMS 中模板的占位符创建自定义布局时，这是非常有用的：

```py
{# templates/cms/start_page.html #} {% load cms_tags %}
{% with editorial_content_template_path=
"cms/plugins/editorial_content/start_page.html" %}
    {% placeholder "main_content" %}
{% endwith %}
```

稍后，占位符可以使用`editorial_content`插件填充，然后读取`editorial_content_template_path`上下文变量，如果可用，则可以安全地包含模板：

```py
{# templates/cms/plugins/editorial_content.html #}
{% load utility_tags %}
{% if editorial_content_template_path %}
    {% try_to_include editorial_content_template_path %}
{% else %}
    <div>
        <!-- Some default presentation of
        editorial content plugin -->
    </div>
{% endif %}
```

# 还有更多...

您可以在任何组合中使用`{% try_to_include %}`标签和默认的`{% include %}`标签来包含扩展其他模板的模板。这对于大型网络平台非常有益，其中您有不同类型的列表，其中复杂的项目与小部件具有相同的结构，但具有不同的数据来源。

例如，在艺术家列表模板中，您可以包含`artist_item`模板，如下所示：

```py
{% load utility_tags %}
{% for object in object_list %}
    {% try_to_include "artists/includes/artist_item.html" %}
{% endfor %}
```

此模板将从项目基础扩展，如下所示：

```py
{# templates/artists/includes/artist_item.html #} {% extends "utils/includes/item_base.html" %}
{% block item_title %}
    {{ object.first_name }} {{ object.last_name }}
{% endblock %}
```

项目基础定义了任何项目的标记，并包括`Like`小部件，如下所示：

```py
{# templates/utils/includes/item_base.html #} {% load likes_tags %}
<h3>{% block item_title %}{% endblock %}</h3>
{% if request.user.is_authenticated %}
    {% like_widget for object %}
{% endif %}
```

# 另请参阅

+   *在第四章*中实现`Like`小部件的食谱，模板和 JavaScript

+   *创建一个模板标签以在模板中加载 QuerySet*食谱

+   *创建一个将内容解析为模板的模板标签*食谱

+   *创建模板标签以修改请求查询参数*食谱

# 创建一个模板标签以在模板中加载 QuerySet

通常，应在视图中定义应显示在网页上的内容。如果要在每个页面上显示内容，逻辑上应创建上下文处理器以使其全局可用。另一种情况是当您需要在某些页面上显示其他内容，例如最新新闻或随机引用，例如起始页面或对象的详细页面。在这种情况下，您可以使用自定义 `{% load_objects %}` 模板标签加载必要的内容，我们将在本教程中实现。

# 准备工作

我们将再次从 `core` 应用程序开始，该应用程序应已安装并准备好用于自定义模板标签。

此外，为了说明这个概念，让我们创建一个带有 `Article` 模型的 `news` 应用程序，如下所示：

```py
# myproject/apps/news/models.py from django.db import models
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

from myproject.apps.core.models import CreationModificationDateBase, UrlBase

class ArticleManager(models.Manager):
 def random_published(self):
 return self.filter(
 publishing_status=self.model.PUBLISHING_STATUS_PUBLISHED,
 ).order_by("?")

class Article(CreationModificationDateBase, UrlBase):
    PUBLISHING_STATUS_DRAFT, PUBLISHING_STATUS_PUBLISHED = "d", "p"
    PUBLISHING_STATUS_CHOICES = (
        (PUBLISHING_STATUS_DRAFT, _("Draft")),
        (PUBLISHING_STATUS_PUBLISHED, _("Published")),
    )
    title = models.CharField(_("Title"), max_length=200)
    slug = models.SlugField(_("Slug"), max_length=200)
    content = models.TextField(_("Content"))
    publishing_status = models.CharField(
        _("Publishing status"),
        max_length=1,
        choices=PUBLISHING_STATUS_CHOICES,
        default=PUBLISHING_STATUS_DRAFT,
    )

 custom_manager = ArticleManager()

    class Meta:
        verbose_name = _("Article")
        verbose_name_plural = _("Articles")

    def __str__(self):
        return self.title

    def get_url_path(self):
        return reverse("news:article_detail", kwargs={"slug": self.slug})
```

在这里，有趣的部分是 `Article` 模型的 `custom_manager`。该管理器可用于列出随机发布的文章。

使用上一章的示例，您可以完成具有 URL 配置、视图、模板和管理设置的应用程序。然后，使用管理表单向数据库添加一些文章。

# 如何做...

高级自定义模板标签由解析传递给标签的参数的函数和呈现标签输出或修改模板上下文的 `Node` 类组成。执行以下步骤创建 `{% load_objects %}` 模板标签：

1.  首先，让我们创建处理模板标签参数解析的函数，如下所示：

```py
# myproject/apps/core/templatetags/utility_tags.py from django import template
from django.apps import apps

register = template.Library()

""" TAGS """

@register.tag
def load_objects(parser, token):
    """
    Gets a queryset of objects of the model specified by app and
    model names

    Usage:
        {% load_objects [<manager>.]<method>
                        from <app_name>.<model_name>
                        [limit <amount>]
                        as <var_name> %}

    Examples:
        {% load_objects latest_published from people.Person
                        limit 3 as people %}
        {% load_objects site_objects.all from news.Article
                        as articles %}
        {% load_objects site_objects.all from news.Article
                        limit 3 as articles %}
    """
    limit_count = None
    try:
        (tag_name, manager_method,
         str_from, app_model,
         str_limit, limit_count,
         str_as, var_name) = token.split_contents()
    except ValueError:
        try:
            (tag_name, manager_method,
             str_from, app_model,
             str_as, var_name) = token.split_contents()
        except ValueError:
            tag_name = token.contents.split()[0]
            raise template.TemplateSyntaxError(
                f"{tag_name} tag requires the following syntax: "
                f"{{% {tag_name} [<manager>.]<method> from "
                "<app_name>.<model_name> [limit <amount>] "
                "as <var_name> %}")
    try:
        app_name, model_name = app_model.split(".")
    except ValueError:
        raise template.TemplateSyntaxError(
            "load_objects tag requires application name "
            "and model name, separated by a dot")
    model = apps.get_model(app_name, model_name)
    return ObjectsNode(
        model, manager_method, limit_count, var_name
    )
```

1.  然后，我们将在同一文件中创建自定义 `ObjectsNode` 类，扩展自 `template.Node` 基类。让我们在 `load_objects()` 函数之前插入它，如下面的代码所示：

```py
class ObjectsNode(template.Node):
    def __init__(self, model, manager_method, limit, var_name):
        self.model = model
        self.manager_method = manager_method
        self.limit = template.Variable(limit) if limit else None
        self.var_name = var_name

    def render(self, context):
        if "." in self.manager_method:
            manager, method = self.manager_method.split(".")
        else:
            manager = "_default_manager"
            method = self.manager_method

        model_manager = getattr(self.model, manager)
        fallback_method = self.model._default_manager.none
        qs = getattr(model_manager, method, fallback_method)()
        limit = None
        if self.limit:
            try:
                limit = self.limit.resolve(context)
            except template.VariableDoesNotExist:
                limit = None
        context[self.var_name] = qs[:limit] if limit else qs
        return ""

@register.tag
def load_objects(parser, token):
    # …
```

# 它是如何工作的...

`{% load_objects %}` 模板标签加载由管理器方法定义的指定应用程序和模型的 QuerySet，将结果限制为指定的计数，并将结果保存到给定的上下文变量中。

以下代码是如何使用我们刚刚创建的模板标签的简单示例。它将在任何模板中加载所有新闻文章，使用以下代码片段：

```py
{% load utility_tags %}
{% load_objects all from news.Article as all_articles %}
<ul>
    {% for article in all_articles %}
        <li><a href="{{ article.get_url_path }}">
         {{ article.title }}</a></li>
    {% endfor %}
</ul>
```

这是使用 `Article` 模型的默认 `objects` 管理器的 `all()` 方法，并且它将按照模型的 `Meta` 类中定义的 `ordering` 属性对文章进行排序。

接下来是一个示例，使用自定义管理器和自定义方法从数据库中查询对象。管理器是为模型提供数据库查询操作的接口。

每个模型至少有一个默认的名为 `objects` 的管理器。对于我们的 `Article` 模型，我们添加了一个名为 `custom_manager` 的额外管理器，其中包含一个名为 `random_published()` 的方法。以下是我们如何在 `{% load_objects %}` 模板标签中使用它来加载一个随机发布的文章：

```py
{% load utility_tags %}
{% load_objects custom_manager.random_published from news.Article limit 1 as random_published_articles %}
<ul>
    {% for article in random_published_articles %}
        <li><a href="{{ article.get_url_path }}">
         {{ article.title }}</a></li>
    {% endfor %}
</ul>
```

让我们来看一下 `{% load_objects %}` 模板标签的代码。在解析函数中，标签有两种允许的形式——带有或不带有 `limit`。字符串被解析，如果识别格式，则模板标签的组件将传递给 `ObjectsNode` 类。

在 `Node` 类的 `render()` 方法中，我们检查管理器的名称及其方法的名称。如果未指定管理器，则将使用 `_default_manager`。这是 Django 注入的任何模型的自动属性，并指向第一个可用的 `models.Manager()` 实例。在大多数情况下，`_default_manager` 将是 `objects` 管理器。之后，我们将调用管理器的方法，并在方法不存在时回退到空的 QuerySet。如果定义了 `limit`，我们将解析其值并相应地限制 QuerySet。最后，我们将将结果的 QuerySet 存储在上下文变量中，如 `var_name` 所给出的那样。

# 另请参阅

+   *在 Chapter 2*，模型和数据库结构中创建一个带有 URL 相关方法的模型混合的食谱

+   在 Chapter 2*，Models and Database Structure*中的*创建模型混合以处理创建和修改日期*配方

+   在 Chapter 2*，Models and Database Structure*中的*创建一个模板标签以包含模板（如果存在）*配方

+   在 Chapter 2*，Models and Database Structure*中的*创建一个模板标签以将内容解析为模板*配方

+   创建模板标签以修改请求查询参数的配方

# 创建一个模板标签以将内容解析为模板

在这个配方中，我们将创建`{% parse %}`模板标签，它将允许您将模板片段放入数据库。当您想要为经过身份验证和未经身份验证的用户提供不同的内容，当您想要包含个性化的称谓，或者当您不想在数据库中硬编码媒体路径时，这将非常有价值。

# 准备工作

像往常一样，我们将从`core`应用程序开始，该应用程序应该已经安装并准备好用于自定义模板标签。

# 如何做...

高级自定义模板标签由一个解析传递给标签的参数的函数和一个`Node`类组成，该类渲染标签的输出或修改模板上下文。执行以下步骤来创建`{% parse %}`模板标签：

1.  首先，让我们创建解析模板标签参数的函数，如下所示：

```py
# myproject/apps/core/templatetags/utility_tags.py
from django import template

register = template.Library()

""" TAGS """

@register.tag
def parse(parser, token):
    """
    Parses a value as a template and prints or saves to a variable

    Usage:
        {% parse <template_value> [as <variable>] %}

    Examples:
        {% parse object.description %}
        {% parse header as header %}
        {% parse "{{ MEDIA_URL }}js/" as js_url %}
    """
    bits = token.split_contents()
    tag_name = bits.pop(0)
    try:
        template_value = bits.pop(0)
        var_name = None
        if len(bits) >= 2:
            str_as, var_name = bits[:2]
    except ValueError:
        raise template.TemplateSyntaxError(
            f"{tag_name} tag requires the following syntax: "
            f"{{% {tag_name} <template_value> [as <variable>] %}}")
    return ParseNode(template_value, var_name)
```

1.  然后，我们将在同一文件中创建自定义的`ParseNode`类，该类从基本的`template.Node`扩展，如下面的代码所示（将其放在`parse()`函数之前）：

```py
class ParseNode(template.Node):
    def __init__(self, template_value, var_name):
        self.template_value = template.Variable(template_value)
        self.var_name = var_name

    def render(self, context):
        template_value = self.template_value.resolve(context)
        t = template.Template(template_value)
        context_vars = {}
        for d in list(context):
            for var, val in d.items():
                context_vars[var] = val
        req_context = template.RequestContext(
            context["request"], context_vars
        )
        result = t.render(req_context)
        if self.var_name:
            context[self.var_name] = result
            result = ""
        return result

@register.tag
def parse(parser, token):
    # …
```

# 它是如何工作的...

`{% parse %}`模板标签允许您将值解析为模板并立即渲染它，或将其存储在上下文变量中。

如果我们有一个带有描述字段的对象，该字段可以包含模板变量或逻辑，我们可以使用以下代码解析和渲染它：

```py
{% load utility_tags %}
{% parse object.description %}
```

还可以使用引号字符串定义要解析的值，如下面的代码所示：

```py
{% load static utility_tags %}
{% get_static_prefix as STATIC_URL %}
{% parse "{{ STATIC_URL }}site/img/" as image_directory %}
<img src="img/{{ image_directory }}logo.svg" alt="Logo" />
```

让我们来看一下`{% parse %}`模板标签的代码。解析函数逐位检查模板标签的参数。首先，我们期望解析名称和模板值。如果仍然有更多的位于令牌中，我们期望可选的`as`单词后跟上上下文变量名的组合。模板值和可选变量名被传递给`ParseNode`类。

该类的`render()`方法首先解析模板变量的值，并将其创建为模板对象。然后复制`context_vars`并生成请求上下文，模板进行渲染。如果定义了变量名，则将结果存储在其中并渲染一个空字符串；否则，立即显示渲染的模板。

# 另请参阅

+   在 Chapter 2*，Models and Database Structure*中的*创建一个模板标签以包含模板（如果存在）*配方

+   在模板中加载查询集的*创建模板标签*配方

+   在*创建模板标签以修改请求查询参数*配方中

# 创建模板标签以修改请求查询参数

Django 有一个方便灵活的系统，可以通过向 URL 配置文件添加正则表达式规则来创建规范和干净的 URL。然而，缺乏内置技术来管理查询参数。诸如搜索或可过滤对象列表的视图需要接受查询参数，以通过另一个参数深入筛选结果或转到另一页。在这个配方中，我们将创建`{% modify_query %}`、`{% add_to_query %}`和`{% remove_from_query %}`模板标签，让您可以添加、更改或删除当前查询的参数。

# 准备工作

再次，我们从`core`应用程序开始，该应用程序应该在`INSTALLED_APPS`中设置，其中包含`templatetags`包。

还要确保在`OPTIONS`下的`TEMPLATES`设置中将`request`上下文处理器添加到`context_processors`列表中。

```py
# myproject/settings/_base.py
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, "myproject", "templates")],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
 "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "myproject.apps.core.context_processors.website_url",
            ]
        },
    }
]
```

# 如何做...

对于这些模板标签，我们将使用`@simple_tag`装饰器来解析组件，并要求您只需定义呈现函数，如下所示：

1.  首先，让我们添加一个辅助方法来组合每个标签输出的查询字符串：

```py
# myproject/apps/core/templatetags/utility_tags.py from urllib.parse import urlencode

from django import template
from django.utils.encoding import force_str
from django.utils.safestring import mark_safe

register = template.Library()

""" TAGS """

def construct_query_string(context, query_params):
    # empty values will be removed
    query_string = context["request"].path
    if len(query_params):
        encoded_params = urlencode([
            (key, force_str(value))
            for (key, value) in query_params if value
        ]).replace("&", "&amp;")
        query_string += f"?{encoded_params}"
    return mark_safe(query_string)
```

1.  然后，我们将创建`{% modify_query %}`模板标签：

```py
@register.simple_tag(takes_context=True)
def modify_query(context, *params_to_remove, **params_to_change):
    """Renders a link with modified current query parameters"""
    query_params = []
    for key, value_list in context["request"].GET.lists():
        if not key in params_to_remove:
            # don't add key-value pairs for params_to_remove
            if key in params_to_change:
                # update values for keys in params_to_change
                query_params.append((key, params_to_change[key]))
                params_to_change.pop(key)
            else:
                # leave existing parameters as they were
                # if not mentioned in the params_to_change
                for value in value_list:
                    query_params.append((key, value))
                    # attach new params
    for key, value in params_to_change.items():
        query_params.append((key, value))
    return construct_query_string(context, query_params)
```

1.  接下来，让我们创建`{% add_to_query %}`模板标签：

```py
@register.simple_tag(takes_context=True)
def add_to_query(context, *params_to_remove, **params_to_add):
    """Renders a link with modified current query parameters"""
    query_params = []
    # go through current query params..
    for key, value_list in context["request"].GET.lists():
        if key not in params_to_remove:
            # don't add key-value pairs which already
            # exist in the query
            if (key in params_to_add
                    and params_to_add[key] in value_list):
                params_to_add.pop(key)
            for value in value_list:
                query_params.append((key, value))
    # add the rest key-value pairs
    for key, value in params_to_add.items():
        query_params.append((key, value))
    return construct_query_string(context, query_params)
```

1.  最后，让我们创建`{% remove_from_query %}`模板标签：

```py
@register.simple_tag(takes_context=True)
def remove_from_query(context, *args, **kwargs):
    """Renders a link with modified current query parameters"""
    query_params = []
    # go through current query params..
    for key, value_list in context["request"].GET.lists():
        # skip keys mentioned in the args
        if key not in args:
            for value in value_list:
                # skip key-value pairs mentioned in kwargs
                if not (key in kwargs and
                        str(value) == str(kwargs[key])):
                    query_params.append((key, value))
    return construct_query_string(context, query_params)
```

# 工作原理...

所有三个创建的模板标签的行为都类似。首先，它们从`request.GET`字典样的`QueryDict`对象中读取当前查询参数，然后将其转换为新的（键，值）`query_params`元组列表。然后，根据位置参数和关键字参数更新值。最后，通过首先定义的辅助方法形成新的查询字符串。在此过程中，所有空格和特殊字符都被 URL 编码，并且连接查询参数的和号被转义。将此新的查询字符串返回到模板。

要了解有关`QueryDict`对象的更多信息，请参阅官方 Django 文档

在[`docs.djangoproject.com/en/3.0/ref/request-response/#querydict-objects`](https://docs.djangoproject.com/en/3.0/ref/request-response/#querydict-objects)。

让我们看一个示例，演示了`{% modify_query %}`模板标签的用法。模板标签中的位置参数定义要删除哪些查询参数，关键字参数定义要在当前查询中更新哪些查询参数。如果当前 URL 是`http://127.0.0.1:8000/artists/?category=fine-art&page=5`，我们可以使用以下模板标签呈现一个转到下一页的链接：

```py
{% load utility_tags %}
<a href="{% modify_query page=6 %}">6</a>
```

使用前述模板标签呈现的输出如下代码段所示：

```py
<a href="/artists/?category=fine-art&amp;page=6">6</a>
```

我们还可以使用以下示例来呈现一个重置分页并转到另一个类别`sculpture`的链接，如下所示：

```py
{% load utility_tags %}
<a href="{% modify_query "page" category="sculpture" %}">
    Sculpture
</a>
```

因此，使用前述模板标签呈现的输出将如下代码段所示：

```py
<a href="/artists/?category=sculpture">
    Sculpture
</a>
```

使用`{% add_to_query %}`模板标签，您可以逐步添加具有相同名称的参数。例如，如果当前 URL 是`http://127.0.0.1:8000/artists/?category=fine-art`，您可以使用以下代码段添加另一个类别`Sculpture`：

```py
{% load utility_tags %}
<a href="{% add_to_query category="sculpture" %}">
    + Sculpture
</a> 
```

这将在模板中呈现，如下代码段所示：

```py
<a href="/artists/?category=fine-art&amp;category=sculpture">
    + Sculpture
</a>
```

最后，借助`{% remove_from_query %}`模板标签的帮助，您可以逐步删除具有相同名称的参数。例如，如果当前 URL 是`http://127.0.0.1:8000/artists/?category=fine-art&category=sculpture`，您可以使用以下代码段删除`Sculpture`类别：

```py
{% load utility_tags %}
<a href="{% remove_from_query category="sculpture" %}">
    - Sculpture
</a>
```

这将在模板中呈现如下：

```py
<a href="/artists/?category=fine-art">
    - Sculpture
</a>
```

# 另请参阅

+   第三章*中的*对象列表过滤器*配方，表单和视图

+   *创建一个模板标签来包含模板（如果存在）*配方

+   *创建一个模板标签来在模板中加载 QuerySet*配方

+   *创建一个模板标签来解析内容作为模板*配方


# 第六章：模型管理

在本章中，我们将涵盖以下主题：

+   在更改列表页面上自定义列

+   创建可排序的内联

+   创建管理操作

+   开发更改列表过滤器

+   更改第三方应用程序的应用程序标签

+   创建自定义帐户应用

+   获取用户 Gravatars

+   将地图插入更改表单

# 介绍

Django 框架提供了一个内置的管理系统，用于数据模型。通过很少的努力，您可以设置可过滤、可搜索和可排序的列表，以浏览您的模型，并且可以配置表单以添加和管理数据。在本章中，我们将通过开发一些实际案例来介绍我们可以使用的高级技术来自定义管理。

# 技术要求

要使用本章中的代码，您需要最新稳定版本的 Python，一个 MySQL 或 PostgreSQL 数据库，以及一个带有虚拟环境的 Django 项目。

您可以在本书的 GitHub 存储库的`chapter 06`目录中找到本章的所有代码：[`github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition`](https://github.com/PacktPublishing/Django-3-Web-Development-Cookbook-Fourth-Edition)

# 在更改列表页面上自定义列

默认的 Django 管理系统中的更改列表视图提供了特定模型的所有实例的概述。默认情况下，`list_display`模型管理属性控制在不同列中显示的字段。此外，您还可以实现自定义管理方法，该方法将返回关系的数据或显示自定义 HTML。在本示例中，我们将创建一个特殊函数，用于`list_display`属性，该函数将在列表视图的一列中显示图像。作为奖励，我们将通过添加`list_editable`设置使一个字段直接在列表视图中可编辑。

# 准备工作

对于本示例，我们将需要`Pillow`和`django-imagekit`库。让我们使用以下命令在虚拟环境中安装它们：

```py
(env)$ pip install Pillow
(env)$ pip install django-imagekit
```

确保在设置中`INSTALLED_APPS`中包含`django.contrib.admin`和`imagekit`：

```py
# myproject/settings/_base.py
INSTALLED_APPS = [
   # …
   "django.contrib.admin",
   "imagekit",
]
```

然后，在 URL 配置中连接管理站点，如下所示：

```py
# myproject/urls.py
from django.contrib import admin
from django.conf.urls.i18n import i18n_patterns
from django.urls import include, path

urlpatterns = i18n_patterns(
    # …
    path("admin/", admin.site.urls),
)
```

接下来，创建一个新的`products`应用程序，并将其放在`INSTALLED_APPS`下。此应用程序将包含`Product`和`ProductPhoto`模型。在这里，一个产品可能有多张照片。例如，我们还将使用在第二章的*创建具有 URL 相关方法的模型 mixin*食谱中定义的`UrlMixin`。

让我们在`models.py`文件中创建`Product`和`ProductPhoto`模型，如下所示：

```py
# myproject/apps/products/models.py import os

from django.urls import reverse, NoReverseMatch
from django.db import models
from django.utils.timezone import now as timezone_now
from django.utils.translation import ugettext_lazy as _

from ordered_model.models import OrderedModel

from myproject.apps.core.models import UrlBase

def product_photo_upload_to(instance, filename):
    now = timezone_now()
    slug = instance.product.slug
    base, ext = os.path.splitext(filename)
    return f"products/{slug}/{now:%Y%m%d%H%M%S}{ext.lower()}"

class Product(UrlBase):
    title = models.CharField(_("title"), max_length=200)
    slug = models.SlugField(_("slug"), max_length=200)
    description = models.TextField(_("description"), blank=True)
    price = models.DecimalField(
        _("price (EUR)"), max_digits=8, decimal_places=2, 
         blank=True, null=True
    )

    class Meta:
        verbose_name = _("Product")
        verbose_name_plural = _("Products")

    def get_url_path(self):
        try:
            return reverse("product_detail", kwargs={"slug": self.slug})
        except NoReverseMatch:
            return ""

    def __str__(self):
        return self.title

class ProductPhoto(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    photo = models.ImageField(_("photo"), 
     upload_to=product_photo_upload_to)

    class Meta:
        verbose_name = _("Photo")
        verbose_name_plural = _("Photos")

    def __str__(self):
        return self.photo.name
```

# 如何做...

在本示例中，我们将为`Product`模型创建一个简单的管理，该管理将具有附加到产品的`ProductPhoto`模型的实例。

在`list_display`属性中，我们将包括模型管理的`first_photo()`方法，该方法将用于显示一对多关系中的第一张照片。所以，让我们开始：

1.  让我们创建一个包含以下内容的`admin.py`文件：

```py
# myproject/apps/products/admin.py from django.contrib import admin
from django.template.loader import render_to_string
from django.utils.html import mark_safe
from django.utils.translation import ugettext_lazy as _

from .models import Product, ProductPhoto

class ProductPhotoInline(admin.StackedInline):
    model = ProductPhoto
    extra = 0
    fields = ["photo"]
```

1.  然后，在同一个文件中，让我们为产品添加管理：

```py
@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ["first_photo", "title", "has_description", 
     "price"]
    list_display_links = ["first_photo", "title"]
    list_editable = ["price"]

    fieldsets = ((_("Product"), {"fields": ("title", "slug", 
     "description", "price")}),)
    prepopulated_fields = {"slug": ("title",)}
    inlines = [ProductPhotoInline]

def first_photo(self, obj):
        project_photos = obj.productphoto_set.all()[:1]
         if project_photos.count() > 0:
 photo_preview = render_to_string(
           "admin/products/includes/photo-preview.html",
             {"photo": project_photos[0], "product": obj},
            )
           return mark_safe(photo_preview)
         return ""

    first_photo.short_description = _("Preview")

def has_description(self, obj):
return bool(obj.description)

    has_description.short_description = _("Has description?")
    has_description.admin_order_field = "description"
    has_description.boolean = True
```

1.  现在，让我们创建将用于生成`photo-preview`的模板，如下所示：

```py
{# admin/products/includes/photo-preview.html #} {% load imagekit %}
{% thumbnail "120x120" photo.photo -- alt=
 "{{ product.title }} preview" %}
```

# 它是如何工作的...

如果您添加了一些带有照片的产品，然后在浏览器中查看产品管理列表，它将类似于以下截图：

！[](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/d14311ca-f563-4422-bb00-8eb990292a4f.png)

`list_display`属性通常用于定义字段，以便它们在管理列表视图中显示；例如，`TITLE`和`PRICE`是`Product`模型的字段。除了正常的字段名称之外，`list_display`属性还接受以下内容：

+   一个函数，或者另一个可调用的

+   模型管理类的属性名称

+   模型的属性名称

在`list_display`中使用可调用函数时，每个函数都将模型实例作为第一个参数传递。因此，在我们的示例中，我们在模型管理类中定义了`get_photo()`方法，该方法将`Product`实例作为`obj`接收。该方法尝试从一对多关系中获取第一个`ProductPhoto`对象，如果存在，则返回从包含`<img>`标签的包含模板生成的 HTML。通过设置`list_display_links`，我们使照片和标题都链接到`Product`模型的管理更改表单。

您可以为在`list_display`中使用的可调用函数设置多个属性：

+   可调用的`short_description`属性定义了列顶部显示的标题。

+   默认情况下，可调用返回的值在管理中是不可排序的，但可以设置`admin_order_field`属性来定义应该按哪个数据库字段对生成的列进行排序。可选地，您可以使用连字符前缀来指示反向排序顺序。

+   通过设置`boolean = True`，您可以显示`True`或`False`值的图标。

最后，如果我们将 PRICE 字段包含在`list_editable`设置中，它可以被编辑。由于现在有可编辑字段，底部将出现一个保存按钮，以便我们可以保存整个产品列表。

# 另请参阅

+   *使用 URL 相关方法创建模型 mixin*配方在第二章*，模型和数据库结构*

+   *创建管理操作*配方

+   *开发更改列表过滤器*配方

# 创建可排序的内联

您将希望对数据库中的大多数模型按创建日期、发生日期或按字母顺序进行排序。但有时，用户必须能够以自定义排序顺序显示项目。这适用于类别、图库、策划列表和类似情况。在这个配方中，我们将向您展示如何使用`django-ordered-model`在管理中允许自定义排序。

# 准备工作

在这个配方中，我们将在之前的配方中定义的`products`应用程序的基础上构建。按照以下步骤开始：

1.  让我们在虚拟环境中安装`django-ordered-model`：

```py
(env)$ pip install django-ordered-model 
```

1.  在设置中将`ordered_model`添加到`INSTALLED_APPS`中。

1.  然后，修改之前定义的`products`应用程序中的`ProductPhoto`模型，如下所示：

```py
# myproject/apps/products/models.py from django.db import models
from django.utils.translation import ugettext_lazy as _

from ordered_model.models import OrderedModel

# …

class ProductPhoto(OrderedModel):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    photo = models.ImageField(_("photo"), 
     upload_to=product_photo_upload_to)

order_with_respect_to = "product" 
    class Meta(OrderedModel.Meta):
        verbose_name = _("Photo")
        verbose_name_plural = _("Photos")

def __str__(self):
return self.photo.name
```

`OrderedModel`类引入了一个`order`字段。创建并运行迁移，将新的`order`字段添加到数据库中的`ProductPhoto`。

# 如何做...

要设置可排序的产品照片，我们需要修改`products`应用程序的模型管理。让我们开始吧：

1.  在管理文件中修改`ProductPhotoInline`，如下所示：

```py
# myproject/apps/products/admin.py from django.contrib import admin
from django.template.loader import render_to_string
from django.utils.html import mark_safe
from django.utils.translation import ugettext_lazy as _
from ordered_model.admin import OrderedTabularInline, OrderedInlineModelAdminMixin

from .models import Product, ProductPhoto

class ProductPhotoInline(OrderedTabularInline):
    model = ProductPhoto
    extra = 0
    fields = ("photo_preview", "photo", "order", 
    "move_up_down_links")
    readonly_fields = ("photo_preview", "order", 
    "move_up_down_links")
    ordering = ("order",)

    def get_photo_preview(self, obj):
 photo_preview = render_to_string(
 "admin/products/includes/photo-preview.html",
 {"photo": obj, "product": obj.product},
 )
 return mark_safe(photo_preview)

 get_photo_preview.short_description = _("Preview")
```

1.  然后，修改`ProductAdmin`如下：

```py
@admin.register(Product)
class ProductAdmin(OrderedInlineModelAdminMixin, admin.ModelAdmin):
    # …
```

# 它是如何工作的...

如果您打开更改产品表单，您将看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/11c19c3c-8124-4f8d-b852-5c08271d85fa.png)

在模型中，我们设置了`order_with_respect_to`属性，以确保对每个产品进行排序，而不仅仅是对产品照片的整个列表进行排序。

在 Django 管理中，产品照片可以通过将产品详细信息本身作为表格内联来进行编辑。在第一列中，我们有一个照片预览。我们使用与之前配方中使用的相同的`photo-preview.html`模板来生成它。在第二列中，有一个用于更改照片的字段。然后，有一个用于 ORDER 字段的列，旁边是一个带有箭头按钮的列，以便我们可以手动重新排序照片。箭头按钮来自`move_up_down_links`方法。最后，有一个带有复选框的列，以便我们可以删除内联。

`readonly_fields`属性告诉 Django，某些字段或方法仅用于阅读。如果要使用另一种方法在更改表单中显示某些内容，必须将这些方法放在`readonly_fields`列表中。在我们的情况下，`get_photo_preview`和`move_up_down_links`就是这样的方法。

`move_up_down_links`在`OrderedTabularInline`中定义，我们正在扩展它而不是`admin.StackedInline`或`admin.TabularInline`。这样可以渲染箭头按钮，使它们在产品照片中交换位置。

# 另请参阅

+   *自定义更改列表页面上的列*食谱

+   *创建管理操作*食谱

+   *开发更改列表过滤器*食谱

# 创建管理操作

Django 管理系统提供了可以为列表中的选定项目执行的操作。默认情况下提供了一个操作，用于删除选定的实例。在这个食谱中，我们将为`Product`模型的列表创建一个额外的操作，允许管理员将选定的产品导出到 Excel 电子表格中。

# 准备工作

我们将从前面的食谱中创建的`products`应用程序开始。确保您的虚拟环境中安装了`openpyxl`模块，以便创建 Excel 电子表格，如下所示：

```py
(env)$ pip install openpyxl
```

# 如何做...

管理操作是带有三个参数的函数，如下所示：

+   当前的`ModelAdmin`值

+   当前的`HttpRequest`值

+   包含所选项目的`QuerySet`值

执行以下步骤创建自定义管理操作以导出电子表格：

1.  在`products`应用程序的`admin.py`文件中为电子表格列配置创建`ColumnConfig`类，如下所示：

```py
# myproject/apps/products/admin.py from openpyxl import Workbook
from openpyxl.styles import Alignment, NamedStyle, builtins
from openpyxl.styles.numbers import FORMAT_NUMBER
from openpyxl.writer.excel import save_virtual_workbook

from django.http.response import HttpResponse
from django.utils.translation import ugettext_lazy as _
from ordered_model.admin import OrderedTabularInline, OrderedInlineModelAdminMixin

# other imports…

class ColumnConfig:
    def __init__(
            self,
            heading,
            width=None,
            heading_style="Headline 1",
            style="Normal Wrapped",
            number_format=None,
         ):
        self.heading = heading
        self.width = width
        self.heading_style = heading_style
        self.style = style
        self.number_format = number_format
```

1.  然后，在同一个文件中，创建`export_xlsx()`函数：

```py
def export_xlsx(modeladmin, request, queryset):
    wb = Workbook()
    ws = wb.active
    ws.title = "Products"

    number_alignment = Alignment(horizontal="right")
    wb.add_named_style(
        NamedStyle(
            "Identifier", alignment=number_alignment, 
             number_format=FORMAT_NUMBER
        )
    )
    wb.add_named_style(
        NamedStyle("Normal Wrapped", 
         alignment=Alignment(wrap_text=True))
    )

    column_config = {
        "A": ColumnConfig("ID", width=10, style="Identifier"),
        "B": ColumnConfig("Title", width=30),
        "C": ColumnConfig("Description", width=60),
        "D": ColumnConfig("Price", width=15, style="Currency", 
             number_format="#,##0.00 €"),
        "E": ColumnConfig("Preview", width=100, style="Hyperlink"),
    }

    # Set up column widths, header values and styles
    for col, conf in column_config.items():
        ws.column_dimensions[col].width = conf.width

        column = ws[f"{col}1"]
        column.value = conf.heading
        column.style = conf.heading_style

    # Add products
    for obj in queryset.order_by("pk"):
        project_photos = obj.productphoto_set.all()[:1]
        url = ""
        if project_photos:
            url = project_photos[0].photo.url

        data = [obj.pk, obj.title, obj.description, obj.price, url]
        ws.append(data)

        row = ws.max_row
        for row_cells in ws.iter_cols(min_row=row, max_row=row):
            for cell in row_cells:
                conf = column_config[cell.column_letter]
                cell.style = conf.style
                if conf.number_format:
                    cell.number_format = conf.number_format

    mimetype = "application/vnd.openxmlformats-
     officedocument.spreadsheetml.sheet"
    charset = "utf-8"
    response = HttpResponse(
        content=save_virtual_workbook(wb),
        content_type=f"{mimetype}; charset={charset}",
        charset=charset,
    )
    response["Content-Disposition"] = "attachment; 
     filename=products.xlsx"
    return response

export_xlsx.short_description = _("Export XLSX")
```

1.  然后，将`actions`设置添加到`ProductAdmin`中，如下所示：

```py
@admin.register(Product)
class ProductAdmin(OrderedInlineModelAdminMixin, admin.ModelAdmin):
    # …
 actions = [export_xlsx]
    # …
```

# 它是如何工作的...

如果您在浏览器中查看产品管理列表页面，您将看到一个名为 Export XLSX 的新操作，以及默认的 Delete selected Products 操作，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/ae598c42-d15a-4aef-a26d-1c24e63d4537.png)

我们使用`openpyxl` Python 模块创建与 Excel 和其他电子表格软件兼容的 OpenOffice XML 文件。

首先创建一个工作簿，并选择活动工作表，为其设置标题为`Products`。因为有一些通用样式，我们希望在整个工作表中使用，所以这些样式被设置为命名样式，这样它们可以按名称应用到每个单元格中。这些样式、列标题和列宽度被存储为`Config`对象，并且`column_config`字典将列字母键映射到对象。然后迭代设置标题和列宽度。

我们使用工作表的`append()`方法为`QuerySet`中的每个选定产品添加内容，按 ID 排序，包括产品的第一张照片的 URL（如果有照片）。然后通过迭代刚添加的行中的每个单元格来单独设置产品数据的样式，再次参考`column_config`以保持样式一致。

默认情况下，管理操作对`QuerySet`执行某些操作，并将管理员重定向回更改列表页面。但是，对于更复杂的操作，可以返回`HttpResponse`。`export_xlsx()`函数将工作簿的虚拟副本保存到`HttpResponse`中，内容类型和字符集适合**Office Open XML**（**OOXML**）电子表格。使用`Content-Disposition`标头，我们设置响应以便可以将其下载为`products.xlsx`文件。生成的工作表可以在 Open Office 中打开，并且看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/85faa318-6a66-4cc2-9cb2-14950f5e4f76.png)

# 另请参阅

+   *自定义更改列表页面上的列*食谱

+   *开发更改列表过滤器*食谱

+   第九章*，导入和导出数据*

# 开发更改列表过滤器

如果您希望管理员能够按日期、关系或字段选择过滤更改列表，您必须使用 admin 模型的`list_filter`属性。此外，还有可能有定制的过滤器。在本教程中，我们将添加一个过滤器，允许我们按附加到产品的照片数量进行选择。

# 准备工作

让我们从我们在之前的教程中创建的`products`应用程序开始。

# 如何做...

执行以下步骤：

1.  在`admin.py`文件中，创建一个`PhotoFilter`类，该类扩展自`SimpleListFilter`，如下所示：

```py
# myproject/apps/products/admin.py
from django.contrib import admin
from django.db import models
from django.utils.translation import ugettext_lazy as _

# other imports…

ZERO = "zero"
ONE = "one"
MANY = "many"

class PhotoFilter(admin.SimpleListFilter):
    # Human-readable title which will be displayed in the
    # right admin sidebar just above the filter options.
    title = _("photos")

    # Parameter for the filter that will be used in the
    # URL query.
    parameter_name = "photos"

    def lookups(self, request, model_admin):
        """
        Returns a list of tuples, akin to the values given for
        model field choices. The first element in each tuple is the
        coded value for the option that will appear in the URL
        query. The second element is the human-readable name for
        the option that will appear in the right sidebar.
        """
        return (
            (ZERO, _("Has no photos")),
            (ONE, _("Has one photo")),
            (MANY, _("Has more than one photo")),
        )

    def queryset(self, request, queryset):
        """
        Returns the filtered queryset based on the value
        provided in the query string and retrievable via
        `self.value()`.
        """
        qs = queryset.annotate(num_photos=
         models.Count("productphoto"))

        if self.value() == ZERO:
            qs = qs.filter(num_photos=0)
        elif self.value() == ONE:
            qs = qs.filter(num_photos=1)
        elif self.value() == MANY:
            qs = qs.filter(num_photos__gte=2)
        return qs
```

1.  然后，在`ProductAdmin`中添加一个列表过滤器，如下所示：

```py
@admin.register(Product)
class ProductAdmin(OrderedInlineModelAdminMixin, admin.ModelAdmin):
    # …
    list_filter = [PhotoFilter]
    # …
```

# 工作原理...

基于我们刚刚创建的自定义字段的列表过滤器将显示在产品列表的侧边栏中，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/ca4b4b04-eecf-40ee-b6c2-b4f3f61129ec.png)

`PhotoFilter`类具有可翻译的标题和查询参数名称作为属性。它还有两种方法，如下所示：

+   `lookups()`方法，定义了过滤器的选择

+   `queryset()`方法，定义了如何在选择特定值时过滤`QuerySet`对象

在`lookups()`方法中，我们定义了三个选择，如下所示：

+   没有照片

+   有一张照片

+   有多张照片附加

在`queryset()`方法中，我们使用`QuerySet`的`annotate()`方法来选择每个产品的照片数量。然后根据所选的选择进行过滤。

要了解有关聚合函数（如`annotate()`）的更多信息，请参阅官方 Django 文档[`docs.djangoproject.com/en/3.0/topics/db/aggregation/`](https://docs.djangoproject.com/en/3.0/topics/db/aggregation/)。

# 另请参阅

+   *自定义更改列表页面上的列*教程

+   *创建管理员操作*教程

+   *创建自定义帐户应用程序*教程

# 更改第三方应用程序的应用程序标签

Django 框架有很多第三方应用程序可以在项目中使用。您可以在[`djangopackages.org/`](https://djangopackages.org/)上浏览和比较大多数应用程序。在本教程中，我们将向您展示如何在管理中重命名`python-social-auth`应用程序的标签。类似地，您可以更改任何 Django 第三方应用程序的标签。

# 准备工作

按照[`python-social-auth.readthedocs.io/en/latest/configuration/django.html`](https://python-social-auth.readthedocs.io/en/latest/configuration/django.html)上的说明将 Python Social Auth 安装到您的项目中。Python Social Auth 允许用户使用社交网络帐户或其 Open ID 登录。完成后，管理页面的索引页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/828e2e92-06ce-4cb5-b807-1216415cb22a.png)

# 如何做...

首先，将 PYTHON SOCIAL AUTH 标签更改为更用户友好的内容，例如 SOCIAL AUTHENTICATION。现在，请按照以下步骤进行操作：

1.  创建一个名为`accounts`的应用程序。在那里的`apps.py`文件中，添加以下内容：

```py
# myproject/apps/accounts/apps.py
from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _

class AccountsConfig(AppConfig):
    name = "myproject.apps.accounts"
    verbose_name = _("Accounts")

    def ready(self):
        pass

class SocialDjangoConfig(AppConfig):
 name = "social_django"
    verbose_name = _("Social Authentication")
```

1.  设置 Python Social Auth 的一个步骤涉及将`"social_django"`应用添加到`INSTALLED_APPS`中。现在，请将该应用替换为`"myproject.apps.accounts.apps.SocialDjangoConfig"`：

```py
# myproject/settings/_base.py # …
INSTALLED_APPS = [
    # …
    #"social_django",
    "myproject.apps.accounts.apps.SocialDjangoConfig",
    # …
]
```

# 工作原理...

如果您检查管理的索引页面，您将看到类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/ed96a18a-c5ab-44ed-b35f-5b191f230566.png)

`INSTALLED_APPS`设置接受应用程序的路径或应用程序配置的路径。我们可以传递应用程序配置而不是默认的应用程序路径。在那里，我们更改应用程序的显示名称，甚至可以应用一些信号处理程序或对应用程序进行一些其他初始设置。

# 另请参阅

+   *创建自定义帐户应用程序*教程

+   *获取用户 Gravatars*教程

# 创建自定义帐户应用程序

Django 自带了一个用于身份验证的`django.contrib.auth`应用程序。它允许用户使用他们的用户名和密码登录以使用管理功能，例如。这个应用程序被设计成可以通过您自己的功能进行扩展。在这个示例中，我们将创建自定义用户和角色模型，并为它们设置管理。您将能够通过电子邮件和密码而不是用户名和密码进行登录。

# 准备工作

创建一个`accounts`应用程序，并将该应用程序放在设置的`INSTALLED_APPS`下：

```py
# myproject/apps/_base.py
INSTALLED_APPS = [
   # …
   "myproject.apps.accounts",
]
```

# 如何做...

按照以下步骤覆盖用户和组模型：

1.  在`accounts`应用程序中创建`models.py`，内容如下：

```py
# myproject/apps/accounts/models.py import uuid

from django.contrib.auth.base_user import BaseUserManager
from django.db import models
from django.contrib.auth.models import AbstractUser, Group
from django.utils.translation import ugettext_lazy as _

class Role(Group):
    class Meta:
        proxy = True
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")

    def __str__(self):
        return self.name

class UserManager(BaseUserManager):
    def create_user(self, username="", email="", password="", 
     **extra_fields):
        if not email:
            raise ValueError("Enter an email address")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, 
         **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username="", email="", password=""):
        user = self.create_user(email=email, password=password, 
         username=username)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user

class User(AbstractUser):
    uuid = models.UUIDField(primary_key=True, default=None, 
     editable=False)
    # change username to non-editable non-required field
    username = models.CharField(
        _("username"), max_length=150, editable=False, blank=True
    )
    # change email to unique and required field
    email = models.EmailField(_("email address"), unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.pk = uuid.uuid4()
        super().save(*args, **kwargs)
```

1.  在`accounts`应用程序中创建`admin.py`文件，其中包含`User`模型的管理配置：

```py
# myproject/apps/accounts/admin.py
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin, Group, GroupAdmin
from django.urls import reverse
from django.contrib.contenttypes.models import ContentType
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.encoding import force_bytes
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.forms import UserCreationForm

from .helpers import download_avatar
from .models import User, Role

class MyUserCreationForm(UserCreationForm):
    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = user.email
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

@admin.register(User)
class MyUserAdmin(UserAdmin):
    save_on_top = True
    list_display = [
        "get_full_name",
        "is_active",
        "is_staff",
        "is_superuser",
    ]
    list_display_links = [
        "get_full_name",
    ]
    search_fields = ["email", "first_name", "last_name", "id", 
     "username"]
    ordering = ["-is_superuser", "-is_staff", "last_name", 
     "first_name"]

    fieldsets = [
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("first_name", 
         "last_name")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (_("Important dates"), {"fields": ("last_login", 
         "date_joined")}),
    ]
    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("email", 
         "password1", "password2")}),
    )
    add_form = MyUserCreationForm

    def get_full_name(self, obj):
        return obj.get_full_name()

    get_full_name.short_description = _("Full name")

```

1.  在同一文件中，为`Role`模型添加配置：

```py
admin.site.unregister(Group)

@admin.register(Role)
class MyRoleAdmin(GroupAdmin):
    list_display = ("__str__", "display_users")
    save_on_top = True

    def display_users(self, obj):
        links = []
        for user in obj.user_set.all():
            ct = ContentType.objects.get_for_model(user)
            url = reverse(
                "admin:{}_{}_change".format(ct.app_label, 
                  ct.model), args=(user.pk,)
            )
            links.append(
                """<a href="{}" target="_blank">{}</a>""".format(
                    url,
                    user.get_full_name() or user.username,
                )
            )
        return mark_safe(u"<br />".join(links))

    display_users.short_description = _("Users")
```

# 工作原理...

默认的用户管理列表看起来类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/0f12f73f-ee33-4eef-995b-e509b0d8d735.png)

默认的组管理列表看起来类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/a142a4a5-3f57-40b6-9387-f275500e616d.png)

在这个示例中，我们创建了两个模型：

+   `Role`模型是`django.contrib.auth`应用程序中`Group`模型的代理。`Role`模型被创建来将`Group`的显示名称重命名为`Role`。

+   `User`模型，它扩展了与`django.contrib.auth`中的`User`模型相同的抽象`AbstractUser`类。`User`模型被创建来用`UUIDField`替换主键，并允许我们通过电子邮件和密码而不是用户名和密码进行登录。

管理类`MyUserAdmin`和`MyRoleAdmin`扩展了贡献的`UserAdmin`和`GroupAdmin`类，并覆盖了一些属性。然后，我们取消注册了现有的`User`和`Group`模型的管理类，并注册了新的修改后的管理类。

以下屏幕截图显示了用户管理的外观：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/6433a0e7-b052-45b9-be81-5a8f7b747266.png)

修改后的用户管理设置在列表视图中显示了更多字段，还有额外的过滤和排序选项，并在编辑表单顶部有提交按钮。

在新的组管理设置的更改列表中，我们将显示那些已被分配到特定组的用户。在浏览器中，这将类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/516c43fe-6b6d-47e7-879e-989fe89765cf.png)

# 另请参阅

+   *自定义更改列表页面上的列*示例

+   *在更改表单中插入地图*示例

# 获取用户 Gravatars

现在我们已经开始使用自定义的`User`模型进行身份验证，我们可以通过添加更多有用的字段来进一步增强它。在这个示例中，我们将添加一个`avatar`字段，并且可以从 Gravatar 服务（[`en.gravatar.com/`](https://en.gravatar.com/)）下载用户的头像。该服务的用户可以上传头像并将其分配给他们的电子邮件。通过这样做，不同的评论系统和社交平台将能够根据用户电子邮件的哈希值从 Gravatar 显示这些头像。

# 准备工作

让我们继续使用之前创建的`accounts`应用程序。

# 如何做...

按照以下步骤增强`accounts`应用程序中的`User`模型：

1.  为`User`模型添加`avatar`字段和`django-imagekit`缩略图规范：

```py
# myproject/apps/accounts/models.py import os

from imagekit.models import ImageSpecField
from pilkit.processors import ResizeToFill
from django.utils import timezone

# …

def upload_to(instance, filename):
 now = timezone.now()
 filename_base, filename_ext = os.path.splitext(filename)
 return "users/{user_id}/{filename}{ext}".format(
 user_id=instance.pk,
 filename=now.strftime("%Y%m%d%H%M%S"),
 ext=filename_ext.lower(),
 )

class User(AbstractUser):
    # …

 avatar = models.ImageField(_("Avatar"), upload_to=upload_to, 
     blank=True)
 avatar_thumbnail = ImageSpecField(
 source="avatar",
 processors=[ResizeToFill(60, 60)],
 format="JPEG",
 options={"quality": 100},
 )

    # …
```

1.  添加一些方法以便在`MyUserAdmin`类中下载和显示 Gravatar：

```py
# myprojects/apps/accounts/admin.py from django.contrib import admin
from django.contrib.auth.admin import UserAdmin, Group, GroupAdmin
from django.urls import reverse
from django.contrib.contenttypes.models import ContentType
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from django.contrib.auth.forms import UserCreationForm

from .helpers import download_avatar
from .models import User, Role

class MyUserCreationForm(UserCreationForm):
    def save(self, commit=True):
        user = super().save(commit=False)
        user.username = user.email
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user

@admin.register(User)
class MyUserAdmin(UserAdmin):
    save_on_top = True
    list_display = [
        "get_avatar",
        "get_full_name",
        "download_gravatar",
        "is_active",
        "is_staff",
        "is_superuser",
    ]
    list_display_links = [
        "get_avatar",
        "get_full_name",
    ]
    search_fields = ["email", "first_name", "last_name", "id", 
     "username"]
    ordering = ["-is_superuser", "-is_staff", "last_name", 
     "first_name"]

    fieldsets = [
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("first_name", 
         "last_name")}),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
 (_("Avatar"), {"fields": ("avatar",)}),
        (_("Important dates"), {"fields": ("last_login", 
         "date_joined")}),
    ]
    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("email", 
         "password1", "password2")}),
    )
    add_form = MyUserCreationForm

    def get_full_name(self, obj):
        return obj.get_full_name()

    get_full_name.short_description = _("Full name")

    def get_avatar(self, obj):
        from django.template.loader import render_to_string
        html = render_to_string("admin/accounts
         /includes/avatar.html", context={
            "obj": obj
        })
        return mark_safe(html)

    get_avatar.short_description = _("Avatar")

    def download_gravatar(self, obj):
        from django.template.loader import render_to_string
        info = self.model._meta.app_label, 
         self.model._meta.model_name
        gravatar_url = reverse("admin:%s_%s_download_gravatar" % 
         info, args=[obj.pk])
        html = render_to_string("admin/accounts
         /includes/download_gravatar.html", context={
            "url": gravatar_url
        })
        return mark_safe(html)

    download_gravatar.short_description = _("Gravatar")

    def get_urls(self):
        from functools import update_wrapper
        from django.conf.urls import url

        def wrap(view):
            def wrapper(*args, **kwargs):
                return self.admin_site.admin_view(view)(*args, 
                 **kwargs)

            wrapper.model_admin = self
            return update_wrapper(wrapper, view)

        info = self.model._meta.app_label, 
         self.model._meta.model_name

        urlpatterns = [
            url(
                r"^(.+)/download-gravatar/$",
                wrap(self.download_gravatar_view),
                name="%s_%s_download_gravatar" % info,
            )
        ] + super().get_urls()

        return urlpatterns

    def download_gravatar_view(self, request, object_id):
        if request.method != "POST":
            return HttpResponse(
                "{} method not allowed.".format(request.method), 
                 status=405
            )
        from .models import User

        user = get_object_or_404(User, pk=object_id)
        import hashlib

        m = hashlib.md5()
        m.update(force_bytes(user.email))
        md5_hash = m.hexdigest()
        # d=404 ensures that 404 error is raised if gravatar is not 
        # found instead of returning default placeholder
        url = "https://www.gravatar.com/avatar
         /{md5_hash}?s=800&d=404".format(
            md5_hash=md5_hash
        )
        download_avatar(object_id, url)
        return HttpResponse("Gravatar downloaded.", status=200)
```

1.  在`accounts`应用程序中添加一个`helpers.py`文件，内容如下：

```py
# myproject/apps/accounts/helpers.py 
def download_avatar(user_id, image_url):
    import tempfile
    import requests
    from django.contrib.auth import get_user_model
    from django.core.files import File

    response = requests.get(image_url, allow_redirects=True, 
     stream=True)
    user = get_user_model().objects.get(pk=user_id)

    if user.avatar:  # delete the old avatar
        user.avatar.delete()

    if response.status_code != requests.codes.ok:
        user.save()
        return

    file_name = image_url.split("/")[-1]

    image_file = tempfile.NamedTemporaryFile()

    # Read the streamed image in sections
    for block in response.iter_content(1024 * 8):
        # If no more file then stop
        if not block:
            break
        # Write image block to temporary file
        image_file.write(block)

    user.avatar.save(file_name, File(image_file))
    user.save()
```

1.  为管理文件中的头像创建一个模板：

```py
{# admin/accounts/includes/avatar.html #}
{% if obj.avatar %}
    <img src="img/{{ obj.avatar_thumbnail.url }}" alt="" 
     width="30" height="30" />
{% endif %}
```

1.  为下载`Gravatar`的`button`创建一个模板：

```py
{# admin/accounts/includes/download_gravatar.html #}
{% load i18n %}
<button type="button" data-url="{{ url }}" class="button js_download_gravatar download-gravatar">
    {% trans "Get Gravatar" %}
</button>
```

1.  最后，为用户更改列表管理创建一个模板，其中包含处理鼠标点击`Get Gravatar`按钮的 JavaScript：

```py
{# admin/accounts/user/change_list.html #}
{% extends "admin/change_list.html" %}
{% load static %}

{% block footer %}
{{ block.super }}
<style nonce="{{ request.csp_nonce }}">
.button.download-gravatar {
    padding: 2px 10px;
}
</style>
<script nonce="{{ request.csp_nonce }}">
django.jQuery(function($) {
    $('.js_download_gravatar').on('click', function(e) {
        e.preventDefault();
        $.ajax({
            url: $(this).data('url'),
            cache: 'false',
            dataType: 'json',
            type: 'POST',
            data: {},
            beforeSend: function(xhr) {
                xhr.setRequestHeader('X-CSRFToken', 
                 '{{ csrf_token }}');
            }
        }).then(function(data) {
            console.log('Gravatar downloaded.');
            document.location.reload(true);
        }, function(data) {
            console.log('There were problems downloading the 
             Gravatar.');
            document.location.reload(true);
        });
    })
})

</script>
{% endblock %}
```

# 工作原理...

如果您现在查看用户更改列表管理，您将看到类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/ddc67c53-0a92-4f43-8864-7722138222d9.png)

列从用户的 AVATAR 开始，然后是 FULL NAME，然后是一个获取 Gravatar 的按钮。当用户点击获取 Gravatar 按钮时，JavaScript 的`onclick`事件处理程序会向`download_gravatar_view`发出`POST`请求。此视图将为用户的 Gravatar 创建一个 URL，该 URL 依赖于用户电子邮件的 MD5 哈希，然后调用一个帮助函数为用户下载图像，并将其链接到`avatar`字段。

# 还有更多...

Gravatar 图像相当小，下载速度相对较快。如果您从其他服务下载更大的图像，可以使用 Celery 或 Huey 任务队列在后台检索图像。您可以在[`docs.celeryproject.org/en/latest/django/first-steps-with-django.html`](https://docs.celeryproject.org/en/latest/django/first-steps-with-django.html)了解有关 Celery 的信息，并在[`huey.readthedocs.io/en/0.4.9/django.html`](https://huey.readthedocs.io/en/0.4.9/django.html)了解有关 Huey 的信息。

# 另请参阅

+   *更改第三方应用程序的应用标签*示例

+   *创建自定义帐户应用程序*示例

# 在更改表单中插入地图

Google Maps 提供了一个 JavaScript API，我们可以使用它将地图插入到我们的网站中。在这个示例中，我们将创建一个带有`Location`模型的`locations`应用程序，并扩展更改表单的模板，以便管理员可以找到并标记位置的地理坐标。

# 准备工作

注册一个 Google Maps API 密钥，并将其暴露给模板，就像我们在第四章*模板和 JavaScript*中的*使用 HTML5 数据属性*示例中所做的那样。请注意，对于此示例，在 Google Cloud Platform 控制台中，您需要激活地图 JavaScript API 和地理编码 API。为了使这些 API 正常工作，您还需要设置计费数据。

我们将继续创建一个`locations`应用程序：

1.  将应用程序放在设置中的`INSTALLED_APPS`下：

```py
# myproject/settings/_base.py
INSTALLED_APPS = [
    # …
    "myproject.apps.locations",
]
```

1.  在那里创建一个`Location`模型，包括名称、描述、地址、地理坐标和图片，如下所示：

```py
# myproject/apps/locations/models.py
import os
import uuid
from collections import namedtuple

from django.contrib.gis.db import models
from django.urls import reverse
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now as timezone_now

from myproject.apps.core.models import CreationModificationDateBase, UrlBase

COUNTRY_CHOICES = getattr(settings, "COUNTRY_CHOICES", [])

Geoposition = namedtuple("Geoposition", ["longitude", "latitude"])

def upload_to(instance, filename):
    now = timezone_now()
    base, extension = os.path.splitext(filename)
    extension = extension.lower()
    return f"locations/{now:%Y/%m}/{instance.pk}{extension}"

class Location(CreationModificationDateBase, UrlBase):
    uuid = models.UUIDField(primary_key=True, default=None, 
     editable=False)
    name = models.CharField(_("Name"), max_length=200)
    description = models.TextField(_("Description"))
    street_address = models.CharField(_("Street address"), 
     max_length=255, blank=True)
    street_address2 = models.CharField(
        _("Street address (2nd line)"), max_length=255, blank=True
    )
    postal_code = models.CharField(_("Postal code"), 
     max_length=255, blank=True)
    city = models.CharField(_("City"), max_length=255, blank=True)
    country = models.CharField(
        _("Country"), choices=COUNTRY_CHOICES, max_length=255, 
         blank=True
    )
    geoposition = models.PointField(blank=True, null=True)
    picture = models.ImageField(_("Picture"), upload_to=upload_to)

    class Meta:
        verbose_name = _("Location")
        verbose_name_plural = _("Locations")

    def __str__(self):
        return self.name

    def get_url_path(self):
        return reverse("locations:location_detail", 
         kwargs={"pk": self.pk})

    def save(self, *args, **kwargs):
        if self.pk is None:
            self.pk = uuid.uuid4()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.picture:
            self.picture.delete()
        super().delete(*args, **kwargs)

    def get_geoposition(self):
        if not self.geoposition:
            return None
        return Geoposition(self.geoposition.coords[0], 
         self.geoposition.coords[1])

    def set_geoposition(self, longitude, latitude):
        from django.contrib.gis.geos import Point
        self.geoposition = Point(longitude, latitude, srid=4326)
```

1.  接下来，我们需要为我们的 PostgreSQL 数据库安装 PostGIS 扩展。最简单的方法是运行`dbshell`管理命令，并执行以下命令：

```py
> CREATE EXTENSION postgis;
```

1.  现在，使用地理位置模型创建默认管理（我们将在*如何做...*部分中更改这一点）：

```py
# myproject/apps/locations/admin.py
from django.contrib.gis import admin
from .models import Location

@admin.register(Location)
class LocationAdmin(admin.OSMGeoAdmin):
    pass
```

来自`gis`模块的地理`Point`字段的默认 Django 管理使用`Leaflet.js` JavaScript 映射库。瓷砖来自 Open Street Maps，管理将如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/2a5e6034-e6a8-4277-b892-a9a672aa341b.png)

请注意，在默认设置中，您无法手动输入经度和纬度，也无法从地址信息中获取地理位置的可能性。我们将在此示例中实现这一点。

# 如何做...

`Location`模型的管理将从多个文件中组合而成。执行以下步骤来创建它：

1.  让我们为`Location`模型创建管理配置。请注意，我们还创建了一个自定义模型表单，以创建单独的`latitude`和`longitude`字段：

```py
# myproject/apps/locations/admin.py from django.contrib import admin
from django import forms
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.translation import ugettext_lazy as _

from .models import Location

LATITUDE_DEFINITION = _(
    "Latitude (Lat.) is the angle between any point and the "
    "equator (north pole is at 90°; south pole is at -90°)."
)

LONGITUDE_DEFINITION = _(
    "Longitude (Long.) is the angle east or west of a point "
    "on Earth at Greenwich (UK), which is the international "
    "zero-longitude point (longitude = 0°). The anti-meridian "
    "of Greenwich (the opposite side of the planet) is both "
    "180° (to the east) and -180° (to the west)."
)

class LocationModelForm(forms.ModelForm):
    latitude = forms.FloatField(
        label=_("Latitude"), required=False, help_text=LATITUDE_DEFINITION
    )
    longitude = forms.FloatField(
        label=_("Longitude"), required=False, help_text=LONGITUDE_DEFINITION
    )

    class Meta:
        model = Location
        exclude = ["geoposition"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            geoposition = self.instance.get_geoposition()
            if geoposition:
                self.fields["latitude"].initial = 
               geoposition.latitude
                self.fields["longitude"].initial = 
               geoposition.longitude

    def save(self, commit=True):
        cleaned_data = self.cleaned_data
        instance = super().save(commit=False)
        instance.set_geoposition(
            longitude=cleaned_data["longitude"],
            latitude=cleaned_data["latitude"],
        )
        if commit:
            instance.save()
            self.save_m2m()
        return instance

@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    form = LocationModelForm
    save_on_top = True
    list_display = ("name", "street_address", "description")
    search_fields = ("name", "street_address", "description")

    def get_fieldsets(self, request, obj=None):
        map_html = render_to_string(
            "admin/locations/includes/map.html",
            {"MAPS_API_KEY": settings.GOOGLE_MAPS_API_KEY},
        )
        fieldsets = [
            (_("Main Data"), {"fields": ("name", "description")}),
            (
                _("Address"),
                {
                    "fields": (
                        "street_address",
                        "street_address2",
                        "postal_code",
                        "city",
                        "country",
                        "latitude",
 "longitude",
                    )
                },
            ),
            (_("Map"), {"description": map_html, "fields": []}),
            (_("Image"), {"fields": ("picture",)}),
        ]
        return fieldsets
```

1.  要创建自定义更改表单模板，请在`admin/locations/location/`下的模板目录中添加一个新的`change_form.html`文件。此模板将扩展默认的`admin/change_form.html`模板，并将覆盖`extrastyle`和`field_sets`块，如下所示：

```py
{# admin/locations/location/change_form.html #} {% extends "admin/change_form.html" %}
{% load i18n static admin_modify admin_urls %}

{% block extrastyle %}
    {{ block.super }}
    <link rel="stylesheet" type="text/css"
          href="{% static 'site/css/location_map.css' %}" />
{% endblock %}

{% block field_sets %}
    {% for fieldset in adminform %}
        {% include "admin/includes/fieldset.html" %}
    {% endfor %}
    <script src="img/>     %}"></script>
{% endblock %}
```

1.  然后，我们必须为将插入到`Map`字段集中的地图创建模板，如下所示：

```py
{# admin/locations/includes/map.html #} {% load i18n %}
<div class="form-row map js_map">
    <div class="canvas">
        <!-- THE GMAPS WILL BE INSERTED HERE DYNAMICALLY -->
    </div>
    <ul class="locations js_locations"></ul>
    <div class="btn-group">
        <button type="button"
                class="btn btn-default locate-address  
                 js_locate_address">
            {% trans "Locate address" %}
        </button>
        <button type="button"
                class="btn btn-default remove-geo js_remove_geo">
            {% trans "Remove from map" %}
        </button>
    </div>
</div>
<script src="img/js?key={{ MAPS_API_KEY }}"></script>
```

1.  当然，默认情况下地图不会被自动设置样式。因此，我们需要添加一些 CSS，如下所示：

```py
/* site_static/site/css/location_map.css */ .map {
    box-sizing: border-box;
    width: 98%;
}
.map .canvas,
.map ul.locations,
.map .btn-group {
    margin: 1rem 0;
}
.map .canvas {
    border: 1px solid #000;
    box-sizing: padding-box;
    height: 0;
    padding-bottom: calc(9 / 16 * 100%); /* 16:9 aspect ratio */
    width: 100%;
}
.map .canvas:before {
    color: #eee;
    color: rgba(0, 0, 0, 0.1);
    content: "map";
    display: block;
    font-size: 5rem;
    line-height: 5rem;
    margin-top: -25%;
    padding-top: calc(50% - 2.5rem);
    text-align: center;
}
.map ul.locations {
    padding: 0;
}
.map ul.locations li {
    border-bottom: 1px solid #ccc;
    list-style: none;
}
.map ul.locations li:first-child {
    border-top: 1px solid #ccc;
}
.map .btn-group .btn.remove-geo {
    float: right;
}
```

1.  接下来，让我们创建一个`location_change_form.js`的 JavaScript 文件。我们不想用全局变量来污染环境。因此，我们将从闭包开始，以便为变量和函数创建一个私有作用域。

在这个文件中，我们将使用 jQuery（因为 jQuery 随着贡献的管理系统而来，使得这变得简单且跨浏览器），如下所示：

```py
/* site_static/site/js/location_change_form.js */
(function ($, undefined) {
    var gettext = window.gettext || function (val) {
        return val;
    };
    var $map, $foundLocations, $lat, $lng, $street, $street2,
        $city, $country, $postalCode, gMap, gMarker;
    // …this is where all the further JavaScript functions go…
}(django.jQuery));
```

1.  我们将逐一创建 JavaScript 函数并将它们添加到`location_change_form.js`中。`getAddress4search()`函数将从地址字段中收集地址字符串，以便稍后用于地理编码，如下所示：

```py
function getAddress4search() {
    var sStreetAddress2 = $street2.val();
    if (sStreetAddress2) {
        sStreetAddress2 = " " + sStreetAddress2;
    }

    return [
        $street.val() + sStreetAddress2,
        $city.val(),
        $country.val(),
        $postalCode.val()
    ].join(", ");
}
```

1.  `updateMarker()`函数将接受`latitude`和`longitude`参数，并在地图上绘制或移动标记。它还会使标记可拖动，如下所示：

```py
function updateMarker(lat, lng) {
    var point = new google.maps.LatLng(lat, lng);

    if (!gMarker) {
        gMarker = new google.maps.Marker({
            position: point,
            map: gMap
        });
    }

    gMarker.setPosition(point);
    gMap.panTo(point, 15);
    gMarker.setDraggable(true);

    google.maps.event.addListener(gMarker, "dragend",
        function() {
            var point = gMarker.getPosition();
            updateLatitudeAndLongitude(point.lat(), point.lng());
        }
    );
}
```

1.  `updateLatitudeAndLongitude()`函数，如前面的 dragend 事件监听器中所引用的，接受`latitude`和`longitude`参数，并更新具有`id_latitude`和`id_longitude` ID 的字段的值，如下所示：

```py
function updateLatitudeAndLongitude(lat, lng) {
    var precision = 1000000;
    $lat.val(Math.round(lat * precision) / precision);
    $lng.val(Math.round(lng * precision) / precision);
}
```

1.  `autocompleteAddress()`函数从 Google Maps 地理编码中获取结果，并在地图下方列出这些结果，以便选择正确的结果。如果只有一个结果，它将更新地理位置和地址字段，如下所示：

```py
function autocompleteAddress(results) {
    var $item = $('<li/>');
    var $link = $('<a href="#"/>');

    $foundLocations.html("");
    results = results || [];

    if (results.length) {
        results.forEach(function (result, i) {
            $link.clone()
                 .html(result.formatted_address)
                 .click(function (event) {
                     event.preventDefault();
                     updateAddressFields(result
                      .address_components);

                     var point = result.geometry.location;
                     updateLatitudeAndLongitude(
                         point.lat(), point.lng());
                     updateMarker(point.lat(), point.lng());
                     $foundLocations.hide();
                 })
                 .appendTo($item.clone()
                  .appendTo($foundLocations));
        });
        $link.clone()
             .html(gettext("None of the above"))
             .click(function(event) {
                 event.preventDefault();
                 $foundLocations.hide();
             })
             .appendTo($item.clone().appendTo($foundLocations));
        $foundLocations.show();
    } else {
        $foundLocations.hide();
    }
}
```

1.  `updateAddressFields()`函数接受一个嵌套字典，其中包含地址组件作为参数，并填写所有地址字段，如下所示：

```py
function updateAddressFields(addressComponents) {
    var streetName, streetNumber;
    var typeActions = {
        "locality": function(obj) {
            $city.val(obj.long_name);
        },
        "street_number": function(obj) {
            streetNumber = obj.long_name;
        },
        "route": function(obj) {
            streetName = obj.long_name;
        },
        "postal_code": function(obj) {
            $postalCode.val(obj.long_name);
        },
        "country": function(obj) {
            $country.val(obj.short_name);
        }
    };

    addressComponents.forEach(function(component) {
        var action = typeActions[component.types[0]];
        if (typeof action === "function") {
            action(component);
        }
    });

    if (streetName) {
        var streetAddress = streetName;
        if (streetNumber) {
            streetAddress += " " + streetNumber;
        }
        $street.val(streetAddress);
    }
}
```

1.  最后，我们有初始化函数，在页面加载时调用。它将为按钮附加`onclick`事件处理程序，创建一个 Google 地图，并最初标记在`latitude`和`longitude`字段中定义的地理位置，如下所示：

```py
$(function(){
    $map = $(".map");

    $foundLocations = $map.find("ul.js_locations").hide();
    $lat = $("#id_latitude");
    $lng = $("#id_longitude");
    $street = $("#id_street_address");
    $street2 = $("#id_street_address2");
    $city = $("#id_city");
    $country = $("#id_country");
    $postalCode = $("#id_postal_code");

    $map.find("button.js_locate_address")
        .click(function(event) {
            var geocoder = new google.maps.Geocoder();
            geocoder.geocode(
                {address: getAddress4search()},
                function (results, status) {
                    if (status === google.maps.GeocoderStatus.OK) {
                        autocompleteAddress(results);
                    } else {
                        autocompleteAddress(false);
                    }
                }
            );
        });

    $map.find("button.js_remove_geo")
        .click(function() {
            $lat.val("");
            $lng.val("");
            gMarker.setMap(null);
            gMarker = null;
        });

    gMap = new google.maps.Map($map.find(".canvas").get(0), {
        scrollwheel: false,
        zoom: 16,
        center: new google.maps.LatLng(51.511214, -0.119824),
        disableDoubleClickZoom: true
    });

    google.maps.event.addListener(gMap, "dblclick", function(event) 
    {
        var lat = event.latLng.lat();
        var lng = event.latLng.lng();
        updateLatitudeAndLongitude(lat, lng);
        updateMarker(lat, lng);
    });

    if ($lat.val() && $lng.val()) {
        updateMarker($lat.val(), $lng.val());
    }
});
```

# 工作原理...

如果您在浏览器中查看更改位置表单，您将看到一个地图显示在一个字段集中，后面是包含地址字段的字段集，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/7d71d3a9-f2a1-4a60-bec1-13d786f860b4.png)

在地图下方有两个按钮：定位地址和从地图中删除。

当您单击“定位地址”按钮时，将调用地理编码以搜索输入地址的地理坐标。执行地理编码的结果是以嵌套字典格式列出的一个或多个地址。我们将把地址表示为可点击链接的列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/7c5cc0dc-642e-4cf2-abce-03d0fde80113.png)

要在开发者工具的控制台中查看嵌套字典的结构，请在`autocompleteAddress()`函数的开头放置以下行：

```py
console.log(JSON.stringify(results, null, 4));
```

当您点击其中一个选择时，地图上会出现标记，显示位置的确切地理位置。纬度和经度字段将填写如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj3-webdev-cb-4e/img/f5e23aa4-d2ee-4a07-849c-109c29a007e1.png)

然后，管理员可以通过拖放在地图上移动标记。此外，双击地图上的任何位置将更新地理坐标和标记位置。

最后，如果单击“从地图中删除”按钮，则地理坐标将被清除，并且标记将被移除。

管理使用自定义的`LocationModelForm`，其中排除了`geoposition`字段，添加了`Latitude`和`Longitude`字段，并处理它们的值的保存和加载。

# 另请参阅

+   第四章*，模板和 JavaScript*
