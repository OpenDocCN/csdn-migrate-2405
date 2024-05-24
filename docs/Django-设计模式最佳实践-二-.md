# Django 设计模式最佳实践（二）

> 原文：[`zh.annas-archive.org/md5/60442E9F3DEB860EA5C31D69FB8A3E2C`](https://zh.annas-archive.org/md5/60442E9F3DEB860EA5C31D69FB8A3E2C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：模板

在本章中，我们将讨论以下主题：

+   Django 模板语言的特性

+   组织模板

+   Bootstrap

+   模板继承树模式

+   活动链接模式

# 了解 Django 的模板语言特性

是时候谈谈 MTV 三人组中的第三个伙伴-模板了。您的团队可能有设计师负责设计模板。或者您可能自己设计它们。无论哪种方式，您都需要非常熟悉它们。毕竟，它们直接面向您的用户。

让我们从快速介绍 Django 的模板语言特性开始。

## 变量

每个模板都有一组上下文变量。与 Python 的字符串`format()`方法的单花括号`{variable}`语法类似，Django 使用双花括号`{{ variable }}`语法。让我们看看它们的比较：

+   在纯 Python 中，语法是`<h1>{title}</h1>`。例如：

```py
>>> "<h1>{title}</h1>".format(title="SuperBook")
'<h1>SuperBook</h1>'

```

+   在 Django 模板中的等效语法是`<h1>{{ title }}</h1>`。

+   使用相同的上下文进行渲染将产生相同的输出，如下所示：

```py
>>> from django.template import Template, Context
>>> Template("<h1>{{ title }}</h1>").render(Context({"title": "SuperBook"}))
'<h1>SuperBook</h1>'

```

## 属性

在 Django 模板中，点是一个多功能运算符。有三种不同的操作-属性查找、字典查找或列表索引查找（按顺序）。

+   首先，在 Python 中，让我们定义上下文变量和类：

```py
>>> class DrOct:
 arms = 4
 def speak(self):
 return "You have a train to catch."
>>> mydict = {"key":"value"}
>>> mylist = [10, 20, 30]

```

让我们来看看 Python 对三种查找的语法：

```py
>>> "Dr. Oct has {0} arms and says: {1}".format(DrOct().arms, DrOct().speak())
'Dr. Oct has 4 arms and says: You have a train to catch.'
>>> mydict["key"]
 'value'
>>> mylist[1]
 20

```

+   在 Django 的模板等价物中，如下所示：

```py
Dr. Oct has {{ s.arms }} arms and says: {{ s.speak }}
{{ mydict.key }}
{{ mylist.1 }}

```

### 注意

注意`speak`，一个除了`self`之外不带参数的方法，在这里被当作属性对待。

## 过滤器

有时，变量需要被修改。基本上，您想要在这些变量上调用函数。Django 使用管道语法`{{ var|method1|method2:"arg" }}`，而不是链接函数调用，例如`var.method1().method2(arg)`，这类似于 Unix 过滤器。但是，这种语法只适用于内置或自定义的过滤器。

另一个限制是过滤器无法访问模板上下文。它只能使用传递给它的数据及其参数。因此，它主要用于更改模板上下文中的变量。

+   在 Python 中运行以下命令：

```py
>>> title="SuperBook"
>>> title.upper()[:5]
 'SUPER'

```

+   它的 Django 模板等价物：

```py
{{ title|upper|slice:':5' }}"

```

## 标签

编程语言不仅可以显示变量。Django 的模板语言具有许多熟悉的语法形式，如`if`和`for`。它们应该以标签语法编写，如`{% if %}`。几种特定于模板的形式，如`include`和`block`，也是以标签语法编写的。

+   在 Python 中运行以下命令：

```py
>>> if 1==1:
...     print(" Date is {0} ".format(time.strftime("%d-%m-%Y")))
 Date is 31-08-2014

```

+   它对应的 Django 模板形式：

```py
{% if 1 == 1 %} Date is {% now 'd-m-Y' %} {% endif %}

```

## 哲学-不要发明一种编程语言

初学者经常问的一个问题是如何在模板中执行数值计算，比如找到百分比。作为设计哲学，模板系统故意不允许以下操作：

+   变量赋值

+   高级逻辑

这个决定是为了防止您在模板中添加业务逻辑。根据我们对 PHP 或类似 ASP 语言的经验，混合逻辑和表现可能会成为维护的噩梦。但是，您可以编写自定义模板标签（很快会介绍），以执行任何计算，特别是与表现相关的计算。

### 提示

**最佳实践**

将业务逻辑从模板中剥离出来。

# 组织模板

`startproject`命令创建的默认项目布局未定义模板的位置。这很容易解决。在项目的根目录中创建一个名为`templates`的目录。在您的`settings.py`中添加`TEMPLATE_DIRS`变量：

```py
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
TEMPLATE_DIRS = [os.path.join(BASE_DIR, 'templates')]
```

就是这样。例如，您可以添加一个名为`about.html`的模板，并在`urls.py`文件中引用它，如下所示：

```py
urlpatterns = patterns(
    '',
    url(r'^about/$', TemplateView.as_view(template_name='about.html'),
        name='about'),
```

您的模板也可以位于应用程序中。在您的`app`目录内创建一个`templates`目录是存储特定于应用程序的模板的理想选择。

以下是一些组织模板的良好实践：

+   将所有特定于应用程序的模板放在`app`的模板目录中的单独目录中，例如`projroot/app/templates/app/template.html`—注意路径中`app`出现了两次

+   为您的模板使用`.html`扩展名

+   为要包含的模板添加下划线，例如`_navbar.html`

## 对其他模板语言的支持

从 Django 1.8 开始，将支持多个模板引擎。将内置支持 Django 模板语言（前面讨论过的标准模板语言）和 Jinja2。在许多基准测试中，Jinja2 比 Django 模板要快得多。

预计将有一个额外的`TEMPLATES`设置用于指定模板引擎和所有与模板相关的设置。`TEMPLATE_DIRS`设置将很快被弃用。

### 注

**乐观夫人**

几个星期以来，史蒂夫的办公室角落第一次充满了疯狂的活动。随着更多的新成员加入，现在的五人团队包括布拉德、埃文、雅各布、苏和史蒂夫。就像一个超级英雄团队一样，他们的能力深厚而惊人地平衡。

布拉德和埃文是编码大师。埃文着迷于细节，布拉德是大局观的人。雅各布在发现边缘情况方面的才能使他成为测试的完美人选。苏负责营销和设计。

事实上，整个设计本来应该由一家前卫的设计机构完成。他们花了一个月时间制作了一份抽象、生动、色彩斑斓的概念，受到了管理层的喜爱。他们又花了两个星期的时间从他们的 Photoshop 模型中制作出一个 HTML 版本。然而，由于在移动设备上表现迟缓和笨拙，最终被抛弃了。

史蒂夫对现在被广泛称为“独角兽呕吐物”设计的失败感到失望。哈特曾经打电话给他，非常担心没有任何可见的进展向管理层展示。他以严肃的口吻提醒史蒂夫：“我们已经耗尽了项目的缓冲时间。我们不能承受任何最后一刻的意外。”

苏自加入以来一直异常安静，那时她提到她一直在使用 Twitter 的 Bootstrap 进行模拟设计。苏是团队中的增长黑客——一个热衷于编码和创意营销的人。

她承认自己只有基本的 HTML 技能。然而，她的模型设计非常全面，对其他当代社交网络的用户来说看起来很熟悉。最重要的是，它是响应式的，并且在从平板电脑到手机等各种设备上都能完美运行。

管理层一致同意苏的设计，除了一个名叫乐观夫人的人。一个星期五的下午，她冲进苏的办公室，开始质疑从背景颜色到鼠标指针大小的一切。苏试图以令人惊讶的镇定和冷静向她解释。

一个小时后，当史蒂夫决定介入时，乐观夫人正在争论为什么个人资料图片必须是圆形而不是方形。“但是这样的全站更改永远不会及时完成，”他说。乐观夫人转移了目光，对他微笑。突然间，史蒂夫感到一股幸福和希望的波涌上涌。这让他感到非常宽慰和振奋。他听到自己愉快地同意她想要的一切。

后来，史蒂夫得知乐观夫人是一位可以影响易受影响的心灵的次要心灵感应者。他的团队喜欢在最轻微的场合提到后一事实。

# 使用 Bootstrap

如今几乎没有人从头开始建立整个网站。Twitter 的 Bootstrap 或 Zurb 的 Foundation 等 CSS 框架是具有网格系统、出色的排版和预设样式的简单起点。它们大多使用响应式网页设计，使您的网站适合移动设备。

![使用 Bootstrap](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644OS_05_02.jpg)

使用 Edge 项目骨架构建的使用 vanilla Bootstrap Version 3.0.2 的网站

我们将使用 Bootstrap，但其他 CSS 框架的步骤也类似。有三种方法可以在您的网站中包含 Bootstrap：

+   **找到一个项目骨架**：如果您还没有开始项目，那么找到一个已经包含 Bootstrap 的项目骨架是一个很好的选择。例如，像`edge`（由我亲自创建）这样的项目骨架可以在运行`startproject`时用作初始结构，如下所示：

```py
$ django-admin.py startproject --template=https://github.com/arocks/edge/archive/master.zip --extension=py,md,html myproj

```

或者，您可以使用支持 Bootstrap 的`cookiecutter`模板之一。

+   **使用包**：如果您已经开始了项目，最简单的选择就是使用一个包，比如`django-frontend-skeleton`或`django-bootstrap-toolkit`。

+   **手动复制**：前面提到的选项都不能保证它们的 Bootstrap 版本是最新的。Bootstrap 发布频率如此之高，以至于包作者很难及时更新他们的文件。因此，如果您想使用最新版本的 Bootstrap，最好的选择是从[`getbootstrap.com`](http://getbootstrap.com)自己下载。一定要阅读发布说明，以检查您的模板是否需要由于向后不兼容性而进行更改。

将包含`css`、`js`和`fonts`目录的`dist`目录复制到您的项目根目录下的`static`目录中。确保在您的`settings.py`中为`STATICFILES_DIRS`设置了这个路径：

```py
STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]
```

现在您可以在您的模板中包含 Bootstrap 资源，如下所示：

```py
{% load staticfiles %}
  <head>
    <link href="{% static 'css/bootstrap.min.css' %}" rel="stylesheet">
```

## 但它们看起来都一样！

Bootstrap 可能是一个快速入门的好方法。然而，有时开发人员会变懒，不去改变默认外观。这会给您的用户留下不好的印象，他们可能会觉得您网站的外观有点太熟悉和无趣。

Bootstrap 带有大量选项来改善其视觉吸引力。有一个名为`variables.less`的文件，其中包含了从主品牌颜色到默认字体等几个变量，如下所示：

```py
@brand-primary:         #428bca;
@brand-success:         #5cb85c;
@brand-info:            #5bc0de;
@brand-warning:         #f0ad4e;
@brand-danger:          #d9534f;

@font-family-sans-serif:  "Helvetica Neue", Helvetica, Arial, sans-serif;
@font-family-serif:       Georgia, "Times New Roman", Times, serif;
@font-family-monospace:   Menlo, Monaco, Consolas, "Courier New", monospace;
@font-family-base:        @font-family-sans-serif;
```

Bootstrap 文档解释了如何设置构建系统（包括 LESS 编译器）来将这些文件编译成样式表。或者非常方便的是，您可以访问 Bootstrap 网站的“自定义”区域，在那里在线生成您定制的样式表。

由于 Bootstrap 周围有庞大的社区，还有一些网站，比如[bootswatch.com](http://bootswatch.com)，它们有主题样式表，可以直接替换您的`bootstrap.min.css`。

另一种方法是覆盖 Bootstrap 样式。如果您发现在不同的 Bootstrap 版本之间升级自定义的 Bootstrap 样式表非常乏味，那么这是一个推荐的方法。在这种方法中，您可以在一个单独的 CSS（或 LESS）文件中添加站点范围的样式，并在标准 Bootstrap 样式表之后包含它。因此，您可以只需对站点范围的样式表进行最小的更改，就可以简单地升级 Bootstrap 文件。

最后但同样重要的是，您可以通过用更有意义的名称替换结构名称（例如'row'或'column-md-4'替换为'wrapper'或'sidebar'）来使您的 CSS 类更有意义。您可以通过几行 LESS 代码来实现这一点，如下所示：

```py
.wrapper {
  .make-row();
}
.sidebar {
  .make-md-column(4);
}
```

这是可能的，因为有一个叫做 mixin 的功能（听起来很熟悉吧？）。有了 Less 源文件，Bootstrap 可以完全按照您的需求进行定制。

# 模板模式

Django 的模板语言非常简单。然而，通过遵循一些优雅的模板设计模式，您可以节省大量时间。让我们来看看其中一些。

## 模式 - 模板继承树

**问题**：模板中有很多重复的内容在几个页面中。

**解决方案**：在可能的地方使用模板继承，并在其他地方包含片段。

### 问题细节

用户期望网站的页面遵循一致的结构。某些界面元素，如导航菜单、标题和页脚，在大多数 Web 应用程序中都会出现。然而，在每个模板中重复它们是很麻烦的。

大多数模板语言都有一个包含机制。另一个文件的内容，可能是一个模板，可以在调用它的位置包含进来。在一个大型项目中，这可能会变得乏味。

在每个模板中包含的片段的顺序大多是相同的。顺序很重要，很难检查错误。理想情况下，我们应该能够创建一个'基础'结构。新页面应该扩展此基础，以指定仅更改或扩展基础内容。

### 解决方案详情

Django 模板具有强大的扩展机制。类似于编程中的类，模板可以通过继承进行扩展。但是，为了使其工作，基础本身必须按照以下块的结构进行组织：

![解决方案详情](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644OS_05_01.jpg)

`base.html`模板通常是整个站点的基本结构。该模板通常是格式良好的 HTML（即，具有前言和匹配的闭合标签），其中有几个用`{% block tags %}`标记标记的占位符。例如，一个最小的`base.html`文件看起来像下面这样：

```py
<html>
<body>
<h1>{% block heading %}Untitled{% endblock %}</h1>
{% block content %}
{% endblock %}
</body>
</html>
```

这里有两个块，`heading`和`content`，可以被覆盖。您可以扩展基础以创建可以覆盖这些块的特定页面。例如，这是一个`about`页面：

```py
{% extends "base.html" %}
{% block content %}
<p> This is a simple About page </p>
{% endblock %}
{% block heading %}About{% endblock %}
```

请注意，我们不必重复结构。我们也可以按任何顺序提及块。渲染的结果将在`base.html`中定义的正确位置具有正确的块。

如果继承模板没有覆盖一个块，那么将使用其父级的内容。在前面的例子中，如果`about`模板没有标题，那么它将具有默认的标题'Untitled'。

继承模板可以进一步继承形成继承链。这种模式可以用来创建具有特定布局的页面的共同派生基础，例如，单列布局。还可以为站点的某个部分创建一个共同的基础模板，例如，博客页面。

通常，所有的继承链都可以追溯到一个共同的根，`base.html`；因此，这种模式被称为模板继承树。当然，这并不一定要严格遵循。错误页面`404.html`和`500.html`通常不会被继承，并且会被剥离大部分标签，以防止进一步的错误。

## 模式-活动链接

**问题**：导航栏是大多数页面中的常见组件。但是，活动链接需要反映用户当前所在的页面。

**解决方案**：通过设置上下文变量或基于请求路径，有条件地更改活动链接标记。

### 问题详情

在导航栏中实现活动链接的天真方式是在每个页面中手动设置它。然而，这既不符合 DRY 原则，也不是绝对可靠的。

### 解决方案详情

有几种解决方案可以确定活动链接。除了基于 JavaScript 的方法之外，它们主要可以分为仅模板和基于自定义标签的解决方案。

#### 仅模板解决方案

通过在包含导航模板的同时提及`active_link`变量，这种解决方案既简单又易于实现。

在每个模板中，您需要包含以下行（或继承它）：

```py
{% include "_navbar.html" with active_link='link2' %}
```

`_navbar.html`文件包含了带有一组检查活动链接变量的导航菜单：

```py
{# _navbar.html #}
<ul class="nav nav-pills">
  <li{% if active_link == "link1" %} class="active"{% endif %}><a href="{% url 'link1' %}">Link 1</a></li>
  <li{% if active_link == "link2" %} class="active"{% endif %}><a href="{% url 'link2' %}">Link 2</a></li>
  <li{% if active_link == "link3" %} class="active"{% endif %}><a href="{% url 'link3' %}">Link 3</a></li>
</ul>
```

#### 自定义标签

Django 模板提供了一个多功能的内置标签集。创建自定义标签非常容易。由于自定义标签位于应用程序内部，因此在应用程序内创建一个`templatetags`目录。该目录必须是一个包，因此它应该有一个（空的）`__init__.py`文件。

接下来，在一个适当命名的 Python 文件中编写您的自定义模板。例如，对于这个活动链接模式，我们可以创建一个名为`nav.py`的文件，其中包含以下内容：

```py
# app/templatetags/nav.py
from django.core.urlresolvers import resolve
from django.template import Library

register = Library()
@register.simple_tag
def active_nav(request, url):
    url_name = resolve(request.path).url_name
    if url_name == url:
        return "active"
    return ""
```

该文件定义了一个名为`active_nav`的自定义标签。它从请求参数中检索 URL 的路径组件（比如`/about/`—参见第四章，“视图和 URL”中对 URL 路径的详细解释）。然后，使用`resolve()`函数来查找路径对应的 URL 模式名称（在`urls.py`中定义）。最后，只有当模式名称匹配预期的模式名称时，它才返回字符串`"active"`。

在模板中调用这个自定义标签的语法是`{% active_nav request 'pattern_name' %}`。注意，请求需要在每个使用该标签的页面中传递。

在多个视图中包含一个变量可能会变得繁琐。相反，我们可以在`settings.py`的`TEMPLATE_CONTEXT_PROCESSORS`中添加一个内置的上下文处理器，这样请求将在整个站点中以`request`变量的形式存在。

```py
# settings.py
from django.conf import global_settings
TEMPLATE_CONTEXT_PROCESSORS = \
    global_settings.TEMPLATE_CONTEXT_PROCESSORS + (
        'django.core.context_processors.request',
    )
```

现在，唯一剩下的就是在模板中使用这个自定义标签来设置活动属性：

```py
{# base.html #}
{% load nav %}
<ul class="nav nav-pills">
  <li class={% active_nav request 'active1' %}><a href="{% url 'active1' %}">Active 1</a></li>
  <li class={% active_nav request 'active2' %}><a href="{% url 'active2' %}">Active 2</a></li>
  <li class={% active_nav request 'active3' %}><a href="{% url 'active3' %}">Active 3</a></li>
</ul>
```

# 总结

在本章中，我们看了 Django 模板语言的特性。由于在 Django 中很容易更改模板语言，许多人可能会考虑替换它。然而，在寻找替代方案之前，了解内置模板语言的设计哲学是很重要的。

在下一章中，我们将探讨 Django 的一个杀手功能，即管理界面，以及我们如何对其进行定制。


# 第六章：管理员界面

在本章中，我们将讨论以下主题：

+   自定义管理员

+   增强管理员模型

+   管理员最佳实践

+   功能标志

Django 备受瞩目的管理员界面使其脱颖而出。它是一个内置应用程序，可以自动生成用户界面以添加和修改站点的内容。对许多人来说，管理员是 Django 的杀手应用程序，自动化了为项目中的模型创建管理员界面这一乏味任务。

管理员使您的团队能够同时添加内容并继续开发。一旦您的模型准备好并应用了迁移，您只需要添加一两行代码来创建其管理员界面。让我们看看如何做到。

# 使用管理员界面

在 Django 1.7 中，默认情况下启用了管理员界面。创建项目后，当您导航到`http://127.0.0.1:8000/admin/`时，您将能够看到登录页面。

如果您输入超级用户凭据（或任何员工用户的凭据），您将登录到管理员界面，如下面的屏幕截图所示：

![使用管理员界面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644OS_06_01.jpg)

然而，除非您定义相应的`ModelAdmin`类，否则您的模型在这里将不可见。这通常在您的应用程序的`admin.py`中定义如下：

```py
from django.contrib import admin
from . import models

admin.site.register(models.SuperHero)
```

这里，register 的第二个参数，一个`ModelAdmin`类，已被省略。因此，我们将为 Post 模型获得一个默认的管理员界面。让我们看看如何创建和自定义这个`ModelAdmin`类。

### 注意

**信标**

“在喝咖啡吗？”角落里传来一个声音。苏差点把咖啡洒出来。一个穿着紧身红蓝色服装的高个子男人双手叉腰微笑着站在那里。他胸前的标志大大地写着“显而易见船长”。

“哦，天哪，”苏在用餐巾擦咖啡渍时说道。“抱歉，我想我吓到你了，”显而易见船长说。“有什么紧急情况吗？”

“她不知道这是显而易见的吗？”一个平静的女声从上方传来。苏抬头看到一个阴影般的人物从开放的大厅缓缓降下。她的脸部被她那几缕灰色的头发部分遮挡住。“嗨，海克萨！”船长说。“但是，超级书上的消息是什么？”

很快，他们都来到了史蒂夫的办公室，盯着他的屏幕。“看，我告诉过你，首页上没有信标，”埃文说。“我们还在开发这个功能。”“等等，”史蒂夫说。“让我用一个非员工账户登录。”

几秒钟后，页面刷新了，一个动画的红色信标显眼地出现在顶部。“那就是我说的信标！”显而易见船长惊叫道。“等一下，”史蒂夫说。他打开了当天早些时候部署的新功能的源文件。一眼看到信标功能分支代码就清楚了出了什么问题：

```py
    if switch_is_active(request, 'beacon') and not request.user.is_staff():
        # Display the beacon
```

“对不起，各位，”史蒂夫说。“出现了逻辑错误。我们不是只为员工打开了这个功能，而是不小心为所有人打开了这个功能，除了员工。现在已经关闭了。对于任何混淆，我们深表歉意。”

“所以，没有紧急情况吗？”船长失望地说。海克萨把手搭在他肩上说：“恐怕没有，船长。”突然，传来一声巨响，所有人都跑到了走廊。一个人显然是从天花板到地板的玻璃墙中间降落在办公室里。他甩掉了碎玻璃，站了起来。“对不起，我尽快赶过来了，”他说，“我来晚了吗？”海克萨笑了。“不，闪电。一直在等你加入，”她说。

# 增强管理员模型

管理员应用程序足够聪明，可以自动从您的模型中推断出很多东西。但是，有时推断出的信息可以得到改进。这通常涉及向模型本身添加属性或方法（而不是在`ModelAdmin`类中）。

让我们首先看一个增强模型以获得更好展示的示例，包括管理员界面：

```py
# models.py
class SuperHero(models.Model):
    name = models.CharField(max_length=100)
    added_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "{0} - {1:%Y-%m-%d %H:%M:%S}".format(self.name,
                                                    self.added_on)

    def get_absolute_url(self):
        return reverse('superhero.views.details', args=[self.id])

    class Meta:
        ordering = ["-added_on"]
        verbose_name = "superhero"
        verbose_name_plural = "superheroes"
```

让我们看看管理员如何使用所有这些非字段属性：

+   `__str__()`: 如果没有这个，超级英雄条目列表将看起来非常无聊。每个条目都会简单地显示为`<SuperHero: SuperHero object>`。尽量在其`str`表示中包含对象的唯一信息（或 Python 2.x 代码中的`unicode`表示），比如它的名称或版本。任何有助于管理员明确识别对象的信息都会有所帮助。

+   `get_absolute_url()`: 如果您喜欢在网站上的管理视图和对象的详细视图之间切换，那么这个属性非常方便。如果定义了这个方法，那么在对象的编辑页面的右上方将出现一个标有“**在网站上查看**”的按钮。

+   `ordering`: 如果没有这个元选项，您的条目可以以从数据库返回的任何顺序出现。可以想象，如果您有大量对象，这对管理员来说并不有趣。通常希望首先看到新条目，因此按日期的逆向时间顺序排序是常见的。

+   `verbose_name`: 如果省略了这个属性，您的模型名称将从驼峰式转换为小驼峰式。在这种情况下，“超级英雄”看起来很奇怪，因此最好明确指定用户可读名称在管理界面中的显示方式。

+   `verbose_name_plural`: 再次，省略此选项会导致有趣的结果。由于 Django 只是在单词前加上's'，超级英雄的复数将显示为“superheros”（甚至在管理前页）。因此，在这里正确定义它会更好。

建议您不仅为管理界面定义先前的`Meta`属性和方法，还为更好地在 shell、日志文件等中表示。

当然，通过创建`ModelAdmin`类，可以进一步改进管理中的表示，如下所示：

```py
# admin.py
class SuperHeroAdmin(admin.ModelAdmin):
    list_display = ('name', 'added_on')
    search_fields = ["name"]
    ordering = ["name"]

admin.site.register(models.SuperHero, SuperHeroAdmin)
```

让我们更仔细地看看这些选项：

+   `list_display`: 此选项以表格形式显示模型实例。它不使用模型的`__str__`表示，而是将每个字段作为单独的可排序列显示。如果您希望查看模型的多个属性，这是理想的选择。

+   `search_fields`: 此选项在列表上方显示一个搜索框。输入的任何搜索词都将针对所述字段进行搜索。因此，只能在这里提到文本字段，如`CharField`或`TextField`。

+   `ordering`: 这个选项优先于模型的默认排序。如果您在管理屏幕中更喜欢不同的排序方式，这将非常有用。

增强模型的管理页面

上述截图显示了以下插图：

+   插图 1：没有`str`或`Meta`属性

+   插图 2：带有增强模型`meta`属性

+   插图 3：带有自定义`ModelAdmin`

在这里，我们只提到了一些常用的管理选项子集。某些类型的网站会大量使用管理界面。在这种情况下，强烈建议您阅读并了解 Django 文档中的管理部分。

## 并非每个人都应该成为管理员

由于管理界面很容易创建，人们往往滥用它们。一些人仅仅通过打开他们的“工作人员”标志就给予早期用户管理员访问权限。很快，这些用户开始提出功能请求，误以为管理界面是实际应用程序界面。

不幸的是，这并不是管理界面的用途。正如标志所示，它是一个内部工具，供工作人员输入内容使用。它已经准备好投入生产，但并不真正面向您网站的最终用户。

最好将管理用于简单的数据输入。例如，在我审查过的一个项目中，每个老师都被设置为 Django 应用程序管理大学课程的管理员。这是一个糟糕的决定，因为管理界面让老师感到困惑。

安排课程的工作流程涉及检查其他教师和学生的日程安排。使用管理界面使他们直接查看数据库。对于管理员如何修改数据，几乎没有任何控制。

因此，尽量将具有管理访问权限的人数保持得尽可能少。除非是简单的数据输入，例如添加文章内容，否则请谨慎通过管理进行更改。

### 提示

**最佳实践**

不要将管理访问权限授予最终用户。

确保您的所有管理员都了解通过管理进行更改可能导致的数据不一致性。如果可能的话，手动记录或使用应用程序，例如`django-audit-loglog`，可以记录未来参考所做的管理更改。

在大学示例中，我们为教师创建了一个单独的界面，例如课程构建器。只有当用户具有教师配置文件时，这些工具才会可见和可访问。

基本上，纠正大多数管理界面的误用涉及为某些用户组创建更强大的工具。但是，不要采取简单（错误的）路径，授予他们管理访问权限。

# 管理界面自定义

开箱即用的管理界面非常有用。不幸的是，大多数人认为很难更改 Django 管理界面，因此将其保持原样。实际上，管理界面是非常可定制的，只需付出最少的努力即可大幅改变其外观。

## 更改标题

许多管理界面的用户可能会被标题“Django administration”困惑。更改为一些自定义的内容，例如“MySite admin”或者“SuperBook Secret Area”可能更有帮助。

这种更改非常容易。只需将以下行添加到站点的`urls.py`中：

```py
admin.site.site_header = "SuperBook Secret Area"
```

## 更改基础和样式表

几乎每个管理页面都是从名为`admin/base_site.html`的通用基础模板扩展而来。这意味着只要稍微了解 HTML 和 CSS，您就可以进行各种自定义，改变管理界面的外观和感觉。

只需在任何`templates`目录中创建一个名为`admin`的目录。然后，从 Django 源目录中复制`base_site.html`文件，并根据需要进行修改。如果您不知道模板的位置，请在 Django shell 中运行以下命令：

```py
>>> from os.path import join
>>> from django.contrib import admin
>>> print(join(admin.__path__[0], "templates", "admin"))
/home/arun/env/sbenv/lib/python3.4/site-packages/django/contrib/admin/templates/admin

```

最后一行是所有管理模板的位置。您可以覆盖或扩展这些模板中的任何一个。有关扩展模板的示例，请参考下一节。

关于自定义管理基础模板的示例，您可以将整个管理界面的字体更改为来自 Google Fonts 的“Special Elite”，这对于赋予一种模拟严肃的外观非常有用。您需要在模板目录之一中添加一个`admin/base_site.html`文件，内容如下：

```py
{% extends "admin/base.html" %}

{% block extrastyle %}
    <link href='http://fonts.googleapis.com/css?family=Special+Elite' rel='stylesheet' type='text/css'>
    <style type="text/css">
     body, td, th, input {
       font-family: 'Special Elite', cursive;
     }
    </style>
{% endblock %}
```

这将添加一个额外的样式表，用于覆盖与字体相关的样式，并将应用于每个管理页面。

### 为所见即所得编辑添加富文本编辑器

有时，您需要在管理界面中包含 JavaScript 代码。常见的要求是为您的`TextField`使用 HTML 编辑器，例如`CKEditor`。

在 Django 中有几种实现这一点的方法，例如在`ModelAdmin`类上使用`Media`内部类。但是，我发现扩展管理`change_form`模板是最方便的方法。

例如，如果您有一个名为`Posts`的应用程序，则需要在`templates/admin/posts/`目录中创建一个名为`change_form.html`的文件。如果需要为该应用程序中任何模型的`message`字段显示`CKEditor`（也可以是任何 JavaScript 编辑器，但我更喜欢这个），则文件的内容可以如下所示：

```py
{% extends "admin/change_form.html" %}

{% block footer %}
  {{ block.super }}
  <script src="img/ckeditor.js"></script>
  <script>
   CKEDITOR.replace("id_message", {
     toolbar: [
     [ 'Bold', 'Italic', '-', 'NumberedList', 'BulletedList'],],
     width: 600,
   });
  </script>
  <style type="text/css">
   .cke { clear: both; }
  </style>
{% endblock %}
```

突出显示的部分是我们希望从普通文本框改为富文本编辑器的表单元素自动生成的`ID`。这些脚本和样式已添加到页脚块，以便在更改之前在 DOM 中创建表单元素。

## 基于 Bootstrap 的管理

总的来说，管理界面设计得相当不错。然而，它是在 2006 年设计的，大部分看起来也是这样。它没有移动 UI 或其他今天已经成为标准的美化功能。

毫不奇怪，对管理自定义的最常见请求是是否可以与 Bootstrap 集成。有几个包可以做到这一点，比如 `django-admin-bootstrapped` 或 `djangosuit`。

这些包提供了现成的基于 Bootstrap 主题的模板，易于安装和部署。基于 Bootstrap，它们是响应式的，并带有各种小部件和组件。

## 完全改版

也有人尝试完全重新构想管理界面。**Grappelli** 是一个非常受欢迎的皮肤，它通过自动完成查找和可折叠的内联等新功能扩展了 Django 管理。使用 `django-admin-tools`，您可以获得可定制的仪表板和菜单栏。

已经有人尝试完全重写管理界面，比如 `django-admin2` 和 `nexus`，但没有获得任何重大的采用。甚至有一个名为 `AdminNext` 的官方提案来改进整个管理应用。考虑到现有管理的规模、复杂性和受欢迎程度，任何这样的努力都预计需要大量的时间。

# 保护管理

您网站的管理界面可以访问几乎所有存储的数据。因此，不要轻易留下象征性的门。事实上，当你导航到 `http://example.com/admin/` 时，你会看到蓝色的登录界面，这是运行 Django 的人的一个明显迹象。

在生产中，建议将此位置更改为不太明显的位置。只需在根 `urls.py` 中更改这一行即可：

```py
    url(r'^secretarea/', include(admin.site.urls)),
```

一个稍微更复杂的方法是在默认位置使用一个虚拟的管理站点或者蜜罐（参见 `django-admin-honeypot` 包）。然而，最好的选择是在管理区域使用 HTTPS，因为普通的 HTTP 会将所有数据以明文形式发送到网络上。

查看您的 Web 服务器文档，了解如何为管理请求设置 HTTPS。在 Nginx 上，设置这个很容易，涉及指定 SSL 证书的位置。最后，将所有管理页面的 HTTP 请求重定向到 HTTPS，这样你就可以更加安心地睡觉了。

以下模式不仅限于管理界面，但仍然包括在本章中，因为它经常在管理中受到控制。

## 模式 - 功能标志

**问题**：向用户发布新功能和在生产环境中部署相应的代码应该是独立的。

**解决方案**：使用功能标志在部署后选择性地启用或禁用功能。

### 问题细节

今天，频繁地将错误修复和新功能推向生产是很常见的。其中许多变化并不为用户所注意。然而，在可用性或性能方面有重大影响的新功能应该以分阶段的方式推出。换句话说，部署应该与发布分离。

简化的发布流程在部署后立即激活新功能。这可能会导致从用户问题（淹没您的支持资源）到性能问题（导致停机时间）等灾难性的结果。

因此，在大型网站中，重要的是将新功能的部署与在生产环境中激活它们分开。即使它们被激活，有时也只能被一小部分用户看到。这个小组可以是员工或一小部分客户用于试用目的。

### 解决方案细节

许多网站使用**功能标志**来控制新功能的激活。功能标志是代码中的开关，用于确定是否应向某些客户提供某项功能。

几个 Django 包提供了功能标志，如`gargoyle`和`django-waffle`。这些包将站点的功能标志存储在数据库中。它们可以通过管理界面或管理命令激活或停用。因此，每个环境（生产、测试、开发等）都可以拥有自己激活的功能集。

功能标志最初是在 Flickr 中记录的（请参阅[`code.flickr.net/2009/12/02/flipping-out/`](http://code.flickr.net/2009/12/02/flipping-out/)）。他们管理了一个没有任何分支的代码库，也就是说，所有东西都被检入主线。他们还将这些代码部署到生产环境中多次。如果他们发现新功能在生产环境中出现故障或增加了数据库的负载，那么他们只需通过关闭该功能标志来禁用它。

功能标志可以用于各种其他情况（以下示例使用`django-waffle`）：

+   **试验**：功能标志也可以有条件地对某些用户进行激活。这些可以是您自己的员工或某些早期采用者，如下所示：

```py
    def my_view(request):
        if flag_is_active(request, 'flag_name'):
            # Behavior if flag is active.
```

网站可以同时运行几个这样的试验，因此不同的用户可能会有不同的用户体验。在更广泛的部署之前，会从这些受控测试中收集指标和反馈。

+   **A/B 测试**：这与试验非常相似，只是在受控实验中随机选择用户。这在网页设计中很常见，用于确定哪些更改可以提高转化率。以下是编写这样一个视图的方法：

```py
    def my_view(request):
        if sample_is_active(request, 'design_name'):
            # Behavior for test sample.
```

+   **性能测试**：有时很难衡量某项功能对服务器性能的影响。在这种情况下，最好先仅为小部分用户激活该标志。如果性能在预期范围内，可以逐渐增加激活的百分比。

+   **限制外部性**：我们还可以使用功能标志作为反映其服务可用性的站点范围功能开关。例如，外部服务（如 Amazon S3）的停机可能导致用户在执行上传照片等操作时面临错误消息。

当外部服务长时间停机时，可以停用功能标志，从而禁用上传按钮和/或显示有关停机的更有帮助的消息。这个简单的功能节省了用户的时间，并提供了更好的用户体验：

```py
    def my_view(request):
        if switch_is_active('s3_down'):
            # Disable uploads and show it is downtime
```

这种方法的主要缺点是代码中充斥着条件检查。但是，可以通过定期的代码清理来控制这一点，以删除对已完全接受的功能的检查，并清除永久停用的功能。

# 总结

在本章中，我们探讨了 Django 内置的管理应用程序。我们发现它不仅可以直接使用，而且还可以进行各种自定义以改善其外观和功能。

在下一章中，我们将探讨如何通过考虑各种模式和常见用例来更有效地使用 Django 中的表单。


# 第七章：表单

在本章中，我们将讨论以下主题：

+   表单工作流程

+   不受信任的输入

+   使用基于类的视图处理表单

+   使用 CRUD 视图

让我们把 Django 表单放在一边，谈谈一般的网络表单。表单不仅仅是一长串的、乏味的页面，上面有几个你必须填写的项目。表单无处不在。我们每天都在使用它们。表单驱动着从谷歌的搜索框到 Facebook 的**赞**按钮的一切。

在处理表单时，Django 会抽象出大部分繁重的工作，例如验证或呈现。它还实现了各种安全最佳实践。然而，由于它们可能处于多种状态之一，表单也是混淆的常见来源。让我们更仔细地研究它们。

# 表单的工作原理

理解表单可能有些棘手，因为与它们的交互需要多个请求-响应周期。在最简单的情况下，您需要呈现一个空表单，用户填写正确并提交它。在其他情况下，他们输入了一些无效数据，表单需要重新提交，直到整个表单有效为止。

因此，表单经历了几种状态：

+   **空表单**：这种表单在 Django 中称为未绑定表单

+   填充表单：在 Django 中，这种表单称为绑定表单

+   **提交的带有错误的表单**：这种表单称为绑定表单，但不是有效的表单

+   **提交的没有错误的表单**：这种表单在 Django 中称为绑定和有效的表单

请注意，用户永远不会看到表单处于最后状态。他们不必这样做。提交有效的表单应该将用户带到成功页面。

## Django 中的表单

Django 的`form`类包含每个字段的状态，通过总结它们到一个级别，还包括表单本身的状态。表单有两个重要的状态属性，如下所示：

+   `is_bound`：如果返回 false，则它是一个未绑定的表单，也就是说，一个带有空或默认字段值的新表单。如果为 true，则表单是绑定的，也就是说，至少有一个字段已经设置了用户输入。

+   `is_valid()`: 如果返回 true，则绑定表单中的每个字段都有有效数据。如果为 false，则至少一个字段中有一些无效数据或者表单未绑定。

例如，假设您需要一个简单的表单，接受用户的姓名和年龄。表单类可以定义如下：

```py
# forms.py
from django import forms

class PersonDetailsForm(forms.Form):
    name = forms.CharField(max_length=100)
    age = forms.IntegerField()
```

这个类可以以绑定或未绑定的方式初始化，如下面的代码所示：

```py
>>> f = PersonDetailsForm()
>>> print(f.as_p())
<p><label for="id_name">Name:</label> <input id="id_name" maxlength="100" name="name" type="text" /></p>
<p><label for="id_age">Age:</label> <input id="id_age" name="age" type="number" /></p>

>>> f.is_bound
 False

>>> g = PersonDetailsForm({"name": "Blitz", "age": "30"})
>>> print(g.as_p())
<p><label for="id_name">Name:</label> <input id="id_name" maxlength="100" name="name" type="text" value="Blitz" /></p>
<p><label for="id_age">Age:</label> <input id="id_age" name="age" type="number" value="30" /></p>

>>> g.is_bound
 True

```

请注意 HTML 表示如何更改以包括带有其中的绑定数据的值属性。

表单只能在创建表单对象时绑定，也就是在构造函数中。用户输入是如何进入包含每个表单字段值的类似字典的对象中的呢？

要了解这一点，您需要了解用户如何与表单交互。在下图中，用户打开人员详细信息表单，首先填写不正确，然后提交，然后使用有效信息重新提交：

![Django 中的表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_07_01.jpg)

如前图所示，当用户提交表单时，视图可调用获取`request.POST`中的所有表单数据（`QueryDict`的实例）。表单使用这个类似字典的对象进行初始化，因为它的行为类似于字典并且具有一些额外的功能。

表单可以定义为以两种不同的方式发送表单数据：`GET`或`POST`。使用`METHOD="GET"`定义的表单将表单数据编码在 URL 本身中，例如，当您提交 Google 搜索时，您的 URL 将具有您的表单输入，即搜索字符串可见地嵌入其中，例如`?q=Cat+Pictures`。`GET`方法用于幂等表单，它不会对世界的状态进行任何持久性更改（或者更严谨地说，多次处理表单的效果与一次处理它的效果相同）。在大多数情况下，这意味着它仅用于检索数据。

然而，绝大多数的表单都是用`METHOD="POST"`定义的。在这种情况下，表单数据会随着 HTTP 请求的主体一起发送，用户看不到。它们用于任何涉及副作用的事情，比如存储或更新数据。

取决于您定义的表单类型，当用户提交表单时，视图将在`request.GET`或`request.POST`中接收表单数据。如前所述，它们中的任何一个都将像字典一样。因此，您可以将其传递给您的表单类构造函数以获取一个绑定的`form`对象。

### 注

**入侵**

史蒂夫蜷缩着，沉沉地在他的大三座沙发上打呼噜。在过去的几个星期里，他一直在办公室呆了超过 12 个小时，今晚也不例外。他的手机放在地毯上发出了哔哔声。起初，他还在睡梦中说了些什么，然后，它一次又一次地响，声音越来越紧急。

第五声响起时，史蒂夫惊醒了。他疯狂地在沙发上四处搜寻，最终找到了他的手机。屏幕上显示着一个色彩鲜艳的条形图。每根条都似乎触及了高线，除了一根。他拿出笔记本电脑，登录了 SuperBook 服务器。网站正常，日志中也没有任何异常活动。然而，外部服务看起来并不太好。

电话那头似乎响了很久，直到一个嘶哑的声音回答道：“喂，史蒂夫？”半个小时后，雅各布终于把问题追溯到了一个无响应的超级英雄验证服务。“那不是运行在 Sauron 上吗？”史蒂夫问道。有一瞬间的犹豫。“恐怕是的，”雅各布回答道。

史蒂夫感到一阵恶心。Sauron 是他们对抗网络攻击和其他可能攻击的第一道防线。当他向任务控制团队发出警报时，已经是凌晨三点了。雅各布一直在和他聊天。他运行了所有可用的诊断工具。没有任何安全漏洞的迹象。

史蒂夫试图让自己冷静下来。他安慰自己也许只是暂时超载，应该休息一下。然而，他知道雅各布不会停止，直到找到问题所在。他也知道 Sauron 不会出现暂时超载的情况。感到极度疲惫，他又睡了过去。

第二天早上，史蒂夫手持一个百吉饼匆匆赶往办公楼时，听到了一阵震耳欲聋的轰鸣声。他转过身，看到一艘巨大的飞船朝他飞来。本能地，他躲到了篱笆后面。在另一边，他听到几个沉重的金属物体落到地面上的声音。就在这时，他的手机响了。是雅各布。有什么东西靠近了他。史蒂夫抬头一看，看到了一个将近 10 英尺高的机器人，橙色和黑色相间，直指他的头上，看起来像是一把武器。

他的手机还在响。他冲到开阔地，差点被周围喷射的子弹击中。他接了电话。“嘿，史蒂夫，猜猜，我终于找到真相了。”“我迫不及待想知道，”史蒂夫说。

“记得我们用 UserHoller 的表单小部件收集客户反馈吗？显然，他们的数据并不那么干净。我的意思是有几个严重的漏洞。嘿，有很多背景噪音。那是电视吗？”史蒂夫朝着一个大大的标志牌扑去，上面写着“安全集结点”。“别理它。告诉我发生了什么事，”他尖叫道。

“好的。所以，当我们的管理员打开他们的反馈页面时，他的笔记本电脑一定被感染了。这个蠕虫可能会传播到他有权限访问的其他系统，特别是 Sauron。我必须说，雅各布，这是一次非常有针对性的攻击。了解我们安全系统的人设计了这个。我有一种不祥的预感，有可怕的事情即将发生。”

在草坪上，一个机器人抓起了一辆 SUV，朝着史蒂夫扔去。他举起手，闭上眼睛。金属的旋转质量在他上方几英尺处冻结了下来。 “重要电话？”Hexa 问道，她放下了车。“是的，请帮我离开这里，”史蒂夫恳求道。

## 为什么数据需要清理？

最终，您需要从表单中获取“清理后的数据”。这是否意味着用户输入的值不干净？是的，有两个原因。

首先，来自外部世界的任何东西最初都不应该被信任。恶意用户可以通过一个表单输入各种各样的漏洞，从而破坏您网站的安全性。因此，任何表单数据在使用之前都必须经过清理。

### 提示

**最佳实践**

永远不要相信用户输入。

其次，`request.POST`或`request.GET`中的字段值只是字符串。即使您的表单字段可以定义为整数（比如年龄）或日期（比如生日），浏览器也会将它们作为字符串发送到您的视图。无论如何，您都希望在使用之前将它们转换为适当的 Python 类型。`form`类在清理时会自动为您执行此转换。

让我们看看这个实际操作：

```py
>>> fill = {"name": "Blitz", "age": "30"}

>>> g = PersonDetailsForm(fill)

>>> g.is_valid()
 True

>>> g.cleaned_data
 {'age': 30, 'name': 'Blitz'}

>>> type(g.cleaned_data["age"])
 int
```

年龄值作为字符串（可能来自`request.POST`）传递给表单类。验证后，清理数据包含整数形式的年龄。这正是你所期望的。表单试图抽象出字符串传递的事实，并为您提供可以使用的干净的 Python 对象。

# 显示表单

Django 表单还可以帮助您创建表单的 HTML 表示。它们支持三种不同的表示形式：`as_p`（作为段落标签），`as_ul`（作为无序列表项）和`as_table`（作为，不出所料，表格）。

这些表示形式的模板代码、生成的 HTML 代码和浏览器渲染已经总结在下表中：

| 模板 | 代码 | 浏览器中的输出 |
| --- | --- | --- |
| `{{ form.as_p }}` |

```py
<p><label for="id_name"> Name:</label>
<input class="textinput textInput form-control" id="id_name" maxlength="100" name="name" type="text" /></p>
<p><label for="id_age">Age:</label> <input class="numberinput form-control" id="id_age" name="age" type="number" /></p>
```

| ![显示表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_07_02.jpg) |
| --- |
| `{{ form.as_ul }}` |

```py
<li><label for="id_name">Name:</label> <input class="textinput textInput form-control" id="id_name" maxlength="100" name="name" type="text" /></li>
<li><label for="id_age">Age:</label> <input class="numberinput form-control" id="id_age" name="age" type="number" /></li>
```

| ![显示表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_07_03.jpg) |
| --- |
| `{{ form.as_table }}` |

```py
<tr><th><label for="id_name">Name:</label></th><td><input class="textinput textInput form-control" id="id_name" maxlength="100" name="name" type="text" /></td></tr>
<tr><th><label for="id_age">Age:</label></th><td><input class="numberinput form-control" id="id_age" name="age" type="number" /></td></tr>
```

| ![显示表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_07_04.jpg) |
| --- |

请注意，HTML 表示仅提供表单字段。这样可以更容易地在单个 HTML 表单中包含多个 Django 表单。但是，这也意味着模板设计者需要为每个表单编写相当多的样板代码，如下面的代码所示：

```py
<form method="post">
  {% csrf_token %}
  <table>{{ form.as_table }}</table>
  <input type="submit" value="Submit" />
</form>
```

请注意，为了使 HTML 表示完整，您需要添加周围的`form`标签，CSRF 令牌，`table`或`ul`标签和**submit**按钮。

## 时间变得简洁

在模板中为每个表单编写如此多的样板代码可能会让人感到厌烦。`django-crispy-forms`包使得编写表单模板代码更加简洁（在长度上）。它将所有的演示和布局都移到了 Django 表单本身。这样，您可以编写更多的 Python 代码，而不是 HTML。

下表显示了脆弱的表单模板标记生成了一个更完整的表单，并且外观更符合 Bootstrap 样式：

| 模板 | 代码 | 浏览器中的输出 |
| --- | --- | --- |
| `{% crispy form %}` |

```py
<form method="post">
<input type='hidden' name='csrfmiddlewaretoken' value='...' />
<div id="div_id_name" class="form-group">
<label for="id_name" class="control-label  requiredField">
Name<span class="asteriskField">*</span></label>
<div class="controls ">
<input class="textinput textInput form-control form-control" id="id_name" maxlength="100" name="name" type="text" /> </div></div> ...
```

（为简洁起见截断了 HTML）| ![时间变得简洁](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_07_05.jpg) |

那么，如何获得更清晰的表单？您需要安装`django-crispy-forms`包并将其添加到`INSTALLED_APPS`中。如果您使用 Bootstrap 3，则需要在设置中提到这一点：

```py
CRISPY_TEMPLATE_PACK = "bootstrap3"
```

表单初始化将需要提及`FormHelper`类型的辅助属性。下面的代码旨在尽量简化，并使用默认布局：

```py
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit

class PersonDetailsForm(forms.Form):
    name = forms.CharField(max_length=100)
    age = forms.IntegerField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper(self)
        self.helper.layout.append(Submit('submit', 'Submit'))
```

# 理解 CSRF

因此，您一定会注意到表单模板中有一个名为**CSRF**令牌的东西。它是针对您的表单的**跨站请求伪造**（CSRF）攻击的安全机制。

它通过注入一个名为 CSRF 令牌的服务器生成的随机字符串来工作，该令牌对用户的会话是唯一的。每次提交表单时，必须有一个包含此令牌的隐藏字段。此令牌确保表单是由原始站点为用户生成的，而不是攻击者创建的具有类似字段的伪造表单。

不建议为使用`GET`方法的表单使用 CSRF 令牌，因为`GET`操作不应更改服务器状态。此外，通过`GET`提交的表单将在 URL 中公开 CSRF 令牌。由于 URL 有更高的被记录或被窥视的风险，最好在使用`POST`方法的表单中使用 CSRF。

# 使用基于类的视图进行表单处理

我们可以通过对基于类的视图本身进行子类化来实质上处理表单：

```py
class ClassBasedFormView(generic.View):
    template_name = 'form.html'

    def get(self, request):
        form = PersonDetailsForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = PersonDetailsForm(request.POST)
        if form.is_valid():
            # Success! We can use form.cleaned_data now
            return redirect('success')
        else:
            # Invalid form! Reshow the form with error highlighted
            return render(request, self.template_name,
                          {'form': form})
```

将此代码与我们之前看到的序列图进行比较。这三种情况已经分别处理。

每个表单都应遵循**Post/Redirect/Get**（**PRG**）模式。如果提交的表单被发现有效，则必须发出重定向。这可以防止重复的表单提交。

但是，这不是一个非常 DRY 的代码。表单类名称和模板名称属性已被重复。使用诸如`FormView`之类的通用基于类的视图可以减少表单处理的冗余。以下代码将以更少的代码行数为您提供与以前相同的功能：

```py
from django.core.urlresolvers import reverse_lazy

class GenericFormView(generic.FormView):
    template_name = 'form.html'
    form_class = PersonDetailsForm
    success_url = reverse_lazy("success")
```

在这种情况下，我们需要使用`reverse_lazy`，因为在导入视图文件时，URL 模式尚未加载。

# 表单模式

让我们看一些处理表单时常见的模式。

## 模式 - 动态表单生成

**问题**：动态添加表单字段或更改已声明的表单字段。

**解决方案**：在表单初始化期间添加或更改字段。

### 问题细节

通常以声明式样式定义表单，其中表单字段列为类字段。但是，有时我们事先不知道这些字段的数量或类型。这需要动态生成表单。这种模式有时被称为**动态表单**或**运行时表单生成**。

想象一个航班乘客登机系统，允许将经济舱机票升级到头等舱。如果还有头等舱座位，需要为用户提供一个额外的选项，询问他们是否想要头等舱。但是，这个可选字段不能被声明，因为它不会显示给所有用户。这种动态表单可以通过这种模式处理。

### 解决方案细节

每个表单实例都有一个名为`fields`的属性，它是一个保存所有表单字段的字典。这可以在运行时进行修改。在表单初始化期间可以添加或更改字段。

例如，如果我们需要在用户详细信息表单中添加一个复选框，只有在表单初始化时命名为"`upgrade`"的关键字参数为 true 时，我们可以实现如下：

```py
class PersonDetailsForm(forms.Form):
    name = forms.CharField(max_length=100)
    age = forms.IntegerField()

    def __init__(self, *args, **kwargs):
        upgrade = kwargs.pop("upgrade", False)
        super().__init__(*args, **kwargs)

        # Show first class option?
        if upgrade:
            self.fields["first_class"] = forms.BooleanField(
                label="Fly First Class?")
```

现在，我们只需要传递`PersonDetailsForm(upgrade=True)`关键字参数，就可以使一个额外的布尔输入字段（复选框）出现。

### 注意

请注意，在调用`super`之前，新引入的关键字参数必须被移除或弹出，以避免`unexpected keyword`错误。

如果我们在这个例子中使用`FormView`类，则需要通过覆盖视图类的`get_form_kwargs`方法传递关键字参数，如下面的代码所示：

```py
class PersonDetailsEdit(generic.FormView):
    ...

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["upgrade"] = True
        return kwargs
```

此模式可用于在运行时更改字段的任何属性，例如其小部件或帮助文本。它也适用于模型表单。

在许多情况下，看似需要动态表单的需求可以使用 Django 表单集来解决。当需要在页面中重复一个表单时，可以使用表单集。表单集的典型用例是在设计类似数据网格的视图时，逐行添加元素。这样，您不需要创建具有任意行数的动态表单。您只需要为行创建一个表单，并使用`formset_factory`函数创建多行。

## 模式 - 基于用户的表单

**问题**：根据已登录用户的情况自定义表单。

**解决方案**：将已登录用户作为关键字参数传递给表单的初始化程序。

### 问题细节

根据用户的不同，表单可以以不同的方式呈现。某些用户可能不需要填写所有字段，而另一些用户可能需要添加额外的信息。在某些情况下，您可能需要对用户的资格进行一些检查，例如验证他们是否是某个组的成员，以确定应该如何构建表单。

### 解决方案细节

正如您可能已经注意到的，您可以使用动态表单生成模式中提供的解决方案来解决这个问题。您只需要将`request.user`作为关键字参数传递给表单。但是，我们也可以使用`django-braces`包中的 mixin 来实现更简洁和更可重用的解决方案。

与前面的例子一样，我们需要向用户显示一个额外的复选框。但是，只有当用户是 VIP 组的成员时才会显示。让我们看看如何使用`django-braces`中的表单 mixin`UserKwargModelFormMixin`简化了`PersonDetailsForm`：

```py
from braces.forms import UserKwargModelFormMixin

class PersonDetailsForm(UserKwargModelFormMixin, forms.Form):
    ...

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Are you a member of the VIP group?
        if self.user.groups.filter(name="VIP").exists():
            self.fields["first_class"] = forms.BooleanField(
                label="Fly First Class?")
```

请注意，mixin 通过弹出`user`关键字参数自动使`self.user`可用。

与表单 mixin 对应的是一个名为`UserFormKwargsMixin`的视图 mixin，需要将其添加到视图中，以及`LoginRequiredMixin`以确保只有已登录用户才能访问此视图：

```py
class VIPCheckFormView(LoginRequiredMixin, UserFormKwargsMixin, generic.FormView):

   form_class = PersonDetailsForm
    ...
```

现在，`user`参数将自动传递给`PersonDetailsForm`表单。

请查看`django-braces`中的其他表单 mixin，例如`FormValidMessageMixin`，这些都是常见表单使用模式的现成解决方案。

## 模式-单个视图中的多个表单操作

**问题**：在单个视图或页面中处理多个表单操作。

**解决方案**：表单可以使用单独的视图来处理表单提交，或者单个视图可以根据`Submit`按钮的名称来识别表单。

### 问题细节

Django 相对简单地将多个具有相同操作的表单组合在一起，例如一个单独的提交按钮。然而，大多数网页需要在同一页上显示多个操作。例如，您可能希望用户在同一页上通过两个不同的表单订阅或取消订阅通讯。

然而，Django 的`FormView`设计为每个视图场景处理一个表单。许多其他通用的基于类的视图也有这种假设。

### 解决方案细节

处理多个表单有两种方法：单独视图和单一视图。让我们先看看第一种方法。

#### 针对不同操作的单独视图

这是一个非常直接的方法，每个表单都指定不同的视图作为它们的操作。例如，订阅和取消订阅表单。可以有两个单独的视图类来处理它们各自表单的`POST`方法。

#### 相同视图用于不同操作

也许您会发现拆分视图以处理表单是不必要的，或者您会发现在一个公共视图中处理逻辑相关的表单更加优雅。无论哪种方式，我们都可以解决通用基于类的视图的限制，以处理多个表单。

在使用相同的视图类处理多个表单时，挑战在于识别哪个表单发出了`POST`操作。在这里，我们利用了`Submit`按钮的名称和值也会被提交的事实。如果`Submit`按钮在各个表单中具有唯一的名称，那么在处理过程中就可以识别表单。

在这里，我们使用 crispy forms 定义一个订阅表单，以便我们也可以命名`submit`按钮：

```py
class SubscribeForm(forms.Form):
    email = forms.EmailField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.helper = FormHelper(self)
        self.helper.layout.append(Submit('subscribe_butn', 'Subscribe'))
```

`UnSubscribeForm`取消订阅表单类的定义方式完全相同（因此被省略），只是其`Submit`按钮的名称为`unsubscribe_butn`。

由于`FormView`设计为单个表单，我们将使用一个更简单的基于类的视图，比如`TemplateView`，作为我们视图的基础。让我们来看看视图定义和`get`方法：

```py
from .forms import SubscribeForm, UnSubscribeForm

class NewsletterView(generic.TemplateView):
    subcribe_form_class = SubscribeForm
    unsubcribe_form_class = UnSubscribeForm
    template_name = "newsletter.html"

    def get(self, request, *args, **kwargs):
        kwargs.setdefault("subscribe_form", self.subcribe_form_class())
        kwargs.setdefault("unsubscribe_form", self.unsubcribe_form_class())
        return super().get(request, *args, **kwargs)
```

`TemplateView` 类的关键字参数方便地插入到模板上下文中。我们只有在它们不存在时才创建任一表单的实例，借助 `setdefault` 字典方法的帮助。我们很快就会看到原因。

接下来，我们将看一下 `POST` 方法，它处理来自任一表单的提交：

```py
    def post(self, request, *args, **kwargs):
        form_args = {
            'data': self.request.POST,
            'files': self.request.FILES,
        }
        if "subscribe_butn" in request.POST:
            form = self.subcribe_form_class(**form_args)
            if not form.is_valid():
                return self.get(request,
                                   subscribe_form=form)
            return redirect("success_form1")
        elif "unsubscribe_butn" in request.POST:
            form = self.unsubcribe_form_class(**form_args)
            if not form.is_valid():
                return self.get(request,
                                   unsubscribe_form=form)
            return redirect("success_form2")
        return super().get(request)
```

首先，表单关键字参数，如 `data` 和 `files`，在 `form_args` 字典中填充。接下来，在 `request.POST` 中检查第一个表单的 `Submit` 按钮是否存在。如果找到按钮的名称，则实例化第一个表单。

如果表单未通过验证，则返回由第一个表单实例创建的 `GET` 方法创建的响应。同样，我们查找第二个表单的提交按钮，以检查是否提交了第二个表单。

在同一个视图中实现相同表单的实例可以通过表单前缀以相同的方式实现。您可以使用前缀参数实例化一个表单，例如 `SubscribeForm(prefix="offers")`。这样的实例将使用给定的参数为其所有表单字段添加前缀，有效地像表单命名空间一样工作。

## 模式 - CRUD 视图

**问题**：为模型创建 CRUD 接口的样板代码是重复的。

**解决方案**：使用通用基于类的编辑视图。

### 问题细节

在大多数 Web 应用程序中，大约 80% 的时间用于编写、创建、读取、更新和删除（CRUD）与数据库的接口。例如，Twitter 本质上涉及创建和阅读彼此的推文。在这里，推文将是正在被操作和存储的数据库对象。

从头开始编写这样的接口可能会变得乏味。如果可以从模型类自动创建 CRUD 接口，这种模式就可以很容易地管理。

### 解决方案细节

Django 通过一组四个通用的基于类的视图简化了创建 CRUD 视图的过程。它们可以映射到它们对应的操作，如下所示：

+   `CreateView`：此视图显示一个空白表单以创建一个新对象

+   `DetailView`：此视图通过从数据库中读取显示对象的详细信息

+   `UpdateView`：此视图允许通过预填充表单更新对象的详细信息

+   `DeleteView`：此视图显示确认页面，并在批准后删除对象

让我们看一个简单的例子。我们有一个包含重要日期的模型，这对于使用我们的网站的每个人都很重要。我们需要构建简单的 CRUD 接口，以便任何人都可以查看和修改这些日期。让我们看看 `ImportantDate` 模型本身：

```py
# models.py
class ImportantDate(models.Model):
    date = models.DateField()
    desc = models.CharField(max_length=100)

    def get_absolute_url(self):
        return reverse('impdate_detail', args=[str(self.pk)])
```

`get_absolute_url()` 方法被 `CreateView` 和 `UpdateView` 类使用，用于在成功创建或更新对象后重定向。它已经路由到对象的 `DetailView`。

CRUD 视图本身足够简单，可以自解释，如下面的代码所示：

```py
# views.py
from django.core.urlresolvers import reverse_lazyfrom . import forms

class ImpDateDetail(generic.DetailView):
    model = models.ImportantDate

class ImpDateCreate(generic.CreateView):
    model = models.ImportantDate
    form_class = forms.ImportantDateForm

class ImpDateUpdate(generic.UpdateView):
    model = models.ImportantDate
    form_class = forms.ImportantDateForm

class ImpDateDelete(generic.DeleteView):
    model = models.ImportantDate
    success_url = reverse_lazy("impdate_list")
```

在这些通用视图中，模型类是唯一必须提及的成员。然而，在 `DeleteView` 的情况下，还需要提及 `success_url` 函数。这是因为在删除后，不能再使用 `get_absolute_url` 来找出要重定向用户的位置。

定义 `form_class` 属性不是强制性的。如果省略，将创建一个与指定模型对应的 `ModelForm` 方法。然而，我们希望创建自己的模型表单以利用 crispy forms，如下面的代码所示：

```py
# forms.py
from django import forms
from . import models
from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
class ImportantDateForm(forms.ModelForm):
    class Meta:
        model = models.ImportantDate
        fields = ["date", "desc"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.helper = FormHelper(self)
        self.helper.layout.append(Submit('save', 'Save'))
```

由于 crispy forms，我们在模板中几乎不需要太多的 HTML 标记来构建这些 CRUD 表单。

### 注意

请注意，明确提及 `ModelForm` 方法的字段是最佳实践，并且很快将在未来的版本中成为强制性的。

默认情况下，模板路径基于视图类和模型名称。为简洁起见，我们在这里省略了模板源。请注意，我们可以在 `CreateView` 和 `UpdateView` 中使用相同的表单。

最后，我们来看看 `urls.py`，在那里一切都被连接在一起：

```py
url(r'^impdates/create/$',
    pviews.ImpDateCreate.as_view(), name="impdate_create"),
url(r'^impdates/(?P<pk>\d+)/$',
    pviews.ImpDateDetail.as_view(), name="impdate_detail"),
url(r'^impdates/(?P<pk>\d+)/update/$',
    pviews.ImpDateUpdate.as_view(), name="impdate_update"),
url(r'^impdates/(?P<pk>\d+)/delete/$',
    pviews.ImpDateDelete.as_view(), name="impdate_delete"),
```

Django 通用视图是创建模型的 CRUD 视图的绝佳方式。只需几行代码，您就可以获得经过充分测试的模型表单和视图，而不是自己进行乏味的任务。

# 总结

在这一章中，我们看了网页表单是如何工作的，以及它们如何在 Django 中使用表单类进行抽象。我们还研究了在处理表单时节省时间的各种技术和模式。

在下一章中，我们将系统地探讨如何处理遗留的 Django 代码库，并如何增强它以满足不断发展的客户需求。


# 第八章：处理遗留代码

在本章中，我们将讨论以下主题：

+   阅读 Django 代码库

+   发现相关文档

+   增量更改与完全重写

+   在更改代码之前编写测试

+   遗留数据库集成

当你被要求加入一个项目时，听起来很令人兴奋。可能会有强大的新工具和尖端技术等着你。然而，很多时候，你被要求与现有的、可能是古老的代码库一起工作。

公平地说，Django 并没有存在那么长时间。然而，为旧版本的 Django 编写的项目有足够的不同之处，引起了担忧。有时，仅有整个源代码和文档可能是不够的。

如果要求重新创建环境，那么您可能需要在本地或网络上处理操作系统配置、数据库设置和运行服务。这个谜团有太多的部分，让你想知道如何开始和从哪里开始。

了解代码中使用的 Django 版本是关键信息。随着 Django 的发展，从默认项目结构到推荐的最佳实践，一切都发生了变化。因此，确定使用的 Django 版本是理解它的重要部分。

### 注意

**交接**

坐在培训室里那些极短的豆袋上，SuperBook 团队耐心等待着哈特。他召集了一个紧急的上线会议。没有人理解“紧急”的部分，因为上线至少还有 3 个月的时间。

欧康夫人匆匆忙忙地拿着一个大设计师咖啡杯，一手拿着一堆看起来像项目时间表的印刷品。她不抬头地说：“我们迟到了，所以我会直奔主题。鉴于上周的袭击，董事会决定立即加快 SuperBook 项目，并将截止日期定为下个月底。有问题吗？”

“是的，”布拉德说，“哈特在哪里？”欧康夫人犹豫了一下，回答说：“嗯，他辞职了。作为 IT 安全主管，他对周界被突破负有道德责任。”显然受到震惊的史蒂夫摇了摇头。“对不起，”她继续说道，“但我被指派负责 SuperBook，并确保我们没有障碍来满足新的截止日期。”

有一阵集体的抱怨声。欧康夫人毫不畏惧，拿起其中一张纸开始说：“这里写着，远程存档模块是未完成状态中最重要的项目。我相信伊万正在处理这个。”

“没错，”远处的伊万说。“快了，”他对其他人微笑着，他们的注意力转向了他。欧康夫人从眼镜的边缘上方凝视着，微笑得几乎太客气了。“考虑到我们在 Sentinel 代码库中已经有一个经过充分测试和运行良好的 Archiver，我建议你利用它，而不是创建另一个多余的系统。”

“但是，”史蒂夫打断道，“这几乎不是多余的。我们可以改进传统的存档程序，不是吗？”“如果没有坏，就不要修理”，欧康夫人简洁地回答道。他说：“他正在努力，”布拉德几乎大声喊道，“他已经完成了所有的工作，那怎么办？”

“伊万，你到目前为止完成了多少工作？”欧康夫人有点不耐烦地问道。“大约 12%”，他辩解地回答道。每个人都不可思议地看着他。“什么？那是最难的 12%”，他补充道。

欧康夫人以同样的模式继续了会议的其余部分。每个人的工作都被重新排列，以适应新的截止日期。当她拿起她的文件准备离开时，她停顿了一下，摘下了眼镜。

“我知道你们都在想什么...真的。但你们需要知道，我们对截止日期别无选择。我现在能告诉你们的就是，全世界都指望着你们在那个日期之前完成，无论如何。”她戴上眼镜，离开了房间。

“我肯定会带上我的锡纸帽，”伊万大声对自己说。

# 查找 Django 版本

理想情况下，每个项目都会在根目录下有一个`requirements.txt`或`setup.py`文件，并且它将包含用于该项目的 Django 的确切版本。让我们寻找类似于这样的一行：

```py
Django==1.5.9
```

请注意，版本号是精确指定的（而不是`Django>=1.5.9`），这被称为**固定**。固定每个软件包被认为是一个很好的做法，因为它减少了意外，并使您的构建更加确定。

不幸的是，有些真实世界的代码库中`requirements.txt`文件没有被更新，甚至完全丢失。在这种情况下，您需要探测各种迹象来找出确切的版本。

## 激活虚拟环境

在大多数情况下，Django 项目将部署在虚拟环境中。一旦找到项目的虚拟环境，您可以通过跳转到该目录并运行操作系统的激活脚本来激活它。对于 Linux，命令如下：

```py
$ source venv_path/bin/activate

```

一旦虚拟环境激活，启动 Python shell 并查询 Django 版本如下：

```py
$ python
>>> import django
>>> print(django.get_version())
1.5.9

```

在这种情况下使用的 Django 版本是 1.5.9 版本。

或者，您可以在项目中运行`manage.py`脚本以获得类似的输出：

```py
$ python manage.py --version
1.5.9

```

但是，如果传统项目源快照以未部署的形式发送给您，则此选项将不可用。如果虚拟环境（和包）也包括在内，那么您可以轻松地在 Django 目录的`__init__.py`文件中找到版本号（以元组形式）。例如：

```py
$ cd envs/foo_env/lib/python2.7/site-packages/django 
$ cat __init__.py
VERSION = (1, 5, 9, 'final', 0)
...

```

如果所有这些方法都失败了，那么您将需要查看过去 Django 版本的发布说明，以确定可识别的更改（例如，`AUTH_PROFILE_MODULE`设置自 1.5 版本以来已被弃用），并将其与您的传统代码进行匹配。一旦确定了正确的 Django 版本，那么您就可以继续分析代码。

# 文件在哪里？这不是 PHP

其中最难适应的一个想法，特别是如果您来自 PHP 或 ASP.NET 世界，那就是源文件不位于您的 Web 服务器的文档根目录中，通常命名为`wwwroot`或`public_html`。此外，代码的目录结构与网站的 URL 结构之间没有直接关系。

实际上，您会发现您的 Django 网站的源代码存储在一个隐蔽的路径中，比如`/opt/webapps/my-django-app`。为什么会这样呢？在许多很好的理由中，将机密数据移出公共 webroot 通常更安全。这样，网络爬虫就不会意外地进入您的源代码目录。

正如您在第十一章中所读到的，*生产就绪*，源代码的位置可以通过检查您的 Web 服务器的配置文件来找到。在这里，您将找到环境变量`DJANGO_SETTINGS_MODULE`设置为模块路径，或者它将将请求传递给配置为指向您的`project.wsgi`文件的 WSGI 服务器。

# 从 urls.py 开始

即使您可以访问 Django 网站的整个源代码，弄清楚它在各种应用程序中的工作方式可能令人望而生畏。通常最好从根`urls.py` `URLconf`文件开始，因为它实际上是将每个请求与相应视图联系起来的地图。

对于普通的 Python 程序，我经常从执行的开始开始阅读，比如从顶级主模块或`__main__`检查成语开始的地方。在 Django 应用程序的情况下，我通常从`urls.py`开始，因为根据站点具有的各种 URL 模式来跟踪执行流程更容易。

在 Linux 中，您可以使用以下`find`命令来定位`settings.py`文件和指定根`urls.py`的相应行：

```py
$ find . -iname settings.py -exec grep -H 'ROOT_URLCONF' {} \;
./projectname/settings.py:ROOT_URLCONF = 'projectname.urls'

$ ls projectname/urls.py
projectname/urls.py

```

# 在代码中跳转

有时阅读代码感觉像在浏览没有超链接的网页。当您遇到在其他地方定义的函数或变量时，您将需要跳转到包含该定义的文件。只要告诉 IDE 要跟踪项目的哪些文件，一些 IDE 就可以自动为您执行此操作。

如果您使用 Emacs 或 Vim，那么您可以创建一个 TAGS 文件以快速在文件之间导航。转到项目根目录并运行一个名为**Exuberant Ctags**的工具，如下所示：

```py
find . -iname "*.py" -print | etags -

```

这将创建一个名为 TAGS 的文件，其中包含位置信息，其中定义了诸如类和函数之类的每个句法单元。在 Emacs 中，您可以使用`M-.`命令找到标签的定义，其中您的光标（或在 Emacs 中称为点）所在的位置。

虽然对于大型代码库来说，使用标签文件非常快速，但它相当基本，并不知道虚拟环境（大多数定义可能位于其中）。一个很好的替代方案是在 Emacs 中使用`elpy`包。它可以配置为检测虚拟环境。使用相同的`M-.`命令跳转到句法元素的定义。但是，搜索不限于标签文件。因此，您甚至可以无缝地跳转到 Django 源代码中的类定义。

# 理解代码库

很少能找到具有良好文档的遗留代码。即使您有文档，文档可能与代码不同步，这可能会导致进一步的问题。通常，理解应用程序功能的最佳指南是可执行的测试用例和代码本身。

官方的 Django 文档已经按版本在[`docs.djangoproject.com`](https://docs.djangoproject.com)上组织。在任何页面上，您都可以使用页面底部右侧的选择器快速切换到 Django 先前版本的相应页面：

![理解代码库](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_08_01.jpg)

同样，托管在[readthedocs.org](http://readthedocs.org)上的任何 Django 包的文档也可以追溯到其先前的版本。例如，您可以通过单击页面左下角的选择器选择`django-braces`的文档，一直回到 v1.0.0：

![理解代码库](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_08_02.jpg)

## 创建大图

大多数人发现，如果向他们展示一个高层次的图表，他们更容易理解一个应用程序。虽然理想情况下，这是由了解应用程序工作原理的人创建的，但也有工具可以创建非常有帮助的 Django 应用程序的高层次描述。

`graph_models`管理命令可以生成应用程序中所有模型的图形概述，该命令由`django-command-extensions`包提供。如下图所示，可以一目了然地理解模型类及其关系：

![创建大图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644_08_03.jpg)

SuperBook 项目中使用的模型类通过箭头连接，指示它们的关系

实际上，这个可视化是使用 PyGraphviz 创建的。对于甚至中等复杂的项目，这可能会变得非常庞大。因此，如果应用程序被逻辑分组并分别可视化，可能会更容易。

### 注意

**PyGraphviz 安装和使用**

如果您发现安装 PyGraphviz 具有挑战性，那么不用担心，您并不孤单。最近，我在 Ubuntu 上安装时遇到了许多问题，从 Python 3 不兼容到文档不完整。为了节省您的时间，我列出了对我有效的步骤来达到一个可用的设置。

在 Ubuntu 上，您需要安装以下软件包才能安装 PyGraphviz：

```py
$ sudo apt-get install python3.4-dev graphviz libgraphviz-dev pkg-config
```

现在激活您的虚拟环境并运行 pip 从 GitHub 直接安装 PyGraphviz 的开发版本，该版本支持 Python 3：

```py
$ pip install git+http://github.com/pygraphviz/pygraphviz.git#egg=pygraphviz
```

接下来，安装`django-extensions`并将其添加到您的`INSTALLED_APPS`中。现在，您已经准备好了。

以下是一个示例用法，用于创建仅包含两个应用程序的 GraphViz dot 文件，并将其转换为 PNG 图像以进行查看：

```py
$ python manage.py graph_models app1 app2 > models.dot
$ dot -Tpng models.dot -o models.png
```

# 渐进式更改还是完全重写？

通常情况下，你会被应用所有者交付遗留代码，并怀着真诚的希望，希望大部分代码可以立即或经过一些小的调整后就可以使用。然而，阅读和理解庞大而经常过时的代码库并不是一件容易的工作。毫不奇怪，大多数程序员更愿意从事全新的开发工作。

在最好的情况下，遗留代码应该易于测试，有良好的文档记录，并且灵活适应现代环境，以便您可以立即开始进行渐进式更改。在最坏的情况下，您可能会建议放弃现有代码，进行完全重写。或者，通常决定采取的是短期方法，即继续进行渐进式更改，并且可能正在进行完全重新实现的长期并行努力。

在做出此类决定时，一个通用的经验法则是——如果重写应用程序和维护应用程序的成本低于随时间维护旧应用程序的成本，那么建议进行重写。必须考虑所有因素，例如让新程序员熟悉所需时间、维护过时硬件的成本等。

有时，应用领域的复杂性成为重写的巨大障碍，因为在构建旧代码过程中学到的许多知识都会丢失。通常，对遗留代码的依赖表明应用设计不佳，例如未能将业务规则从应用逻辑中外部化。

您可能进行的最糟糕的重写形式可能是转换，或者是机械地将一种语言转换为另一种语言，而不利用现有的最佳实践。换句话说，您失去了通过消除多年的混乱来现代化代码库的机会。

代码应被视为一种负债而不是一种资产。尽管这听起来可能有些违反直觉，但如果您可以用更少的代码实现业务目标，您的生产力将大大提高。拥有更少的代码需要测试、调试和维护，不仅可以减少持续成本，还可以使您的组织更具敏捷性和灵活性以应对变化。

### 提示

代码是一种负债而不是一种资产。更少的代码更易维护。

无论您是在添加功能还是精简代码，都不应在没有测试的情况下触碰工作中的遗留代码。

# 在进行任何更改之前编写测试

在《与遗留代码有效工作》一书中，迈克尔·费瑟斯将遗留代码定义为简单的没有测试的代码。他解释说，有了测试，可以轻松快速地修改代码的行为并进行验证。在没有测试的情况下，无法判断更改是否使代码变得更好还是更糟。

通常情况下，我们对遗留代码了解不足，无法自信地编写测试。迈克尔建议编写保留和记录现有行为的测试，这些测试称为表征测试。

与通常的编写测试的方法不同，在编写表征测试时，您将首先编写一个带有虚拟输出（例如*X*）的失败测试，因为您不知道预期结果。当测试工具出现错误时，例如“**预期输出为 X，但得到了 Y**”，然后您将更改测试以期望*Y*。现在测试将通过，并且它成为了代码现有行为的记录。

请注意，我们可能记录有错误的行为。毕竟，这是陌生的代码。然而，在开始更改代码之前，编写这些测试是必要的。稍后，当我们更了解规格和代码时，我们可以修复这些错误并更新我们的测试（不一定按照这个顺序）。

## 编写测试的逐步过程

在更改代码之前编写测试类似于在修复旧建筑之前搭建脚手架。它提供了一个结构框架，帮助您自信地进行修复。

您可能希望以以下步骤逐步进行这个过程：

1.  确定您需要进行更改的区域。编写着重于这个区域的表征测试，直到您满意地捕捉到它的行为。

1.  看看你需要做出的改变，并为这些改变编写具体的测试用例。更喜欢较小的单元测试而不是较大和较慢的集成测试。

1.  引入增量更改并进行锁步测试。如果测试失败，那么尝试分析是否是预期的。不要害怕甚至打破表征测试，如果该行为是打算更改的。

如果您的代码周围有一套良好的测试，那么您可以快速找到更改代码的影响。

另一方面，如果你决定通过放弃代码而不是数据来重写，那么 Django 可以帮助你很多。

# 遗留数据库

Django 文档中有一个完整的遗留数据库部分，这是正确的，因为你会经常遇到它们。数据比代码更重要，而数据库是大多数企业数据的存储库。

您可以通过将其数据库结构导入 Django 来现代化使用其他语言或框架编写的遗留应用程序。作为一个直接的优势，您可以使用 Django 管理界面来查看和更改您的遗留数据。

Django 通过`inspectdb`管理命令使这变得容易，如下所示：

```py
$ python manage.py inspectdb > models.py

```

如果在设置配置为使用遗留数据库的情况下运行此命令，它可以自动生成 Python 代码，该代码将放入您的模型文件中。

如果您正在使用这种方法来集成到遗留数据库中，以下是一些最佳实践：

+   事先了解 Django ORM 的限制。目前，不支持多列（复合）主键和 NoSQL 数据库。

+   不要忘记手动清理生成的模型，例如删除冗余的`ID`字段，因为 Django 会自动创建它们。

+   外键关系可能需要手动定义。在一些数据库中，自动生成的模型将它们作为整数字段（后缀为`_id`）。

+   将模型组织到单独的应用程序中。稍后，将更容易在适当的文件夹中添加视图、表单和测试。

+   请记住，运行迁移将在遗留数据库中创建 Django 的管理表（`django_*`和`auth_*`）。

在理想的世界中，您的自动生成的模型将立即开始工作，但在实践中，这需要大量的试验和错误。有时，Django 推断的数据类型可能与您的期望不符。在其他情况下，您可能希望向模型添加额外的元信息，如`unique_together`。

最终，你应该能够在熟悉的 Django 管理界面中看到那个老化的 PHP 应用程序中锁定的所有数据。我相信这会让你微笑。

# 总结

在本章中，我们讨论了理解遗留代码的各种技术。阅读代码经常是被低估的技能。但我们需要明智地重用好的工作代码，而不是重复造轮子。在本章和本书的其余部分，我们强调编写测试用例作为编码的一个组成部分的重要性。

在下一章中，我们将讨论编写测试用例和随之而来的经常令人沮丧的调试任务。


# 第九章：测试和调试

在本章中，我们将讨论以下主题：

+   测试驱动开发

+   编写测试的注意事项

+   模拟

+   调试

+   日志

每个程序员至少都考虑过跳过编写测试。在 Django 中，默认的应用程序布局具有一个带有一些占位内容的`tests.py`模块。这是一个提醒，需要测试。然而，我们经常会有跳过它的诱惑。

在 Django 中，编写测试与编写代码非常相似。实际上，它几乎就是代码。因此，编写测试的过程可能看起来像是编写代码的两倍（甚至更多）。有时，我们在时间上承受如此大的压力，以至于在试图让事情正常运行时，花时间编写测试似乎是荒谬的。

然而，最终，如果您希望其他人使用您的代码，跳过测试是毫无意义的。想象一下，您发明了一种电动剃须刀，并试图向朋友出售，说它对您来说效果很好，但您没有进行适当的测试。作为您的好朋友，他或她可能会同意，但是想象一下，如果您告诉这个情况给一个陌生人，那将是多么可怕。

# 为什么要编写测试？

软件中的测试检查它是否按预期工作。没有测试，您可能能够说您的代码有效，但您将无法证明它是否正确工作。

此外，重要的是要记住，在 Python 中省略单元测试可能是危险的，因为它具有鸭子类型的特性。与 Haskell 等语言不同，类型检查无法在编译时严格执行。在 Python 开发中，单元测试在运行时（尽管在单独的执行中）是必不可少的。

编写测试可能是一种令人谦卑的经历。测试将指出您的错误，并且您将有机会进行早期的调整。事实上，有些人主张在编写代码之前先编写测试。

# 测试驱动开发

**测试驱动开发（TDD）**是一种软件开发形式，您首先编写测试，运行测试（最初会失败），然后编写使测试通过所需的最少代码。这可能听起来有违直觉。为什么我们需要在知道我们还没有编写任何代码并且确定它会因此失败时编写测试呢？

然而，请再次看一看。我们最终确实会编写仅满足这些测试的代码。这意味着这些测试不是普通的测试，它们更像是规范。它们告诉你可以期待什么。这些测试或规范将直接来自您的客户的用户故事。您只需编写足够的代码使其正常工作。

测试驱动开发的过程与科学方法有许多相似之处，这是现代科学的基础。在科学方法中，重要的是首先提出假设，收集数据，然后进行可重复和可验证的实验来证明或证伪你的假设。

我的建议是，一旦您熟悉为项目编写测试，就尝试 TDD。初学者可能会发现很难构建一个检查代码应该如何行为的测试用例。出于同样的原因，我不建议探索性编程使用 TDD。

# 编写测试用例

有不同类型的测试。但是，至少程序员需要了解单元测试，因为他们必须能够编写它们。单元测试检查应用程序的最小可测试部分。集成测试检查这些部分是否与彼此良好地配合。

这里的关键词是单元。一次只测试一个单元。让我们看一个简单的测试用例的例子：

```py
# tests.py
from django.test import TestCase
from django.core.urlresolvers import resolve
from .views import HomeView
class HomePageOpenTestCase(TestCase):
    def test_home_page_resolves(self):
        view = resolve('/')
        self.assertEqual(view.func.__name__,
                         HomeView.as_view().__name__)
```

这是一个简单的测试，检查当用户访问我们网站域的根目录时，他们是否被正确地带到主页视图。像大多数好的测试一样，它有一个长而自描述的名称。该测试简单地使用 Django 的`resolve（）`函数将视图可调用匹配到`/`根位置的视图函数，通过它们的名称。

更重要的是要注意这个测试中没有做什么。我们没有尝试检索页面的 HTML 内容或检查其状态代码。我们限制自己只测试一个单元，即`resolve()`函数，它将 URL 路径映射到视图函数。

假设此测试位于项目的`app1`中，可以使用以下命令运行测试：

```py
$ ./manage.py test app1
Creating test database for alias 'default'...
.
-----------------------------------------------------------------
Ran 1 test in 0.088s

OK
Destroying test database for alias 'default'...
```

此命令将运行`app1`应用程序或包中的所有测试。默认的测试运行程序将在此包中的所有模块中查找与模式`test*.py`匹配的测试。

Django 现在使用 Python 提供的标准`unittest`模块，而不是捆绑自己的模块。您可以通过从`django.test.TestCase`继承来编写`testcase`类。该类通常具有以下命名约定的方法：

+   `test*`：任何以`test`开头的方法都将作为测试方法执行。它不带参数，也不返回任何值。测试将按字母顺序运行。

+   `setUp`（可选）：此方法将在每个测试方法运行之前运行。它可用于创建公共对象或执行其他初始化任务，使测试用例处于已知状态。

+   `tearDown`（可选）：此方法将在测试方法之后运行，无论测试是否通过。通常在此执行清理任务。

测试用例是逻辑上组织测试方法的一种方式，所有这些方法都测试一个场景。当所有测试方法都通过（即不引发任何异常）时，测试用例被视为通过。如果其中任何一个失败，则测试用例失败。

## assert 方法

每个测试方法通常调用`assert*()`方法来检查测试的某些预期结果。在我们的第一个示例中，我们使用`assertEqual()`来检查函数名称是否与预期函数匹配。

与`assertEqual()`类似，Python 3 的`unittest`库提供了超过 32 个断言方法。Django 通过超过 19 个特定于框架的断言方法进一步扩展了它。您必须根据您期望的最终结果选择最合适的方法，以便获得最有帮助的错误消息。

让我们通过查看具有以下`setUp()`方法的示例`testcase`来看看为什么：

```py
def setUp(self):
    self.l1 = [1, 2]
    self.l2 = [1, 0]
```

我们的测试是断言`l1`和`l2`是否相等（鉴于它们的值，它应该失败）。让我们看看几种等效的方法来实现这一点：

| 测试断言语句 | 测试输出的外观（省略不重要的行） |
| --- | --- |

|

```py
assert self.l1 == self.l2
```

|

```py
assert self.l1 == self.l2
AssertionError
```

|

|

```py
self.assertEqual(self.l1, self.l2)
```

|

```py
AssertionError: Lists differ: [1, 2] != [1, 0]
First differing element 1:
2
0
```

|

|

```py
self.assertListEqual( self.l1, self.l2)
```

|

```py
AssertionError: Lists differ: [1, 2] != [1, 0]

First differing element 1:
2
0
```

|

|

```py
self.assertListEqual(self.l1, None)
```

|

```py
AssertionError: Second sequence is not a list: None
```

|

第一条语句使用了 Python 内置的`assert`关键字。请注意，它抛出的错误最不有帮助。您无法推断出`self.l1`和`self.l2`变量中的值或类型。这主要是我们需要使用`assert*()`方法的原因。

接下来，`assertEqual()`抛出的异常非常有帮助，它告诉您正在比较两个列表，甚至告诉您它们开始有差异的位置。这与更专门的`assertListEqual()`函数抛出的异常完全相同。这是因为，正如文档所告诉您的那样，如果`assertEqual()`给出两个列表进行比较，那么它会将其交给`assertListEqual()`。

尽管如最后一个示例所证明的那样，对于测试来说，始终最好使用最具体的`assert*`方法。由于第二个参数不是列表，错误明确告诉您期望的是列表。

### 提示

在测试中使用最具体的`assert*`方法。

因此，您需要熟悉所有的`assert`方法，并选择最具体的方法来评估您期望的结果。这也适用于当您检查应用程序是否没有执行不应该执行的操作时，即负面测试用例。您可以分别使用`assertRaises`和`assertWarns`来检查异常或警告。

## 编写更好的测试用例

我们已经看到，最好的测试用例一次测试一小部分代码。它们还需要快速。程序员需要在每次提交到源代码控制之前至少运行一次测试。即使延迟几秒钟也可能会诱使程序员跳过运行测试（这不是一件好事）。

以下是一个好的测试用例的一些特点（当然，这是一个主观的术语），以易于记忆的助记符“**F.I.R.S.T**”形式的类测试用例：

1.  **快速**：测试越快，运行次数越多。理想情况下，您的测试应该在几秒钟内完成。

1.  **独立**：每个测试用例必须独立于其他测试用例，并且可以以任何顺序运行。

1.  **可重复**：结果在每次运行测试时必须相同。理想情况下，所有随机和变化因素都必须在运行测试之前得到控制或设置为已知值。

1.  **小型**：测试用例必须尽可能简短，以提高速度和易于理解。

1.  **透明**：避免棘手的实现或模糊的测试用例。

此外，确保您的测试是自动的。消除任何手动步骤，无论多么小。自动化测试更有可能成为团队工作流程的一部分，并且更容易用于工具化目的。

也许，编写测试用例时更重要的是要记住的一些不要做的事情：

+   **不要（重新）测试框架**：Django 经过了充分的测试。不要检查 URL 查找、模板渲染和其他与框架相关的功能。

+   **不要测试实现细节**：测试接口，留下较小的实现细节。这样以后重构会更容易，而不会破坏测试。

+   **测试模型最多，模板最少**：模板应该具有最少的业务逻辑，并且更改频率更高。

+   **避免 HTML 输出验证**：测试视图使用其上下文变量的输出，而不是其 HTML 渲染的输出。

+   **避免在单元测试中使用 Web 测试客户端**：Web 测试客户端调用多个组件，因此更适合集成测试。

+   **避免与外部系统交互**：如果可能的话，对其进行模拟。数据库是一个例外，因为测试数据库是内存中的，而且非常快。

当然，您可以（也应该）在有充分理由的情况下打破规则（就像我在我的第一个例子中所做的那样）。最终，您在编写测试时越有创意，就越早发现错误，您的应用程序就会越好。

# 模拟

大多数现实项目的各个组件之间存在各种相互依赖关系。在测试一个组件时，其结果不能受到其他组件行为的影响。例如，您的应用程序可能调用一个可能在网络连接方面不可靠或响应速度慢的外部网络服务。

模拟对象通过具有相同接口来模拟这些依赖关系，但它们会对方法调用做出预先设定的响应。在测试中使用模拟对象后，您可以断言是否调用了某个特定方法，并验证预期的交互是否发生。

以*模式：服务对象*（见第三章，*模型*）中提到的超级英雄资格测试为例。我们将使用 Python 3 的`unittest.mock`库在测试中模拟对服务对象方法的调用：

```py
# profiles/tests.py
from django.test import TestCase
from unittest.mock import patch
from django.contrib.auth.models import User

class TestSuperHeroCheck(TestCase):
    def test_checks_superhero_service_obj(self):
        with patch("profiles.models.SuperHeroWebAPI") as ws:
            ws.is_hero.return_value = True
            u = User.objects.create_user(username="t")
            r = u.profile.is_superhero()
        ws.is_hero.assert_called_with('t')
        self.assertTrue(r)
```

在这里，我们在`with`语句中使用`patch()`作为上下文管理器。由于配置文件模型的`is_superhero()`方法将调用`SuperHeroWebAPI.is_hero()`类方法，我们需要在`models`模块内对其进行模拟。我们还将硬编码此方法的返回值为`True`。

最后两个断言检查方法是否使用正确的参数进行了调用，以及`is_hero()`是否返回了`True`。由于`SuperHeroWebAPI`类的所有方法都已被模拟，这两个断言都将通过。

模拟对象来自一个称为**测试替身**的家族，其中包括存根、伪造等。就像电影替身代替真正的演员一样，这些测试替身在测试时代替真实对象使用。虽然它们之间没有明确的界限，但模拟对象是可以测试行为的对象，而存根只是占位符实现。

# 模式 - 测试固件和工厂

**问题**：测试一个组件需要在测试之前创建各种先决对象。在每个测试方法中显式创建它们会变得重复。

**解决方案**：利用工厂或固件来创建测试数据对象。

## 问题细节

在运行每个测试之前，Django 会将数据库重置为其初始状态，就像运行迁移后的状态一样。大多数测试都需要创建一些初始对象来设置状态。通常情况下，不同的初始对象不会为不同的场景创建，而是通常创建一组通用的初始对象。

在大型测试套件中，这可能很快变得难以管理。这些初始对象的种类繁多，很难阅读和理解。这会导致测试数据本身中难以找到的错误！

作为一个常见的问题，有几种方法可以减少混乱并编写更清晰的测试用例。

## 解决方案细节

我们将首先看一下 Django 文档中提供的解决方案 - 测试固件。在这里，测试固件是一个包含一组数据的文件，可以导入到数据库中，使其达到已知状态。通常情况下，它们是从同一数据库中导出的 YAML 或 JSON 文件，当时数据库中有一些数据。

例如，考虑以下使用测试固件的测试用例：

```py
from django.test import TestCase

class PostTestCase(TestCase):
    fixtures = ['posts']

    def setUp(self):
        # Create additional common objects
        pass

    def test_some_post_functionality(self):
        # By now fixtures and setUp() objects are loaded
        pass
```

在每个测试用例中调用`setUp()`之前，指定的固件`posts`会被加载。粗略地说，固件将在固件目录中搜索具有某些已知扩展名的文件，例如`app/fixtures/posts.json`。

然而，固件存在许多问题。固件是数据库的静态快照。它们依赖于模式，并且每当模型更改时都必须更改。当测试用例的断言更改时，它们也可能需要更新。手动更新一个包含多个相关对象的大型固件文件并不是一件简单的事情。

出于所有这些原因，许多人认为使用固件是一种反模式。建议您改用工厂。工厂类创建特定类的对象，可以在测试中使用。这是一种 DRY 的方式来创建初始测试对象。

让我们使用模型的`objects.create`方法来创建一个简单的工厂：

```py
from django.test import TestCase
from .models import Post

class PostFactory:
    def make_post(self):
        return Post.objects.create(message="")

class PostTestCase(TestCase):

    def setUp(self):
        self.blank_message = PostFactory().makePost()

    def test_some_post_functionality(self):
        pass
```

与使用固件相比，初始对象的创建和测试用例都在一个地方。固件将静态数据原样加载到数据库中，而不调用模型定义的`save()`方法。由于工厂对象是动态生成的，它们更有可能通过应用程序的自定义验证。

然而，编写这种工厂类本身存在很多样板代码。基于 thoughtbot 的`factory_girl`，`factory_boy`包提供了一个声明性的语法来创建对象工厂。

将先前的代码重写为使用`factory_boy`，我们得到以下结果：

```py
import factory
from django.test import TestCase
from .models import Post

class PostFactory(factory.Factory):
    class Meta:
        model = Post
    message = ""

class PostTestCase(TestCase):

    def setUp(self):
        self.blank_message = PostFactory.create()
        self.silly_message = PostFactory.create(message="silly")

    def test_post_title_was_set(self):
        self.assertEqual(self.blank_message.message, "")
        self.assertEqual(self.silly_message.message, "silly")
```

注意在声明性方式下编写的`factory`类变得多么清晰。属性的值不必是静态的。您可以具有顺序、随机或计算的属性值。如果您希望使用更真实的占位符数据，例如美国地址，那么请使用`django-faker`包。

总之，我建议大多数需要初始测试对象的项目使用工厂，特别是`factory_boy`。尽管人们可能仍然希望使用固件来存储静态数据，例如国家列表或 T 恤尺寸，因为它们很少改变。

### 注意

**可怕的预测**

在宣布了不可能的最后期限之后，整个团队似乎突然没有时间了。他们从 4 周的 Scrum 冲刺变成了 1 周的冲刺。史蒂夫把他们日历上的每次会议都取消了，除了“今天与史蒂夫的 30 分钟补充会议”。如果他需要与某人交谈，他更喜欢一对一的讨论。

在 Madam O 的坚持下，30 分钟的会议在 S.H.I.M.总部下面 20 层的隔音大厅举行。周一，团队站在一个灰色金属表面的大圆桌周围。史蒂夫笨拙地站在桌子前，用手掌做了一个僵硬的挥动手势。

尽管每个人都曾见过全息图像活跃起来，但每次看到它们都让他们惊叹不已。这个圆盘几乎分成了数百个金属方块，并像未来模型城市中的迷你摩天大楼一样升起。他们花了一秒钟才意识到他们正在看一个 3D 柱状图。

“我们的燃尽图似乎显示出放缓的迹象。我猜这是我们最近用户测试的结果，这是一件好事。但是……”史蒂夫的脸上似乎带着压抑打喷嚏的表情。他小心翼翼地用食指在空中轻轻一弹，图表顺利地向右延伸。

按照目前的速度，预测显示我们最好也要推迟上线几天。我做了一些分析，发现我们在开发的后期发现了一些关键的错误。如果我们能早点发现它们，我们就可以节省很多时间和精力。我想让你们集思广益，想出一些……”

史蒂夫捂住嘴，打了一个响亮的喷嚏。全息图将这解释为放大图表中一个特别无聊的部分的迹象。史蒂夫咒骂着关掉了它。他借了一张餐巾纸，开始用普通的笔记下每个人的建议。

史蒂夫最喜欢的建议之一是编写一个编码清单，列出最常见的错误，比如忘记应用迁移。他还喜欢在开发过程中早期让用户参与并提供反馈的想法。他还记下了一些不寻常的想法，比如为连续集成服务器的状态发布推特。

会议结束时，史蒂夫注意到埃文不见了。“埃文在哪里？”他问。“不知道，”布拉德看起来很困惑地说，“刚才还在这。”

# 学习更多关于测试

多年来，Django 的默认测试运行器已经有了很大的改进。然而，像`py.test`和`nose`这样的测试运行器在功能上仍然更胜一筹。它们使你的测试更容易编写和运行。更好的是，它们与你现有的测试用例兼容。

你可能也对知道你的代码有多少百分比是由测试覆盖的感兴趣。这被称为**代码覆盖**，`coverage.py`是一个非常流行的工具，可以找出这一点。

今天的大多数项目往往使用了大量的 JavaScript 功能。为它们编写测试通常需要一个类似浏览器的环境来执行。Selenium 是一个用于执行此类测试的出色的浏览器自动化工具。

尽管在本书的范围之外详细讨论 Django 中的测试，我强烈建议你了解更多关于它的知识。

如果没有别的，我想通过这一部分传达的两个主要观点是，首先，编写测试，其次，一旦你对编写测试有信心，就要练习 TDD。

# 调试

尽管进行了最严格的测试，悲哀的现实是，我们仍然不得不处理错误。Django 尽最大努力在报告错误时提供帮助。然而，要识别问题的根本原因需要很多技巧。

幸运的是，通过正确的工具和技术，我们不仅可以识别错误，还可以深入了解代码的运行时行为。让我们来看看其中一些工具。

## Django 调试页面

如果您在开发中遇到任何异常，即`DEBUG=True`时，那么您可能已经看到了类似以下截图的错误页面：

![Django 调试页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644OS_09_01.jpg)

由于它经常出现，大多数开发人员倾向于忽略此页面中的丰富信息。以下是一些要查看的地方：

+   **异常详细信息**：显然，您需要非常仔细地阅读异常告诉您的内容。

+   **异常位置**：这是 Python 认为错误发生的位置。在 Django 中，这可能是错误的根本原因，也可能不是。

+   **回溯**：这是错误发生时的调用堆栈。导致错误的行将在最后。导致它的嵌套调用将在其上方。不要忘记单击“**Local vars**”箭头以检查异常发生时变量的值。

+   **请求信息**：这是一个表格（未在截图中显示），显示上下文变量、元信息和项目设置。在此处检查请求中的格式错误。

### 更好的调试页面

通常，您可能希望在默认的 Django 错误页面中获得更多的交互性。`django-extensions`软件包附带了出色的 Werkzeug 调试器，提供了这个功能。在相同异常的以下截图中，请注意在调用堆栈的每个级别上都有一个完全交互式的 Python 解释器：

![更好的调试页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644OS_09_02.jpg)

要启用此功能，除了将`django_extensions`添加到您的`INSTALLED_APPS`中，您还需要按照以下方式运行测试服务器：

```py
$ python manage.py runserver_plus
```

尽管调试信息减少了，但我发现 Werkzeug 调试器比默认错误页面更有用。

# 打印函数

在代码中到处添加`print()`函数进行调试可能听起来很原始，但对许多程序员来说，这是首选的技术。

通常，在发生异常的行之前添加`print()`函数。它可以用于打印导致异常的各行中变量的状态。您可以通过在达到某一行时打印某些内容来跟踪执行路径。

在开发中，打印输出通常会出现在运行测试服务器的控制台窗口中。而在生产中，这些打印输出可能会出现在服务器日志文件中，从而增加运行时开销。

无论如何，在生产中使用它都不是一个好的调试技术。即使您这样做，也应该从提交到源代码控制中的`print`函数中删除。

# 日志记录

包括前一部分的主要原因是说 - 您应该用 Python 的`logging`模块中的日志函数来替换`print()`函数。日志记录比打印有几个优点：它具有时间戳，明确定义的紧急程度（例如，INFO，DEBUG），而且您以后不必从代码中删除它们。

日志记录对于专业的 Web 开发至关重要。您的生产堆栈中的几个应用程序，如 Web 服务器和数据库，已经使用日志。调试可能会带您到所有这些日志，以追溯导致错误的事件。您的应用程序遵循相同的最佳实践并采用日志记录以记录错误、警告和信息消息是合适的。

与普遍看法不同，使用记录器并不涉及太多工作。当然，设置稍微复杂，但这仅仅是对整个项目的一次性努力。而且，大多数项目模板（例如`edge`模板）已经为您做到了这一点。

一旦您在`settings.py`中配置了`LOGGING`变量，像这样向现有代码添加记录器就非常容易：

```py
# views.py
import logging
logger = logging.getLogger(__name__)

def complicated_view():
    logger.debug("Entered the complicated_view()!")
```

`logging`模块提供了各种级别的日志消息，以便您可以轻松过滤掉不太紧急的消息。日志输出也可以以各种方式格式化，并路由到许多位置，例如标准输出或日志文件。阅读 Python 的`logging`模块文档以了解更多信息。

# Django Debug Toolbar

Django Debug Toolbar 不仅是调试的必不可少的工具，还可以跟踪每个请求和响应的详细信息。工具栏不仅在异常发生时出现，而且始终出现在呈现的页面中。

最初，它会出现在浏览器窗口右侧的可点击图形上。单击后，工具栏将作为一个深色半透明的侧边栏出现，并带有几个标题：

![Django Debug Toolbar](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644OS_09_03.jpg)

每个标题都包含有关页面的详细信息，从执行的 SQL 查询数量到用于呈现页面的模板。由于当`DEBUG`设置为 False 时，工具栏会消失，因此它基本上只能作为开发工具使用。

# Python 调试器 pdb

在调试过程中，您可能需要在 Django 应用程序执行中间停止以检查其状态。实现这一点的简单方法是在所需位置使用简单的`assert False`行引发异常。

如果您想要从那一行开始逐步执行，可以使用交互式调试器，例如 Python 的`pdb`。只需在想要停止执行的位置插入以下行并切换到`pdb`：

```py
import pdb; pdb.set_trace()
```

一旦输入`pdb`，您将在控制台窗口中看到一个命令行界面，带有`(Pdb)`提示。与此同时，您的浏览器窗口不会显示任何内容，因为请求尚未完成处理。

pdb 命令行界面非常强大。它允许您逐行查看代码，通过打印它们来检查变量，或执行甚至可以更改运行状态的任意代码。该界面与 GNU 调试器 GDB 非常相似。

# 其他调试器

有几种可替换`pdb`的工具。它们通常具有更好的界面。以下是一些基于控制台的调试器：

+   `ipdb`：像 IPython 一样，它具有自动完成、语法着色的代码等。

+   `pudb`：像旧的 Turbo C IDE 一样，它将代码和变量并排显示。

+   `IPython`：这不是一个调试器。您可以通过添加`from IPython import embed; embed()`行在代码中的任何位置获取完整的 IPython shell。

PuDB 是我首选的 pdb 替代品。它非常直观，即使是初学者也可以轻松使用这个界面。与 pdb 一样，只需插入以下代码来中断程序的执行：

```py
import pudb; pudb.set_trace()
```

执行此行时，将启动全屏调试器，如下所示：

![其他调试器](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj-dsn-ptn-best-prac/img/6644OS_09_04.jpg)

按下`?`键以获取有关可以使用的完整键列表的帮助。

此外，还有几种图形调试器，其中一些是独立的，例如`winpdb`，另一些是集成到 IDE 中的，例如 PyCharm，PyDev 和 Komodo。我建议您尝试其中几种，直到找到适合您工作流程的调试器。

# 调试 Django 模板

项目的模板中可能有非常复杂的逻辑。在创建模板时出现细微错误可能导致难以找到的错误。我们需要在`settings.py`中将`TEMPLATE_DEBUG`设置为`True`（除了`DEBUG`），以便 Django 在模板出现错误时显示更好的错误页面。

有几种粗糙的调试模板的方法，例如插入感兴趣的变量，如`{{ variable }}`，或者如果要转储所有变量，可以使用内置的`debug`标签，如下所示（在一个方便的可点击文本区域内）：

```py
<textarea onclick="this.focus();this.select()" style="width: 100%;"> 
  {% filter force_escape %} 
 {% debug %} 
  {% endfilter %}
</textarea>
```

更好的选择是使用前面提到的 Django Debug Toolbar。它不仅告诉您上下文变量的值，还显示模板的继承树。

然而，您可能希望在模板的中间暂停以检查状态（比如在循环内）。调试器对于这种情况非常完美。事实上，可以使用前面提到的任何一个 Python 调试器来为您的模板使用自定义模板标签。

这是一个简单的模板标签的实现。在`templatetag`包目录下创建以下文件：

```py
# templatetags/debug.py
import pudb as dbg              # Change to any *db
from django.template import Library, Node

register = Library()

class PdbNode(Node):

    def render(self, context):
        dbg.set_trace()         # Debugger will stop here
        return ''

@register.tag
def pdb(parser, token):
    return PdbNode()
```

在您的模板中，加载模板标签库，将`pdb`标签插入到需要执行暂停的地方，并进入调试器：

```py
{% load debug %}

{% for item in items %}
    {# Some place you want to break #}
    {% pdb %}
{% endfor %}
```

在调试器中，您可以检查任何东西，包括使用`context`字典的上下文变量：

```py
>>> print(context["item"])
Item0
```

如果您需要更多类似的模板标签用于调试和内省，我建议您查看`django-template-debug`包。

# 摘要

在本章中，我们看了 Django 中测试的动机和概念。我们还发现了编写测试用例时应遵循的各种最佳实践。在调试部分，我们熟悉了在 Django 代码和模板中查找错误的各种调试工具和技术。

在下一章中，我们将通过了解各种安全问题以及如何减少各种恶意攻击威胁，使代码更接近生产代码。
