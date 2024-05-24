# Django 1.1 测试和调试教程（二）

> 原文：[`zh.annas-archive.org/md5/ECB5EEA8F49C43CEEB591D269760F77D`](https://zh.annas-archive.org/md5/ECB5EEA8F49C43CEEB591D269760F77D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：变得更高级：Django 单元测试扩展

在上一章中，我们开始学习如何使用单元测试来测试 Django 应用程序。这包括学习一些 Django 特定的支持，比如如何将测试数据从装置文件加载到数据库中进行特定的测试。到目前为止，我们的测试重点一直是应用程序的组成部分。我们还没有开始编写用于为我们的应用程序提供网页服务的代码，也没有考虑如何测试页面是否被正确地提供并包含正确的内容。Django 的`TestCase`类提供了对这种更广泛的测试有用的支持，这将是本章的重点。在本章中，我们将：

+   首先学习如何使用一个 tests 目录来进行 Django 应用程序的测试，而不是单个的`tests.py`文件。这将使我们能够逻辑地组织测试，而不是将各种不同的测试混合在一个巨大的文件中。

+   为调查应用程序开发一些网页。对于每一个，我们将编写单元测试来验证它们的正确操作，途中学习测试 Django 应用程序的`TestCase`支持的具体细节。

+   尝试在管理应用程序的`Survey`模型中添加自定义验证，并查看如何测试这样的定制。

+   简要讨论一些 Django 测试支持中的方面，在我们的示例测试中没有遇到的。

+   最后，我们将学习在什么条件下可能需要使用替代的单元测试类`TransactionTestCase`。这个类的性能不如`TestCase`，但它支持测试一些使用`TestCase`不可能的数据库事务行为。

# 组织测试

在我们开始编写用于为调查应用程序提供网页服务的代码（和测试）之前，让我们先考虑一下我们到目前为止所拥有的测试。如果我们运行`manage.py test survey -v2`并检查输出的末尾，我们会看到我们已经积累了超过十几个单独的测试：

```py
No fixtures found. 
testClearWinner (survey.tests.QuestionWinningAnswersTest) ... ok 
testNoAnswers (survey.tests.QuestionWinningAnswersTest) ... ok 
testNoResponses (survey.tests.QuestionWinningAnswersTest) ... ok 
testTwoWayTie (survey.tests.QuestionWinningAnswersTest) ... ok 
testActive (survey.tests.SurveyManagerTest) ... ok 
testCompleted (survey.tests.SurveyManagerTest) ... ok 
testUpcoming (survey.tests.SurveyManagerTest) ... ok 
Verify closes is autoset correctly ... ok 
Verify closes is honored if specified ... ok 
Verify closes is only autoset during initial create ... ok 
Verify correct exception is raised in error case ... ok 
testUnicode (survey.tests.SurveyUnicodeTest) ... ok 
Doctest: survey.models.Survey.__unicode__ ... ok 
Doctest: survey.models.Survey.save ... ok 
Doctest: survey.tests.__test__.survey_save ... ok 

---------------------------------------------------------------------- 
Ran 15 tests in 0.810s 

OK 
Destroying test database... 

```

其中两个，即以`survey.models.Survey`开头的标签的两个 doctest，来自`survey/models.py`文件。其余的 13 个测试都在`survey/tests.py`文件中，该文件已经增长到大约 150 行。这些数字并不算大，但是如果考虑到我们几乎刚刚开始编写这个应用程序，很明显，继续简单地添加到`tests.py`将很快导致一个难以管理的测试文件。由于我们即将开始从构建和测试调查模型转移到构建和测试提供网页服务的代码，现在是一个比单个文件更好的测试组织的好时机。

幸运的是，这并不难做到。Django 中没有要求测试都驻留在单个文件中；它们只需要在名为`tests`的 Python 模块中。因此，我们可以在`survey`中创建一个名为`tests`的子目录，并将现有的`tests.py`文件移动到其中。由于这个文件中的测试重点是测试应用程序的模型，让我们也将其重命名为`model_tests.py`。我们还应该删除`marketr/survey`中的`tests.pyc`文件，因为在 Python 代码重组后留下零散的`.pyc`文件通常会引起混乱。最后，我们需要在`tests`目录中创建一个`__init__.py`文件，以便 Python 将其识别为一个模块。

就这些吗？并不完全是。Django 使用`unittest.TestLoader.LoadTestsFromModule`来查找并自动加载`tests`模块中的所有`TestCase`类。然而，我们现在已经将所有的`TestCase`类移动到了名为`model_tests`的 tests 子模块中。为了让`LoadTestsFromModule`找到它们，我们需要使它们在父`tests`模块中可见，我们可以通过在`survey/tests`的`__init__.py`文件中添加对`model_tests`的导入来实现这一点：

```py
from model_tests import *
```

现在我们准备好了吗？几乎。如果我们现在运行`manage.py test survey -v2`，我们会发现输出报告显示运行了 14 个测试，而在重新组织之前的运行中报告显示运行了 15 个测试：

```py
No fixtures found. 
testClearWinner (survey.tests.model_tests.QuestionWinningAnswersTest) ... ok 
testNoAnswers (survey.tests.model_tests.QuestionWinningAnswersTest) ... ok

testNoResponses (survey.tests.model_tests.QuestionWinningAnswersTest) ... ok 
testTwoWayTie (survey.tests.model_tests.QuestionWinningAnswersTest) ... ok

testActive (survey.tests.model_tests.SurveyManagerTest) ... ok 
testCompleted (survey.tests.model_tests.SurveyManagerTest) ... ok 
testUpcoming (survey.tests.model_tests.SurveyManagerTest) ... ok 
Verify closes is autoset correctly ... ok 
Verify closes is honored if specified ... ok 
Verify closes is only autoset during initial create ... ok 
Verify correct exception is raised in error case ... ok 
testUnicode (survey.tests.model_tests.SurveyUnicodeTest) ... ok 
Doctest: survey.models.Survey.__unicode__ ... ok 
Doctest: survey.models.Survey.save ... ok 
---------------------------------------------------------------------- 
Ran 14 tests in 0.760s 

OK 
Destroying test database... 

```

哪个测试丢失了？早期运行的最后一个测试，也就是`tests.py`中的`__test__`字典中的 doctest。因为`__test__`以下划线开头（表示它是一个私有属性），所以它不会被`from model_tests import *`导入。命名所暗示的私有性并不受 Python 强制执行，因此我们也可以向`survey/tests/__init__.py`添加对`__test__`的显式导入：

```py
from model_tests import __test__ 
from model_tests import * 
```

如果我们这样做并再次运行测试，我们会发现我们又回到了 15 个测试。然而，这是一个很差的解决方案，因为它无法扩展到`tests`目录中的多个文件。如果我们向`tests`目录添加另一个文件，比如`view_tests.py`，并简单地复制用于`model_tests.py`的导入，我们将会有：

```py
from model_tests import __test__ 
from model_tests import * 
from view_tests import __test__
from view_tests import *
```

这不会导致任何错误，但也不完全有效。第二次导入`__test__`完全替换了第一次，因此如果我们这样做，`model_tests.py`中包含的 doctests 将会丢失。

很容易想出一种方法，可以扩展到多个文件，也许是通过为在单独的测试文件中定义的 doctests 创建我们自己的命名约定。然后，`__init__.py`中的代码可以通过将定义 doctests 的各个测试文件的字典合并为整个`tests`模块的`__test__`字典来实现。但是，出于我们将要研究的示例的目的，这是不必要复杂的，因为我们将要添加的额外测试都是单元测试，而不是 doctests。

实际上，现在在`model_tests.py`中的 doctests 也已经被重新实现为单元测试，因此它们作为测试是多余的，可以安全地删除。然而，它们确实指出了一个与 doctests 相关的问题，如果您决定在自己的项目中摆脱单文件`tests.py`方法，这个问题就会出现。我们可以通过简单地将`model_tests.py`文件中的`__test__`字典定义移动到`survey/tests/__init__.py`文件中来保留我们已经拥有的 doctests。然后，如果我们决定额外的 doctests（超出`models.py`中的 doctests）会很有用，我们可以简单地在`survey/tests/__init__.py`中添加到这个字典，或者想出一个更复杂的方法，允许将 doctests 以及单元测试拆分到不同的文件中。

请注意，不必将`tests`目录树限制在单个级别。我们可以为模型测试创建一个子目录，为视图创建一个子目录，并将这些测试进一步细分为单独的文件。使用我们在这里开始的方法，所需的只是在各种`__init__.py`文件中包含适当的导入，以便测试用例在`tests`包的顶层可见。将树设置多深以及将单个测试文件设置多小是个人偏好的问题。我们现在将坚持单层。

最后，请注意，您可以通过在应用的`models`和/或`tests`模块中定义一个`suite()`函数来完全控制组成应用测试套件的测试。Django 测试运行程序在这些模块中寻找这样的函数，如果`suite()`存在，就会调用它来创建测试套件。如果提供，`suite()`函数必须返回一个适合作为参数传递给`unittest.TestSuite.addTest`的对象（例如，一个`unittest.TestSuite`）。

# 创建调查应用首页

现在是时候把注意力转向为调查应用程序构建一些网页了。首先要考虑的页面是主页，这将是一般用户进行任何与调查相关操作的起点。最终，我们可能计划让这个页面有许多不同的元素，比如标准的页眉和页脚，也可能有一两个侧边栏用于新闻和反馈。我们计划开发全面的样式表，以赋予应用程序漂亮和一致的外观。但所有这些都不是我们现在想要关注的重点，我们现在想要关注的是主页的主要内容。

主页的主要功能将是提供当前调查状态的快照概览，并在适当的情况下提供链接，以允许用户查看各个调查的详细信息。主页将显示分为三类的调查：

+   首先，将列出当前开放的调查。此列表中的每个调查都将有一个链接，供用户参与调查。

+   其次，将列出最近完成的调查。这些调查也将有一个链接，但这个链接将带来一个页面，允许用户查看调查结果。

+   第三，将列出即将开放的调查。此列表中的调查将没有链接，因为用户还不能参与，也没有结果可见。

为了构建和测试这个主页，我们需要做四件事情：

1.  首先，我们需要定义用于访问主页和任何链接到它的页面的 URL，并在`urls.py`文件中定义这些 URL 应该如何映射到将提供页面的视图代码。

1.  其次，我们需要实现用于提供第 1 步中识别的页面的视图代码。

1.  第三，我们需要定义 Django 模板，用于呈现第 2 步生成的响应。

1.  最后，我们需要为每个页面编写测试。

接下来的章节将依次关注这些步骤中的每一个。

## 定义调查应用程序的 URL

从调查主页的描述来看，我们可能需要定义两个或三个不同的 URL。当然，首先是主页本身，最自然地放置在调查应用程序的 URL 树的根目录下。我们可以通过在`survey`目录中创建`urls.py`文件来定义这一点：

```py
from django.conf.urls.defaults import * 

urlpatterns = patterns('survey.views', 
    url(r'^$', 'home', name='survey_home'), 
) 
```

在这里，我们指定了对空（根）URL 的请求应由`survey.views`模块中的`home`函数处理。此外，我们给这个 URL 命名为`survey_home`，我们可以在其他代码中使用这个名称来引用这个 URL。始终使用命名 URL 是一个好的做法，因为它允许通过简单地更改`urls.py`文件而不需要更改其他代码来更改实际的 URL。

除了主页，还有从主页链接过去的页面需要考虑。首先是从活动调查列表中链接的页面，允许用户参与调查。其次是从最近完成的调查列表中链接的页面，允许用户查看结果。你可能会问，这些是否应该由一个还是两个 URL 来覆盖？

虽然听起来这些可能需要不同的 URL，因为页面将显示非常不同的内容，但从某种意义上说，它们都显示了同一件事情——特定调查的详细信息。只是调查的当前状态将影响其详细页面的显示。因此，我们可以选择将决定显示什么内容的逻辑，基于调查状态，放入处理显示调查详细信息的视图中。然后我们可以用一个 URL 模式来覆盖这两种类型的页面。采用这种方法，`survey/urls.py`文件变成了：

```py
from django.conf.urls.defaults import * 

urlpatterns = patterns('survey.views', 
    url(r'^$', 'home', name='survey_home'), 
    url(r'^(?P<pk>\d+)/$', 'survey_detail', name='survey_detail'), 
) 
```

在这里，我们采取了将调查的主键放入 URL 的方法。任何由一个或多个数字（主键）组成的单个路径组件的 URL 将被映射到`survey.views`模块中的`survey_detail`函数。该函数将接收主键路径组件作为参数`pk`，以及标准的请求参数。最后，这个 URL 被命名为`survey_detail`。

这两个 URL 模式足以定义我们到目前为止考虑的调查应用程序页面。但是，我们仍然需要将它们连接到项目的整体 URL 配置中。为此，请编辑项目的根`urls.py`文件，并为调查 URL 添加一行。然后，`urls.py`中的`urlpatterns`变量将被定义如下：

```py
urlpatterns = patterns('', 
    # Example: 
    # (r'^marketr/', include('marketr.foo.urls')), 

    # Uncomment the admin/doc line below and add # 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation: 
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')), 

    # Uncomment the next line to enable the admin: 
    (r'^admin/', include(admin.site.urls)), 
 (r'', include('survey.urls')), 
) 
```

我们在这里添加的最后一行指定了一个空的 URL 模式`r''`。所有匹配的 URL 将被测试与`survey`模块中包含的`urls.py`文件中找到的模式相匹配。模式`r''`将匹配每个 URL，并且在测试与`survey/urls.py`中的 URL 模式相匹配时，不会删除 URL 的任何部分，因此这实质上是将调查`urls.py`文件挂载到项目的 URL 树的根目录。

## 开发视图以提供页面

现在我们已经定义了我们的 URL 并指定了应该调用的视图函数来提供它们，是时候开始编写这些函数了。或者，也许我们应该从这些页面的模板开始？两者都需要完成，它们彼此之间是相互依赖的。视图返回的数据取决于模板的需求，而模板的编写方式取决于视图提供的数据的命名和结构。因此，很难知道从哪里开始，有时需要在它们之间交替进行。

然而，我们必须从某个地方开始，我们将从视图开始。实际上，每当您在`urls.py`文件中添加对视图的引用时，立即编写至少该视图的最小实现是一个好主意。例如，对于我们刚刚添加到`survey/urls.py`的两个视图，我们可能会立即将以下内容放在`survey/views.py`中：

```py
from django.http import HttpResponse 

def home(request): 
    return HttpResponse("This is the home page.") 

def survey_detail(request, pk): 
    return HttpResponse("This is the survey detail page for survey, " "with pk=%s" % pk) 
```

这些视图只是简单地返回描述页面应该显示的`HttpResponse`。创建这样的占位视图可以确保项目的整体 URL 模式配置保持有效。保持这个配置有效很重要，因为任何尝试执行反向 URL 映射（从名称到实际 URL）都会导致异常，如果在 URL 模式配置的任何部分中存在任何错误（例如引用不存在的函数）。因此，无效的 URL 配置很容易似乎破坏其他完全无辜的代码。

例如，管理应用程序需要使用反向 URL 映射在其页面上生成链接。因此，无效的 URL 模式配置可能导致在用户尝试访问管理页面时引发异常，即使管理代码本身没有错误。这种异常很难调试，因为乍一看似乎问题是由完全与实际错误位置分离的代码引起的。因此，即使您更喜欢在编写视图函数之前编写模板，最好立即为您添加到 URL 模式配置中的任何视图提供至少一个最低限度的实现。

我们可以进一步超越最低限度，至少对于主页视图是这样。如前所述，主页将显示三个不同的调查列表：活动的、最近完成的和即将开放的。模板可能不需要将数据结构化得比简单列表（或`QuerySet`）更复杂，因此主页的视图编写起来很简单：

```py
import datetime 
from django.shortcuts import render_to_response 
from survey.models import Survey 

def home(request): 
    today = datetime.date.today() 
    active = Survey.objects.active() 
    completed = Survey.objects.completed().filter(closes__gte=today-datetime.timedelta(14)) 
    upcoming = Survey.objects.upcoming().filter(opens__lte=today+datetime.timedelta(7))
    return render_to_response('survey/home.html', 
        {'active_surveys': active, 
         'completed_surveys': completed, 
         'upcoming_surveys': upcoming, 
        })
```

这个视图设置了三个变量，它们是包含数据库中`Surveys`适当子集的`QuerySets`。最近完成的集合限于在过去两周内关闭的调查，即将开放的集合限于在下周将要开放的调查。然后，视图调用`render_to_response`快捷方式来渲染`survey/home.html`模板，并传递一个上下文字典，其中包含三个`Survey`子集，分别是`active_surveys`、`completed_surveys`和`upcoming_surveys`上下文变量。

此时，我们可以继续用一些真实的代码替换占位符`survey_detail`视图的实现，或者我们可以开始一些模板。编写第二个视图并不能让我们更接近测试我们已经编写的第一个视图，所以继续进行模板的工作会更好。暂时用于第二个视图的占位内容现在也可以。

## 创建页面模板

要开始编写调查应用程序的模板，首先在`survey`下创建一个`templates`目录，然后在`templates`下创建一个`survey`目录。将模板放在应用程序目录下的`templates`目录下，可以使它们被默认启用的`app_directories`模板加载器自动找到。此外，将模板放在`templates`下的`survey`目录下，可以最大程度地减少与其他应用程序使用的模板的名称冲突的机会。

现在，我们需要创建哪些模板？在主页视图中命名的是`survey/home.html`。我们可以只创建一个文件，并将其作为一个完整的独立 HTTP 文档。但这是不现实的。Django 提供了一个方便的模板继承机制，允许重用常见页面元素并选择性地覆盖已定义的块。至少，我们可能希望使用一个定义了整体文档结构和块组件的通用基础模板，然后将个别页面模板实现为扩展基础模板的子模板。

这是一个最小的`base.html`模板，我们可以用它来开始：

```py
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<title>{% block title %}Survey Central{% endblock %}</title>
</head>
<body>
{% block content %}{% endblock %}
</body>
</html>
```

这个文档提供了整体的 HTML 结构标签，并定义了两个块：`title`和`content`。`title`块的默认内容是`Survey Central`，可以被子模板覆盖，或者保持不变。`content`块最初是空的，因此期望子模板始终提供一些内容来填充页面的主体。

有了基础模板，我们可以将`home.html`模板编写为一个扩展`base.html`并为`content`块提供内容的子模板。我们知道`home`视图提供了三个上下文变量（`active_surveys`、`completed_surveys`和`upcoming_surveys`），其中包含应该显示的数据。`home.html`模板的初始实现可能如下所示：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>Welcome to Survey Central</h1> 

{% if active_surveys %} 
<p>Take a survey now!</p> 
<ul> 
{% for survey in active_surveys %} 
<li><a href="{{ survey.get_absolute_url }}">{{ survey.title }}</a></li> 
{% endfor %} 
</ul> 
{% endif %} 

{% if completed_surveys %} 
<p>See how your opinions compared to those of others!</p> 
<ul> 
{% for survey in completed_surveys %} 
<li><a href="{{ survey.get_absolute_url }}">{{ survey.title }}</a></li> 
{% endfor %} 
</ul> 
{% endif %} 

{% if upcoming_surveys %} 
<p>Come back soon to share your opinion!</p> 
<ul> 
{% for survey in upcoming_surveys %} 
<li>{{ survey.title }} opens {{ survey.opens }}</li> 
{% endfor %} 
</ul> 
{% endif %} 
{% endblock content %} 
```

这可能看起来有点吓人，但它很简单。模板首先指定它扩展了`survey/base.html`模板。然后继续定义应该放在`base.html`中定义的`content`块中的内容。第一个元素是一个一级标题`欢迎来到调查中心`。然后，如果`active_surveys`上下文变量不为空，标题后面会跟着一个邀请人们参加调查的段落，然后是活动调查的列表。列表中的每个项目都被指定为一个链接，链接目标值是通过调用 Survey 的`get_absolute_url`方法获得的（我们还没有实现）。每个链接的可见文本都设置为`Survey`的`title`值。

如果有任何`completed_surveys`，则会显示一个几乎相同的段落和列表。最后，`upcoming_surveys`也会以类似的方式处理，只是在它们的情况下不会生成链接。相反，调查标题将与每个调查将开放的日期一起列出。

现在，`get_absolute_url`方法用于生成活动和已完成调查的链接？这是一个标准的模型方法，我们可以实现它来为我们网站上的模型实例提供 URL。除了在我们自己的代码中使用它之外，如果模型实现了它，管理应用程序也会使用它，在模型实例的更改页面上提供一个**在网站上查看**链接。

回想一下，在我们的`urls.py`文件中，我们为调查详情命名了 URL 为`survey_detail`，这个视图需要一个参数`pk`，这是要显示有关`Survey`实例的详细信息的主键。知道了这一点，我们可以在`Survey`模型中实现这个`get_absolute_url`方法：

```py
    def get_absolute_url(self): 
        from django.core.urlresolvers import reverse 
        return reverse('survey_detail', args=(self.pk,)) 
```

这种方法使用了`django.core.urlresolvers`提供的`reverse`函数来构造实际的 URL，该 URL 将映射到具有模型实例的主键值作为参数值的 URL 命名为`survey_detail`。

另外，我们可以使用方便的`models.permalink`装饰器，避免记住`reverse`函数需要从哪里导入：

```py
    @models.permalink
    def get_absolute_url(self):
        return ('survey_detail', (self.pk,))
```

这等同于实现`get_absolute_url`的第一种方式。这种方式只是隐藏了调用`reverse`函数的细节，因为`models.permalink`代码已经完成了这个工作。

现在，我们已经创建了首页视图和它使用的模板，并实现了从这些模板调用的所有模型方法，我们实际上可以测试这个视图。确保开发服务器正在运行（或者使用`manage.py runserver`重新启动），然后从同一台机器上的浏览器中，转到`http://localhost:8000/`。这应该（假设自上一章创建的`Winning Answers Test`距今不到一周）会显示一个页面，列出可以参与的调查：

![为页面创建模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_04_01.jpg)

如果自从创建调查以来已经超过一周，它应该显示在一个段落下，邀请您**查看您的观点与他人的观点相比如何！**。如果已经超过三周，调查就不应该出现在首页上，这种情况下，您可能需要返回管理应用程序并更改其`closes`日期，以便它出现在首页上。

那个**Winning Answers Test**文本是一个链接，可以点击以验证`Survey`的`get_absolute_url`方法是否有效，并且我们设置的 URL 配置是否有效。由于我们仍然只有调查详情视图的占位符视图实现，点击**Winning Answers Test**链接将显示一个页面，看起来像这样：

![为页面创建模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_04_02.jpg)

也许并不是特别令人印象深刻，但它确实验证了我们迄今为止放置的各种部件是否有效。

当然，由于数据库中只有一个调查，我们只验证了视图和模板的一部分。为了进行全面的测试，我们还应该验证所有三个类别中的调查是否正确显示。此外，我们还应该验证数据库中的调查是否不应该出现在首页上，因为它们太旧或太遥远。

我们现在可以通过在管理应用程序中手动添加调查并在进行更改时手动检查首页的内容来完成所有这些工作。然而，我们真正想要学习的是如何编写一个测试来验证我们现在的工作是否正确，并且更重要的是，允许我们在继续开发应用程序时验证它是否保持正确。因此，编写这样的测试是我们接下来要关注的重点。

## 测试调查首页

在考虑如何编写测试本身之前，让我们考虑一下测试所需的数据以及将这些数据放入数据库进行测试的最佳方法。这个测试将与上一章的`SurveyManagerTest`非常相似，因为确定正确的行为将取决于当前日期与测试数据中包含的日期的关系。因此，使用一个 fixture 文件来存储这些数据并不是一个好主意；最好在测试的`setUp`方法中动态添加数据。

因此，我们将首先编写一个`setUp`方法，为测试主页创建一个适当的数据集。由于我们已经开始测试应用的视图，让我们将其放在一个新文件`survey/tests/view_tests.py`中。当我们创建该文件时，我们还需要记得在`survey/tests`的`__init__.py`文件中添加一个`import`行，以便找到其中的测试。

这是我们主页测试的`setUp`方法：

```py
import datetime 
from django.test import TestCase 
from survey.models import Survey 

class SurveyHomeTest(TestCase): 
    def setUp(self): 
        today = datetime.date.today() 
        Survey.objects.all().delete() 
        d = today - datetime.timedelta(15) 
        Survey.objects.create(title="Too Old", opens=d, closes=d) 
        d += datetime.timedelta(1) 
        Survey.objects.create(title="Completed 1", opens=d, closes=d) 
        d = today - datetime.timedelta(1) 
        Survey.objects.create(title="Completed 2", opens=d, closes=d) 
        Survey.objects.create(title="Active 1", opens=d) 
        Survey.objects.create(title="Active 2", opens=today) 
        d = today + datetime.timedelta(1) 
        Survey.objects.create(title="Upcoming 1", opens=d) 
        d += datetime.timedelta(6) 
        Survey.objects.create(title="Upcoming 2", opens=d) 
        d += datetime.timedelta(1) 
        Survey.objects.create(title="Too Far Out", opens=d) 
```

这种方法首先将今天的日期存储在一个本地变量`today`中。然后删除数据库中所有现有的`Surveys`，以防初始数据装置加载了任何可能干扰测试用例中的测试方法正确执行的调查。然后创建八个`Surveys`：三个已完成，两个活跃，三个即将到来的。

已完成调查的截止日期被特别设置，以测试应该出现在主页上的窗口边界。最早的截止日期设置得比过去的时间多一天（15 天），不会出现在主页上。其他两个设置为窗口边缘的极限，应该出现在主页上。即将到来的调查的开放日期也类似地设置，以测试该窗口的极限。一个即将到来的调查开放的时间比未来多一天，不会出现在主页上，而另外两个则在窗口的极限处开放，应该显示为即将到来的调查。最后，有两个活跃的调查，一个是昨天开放的，另一个是今天开放的，每个都有一个默认的截止日期，七天后关闭，所以两者都还在开放中。

现在我们有一个`setUp`例程来创建测试数据，那么我们如何编写一个测试来检查主页的内容呢？Django 提供了一个类`django.test.Client`来帮助这里。这个`Client`类的实例就像一个 Web 浏览器，可以用来请求页面并检查返回的响应。每个`django.test.TestCase`类都会自动分配一个`Client`类的实例，可以使用`self.client`来访问。

要了解如何使用测试`Client`，让我们来看一下调查应用主页测试的开始部分：

```py
    def testHome(self): 
        from django.core.urlresolvers import reverse 
        response = self.client.get(reverse('survey_home')) 
        self.assertEqual(response.status_code, 200) 
```

在`SurveyHomeTest`中定义了一个`testHome`方法。这个方法使用测试的`client`类实例的`get`方法来检索调查主页（再次使用`reverse`来确定正确的 URL，以确保所有 URL 配置信息都被隔离在`urls.py`中）。`get`的返回值是由调用来提供请求页面的视图返回的`django.http.HttpResponse`对象，附带一些额外的信息以便于测试。测试的最后一行通过确保返回的响应的`status_code`属性为`200`（HTTP OK）来验证请求是否成功。

请注意，测试`Client`提供的`get`方法支持不止我们在这里传递的单个 URL 参数。此外，它支持两个关键字参数`data`和`follow`，它们分别默认为空字典和`False`。最后，还可以提供任意数量的`extra`关键字参数。

如果`data`字典不为空，则用于构造请求的查询字符串。例如，考虑这样一个`get`方法：

```py
response = self.client.get('/survey/', data={'pk': 4, 'type': 'results'})
```

为了处理这个请求创建的 URL 将是`/survey/?pk=4&type=results`。

请注意，您还可以在传递给`get`的 URL 路径中包含查询字符串。因此，等效的调用将是：

```py
response = self.client.get('/survey/?pk=4&type=results')
```

如果提供了`data`字典和 URL 路径中的查询字符串，则`data`字典用于处理请求，URL 路径中的查询字符串将被忽略。

`get`的`follow`参数可以设置为`True`，以指示测试客户端跟随响应中的重定向。如果是这样，返回的响应将设置一个`redirect_chain`属性。这个属性将是一个描述重定向链结束之前访问的中间 URL 的列表。列表中的每个元素将是一个元组，包含中间 URL 路径和触发它被检索的状态代码。

最后，任何`extra`关键字参数都可以用于在请求中设置任意的 HTTP 标头值。例如：

```py
response = self.client.get('/', HTTP_USER_AGENT='Tester')
```

这个调用将在请求中将`HTTP_USER_AGENT`标头设置为`Tester`。

针对我们自己的测试，只提供 URL 路径参数，我们现在可以使用`manage.py test survey.SurveyHomeTest`来运行它，并验证到目前为止一切看起来都很好。我们可以检索主页，响应返回成功的状态代码。但是如何测试页面的内容呢？我们希望确保应该出现的各种调查都出现了，并且数据库中不应该出现在页面上的两个调查也没有列出。

返回的实际页面内容存储在响应的`content`属性中。我们可以直接检查这一点，但是 Django `TestCase`类还提供了两种方法来检查响应中是否包含某些文本。这些方法分别命名为`assertContains`和`assertNotContains`。

要使用`assertContains`方法，我们传入`response`和我们要查找的文本。我们还可以选择指定文本应该出现的次数。如果我们指定了`count`，则文本必须在响应中出现相同的次数。如果我们没有指定`count`，`assertContains`只是检查文本是否至少出现一次。最后，我们可以指定响应应该具有的`status_code`。如果我们没有指定这一点，那么`assertContains`将验证状态代码是否为 200。

`assertNotContains`方法与`assertContains`具有相同的参数，但不包括`count`。它验证传递的文本是否不出现在响应内容中。

我们可以使用这两种方法来验证主页是否包含`Completed`、`Active`和`Upcoming`各两个实例，并且不包含`Too Old`或`Too Far Out`。此外，由于这些方法检查状态代码，我们可以从我们自己的测试代码中删除该检查。因此，测试方法变为：

```py
    def testHome(self):
        from django.core.urlresolvers import reverse
        response = self.client.get(reverse('survey_home'))
        self.assertContains(response, "Completed", count=2)
        self.assertContains(response, "Active", count=2)
        self.assertContains(response, "Upcoming", count=2)
        self.assertNotContains(response, "Too Old")
        self.assertNotContains(response, "Too Far Out")
```

如果我们尝试运行这个版本，我们会看到它可以工作。但是，它并不像我们希望的那样具体。换句话说，它没有验证列出的调查是否出现在页面上的正确位置。例如，当前的测试将通过，即使所有列出的调查都出现在段落**现在参与调查！**下面。我们如何验证每个调查是否出现在适当的列表中呢？

一种方法是手动检查`response.content`，找到每个预期字符串的位置，并确保它们按预期顺序出现。但是，这将使测试非常依赖页面的确切布局。将来我们可能决定重新排列列表的呈现方式，这个测试可能会失败，即使每个调查仍然被列在正确的类别中。

我们真正想要做的是验证调查是否包含在传递给模板的适当上下文变量中。实际上我们可以测试这一点，因为`client.get`返回的响应带有用于呈现模板的上下文的注释。因此，我们可以这样检查已完成的调查列表：

```py
        completed = response.context['completed_surveys'] 
        self.assertEqual(len(completed), 2) 
        for survey in completed: 
            self.failUnless(survey.title.startswith("Completed")) 
```

这段代码从响应上下文中检索 `completed_surveys` 上下文变量，验证其中是否有 `2` 个项目，并进一步验证每个项目是否具有以字符串 `Completed` 开头的 `title`。如果我们运行该代码，我们会看到它适用于检查已完成的调查。然后，我们可以将该代码块复制两次，并适当调整，以检查活动和即将开始的调查，或者我们可以变得更加复杂，编写类似于这样的代码：

```py
        context_vars = ['completed_surveys', 'active_surveys', 'upcoming_surveys'] 
        title_starts = ['Completed', 'Active', 'Upcoming'] 
        for context_var, title_start in zip(context_vars, title_starts):
            surveys = response.context[context_var] 
            self.assertEqual(len(surveys), 2) 
            for survey in surveys: 
                self.failUnless(survey.title.startswith(title_start))
```

在这里，我们通过构建一个要检查的事项列表，然后遍历该列表，避免了基本上三次重复相同的代码块，只是有些微的差异。因此，我们只有一个代码块出现一次，但它循环三次，每次都是为了检查我们想要检查的上下文变量之一。这是一种常用的技术，用于避免多次重复几乎相同的代码。

请注意，当在测试中使用这种技术时，最好在断言检查中包含具体的消息。在代码的原始版本中，直接测试已完成的列表，如果出现错误，比如列表中有太多的调查，测试失败将产生一个相当具体的错误报告：

```py
FAIL: testHome (survey.tests.view_tests.SurveyHomeTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests/view_tests.py", line 29, in testHome 
 self.assertEqual(len(completed), 2) 
AssertionError: 3 != 2 

---------------------------------------------------------------------- 

```

在这里，包含字符串 **completed** 的代码失败，因此清楚哪个列表出了问题。使用代码的更通用版本，这个报告就不那么有帮助了：

```py
FAIL: testHome (survey.tests.view_tests.SurveyHomeTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests/view_tests.py", line 35, in testHome 
 self.assertEqual(len(surveys), 2) 
AssertionError: 3 != 2 

---------------------------------------------------------------------- 

```

遇到这种失败报告的可怜程序员将无法知道这三个列表中哪一个有太多的项目。然而，通过提供具体的断言错误消息，这一点可以变得清晰。因此，具有描述性错误的完整测试方法的更好版本将是：

```py
    def testHome(self): 
        from django.core.urlresolvers import reverse 
        response = self.client.get(reverse('survey_home')) 
        self.assertNotContains(response, "Too Old") 
        self.assertNotContains(response, "Too Far Out")          
        context_vars = ['completed_surveys', 'active_surveys', 'upcoming_surveys'] 
        title_starts = ['Completed', 'Active', 'Upcoming'] 
        for context_var, title_start in zip(context_vars, title_starts): 
            surveys = response.context[context_var] 
            self.assertEqual(len(surveys), 2, 
                "Expected 2 %s, found %d instead" % 
                (context_var, len(surveys))) 
            for survey in surveys: 
                self.failUnless(survey.title.startswith(title_start), 
                    "%s title %s does not start with %s" % 
                    (context_var, survey.title, title_start)) 
```

现在，如果在通用代码的检查过程中出现故障，错误消息已经具体到足以指出问题所在：

```py
FAIL: testHome (survey.tests.view_tests.SurveyHomeTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests/view_tests.py", line 36, in testHome 
 (context_var, len(surveys))) 
AssertionError: Expected 2 completed_surveys, found 3 instead 

---------------------------------------------------------------------- 

```

我们现在对我们的调查主页有一个相当完整的测试，或者至少是我们迄今为止实施的部分。是时候把注意力转向调查详细页面了，接下来我们将介绍这部分内容。

# 创建调查详细页面

我们在项目的 URL 配置中添加的第二个 URL 映射是用于调查详细页面的。实现这个视图比主页视图要复杂一些，因为根据请求的调查状态，需要呈现完全不同的数据。如果调查已完成，我们需要显示结果。如果调查正在进行中，我们需要显示一个表单，允许用户参与调查。如果调查即将开始，我们不希望调查可见。

一次性完成所有这些工作，而不在验证的过程中进行测试以确保我们朝着正确的方向前进，那将是在自找麻烦。最好将任务分解成较小的部分，并在进行测试时逐步进行。我们将在接下来的部分中迈出朝着这个方向的第一步。

## 完善调查详细视图

首先要做的是用一个视图替换调查详细页面的简单占位符视图，该视图确定请求的调查状态，并适当地路由请求。例如：

```py
import datetime 
from django.shortcuts import render_to_response, get_object_or_404 
from django.http import Http404 
from survey.models import Survey 
def survey_detail(request, pk): 
    survey = get_object_or_404(Survey, pk=pk) 
    today = datetime.date.today() 
    if survey.closes < today: 
        return display_completed_survey(request, survey) 
    elif survey.opens > today: 
        raise Http404 
    else: 
        return display_active_survey(request, survey) 
```

这个 `survey_detail` 视图使用 `get_object_or_404` 快捷方式从数据库中检索请求的 `Survey`。如果请求的调查不存在，该快捷方式将自动引发 `Http404` 异常，因此以下代码不必考虑这种情况。然后，视图检查返回的 `Survey` 实例上的 `closes` 日期。如果它在今天之前关闭，请求将被发送到名为 `display_completed_survey` 的函数。否则，如果调查尚未开放，将引发 `Http404` 异常。最后，如果这些条件都不成立，调查必须是活动的，因此请求将被路由到名为 `display_active_survey` 的函数。

首先，我们将非常简单地实现这两个新函数。它们不会执行它们的情况所需的任何真正工作，但它们在呈现响应时将使用不同的模板：

```py
def display_completed_survey(request, survey): 
    return render_to_response('survey/completed_survey.html', {'survey': survey}) 

def display_active_survey(request, survey): 
    return render_to_response('survey/active_survey.html', {'survey': survey}) 
```

只需这么多代码，我们就可以继续测试不同州的调查是否被正确路由。不过，首先，我们需要创建视图代码引入的两个新模板。

## 调查详细页面的模板

这两个新模板的名称分别是`survey/completed_survey.html`和`survey/active_survey.html`。将它们创建在`survey/templates`目录下。一开始，它们可以非常简单。例如，`completed_survey.html`可能是：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>Survey results for {{ survey.title }}</h1> 
{% endblock content %} 
```

同样地，`active_survey.html`可能是：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>Survey questions for {{ survey.title }}</h1> 
{% endblock content %} 
```

每个模板都扩展了`survey/base.html`模板，并为`content`块提供了最少但描述性的内容。在每种情况下，显示的只是一个一级标题，用标题标识调查，以及页面是否显示结果或问题。

## 调查详细页面的基本测试

现在考虑如何测试`survey_detail`中的路由代码是否工作正常。同样，我们需要测试数据，其中至少有一个调查处于三种状态之一。我们在`SurveyHomeTest`的`setUp`方法中创建的测试数据就包含了这些。然而，向主页测试用例添加实际测试调查详细页面视图的方法会很混乱。重复非常相似的`setUp`代码也不太吸引人。

幸运的是，我们不需要做任何一种。我们可以将现有的`setUp`代码移到一个更一般的测试用例中，比如`SurveyTest`，然后基于这个新的`SurveyTest`来构建`SurveyHomeTest`和我们的新的`SurveyDetailTest`。通过这种方式，主页测试和详细页面测试将在数据库中由基本的`SurveyTest setUp`方法创建相同的数据。此外，任何需要类似数据的其他测试也可以继承自`SurveyTest`。

鉴于我们已经有了测试数据，我们可以做些什么来测试我们迄今为止实现的详细视图？即将到来的调查的情况很容易，因为它应该简单地返回一个 HTTP 404（未找到）页面。因此，我们可以从`SurveyDetailTest`中为这种情况创建一个方法开始：

```py
from django.core.urlresolvers import reverse 
class SurveyDetailTest(SurveyTest): 
    def testUpcoming(self): 
        survey = Survey.objects.get(title='Upcoming 1') 
        response = self.client.get(reverse('survey_detail', args=(survey.pk,))) 
        self.assertEqual(response.status_code, 404) 
```

`testUpcoming`方法从数据库中检索一个即将到来的调查，并使用测试`client`请求包含该调查详细信息的页面。再次使用`reverse`来构建适当的详细页面的 URL，将我们请求的调查的主键作为`args`元组中的单个参数传递。通过确保响应的`status_code`为 404 来测试对这个请求的正确处理。如果我们现在运行这个测试，我们会看到：

```py
ERROR: testUpcoming (survey.tests.view_tests.SurveyDetailTest)
----------------------------------------------------------------------
Traceback (most recent call last):
 File "/dj_projects/marketr/survey/tests/view_tests.py", line 45, in testUpcoming
 response = self.client.get(reverse('survey_detail', args=(survey.pk,)))
 File "/usr/lib/python2.5/site-packages/django/test/client.py", line 281, in get
 response = self.request(**r)
 File "/usr/lib/python2.5/site-packages/django/core/handlers/base.py", line 119, in get_response
 return callback(request, **param_dict)
 File "/usr/lib/python2.5/site-packages/django/views/defaults.py", line 13, in page_not_found
 t = loader.get_template(template_name) # You need to create a 404.html template.
 File "/usr/lib/python2.5/site-packages/django/template/loader.py", line 81, in get_template
 source, origin = find_template_source(template_name)
 File "/usr/lib/python2.5/site-packages/django/template/loader.py", line 74, in find_template_source
 raise TemplateDoesNotExist, name
TemplateDoesNotExist: 404.html

```

糟糕。为了使`survey_detail`视图成功引发`Http404`并导致“页面未找到”响应，项目中必须存在一个`404.html`模板。我们还没有创建一个，所以这个测试生成了一个错误。为了解决这个问题，我们可以创建一个简单的`survey/templates/404.html`文件，其中包含：

```py
{% extends "survey/base.html" %}
{% block content %}
<h1>Page Not Found</h1>
<p>The requested page was not found on this site.</p>
{% endblock content %}
```

同时，我们还应该创建一个`survey/templates/500.html`文件，以避免在遇到服务器错误的情况下出现类似的无用错误。现在使用的一个简单的`500.html`文件会很像这个`404.html`文件，只是将文本更改为指示问题是服务器错误，而不是页面未找到的情况。

有了`404.html`模板，我们可以尝试再次运行这个测试，这一次，它会通过。

那么如何测试已完成和活动调查的页面呢？我们可以编写测试，检查`response.content`中我们放置在各自模板中的标题文本。然而，随着我们继续开发，该文本可能不会保持不变——在这一点上，它只是占位文本。最好验证正确的模板是否用于呈现每个响应。`TestCase`类有一个用于此目的的方法：`assertTemplateUsed`。因此，我们可以编写这些在长期内可能会继续正常工作的情况的测试，如下所示：

```py
    def testCompleted(self): 
        survey = Survey.objects.get(title='Too Old') 
        response = self.client.get(reverse('survey_detail', args=(survey.pk,))) 
        self.assertTemplateUsed(response, 'survey/completed_survey.html')

    def testActive(self): 
        survey = Survey.objects.get(title='Active 1') 
        response = self.client.get(reverse('survey_detail', args=(survey.pk,))) 
        self.assertTemplateUsed(response, 'survey/active_survey.html') 
```

每个测试方法都从适当的类别中检索调查，并请求该调查的详细页面。到目前为止，对响应的唯一测试是检查是否使用了预期的模板来呈现响应。同样，我们现在可以运行这些测试并验证它们是否通过。

除了`assertTemplateUsed`之外，`TestCase`还提供了一个`assertTemplateNotUsed`方法。它接受与`assertTempalteUsed`相同的参数。正如你所期望的那样，它验证指定的模板未被用于呈现响应。

在这一点上，我们将暂停实施`survey`应用程序页面。下一个单元测试主题是如何测试接受用户输入的页面。我们在调查应用程序中还没有这样的页面，但 Django 管理员应用程序有。因此，在开发测试之前，测试管理员自定义提供了学习如何测试这些页面的更快捷的途径，因为我们需要编写更少的自定义代码。此外，学习如何测试管理员自定义本身也是有用的。

# 自定义管理员添加和更改调查页面

我们已经看到 Django 管理员应用程序提供了一种方便的方式来检查和操作数据库中的数据。在上一章中，我们对管理员进行了一些简单的自定义，以允许在`Surveys`中内联编辑`Questions`和在`Questions`中内联编辑`Answers`。除了这些内联自定义之外，我们没有对管理员默认值进行任何更改。

对管理员进行的另一个很好的改变是确保`Survey opens`和`closes`日期是有效的。显然，对于这个应用程序，拥有一个晚于`closes`的`opens`日期是没有意义的，但管理员无法知道这一点。在这一部分，我们将自定义管理员以强制执行我们的应用程序对`opens`和`closes`之间关系的要求。我们还将为此自定义开发一个测试。

## 开发自定义调查表单

实施此管理员自定义的第一步是为`Survey`实施一个包括自定义验证的表单。例如：

```py
from django import forms
class SurveyForm(forms.ModelForm): 
    class Meta: 
        model = Survey 
    def clean(self): 
        opens = self.cleaned_data.get('opens') 
        closes = self.cleaned_data.get('closes') 
        if opens and closes and opens > closes: 
            raise forms.ValidationError("Opens date cannot come, " "after closes date.") 
        return self.cleaned_data 
```

这是`Survey`模型的标准`ModelForm`。由于我们想要执行的验证涉及表单上的多个字段，最好的地方是在整体表单的`clean`方法中进行。这里的方法从表单的`cleaned_data`字典中检索`opens`和`closes`的值。然后，如果它们都已提供，它会检查`opens`是否晚于`closes`。如果是，就会引发`ValidationError`，否则一切正常，所以从`clean`中返回未修改的现有`cleaned_data`字典。

由于我们将在管理员中使用此表单，并且目前不预期需要在其他地方使用它，我们可以将此表单定义放在现有的`survey/admin.py`文件中。

## 配置管理员使用自定义表单

下一步是告诉管理员使用此表单，而不是默认的`Survey`模型的`ModelForm`。要做到这一点，将`survey/admin.py`中的`SurveyAdmin`定义更改为：

```py
class SurveyAdmin(admin.ModelAdmin):
    form = SurveyForm
    inlines = [QuestionsInline]
```

通过指定`form`属性，我们告诉管理员在添加和编辑`Survey`实例时使用我们的自定义表单。我们可以通过使用管理员编辑我们现有的“获奖答案测试”调查并尝试将其`closes`日期更改为早于`opens`的日期来快速验证这一点。如果我们这样做，我们将看到错误报告如下：

![配置管理员使用自定义表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_04_03.jpg)

我们能够手动验证我们的自定义是否有效是很好的，但我们真正想要的是自动化测试。下面将介绍这一点。

## 测试管理员自定义

我们如何为这个管理员自定义编写测试？关于测试在管理员页面上按下“保存”按钮的行为，至少有一些不同于我们迄今为止测试的地方。首先，我们需要发出 HTTP POST 方法，而不是 GET，以进行请求。测试`Client`提供了一个`post`方法，用于此目的，类似于`get`。对于`post`，我们需要指定要包含在请求中的表单数据值。我们将这些提供为键/值对的字典，其中键是表单字段的名称。由于我们知道管理员正在使用的`ModelForm`，因此我们知道这里的键值是模型字段的名称。

我们将从编写一个测试开始，用于管理员添加调查页面，因为在这种情况下，我们不需要在数据库中有任何预先存在的数据。让我们在测试目录中创建一个名为`admin_tests.py`的新文件来测试管理员视图。还要记得将`from admin_tests import *`添加到`tests/__init__.py`文件中，以便在运行`tests`时找到这些测试。

首次尝试实现对管理员应用程序使用我们定制的“调查”表单的测试可能如下所示：

```py
import datetime 
from django.test import TestCase 
from django.core.urlresolvers import reverse 

class AdminSurveyTest(TestCase):    
    def testAddSurveyError(self): 
        post_data = { 
            'title': u'Time Traveling', 
            'opens': datetime.date.today(), 
            'closes': datetime.date.today() - datetime.timedelta(1), 
        } 
        response = self.client.post(reverse('admin:survey_survey_add'), post_data) 
        self.assertContains(response, "Opens date cannot come after closes date.") 
```

在这里，我们有一个测试方法`testAddSurveyError`，它使用`Survey ModelForm`的`title`，`opens`和`closes`值创建一个`post_data`字典。我们使用测试`client`将该字典`post`到`survey`应用程序的管理员`Survey`添加页面（使用该管理员视图的文档名称的`reverse`）。我们期望返回的`response`应该包含我们自定义`ModelForm`的错误消息，因为我们指定了一个晚于`closes`日期的`opens`日期。我们使用`assertContains`来检查预期的错误消息是否在响应中找到。

请注意，与`get`一样，我们第一个使用`post`的测试只使用了可以提供给该方法的参数的子集。除了 URL`path`和`data`字典之外，`post`还接受一个`content_type`关键字参数。此参数默认为一个值，导致客户端发送`mutlipart/form-data`。除了`content_type`，`post`还支持相同的`follow`和`extra`关键字参数，具有与`get`相同的默认值和处理行为。

我们对管理员自定义测试的第一次尝试有效吗？不幸的是，不是。如果我们使用`manage.py test survey.AdminSurveyTest`运行它，我们将看到以下失败：

```py
FAIL: testAddSurveyError (survey.tests.admin_tests.AdminSurveyTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests/admin_tests.py", line 13, in testAddSurveyError 
 self.assertContains(response, "Opens date cannot come after closes date.") 
 File "/usr/lib/python2.5/site-packages/django/test/testcases.py", line 345, in assertContains 
 "Couldn't find '%s' in response" % text) 
AssertionError: Couldn't find 'Opens date cannot come after closes date.' in response 

---------------------------------------------------------------------- 

```

可能出了什么问题？很难说，因为没有看到返回的响应实际包含什么。意识到这一点，我们可能会想要在错误消息中包含响应的文本。然而，响应往往相当长（因为它们通常是完整的网页），通常将它们包含在测试失败输出中通常会增加更多的噪音。因此，通常最好对测试用例进行临时更改以打印响应，以便弄清楚可能发生了什么。

如果我们在这种情况下这样做，我们将看到返回的响应开始（在一些标准的 HTML 样板之后）：

```py
<title>Log in | Django site admin</title> 

```

哦，对了，我们忘了管理员需要登录用户才能访问。我们在测试用例中没有做任何设置和登录用户的操作，因此当测试尝试访问管理员页面时，管理员代码会简单地返回一个登录页面。

因此，我们的测试首先需要创建一个用户，因为测试数据库最初是空的。该用户需要适当的权限来访问管理，并且必须在尝试对管理应用程序执行任何操作之前登录。这种情况适合于测试`setUp`例程：

```py
import datetime
from django.test import TestCase
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse

class AdminSurveyTest(TestCase):
    def setUp(self):
        self.username = 'survey_admin'
        self.pw = 'pwpwpw'
        self.user = User.objects.create_user(self.username, '', self.pw)
        self.user.is_staff= True
        self.user.is_superuser = True
        self.user.save()
        self.assertTrue(self.client.login(username=self.username, password=self.pw),
            "Logging in user %s, pw %s failed." % (self.username, self.pw))
```

在这里，`setUp`例程使用标准`django.contrib.auth User`模型提供的`create_user`方法创建一个名为`survey_admin`的用户。创建用户后，`setUp`将其`is_staff`和`is_superuser`属性设置为`True`，并将用户再次保存到数据库中。这将允许新创建的用户访问管理应用程序中的所有页面。

最后，`setUp`尝试使用测试`Client login`方法登录新用户。如果成功，此方法将返回`True`。在这里，`setUp`断言`login`确实返回`True`。如果没有，断言将提供特定的指示，说明出了什么问题。这应该比如果`login`调用失败后继续测试更有帮助。

`Client login`方法有一个伴随方法`logout`。我们应该在`setUp`中使用`login`后，在`tearDown`方法中使用它：

```py
    def tearDown(self): 
        self.client.logout() 
```

现在我们的测试工作了吗？不，但它确实更进一步了。这次的错误报告是：

```py
ERROR: testAddSurveyError (survey.tests.admin_tests.AdminSurveyTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests/admin_tests.py", line 26, in testAddSurveyError 
 response = self.client.post(reverse('admin:survey_survey_add'), post_data) 
 File "/usr/lib/python2.5/site-packages/django/test/client.py", line 313, in post 
 response = self.request(**r) 
 File "/usr/lib/python2.5/site-packages/django/core/handlers/base.py", line 92, in get_response 
 response = callback(request, *callback_args, **callback_kwargs) 
 File "/usr/lib/python2.5/site-packages/django/contrib/admin/options.py", line 226, in wrapper 
 return self.admin_site.admin_view(view)(*args, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/views/decorators/cache.py", line 44, in _wrapped_view_func 
 response = view_func(request, *args, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/contrib/admin/sites.py", line 186, in inner 
 return view(request, *args, **kwargs) 
 File "/usr/lib/python2.5/site-packages/django/db/transaction.py", line 240, in _commit_on_success 
 res = func(*args, **kw) 
 File "/usr/lib/python2.5/site-packages/django/contrib/admin/options.py", line 731, in add_view 
 prefix=prefix) 
 File "/usr/lib/python2.5/site-packages/django/forms/models.py", line 724, in __init__ 
 queryset=qs) 
 File "/usr/lib/python2.5/site-packages/django/forms/models.py", line 459, in __init__ 
 super(BaseModelFormSet, self).__init__(**defaults) 
 File "/usr/lib/python2.5/site-packages/django/forms/formsets.py", line 44, in __init__ 
 self._construct_forms() 
 File "/usr/lib/python2.5/site-packages/django/forms/formsets.py", line 87, in _construct_forms 
 for i in xrange(self.total_form_count()): 
 File "/usr/lib/python2.5/site-packages/django/forms/models.py", line 734, in total_form_count 
 return super(BaseInlineFormSet, self).total_form_count() 
 File "/usr/lib/python2.5/site-packages/django/forms/formsets.py", line 66, in total_form_count 
 return self.management_form.cleaned_data[TOTAL_FORM_COUNT] 
 File "/usr/lib/python2.5/site-packages/django/forms/formsets.py", line 54, in _management_form 
 raise ValidationError('ManagementForm data is missing or has been tampered with') 
ValidationError: [u'ManagementForm data is missing or has been tampered with'] 

---------------------------------------------------------------------- 

```

起初可能有点困惑，但在 Django 文档中搜索**ManagementForm**很快就会发现，当使用 formsets 时，这是必需的内容。由于作为我们的管理定制的一部分，我们指定`Questions`内联显示在`Survey`页面上，因此`Survey`的管理页面包含了`Questions`的 formset。但是，在我们的`post_data`字典中没有提供所需的`ManagementForm`值。所需的两个值是`question_set`的`TOTAL_FORMS`和`INITIAL_FORMS`。由于我们不想在这里测试内联的管理处理，我们可以在我们的数据字典中将这些值设置为`0`：

```py
    def testAddSurveyError(self): 
        post_data = { 
            'title': u'Time Traveling', 
            'opens': datetime.date.today(), 
            'closes': datetime.date.today() - datetime.timedelta(1), 
            'question_set-TOTAL_FORMS': u'0', 
            'question_set-INITIAL_FORMS': u'0', 
        } 
        response = self.client.post(reverse('admin:survey_survey_add'), post_data) 
        self.assertContains(response, "Opens date cannot come after closes date.") 
```

现在这个测试工作吗？是的，如果我们运行`manage.py test survey.AdminSurveyTest.testAddSurveyError`，我们会看到测试成功运行。

请注意，`TestCase`提供了一个比`assertContains`更具体的断言来检查表单错误的方法，名为`assertFormError`。`assertFormError`的参数是响应、模板上下文中表单的名称、要检查错误的字段的名称（如果错误是非字段错误，则为`None`），以及要检查的错误字符串（或错误字符串列表）。但是，在测试管理页面时无法使用`assertFormError`，因为管理页面不会直接在上下文中提供表单。相反，上下文包含一个包含实际表单的包装对象。因此，我们无法将这个特定的测试更改为使用更具体的`assertFormError`方法。

我们完成了对管理定制的测试吗？几乎。由于在管理中添加和更改操作都使用相同的表单，因此无需测试更改页面。但是，最好添加一个包含有效数据并确保对于该情况没有出现任何问题的测试。

添加一个测试方法很容易，该方法构建一个包含有效数据的数据字典，并将其发布到管理添加视图。但是，响应中应该测试什么？管理代码在成功完成 POST 请求的某些操作后不会返回简单的`200 OK`响应。相反，它会重定向到另一个页面，以便尝试重新加载 POST 请求的页面不会导致再次尝试 POST 相同的数据。在添加对象的情况下，管理将重定向到已添加模型的更改列表页面。`TestCase`提供了一个`assertRedirects`方法来测试这种行为。我们可以这样使用这个方法：

```py
    def testAddSurveyOK(self): 
        post_data = { 
            'title': u'Time Traveling', 
            'opens': datetime.date.today(), 
            'closes': datetime.date.today(), 
            'question_set-TOTAL_FORMS': u'0', 
            'question_set-INITIAL_FORMS': u'0', 
        } 
        response = self.client.post(reverse('admin:survey_survey_add'), post_data) 
        self.assertRedirects(response, reverse('admin:survey_survey_changelist')) 
```

这个`testAddSurveyOK`方法为`Survey`设置了一个有效的数据字典，指定了相同的`opens`和`closes`日期。然后将这些数据发布到管理员添加调查页面，并保存响应。最后，它断言响应应该重定向到`Survey`模型的管理员调查应用程序更改列表页面。`assertRedirects`的两个额外的可选参数是`status_code`和`target_status_code`。它们分别默认为`302`和`200`，所以我们在这里不需要指定它们，因为这些是我们在这种情况下期望的代码。

# 额外的测试支持

本章中我们开发的测试提供了如何使用 Django 的`TestCase`和测试`Client`类提供的测试支持的相当广泛的概述。然而，这些示例既没有涵盖这些类提供的每一个细节，也没有涵盖`Client`返回的注释`response`对象中的附加数据的每一个细节。在本节中，我们简要提到了`TestCase`，`Client`和`response`对象可用的一些附加功能。我们不会开发使用所有这些功能的示例；它们在这里提到，以便如果您遇到对这种类型的支持有需求，您将知道它的存在。Django 文档提供了所有这些主题的详细信息。

## 支持额外的 HTTP 方法

我们的示例测试只需要使用 HTTP GET 和 POST 方法。测试`Client`类还提供了发出 HTTP HEAD、OPTIONS、PUT 和 DELETE 请求的方法。这些方法分别命名为`head`、`options`、`put`和`delete`。每个方法都支持与`get`和`post`相同的`follow`和`extra`参数。此外，`put`支持与`post`相同的`content_type`参数。

## 保持持久状态

测试`Client`维护两个属性，跨请求/响应周期保持持久状态：`cookies`和`session`。`cookies`属性是一个包含已收到的任何 cookie 的 Python `SimpleCookie`对象。`session`属性是一个类似字典的对象，包含会话数据。

## 电子邮件服务

Web 应用程序中的一些视图可能会创建并发送邮件。在测试时，我们不希望实际发送这样的邮件，但能够验证正在测试的代码是否生成并尝试发送邮件是很好的。`TestCase`类通过在运行测试时将标准的 Python `SMTPConnection`类（仅在运行测试时）替换为一个不发送邮件而是将其存储在`django.core.mail.outbox`中的自定义类来支持这一点。因此，测试代码可以检查这个`outbox`的内容，以验证正在测试的代码是否尝试发送预期的邮件。

## 提供特定于测试的 URL 配置

在本章开发的示例中，我们小心地确保测试独立于 URL 配置的具体细节，始终使用命名 URL 并使用`reverse`将这些符号名称映射回 URL 路径值。这是一个很好的技术，但在某些情况下可能不足够。

考虑到您正在开发一个可重用的应用程序，该应用程序的特定安装可能选择部署可选视图。对于测试这样的应用程序，您不能依赖于可选视图实际上包含在项目的 URL 配置中，但您仍希望能够为它们包括测试。为了支持这一点，`TestCase`类允许实例设置一个`urls`属性。如果设置了这个属性，`TestCase`将使用指定模块中包含的 URL 配置，而不是项目的 URL 配置。

## 响应上下文和模板信息

在测试调查主页时，我们使用简单的字典样式访问检查响应`context`属性中的值。例如：

```py
completed = response.context['completed_surveys'] 
```

虽然这样可以工作，但它忽略了在考虑用于呈现响应的上下文时涉及的一些复杂性。回想一下，我们设置了项目，使其具有两级模板层次结构。`base.html`模板由每个单独的页面模板扩展。用于呈现响应的每个模板都有其自己的关联上下文，因此响应的`context`属性不是一个简单的字典，而是用于呈现每个模板的上下文的列表。实际上，它是一种称为`django.test.utils.ContextList`的东西，其中包含许多`django.template.context.Context`对象。

这个`ContextList`对象支持字典样式的访问以简化操作，并在它包含的每个上下文中搜索指定的键。我们在本章的早期示例中使用了这种简单的访问方式。但是，如果您需要更具体地检查要在哪个模板上下文中，响应的`context`属性也支持这一点，因为您还可以通过索引号到`ContextList`中检索与特定模板相关的完整上下文。

此外，测试`Client`返回的响应具有一个`template`属性，该属性是用于呈现响应的模板的列表。我们没有直接使用这个属性，因为我们使用了`TestCase`提供的`assertTemplateUsed`方法。

# 测试事务行为

本章最后要讨论的主题涉及测试事务行为。如果有必要这样做，有一个替代的测试用例类`TransactionTestCase`，应该使用它来代替`TestCase`。

什么是**测试事务行为**的意思？假设您有一个视图，它在单个数据库事务中进行一系列数据库更新。此外，假设您需要测试至少一个更新起初有效，但随后失败，应该导致整个更新集被回滚而不是提交的情况。为了测试这种行为，您可能会尝试在测试代码中验证，当收到响应时，最初有效的更新之一在数据库中是不可见的。要成功运行这种测试代码，您需要使用`TransactionTestCase`而不是`TestCase`。

这是因为`TestCase`在调用测试方法之间使用事务回滚来将数据库重置为干净状态。为了使这种回滚方法在测试方法之间的清理工作，受测试代码不得允许发出任何数据库提交或回滚操作。因此，`TestCase`拦截任何此类调用，并简单地返回而不实际将它们转发到数据库。因此，您的测试代码将无法验证应该被回滚的更新是否已被回滚，因为在`TestCase`下运行时它们将不会被回滚。

`TransactionTestCase`在测试方法之间不使用回滚来重置数据库。相反，它截断并重新创建所有表。这比回滚方法慢得多，但它确实允许测试代码验证从受测试代码执行成功的任何数据库事务行为。

# 总结

我们现在已经讨论完了 Django 的单元测试扩展，以支持测试 Web 应用程序。在本章中，我们：

+   学会了将单元测试组织成单独的文件，而不是将所有内容放入单个 tests.py 文件

+   开始为调查应用程序开发视图，并学会了如何使用 Django 的单元测试扩展来测试这些视图

+   学会了如何通过为我们的模型提供自定义验证来定制管理界面，并学会了如何测试该管理定制

+   简要讨论了 Django 提供的一些单元测试扩展，我们在任何示例测试中都没有遇到

+   学会了在何时需要使用`TransactionTestCase`而不是`TestCase`进行测试

在学习如何测试 Django 应用程序方面，我们已经涵盖了很多内容，但是测试 Web 应用程序还有许多方面我们甚至还没有涉及。其中一些更适合使用 Django 本身以外的工具进行测试。下一章将探讨一些额外的 Web 应用程序测试需求，并展示如何将外部工具集成到 Django 的测试支持中，以满足这些需求。


# 第五章：填补空白：集成 Django 和其他测试工具

之前的章节已经讨论了 Django 1.1 提供的内置应用程序测试支持。我们首先学习了如何使用 doctests 来测试应用程序的构建模块，然后介绍了单元测试的基础知识。此外，我们还看到了`django.test.TestCase`和`django.test.Client`提供的函数如何帮助测试 Django 应用程序。通过示例，我们学习了如何使用这些函数来测试应用程序的更完整的部分，例如它提供的页面内容和表单处理行为。

然而，Django 本身并没有提供测试支持所需的一切。毕竟，Django 是一个 Web 应用程序框架，而不是一个测试框架。例如，它不提供任何测试覆盖信息，这对于开发全面的测试套件至关重要，也不提供任何支持测试客户端行为的支持，因为 Django 纯粹是一个服务器端框架。存在其他工具来填补这些空白，但通常希望将这些其他工具与 Django 集成，而不是使用完全不同的工具集来构建完整的应用程序测试套件。

在某些情况下，即使 Django 支持某个功能，也可能更喜欢使用其他工具。例如，如果您已经有了使用 Python 测试框架（如`nose`）的经验，它提供了非常灵活的测试发现机制和强大的测试插件架构，您可能会发现 Django 的测试运行器相当受限制。同样，如果您熟悉`twill` Web 测试工具，您可能会发现与`twill`相比，使用 Django 的测试`Client`来测试表单行为相当麻烦。

在本章中，我们将调查 Django 与其他测试工具的集成。集成有时可以通过使用标准的 Python 单元测试扩展机制来实现，但有时需要更多。本章将涵盖这两种情况。具体来说，我们将：

+   讨论集成涉及的问题，并了解 Django 提供的用于将其他工具集成到其测试结构中的钩子。

+   探讨一个问题：我们的代码有多少被我们的测试执行了？我们将看到如何在不对 Django 测试设置进行任何更改的情况下回答这个问题，并利用之前讨论过的钩子。

+   探索`twill`工具，并了解如何在我们的 Django 应用程序测试中使用它，而不是 Django 测试`Client`。对于这种集成，我们不需要使用任何 Django 钩子进行集成，我们只需要使用 Python 的单元测试钩子进行测试设置和拆卸。

# 集成的问题

为什么 Django 测试与其他工具的集成甚至是一个问题？考虑想要使用`nose`测试框架的情况。它提供了自己的命令`nosetests`，用于在项目树中查找并运行测试。然而，在 Django 项目树中尝试运行`nosetests`而不是`manage.py test`，很快就会发现一个问题：

```py
kmt@lbox:/dj_projects/marketr$ nosetests 
E 
====================================================================== 
ERROR: Failure: ImportError (Settings cannot be imported, because environment variable DJANGO_SETTINGS_MODULE is undefined.) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/usr/lib/python2.5/site-packages/nose-0.11.1-py2.5.egg/nose/loader.py", line 379, in loadTestsFromName 
 addr.filename, addr.module) 
 File "/usr/lib/python2.5/site-packages/nose-0.11.1-py2.5.egg/nose/importer.py", line 39, in importFromPath 
 return self.importFromDir(dir_path, fqname) 
 File "/usr/lib/python2.5/site-packages/nose-0.11.1-py2.5.egg/nose/importer.py", line 86, in importFromDir 
 mod = load_module(part_fqname, fh, filename, desc) 
 File "/dj_projects/marketr/survey/tests/__init__.py", line 1, in <module> 
 from model_tests import * 
 File "/dj_projects/marketr/survey/tests/model_tests.py", line 2, in <module> 
 from django.test import TestCase 
 File "/usr/lib/python2.5/site-packages/django/test/__init__.py", line 5, in <module> 
 from django.test.client import Client 
 File "/usr/lib/python2.5/site-packages/django/test/client.py", line 24, in <module> 
 from django.db import transaction, close_connection 
 File "/usr/lib/python2.5/site-packages/django/db/__init__.py", line 10, in <module> 
 if not settings.DATABASE_ENGINE: 
 File "/usr/lib/python2.5/site-packages/django/utils/functional.py", line 269, in __getattr__ 
 self._setup() 
 File "/usr/lib/python2.5/site-packages/django/conf/__init__.py", line 38, in _setup 
 raise ImportError("Settings cannot be imported, because environment variable %s is undefined." % ENVIRONMENT_VARIABLE) 
ImportError: Settings cannot be imported, because environment variable DJANGO_SETTINGS_MODULE is undefined. 

---------------------------------------------------------------------- 
Ran 1 test in 0.007s 

FAILED (errors=1) 

```

问题在于`manage.py test`所做的一些环境设置缺失。具体来说，没有设置环境，以便在调用 Django 代码时找到适当的设置。可以通过在运行`nosetests`之前设置`DJANGO_SETTINGS_MODULE`环境变量来解决这个特定的错误，但`nosetests`不会走得更远，因为还有更多的东西缺失。

下一个遇到的问题将是需要使用数据库的测试。在运行任何测试之前，`manage.py test`调用的支持代码会创建测试数据库。`nosetests`命令对测试数据库的需求一无所知，因此在`nosetests`下运行需要数据库的 Django 测试用例将失败，因为数据库不存在。简单地在运行`nosetests`之前设置环境变量无法解决这个问题。

可以采取两种方法来解决这些集成问题。首先，如果其他工具提供了添加功能的钩子，可以使用它们来执行诸如在运行测试之前设置环境和创建测试数据库等操作。这种方法将 Django 测试集成到其他工具中。或者，可以使用 Django 提供的钩子将其他工具集成到 Django 测试中。

第一种选项超出了本书的范围，因此不会详细讨论。但是，对于`nose`的特定情况，其插件架构当然支持添加必要的功能以使 Django 测试在`nose`下运行。存在可以用于允许 Django 应用程序测试在从`nosetests`调用时成功运行的现有 nose 插件。如果这是您想要采用的方法进行自己的测试，您可能希望在构建自己的`nose`插件之前搜索现有解决方案。

第二个选项是我们将在本节中关注的：Django 提供的允许将其他函数引入到 Django 测试的正常路径中的钩子。这里可以使用两个钩子。首先，Django 允许指定替代测试运行程序。首先将描述指定这一点，测试运行程序的责任以及它必须支持的接口。其次，Django 允许应用程序提供全新的管理命令。因此，可以通过另一个命令来增强`manage.py test`，该命令可能支持不同的选项，并且可以执行将另一个工具集成到测试路径中所需的任何操作。也将讨论如何执行此操作的详细信息。

## 指定替代测试运行程序

Django 使用`TEST_RUNNER`设置来决定调用哪些代码来运行测试。默认情况下，`TEST_RUNNER`的值是`'django.test.simple.run_tests'`。我们可以查看该例程的声明和文档字符串，以了解它必须支持的接口：

```py
def run_tests(test_labels, verbosity=1, interactive=True, extra_tests=[]):  
    """ 
    Run the unit tests for all the test labels in the provided list. 
    Labels must be of the form: 
     - app.TestClass.test_method 
        Run a single specific test method 
     - app.TestClass 
        Run all the test methods in a given class 
     - app 
        Search for doctests and unittests in the named application. 

    When looking for tests, the test runner will look in the models and tests modules for the application. 

    A list of 'extra' tests may also be provided; these tests 
    will be added to the test suite. 

    Returns the number of tests that failed. 
    """ 
```

`test_labels`，`verbosity`和`interactive`参数显然将直接来自`manage.py test`命令行。`extra_tests`参数有点神秘，因为没有受支持的`manage.py test`参数与之对应。实际上，当从`manage.py test`调用时，`extra_tests`将永远不会被指定。这个参数是由 Django 用来运行自己的测试套件的`runtests.py`程序使用的。除非您打算编写一个用于运行 Django 自己的测试的测试运行程序，否则您可能不需要担心`extra_tests`。但是，自定义运行程序应该实现包括`extra_tests`在内的定义行为。

测试运行程序需要做什么？这个问题最容易通过查看现有的`django.test.simple.run_tests`代码并看看它做了什么来回答。简而言之，不逐行进行例程，它：

+   通过调用`django.test.utils.setup_test_environment`设置测试环境。这也是自定义测试运行程序应该调用的一个记录方法。它会执行一些操作，以确保例如测试客户端生成的响应具有上一章中提到的`context`和`templates`属性。

+   将`DEBUG`设置为`False`。

+   构建包含在指定的`test_labels`下发现的所有测试的`unittest.TestSuite`。Django 的简单测试运行程序仅在`models`和`tests`模块中搜索测试。

+   通过调用`connection.creation.create_test_db`创建测试数据库。这是另一个在 Django 测试文档中记录的例程，供替代测试运行程序使用。

+   运行测试。

+   通过调用`connection.creation.destroy_test_db`销毁测试数据库。

+   通过调用`django.test.utils.teardown_test_environment`清理测试环境。

+   返回测试失败和错误的总和。

### 注意

请注意，Django 1.2 添加了对指定替代测试运行器的基于类的方法的支持。虽然 Django 1.2 继续支持先前使用的基于函数的方法，并在此处描述，但将来将弃用使用基于函数的替代测试运行器。基于类的方法简化了对测试运行行为进行小改动的任务。您可以实现一个替代测试运行器类，该类继承自默认类，并简单地覆盖实现所需的任何特定方法以实现所需的替代行为。

因此，编写一个测试运行器是相当简单的。但是，仅仅替换测试运行器，我们受到`manage.py test`命令支持的参数和选项的限制。如果我们的运行器支持一些`manage.py test`不支持的选项，那么没有明显的方法可以将该选项从命令行传递给我们的测试运行器。相反，`manage.py` test 将拒绝它不知道的任何选项。

有一种方法可以绕过这个问题。Django 使用 Python 的`optparse`模块来解析命令行中的选项。在命令行上放置一个裸的`-`或`--`会导致`optparse`停止处理命令行，因此在裸的`-`或`--`之后指定的选项不会被正在解析的常规 Django 代码看到。但它们仍然可以在`sys.argv`中被我们的测试运行器访问，因此它们可以被检索并传递给我们正在集成的任何工具。

这种方法有效，但这些选项的存在将对用户隐藏得很好，因为`test`命令的标准 Django 帮助对它们一无所知。通过使用这种技术，我们扩展了`manage.py test`支持的接口，而没有任何明显的方式来发布我们所做的扩展，作为`test`命令的内置帮助的一部分。

因此，指定自定义测试运行器的一个更好的选择可能是提供一个全新的管理命令。创建一个新命令时，我们可以定义它以接受我们喜欢的任何选项，并在用户请求命令的帮助时提供应该显示的每个新选项的帮助文本。下面将讨论这种方法。

## 创建一个新的管理命令

提供一个新的管理命令很简单。Django 在每个已安装应用程序的目录中的`management.commands`包中查找管理命令。在已安装应用程序的`management.commands`包中找到的任何 Python 模块都可以自动用作`manage.py`的命令指定。

因此，要为我们的调查应用程序创建一个自定义测试命令，比如`survey_test`，我们在调查目录下创建一个`management`子目录，并在`management`下创建一个`commands`目录。我们在这两个目录中都放置`__init__.py`文件，以便 Python 将它们识别为模块。然后，我们将`survey_test`命令的实现放在一个名为`survey_test.py`的文件中。

`survey_test.py`需要包含什么？截至 Django 1.1，有关实现管理命令的文档很少。它只说明文件必须定义一个名为`Command`的类，该类扩展自`django.core.management.base.BaseCommand`。除此之外，它建议查阅一些现有的管理命令，以了解应该做什么。由于我们希望提供一个增强的测试命令，最简单的方法可能是复制`test`命令的实现（在`django/core/management/commands/test.py`中找到）到我们的`survey_test.py`文件中。

查看该文件，我们看到管理命令实现包含两个主要部分。首先，在必要的导入和类声明之后，为类定义了一些属性。这些属性控制诸如它支持什么选项以及用户请求命令时应显示什么帮助之类的事情：

```py
from django.core.management.base import BaseCommand 
from optparse import make_option 
import sys 

class Command(BaseCommand): 
    option_list = BaseCommand.option_list + ( 
        make_option('--noinput', action='store_false', dest='interactive', default=True, 
            help='Tells Django to NOT prompt the user for ''input of any kind.'), 
    ) 
    help = 'Runs the test suite for the specified applications, or '\ 'the entire site if no apps are specified.' 
    args = '[appname ...]' 

    requires_model_validation = False 
```

请注意，虽然`BaseCommand`在官方 Django 1.1 文档中没有记录，但它有一个详尽的文档字符串，因此可以通过查阅源代码或使用 Python shell 的帮助函数来找到这些属性（`option_list`、`help`、`args`、`requires_model_validation`）的确切目的。即使不查看文档字符串，我们也可以看到 Python 的标准`optparse`模块用于构建选项字符串，因此扩展`option_list`以包括其他参数是很简单的。例如，如果我们想要添加一个`--cover`选项来打开测试覆盖数据的生成，我们可以将`option_list`的规范更改为：

```py
     option_list = BaseCommand.option_list + (
        make_option('--noinput', action='store_false',
            dest='interactive', default=True,
            help='Tells Django to NOT prompt the user for '
                'input of any kind.'),
        make_option('--cover', action='store_true',
            dest='coverage', default=False,
            help='Tells Django to generate test coverage data.'),
    ) 
```

在这里，我们添加了对在命令行上指定`--cover`的支持。如果指定了，它将导致`coverage`选项的值为`True`。如果没有指定，这个新选项将默认为`False`。除了添加对该选项的支持，我们还可以为它添加帮助文本。

`Command`实现的声明部分后面是`handle`函数的定义。这是将被调用来实现我们的`survey_test`命令的代码。来自`test`命令的现有代码是：

```py
    def handle(self, *test_labels, **options): 
        from django.conf import settings 
        from django.test.utils import get_runner 

        verbosity = int(options.get('verbosity', 1)) 
        interactive = options.get('interactive', True) 
        test_runner = get_runner(settings) 

        failures = test_runner(test_labels, verbosity=verbosity,  interactive=interactive) 
        if failures: 
            sys.exit(failures) 
```

正如你所看到的，这执行了一个非常简单的选项检索，使用一个实用函数来找到正确的测试运行器来调用，并简单地使用传递的选项调用运行器。当运行器返回时，如果有任何失败，程序将以设置为失败数量的系统退出代码退出。

我们可以用检索新选项的代码替换最后四行，并打印出它是否已被指定：

```py
        coverage = options.get('coverage', False) 
        print 'Here we do our own thing instead of calling the test '\
            'runner.' 
        if coverage: 
            print 'Our new cover option HAS been specified.' 
        else: 
            print 'Our new cover option HAS NOT been specified.' 
```

现在，我们可以尝试运行我们的`survey_test`命令，以验证它是否被找到并且能够接受我们的新选项：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py survey_test --cover 
Here we do our own thing instead of calling the test runner. 
Our new cover option HAS been specified.

```

我们还可以验证，如果我们在命令行上没有传递`--cover`，它默认为`False`：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py survey_test 
Here we do our own thing instead of calling the test runner. 
Our new cover 
option HAS NOT been specified. 

```

最后，我们可以看到我们的选项的帮助包含在新命令的帮助响应中：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py survey_test --help 
Usage: manage.py survey_test [options] [appname ...] 

Runs the test suite for the specified applications, or the entire site if no apps are specified. 

Options: 
 -v VERBOSITY, --verbosity=VERBOSITY 
 Verbosity level; 0=minimal output, 1=normal output, 
 2=all output 
 --settings=SETTINGS   The Python path to a settings module, e.g. 
 "myproject.settings.main". If this isn't provided, the 
 DJANGO_SETTINGS_MODULE environment variable will be used. 
 --pythonpath=PYTHONPATH 
 A directory to add to the Python path, e.g. 
 "/home/djangoprojects/myproject". 
 --traceback           Print traceback on exception 
 --noinput             Tells Django to NOT prompt the user for input of any kind. 
 --cover               Tells Django to generate test coverage data. 
 --version             show program's version number and exit 
 -h, --help            show this help message and exit 

```

请注意，帮助消息中显示的所有其他选项，如果在我们的`option_list`中没有指定，都是从`BaseCommand`继承的。在某些情况下（例如，`settings`和`pythonpath`参数），在调用它们之前，会为我们适当地处理这些参数；在其他情况下（例如`verbosity`），我们期望在我们的实现中遵守选项的文档行为。

添加一个新的管理命令很容易！当然，我们实际上并没有实现运行测试和生成覆盖数据，因为我们还不知道如何做到这一点。有现有的软件包提供了这种支持，我们将在下一节中看到它们如何被用来做到这一点。

现在，我们可能会删除这里创建的`survey/management`树。尝试添加管理命令是一个有用的练习。但实际上，如果我们要提供一个自定义的测试命令来添加诸如记录覆盖数据之类的功能，将这个功能直接绑定到我们的调查应用程序是一个不好的方法。记录覆盖数据的测试命令最好是在一个独立的应用程序中实现。

# 我们测试了多少代码？

在编写测试时，目标是测试一切。虽然我们可以尝试保持警惕并手动确保我们的代码的每一行都有一个测试，但这是一个非常难以实现的目标，除非有一些自动化分析来验证我们的测试执行了哪些代码行。对于 Python 代码，Ned Batchelder 的`coverage`模块是一个优秀的工具，用于确定哪些代码行正在执行。在本节中，我们将看到如何使用`coverage`，首先作为一个独立的实用程序，然后集成到我们的 Django 项目中。

## 使用独立的覆盖

在使用`coverage`之前，必须先安装它，因为它既不包含在 Python 中，也不包含在 Django 1.1 中。如果你使用 Linux，你的发行版包管理器可能有`coverage`可供安装在你的系统上。另外，最新版本的`coverage`始终可以在 Python 软件包索引（PyPI）的网页上找到，[`pypi.python.org/pypi/coverage`](http://pypi.python.org/pypi/coverage)。这里使用的`coverage`版本是 3.2。

安装完成后，我们可以使用`coverage`命令的`run`子命令来运行测试并记录覆盖数据：

```py
kmt@lbox:/dj_projects/marketr$ coverage run manage.py test survey 
Creating test database... 
Creating table auth_permission 
Creating table auth_group 
Creating table auth_user 
Creating table auth_message 
Creating table django_content_type 
Creating table django_session 
Creating table django_site 
Creating table django_admin_log 
Creating table survey_survey 
Creating table survey_question 
Creating table survey_answer 
Installing index for auth.Permission model 
Installing index for auth.Message model 
Installing index for admin.LogEntry model 
Installing index for survey.Question model 
Installing index for survey.Answer model 
..................... 
---------------------------------------------------------------------- 
Ran 21 tests in 11.361s 

OK 
Destroying test database... 

```

如你所见，测试运行器的输出看起来完全正常。覆盖模块不会影响程序的输出；它只是将覆盖数据存储在名为`.coverage`的文件中。

`.coverage`中存储的数据可以使用`coverage`的`report`子命令格式化为报告：

```py
kmt@lbox:/dj_projects/marketr$ coverage report
Name                                                 Stmts   Exec  Cover 
------------------------------------------------------------------------- 
/usr/share/pyshared/mod_python/__init__                   2      2   100% 
/usr/share/pyshared/mod_python/util                     330      1     0% 
/usr/share/pyshared/mx/TextTools/Constants/Sets          42     42   100% 
/usr/share/pyshared/mx/TextTools/Constants/TagTables     12     12   100% 
/usr/share/pyshared/mx/TextTools/Constants/__init__      1      1   100% 
/usr/share/pyshared/mx/TextTools/TextTools              259     47    18% 
/usr/share/pyshared/mx/TextTools/__init__                27     18    66% 
/usr/share/pyshared/mx/TextTools/mxTextTools/__init__    12      9    75% 
/usr/share/pyshared/mx/__init__                          2      2   100% 
/usr/share/pyshared/pysqlite2/__init__                  1      1   100% 
/usr/share/pyshared/pysqlite2/dbapi2               41     26    63% 
/usr/share/python-support/python-simplejson/simplejson/__init__      75     20    26% 
/usr/share/python-support/python-simplejson/simplejson/decoder      208    116    55% 
/usr/share/python-support/python-simplejson/simplejson/encoder      215     40    18% 
/usr/share/python-support/python-simplejson/simplejson/scanner       51     46    90% 
__init__                                                1      1   100% 
manage                                                 9      5    55% 
settings                                                 23     23   100% 
survey/__init__                                             1      1   100% 
survey/admin                                                         24     24   100% 
survey/models                                                        38     37    97% 
survey/tests/__init__                                                 4      4   100% 
survey/tests/admin_tests                                             23     23   100% 
survey/tests/model_tests                                             98     86    87% 
survey/tests/view_tests                                              47     47   100% 
survey/urls                                                           2      2   100% 
survey/views                                                         22     22   100% 
urls                                                                  4      4   100% 
------------------------------------------------------------------------------------- 
TOTAL                                                              1575    663    42% 

```

这比我们实际想要的要多一点。我们只关心我们自己代码的覆盖率，所以首先，对于位于`/usr`目录下的模块报告的内容并不感兴趣。`coverage report`的`--omit`选项可用于省略以特定路径开头的模块。此外，`-m`选项可用于让`coverage`报告未执行（缺失）的行：

```py
kmt@lbox:/dj_projects/marketr$ coverage report --omit /usr -m 
Name                       Stmts   Exec  Cover   Missing 
-------------------------------------------------------- 
__init__                       1      1   100% 
manage                         9      5    55%   5-8 
settings                      23     23   100% 
survey/__init__                1      1   100% 
survey/admin                  24     24   100% 
survey/models                 38     37    97%   66
survey/tests/__init__          4      4   100% 
survey/tests/admin_tests      23     23   100% 
survey/tests/model_tests      98     86    87%   35-42, 47-51 
survey/tests/view_tests       47     47   100% 
survey/urls                    2      2   100% 
survey/views                  23     23   100% 
urls                           4      4   100% 
-------------------------------------------------------- 
TOTAL                        297    280    94% 

```

这样就好多了。毫不奇怪，因为我们已经为讨论的每一部分代码开发了测试，几乎所有内容都显示为已覆盖。还有什么缺失的吗？如果你看一下`manage.py`的 5 到 8 行，它们处理了`settings.py`的`import`引发`ImportError`的情况。由于这部分代码在成功运行时没有被执行，它们在覆盖报告中显示为缺失。

同样，`model_tests`中提到的行（35 到 42，47 到 51）来自于`testClosesReset`方法的替代执行路径，该方法包含从第 34 行开始的代码：

```py
        if settings.DATABASE_ENGINE == 'mysql': 
            from django.db import connection 
            c = connection.cursor() 
            c.execute('SELECT @@SESSION.sql_mode') 
            mode = c.fetchone()[0] 
            if 'STRICT' not in mode: 
                strict = False; 
                from django.utils import importlib 
                debug = importlib.import_module(
                    settings.SETTINGS_MODULE).DEBUG 

        if strict: 
            self.assertRaises(IntegrityError, s.save) 
        elif debug: 
            self.assertRaises(Exception, s.save) 
        else: 
            s.save() 
            self.assertEqual(s.closes, None) 
```

35 到 42 行没有被执行，因为此次运行使用的数据库是 SQLite，而不是 MySQL。然后，在任何单个测试运行中，`if strict/elif debug/else`块中的一个分支将执行，因此其他分支将显示为未覆盖的。在这种情况下，`if strict`分支是被执行的。

最后一个被标记为缺失的行是`survey/models.py`中的第 66 行。这是`Question`模型的`__unicode__`方法实现，我们忽略了为其编写测试。我们可以把这件事放在待办事项清单上。

尽管最后一个是缺失测试的有效指示，但`manage.py`中的缺失行和我们的测试代码中的缺失行并不是我们真正关心的事情，因为它们并没有报告我们应用代码的缺失覆盖。实际上，如果我们很仔细，我们可能会希望确保我们的测试代码在不同的设置下运行了几次，但让我们暂时假设我们只对我们应用代码的覆盖率感兴趣。`coverage`模块支持几种不同的方法来排除报告中的代码。一种可能性是在源代码行上注释`# pgrama no cover`指令，告诉`coverage`将其排除在覆盖率考虑之外。

另外，`coverage`提供了一个 Python API，支持指定应自动排除的代码结构的正则表达式，还支持限制报告中包含的模块。这个 Python API 比命令行提供的功能更强大，比手动使用`# pragma`指令注释源代码更方便。因此，我们可以开始研究如何编写一些`coverage`实用程序脚本，以便轻松生成我们应用代码的测试覆盖率报告。

然而，在开始这项任务之前，我们可能会想知道是否有人已经做过同样的事情，并提供了一个集成`coverage`与 Django 测试支持的即插即用的工具。在网上搜索后发现答案是肯定的——有几篇博客文章讨论了这个主题，至少有一个项目打包为 Django 应用程序。接下来将讨论使用这个包。

## 将覆盖率集成到 Django 项目中

George Song 和 Mikhail Korobov 提供了一个名为`django_coverage`的 Django 应用程序，支持将`coverage`集成到 Django 项目的测试中。与基本的`coverage`包一样，`django_coverage`可以在 PyPI 上找到：[`pypi.python.org/pypi/django-coverage`](http://pypi.python.org/pypi/django-coverage)。这里使用的版本是 1.0.1。

`django_coverage`包提供了将`coverage`与 Django 集成的方法，使用了之前讨论过的两种方法。首先，它提供了一个可以在`settings.py`中指定的测试运行程序：

```py
TEST_RUNNER = 'django_coverage.coverage_runner.run_tests' 
```

使用这个选项，每次运行`manage.py test`时都会生成覆盖信息。

另外，`django_coverage`也可以包含在`INSTALLED_APPS`中。当使用这种方法时，`django_coverage`应用程序提供了一个名为`test_coverage`的新管理命令。`test_coverage`命令可以用来代替`test`来运行测试并生成覆盖信息。由于生成覆盖信息会使测试运行得更慢，我们将使用第二个选项。这样，我们可以选择在对速度要求较高且不关心覆盖率时运行测试。

除了将`django_coverage`列在`INSTALLED_APPS`中之外，无需进行任何设置即可使`django_coverage`与我们的项目一起运行。它带有一个示例`settings.py`文件，显示了它支持的设置，所有设置都有默认选项和注释描述其作用。我们可以通过在我们自己的设置文件中指定我们喜欢的值来覆盖`django_coverage/settings.py`中提供的任何默认设置。

不过，我们将首先使用提供的所有默认设置值。当我们运行`python manage.py test_coverage survey`时，我们将在测试输出的末尾看到覆盖信息：

```py
---------------------------------------------------------------------- 
Ran 21 tests in 10.040s 

OK 
Destroying test database... 
Name            Stmts   Exec  Cover   Missing 
--------------------------------------------- 
survey.admin       21     21   100% 
survey.models      30     30   100% 
survey.views       18     18   100% 
--------------------------------------------- 
TOTAL              69     69   100% 

The following packages or modules were excluded: survey.__init__ survey.tests survey.urls

There were problems with the following packages or modules: survey.templates survey.fixtures 

```

这有点奇怪。回想一下，在上一节中，`coverage`包报告说`survey.models`中的一行代码没有被测试覆盖——`Question`模型的`__unicode__`方法。然而，这个报告显示`survey.models`的覆盖率为 100%。仔细观察这两份报告，我们可以看到列出的模块的语句在`django_coverage`报告中都比在`coverage`报告中低。

这种差异是由`django_coverage`使用的`COVERAGE_CODE_EXCLUDES`设置的默认值造成的。此设置的默认值导致所有`import`行、所有`__unicode__`方法定义和所有`get_absolute_url`方法定义都被排除在考虑范围之外。这些默认排除导致了这两份报告之间的差异。如果我们不喜欢这种默认行为，我们可以提供自己的替代设置，但现在我们将保持原样。

此外，`coverage`列出的一些模块在`django_coverage`报告中完全缺失。这也是默认设置值的结果（在这种情况下是`COVERAGE_MODULE_EXCLUDES`），输出中有一条消息指出由于此设置而被排除的模块。正如你所看到的，`survey`中的`__init__`、`tests`和`urls`模块都被自动排除在覆盖范围之外。

然而，默认情况下不排除`templates`和`fixtures`，这导致了一个问题，因为它们实际上不是 Python 模块，所以不能被导入。为了摆脱关于加载这些问题的消息，我们可以在自己的`settings.py`文件中为`COVERAGE_MODULE_EXCLUDES`指定一个值，并包括这两个。将它们添加到默认列表中，我们有：

```py
COVERAGE_MODULE_EXCLUDES = ['tests$', 'settings$', 'urls$',
                            'common.views.test', '__init__', 'django',
                            'migrations', 'fixtures$', 'templates$']
```

如果我们在进行此更改后再次运行`test_coverage`命令，我们将看到关于加载某些模块存在问题的消息已经消失了。

显示在测试输出中的摘要信息很有用，但更好的是`django_coverage`可以生成的 HTML 报告。要获得这些报告，我们必须为`COVERAGE_REPORT_HTML_OUTPUT_DIR`设置指定一个值，默认值为`None`。因此，我们可以在`/dj_projects/marketr`中创建一个`coverage_html`目录，并在`settings.py`中指定它：

```py
COVERAGE_REPORT_HTML_OUTPUT_DIR = '/dj_projects/marketr/coverage_html'
```

当代码覆盖率达到 100％时，HTML 报告并不特别有趣。因此，为了看到报告的完整用处，让我们只运行单个测试，比如尝试使用`closes`日期早于其`opens`日期的`Survey`的管理员测试：

```py
python manage.py test_coverage survey.AdminSurveyTest.testAddSurveyError

```

这一次，由于我们为 HTML 覆盖率报告指定了一个目录，所以在测试运行结束时，我们看到的不是摘要覆盖率信息，而是：

```py
Ran 1 test in 0.337s

OK
Destroying test database...

HTML reports were output to '/dj_projects/marketr/coverage_html'

```

然后，我们可以使用 Web 浏览器加载放置在`coverage_html`目录中的`index.html`文件。它会看起来像这样：

![将覆盖率整合到 Django 项目中](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_05_01.jpg)

由于我们只运行了单个测试，我们只对我们的代码进行了部分覆盖。HTML 报告中的**％ covered**值以颜色编码方式反映了每个模块的覆盖情况。绿色是好的，黄色是一般，红色是差的。在这种情况下，由于我们运行了其中一个管理员测试，只有**survey.admin**被标记为绿色，而且它并不是 100％。要查看该模块中遗漏的内容，我们可以点击**survey.admin**链接：

![将覆盖率整合到 Django 项目中](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_05_02.jpg)

这样的报告提供了一种非常方便的方式来确定我们的应用程序代码中哪些部分被测试覆盖，哪些部分没有被测试覆盖。未执行的行会以红色高亮显示。在这里，我们只运行了通过`SurveyFrom clean`方法的错误路径的测试，所以该方法的成功代码路径以红色显示。此外，`import`行的颜色编码表明它们被排除了。这是由于默认的`COVERAGE_CODE_EXCLUDES`设置。最后，文件中的六行空行被忽略了（带有注释的行也会被忽略）。

使用像`coverage`这样的工具对于确保测试套件正常运行至关重要。未来，Django 可能会提供一些集成的代码覆盖支持。但与此同时，正如我们所看到的，将`coverage`作为项目的附加组件集成并不困难。在`django_coverage`的情况下，它提供了使用之前讨论过的 Django 扩展方式的选项。我们将讨论的下一个集成任务既不需要这两种方式，也只需要标准的 Python 钩子来设置和拆卸单元测试。

# twill 网络浏览和测试工具

`twill`是一个支持与网站进行命令行交互的 Python 包，主要用于测试目的。与`coverage`和`django_coverage`包一样，twill 可以在 PyPI 上找到：[`pypi.python.org/pypi/twill`](http://pypi.python.org/pypi/twill)。虽然`twill`提供了一个用于交互使用的命令行工具，但它提供的命令也可以通过 Python API 使用，这意味着可以在 Django `TestCase`中使用`twill`。当我们这样做时，我们实质上是用替代的`twill`实现替换了 Django 测试`Client`的使用。

### 注意

请注意，目前在 PyPI 上可用的`twill`的最新官方版本（在撰写本文时为 0.9）非常古老。最新的开发版本可在[`darcs.idyll.org/~t/projects/twill-latest.tar.gz`](http://darcs.idyll.org/~t/projects/twill-latest.tar.gz)上找到。截至 2010 年 1 月的最新开发版本的输出如本节所示。此处包含的代码也经过了官方的 0.9 版本测试。使用旧的`twill`代码一切正常，但`twill`的错误输出略显不足，而且在作为 Django `TestCase`的一部分运行时，有些`twill`输出无法被抑制。因此，我建议使用最新的开发版本而不是 0.9 版本。

为什么我们要使用`twill`而不是 Django 测试`Client`？为了理解使用`twill`而不是 Django 测试`Client`的动机，让我们重新审视上一章的管理员定制测试。回想一下，我们为添加和编辑`Survey`对象提供了一个自定义表单。这个表单有一个`clean`方法，对于任何试图保存`opens`日期晚于其`closes`日期的`Survey`都会引发`ValidationError`。确保在应该引发`ValidationError`时引发它的测试如下所示：

```py
    def testAddSurveyError(self): 
        post_data = { 
            'title': u'Time Traveling', 
            'opens': datetime.date.today(), 
            'closes': datetime.date.today() - datetime.timedelta(1), 
            'question_set-TOTAL_FORMS': u'0', 
            'question_set-INITIAL_FORMS': u'0', 
        } 
        response = self.client.post(
            reverse('admin:survey_survey_add'), post_data) 
        self.assertContains(response,"Opens date cannot come after closes date.") 
```

请注意，这个测试向服务器发送了一个包含 POST 数据字典的 POST，而没有发出 GET 请求来获取页面。这最初引起了问题：回想一下，我们最初没有在 POST 字典中包含`question_set-TOTAL_FORMS`和`question_set-INITIAL_FORMS`的值。我们当时专注于测试页面上表单的`Survey`部分，并没有意识到管理员用于显示`Surveys`中的`Questions`的表单集需要这些其他值。当我们发现它们是必需的时，我们有点鲁莽地将它们的值设置为`0`，并希望这对我们想要测试的内容是可以接受的。

一个更好的方法是首先`get`调查添加页面。响应将包括一个带有一组初始值的表单，可以用作`post`回去的字典的基础。在发出`post`请求之前，我们只需更改我们测试所需的值（`title`，`opens`和`closes`）。因此，当我们发出`post`调用时，服务器最初在表单中提供的任何其他表单值都将不变地发送回去。我们不必为测试不打算更改的表单部分编制额外的值。

除了更真实地模拟服务器交互场景之外，这种方法还确保服务器正确响应 GET 请求。在这种特殊情况下，测试 GET 路径并不是必要的，因为我们在管理员中添加的额外验证不会影响其对页面的 GET 响应。但是，对于我们自己的视图中提供响应的表单，我们希望测试对`get`和`post`的响应。

那么为什么我们不以这种方式编写测试呢？测试`Client`支持`get`和`post`；我们当然可以通过检索包含表单的页面来开始。问题在于返回的响应是 HTML，而 Django 测试`Client`没有提供任何实用函数来解析 HTML 表单并将其转换为我们可以轻松操作的内容。Django 没有直接的方法来获取响应，更改表单中的一些值，然后将其`post`回服务器。另一方面，`twill`包可以轻松实现这一点。

在接下来的章节中，我们将使用`twill`重新实现`AdminSurveyTest`。首先，我们将看到如何使用其命令行工具，然后将我们学到的内容转移到 Django `TestCase`中。

## 使用 twill 命令行程序

`twill`包括一个名为`twill-sh`的 shell 脚本，允许进行命令行测试。这是一种方便的方法，可以进行一些初始测试，并找出测试用例代码需要做什么。从 shell 程序中，我们可以使用`go`命令访问页面。一旦我们访问了一个页面，我们可以使用`showforms`命令查看页面上有哪些表单，表单包含哪些字段和初始值。由于我们将使用`twill`重新实现`AdminSurveyTest`，让我们看看为我们的测试服务器访问`Survey`添加页面会产生什么：

```py
kmt@lbox:~$ twill-sh 

 -= Welcome to twill! =- 

current page:  *empty page* 
>> go http://localhost:8000/admin/survey/survey/add/ 
==> at http://localhost:8000/admin/survey/survey/add/ 
current page: http://localhost:8000/admin/survey/survey/add/ 
>> showforms 

Form #1 
## ## __Name__________________ __Type___ __ID________ __Value____________
1     username                 text      id_username 
2     password                 password  id_password 
3     this_is_the_login_form   hidden    (None)       1 
4  1  None                     submit    (None)       Log in 

current page: http://localhost:8000/admin/survey/survey/add/ 
>> 

```

显然，我们实际上没有到达调查添加页面。由于我们没有登录，服务器响应了一个登录页面。我们可以使用`formvalue`命令填写登录表单：

```py
>> formvalue 1 username kmt 
current page: http://localhost:8000/admin/survey/survey/add/ 
>> formvalue 1 password secret
current page: http://localhost:8000/admin/survey/survey/add/ 
>> 

```

`formvalue`的参数首先是表单编号，然后是字段名称，然后是我们要为该字段设置的值。一旦我们在表单中填写了用户名和密码，我们就可以`submit`表单了。

```py
>> submit 
Note: submit is using submit button: name="None", value="Log in" 

current page: http://localhost:8000/admin/survey/survey/add/ 

```

请注意，`submit`命令还可以选择接受要使用的提交按钮的名称。在只有一个（就像这里）或者如果使用表单上的第一个提交按钮是可以接受的情况下，我们可以简单地使用没有参数的`submit`。现在我们已经登录，我们可以再次使用`showforms`来查看我们是否真的检索到了`Survey`添加页面：

```py
>> showforms 

Form #1 
## ## __Name__________________ __Type___ __ID________ __Value____________
1     title                    text      id_title 
2     opens                    text      id_opens 
3     closes                   text      id_closes 
4     question_set-TOTAL_FORMS hidden    id_quest ... 4 
5     question_set-INITIAL ... hidden    id_quest ... 0 
6     question_set-0-id        hidden    id_quest ... 
7     question_set-0-survey    hidden    id_quest ... 
8     question_set-0-question  text      id_quest ... 
9     question_set-1-id        hidden    id_quest ... 
10    question_set-1-survey    hidden    id_quest ... 
11    question_set-1-question  text      id_quest ... 
12    question_set-2-id        hidden    id_quest ... 
13    question_set-2-survey    hidden    id_quest ... 
14    question_set-2-question  text      id_quest ... 
15    question_set-3-id        hidden    id_quest ... 
16    question_set-3-survey    hidden    id_quest ... 
17    question_set-3-question  text      id_quest ... 
18 1  _save                    submit    (None)       Save 
19 2  _addanother              submit    (None)       Save and add another 
20 3  _continue                submit    (None)       Save and continue editing 

current page: http://localhost:8000/admin/survey/survey/add/ 
>> 

```

这更像是一个`Survey`添加页面。确实，我们在第一个测试用例中将`question_set-TOTAL_FORMS`设置为`0`是不现实的，因为服务器实际上提供了一个将其设置为`4`的表单。但它起作用了。这意味着我们不必为这四个内联问题制造值，因此这不是一个致命的缺陷。然而，使用`twill`，我们可以采取更现实的路径，将所有这些值保持不变，只改变我们感兴趣的字段，再次使用`formvalue`命令：

```py
>> formvalue 1 title 'Time Traveling' 
current page: http://localhost:8000/admin/survey/survey/add/ 
>> formvalue 1 opens 2009-08-15 
current page: http://localhost:8000/admin/survey/survey/add/ 
>> formvalue 1 closes 2009-08-01 
current page: http://localhost:8000/admin/survey/survey/add/ 

```

当我们提交该表单时，我们期望服务器会用相同的表单重新显示，并显示来自我们自定义`clean`方法的`ValidationError`消息文本。我们可以使用`find`命令验证返回页面上是否有该文本：

```py
>> submit 
Note: submit is using submit button: name="_save", value="Save" 

current page: http://localhost:8000/admin/survey/survey/add/ 
>> find "Opens date cannot come after closes date." 
current page: http://localhost:8000/admin/survey/survey/add/ 
>>

```

对于`find`的响应可能不会立即明显它是否起作用。让我们看看它对于页面上最有可能不存在的内容会做什么：

```py
>> find "lalalala I don't hear you" 

ERROR: no match to 'lalalala I don't hear you' 

current page: http://localhost:8000/admin/survey/survey/add/ 
>> 

```

好吧，由于`twill`明显在找不到文本时会抱怨，第一个`find`必须已经成功地在页面上找到了预期的验证错误文本。现在，我们可以再次使用`showforms`来查看服务器是否确实发送回我们提交的表单。请注意，初始值是我们提交的值，而不是我们第一次检索页面时的空值。

```py
>> showforms 

Form #1 
## ## __Name__________________ __Type___ __ID________ __Value________________
1     title                    text      id_title     Time Traveling 
2     opens                    text      id_opens     2009-08-15 
3     closes                   text      id_closes    2009-08-01 
4     question_set-TOTAL_FORMS hidden    id_quest ... 4 
5     question_set-INITIAL ... hidden    id_quest ... 0 
6     question_set-0-id        hidden    id_quest ... 
7     question_set-0-survey    hidden    id_quest ... 
8     question_set-0-question  text      id_quest ... 
9     question_set-1-id        hidden    id_quest ... 
10    question_set-1-survey    hidden    id_quest ... 
11    question_set-1-question  text      id_quest ... 
12    question_set-2-id        hidden    id_quest ... 
13    question_set-2-survey    hidden    id_quest ... 
14    question_set-2-question  text      id_quest ... 
15    question_set-3-id        hidden    id_quest ... 
16    question_set-3-survey    hidden    id_quest ... 
17    question_set-3-question  text      id_quest ... 
18 1  _save                    submit    (None)       Save 
19 2  _addanother              submit    (None)     Save and add another 
20 3  _continue                submit    (None)     Save and continue editing 

current page: http://localhost:8000/admin/survey/survey/add/ 
>>

```

在这一点上，我们可以简单地调整一个日期以使表单有效，并尝试再次提交它：

```py
>> formvalue 1 opens 2009-07-15 
current page: http://localhost:8000/admin/survey/survey/add/ 
>> submit 
Note: submit is using submit button: name="_save", value="Save" 

current page: http://localhost:8000/admin/survey/survey/ 
>> 

```

当前页面已更改为调查变更列表页面（URL 路径末尾不再有`add`）。这是一个线索，表明`Survey`添加这次起作用了，因为服务器在成功保存后会重定向到变更列表页面。有一个名为`show`的 twill 命令用于显示页面的 HTML 内容。当你有一个可以滚动回去的显示窗口时，这可能很有用。然而，HTML 页面在纸上复制时并不是很有用，所以这里不显示。

`twill`提供了许多更有用的命令，超出了我们现在所涵盖的范围。这里的讨论旨在简单地展示`twill`提供了什么，并展示如何在 Django 测试用例中使用它。下面将介绍第二个任务。

## 在 TestCase 中使用 twill

我们需要做什么来将我们在`twill-sh`程序中所做的工作转换为`TestCase`？首先，我们需要在测试代码中使用`twill`的 Python API。我们在`twill-sh`中使用的`twill`命令在`twill.commands`模块中可用。此外，`twill`提供了一个浏览器对象（通过`twill.get_browser()`访问），可能更适合从 Python 调用。命令的浏览器对象版本可能返回一个值，例如，而不是在屏幕上打印一些东西。然而，浏览器对象不直接支持`twill.commands`中的所有命令，因此通常使用混合`twill.commands`方法和浏览器方法是常见的。混合使用是可以的，因为`twill.commands`中的代码在从`twill.get_browser()`返回的同一个浏览器实例上运行。

其次，出于测试代码的目的，我们希望指示`twill`直接与我们的 Django 服务器应用程序代码交互，而不是将请求发送到实际服务器。在使用`twill-sh`代码针对我们正在运行的开发服务器进行测试时，这是可以的，但我们不希望服务器在运行以使我们的测试通过。Django 测试`Client`会自动执行这一点，因为它是专门编写用于从测试代码中使用的。

使用`twill`，我们必须调用它的`add_wsgi_intercept`方法，告诉它将特定主机和端口的请求直接路由到 WSGI 应用程序，而不是将请求发送到网络上。Django 提供了一个支持 WSGI 应用程序接口（名为`WSGIHandler`）的类，在`django.core.handlers.wsgi`中。因此，在我们的测试中使用`twill`的设置代码中，我们可以包含类似这样的代码：

```py
from django.core.handlers.wsgi import WSGIHandler 
import twill 
TWILL_TEST_HOST = 'twilltest'   
twill.add_wsgi_intercept(TWILL_TEST_HOST, 80, WSGIHandler) 
```

这告诉`twill`，一个`WSGIHandler`实例应该用于处理任何发送到名为`twilltest`的主机的端口 80 的请求。这里使用的实际主机名和端口不重要；它们只是必须与我们的测试代码尝试访问的主机名和端口匹配。

这将我们带到我们的测试代码中必须考虑的第三件事。我们在 Django 测试`Client`中使用的 URL 没有主机名或端口组件，因为测试`Client`不基于该信息执行任何路由，而是直接将请求发送到我们的应用程序代码。另一方面，`twill`接口确实期望在传递给它的 URL 中包含主机（和可选端口）组件。因此，我们需要构建对于`twill`正确并且将被适当路由的 URL。由于我们通常在测试期间使用 Django 的`reverse`来创建我们的 URL，因此一个实用函数，它接受一个命名的 URL 并返回将其反转为`twill`可以正确处理的形式的结果将会很方便。

```py
def reverse_for_twill(named_url): 
    return 'http://' + TWILL_TEST_HOST + reverse(named_url) 
```

请注意，由于我们在`add_wsgi_intercept`调用中使用了默认的 HTTP 端口，因此我们不需要在 URL 中包含端口号。

关于使用`WSGIHandler`应用程序接口进行测试的一件事是，默认情况下，该接口会抑制在处理请求时引发的任何异常。这是在生产环境中使用的相同接口，例如在 Apache 下运行时使用的`mod_wsgi`模块。在这样的环境中，`WSGIHandler`暴露异常给其调用者是不可接受的，因此它捕获所有异常并将它们转换为服务器错误（HTTP 500）响应。

尽管在生产环境中抑制异常是正确的行为，但在测试中并不是很有用。生成的服务器错误响应而不是异常完全无助于确定问题的根源。因此，这种行为可能会使诊断测试失败变得非常困难，特别是在被测试的代码引发异常的情况下。

为了解决这个问题，Django 有一个设置`DEBUG_PROPAGATE_EXCEPTIONS`，可以设置为`True`，告诉`WSGIHandler`接口允许异常传播。这个设置默认为`False`，在生产环境中永远不应该设置为`True`。然而，我们的`twill`测试设置代码应该将其设置为`True`，这样如果在请求处理过程中引发异常，它将在测试运行时被看到，而不是被通用的服务器错误响应替换。

使用 Django 的`WSGIHandler`接口进行测试时的最后一个问题是保持单个数据库连接用于单个测试发出的多个网页请求。通常，每个请求（获取或提交页面）都使用自己新建立的数据库连接。对于成功请求的处理结束时，数据库连接上的任何打开事务都将被提交，并关闭数据库连接。

然而，正如在第四章的结尾所指出的，`TestCase`代码会阻止由测试代码发出的任何数据库提交实际到达数据库。因此，在测试数据库中将不会看到通常在请求结束时出现的提交，而是只会看到连接关闭。一些数据库，如具有 InnoDB 存储引擎的 PostgreSQL 和 MySQL，将在这种情况下自动回滚打开的事务。这将对需要发出多个请求并且需要让先前请求所做的数据库更新对后续请求可访问的测试造成问题。例如，任何需要登录的测试都会遇到麻烦，因为登录信息存储在`django_session`数据库表中。

一种解决方法是将`TransactionTestCase`用作所有使用`twill`的测试的基类，而不是`TestCase`。使用`TransactionTestCase`，通常在请求处理结束时发生的提交将像往常一样发送到数据库。然而，在每个测试之间将数据库重置为干净状态的过程对于`TransactionTestCase`来说要比`TestCase`慢得多，因此这种方法可能会显著减慢我们的测试速度。

另一种解决方案是阻止在请求处理结束时关闭数据库连接。这样，在测试过程中就不会触发数据库在测试中间回滚任何更新。我们可以在测试的`setUp`方法中将`close_connection`信号处理程序与`request_finished`信号断开连接来实现这一点。这不是一个非常干净的解决方案，但这样做是值得的（这也是测试`Client`用来克服相同问题的方法）。

因此，让我们从为`AdminSurveyTest`编写一个`twill`版本的`setUp`方法开始。前一章中的测试`Client`版本如下：

```py
class AdminSurveyTest(TestCase):
    def setUp(self):
        self.username = 'survey_admin'
        self.pw = 'pwpwpw'
        self.user = User.objects.create_user(self.username, '', " "self.pw)
        self.user.is_staff= True
        self.user.is_superuser = True
        self.user.save()
        self.assertTrue(self.client.login(username=self.username, password=self.pw),
            "Logging in user %s, pw %s failed." % (self.username, self.pw))
```

`twill`版本将需要执行相同的用户创建步骤，但登录步骤会有所不同。我们将用户创建代码提取到一个公共基类（称为`AdminTest`）中，供`AdminSurveyTest`和`twill`版本的`AdminSurveyTwillTest`使用。对于`twill`版本的登录，我们可以填写并提交登录表单，如果在登录之前尝试访问任何管理员页面，将返回该表单。因此，`twill`版本的`setUp`可能如下所示：

```py
from django.db import close_connection
from django.core import signals
from django.core.handlers.wsgi import WSGIHandler 
from django.conf import settings
import twill 

class AdminSurveyTwillTest(AdminTest): 
    def setUp(self): 
        super(AdminSurveyTwillTest, self).setUp() 
        self.old_propagate = settings.DEBUG_PROPAGATE_EXCEPTIONS
        settings.DEBUG_PROPAGATE_EXCEPTIONS = True
        signals.request_finished.disconnect(close_connection)
        twill.add_wsgi_intercept(TWILL_TEST_HOST, 80, WSGIHandler) 
        self.browser = twill.get_browser() 
        self.browser.go(reverse_for_twill('admin:index')) 
        twill.commands.formvalue(1, 'username', self.username) 
        twill.commands.formvalue(1, 'password', self.pw) 
        self.browser.submit() 
        twill.commands.find('Welcome') 
```

这个`setUp`首先调用超类`setUp`来创建管理员用户，然后保存现有的`DEBUG_PROPAGATE_EXCEPTIONS`设置，然后将其设置为`True`。然后，它断开`close_connection`信号处理程序与`request_finished`信号的连接。接下来，它调用`twill.add_wsgi_intercept`来设置`twill`以将对`twilltest`主机的请求路由到 Django 的`WSGIHandler`。为了方便访问，它将`twill`浏览器对象存储在`self.browser`中。然后，它使用先前提到的`reverse_for_twill`实用函数来创建管理员索引页面的适当 URL，并调用浏览器`go`方法来检索该页面。

返回的页面应该有一个包含`用户名`和`密码`字段的表单。这些字段设置为由超类`setUp`创建的用户的值，使用`formvalue`命令，并使用浏览器`submit`方法提交表单。如果登录成功，结果应该是管理员索引页面。该页面上将有字符串`Welcome`，因此这个`setUp`例程的最后一件事是验证页面上是否找到了文本，这样如果登录失败，错误就会在遇到问题的地方而不是后来引发。

当我们编写`setUp`时，我们还应该编写相应的`tearDown`方法来撤消`setUp`的影响：

```py
    def tearDown(self): 
        self.browser.go(reverse_for_twill('admin:logout')) 
        twill.remove_wsgi_intercept(TWILL_TEST_HOST, 80)
        signals.request_finished.connect(close_connection) 
        settings.DEBUG_PROPAGATE_EXCEPTIONS = self.old_propagate 
```

在这里，我们`go`到管理员注销页面以从管理员站点注销，调用`remove_wsgi_intercept`以删除名为`twilltest`的主机的特殊路由，重新连接正常的`close_connection`信号处理程序到`request_finished`信号，最后恢复`DEBUG_PROPAGATE_EXCEPTIONS`的旧值。

然后，一个检查`closes`早于`opens`的错误情况的`twill`版本的测试例程将是：

```py
    def testAddSurveyError(self): 
        self.browser.go(reverse_for_twill('admin:survey_survey_add')) 
        twill.commands.formvalue(1, 'title', 'Time Traveling') 
        twill.commands.formvalue(1, 'opens', str(datetime.date.today())) 
         twill.commands.formvalue(1, 'closes',
            str(datetime.date.today()-datetime.timedelta(1)))
        self.browser.submit()
        twill.commands.url(reverse_for_twill(
            'admin:survey_survey_add'))
        twill.commands.find("Opens date cannot come after closes "
            "date.") 
```

与测试`Client`版本不同，这里我们首先访问管理员`Survey`添加页面。我们期望响应包含一个单独的表单，并为其中的`title`、`opens`和`closes`设置值。我们不关心表单中可能还有什么，所以保持不变。然后我们`submit`表单。

我们期望在错误情况下（鉴于我们将`closes`设置为比`opens`早一天，这应该是错误情况），管理员将重新显示相同的页面，并显示错误消息。我们通过首先使用`twill url`命令来测试当前 URL 是否仍然是`Survey`添加页面的 URL 来测试这一点。然后，我们还使用`twill find`命令来验证页面上是否找到了预期的错误消息。（可能只需要执行其中一个检查，但同时执行两个不会有害。因此，这里包括了两个以示例目的。）

如果我们现在使用`python manage.py test survey.AdminSurveyTwillTest`运行这个测试，我们会看到它可以工作，但即使使用 Python API，`twill`也有点啰嗦。在测试输出的末尾，我们会看到：

```py
Installing index for survey.Answer model 
==> at http://twilltest/admin/ 
Note: submit is using submit button: name="None", value="Log in" 

==> at http://twilltest/admin/survey/survey/add/ 
Note: submit is using submit button: name="_save", value="Save" 

==> at http://twilltest/admin/logout/ 
. 
---------------------------------------------------------------------- 
Ran 1 test in 0.845s 

OK 
Destroying test database... 

```

我们不希望`twill`的输出混乱了我们的测试输出，所以我们希望将这些输出重定向到其他地方。幸运的是，`twill`提供了一个用于此目的的例程，`set_output`。因此，我们可以将以下内容添加到我们的`setUp`方法中：

```py
        twill.set_output(StringIO())
```

在打印输出的任何`twill`命令之前放置这个，并记得在引用`StringIO`之前在导入中包括`from StringIO import StringIO`。我们还应该在我们的`tearDown`例程中通过调用`twill.commands.reset_output()`来撤消这一点。这将恢复`twill`将输出发送到屏幕的默认行为。做出这些更改后，如果我们再次运行测试，我们会看到它通过了，并且`twill`的输出不再存在。

然后，最后要编写的是添加一个`Survey`的测试用例，其中日期不会触发验证错误。它可能看起来像这样：

```py
    def testAddSurveyOK(self): 
        self.browser.go(reverse_for_twill('admin:survey_survey_add')) 
        twill.commands.formvalue(1, 'title', 'Not Time Traveling') 
        twill.commands.formvalue(1, 'opens', str(datetime.date.today())) 
        twill.commands.formvalue(1, 'closes', str(datetime.date.today())) 
        self.browser.submit() 
        twill.commands.url(reverse_for_twill('admin:survey_survey_changelist'))
```

这与之前的测试非常相似，只是我们尝试验证在预期的成功提交时是否重定向到管理员 changelist 页面。如果我们运行这个测试，它会通过，但实际上是不正确的。也就是说，如果管理员重新显示添加页面而不是重定向到 changelist 页面，它将不会失败。因此，如果我们破坏了某些东西并导致应该成功的提交失败，这个测试将无法捕捉到。

要看到这一点，将这个测试用例中的`closes`日期更改为`opens`之前一天。这将触发一个错误，就像`testAddSurveyError`方法中的情况一样。然而，如果我们进行了这个更改运行测试，它仍然会通过。

这是因为`twill url`命令以正则表达式作为其参数。它不是检查传递的参数与实际 URL 的精确匹配，而是实际 URL 是否与传递给`url`命令的正则表达式匹配。我们传递给`url`方法的 changelist URL 是：

`http://twilltest/admin/survey/survey/`

在提交时出现错误时，将重新显示添加页面的 URL 将是：

`http://twilltest/admin/survey/survey/add/`

尝试将添加页面 URL 与 changelist 页面 URL 进行匹配将成功，因为 changelist URL 包含在添加页面 URL 中。因此，`twill url`命令不会像我们希望的那样引发错误。为了解决这个问题，我们必须在传递给`url`的正则表达式中指示，我们要求实际 URL 以我们传递的值结束，通过在我们传递的值上包含一个字符串结束标记：

```py
twill.commands.url(reverse_for_twill('admin:survey_survey_changelist') + '$') 
```

我们还可以在开头包括一个字符串标记，但实际上并不需要修复这个特定问题。如果我们进行这个更改，保留不正确的`closes`日期设置，我们会看到这个测试用例现在确实失败了，当服务器重新显示添加页面时，而不是成功处理提交：

```py
====================================================================== 
ERROR: testAddSurveyOK (survey.tests.admin_tests.AdminSurveyTwillTest) 
---------------------------------------------------------------------- 
Traceback (most recent call last): 
 File "/dj_projects/marketr/survey/tests/admin_tests.py", line 91, in testAddSurveyOK 
 twill.commands.url(reverse_for_twill('admin:survey_survey_changelist') + '$') 
 File "/usr/lib/python2.5/site-packages/twill/commands.py", line 178, in url 
 """ % (current_url, should_be,)) 
TwillAssertionError: current url is 'http://twilltest/admin/survey/survey/add/'; 
does not match 'http://twilltest/admin/survey/survey/$' 

---------------------------------------------------------------------- 
Ran 2 tests in 1.349s 

FAILED (errors=1) 
Destroying test database... 

```

一旦我们验证测试在服务器不按预期响应的情况下失败，我们可以将`closes`日期设置恢复为可接受的保存，并且测试将再次通过。这里的一个教训是在使用`twill`提供的`url`命令时要小心。第二个教训是始终尝试验证测试在适当时报告失败。当专注于编写通过的测试时，我们经常忘记验证测试在应该失败时是否能够正确失败。

我们现在已经有了基于`twill`的工作版本的管理员定制测试。实现这一点并不容易——例如，一些`setUp`代码的需求并不一定立即显而易见。然而，一旦放置，它可以很容易地被需要比我们在这里需要的更复杂的表单操作的测试所重用。表单操作是 Django 测试框架的一个薄弱点，而且不太可能通过在 Django 中添加重复外部工具中已有的函数的函数来解决这个问题。更有可能的是，在将来，Django 将提供更容易与`twill`或类似工具集成。因此，投资学习如何使用类似`twill`的工具可能是一个很好的时间利用。

# 总结

这使我们结束了讨论 Django 应用程序的测试。在本章中，我们重点介绍了如何通过与其他测试工具集成来填补 Django 中测试函数的任何空白。不可能涵盖与每个工具集成的具体细节，但我们学习了可用的一般机制，并详细讨论了一些例子。这为理解如何一般完成任务提供了坚实的基础。

随着 Django 的不断发展，这样的空白可能会变得更少，但是 Django 不太可能能够在测试支持方面提供每个人都想要的一切。在某些情况下，Python 的类继承结构和单元测试扩展机制允许将其他测试工具直接集成到 Django 测试用例中。在其他情况下，这是不够的。因此，Django 提供了用于添加额外功能的钩子是有帮助的。在本章中，我们：

+   学习了 Django 为添加测试功能提供的钩子

+   看到了这些钩子如何被使用的例子，特别是在添加代码覆盖报告的情况下

+   还探讨了一个例子，在这个例子中，使用这些钩子是不必要的——当将`twill`测试工具集成到我们的 Django 测试用例中时

在下一章中，我们将从测试转向调试，并开始学习 Django 提供的哪些设施来帮助调试我们的 Django 应用程序。


# 第六章：Django 调试概述

世界上最好的测试套件也无法使您免受调试问题的困扰。测试只是报告代码是否正常工作。当代码出现问题时，无论是通过失败的测试还是其他方式发现的，都需要进行调试以弄清楚到底出了什么问题。一个良好的测试套件，定期运行，当然可以帮助调试。从失败的测试中得到的错误消息的具体信息，通过测试通过与测试失败提供的聚合信息，以及引入问题的代码更改的知识，都可以为调试提供重要线索。有时这些线索足以弄清楚出了什么问题以及如何解决，但通常需要进行额外的调试。

本章介绍了 Django 的调试支持。它概述了将在随后章节中更深入讨论的主题。具体来说，本章将：

+   列出控制调试信息收集和呈现的 Django 设置，并简要描述启用调试的影响

+   在严重代码失败的情况下运行调试时的结果

+   描述了启用调试时收集的数据库查询历史记录，并显示如何访问它

+   讨论开发服务器的功能，以帮助调试

+   描述了在生产过程中如何处理错误，当调试关闭时，以及如何确保适当地报告此类错误的信息

# Django 调试设置

Django 有许多设置，用于控制调试信息的收集和呈现。主要设置名为 DEBUG；它广泛地控制服务器是在开发模式（如果 DEBUG 为 True）还是生产模式下运行。

在开发模式下，最终用户预期是站点开发人员。因此，如果在处理请求时出现错误，则在发送到 Web 浏览器的响应中包含有关错误的具体技术信息是有用的。但在生产模式下，当用户预期只是一般站点用户时，这是没有用的。

本节描述了在开发过程中用于调试的三个 Django 设置。在生产过程中使用其他设置来控制应该报告什么错误，以及错误报告应该发送到哪里。这些额外的设置将在处理生产中的问题部分中讨论。

## 调试和 TEMPLATE_DEBUG 设置

DEBUG 是主要的调试设置。将其设置为 True 的最明显影响之一是，当 Django 在处理请求时出现严重代码问题，例如引发异常时，将生成花哨的错误页面响应。如果 TEMPLATE_DEBUG 也为 True，并且引发的异常与模板错误有关，则花哨的错误页面还将包括有关错误发生位置的信息。

这些设置的默认值都是 False，但由 manage.py startproject 创建的 settings.py 文件通过在文件顶部包含以下行来打开它们：

```py
DEBUG = True 
TEMPLATE_DEBUG = DEBUG 
```

请注意，当 DEBUG 为 False 时，将 TEMPLATE_DEBUG 设置为 True 是没有用的。如果不显示由 DEBUG 设置控制的花哨错误页面，则打开 TEMPLATE_DEBUG 时收集的额外信息将永远不会显示。同样，当 DEBUG 为 True 时，将 TEMPLATE_DEBUG 设置为 False 也没有什么用。在这种情况下，对于模板错误，花哨的调试页面将缺少有用的信息。因此，保持这些设置彼此相关是有意义的，如之前所示。

关于花哨的错误页面以及它们何时生成将在下一节中介绍。除了生成这些特殊页面之外，打开 DEBUG 还有其他一些影响。具体来说，当 DEBUG 打开时：

+   将记录发送到数据库的所有查询。记录的详细信息以及如何访问它将在随后的部分中介绍。

+   对于 MySQL 数据库后端，数据库发出的警告将转换为 Python`Exceptions`。这些 MySQL 警告可能表明存在严重问题，但警告（仅导致消息打印到`stderr`）可能会被忽略。由于大多数开发都是在打开`DEBUG`的情况下进行的，因此对 MySQL 警告引发异常可以确保开发人员意识到可能存在的问题。我们在第三章中遇到了这种行为，*测试 1、2、3：基本单元测试*，当我们看到`testClosesReset`单元测试根据`DEBUG`设置和 MySQL 服务器配置的不同而产生不同的结果时。

+   管理应用程序对所有注册模型的配置进行了广泛的验证，并且在发现配置中存在错误时，在首次尝试访问任何管理页面时引发`ImproperlyConfigured`异常。这种广泛的验证相当昂贵，通常不希望在生产服务器启动期间进行，因为管理配置可能自上次启动以来没有更改。但是，在打开`DEBUG`的情况下，可能会发生管理配置的更改，因此进行显式验证并提供有关检测到问题的具体错误消息是有用且值得成本的。

+   最后，在 Django 代码中有几个地方，当`DEBUG`打开时会发生错误，并且生成的响应将包含有关错误原因的特定信息，而当`DEBUG`关闭时，生成的响应将是一个通用错误页面。

## TEMPLATE_STRING_IF_INVALID 设置

在开发过程中进行调试时可能有用的第三个设置是`TEMPLATE_STRING_IF_INVALID`。此设置的默认值为空字符串。此设置用于控制在模板中插入无效引用（例如，在模板上下文中不存在的引用）的位置。将空字符串的默认值设置为结果中没有任何可见的东西代替这些无效引用，这可能使它们难以注意到。将`TEMPLATE_STRING_IF_INVALID`设置为某个值可以使跟踪此类无效引用更容易。

然而，Django 附带的一些代码（特别是管理应用程序）依赖于无效引用的默认行为被替换为空字符串。使用非空的`TEMPLATE_STRING_IF_INVALID`设置运行此类代码可能会产生意外结果，因此此设置仅在您明确尝试跟踪诸如代码中始终确保变量（即使是空变量）在模板上下文中设置的拼写错误模板变量之类的内容时才有用。

# 调试错误页面

使用`DEBUG`，Django 在两种情况下生成漂亮的调试错误页面：

+   当引发`django.http.Http404`异常时

+   当引发任何其他异常并且未被常规视图处理代码处理时

在后一种情况下，调试页面包含大量关于错误、引发错误的请求以及发生错误时的环境的信息。解密此页面并充分利用其呈现的信息将在下一章中介绍。`Http404`异常的调试页面要简单得多，将在此处介绍。

查看`Http404`调试页面的示例，请考虑第四章中的`survey_detail`视图：

```py
def survey_detail(request, pk): 
    survey = get_object_or_404(Survey, pk=pk) 
    today = datetime.date.today() 
    if survey.closes < today: 
        return display_completed_survey(request, survey) 
    elif survey.opens > today: 
        raise Http404 
    else: 
        return display_active_survey(request, survey) 
```

此视图可能引发`Http404`异常的两种情况：当在数据库中找不到请求的调查时，以及当找到但尚未打开时。因此，我们可以通过尝试访问不存在的调查的调查详细信息，比如调查编号 24，来查看调试 404 页面。结果将如下所示：

![调试错误页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_06_01.jpg)

请注意页面中间有一条消息，描述了页面未找到响应的原因：**没有符合给定查询的调查**。这条消息是由`get_object_or_404`函数自动生成的。相比之下，在找到调查但尚未开放的情况下，裸露的`raise Http404`看起来不会有任何描述性消息。为了确认这一点，添加一个将来有开放日期的调查，并尝试访问其详细页面。结果将类似于以下内容：

![调试错误页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_06_02.jpg)

这不是一个非常有用的调试页面，因为它缺乏关于搜索内容和为什么无法显示的任何信息。为了使此页面更有用，在引发`Http404`异常时包含一条消息。例如：

```py
        raise Http404("%s does not open until %s; it is only %s" %  
            (survey.title, survey.opens, today)) 
```

然后尝试访问此页面将会更有帮助：

![调试错误页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_06_03.jpg)

请注意，`Http404`异常附带的错误消息只会显示在调试 404 页面上；它不会出现在标准的 404 页面上。因此，您可以尽量使这些消息描述性，而不必担心它们会向普通用户泄露私人或敏感信息。

还要注意的一点是，只有在引发`Http404`异常时才会生成调试 404 页面。如果您手动构造带有 404 状态代码的`HttpResponse`，它将被返回，而不是调试 404 页面。考虑以下代码：

```py
      return HttpResponse("%s does not open until %s; it is only %s" %
          (survey.title, survey.opens, today), status=404) 
```

如果使用这段代码来替代`raise Http404`变体，那么浏览器将简单地显示传递的消息：

![调试错误页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_06_04.jpg)

没有显著的**页面未找到**消息和独特的错误页面格式，这个页面甚至不明显是一个错误报告。还要注意，一些浏览器默认会用所谓的“友好”错误页面替换服务器提供的内容，这些页面往往更加缺乏信息。因此，使用`Http404`异常而不是手动构建带有状态码 404 的`HttpResponse`对象既更容易又更有用。

调试 404 页面的最后一个示例非常有用，当 URL 解析失败时会生成。例如，如果我们在 URL 中的调查号之前添加了额外的空格，生成的调试 404 页面将如下所示：

![调试错误页面](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_06_05.jpg)

此页面上的消息包括了解析 URL 失败的所有必要信息。它包括当前 URL，用于解析的基本`URLConf`的名称，以及按顺序尝试匹配的所有模式。

如果您进行了大量的 Django 应用程序编程，很可能会在某个时候看到此页面，并且会相信其中列出的模式之一应该匹配给定的 URL。你错了。不要浪费精力试图弄清楚 Django 怎么会出现这样的问题。相反，相信错误消息，并集中精力弄清楚为什么你认为应该匹配的模式实际上并没有匹配。仔细查看模式的每个元素，并将其与当前 URL 中的实际元素进行比较：总会有一些不匹配的地方。

在这种情况下，您可能会认为第三个列出的模式应该与当前 URL 匹配。模式中的第一个元素是主键值的捕获，而实际的 URL 值确实包含可能是主键的数字。然而，捕获是使用模式**\d+**完成的。尝试将其与实际 URL 字符匹配——一个空格后跟着**2**——失败了，因为**\d**只匹配数字字符，而空格字符不是数字字符。总会有类似这样的东西来解释为什么 URL 解析失败。

下一章将包括更多导致调试页面的常见错误示例，并深入了解这些页面上提供的所有信息。现在，我们将离开调试页面的主题，学习在`DEBUG`打开时维护的数据库查询历史的访问。

# 数据库查询历史

当`DEBUG`为`True`时，Django 会保留发送到数据库的所有 SQL 命令的历史记录。这个历史记录保存在名为`queries`的列表中，位于`django.db.connection`模块中。查看此列表中保存的内容最简单的方法是从 shell 会话中检查它。

```py
>>> from django.db import connection 
>>> connection.queries 
[] 
>>> from survey.models import Survey 
>>> Survey.objects.count() 
2 
>>> connection.queries 
[{'time': '0.002', 'sql': u'SELECT COUNT(*) FROM "survey_survey"'}] 
>>> 

```

在这里，我们看到`queries`在 shell 会话开始时最初是空的。然后，我们检索数据库中`Survey`对象的数量，结果为**2**。当我们再次显示`queries`的内容时，我们看到`queries`列表中现在有一个查询。列表中的每个元素都是一个包含两个键的字典：`time`和`sql`。`time`的值是查询执行所需的时间（以秒为单位）。`sql`的值是实际发送到数据库的 SQL 查询。

关于`connection.queries`中包含的 SQL 的一件事：它不包括查询参数的引用。例如，考虑对以`Christmas`开头的`Surveys`进行查询时显示的 SQL：

```py
>>> Survey.objects.filter(title__startswith='Christmas') 
[<Survey: Christmas Wish List (opens 2009-11-26, closes 2009-12-31)>] 
>>> print connection.queries[-1]['sql'] 
SELECT "survey_survey"."id", "survey_survey"."title", "survey_survey"."opens", "survey_survey"."closes" FROM "survey_survey" WHERE "survey_survey"."title" LIKE Christmas% ESCAPE '\'  LIMIT 21 
>>>

```

在显示的 SQL 中，`Christmas％`需要引用才能使 SQL 有效。然而，在存储在`connection.queries`中时，我们看到它没有被引用。原因是 Django 实际上并没有以这种形式将查询传递给数据库后端。相反，Django 传递参数化查询。也就是说，传递的查询字符串包含参数占位符，并且参数值是分开传递的。然后，由数据库后端执行参数替换和适当的引用。

对于放置在`connection.queries`中的调试信息，Django 进行参数替换，但不尝试进行引用，因为这取决于后端。因此，不要担心`connection.queries`中缺少参数引用：这并不意味着参数在实际发送到数据库时没有正确引用。但是，这意味着`connection.queries`中的 SQL 不能直接成功地剪切和粘贴到数据库 shell 程序中。如果要在数据库 shell 中使用`connection.queries`中的 SQL 形式，您需要提供缺失的参数引用。

你可能已经注意到并且可能对前面的 SQL 中包含的`LIMIT 21`感到好奇。所请求的`QuerySet`没有包括限制，那么为什么 SQL 包括了限制呢？这是`QuerySet repr`方法的一个特性，这是 Python shell 调用来显示`Survey.objects.filter`调用返回的值。

`QuerySet`可能有许多元素，如果非常大，则在 Python shell 会话中显示整个集合并不特别有用。因此，`QuerySet repr`最多显示 20 个项目。如果有更多，`repr`将在末尾添加省略号，以指示显示不完整。因此，对`QuerySet`进行`repr`调用的结果的 SQL 将限制结果为 21 个项目，这足以确定是否需要省略号来指示打印的结果是不完整的。

每当您在数据库查询中看到包含`LIMIT 21`，这表明该查询很可能是对`repr`的调用的结果。由于应用程序代码不经常调用`repr`，因此这样的查询很可能是由其他代码（例如 Python shell，或图形调试器变量显示窗口）导致的，这些代码可能会自动显示`QuerySet`变量的值。牢记这一点可以帮助减少在尝试弄清楚为什么某些查询出现在`connection.queries`中时的困惑。

关于`connection.queries`还有一件事要注意：尽管名字是这样，它不仅限于 SQL 查询。所有发送到数据库的 SQL 语句，包括更新和插入，都存储在`connection.queries`中。例如，如果我们从 shell 会话中创建一个新的`Survey`，我们将看到生成的 SQL INSERT 存储在`connection.queries`中。

```py
>>> import datetime
>>> Survey.objects.create(title='Football Favorites',opens=datetime.date.today()) 
<Survey: Football Favorites (opens 2009-09-24, closes 2009-10-01)> 
>>> print connection.queries[-1]['sql'] 
INSERT INTO "survey_survey" ("title", "opens", "closes") VALUES (Football Favorites, 2009-09-24, 2009-10-01) 
>>> 

```

在这里，我们一直在从 shell 会话中访问`connection.queries`。然而，通常在请求处理后查看它的内容可能是有用的。也就是说，我们可能想知道在创建页面期间生成了什么数据库流量。然而，在 Python shell 中重新创建视图函数的调用，然后手动检查`connection.queries`并不特别方便。因此，Django 提供了一个上下文处理器`django.core.contextprocessors.debug`，它提供了方便的访问从模板中存储在`connection.queries`中的数据。在第八章*问题隐藏时：获取更多信息*中，我们将看到如何使用这个上下文处理器将`connection.queries`中的信息包含在我们生成的页面中。

# 开发服务器中的调试支持

我们一直在使用的开发服务器自第三章以来，具有几个特点有助于调试。首先，它提供了一个控制台，允许在开发过程中轻松报告 Django 应用程序代码的情况。开发服务器本身向控制台报告其操作的一般信息。例如，开发服务器的典型输出如下：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py runserver 
Validating models... 
0 errors found 

Django version 1.1, using settings 'marketr.settings' 
Development server is running at http://127.0.0.1:8000/ 
Quit the server with CONTROL-C. 
[25/Sep/2009 07:51:24] "GET / HTTP/1.1" 200 480 
[25/Sep/2009 07:51:27] "GET /survey/1/ HTTP/1.1" 200 280 
[25/Sep/2009 07:51:33] "GET /survey/888/ HTTP/1.1" 404 1704 

```

正如你所看到的，开发服务器首先通过显式验证模型来启动。如果发现任何错误，它们将在服务器启动期间得到突出报告，并且将阻止服务器进入请求处理循环。这有助于确保在开发过程中发现任何错误的模型更改。

服务器然后报告正在运行的 Django 的级别，使用的设置文件，以及它正在侦听的主机地址和端口。其中的第一个在你安装了多个 Django 版本并在它们之间切换时非常有用。例如，如果你在`site-packages`中安装了最新版本，但也有一个当前主干的 SVN 检出，你可以通过开发服务器报告的版本来确认（或不确认）你当前使用的版本是否是你打算使用的版本。

最后的启动消息指出，你可以通过按*Ctrl-C*来终止服务器。然后服务器进入请求处理循环，并将继续报告它处理的每个请求的信息。对于每个请求打印的信息是：

+   请求被处理的日期和时间，用方括号括起来

+   请求本身，其中包括 HTTP 方法（例如 GET 或 POST）、路径和客户端指定的 HTTP 版本，全部用引号括起来

+   返回的 HTTP 状态代码

+   返回响应中的字节数

在前面的示例输出中，我们可以看到服务器已经响应了三个`GET`请求，所有请求都指定了`1.1`的 HTTP 版本。首先是根 URL`/`，导致 HTTP`200`（OK）状态代码和`480`字节的响应。对`/survey/1/`的请求也被成功处理，并产生了`280`字节的响应，但`/survey/888/`导致了`404`的 HTTP 状态和`1704`字节的响应。返回`404`状态是因为数据库中不存在主键为`888`的调查。能够看到开发服务器实际接收到了什么请求，以及返回了什么响应，通常非常有用。

开发服务器处理的一些请求不会显示在控制台上。首先，不会记录对管理员媒体文件（即 CSS、JavaScript 和图像）的请求。如果查看管理员页面的 HTML 源代码，你会看到它在`<head>`部分包含了 CSS 文件的链接。例如：

```py
<head> 
<title>Site administration | Django site admin</title> 
<link rel="stylesheet" type="text/css" href="/media/css/base.css" /> 
<link rel="stylesheet" type="text/css" href="/media/css/dashboard.css" /> 
```

接收此文档的 Web 浏览器将继续从生成原始页面的同一服务器检索`/media/css/base.css`和`/media/css/dashboard.css`。开发服务器将接收并自动提供这些文件，但不会记录这一活动。具体来说，它将提供但不记录以`ADMIN_MEDIA_PREFIX`设置开头的 URL 的请求。（此设置的默认值为`/media/`）。

开发服务器不会记录的第二个请求是对`/favicon.ico`的任何请求。这是许多 Web 浏览器自动请求的文件，以便将图标与书签页面关联，或在地址栏中显示图标。没有必要用这个文件的请求来混淆开发服务器的输出，因此它永远不会被记录。

通常在调试问题时，开发服务器自动记录的非常基本的信息可能不足以弄清楚发生了什么。当发生这种情况时，你可以向应用程序代码添加日志。假设你将添加的日志输出路由到`stdout`或`stderr`，它将与开发服务器的正常输出一起显示在控制台上。

请注意，一些生产部署环境不允许将输出发送到`stdout`。在这种环境中，应用程序代码中错误地留下的调试打印语句可能会导致生产中的服务器故障。为了避免这种情况，始终将调试打印语句路由到`stderr`而不是`stdout`。

还要注意的是，开发服务器进行的请求日志记录发生在请求处理的最后。记录的信息包括响应的大小，因此在此行出现之前，响应已经完全生成。因此，例如在应用程序视图函数中添加的任何日志都会出现在开发服务器记录的单行之前。不要混淆并认为视图函数中的打印是指上面记录的请求服务所做的工作。有关向应用程序代码添加日志的更多详细信息将在第八章中讨论。

开发服务器的第二个功能是在开发和调试代码时非常有用的，它会自动注意到磁盘上的源代码更改并重新启动，以便始终运行当前的代码。当它重新启动时，会再次打印启动消息，你可以从中得知发生了什么。例如，考虑以下输出：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py runserver 
Validating models... 
0 errors found 

Django version 1.1, using settings 'marketr.settings' 
Development server is running at http://127.0.0.1:8000/ 
Quit the server with CONTROL-C. 
[25/Sep/2009 07:51:24] "GET / HTTP/1.1" 200 480 
[25/Sep/2009 07:51:27] "GET /survey/1/ HTTP/1.1" 200 280 
[25/Sep/2009 07:51:33] "GET /survey/888/ HTTP/1.1" 404 1704 
Validating models... 
0 errors found 

Django version 1.1, using settings 'marketr.settings' 
Development server is running at http://127.0.0.1:8000/ 
Quit the server with CONTROL-C. 
[25/Sep/2009 08:20:15] "GET /admin/ HTTP/1.1" 200 7256 

```

在这里进行了一些代码更改，导致开发服务器在处理**GET /survey/888/**和**GET /admin/**请求之间重新启动。

虽然这种自动重新启动行为很方便，但有时也会遇到问题。这种情况最常发生在编辑并保存带有错误的代码时。有时，但并非总是，加载错误的文件会导致开发服务器无法注意到文件的后续更改。因此，即使错误被注意到并修复，修正版本也可能不会自动加载。如果看起来开发服务器没有在应该的时候重新加载，最好手动停止并重新启动它。

开发服务器的这种自动重新加载功能可以通过向`runserver`传递`--noreload`选项来关闭。当单独运行开发服务器时，您可能不经常想要指定这一点，但是如果您在调试器下运行它，您可能需要指定这个选项，以便调试器断点能够被正确识别。这是开发服务器的最后一个使其用于调试的特性：很容易在调试器下运行。关于这一点将在第九章中进行详细介绍，*当你甚至不知道要记录什么时：使用调试器*。

# 处理生产中的问题

在理想的世界中，所有的代码问题都会在开发过程中被发现，并且在代码运行在生产模式时永远不会出错。然而，尽管尽最大努力，这种理想在现实中很少实现。我们必须为代码在生产模式下运行时出现严重问题的情况做好准备，并在发生时安排做一些明智的事情。

做一些明智的事情需要考虑什么？首先，仍然需要向发送引发错误请求的客户端返回一些响应。但是响应应该只是一个一般的错误指示，不包含在`DEBUG`激活时生成的复杂调试错误页面中找到的具体内部细节。在最好的情况下，Django 调试错误页面可能会让一般的网络用户感到困惑，但在最坏的情况下，从中获取的信息可能会被一些恶意用户用来尝试破坏网站。因此，对于引发错误的请求产生的公共响应应该是一个通用的错误页面。

这些错误的具体细节仍然应该提供给网站管理员，以便分析和修复问题。Django 通过将`DEBUG`设置为`False`时遇到的错误详细信息发送到`settings.py`中指定的电子邮件地址列表来实现这一点。电子邮件中包含的信息并不像调试页面上所找到的那样详尽，但通常足以开始重新创建和修复问题。

本节讨论了处理生产过程中遇到的错误所需的步骤。首先，描述了返回通用错误页面所需的操作，然后讨论了指定发送更详细错误信息的设置。

## 创建通用错误页面

与复杂的错误页面一样，通用错误页面有两种类型：一种是报告网站上不存在页面的情况，另一种是报告在处理请求时发生了一些内部服务器错误。Django 为这些错误情况提供了默认处理程序，自动加载和呈现名为`404.html`和`500.html`的模板。依赖于这些错误的默认处理的项目必须提供这些名称的模板以供加载和呈现。`manage.py startproject`不会创建这些文件的默认值。

当呈现`404.html`模板时，它会传递一个`RequestContext`，其中一个名为`request_path`的变量被设置为引发`Http404`异常的 URL 路径的值。然后，`404.html`模板可以使用`request_path`值和上下文处理器设置的其他变量来定制生成的特定响应。

另一方面，`500.html`模板是使用空上下文呈现的。当发生内部服务器错误时，服务器代码出现了严重问题。尝试通过上下文处理器处理`RequestContext`可能会导致另一个异常被引发。为了确保响应能够在没有进一步错误的情况下生成，`500.html`模板是使用空上下文呈现的。这意味着`500.html`模板不能依赖于通常由上下文处理器设置的任何上下文变量。

可以通过为这两种错误情况中的任何一种或两种提供自定义错误处理程序来覆盖默认的错误处理。Django 文档提供了如何执行此操作的详细信息；这里没有涵盖，因为默认处理程序对绝大多数情况都很好。

## 报告生产错误信息

尽管最好避免向一般用户呈现详细的技术错误信息，但完全丢失这些信息也不好。Django 支持在生产中遇到错误时通知站点管理员。与这些通知相关的设置在本节中讨论。第十一章，“当是时候上线：转向生产”，提供了有关转向生产并解决沿途遇到的一些常见问题的更多指导。

### 内部服务器错误通知

当服务器发生错误时，Django 会向`ADMINS`设置中列出的所有电子邮件地址发送一封包含生成错误的请求的详细信息和错误的回溯的电子邮件。`ADMINS`是包含名称和电子邮件地址的元组列表。由`manage.py startproject`设置的值是：

```py
ADMINS = ( 
    # ('Your Name', 'your_email@domain.com'), 
) 
```

注释行显示了您应该使用的格式来向此设置添加值。

没有设置来控制是否应发送服务器错误通知：Django 将始终尝试发送这些通知。但是，如果您真的不希望为内部服务器错误生成电子邮件通知，可以将`ADMINS`设置为空。尽管这不是推荐的做法，因为除非您的用户向您抱怨，否则您将不知道您的网站是否遇到困难。

Django 使用 Python 的 SMTP 支持来发送电子邮件。为了使其工作，Django 必须正确配置以与 SMTP 服务器通信。有几个设置可以控制发送邮件，您可能需要根据您的安装进行自定义：

+   `EMAIL_HOST`是运行 SMTP 服务器的主机的名称。此设置的默认值为`localhost`，因此如果在与 Django 服务器相同的机器上没有运行 SMTP 服务器，则需要将其设置为运行 SMTP 服务器的主机，以便用于发送邮件。

+   `EMAIL_HOST_USER`和`EMAIL_HOST_PASSWORD`可以一起用于对 SMTP 服务器进行身份验证。默认情况下，两者都设置为空字符串。如果其中一个设置为空字符串，那么 Django 将不会尝试对 SMTP 服务器进行身份验证。如果您使用需要身份验证的服务器，则需要将其设置为正在使用的 SMTP 服务器的有效值。

+   `EMAIL_USE_TLS`指定是否使用安全（传输层安全）连接到 SMTP 服务器。默认值为`False`。如果您使用需要安全连接的 SMTP 服务器，则需要将其设置为`True`。

+   `EMAIL_PORT`指定要连接的端口。默认值是默认的 SMTP 端口，25。如果您的 SMTP 服务器在不同的端口上监听（当`EMAIL_USE_TLS`为`True`时很典型），则必须在此处指定。

+   `SERVER_EMAIL`是将用作发送邮件的`From`地址的电子邮件地址。默认值为`root@localhost`。一些电子邮件提供商拒绝接受使用此默认`From`地址的邮件，因此最好将其设置为电子邮件服务器的有效`From`地址。

+   `EMAIL_SUBJECT_PREFIX`是一个字符串，将放在电子邮件的`Subject`开头。默认值为`[Django]`。您可能希望将其自定义为特定于站点的内容，以便支持多个站点的管理员可以从电子邮件主题一瞥中知道哪个站点遇到了错误。

一旦您设置了您认为对于正在使用的 SMTP 服务器正确的所有值，最好验证邮件是否成功发送。为此，将`ADMINS`设置为包括您自己的电子邮件地址。然后将`DEBUG=False`，并执行会导致服务器错误的操作。实现这一点的一种简单方法是将`404.html`模板重命名为其他内容，然后尝试访问服务器指定会引发`Http404`异常的 URL。

例如，尝试访问不存在的调查详细页面或未来的开放日期。这个尝试应该会导致发送一封电子邮件给您。主题将以您服务器的`EMAIL_SUBJECT_PREFIX`开头，并包括生成错误的请求的 URL 路径。电子邮件的文本将包含错误的回溯，然后是导致错误的请求的详细信息。

### 未找到页面通知

页面未找到错误比服务器错误要轻得多。实际上，它们可能根本不表示代码中的错误，因为它们可能是用户在浏览器地址栏中错误输入地址导致的。然而，如果它们是用户尝试跟随链接的结果，您可能想知道这一点。这种情况被称为损坏的链接，通常可以通过请求中的 HTTP `Referer` [sic]标头来区分开第一种情况。Django 支持在检测到用户通过损坏的链接尝试访问不存在的页面时发送电子邮件通知。

与内部服务器错误通知不同，发送损坏的链接通知是可选的。控制 Django 是否发送损坏链接的电子邮件通知的设置是`SEND_BROKEN_LINK_EMAILS`。此设置的默认值为`False`；如果要 Django 生成这些电子邮件，则需要将其设置为`True`。此外，必须启用常见中间件（`django.middleware.common.CommonMiddleware`）才能发送损坏的链接电子邮件。此中间件默认启用。

此设置生成的电子邮件将发送到`MANAGERS`设置中找到的电子邮件地址。因此，您可以将这些通知发送给不同的人员组，而不是服务器错误电子邮件。但是，如果您希望将这些发送给接收服务器错误电子邮件的相同人员组，只需在`settings.py`中的`ADMINS`设置后设置`MANAGERS = ADMINS`。

除了电子邮件收件人之外，所有相同的电子邮件设置都将用于发送损坏的链接电子邮件，就像用于服务器错误电子邮件一样。因此，如果您已经验证了服务器错误电子邮件成功发送，损坏的链接电子邮件也将成功发送。

损坏的链接电子邮件通知只有在合法问题的报告没有被网页爬虫、机器人和恶意人员的活动淹没时才有用。为了确保发送的通知与有效问题相关，还有一些额外的设置可以用来限制报告为损坏链接的 URL 路径。这些是`IGNORABLE_404_STARTS`和`IGNORABLE_404_ENDS`。只有不以`IGNORABLE_404_STARTS`开头且不以`IGNORABLE_404_ENDS`结尾的请求页面才会发送损坏的链接电子邮件。

`IGNORABLE_404_STARTS`的默认值是：

```py
('/cgi-bin/', '/_vti_bin', '/_vti_inf')
```

`IGNORABLE_404_ENDS`的默认值是：

```py
('mail.pl', 'mailform.pl', 'mail.cgi', 'mailform.cgi', 'favicon.ico', '.php')
```

您可以根据需要添加这些内容，以确保为损坏的链接生成的电子邮件报告实际问题。

# 总结

我们现在已经完成了 Django 中的调试支持概述。在本章中，介绍了许多主题，这些主题将在后续章节中得到更深入的介绍。具体来说，我们有：

+   学习了关于 Django 设置的知识，这些设置控制了调试信息的收集和展示

+   看到了当调试打开时，会生成特殊的错误页面，这有助于调试问题的任务。

+   了解了在调试打开时维护的数据库查询历史，并看到如何访问它

+   讨论了开发服务器的几个特性，在调试时非常有帮助

+   描述了在生产环境中如何处理错误，以及与确保有用的调试信息发送到正确人员相关的设置

下一章将继续深入探讨 Django 调试页面的细节。
