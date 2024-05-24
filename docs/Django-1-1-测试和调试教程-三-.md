# Django 1.1 测试和调试教程（三）

> 原文：[`zh.annas-archive.org/md5/ECB5EEA8F49C43CEEB591D269760F77D`](https://zh.annas-archive.org/md5/ECB5EEA8F49C43CEEB591D269760F77D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：当车轮脱落：理解 Django 调试页面

当您的代码在生产中运行时，您最不希望发生的事情之一就是遇到一个错误，这个错误严重到只能向客户端返回“对不起，服务器遇到了一个错误，请稍后再试”的消息。然而，在开发过程中，这些服务器错误情况是最糟糕的结果之一。它们通常表示已经引发了异常，当发生这种情况时，有大量信息可用于弄清楚出了什么问题。当`DEBUG`打开时，这些信息以 Django 调试页面的形式返回，作为导致错误的请求的响应。在本章中，我们将学习如何理解和利用 Django 调试页面提供的信息。

具体来说，在本章中我们将：

+   继续开发示例调查应用程序，沿途犯一些典型的错误

+   看看这些错误如何在 Django 调试页面的形式中表现出来

+   了解这些调试页面提供了哪些信息

+   对于每个错误，深入研究生成的调试页面上可用的信息，看看它如何被用来理解错误并确定如何修复它

# 开始调查投票实施

在第四章中，*变得更加花哨：Django 单元测试扩展*，我们开始开发代码为`survey`应用程序提供页面。我们实现了主页视图。这个视图生成一个页面，列出了活动和最近关闭的调查，并根据需要提供链接，以便参加活动调查或显示关闭调查的结果。这两种链接都路由到同一个视图函数`survey_detail`，该函数根据所请求的`Survey`的状态进一步路由请求：

```py
def survey_detail(request, pk): 
    survey = get_object_or_404(Survey, pk=pk) 
    today = datetime.date.today() 
    if survey.closes < today: 
        return display_completed_survey(request, survey) 
    elif survey.opens > today: 
        raise Http404("%s does not open until %s; it is only %s" %
            (survey.title, survey.opens, today))
    else: 
        return display_active_survey(request, survey) 
```

然而，我们并没有编写代码来实际显示一个活动的`Survey`或显示`Survey`的结果。相反，我们创建了占位符视图和模板，只是简单地说明了这些页面最终打算显示的内容。例如，`display_active_survey`函数仅保留为：

```py
def display_active_survey(request, survey): 
    return render_to_response('survey/active_survey.html', {'survey': survey}) 
```

它引用的模板`active_survey.html`包含：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>Survey questions for {{ survey.title }}</h1> 
{% endblock content %} 
```

我们现在将从上次离开的地方继续，并开始用处理显示活动“调查”的真实代码替换这个占位符视图和模板。

这需要什么？首先，当请求显示一个活动调查时，我们希望返回一个页面，显示`Survey`中的问题列表，每个问题都有其相关的可能答案。此外，我们希望以一种方式呈现这些问题和答案数据，以便用户可以参与`Survey`，并提交他们选择的问题答案。因此，我们需要以 HTML 表单的形式呈现问题和答案数据，并且还需要在服务器上编写代码，处理接收、验证、记录和响应发布的`Survey`响应。

这一切一次性解决起来很多。我们可以先实现哪个最小的部分，以便我们开始实验并验证我们是否朝着正确的方向前进？我们将从显示一个允许用户查看单个问题并从其相关答案中选择的表单开始。不过，首先让我们在开发数据库中设置一些合理的测试数据来使用。

## 为投票创建测试数据

由于我们已经有一段时间没有使用这些模型了，我们可能不再有任何活动调查。让我们通过运行`manage.py reset survey`来从头开始。然后，确保开发服务器正在运行，并使用管理应用程序创建一个新的`Survey`，`Question`和`Answers`。这是即将到来的示例中将使用的`Survey`：

![为投票创建测试数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_01.jpg)

为这个`Survey`中的一个`Question`定义的`Answers`是：

![为投票创建测试数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_02.jpg)

这就足够开始了。我们可以随后返回并根据需要添加更多数据。现在，我们将继续开发用于显示一个`Question`并选择其答案的表单。

## 为投票定义问题表单

Django 的`forms`包提供了一个方便的框架，用于创建、显示、验证和处理 HTML 表单数据。在 forms 包中，`ModelForm`类通常用于自动构建代表模型的表单。我们可能最初认为使用`ModelForm`会对我们的任务有所帮助，但`ModelForm`不会提供我们所需要的。回想一下，`survey`应用程序`Question`模型包含这些字段：

```py
class Question(models.Model): 
    question = models.CharField(max_length=200) 
    survey = models.ForeignKey(Survey) 
```

此外，`Answer`模型是：

```py
class Answer(models.Model): 
    answer = models.CharField(max_length=200) 
    question = models.ForeignKey(Question) 
    votes = models.IntegerField(default=0) 
```

`ModelForm`包含模型中每个字段的 HTML 输入字段。因此，`Question`模型的`ModelForm`将包括一个文本输入，允许用户更改`question`字段的内容，并包括一个选择框，允许用户选择与之关联的`Survey`实例。这并不是我们想要的。从`Answer`模型构建的`ModelForm`也不是我们要找的。

相反，我们想要一个表单，它将显示`question`字段的文本（但不允许用户更改该文本），以及与`Question`实例关联的所有`Answer`实例，以一种允许用户精确选择列出的答案之一的方式。这听起来像是一个 HTML 单选输入组，其中单选按钮的值由与`Question`实例关联的`Answers`集合定义。

我们可以创建一个自定义表单来表示这一点，使用 Django 提供的基本表单字段和小部件类。让我们创建一个新文件，`survey/forms.py`，并在其中尝试实现将用于显示`Question`及其关联答案的表单：

```py
from django import forms
class QuestionVoteForm(forms.Form): 
    answer = forms.ModelChoiceField(widget=forms.RadioSelect) 

    def __init__(self, question, *args, **kwargs): 
        super(QuestionVoteForm, self).__init__(*args, **kwargs) 
        self.fields['answer'].queryset = question.answer_set.all() 
```

这个表单名为`QuestionVoteForm`，只有一个字段`answer`，它是一个`ModelChoiceField`。这种类型的字段允许从`QuerySet`定义的一组选择中进行选择，由其`queryset`属性指定。由于此字段的正确答案集将取决于构建表单的特定`Question`实例，因此我们在字段声明中省略了指定`queryset`，并在`__init__`例程中设置它。但是，我们在字段声明中指定，我们要使用`RadioSelect`小部件进行显示，而不是默认的`Select`小部件（它在 HTML 选择下拉框中呈现选择）。

在单个`answer`字段的声明之后，该表单定义了`__init__`方法的覆盖。这个`__init__`要求在创建表单实例时传入一个`question`参数。在首先使用可能提供的其他参数调用`__init__`超类之后，传递的`question`用于将`answer`字段的`queryset`属性设置为与此`Question`实例关联的答案集。

为了查看这个表单是否按预期显示，我们需要在`display_active_survey`函数中创建一个这样的表单，并将其传递给模板进行显示。现在，我们不想担心显示问题列表；我们只会选择一个传递给模板。因此，我们可以将`display_active_survey`更改为：

```py
from survey.forms import QuestionVoteForm 
def display_active_survey(request, survey): 
    qvf = QuestionVoteForm(survey.question_set.all()[0]) 
    return render_to_response('survey/active_survey.html', {'survey': survey, 'qvf': qvf}) 
```

现在，这个函数为指定调查的一组问题中的第一个问题创建了一个`QuestionVoteForm`的实例，并将该表单传递给模板以作为上下文变量`qvf`进行渲染。

我们还需要修改模板以显示传递的表单。为此，请将`active_survey.html`模板更改为：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>{{ survey.title }}</h1> 
<form method="post" action="."> 
<div> 
{{ qvf.as_p }} 
<button type="submit">Submit</button> 
</div> 
</form> 
{% endblock content %} 
```

在这里，我们已经添加了必要的 HTML 元素来包围 Django 表单，并使其成为有效的 HTML 表单。我们使用了`as_p`方法来显示表单，只是因为它很容易。长期来看，我们可能会用自定义输出来替换它，但是在目前，将表单显示在 HTML 段落元素中就足够了。

现在，我们希望能够测试并查看我们的`QuestionVoteForm`是否显示我们想要的内容。我们接下来会尝试。

## 调试页面＃1：/处的 TypeError

为了查看`QuestionVoteForm`目前的样子，我们可以先转到调查主页，然后从那里我们应该能够点击我们拥有的一个活动调查的链接，看看问题和答案选择是如何显示的。效果如何？并不好。由于我们所做的代码更改，我们甚至无法显示主页。相反，尝试访问它会产生一个调试页面：

![调试页面＃1：/处的 TypeError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_03.jpg)

天啊，看起来很糟糕。在我们深入了解页面显示的细节之前，让我们先试着理解这里发生了什么。我们添加了一个新的表单，并且更改了用于显示活动调查的视图，以便创建新定义的表单之一。我们还更改了该视图使用的模板。但我们并没有改变主页视图。那么它怎么会出错呢？

答案是主页视图本身并没有出错，但其他地方出了问题。这个出错的其他地方阻止了主页视图的调用。请注意，为了调用主页视图，包含它的模块（`survey.views`）必须被无错误地导入。因此，`survey.views`本身以及在导入时它引用的任何内容都必须是无错误的。即使主页视图中没有任何错误，甚至整个`survey.views`都没有问题，如果在导入`survey.views`的过程中引入了任何模块的错误，那么在尝试调用主页视图时可能会引发错误。

关键是，在一个地方做出的改变可能会导致最初令人惊讶的故障，而这似乎是完全无关的领域。实际上，另一个领域并不是完全无关的，而是以某种方式（通常通过一系列的导入）与做出改变的领域相连接。在这种情况下，重点放在正确的地方以找到并修复错误是很重要的。

在这种情况下，例如，盯着主页视图代码发呆是没有用的，因为那是我们试图运行的代码，试图弄清楚问题出在哪里也是徒劳的。问题并不在那里。相反，我们需要放下我们对可能在错误发生时运行的代码的任何先入为主的想法，并利用呈现的调试信息来弄清楚实际运行的代码是什么。弄清楚为什么一部分代码最终运行了，而我们本来想运行的是另一些代码，也是有益的，尽管不总是必要的来解决手头的问题。

# 调试页面的元素

现在让我们把注意力转向我们遇到的调试页面。页面上有很多信息，分成四个部分（截图中只能看到第一个部分和第二个部分的开头）。在本节中，我们重点关注调试页面的每个部分中通常包含的信息，注意我们在这个页面上看到的值只是作为示例。在本章的后面，我们将看到如何使用这个调试页面上呈现的具体信息来修复我们所犯的错误。

## 基本错误信息

调试页面的顶部包含基本的错误信息。页面标题和页面正文的第一行都说明了遇到的异常类型，以及触发异常的请求中包含的 URL 路径。在我们的情况下，异常类型是**TypeError**，URL 路径是**/**。因此，我们在页面上看到**TypeError at /**作为第一行。

第二行包含异常值。这通常是对导致错误的具体描述。在这种情况下，我们看到 __init__()至少需要 2 个非关键字参数（给定 1 个）。

在异常值之后是一个包含九个项目的列表：

+   请求方法：请求中指定的 HTTP 方法。在这种情况下，它是 GET。

+   请求 URL：请求的完整 URL。在这种情况下，它是 http://localhost:8000/。其中的路径部分是第一行报告的路径的重复。

+   异常类型：这是在第一行包括的异常类型的重复。

+   异常值：这是在第二行包括的异常值的重复。

+   异常位置：异常发生的代码行。在这种情况下，它是/dj_projects/marketr/survey/forms.py 中的 QuestionVoteForm，第 3 行。

+   Python 可执行文件：发生错误时运行的 Python 可执行文件。在这种情况下，它是/usr/bin/python。除非您正在使用不同的 Python 版本进行测试，否则这些信息通常只是有趣的。

+   Python 版本：这标识正在运行的 Python 版本。同样，除非您正在使用不同的 Python 版本进行测试，否则这通常不会引起兴趣。但是，当查看其他人报告的问题时，如果有任何怀疑问题可能取决于 Python 版本，这可能是非常有用的信息。

+   Python 路径：实际生效的完整 Python 路径。当异常类型涉及导入错误时，这通常是最有用的。当安装了不同版本的附加包时，这也可能会派上用场。这加上不正确的路径规范可能会导致使用意外的版本，这可能会导致错误。有可用的完整 Python 路径有助于跟踪这种情况下发生的情况。

+   服务器时间：这显示了异常发生时服务器的日期、时间和时区。这对于返回与时间相关的结果的任何视图都是有用的。

当出现调试页面时，异常类型、异常值和异常位置是首先要查看的三个项目。这三个项目揭示了出了什么问题，为什么以及发生了什么地方。通常，这就是您需要了解的一切，以便解决问题。但有时，仅凭这些基本信息就不足以理解和解决错误。在这种情况下，了解代码最终运行到哪里可能会有所帮助。对于这一点，调试页面的下一部分是有用的。

## 回溯

调试页面的回溯部分显示了控制线程如何到达遇到错误的地方。在顶部，它从运行以处理请求的代码的最外层级别开始，显示它调用了下一个更低级别，然后显示下一个调用是如何进行的，最终在底部以导致异常的代码行结束。因此，通常是回溯的最底部（在截图中不可见）最有趣，尽管有时代码走过的路径是理解和修复出了问题的关键。

在回溯中显示的每个调用级别，都显示了三个信息：首先标识代码行，然后显示它，然后有一行带有三角形和文本本地变量。

例如，在调试页面上回溯的顶层的第一部分信息标识了代码行为/usr/lib/python2.5/site-packages/django/core/handlers/base.py in get_response。这显示了包含代码的文件以及在该文件中执行代码的函数（或方法或类）的名称。

接下来是一个背景较暗的带有**83\. request.path_info)**的行。这看起来有点奇怪。左边的数字是文件内的行号，右边是该行的内容。在这种情况下，调用语句跨越了多行，我们只看到了调用的最后一行，这并不是很有信息量。我们只能知道**request.path_info**作为最后一个参数传递给了某个东西。看到这一行周围的其他代码行可能会更好，这样会更清楚正在调用什么。事实上，我们可以通过单击该行来做到这一点：

![Traceback](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_04.jpg)

啊哈！现在，我们可以看到有一个名为**resolver.resolve**的东西被调用并传递了**request.path_info**。显然，这个级别的代码是从请求的路径开始，并尝试确定应调用什么代码来处理当前请求。

再次单击显示的代码的任何位置将切换周围代码上下文的显示状态，使得只显示一行。通常，不需要在回溯中看到周围的代码，这就是为什么它最初是隐藏的。但是当需要查看更多内容时，只需单击一下就很方便了。

本地变量包含在每个回溯级别显示的信息的第三个块中。这些变量最初也是隐藏的，因为如果它们被显示出来，可能会占用大量空间并且使页面混乱，从而很难一眼看清控制流是什么样的。单击任何**Local vars**行会展开该块，显示该级别的本地变量列表和每个变量的值。例如：

![Traceback](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_05.jpg)

我们不需要完全理解此处运行的 Django 代码，就可以根据显示的变量的名称和值猜测，代码正在尝试查找处理显示主页的视图。再次单击**Local vars**行会将该块切换回隐藏状态。

调试页面的回溯部分还有一个非常有用的功能。在**Traceback**标题旁边有一个链接：**切换到剪切和粘贴视图**。单击该链接会将回溯显示切换为可以有用地复制和粘贴到其他地方的显示。例如，在本页上，单击该链接会产生一个包含以下内容的文本框：

```py
Environment:

Request Method: GET
Request URL: http://localhost:8000/
Django Version: 1.1
Python Version: 2.5.2
Installed Applications:
['django.contrib.auth',
 'django.contrib.contenttypes',
 'django.contrib.sessions',
 'django.contrib.sites',
 'django.contrib.admin',
 'survey',
 'django_coverage']
Installed Middleware:
('django.middleware.common.CommonMiddleware',
 'django.contrib.sessions.middleware.SessionMiddleware',
 'django.contrib.auth.middleware.AuthenticationMiddleware')

Traceback:
File "/usr/lib/python2.5/site-packages/django/core/handlers/base.py" in get_response
 83\.                     request.path_info)
File "/usr/lib/python2.5/site-packages/django/core/urlresolvers.py" in resolve
 218\.                     sub_match = pattern.resolve(new_path)
File "/usr/lib/python2.5/site-packages/django/core/urlresolvers.py" in resolve
 218\.                     sub_match = pattern.resolve(new_path)
File "/usr/lib/python2.5/site-packages/django/core/urlresolvers.py" in resolve
 125\.             return self.callback, args, kwargs
File "/usr/lib/python2.5/site-packages/django/core/urlresolvers.py" in _get_callback
 131\.             self._callback = get_callable(self._callback_str)
File "/usr/lib/python2.5/site-packages/django/utils/functional.py" in wrapper
 130\.         result = func(*args)
File "/usr/lib/python2.5/site-packages/django/core/urlresolvers.py" in get_callable
 58\.                 lookup_view = getattr(import_module(mod_name), func_name)
File "/usr/lib/python2.5/site-packages/django/utils/importlib.py" in import_module
 35\.     __import__(name)
File "/dj_projects/marketr/survey/views.py" in <module>
 24\. from survey.forms import QuestionVoteForm
File "/dj_projects/marketr/survey/forms.py" in <module>
 2\. class QuestionVoteForm(forms.Form):
File "/dj_projects/marketr/survey/forms.py" in QuestionVoteForm
 3\.     answer = forms.ModelChoiceField(widget=forms.RadioSelect)

Exception Type: TypeError at /
Exception Value: __init__() takes at least 2 non-keyword arguments (1 given)

```

正如您所看到的，这一块信息包含了基本的回溯以及从调试页面的其他部分提取的一些其他有用信息。它远不及完整调试页面上提供的信息，但通常足以在解决问题时从他人那里获得帮助。如果您发现自己无法解决问题并希望向他人寻求帮助，那么您想要向他人提供的就是这些信息，而不是调试页面的截图。

事实上，剪切和粘贴视图本身底部有一个按钮：**在公共网站上共享此回溯**。如果您按下该按钮，回溯信息的剪切和粘贴版本将被发布到[dpaste.com](http://dpaste.com)网站，并且您将被带到该网站，在那里您可以记录分配的 URL 以供参考或删除该条目。

显然，只有在您的计算机连接到互联网并且可以访问[dpaste.com](http://dpaste.com)时，此按钮才能正常工作。如果您尝试并且无法连接到该网站，您的浏览器将报告无法连接到[dpaste.com](http://dpaste.com)的错误。单击返回按钮将返回到调试页面。第十章，*当一切都失败时：寻求外部帮助*，将更详细地介绍解决棘手问题时获取额外帮助的技巧。

单击**切换到复制和粘贴视图**链接时，该链接会自动替换为另一个链接：**切换回交互视图**。因此，在回溯信息的两种形式之间切换很容易。

## 请求信息

在调试页面上的回溯信息部分之后是详细的请求信息。通常情况下，您不需要查看这个部分，但是当错误是由正在处理的请求的一些奇怪特征触发时，这个部分就非常有价值。它分为五个小节，每个小节都在下面描述。

### GET

这个部分包含了`request.GET`字典中所有键和它们的值的列表。或者，如果请求没有 GET 数据，则显示字符串**没有 GET 数据**。

### POST

这个部分包含了`request.POST`字典中所有键和它们的值的列表。或者，如果请求没有 POST 数据，则显示字符串**没有 POST 数据**。

### 文件

这个部分包含了`request.FILES`字典中所有键和它们的值的列表。请注意，这里显示的信息只是上传的文件名，而不是实际的文件数据（这可能相当大）。或者，如果请求没有上传文件数据，则显示字符串**没有文件数据**。

### Cookies

这个部分包含了浏览器发送的任何 cookie。例如，如果`contrib.sessions`应用程序在`INSTALLED_APPS`中列出，您将在这里看到它使用的`sessionid` cookie。或者，如果浏览器没有在请求中包含任何 cookie，则显示字符串**没有 cookie 数据**。

### 元数据

这个部分包含了`request.META`字典中所有键和它们的值的列表。这个字典包含了所有的 HTTP 请求头，以及与 HTTP 无关的其他变量。

例如，如果您在运行开发服务器时查看这个部分的内容，您将看到它列出了在开发服务器运行的命令提示符的环境中导出的所有环境变量。这是因为这个字典最初被设置为 Python `os.environ`字典的值，然后添加了其他值。因此，这里可能列出了很多无关紧要的信息，但是如果您需要检查 HTTP 头的值，您可以在这里找到它。

## 设置

调试页面的最后部分是错误发生时生效的所有设置的详尽列表。这是另一个您可能很少需要查看的部分，但当您需要时，将会非常有帮助。

这个部分包括两项内容：安装的应用程序和安装的中间件，它们都包含在前面提到的调试信息的剪切和粘贴版本中，因为它们在分析他人发布的问题时通常是很有帮助的。

如果您浏览调试页面的这个部分，您可能会注意到一些设置的值实际上并没有报告，而是列出了一串星号。这是一种隐藏信息的方式，不应该随意暴露给可能看到调试页面的任何用户。这种隐藏技术适用于任何设置中包含`PASSWORD`或`SECRET`字符串的设置。

请注意，这种隐藏技术仅适用于调试页面设置部分中报告的值。这并不意味着在生产站点中启用`DEBUG`是安全的。仍然有可能从调试页面中检索到敏感信息。例如，如果密码设置的值存储在本地变量中，那么当它被用于建立到数据库或邮件服务器的连接时，典型情况下会发生这种情况。如果在连接尝试期间引发异常，密码值可以从页面的回溯部分的本地变量信息中检索出来。

我们现在已经完成了调试页面上可用信息的一般描述。接下来，我们将看到如何使用我们遇到的页面上的具体信息来追踪并修复代码中的错误。

# 理解和修复 TypeError

导致我们遇到的调试页面出现问题的原因是什么？在这种情况下，基本的错误信息足以识别和修复问题。我们报告了一个**TypeError**，异常值为**__init__()至少需要 2 个非关键字参数（给出了 1 个）**。此外，导致错误的代码的位置是**/dj_projects/marketr/survey/forms.py 中的 QuestionVoteForm，第 3 行**。看看那一行，我们看到：

```py
    answer = forms.ModelChoiceField(widget=forms.RadioSelect) 
```

我们没有指定创建`ModelChoiceField`所需的所有必要参数。如果您是 Python 的新手，错误消息的具体内容可能有点令人困惑，因为代码行中没有引用任何名为`__init__`的东西，也没有传递任何非关键字参数，但错误消息却说给出了一个。其解释是，`__init__`是 Python 在创建对象时调用的方法，它和所有对象实例方法一样，自动接收一个对自身的引用作为其第一个位置参数。

因此，已经提供的一个非关键字参数是`self`。缺少什么？检查文档，我们发现`queryset`是`ModelChoiceField`的一个必需参数。我们省略了它，因为在声明字段时并不知道正确的值，而只有在创建包含该字段的表单的实例时才知道。但我们不能只是将其省略，因此我们需要在声明字段时指定`queryset`值。应该是什么？因为它将在创建表单的任何实例时立即重置，所以`None`可能会起作用。所以让我们尝试将那一行改为：

```py
    answer = forms.ModelChoiceField(widget=forms.RadioSelect, queryset=None) 
```

这样行得通吗？是的，如果我们点击浏览器重新加载页面按钮，我们现在可以得到调查首页：

![理解和修复 TypeError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_06.jpg)

同样，如果您是 Python 的新手，修复方法的有效性可能会有点令人困惑。错误消息说至少需要两个非关键字参数，但我们没有使用修复方法添加非关键字参数。错误消息似乎表明，唯一正确的修复方法可能是将`queryset`值作为非关键字参数提供：

```py
    answer = forms.ModelChoiceField(None, widget=forms.RadioSelect) 
```

显然情况并非如此，因为上面显示的替代修复方法确实有效。这样解释的原因是，消息并不是指调用者指定了多少个非关键字参数，而是指目标方法的声明中指定了多少个参数（在这种情况下是`ModelChoiceField`的`__init__`方法）。调用者可以自由地使用关键字语法传递参数，即使它们在方法声明中没有列为关键字参数，Python 解释器也会正确地将它们匹配起来。因此，第一个修复方法可以正常工作。

现在我们又让首页正常工作了，我们可以继续看看我们是否能够创建和显示我们的新`QuestionVoteForm`。要做到这一点，请点击**电视趋势**调查的链接。结果将是：

![理解和修复 TypeError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_07.jpg)

虽然不再出现调试页面很好，但这并不是我们要找的。这里有一些问题。

首先，答案列表的标题是**Answer**，但我们希望它是问题文本。这里显示的值是分配给`ModelChoiceField`的标签。任何表单字段的默认标签都是字段的名称，大写并跟着一个冒号。当我们声明`ModelChoiceField`答案时，我们没有覆盖默认值，所以显示**Answer**。修复方法是手动设置字段的`label`属性。与`queryset`属性一样，特定表单实例的正确值只有在创建表单时才知道，所以我们通过在表单的`__init__`方法中添加这一行来实现这一点：

```py
        self.fields['answer'].label = question.question 
```

其次，答案列表包括一个空的第一个选择，显示为破折号列表。这种默认行为对于选择下拉框非常有帮助，以确保用户被迫选择一个有效的值。然而，在使用单选输入组时是不必要的，因为对于单选输入，当表单显示时我们不需要任何单选按钮被初始选择。因此，我们不需要空的选择。我们可以通过在`ModelChoiceField`声明中指定`empty_label=None`来摆脱它。

第三，列出的所有选项都显示为**Answer object**，而不是实际的答案文本。默认情况下，这里显示的值是模型实例的`__unicode__`方法返回的任何内容。由于我们还没有为`Answer`模型实现`__unicode__`方法，所以我们只能看到**Answer object**。一个修复方法是在`Answer`中实现一个返回`answer`字段值的`__unicode__`方法：

```py
class Answer(models.Model): 
    answer = models.CharField(max_length=200) 
    question = models.ForeignKey(Question) 
    votes = models.IntegerField(default=0) 

    def __unicode__(self): 
        return self.answer 
```

请注意，如果我们希望`Answer`模型的`__unicode__`方法返回其他内容，我们也可以适应。要做到这一点，我们可以对`ModelChoiceField`进行子类化，并提供`label_from_instance`方法的覆盖。这是用于在列表中显示选择值的方法，默认实现使用实例的文本表示。因此，如果我们需要在选择列表中显示除模型的默认文本表示之外的其他内容，我们可以采取这种方法，但对于我们的目的，只需让`Answer`模型的`__unicode__`方法返回答案文本即可。

第四，答案选择显示为无序列表，并且该列表显示为带有项目符号，这有点丑陋。有各种方法可以解决这个问题，可以通过添加 CSS 样式规范或更改选择列表的呈现方式来解决。然而，项目符号并不是一个功能性问题，去掉它们并不能进一步帮助我们了解 Django 调试页面的任务，所以现在我们将让它们存在。

先前对`QuestionVoteForm`所做的修复，导致代码现在看起来像这样：

```py
class QuestionVoteForm(forms.Form): 
    answer = forms.ModelChoiceField(widget=forms.RadioSelect, queryset=None, empty_label=None) 

    def __init__(self, question, *args, **kwargs): 
        super(QuestionVoteForm, self).__init__(*args, **kwargs) 
        self.fields['answer'].queryset = question.answer_set.all() 
        self.fields['answer'].label = question.question 
```

有了这个表单，并在 Answer 模型中实现了`__unicode__`方法，重新加载我们的调查详情页面会产生一个看起来更好的结果：

![理解和修复 TypeError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_08.jpg)

现在我们有一个显示得相当好的表单，并准备继续实施调查投票的下一步。

# 处理多个调查问题

我们已经让单个问题表单的显示工作了，还剩下什么要做？首先，我们需要处理与调查相关的任意数量的问题的显示，而不仅仅是一个单独的问题。其次，我们需要处理接收、验证和处理结果。在本节中，我们将专注于第一个任务。

## 创建多个问题的数据

在编写处理多个问题的代码之前，让我们在我们的测试调查中添加另一个问题，这样我们就能看到新代码的运行情况。接下来的示例将显示这个额外的问题：

![创建多个问题的数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_09.jpg)

## 支持多个问题的编码

接下来，更改视图以创建`QuestionVoteForms`的列表，并将此列表传递到模板上下文中：

```py
def display_active_survey(request, survey): 
    qforms = [] 
    for i, q in enumerate(survey.question_set.all()): 
        if q.answer_set.count() > 1: 
            qforms.append(QuestionVoteForm(q, prefix=i)) 
    return render_to_response('survey/active_survey.html', {'survey': survey, 'qforms': qforms})
```

我们从一个名为`qforms`的空列表开始。然后，我们循环遍历与传递的`survey`相关联的所有问题，并为每个具有多个答案的问题创建一个表单。（具有少于两个答案的`Question`可能是设置错误。由于最好避免向一般用户呈现他们实际上无法选择答案的问题，我们选择在活动`Survey`的显示中略过这样的问题。）

请注意，我们在表单创建时添加了传递`prefix`参数，并将值设置为调查的全部问题集中当前问题的位置。这为每个表单实例提供了一个唯一的`prefix`值。如果表单中存在`prefix`值，则在生成 HTML 表单元素的`id`和`name`属性时将使用它。指定唯一的`prefix`是必要的，以确保在页面上存在相同类型的多个表单时生成的 HTML 是有效的，就像我们在这里实现的情况一样。

最后，每个创建的`QuestionVoteForm`都被附加到`qforms`列表中，并且在函数结束时，`qforms`列表被传递到上下文中以在模板中呈现。

因此，最后一步是更改模板以支持显示多个问题而不仅仅是一个。为此，我们可以像这样更改`active_survey.html`模板：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>{{ survey.title }}</h1> 
<form method="post" action="."> 
<div> 
{% for qform in qforms %} 
    {{ qform.as_p }} 
<button type="submit">Submit</button> 
</div> 
</form> 
{% endblock content %} 
```

与上一个版本唯一的变化是用循环遍历`qforms`上下文变量中的表单列表的`{% for %}`块替换了显示单个表单的`{{ qvf.as_p }}`。每个表单依次显示，仍然使用`as_p`便利方法。

## 调试页面＃2：TemplateSyntaxError at /1/

这样做效果如何？效果不太好。如果我们尝试重新加载显示此调查问题的页面，我们将看到：

![调试页面＃2：TemplateSyntaxError at /1/](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_10.jpg)

我们犯了一个错误，并触发了一个略有不同的调试页面。我们看到一个**模板错误**部分，而不是基本的异常信息后面紧接着回溯部分。对于`TemplateSyntaxError`类型的异常，当`TEMPLATE_DEBUG`为`True`时，将包括此部分。它显示了导致异常的模板的一些上下文，并突出显示了被识别为导致错误的行。通常对于`TemplateSyntaxError`，问题是在模板本身中找到的，而不是尝试呈现模板的代码（这将是回溯部分显示的内容），因此调试页面突出显示模板内容是有帮助的。

## 理解和修复 TemplateSyntaxError

在这种情况下，被识别为导致错误的行可能有些令人困惑。`{% endblock content %}`行自上一个工作版本的模板以来并没有改变；它肯定不是一个无效的块标签。为什么模板引擎现在报告它是无效的？答案是，模板语法错误，就像许多编程语言中报告的语法错误一样，有时在试图指出错误位置时会产生误导。被识别为错误的点实际上是在识别错误时，而实际上错误可能发生得更早一些。

当漏掉了某些必需的内容时，经常会发生这种误导性的识别。解析器继续处理输入，但最终达到了当前状态下不允许的内容。此时，应该有缺失部分的地方可能相距几行。这就是这里发生的情况。`{% endblock content %}`被报告为无效，因为在模板中仍然有一个未关闭的`{% for %}`标签。

在为支持多个问题进行模板更改时，我们添加了一个`{% for %}`标签，但忽略了关闭它。Django 模板语言不是 Python，它不认为缩进很重要。因此，它不认为`{% for %}`块是通过返回到先前的缩进级别终止的。相反，我们必须使用`{% endfor %}`显式关闭新的`{% for %}`块：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>{{ survey.title }}</h1> 
<form method="post" action="."> 
<div> 
{% for qform in qforms %} 
    {{ qform.as_p }} 
{% endfor %} 
<button type="submit">Submit</button> 
</div> 
</form> 
{% endblock content %} 
```

一旦我们做出了这个改变，我们可以重新加载页面，看到我们现在在页面上显示了多个问题：

![理解和修复 TemplateSyntaxError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_11.jpg)

随着多个问题的显示，我们可以继续添加处理提交的回答的代码。

# 记录调查回答

我们已经有测试数据可以用来练习处理调查回答，因此我们不需要为下一步向开发数据库添加任何数据。此外，模板不需要更改以支持提交回答。它已经在 HTML 表单中包含了一个提交按钮，并指定在提交表单时应将表单数据提交为 HTTP POST。现在**提交**按钮将起作用，因为它可以被按下而不会出现错误，但唯一的结果是页面被重新显示。这是因为视图代码不尝试区分 GET 和 POST，并且将所有请求都视为 GET 请求。因此，我们需要更改视图代码以添加对处理 POST 请求和 GET 请求的支持。

## 记录调查回答的编码支持

然后，视图代码需要更改以检查请求中指定的方法。处理 GET 请求的方式应该保持不变。然而，如果请求是 POST，那么应该使用提交的 POST 数据构建`QuestionVoteForms`。然后可以对其进行验证，如果所有的回答都是有效的（在这种情况下，这意味着用户为每个问题选择了一个选项），那么可以记录投票并向用户发送适当的响应。如果有任何验证错误，构建的表单应该重新显示带有错误消息。这方面的初始实现如下：

```py
def display_active_survey(request, survey): 
    if request.method == 'POST': 
        data = request.POST 
    else: 
        data = None 

    qforms = []
    for i, q in enumerate(survey.question_set.all()): 
        if q.answer_set.count() > 1: 
            qforms.append(QuestionVoteForm(q, prefix=i, data=data)) 

    if request.method == 'POST': 
        chosen_answers = [] 
        for qf in qforms: 
            if not qf.is_valid(): 
                break; 
            chosen_answers.append(qf.cleaned_data['answer']) 
        else: 
            from django.http import HttpResponse
            response = "" 
            for answer in chosen_answers: 
                answer.votes += 1 
                response += "Votes for %s is now %d<br/>" % (answer.answer, answer.votes) 
                answer.save() 
            return HttpResponse(response) 

    return render_to_response('survey/active_survey.html', {'survey': survey, 'qforms': qforms})
```

在这里，我们首先将本地变量`data`设置为`request.POST`字典，如果请求方法是`POST`，或者为`None`。我们将在表单构建过程中使用它，并且它必须是`None`（而不是空字典），以便创建未绑定的表单，这是用户在获取页面时所需的。

然后像以前一样构建`qforms`列表。这里唯一的区别是我们传入`data`参数，以便在请求为 POST 时将创建的表单绑定到已发布的数据。将数据绑定到表单允许我们稍后检查提交的数据是否有效。

然后我们有一段新的代码块来处理请求为 POST 的情况。我们创建一个空列表来保存选择的答案，然后循环遍历表单，检查每个表单是否有效。如果有任何无效的表单，我们立即跳出`for`循环。这将导致跳过与循环相关联的`else`子句（因为只有在`for`循环中的项目列表耗尽时才执行）。因此，一旦遇到无效的表单，这个程序将跳到`return render_to_response`行，这将导致页面重新显示，并在无效的表单上显示错误注释。

但是等等——一旦找到第一个无效的表单，我们就会跳出`for`循环。如果有多个无效的表单，我们不是想在所有表单上显示错误，而不仅仅是第一个吗？答案是是，但我们不需要在视图中显式调用`is_valid`来实现这一点。当表单在模板中呈现时，如果它被绑定并且尚未经过验证，`is_valid`将在其值呈现之前被调用。因此，无论视图代码是否显式调用`is_valid`，模板中都将显示任何表单中的错误。

如果所有表单都有效，`for`循环将耗尽其列表，并且`for`循环上的`else`子句将运行。在这里，我们想记录投票并向用户返回适当的响应。我们已经完成了第一个，通过增加每个选择答案实例的投票数。但是，对于第二个，我们实现了一个开发版本，该版本构建了一个响应，指示所有问题的当前投票值。这不是我们希望一般用户看到的，但我们可以将其用作快速验证答案记录代码是否符合我们的期望。

如果我们现在选择**戏剧**和**几乎没有：我已经看了太多电视了！**作为答案并提交表单，我们会看到：

![为记录调查响应提供编码支持](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_12.jpg)

看起来不错：没有调试页面，所选的投票值是正确的，所以投票记录代码正在工作。现在我们可以用适用于一般用户的生成响应的开发版本替换开发版本。

在响应成功的 POST 请求时，最佳做法是重定向到其他页面，这样用户按下浏览器的重新加载按钮不会导致已发布的数据被重新提交和重新处理。为此，我们可以将 else 块更改为：

```py
        else: 
            from django.http import HttpResponseRedirect 
            from django.core.urlresolvers import reverse 
            for answer in chosen_answers:
                answer.votes += 1
                answer.save()
            return HttpResponseRedirect(reverse('survey_thanks', args=(survey.pk,)))
```

请注意，这里包含了导入，只是为了显示需要导入的内容；通常情况下，这些内容会放在文件顶部，而不是嵌套在函数中。现在，这段代码不再构建一个注释所有新答案投票值的响应，而是发送一个 HTTP 重定向。为了避免在实际的 `urls.py` 文件之外的任何地方硬编码 URL 配置，我们在这里使用了 reverse 来生成与新命名的 URL 模式 `survey_thanks` 对应的 URL 路径。我们传递调查的主键值作为参数，以便生成的页面可以根据提交的调查进行定制。

在`reverse`调用之前，我们需要在`survey/urls.py`文件中添加一个名为`survey_thanks`的新模式。我们可以这样添加，以便`survey/urls.py`中的完整`urlpatterns`是：

```py
urlpatterns = patterns('survey.views', 
    url(r'^$', 'home', name='survey_home'), 
    url(r'^(?P<pk>\d+)/$', 'survey_detail', name='survey_detail'),
    url(r'^thanks/(?P<pk>\d+/)$', 'survey_thanks', name='survey_thanks'),
) 
```

添加的`survey_thanks`模式与`survey_detail`模式非常相似，只是相关的 URL 路径在包含调查的主键值的段之前有字符串`thanks`。

另外，我们需要在 `survey/views.py` 中添加一个 `survey_thanks` 视图函数：

```py
def survey_thanks(request, pk): 
    survey = get_object_or_404(Survey, pk=pk) 
    return render_to_response('survey/thanks.html', {'survey': survey}) 

```

这个视图使用`get_object_or_404`查找指定的调查。如果找不到匹配的调查，那么将引发`Http404`错误，并返回一个未找到页面的响应。如果找到了调查，那么将使用一个新的模板`survey/thanks.html`来渲染响应。调查被传递到模板中，允许根据提交的调查定制响应。

## 调试页面＃3：/1/处的 NoReverseMatch

在编写新模板之前，让我们检查一下重定向是否有效，因为它只需要对`survey/urls.py`和视图实现进行更改。如果我们在`views.py`中提交了带有新重定向代码的响应，会发生什么？并不是我们所希望的：

![调试页面＃3：/1/处的 NoReverseMatch](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_13.jpg)

`NoReverseMatch`异常可能是最令人沮丧的异常之一。与正向匹配失败时不同，调试页面不会提供尝试的模式列表以及匹配尝试的顺序。这有时会让我们认为适当的模式甚至没有被考虑。请放心，它已经被考虑了。问题不是适当的模式没有被考虑，而是它没有匹配。

## 理解和修复 NoReverseMatch 异常

如何找出预期匹配的模式为何不匹配？猜测可能出错的地方并根据这些猜测进行更改有可能奏效，但也很可能会使情况变得更糟。更好的方法是有条不紊地逐一检查事物，通常会导致问题根源的发现。以下是一系列要检查的事物。我们将按顺序进行检查，并考虑它如何适用于我们的模式，其中`reverse`出现意外失败：

```py
    url(r'^thanks/(?P<pk>\d+/)$', 'survey_thanks', name='survey_thanks'), 
```

首先，验证异常中标识的名称是否与 URL 模式规范中的名称匹配。在这种情况下，异常引用了`survey_thanks`，而我们期望匹配的 URL 模式中指定了`name='survey_thanks'`，所以它们是匹配的。

请注意，如果 URL 模式省略了`name`参数，并且`patterns`调用是指定了视图`prefix`的参数，则在指定要反转的名称时，`reverse`的调用者也必须包括视图`prefix`。例如，在这种情况下，如果我们没有为`survey_thanks`视图指定名称，那么成功的`reverse`调用将需要指定`survey.views.survey_thanks`作为要反转的名称，因为在`survey/urls.py`中指定了`survey.views`作为`patterns prefix`。

其次，确保异常消息中列出的参数数量与 URL 模式中的正则表达式组数量相匹配。在这种情况下，异常中列出了一个参数`1L`，一个正则表达式组`(?P<pk>\d+/)`，所以数字是匹配的。

第三，如果异常显示指定了关键字参数，请验证正则表达式组是否具有名称。此外，请验证组的名称是否与关键字参数的名称匹配。在这种情况下，`reverse`调用没有指定关键字参数，因此在这一步没有什么可检查的。

请注意，当在异常中显示了位置参数时，不需要确保 URL 模式中使用了非命名组，因为位置参数可以与 URL 模式中的命名组匹配。因此，在我们的情况下，URL 模式使用了命名组，而`reverse`调用者指定了位置参数时，就没有问题。

第四，对于每个参数，验证异常中列出的实际参数值的字符串表示是否与 URL 模式中关联的正则表达式组匹配。请注意，异常中显示的值是对参数调用`repr`的结果，因此它们可能不完全匹配参数的字符串表示。例如，在这里，异常报告参数值为`1L`，表示 Python 长整型值（该值是长整型，因为这是本例中使用的数据库 MySQL 对整数值的返回方式）。后缀`L`用于清晰地表示`repr`中的类型，但它不会出现在值的字符串表示中，它只是简单的`1`。

因此，对于我们的例子，异常消息中显示的参数的字符串表示形式是`1`。这是否与 URL 模式中关联的正则表达式组匹配？请记住，该组是`(?P<pk>\d+/)`。括号标识了它是一个组。`?P<pk>`为该组分配了名称`pk`。其余部分`\d+/`是我们试图与`1`匹配的正则表达式。这些不匹配。正则表达式指定了一个或多个数字，后跟一个斜杠，然而我们实际拥有的值是一个单个数字，没有尾随斜杠。我们在这里犯了一个错别字，并在组内部包括了斜杠，而不是在其后。我们新的`survey_thanks`视图的正确规范是：

```py
    url(r'^thanks/(?P<pk>\d+)/$', 'survey_thanks', name='survey_thanks'), 
```

这样的错别字很容易出现在 URL 模式规范中，因为模式规范往往很长，而且充满了具有特殊含义的标点符号。将它们分解成组件，并验证每个组件是否正确，将为您节省大量麻烦。然而，如果这样做不起作用，当所有部分看起来都正确但仍然出现`NoReverseMatch`异常时，也许是时候从另一个方向解决问题了。

从整体模式的最简单部分开始，并验证`reverse`是否有效。例如，您可以从`reverse`调用中删除所有参数以及 URL 模式规范中的所有组，并验证是否可以按名称`reverse` URL。然后添加一个参数及其相关的 URL 规范中的模式组，并验证是否有效。继续直到出现错误。然后切换回尝试最简单的版本，除了仅导致错误的参数之外。如果有效，则整体模式中将该参数与其他参数组合在一起存在问题，这是一个线索，因此您可以开始调查可能导致该问题的原因。

这种方法是一种通用的调试技术，可以在遇到复杂代码集中的神秘问题时应用。首先，退回到非常简单的有效内容。然后逐一添加内容，直到再次失败。现在您已经确定了与失败有关的一个部分，并且可以开始调查它是否是单独的问题，或者它在隔离状态下是否有效，但仅在与其他部分组合时才会出现问题。

## 调试页面＃4：/thanks/1/处的 TemplateDoesNotExist

现在，让我们回到我们的例子。现在我们已经解决了`reverse`问题，重定向到我们的调查感谢页面是否有效？还不够。如果我们再次尝试提交我们的调查结果，我们会看到：

![调试页面＃4：/thanks/1/处的 TemplateDoesNotExist](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_14.jpg)

这个很容易理解；在追踪`NoReverseMatch`错误时，我们忘记了我们还没有写新视图的模板。修复将很容易，但首先需要注意这个调试页面的一个部分：**模板加载程序事后分析**。这是另一个可选部分，就像`TemplateSyntaxError`调试页面中包含的**模板错误**部分一样，它提供了有助于确定错误确切原因的额外信息。

**模板加载程序事后分析**部分具体列出了尝试定位模板时尝试的所有模板加载程序。对于每个加载程序，它列出了该加载程序搜索的完整文件名，以及结果。

在这个页面上，我们可以看到 `filesystem` 模板加载器被首先调用。但是没有任何文件被该加载器尝试加载。`filesystem` 加载器包含在我们的 `settings.py` 文件中，因为它是由 `django-admin.py startproject` 生成的 `settings.py` 文件中 `TEMPLATE_LOADERS` 中的第一个加载器，并且我们没有更改该设置。它会在设置 `TEMPLATE_DIRS` 的所有指定目录中查找。然而，默认情况下 `TEMPLATE_DIRS` 是空的，我们也没有更改该设置，因此 `filesystem` 加载器没有地方可以查找以尝试找到 `survey/thanks.html`。

第二个尝试的加载器是 `app_directories` 加载器。这是我们迄今为止一直依赖的加载器，用于加载我们调查应用程序的模板。它从每个应用程序目录下的 `templates` 目录加载模板。调试页面显示，它首先尝试在 `admin` 应用程序的 `templates` 目录下找到 `survey/thanks.html` 文件，然后在 `survey` 应用程序的 `templates` 目录下找到。在文件名后面，显示了搜索指定文件的结果；在这两种情况下，我们都看到了 **文件不存在**，这并不奇怪。

有时，这个消息会显示 **文件存在**，这可能有点令人困惑。如果文件存在，加载器也能看到它存在，为什么加载器没有加载它呢？这经常发生在像 Apache 这样的 Web 服务器上运行时，问题在于 Web 服务器进程没有必要的权限来读取文件。在这种情况下的解决方法是让 Web 服务器进程可以读取文件。处理这种生产时问题将在第十一章中更详细地讨论，*当是时候上线：转向生产*。

## 理解和修复 TemplateDoesNotExist

在我们的情况下，修复很简单，我们甚至不需要仔细查看错误消息就知道需要做什么，但请注意，本节提供了追踪 `TemplateDoesNotExist` 错误所需的一切。您将知道您依赖于哪个加载器来加载模板。如果在 **Template-loader postmortem** 中没有显示该加载器，那么问题很可能是 `settings.py` 中 `TEMPLATE_LOADERS` 设置不正确。

如果加载器被列出，但没有列出尝试加载预期文件，则下一步是弄清楚原因。这一步取决于加载器，因为每个加载器都有自己的规则来查找模板文件。例如，`app_directories` 加载器会在 `INSTALLED_APPS` 中列出的每个应用程序的 `templates` 目录下查找。因此，确保应用程序在 `INSTALLED_APPS` 中，并且有一个 `templates` 目录，是在 `app_directories` 加载器没有按预期搜索文件时要检查的两件事情。

如果加载器被列出，并且预期的文件被列为尝试加载，那么加载器列出的文件状态所暗示的问题。**文件不存在**是一个明确的状态，有一个简单的解决方法。如果 **文件不存在** 出现得出乎意料，那么请仔细检查文件名。从调试页面复制并粘贴到命令提示符中，尝试显示文件可能会有所帮助，因为它可能有助于澄清加载器尝试加载的文件名与实际存在的文件名之间的差异。其他状态消息，比如 **文件存在**，可能不那么直接，但仍然暗示了问题的性质，并指向了解决问题的方向。

对于我们的示例案例，修复很简单：创建我们之前忘记创建的 `survey/thanks.html` 模板文件。这个模板返回一个基本页面，其中包含一条感谢用户参与调查的消息：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>Thanks</h1> 
<p>Thanks for completing our {{ survey.title }} survey.  Come back soon and check out the full results!</p> 
{% endblock content %} 
```

在`survey/templates`目录下放置了这个模板后，我们现在可以提交一个调查而不会出错。相反，我们看到：

![理解和修复 TemplateDoesNotExist](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_15.jpg)

好！我们现在是否已经完成了显示调查和处理结果？还没有。我们还没有测试提交无效的调查响应会发生什么。接下来我们将尝试。

# 处理无效的调查提交

我们已经编写了处理调查提交的视图，以便在提交的表单中发现任何错误时，重新显示页面并显示错误，而不是处理结果。在显示方面，由于我们使用了`as_p`方便的方法来显示表单，它将负责显示表单中的任何错误。因此，我们不需要进行任何代码或模板更改，就可以看到当提交无效的调查时会发生什么。

什么情况下会使调查提交无效？对于我们的`QuestionVoteForm`来说，唯一可能的错误情况是没有选择答案。那么，如果我们尝试提交一个缺少答案的调查，会发生什么？如果我们尝试，我们会发现结果并不理想：

![处理无效的调查提交](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_16.jpg)

这里至少有两个问题。首先，错误消息的放置位置在调查问题上方，这很令人困惑。很难知道页面上的第一个错误消息指的是什么，第二个错误看起来像是与第一个问题相关联的。最好将错误消息移到实际进行选择的地方附近，例如在问题和答案选择列表之间。

其次，错误消息的文本对于这个特定的表单来说并不是很好。从技术上讲，答案选择列表是一个单一的表单字段，但对于一般用户来说，将**字段**用于选择列表的引用听起来很奇怪。接下来我们将纠正这两个错误。

## 编写自定义错误消息和放置

更改错误消息很容易，因为 Django 提供了一个钩子。为了覆盖当未提供必填字段时发出的错误消息的值，我们可以在字段声明中作为参数传递的`error_messages`字典中，指定`required`键的值作为我们想要的消息。因此，`QuestionVoteForm`中`answer`字段的新定义将把错误消息更改为`请在下面选择一个答案`：

```py
class QuestionVoteForm(forms.Form): 
    answer = forms.ModelChoiceField(widget=forms.RadioSelect, 
        queryset=None, 
        empty_label=None, 
        error_messages={'required': 'Please select an answer below:'}) 
```

更改错误消息的放置位置需要更改模板。我们将尝试显示答案字段的标签、答案字段的错误以及显示选择的答案字段，而不是使用`as_p`方便的方法。然后在`survey/active_survey.html`模板中显示调查表单的`{% for %}`块变为：

```py
{% for qform in qforms %} 
    {{ qform.answer.label }} 
    {{ qform.answer.errors }} 
    {{ qform.answer }} 
{% endfor %} 
```

这样做有什么效果？比以前好。如果我们现在尝试提交无效的表单，我们会看到：

![编写自定义错误消息和放置](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_17.jpg)

虽然错误消息本身得到了改进，放置位置也更好了，但显示的确切形式并不理想。默认情况下，错误显示为 HTML 无序列表。我们可以使用 CSS 样式来去除出现的项目符号（就像我们最终会对选择列表做的那样），但 Django 也提供了一种实现自定义错误显示的简单方法，因此我们可以尝试使用它。

为了覆盖错误消息的显示，我们可以为`QuestionVoteForm`指定一个替代的`error_class`属性，并在该类中实现一个`__unicode__`方法，以返回我们期望的格式的错误消息。对`QuestionVoteForm`和新类进行这一更改的初始实现可能是：

```py
class QuestionVoteForm(forms.Form): 
    answer = forms.ModelChoiceField(widget=forms.RadioSelect, 
        queryset=None,                            
        empty_label=None,                            
        error_messages={'required': 'Please select an answer below:'}) 

    def __init__(self, question, *args, **kwargs): 
        super(QuestionVoteForm, self).__init__(*args, **kwargs) 
        self.fields['answer'].queryset = question.answer_set.all() 
        self.fields['answer'].label = question.question 
        self.error_class = PlainErrorList 

from django.forms.util import ErrorList 
class PlainErrorList(ErrorList): 
    def __unicode__(self): 
        return u'%s' % ' '.join([e for e in sefl]) 
```

对`QuestionVoteForm`的唯一更改是在其`__init__`方法中将其`error_class`属性设置为`PlainErrorList`。`PlainErrorList`类基于`django.form.util.ErrorList`类，并简单地重写`__unicode__`方法，以字符串形式返回错误，而不进行特殊的 HTML 格式化。这里的实现利用了基本的`ErrorList`类继承自`list`，因此对实例本身进行迭代会依次返回各个错误。然后这些错误用空格连接在一起，并返回整个字符串。

请注意，我们只希望这里只会有一个错误，但以防万一我们对这个假设是错误的，最安全的做法是编写多个错误存在的代码。尽管在这种情况下我们的假设可能永远不会错，但可能我们会决定在其他情况下重用这个自定义错误类，而单个可能的错误预期不成立。如果我们根据我们的假设编写代码，并简单地返回列表中的第一个错误，这可能会导致在某些情况下出现混乱的错误显示，因为我们将阻止报告除第一个错误之外的所有错误。如果我们到达那一点，我们可能还会发现，仅用空格分隔的错误列表格式不是一个好的展示方式，但我们可以稍后处理。首先，我们只想简单验证我们对错误列表显示的自定义是否被使用。

## 调试页面＃5：另一个 TemplateSyntaxError

现在我们指定了自定义错误类，如果我们尝试提交一个无效的调查会发生什么？现在尝试提交一个无效的调查会返回：

![调试页面＃5：另一个 TemplateSyntaxError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_18.jpg)

哎呀，我们又犯了一个错误。第二行显示的异常值非常清楚地表明我们将`self`误输入为`sefl`，由于我们刚刚做的代码更改总共只影响了五行，所以我们不需要花太多时间来找到这个拼写错误。但让我们仔细看看这个页面，因为它看起来与我们遇到的其他`TemplateSyntaxError`有些不同。

这一页与其他`TemplateSyntaxError`相比有什么不同？实际上，在结构上并没有什么不同；它包含了所有相同的部分和相同的内容。显著的区别在于异常值不是单行的，而是一个包含**原始回溯**的多行消息。那是什么？如果我们看一下调试页面的回溯部分，我们会发现它相当长、重复且无信息。通常最有趣的部分是结尾部分，它是：

![调试页面＃5：另一个 TemplateSyntaxError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_19.jpg)

在那个回溯中引用的每一行代码都是 Django 代码，而不是我们的应用程序代码。然而，我们可以非常确定这里的问题不是由 Django 模板处理代码引起的，而是由我们刚刚对`QuestionVoteForm`进行的更改引起的。发生了什么？

这里发生的是在渲染模板时引发了一个异常。渲染期间的异常会被捕获并转换为`TemplateSyntaxErrors`。异常的大部分堆栈跟踪可能不会对解决问题有趣或有帮助。更有信息的是原始异常的堆栈跟踪，在被捕获并转换为`TemplateSyntaxError`之前。这个堆栈跟踪作为最终引发的`TemplateSyntaxError`的异常值的**原始回溯**部分提供。

这种行为的一个好处是，很可能是非常长的回溯的重要部分在调试页面的顶部被突出显示。一个不幸的方面是，回溯的重要部分在回溯部分本身不再可用，因此调试页面的回溯部分的特殊功能对其不可用。不可能扩展原始回溯中标识的行周围的上下文，也无法看到原始回溯每个级别的局部变量。这些限制不会导致解决这个特定问题时出现任何困难，但对于更晦涩的错误可能会很烦人。

### 注意

请注意，Python 2.6 对基本的`Exception`类进行了更改，导致在显示`TemplateSyntaxError`异常值时省略了此处提到的**原始回溯**信息。因此，如果您使用的是 Python 2.6 和 Django 1.1.1，您将看不到调试页面上包括**原始回溯**。这可能会在 Django 的新版本中得到纠正，因为丢失**原始回溯**中的信息会使调试错误变得非常困难。这个问题的解决方案也可能解决先前提到的一些烦人的问题，与`TemplateSyntaxErrors`包装其他异常有关。

## 修复第二个 TemplateSyntaxError

修复这个第二个`TemplateSyntaxError`很简单：只需在原始回溯中指出的行上纠正`sefl`拼写错误。当我们这样做并再次尝试提交无效的调查时，我们会看到响应：

![修复第二个 TemplateSyntaxError](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_07_20.jpg)

那不是一个调试页面，所以很好。此外，错误消息不再显示为 HTML 无序列表，这是我们对此更改的目标，所以很好。它们的确切位置可能不完全是我们想要的，我们可能希望添加一些 CSS 样式，使它们更加突出，但现在它们会做到这一点。

# 总结

我们现在已经完成了调查投票的实施，并对 Django 调试页面进行了深入的覆盖。在本章中，我们：

+   着手用真正的实现替换活动调查的占位符视图和模板以进行显示

+   在实施过程中犯了一些典型的错误，导致我们看到了五个不同的 Django 调试页面。

+   在遇到第一个调试页面时，了解了调试页面的所有不同部分以及每个部分包含的信息

+   对于每个遇到的调试页面，使用呈现的信息来定位和纠正编码错误

在下一章中，我们将继续学习即使代码没有导致调试页面显示也能收集调试信息的技术。


# 第八章：当问题隐藏时：获取更多信息

有时代码不会触发显示调试页面，但也不会产生正确的结果。事实上，即使代码似乎在浏览器中显示的可见结果方面工作正常，幕后它可能也在做一些意想不到的事情，这可能会在以后引起麻烦。例如，如果一个页面需要许多（或非常耗时的）SQL 查询，那么在开发过程中它可能看起来运行正常，但在生产环境中很快就会导致服务器超载。

因此，养成检查代码行为的习惯是很好的做法，即使外部结果没有显示任何问题。首先，这种做法可以揭示最好尽早知道的隐藏问题。其次，当问题确实出现时，了解正常的代码路径是非常有价值的。

本章重点介绍了获取有关 Django 应用程序代码正在执行的更多信息的方法。具体来说，在本章中我们将：

+   开发模板代码，用于在页面本身包含有关渲染页面所需的所有 SQL 查询的信息

+   学习如何使用 Django 调试工具栏收集类似信息，以及更多

+   讨论向 Django 应用程序代码添加日志记录的技术

# 跟踪请求的 SQL 查询

对于典型的 Django 应用程序，数据库交互非常重要。确保所做的数据库查询是正确的有助于确保应用程序的结果是正确的。此外，确保为应用程序生成的数据库查询是高效的有助于确保应用程序能够支持所需数量的并发用户。

Django 通过使数据库查询历史可供检查来支持这一领域。第六章，“Django 调试概述”介绍了这一历史，并展示了如何从 Python shell 会话中访问它。这种访问对于查看由于调用特定模型方法而发出的 SQL 非常有用。然而，它对于了解在处理特定请求期间进行了哪些 SQL 查询并不有用。

本节将展示如何在页面本身包含有关生产页面所需的 SQL 查询的信息。我们将修改现有的调查应用程序模板以包含查询信息，并检查一些现有调查应用程序视图的查询历史。虽然我们不知道现有视图存在任何问题，但在验证它们是否发出我们期望的查询时，我们可能会学到一些东西。

## 在模板中访问查询历史的设置

在可以从模板中访问查询历史之前，我们需要确保一些必需的设置被正确配置。为了使 SQL 查询信息在模板中可用，需要三个设置。首先，必须在`TEMPLATE_CONTEXT_PROCESSORS`设置中包含调试上下文处理器`django.core.context_processors.debug`。这个上下文处理器包含在`TEMPLATE_CONTEXT_PROCESSORS`的默认值中。我们没有更改该设置；因此，我们不需要在项目中做任何事情来启用这个上下文处理器。

其次，发送请求的机器的 IP 地址必须列在`INTERNAL_IPS`设置中。这不是我们以前使用过的设置，默认情况下为空，因此我们需要将其添加到设置文件中。在使用与开发服务器运行的相同机器进行测试时，将`INTERNAL_IPS`设置为包括环回地址就足够了：

```py
# Addresses for internal machines that can see potentially sensitive
# information such as the query history for a request.
INTERNAL_IPS = ('127.0.0.1', ) 
```

如果您还从其他机器进行测试，您还需要在此设置中包含它们的 IP 地址。

第三，最后，`DEBUG`必须为`True`，才能在模板中使用 SQL 查询历史。

当满足这三个设置条件时，SQL 查询历史可能可以通过名为`sql_queries`的模板变量在模板中使用。这个变量包含一个字典列表。每个字典包含两个键：`sql`和`time`。`sql`的值是 SQL 查询本身，`time`的值是查询执行所花费的秒数。

请注意，`sql_queries`上下文变量是由调试上下文处理器设置的。只有在使用`RequestContext`来渲染模板时，上下文处理器才会被调用。到目前为止，我们在调查应用程序视图中没有使用`RequestContexts`，因为到目前为止代码还不需要。但是为了从模板中访问查询历史，我们需要开始使用`RequestContexts`。因此，除了修改模板，我们还需要稍微修改视图代码，以便在调查应用程序的生成页面中包含查询历史。

## 主页的 SQL 查询

让我们首先看看为了生成`survey`应用程序主页而发出了哪些查询。回想一下主页视图代码是：

```py
def home(request):
    today = datetime.date.today()
    active = Survey.objects.active()
    completed = Survey.objects.completed().filter(closes__gte=today-
                    datetime.timedelta(14))
    upcoming = Survey.objects.upcoming().filter(
                    opens__lte=today+datetime.timedelta(7))
    return render_to_response('survey/home.html',
        {'active_surveys': active,
        'completed_surveys': completed,
        'upcoming_surveys': upcoming,
        }) 
```

模板中呈现了三个`QuerySets`，所以我们期望看到这个视图生成三个 SQL 查询。为了检查这一点，我们必须首先更改视图以使用`RequestContext`：

```py
from django.template import RequestContext 
def home(request): 
    today = datetime.date.today() 
    active = Survey.objects.active() 
    completed = Survey.objects.completed().filter(closes__gte=today-datetime.timedelta(14)) 
    upcoming = Survey.objects.upcoming().filter(opens__lte=today+datetime.timedelta(7)) 
    return render_to_response('survey/home.html', 
        {'active_surveys': active, 
         'completed_surveys': completed, 
         'upcoming_surveys': upcoming,}, 
        RequestContext(request)) 
```

这里唯一的变化是在文件中添加了`import`后，将`RequestContext(request)`作为`render_to_response`的第三个参数添加进去。当我们做出这个改变时，我们可能也会改变其他视图的`render_to_response`行，以便也使用`RequestContexts`。这样，当我们到达检查每个查询的 SQL 查询的时候，我们不会因为忘记做出这个小改变而被绊倒。

其次，我们需要在我们的`survey/home.html`模板中的某个地方显示来自`sql_queries`的信息。但是在哪里？我们不一定希望这些信息与真实应用程序数据一起显示在浏览器中，因为那可能会让人困惑。将其包含在响应中但不自动显示在浏览器页面上的一种方法是将其放在 HTML 注释中。然后浏览器不会在页面上显示它，但可以通过查看显示页面的 HTML 源代码来看到它。

作为实现这一点的第一次尝试，我们可能会改变`survey/home.html`的顶部，看起来像这样：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<!-- 
{{ sql_queries|length }} queries 
{% for qdict in sql_queries %} 
{{ qdict.sql }} ({{ qdict.time }} seconds) 
{% endfor %} 
--> 
```

这个模板代码在`survey/home.html`提供的`content`块的开头以 HTML 注释的形式打印出`sql_queries`的内容。首先，通过`length`过滤器过滤列表来记录查询的数量。然后代码遍历`sql_queries`列表中的每个字典，并显示`sql`，然后跟着每个查询所花费的`time`的括号注释。

这个方法效果如何？如果我们尝试通过检索调查主页（确保开发服务器正在运行），并使用浏览器菜单项查看页面的 HTML 源代码，我们可能会看到评论块包含类似以下内容：

```py
<!--
1 queries

SELECT `django_session`.`session_key`, `django_session`.`session_data`, `django_session`.`expire_date` FROM `django_session` WHERE (`django_session`.`session_key` = d538f13c423c2fe1e7f8d8147b0f6887  AND `django_session`.`expire_date` &gt; 2009-10-24 17:24:49 ) (0.001 seconds)

--> 

```

### 注意

请注意，这里显示的查询数量取决于您正在运行的 Django 版本。这个结果来自 Django 1.1.1；Django 的后续版本可能不会显示任何查询。此外，浏览器与网站的交互历史将影响发出的查询。这个结果来自一个曾用于访问管理应用程序的浏览器，最后一次与管理应用程序的交互是退出登录。如果浏览器曾用于访问管理应用程序但用户未注销，则可能会看到其他查询。最后，使用的数据库也会影响发出的具体查询和其确切格式。这个结果来自一个 MySQL 数据库。

这并不是我们预期的。首先，一个小小的烦恼，但是`1 queries`是错误的，应该是`1 query`。也许这不会让你烦恼，特别是在内部或调试信息中，但对我来说会让我烦恼。我会更改显示查询计数的模板代码，以使用正确的复数形式：

```py
{% with sql_queries|length as qcount %} 
{{ qcount }} quer{{ qcount|pluralize:"y,ies" }} 
{% endwith %} 
```

在这里，由于模板需要多次使用`length`结果，首先通过使用`{% with %}`块将其缓存在`qcount`变量中。然后它被显示，并且它被用作`pluralize`过滤器的变量输入，该过滤器将根据`qcount`值在`quer`的末尾放置正确的字母。现在注释块将显示`0 queries`，`1 query`，`2 queries`等等。

解决了这个小小的烦恼后，我们可以集中精力解决下一个更大的问题，那就是显示的查询不是我们预期的查询。此外，我们预期的三个查询，用于检索已完成、活动和即将进行的调查列表，都不见了。发生了什么？我们将依次处理每一个。

显示的查询正在访问`django_session`表。这个表被`django.contrib.sessions`应用程序使用。尽管调查应用程序不使用这个应用程序，但它在我们的`INSTALLED_APPS`中列出，因为它包含在`settings.py`文件中，`startproject`生成。此外，`sessions`应用程序使用的中间件在`MIDDLEWARE_CLASSES`中列出。

`sessions`应用程序默认将会话标识符存储在名为`sessionid`的 cookie 中，一旦任何应用程序使用会话，它就会立即发送到浏览器。浏览器将在所有请求中返回该 cookie 给同一服务器。如果请求中存在该 cookie，会话中间件将使用它来检索会话数据。这就是我们之前看到的查询：会话中间件正在检索由浏览器发送的会话 cookie 标识的会话数据。

但是调查应用程序不使用 sessions，那么浏览器是如何首先获得会话 cookie 的呢？答案是管理员应用程序使用 sessions，并且此浏览器先前曾用于访问管理员应用程序。那时，`sessionid` cookie 在响应中设置，并且浏览器忠实地在所有后续请求中返回它。因此，似乎很可能这个`django_session`表查询是由于使用管理员应用程序的副作用设置了`sessionid` cookie。

我们能确认吗？如果我们找到并删除浏览器中的 cookie，然后重新加载页面，我们应该会看到这个 SQL 查询不再列出。没有请求中的 cookie，触发对会话数据的访问的任何代码都不会有任何东西可以查找。而且由于调查应用程序不使用 sessions，它的任何响应都不应包含新的会话 cookie，这将导致后续请求包含会话查找。这种推理正确吗？如果我们尝试一下，我们会看到注释块变成：

```py
<!--

0 queries

--> 

```

因此，我们似乎在一定程度上确认了在处理调查应用程序响应期间导致`django_session`表查询的原因。我们没有追踪到哪些确切的代码访问了由 cookie 标识的会话——可能是中间件或上下文处理器，但我们可能不需要知道细节。记住我们的项目中运行的除了我们正在工作的应用程序之外还有其他应用程序，它们可能会导致与我们自己的代码无关的数据库交互就足够了。如果我们观察到的行为看起来可能会对我们的代码造成问题，我们可以进一步调查，但对于这种特殊情况，我们现在将避免使用管理员应用程序，因为我们希望将注意力集中在我们自己的代码生成的查询上。

现在我们了解了列出的查询，那么没有列出的预期查询呢？缺少的查询是由于`QuerySets`的惰性评估属性和列出`sql_queries`内容的`comment`块的确切放置位置的组合。我们将`comment`块放在主页的`content`块顶部，以便在查看页面源时轻松找到 SQL 查询信息。模板在视图创建三个`QuerySets`之后呈现，因此似乎放在顶部的注释应该显示三个`QuerySets`的 SQL 查询。

然而，`QuerySets`是惰性的；仅创建`QuerySet`并不会立即导致与数据库的交互。相反，直到实际访问`QuerySet`结果之前，将 SQL 发送到数据库是延迟的。对于调查主页，直到循环遍历每个`QuerySet`的模板部分被渲染之前，这并不会发生。这些部分都在我们放置`sql_queries`信息的下面，因此相应的 SQL 查询尚未发出。解决此问题的方法是将`comment`块的放置位置移动到`content`块的最底部。

当我们这样做时，我们还应该修复查询显示的另外两个问题。首先，请注意上面显示的查询中显示的是`&gt;`而不是实际发送到数据库的`>`符号。此外，如果使用的数据库是使用直引号而不是反引号进行引用的数据库（例如 PostgreSQL），查询中的所有反引号都将显示为`&quot;`。这是由于 Django 自动转义 HTML 标记字符造成的。这在我们的 HTML 注释中是不必要且难以阅读的，因此我们可以通过将`sql`查询值通过`safe`过滤器发送来抑制它。

其次，查询非常长。为了避免需要向右滚动才能看到整个查询，我们还可以通过`wordwrap`过滤器过滤`sql`值，引入一些换行，使输出更易读。

要进行这些更改，请从`survey/home.html`模板的`content`块顶部删除添加的注释块，而是将此模板的底部更改为：

```py
{% endif %} 
<!-- 
{% with sql_queries|length as qcount %} 
{{ qcount }} quer{{ qcount|pluralize:"y,ies" }} 
{% endwith %} 
{% for qdict in sql_queries %} 
{{ qdict.sql|safe|wordwrap:60 }} ({{ qdict.time }} seconds) 
{% endfor %} 
--> 
{% endblock content %} 
```

现在，如果我们再次重新加载调查主页并查看返回页面的源代码，我们将在底部的注释中看到列出的查询：

```py
<!--

3 queries

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE (`survey_survey`.`opens` <= 2009-10-25
 AND `survey_survey`.`closes` >= 2009-10-25 ) (0.000 seconds)

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE (`survey_survey`.`closes` < 2009-10-25
 AND `survey_survey`.`closes` >= 2009-10-11 ) (0.000 seconds)

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE (`survey_survey`.`opens` > 2009-10-25 
AND `survey_survey`.`opens` <= 2009-11-01 ) (0.000 seconds)

--> 

```

这很好，看起来正是我们期望在主页查询中看到的内容。现在我们似乎有一些可以显示查询的工作模板代码，我们将考虑打包这个片段，以便可以轻松地在其他地方重用。

## 打包模板查询显示以便重用

现在我们有了一小块模板代码，可以将其放在任何模板中，以便轻松查看生成页面所需的 SQL 查询。但是，它并不小到可以在需要时轻松重新输入。因此，最好将其打包成一种形式，可以在需要时方便地包含在任何地方。Django 模板`{% include %}`标签使这一点变得很容易。

这个片段应该放在哪里？请注意，这个模板片段是完全通用的，与调查应用程序没有任何关联。虽然将其简单地包含在调查模板中很容易，但将其放在那里将使其在将来的项目中更难以重用。更好的方法是将其放在一个独立的应用程序中。

为这个片段创建一个全新的应用程序可能看起来有点极端。然而，在开发过程中创建一些不真正属于主应用程序的小型实用函数或模板片段是很常见的。因此，在实际项目的开发过程中，可能会有其他类似的东西，它们在逻辑上应该放在主应用程序之外的某个地方。有一个地方可以放它们是很有帮助的。

让我们创建一个新的 Django 应用程序，用来保存一些通用的实用代码，这些代码在调查应用程序中并不合乎逻辑：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py startapp gen_utils 

```

由于它的目的是保存通用实用代码，我们将新应用程序命名为`gen_utils`。它可以作为一个放置任何非调查特定代码的地方，看起来可能在其他地方有重复使用的潜力。请注意，随着时间的推移，如果在这样的应用程序中积累了越来越多的东西，可能会变得明显，其中的一些子集将有用，可以打包成一个独立的、自包含的应用程序，其名称比`gen_utils`更具描述性。但是现在，开始一个地方放置与调查应用程序没有真正关联的实用代码就足够了。

接下来，我们可以在`gen_utils`中创建一个`templates`目录，然后在`templates`下创建一个`gen_utils`目录，并创建一个文件`showqueries.html`来保存模板片段：

```py
{% if sql_queries %}<!-- 
{% with sql_queries|length as qcount %} 
{{ qcount }} quer{{ qcount|pluralize:"y,ies" }} 
{% endwith %} 
{% for qdict in sql_queries %} 
{{ qdict.sql|safe|wordwrap:60 }} ({{ qdict.time }} seconds){% endfor %} 
-->{% endif %} 
```

我们对之前直接放在`survey/home.html`模板中的代码进行了一个改变，就是将整个 HTML `comment`块放在了`{% if sql_qureies %}`块中。如果`sql_queries`变量没有包含在模板上下文中，那么就没有理由生成注释。

作为代码重用的一部分，检查并确保代码确实可重用，并且不会在给定意外或异常输入时以奇怪的方式失败也是一个好习惯。看看那个片段，有没有什么可能在任意的`sql_queries`输入中引起问题的东西？

答案是肯定的。如果 SQL 查询值包含 HTML 注释结束符，则注释块将被提前终止。这可能导致浏览器将本来应该是注释的内容作为用户显示的页面内容的一部分。为了验证这一点，我们可以尝试在主页视图代码中插入一个包含 HTML 注释结束符的模型`filter`调用，然后查看浏览器显示的内容。

但是 HTML 注释结束符是什么？你可能会猜想是`-->`，但实际上它只是连续的两个破折号。从技术上讲，`<!`和`>`被定义为标记声明的开始和结束，而破折号标记注释的开始和结束。因此，包含连续两个破折号的查询应该触发我们在这里担心的行为。为了测试这一点，将这行代码添加到`home`视图中：

```py
    Survey.objects.filter(title__contains='--').count() 
```

注意不需要对调用的结果做任何处理；添加的代码只需确保包含两个破折号的查询实际上被发送到数据库。通过检索匹配包含两个破折号的模式的结果计数，添加的代码实现了这一点。有了`home`视图中的这一行，Firefox 将显示调查主页如下：

![打包模板查询以便重用](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_01(revised).jpg)

在 SQL 查询值中连续出现的两个破折号导致 Firefox 过早终止了注释块，我们本打算仍然在注释中的数据出现在了浏览器页面上。为了避免这种情况，我们需要确保 SQL 查询值中不会连续出现两个破折号。

快速浏览内置的 Django 过滤器并没有发现可以用来替换两个破折号的字符串的过滤器。`cut`过滤器可以用来移除它们，但仅仅移除它们会使`sql`值具有误导性，因为没有指示这些字符已从字符串中移除。因此，似乎我们需要为此开发一个自定义过滤器。

我们将自定义过滤器放在`gen_utils`应用程序中。过滤器和模板标签必须放在应用程序的`templatetags`模块中，因此我们首先需要创建`templatetags`目录。然后，我们可以将`replace_dashes`过滤器的实现放入`gen_utils/templatetags`目录中的名为`gentags.py`的文件中：

```py
from django import template 

register = template.Library() 

@register.filter 
def replace_dashes(value): 
    return value.replace('--','~~double-dash~~') 
replace_dashes.is_safe = True 
```

这段代码的主要部分是标准的样板`import`，`register`赋值和`@register.filter`装饰，需要注册`replace_dashes`函数，以便它可以作为过滤器使用。函数本身只是用`~~double-dash~~`替换字符串中一对破折号的任何出现。由于没有办法转义破折号，以便它们不被解释为注释的结束，但仍然显示为破折号，我们用描述原内容的字符串替换它们。最后一行将`replace_dashes`过滤器标记为安全，这意味着它不会引入任何需要在输出中转义的 HTML 标记字符。

我们还需要更改`gen_utils/showqueries.html`中的模板片段，以加载和使用此过滤器来显示 SQL 查询的值：

```py
{% if sql_queries %}<!-- 
{% with sql_queries|length as qcount %} 
{{ qcount }} quer{{ qcount|pluralize:"y,ies" }} 
{% endwith %} 
{% load gentags %} 
{% for qdict in sql_queries %} 
{{ qdict.sql|safe|replace_dashes|wordwrap:60 }} ({{ qdict.time }} seconds) 
{% endfor %} 
-->{% endif %} 
```

这里唯一的变化是添加了`{% load gentags %}`一行，并在应用于`qdict.sql`的过滤器序列中添加了`replace_dashes`。

最后，我们可以从`survey/home.html`模板中删除注释片段。相反，我们将把新的通用片段放在`survey/base.html`模板中，因此变成：

```py
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"> 
<html > 
<head> 
<title>{% block title %}Survey Central{% endblock %}</title> 
</head> 
<body> 
{% block content %}{% endblock %}
</body> 
{% include "gen_utils/showqueries.html" %} 
</html> 
```

在基础模板中放置`{% include %}`将导致每个从基础模板继承的模板自动添加注释块，假设`DEBUG`被打开，请求的 IP 地址被列在`INTERNAL_IPS`中，并且响应被使用`RequestContext`渲染。在将应用程序放入生产环境之前，我们可能想要删除这个功能，但在开发过程中，可以方便地自动访问用于生成任何页面的 SQL 查询。

## 测试重新打包的模板代码

代码的重新打包版本效果如何？如果我们现在尝试重新加载调查主页，我们会发现我们忘记了一些东西。第一次尝试会弹出一个 Django 调试页面：

![测试重新打包的模板代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_02.jpg)

这是上一章提到的特殊调试页面的一个实例。这是由于在渲染过程中引发了异常而导致的`TemplateSyntaxError`。原始异常被捕获并转换为`TemplateSyntaxError`，原始回溯作为异常值的一部分显示出来。通过查看原始回溯，我们可以看到原始异常是`TemplateDoesNotExist`。由于某种原因，模板加载器没有找到`gen_utils/showqueries.html`模板文件。

在这里接收到的调试页面中进一步翻页，我们了解到模板引擎将原始异常包装在`TemplateSyntaxError`中的行为有时会令人恼火。因为最终引发的异常是`TemplateSyntaxError`而不是`TemplateDoesNotExist`，这个调试页面没有模板加载器事后报告，该报告将详细说明尝试了哪些模板加载器，以及它们在搜索`gen_utils/showqueries.html`时尝试加载了哪些文件。因此，由于`TemplateSyntaxError`异常用于包装其他异常的方式，我们丢失了一些有用的调试信息。

如果需要的话，我们可以通过尝试直接从视图中渲染它，而不是将其包含在另一个模板中，来强制生成此模板文件的模板加载器事后报告。因此，通过一点工作，我们可以获得这个特定调试页面中不幸未包含的信息。

但在这种情况下并不需要，因为异常的原因并不特别隐晦：我们没有采取任何措施确保新的`gen_utils`应用程序中的模板能够被找到。我们没有将`gen_utils`包含在`INSTALLED_APPS`中，以便应用程序模板加载程序可以搜索其`templates`目录，也没有将`gen_utils 模板`目录的路径放入`TEMPLATE_DIRS`设置中。我们需要做这些事情中的一件，以便找到新的模板文件。由于`gen_utils`现在也有一个过滤器，并且为了加载该过滤器，`gen_utils`需要被包含在`INSTALLED_APPS`中，我们将通过将`gen_utils`包含在`INSTALLED_APPS`中来修复`TemplateDoesNotExist`异常。

一旦我们做出了这个改变，新的代码工作了吗？并没有。尝试重新加载页面现在会出现不同的调试页面：

![测试重新打包的模板代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_03.jpg)

这个有点神秘。显示的模板是`gen_utils/showqueries.html`，所以我们比之前的情况更进一步了。但出于某种原因，尝试`{% load gentags %}`失败了。错误信息显示：

**'gentags'不是有效的标签库：无法从 django.templatetags.gentags 加载模板库，没有名为 gentags 的模块**。

这是一个罕见的情况，你不希望完全相信错误消息似乎在说什么。它似乎在暗示问题是`django.templatetags`中没有`gentags.py`文件。一个自然的下一个想法可能是，需要将自定义模板标签和过滤器库放在 Django 自己的源树中。然而，这将是一个非常奇怪的要求，而且文档明确地与之相矛盾，因为它指出自定义标签和过滤器应该放在应用程序的`templatetags`目录中。我们应该使用除了普通的`{% load %}`标签以外的东西来强制 Django 搜索其自己的`templatetags`目录之外的标签库吗？

不，这种情况下错误只是误导。尽管错误消息中只命名了`django.templatetags`模块，但实际上 Django 代码尝试从`INSTALLED_APPS`中列出的每个应用程序的`templatetags`目录中加载`gentags`。因此问题不在于 Django 为什么未能在`gen_utils/templatetags`目录下查找`gentags`，而是为什么从`genutils.templatetags`加载`gentags`失败？

我们可以尝试回答这个问题，尝试在 Python shell 会话中运行与`{% load %}`相同的 Django 代码：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py shell 
Python 2.5.2 (r252:60911, Oct  5 2008, 19:24:49) 
[GCC 4.3.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information. 
(InteractiveConsole) 
>>> from gen_utils.templatetags import gentags 
Traceback (most recent call last): 
 File "<console>", line 1, in <module> 
ImportError: No module named templatetags 
>>> 

```

果然，尝试从`gen_utils.templatetags`导入`gentags`失败了。Python 声称`templatetags`模块不存在。但这个目录肯定是存在的，`gentags.py`也存在，那么缺少什么呢？答案是在该目录中创建一个`__init__.py`文件，使 Python 将其识别为一个模块。创建该文件并从 shell 重新尝试导入将会显示导入现在可以工作。

然而，尝试在浏览器中简单地重新加载页面会导致相同的调试页面重新显示。这也是开发服务器需要手动停止和重新启动才能接受更改的罕见情况之一。完成这些操作后，我们最终可以重新加载调查首页并看到：

![测试重新打包的模板代码](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_04.jpg)

我们回到了页面被提供而没有引发异常的情况，也不再有`sql_queries`的杂散调试信息包含在 HTML 注释中。如果我们进一步查看页面的 HTML 源代码，底部会看到类似以下内容：

```py
<!--

4 queries

SELECT COUNT(*) FROM `survey_survey` WHERE
`survey_survey`.`title` LIKE BINARY %~~double-dash~~%  (0.015 seconds)

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE (`survey_survey`.`opens` <= 2009-11-01
 AND `survey_survey`.`closes` >= 2009-11-01 ) (0.001 seconds)

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE (`survey_survey`.`closes` < 2009-11-01
 AND `survey_survey`.`closes` >= 2009-10-18 ) (0.000 seconds)

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE (`survey_survey`.`opens` > 2009-11-01 
AND `survey_survey`.`opens` <= 2009-11-08 ) (0.000 seconds)

--> 

```

看起来不错。`replace_dashes`过滤器成功地去掉了两个连字符，因此浏览器不再认为注释块在预期之前被终止。现在我们可以继续检查生成其他调查页面所需的 SQL 查询。

## 用于活动调查表单显示页面的 SQL 查询

单击链接到一个活动调查会显示该调查的活动调查页面：

![用于活动调查表单显示页面的 SQL 查询](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_05.jpg)

查看此页面的源代码，我们看到需要六个 SQL 查询才能生成它：

```py
<!--

6 queries

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE `survey_survey`.`id` = 1  (0.000 seconds)

SELECT `survey_question`.`id`, `survey_question`.`question`,
`survey_question`.`survey_id` FROM `survey_question` WHERE
`survey_question`.`survey_id` = 1  (0.000 seconds)

SELECT COUNT(*) FROM `survey_answer` WHERE
`survey_answer`.`question_id` = 1  (0.001 seconds)

SELECT COUNT(*) FROM `survey_answer` WHERE
`survey_answer`.`question_id` = 2  (0.001 seconds)

SELECT `survey_answer`.`id`, `survey_answer`.`answer`,
`survey_answer`.`question_id`, `survey_answer`.`votes` FROM
`survey_answer` WHERE `survey_answer`.`question_id` = 1  (0.024 seconds)

SELECT `survey_answer`.`id`, `survey_answer`.`answer`,
`survey_answer`.`question_id`, `survey_answer`.`votes` FROM
`survey_answer` WHERE `survey_answer`.`question_id` = 2  (0.001 seconds)

-->

```

我们能否将这些查询与用于生成页面的代码进行匹配？是的，在这种情况下，可以相对容易地看到每个查询来自哪里。第一个查询是根据其主键查找调查，并对应于`survey_detail`视图中第一行中的`get_object_or_404`调用：

```py
def survey_detail(request, pk): 
    survey = get_object_or_404(Survey, pk=pk) 
```

由于这是一个活动调查，控制线程随后转到`display_active_survey`函数，其中包含以下代码来构建页面的表单：

```py
    qforms = [] 
    for i, q in enumerate(survey.question_set.all()): 
        if q.answer_set.count() > 1: 
            qforms.append(QuestionVoteForm(q, prefix=i, data=data)) 
```

调用`enumerate(survey.question_set.all())`负责此页面的第二个 SQL 查询，它检索显示的调查的所有问题。`for`循环中的`q.answer_set.count()`解释了第三和第四个 SQL 查询，它们检索了调查中每个问题的答案计数。

然后，最后两个查询检索了调查中每个问题的答案集。我们可能首先认为这些查询是在创建调查中每个问题的`QuestionVoteForm`时发出的。 `QuestionVoteForm`的`__init__`例程包含此行，以初始化问题的答案集：

```py
        self.fields['answer'].queryset = question.answer_set.all() 
```

然而，该行代码并不会导致对数据库的调用。它只是将表单的`answer`字段的`queryset`属性设置为`QuerySet`值。由于`QuerySets`是惰性的，这不会导致数据库访问。这得到了证实，即请求`COUNT(*)`的两个查询是在检索实际答案信息的查询之前发出的。如果创建`QuestionVoteForm`导致检索答案信息，那么最后两个查询将不会是最后的，而是将与`COUNT(*)`查询交错。然后，触发检索答案信息的查询是在`survey/active_survey.html`模板中呈现答案值时。

如果我们专注于优化，此时我们可能会尝试看看是否可以减少此页面所需的查询数量。在两个单独的查询中检索答案的计数，然后检索答案信息本身似乎效率低下，与仅检索答案信息并根据返回的信息推导计数相比。看起来我们可以用四个查询而不是六个查询来生成此页面。

然而，由于我们专注于理解当前行为以帮助调试，我们不会在这里转向优化讨论。即使我们正在开发一个真正的项目，在开发的这个阶段，现在不是进行此类优化的好时机。这里的低效并不糟糕到被称为错误，所以最好只是将其记录为将来可能要查看的可能事项，当可以确定应用程序的整体性能的全貌时。在那时，最昂贵的低效将值得花时间进行改进的。

## 发布调查答案的 SQL 查询

如果我们现在为调查问题选择了一些答案并按下**提交**按钮，我们会收到**感谢**页面的响应：

![用于发布调查答案的 SQL 查询](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_06.jpg)

查看此页面的源代码，我们发现了一个单独的 SQL 查询，以检索给定主键的`survey`：

```py
<!--

1 query

SELECT `survey_survey`.`id`, `survey_survey`.`title`,
`survey_survey`.`opens`, `survey_survey`.`closes` FROM
`survey_survey` WHERE `survey_survey`.`id` = 1  (0.001 seconds)

-->

```

与该查询相关的代码行是显而易见的；它是`survey_thanks`视图中的`get_object_or_404`：

```py
def survey_thanks(request, pk): 
    survey = get_object_or_404(Survey, pk=pk) 
    return render_to_response('survey/thanks.html', 
        {'survey': survey }, 
        RequestContext(request)) 
```

但是，当表单数据被提交时，处理表单数据所涉及的所有 SQL 查询呢？在调用`survey_thanks`视图之前很久，必须运行`display_active_survey`以接收提交的表单数据并更新所选答案的数据库。然而，我们在感谢页面显示的查询中没有看到其中任何需要的 SQL 查询。

原因是因为`display_active_survey`函数在表单处理成功并更新数据库时，不直接呈现模板，而是返回一个`HttpResponseRedirect`。Web 浏览器在接收到 HTTP 重定向响应后，会自动获取重定向中标识的位置。

因此，在浏览器上按下“提交”按钮和看到感谢页面出现之间，会发生两个完整的请求/响应周期。感谢页面本身可以显示在其（第二个）请求/响应周期期间执行的 SQL 查询，但不能显示在第一个请求/响应周期中发生的任何查询。

这令人失望。此时，我们已经花了相当多的精力开发了一开始看起来似乎会是一个非常简单的实用程序代码。现在，我们发现它对于应用程序中一些最有趣的视图——实际上更新数据库的视图——不起作用。我们该怎么办？

我们当然不希望放弃查看成功处理提交的数据页面的 SQL 查询。但我们也不希望在这个实用程序代码上花费更多的开发工作。虽然我们在这个过程中学到了一些东西，但我们开始偏离我们的主要应用程序。幸运的是，我们不需要做这两件事。相反，我们可以简单地安装并开始使用一个已经开发好的 Django 应用程序的通用调试工具，即 Django Debug Toolbar。这个工具是下一节的重点。

# Django Debug Toolbar

Rob Hudson 的 Django Debug Toolbar 是 Django 应用程序的非常有用的通用调试工具。与我们在本章早些时候开发的代码一样，它可以让您看到生成页面所需的 SQL 查询。然而，正如我们将看到的，它远不止于此，还提供了更多关于 SQL 查询和请求处理的信息的简便访问。此外，调试工具栏有一种更高级的显示信息的方式，而不仅仅是将其嵌入到 HTML 注释中。最好通过示例来展示其功能，因此我们将立即开始安装工具栏。

## 安装 Django Debug Toolbar

工具栏可以在 Python 软件包索引网站上找到：[`pypi.python.org/pypi/django-debug-toolbar`](http://pypi.python.org/pypi/django-debug-toolbar)。安装后，通过添加几个设置即可在 Django 项目中激活调试工具栏。

首先，必须将调试工具栏中间件`debug_toolbar.middleware.DebugToolbarMiddleware`添加到`MIDDLEWARE_CLASSES`设置中。工具栏的文档指出，它应该放在任何其他编码响应内容的中间件之后，因此最好将其放在中间件序列的最后。

其次，需要将`debug_toolbar`应用程序添加到`INSTALLED_APPS`中。`debug_toolbar`应用程序使用 Django 模板来呈现其信息，因此需要在`INSTALLED_APPS`中列出，以便应用程序模板加载程序找到它的模板。

第三，调试工具栏要求将请求的 IP 地址列在`INTERNAL_IPS`中。由于我们在本章早些时候已经进行了此设置更改，因此现在不需要做任何操作。

最后，只有在`DEBUG`为`True`时才会显示调试工具栏。我们一直在调试模式下运行，所以这里也不需要做任何更改。还要注意调试工具栏允许您自定义调试工具栏显示的条件。因此，可以设置工具栏在请求 IP 地址不在`INTERNAL_IPS`中或调试未打开时显示，但对于我们的目的，默认配置就可以了，所以我们不会做任何更改。

不需要的一件事是应用程序本身使用`RequestContext`以便在工具栏中提供 SQL 查询信息等。调试工具栏作为中间件运行，因此不依赖于应用程序使用`RequestContext`来生成信息。因此，如果我们一开始就使用 Django 调试工具栏，就不需要对调查视图进行更改以在`render_to_response`调用上指定`RequestContext`。

## 调试工具栏外观

一旦调试工具栏添加到中间件和已安装应用程序设置中，我们可以通过简单地访问调查应用程序中的任何页面来看看它的外观。让我们从主页开始。返回的页面现在应该看起来像这样：

![调试工具栏外观](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_07.jpg)

请注意，此截图显示了调试工具栏 0.8.0 版本的外观。早期版本看起来会有很大不同，所以如果您的结果不像这样，您可能使用的是不同于 0.8.0 版本的版本。您拥有的版本很可能比写作时可用的版本更新，可能有其他工具栏面板或功能没有在这里介绍。

如您所见，调试工具栏出现在浏览器窗口的右侧。它由一系列面板组成，可以通过更改工具栏配置单独启用或禁用。这里显示的是默认启用的面板。

在更仔细地查看一些单独面板之前，请注意工具栏顶部包含一个隐藏选项。如果选择**隐藏**，工具栏会缩小到一个类似标签的指示，以显示其存在：

![调试工具栏外观](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_08.jpg)

这对于工具栏的扩展版本遮挡页面上的应用程序内容的情况非常有用。单击**DjDT**标签后，工具栏提供的所有信息仍然可以访问；它只是暂时不可见。

大多数面板在单击时会提供详细信息。一些还会在主工具栏显示中提供摘要信息。从调试工具栏版本 0.8.0 开始，列出的第一个面板**Django 版本**只提供摘要信息。单击它不会提供更详细的信息。如您在截图中所见，这里使用的是 Django 1.1.1 版本。

请注意，调试工具栏的当前最新源版本已经为此面板提供了比 0.8.0 版本更多的信息。自 0.8.0 以来，此面板已更名为**版本**，可以单击以提供更多详细信息。这些额外的详细信息包括工具栏本身的版本信息以及为提供版本信息的任何其他已安装的 Django 应用程序的版本信息。

显示摘要信息的另外三个面板是**时间**、**SQL**和**日志**面板。因此，我们可以一眼看出页面的第一次出现使用了 60 毫秒的 CPU 时间（总共用了 111 毫秒的时间），页面需要了四个查询，花费了 1.95 毫秒，请求期间没有记录任何消息。

在接下来的章节中，我们将深入研究每个面板在点击时提供的具体信息。我们将首先从 SQL 面板开始，因为它是最有趣的之一，并且提供了我们在本章前面努力自己获取的相同信息（以及更多信息）。

## SQL 面板

如果我们点击调试工具栏的**SQL**部分，页面将会变成：

![SQL 面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_09.jpg)

乍一看，这个 SQL 查询页面比我们之前想出的要好得多。查询本身被突出显示，使 SQL 关键字更容易阅读。而且，由于它们不是嵌入在 HTML 注释中，它们的内容不需要以任何方式进行修改——没有必要改变包含双破折号的查询内容，以避免它引起显示问题。（现在可能是一个好时机，在我们忘记为什么添加它之前，删除那个额外的查询。）

还要注意，每个查询所列的时间比 Django 默认查询历史中提供的更具体。调试工具栏用自己的查询记录替换了 Django 的查询记录，并以毫秒为单位提供时间，而不是秒。

显示还包括了每个查询所花费时间的图形表示，以水平条形图的形式出现在每个查询的上方。这种表示使人们很容易看出是否有一个或多个查询比其他查询要昂贵得多。实际上，如果一个查询花费的时间过长，它的条形图将会变成红色。在这种情况下，查询时间没有太大的差异，没有一个特别长，所以所有的条形图长度都差不多，并且呈灰色。

更深入地挖掘，我们在本章前面手动找出的一些信息在这个 SQL 查询显示中只需点击一下就可以得到。具体来说，我们可以得到我们的代码中触发特定 SQL 查询的行号。每个显示的查询都有一个**切换堆栈跟踪**选项，点击后将显示与查询相关联的堆栈跟踪：

![SQL 面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_10.jpg)

在这里，我们可以看到所有的查询都是由调查`views.py`文件中的`home`方法发起的。请注意，工具栏会过滤掉 Django 本身的堆栈跟踪级别，这就解释了为什么每个查询只显示了一个级别。第一个查询是由**第 61 行**触发的，其中包含了添加的`filter`调用，用于测试如果记录了一个包含两个连字符的查询会发生什么。其余的查询都归因于**第 66 行**，这是`home`视图中`render_to_response`调用的最后一行。正如我们之前发现的那样，这些查询都是在模板渲染期间进行的。（您的行号可能与此处显示的行号不同，这取决于文件中各种函数的放置位置。）

最后，这个 SQL 查询显示提供了一些我们甚至还没有想到要的信息。在**操作**列下面是每个查询的**SELECT**，**EXPLAIN**和**PROFILE**链接。点击**SELECT**链接会显示数据库在实际执行查询时返回的内容。例如：

![SQL 面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_11.jpg)

类似地，点击**EXPLAIN**和**PROFILE**会显示数据库在被要求解释或分析所选查询时的报告。确切的显示和结果解释将因数据库而异。（事实上，**PROFILE**选项并不适用于所有数据库——它恰好受到了这里使用的数据库，MySQL 的支持。）解释**EXPLAIN**和**PROFILE**的结果超出了本文所涵盖的范围，但值得知道的是，如果您需要深入了解查询的性能特征，调试工具栏可以轻松实现这一点。

我们现在已经深入了几页 SQL 查询显示。我们如何返回到实际应用程序页面？单击主页显示右上角的圈起来的“>>”将返回到上一个 SQL 查询页面，并且圈起来的“>>”将变成圈起来的“X”。单击任何面板详细信息页面上的圈起来的“X”将关闭详细信息并返回到显示应用程序数据。或者，再次单击工具栏上当前显示面板的面板区域将产生与在显示区域上单击圈起来的符号相同的效果。最后，如果您更喜欢使用键盘而不是鼠标，按下*Esc*将产生与单击圈起来的符号相同的效果。

现在我们已经完全探索了 SQL 面板，让我们简要地看一下调试工具栏提供的其他面板。

## 时间面板

单击“时间”面板会显示有关页面生成期间时间花费的更详细信息：

![时间面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_12.jpg)

总 CPU 时间分为用户和系统时间，列出了总经过的（挂钟）时间，并显示了自愿和非自愿的上下文切换次数。对于生成时间过长的页面，关于时间花费在哪里的额外细节可以帮助指向原因。

请注意，此面板提供的详细信息来自 Python 的`resource`模块。这是一个特定于 Unix 的 Python 模块，在非 Unix 类型系统上不可用。因此，在 Windows 上，例如，调试工具栏时间面板只会显示摘要信息，没有更多的详细信息可用。

## 设置面板

单击“设置”会显示所有生效设置的可滚动显示。用于创建此显示的代码与用于在 Django 调试页面上显示设置的代码相同，因此这里的显示将与您在调试页面上看到的相同。

## HTTP 头面板

单击“HTTP 头”会显示请求的所有 HTTP 头：

![HTTP 头面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_13.jpg)

这是调试页面“META”部分中可用信息的子集。如前一章所述，`request.META`字典包含请求的所有 HTTP 头，以及与请求无关的其他信息，因为`request.META`最初是从`os.environ`字典中复制的。调试工具栏选择过滤显示的信息，以包括仅与 HTTP 请求相关的信息，如屏幕截图所示。

## 请求变量面板

单击“请求变量”会显示请求的 cookie、会话变量、GET 变量和 POST 数据。由于调查应用程序主页没有任何信息可显示，因此它的“请求变量”显示并不是很有趣。相反，这里是来自管理员应用程序的一个示例，它确实使用了会话，因此实际上有一些东西可以显示：

![请求变量面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_14.jpg)

在这里，您可以看到由于管理员应用程序使用了`django.contrib.sessions`应用程序而设置的`sessionid` cookie，并且还可以看到已在会话中设置的各个会话变量。

## 模板面板

单击“模板”会显示有关请求的模板处理的信息。以调查主页为例：

![模板面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_15.jpg)

“模板路径”部分列出了`TEMPLATE_DIRS`设置中指定的路径；由于我们没有向该设置添加任何内容，因此它为空。

**模板**部分显示了响应渲染的所有模板。列出了每个模板，显示了应用程序指定的首次渲染的名称。单击此名称将显示实际模板文件内容的显示。在应用程序指定的名称下是模板的完整文件路径。最后，每个模板还有一个**切换上下文**链接，可用于查看每个已呈现模板使用的上下文的详细信息。

**上下文处理器**部分显示了所有安装的上下文处理器。在每个下面都有一个**切换上下文**链接，单击后将显示相关上下文处理器添加到上下文中的上下文变量。

请注意，无论应用程序是否使用`RequestContext`来呈现响应，上下文处理器都会被列出。因此，它们在此页面上列出并不意味着它们设置的变量被添加到此特定响应的上下文中。

## 信号面板

单击**Signals**会显示信号配置的显示：

![信号面板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_16.jpg)

列出了所有定义的 Django 信号。对于每个信号，都显示了提供的参数以及已连接到该信号的接收器。

请注意，此显示不表示当前页面生成过程中实际触发了哪些信号。它只显示信号的配置方式。

## 日志面板

最后，**日志**面板显示了在请求处理过程中通过 Python 的`logging`模块发送的任何消息。由于我们尚未调查在调查应用程序中使用日志记录，并且自 Django 1.1 以来，Django 本身不使用 Python 日志记录模块，因此在此面板上我们没有看到任何内容。

## 调试工具栏处理重定向

现在回想一下我们开始调查调试工具栏的原因：我们发现我们最初用于跟踪页面的 SQL 查询的方法对于返回 HTTP 重定向而不是呈现模板的页面不起作用。调试工具栏如何更好地处理这个问题？要了解这一点，请单击主页上的**Television Trends**链接，为两个问题选择答案，然后单击**提交**。结果将是：

![调试工具栏处理重定向](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_17.jpg)

此页面显示了为什么有时需要在工具栏上使用**隐藏**选项的示例，因为工具栏本身遮挡了页面上的部分消息。隐藏工具栏后，可以看到完整的消息是：

**Django 调试工具栏已拦截重定向到上述 URL 以进行调试查看。您可以单击上面的链接以继续进行正常的重定向。如果要禁用此功能，请将 DEBUG_TOOLBAR_CONFIG 字典的键 INTERCEPT_REDIRECTS 设置为 False。**

调试工具栏在这里所做的是拦截重定向请求，并用包含原始重定向指定位置的渲染响应替换它。工具栏本身仍然存在，并可用于调查我们可能希望查看有关生成重定向的请求处理的任何信息。例如，我们可以单击**SQL**部分并查看：

![调试工具栏处理重定向](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_18.jpg)

这些是处理传入的表单所需的 SQL 查询。毫不奇怪，前四个与我们首次生成表单时看到的完全相同，因为最初对 GET 和 POST 请求都遵循相同的代码路径。

只有在发出这些查询之后，`display_active_survey`视图才对 GET 和 POST 有不同的代码路径。具体来说，在 POST 的情况下，代码是：

```py
    if request.method == 'POST': 
        chosen_answers = [] 
        for qf in qforms: 
            if not qf.is_valid(): 
                break; 
            chosen_answers.append(qf.cleaned_data['answer']) 
        else: 
            for answer in chosen_answers: 
                answer.votes += 1 
                answer.save() 
           return HttpResponseRedirect(reverse('survey_thanks', args=(survey.pk,))) 
```

此页面上列出的第五和第六个查询正在检索在提交的表单上选择的特定答案实例。与 GET 情况不同，在第五和第六个查询中检索了给定问题的所有答案，这些查询还在 SQL WHERE 子句中指定了答案`id`以及问题`id`。在 POST 情况下，不需要检索问题的所有答案；只需要检索选择的那个答案即可。

切换这些查询的堆栈跟踪显示它们是由代码的`if not qf.is_valid()`行导致的。这是有道理的，因为除了验证输入外，`is_valid`方法还会将发布的数据标准化，然后将其放入表单的`cleaned_data`属性中。对于`ModelChoiceField`，标准化值是所选的模型对象实例，因此验证代码需要从数据库中检索所选对象。

在发现两个提交的表单都有效之后，此代码的`else`部分运行。在这里，每个选择的答案的投票计数都会增加，并且更新的`answer`实例将保存到数据库中。然后，这段代码必须负责之前显示的最后四个查询。可以通过检查这四个查询的堆栈跟踪来确认：所有指向代码的`answer.save()`行。

但是为什么需要四个 SQL 语句，两个 SELECT 和两个 UPDATE，来保存两个答案到数据库中？UPDATE 语句是不言自明的，但是在它们之前的 SELECT 语句有点奇怪。在每种情况下，都从`survey_answer`表中选择常量 1，并使用 WHERE 子句指定与正在保存的`survey`匹配的主键值。这个查询的目的是什么？

Django 代码在这里所做的是尝试确定正在保存的`answer`是否已经存在于数据库中，或者是新的。Django 可以通过从 SELECT 返回任何结果来判断在将模型实例保存到数据库时是否需要使用 UPDATE 或 INSERT。选择常量值比实际检索结果更有效，当唯一需要的信息是结果是否存在时。

您可能认为 Django 代码应该知道，仅基于模型实例的主键值已经设置，该实例反映的数据已经在数据库中。但是，Django 模型可以使用手动分配的主键值，因此分配了主键值并不保证模型已经保存到数据库中。因此，在保存数据之前需要额外的 SELECT 来确定模型的状态。

然而，调查应用程序代码肯定知道在处理调查响应时保存的所有`answer`实例已经保存在数据库中。在保存时，调查代码可以通过在保存调用上指定`force_update`来指示必须通过 UPDATE 而不是 INSERT 保存实例：

```py
                answer.save(force_update=True) 
```

如果我们进行更改并尝试提交另一个调查，我们会发现对于这种情况，处理中已经消除了 SELECT 查询，从而将所需的总查询数量从 10 减少到 8：

![调试工具栏的重定向处理](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_19.jpg)

（是的，我意识到之前我说现在不是进行优化的时候，但是我还是进行了一次。这次实在是太容易了。）

我们现在已经介绍了 Django Debug Toolbar 默认显示的所有面板，并看到了它默认处理返回重定向的方式，允许调查导致重定向的处理过程。它是一个非常灵活的工具：它支持添加面板，更改显示的面板，更改工具栏显示的时间，以及配置各种其他选项。讨论所有这些超出了本文的范围。希望所介绍的内容让您对这个工具的强大功能有所了解。如果您有兴趣了解如何配置它的更多细节，可以从其主页链接的 README 开始。

现在我们将离开 Django Debug Toolbar，继续讨论如何通过日志跟踪应用程序代码的内部状态。为此，我们首先要看看没有工具栏时日志是如何显示的，因此此时我们应该在`settings.py`中注释掉工具栏中间件。（请注意，不需要从`INSTALLED_APPS`中删除`debug_toolbar`列表，因为这只是必须为应用程序模板加载器找到中间件指定的模板。）

# 跟踪内部代码状态

有时，即使从像 Django Debug Toolbar 这样的工具中获得的所有信息也不足以弄清楚在处理请求过程中出现错误产生不正确结果的原因。问题可能在应用程序代码的某个地方，但从视觉检查中我们无法弄清楚出了什么问题。为了解决问题，我们需要获取有关应用程序代码内部状态的更多信息。也许我们需要看看应用程序中函数的控制流是什么，或者看看为一些最终导致代码走上错误路径的中间结果计算出了什么值。

我们如何获得这种信息？一种方法是在调试器下运行代码，并逐行执行以查看它在做什么。这种方法将在下一章中详细介绍。这是非常强大的，但可能会耗费时间，在某些情况下并不实用。例如，对于只在生产过程中出现的问题，很难使用。

另一种方法是让代码报告或记录它在做什么。这是本节将要介绍的方法。这种方法并不能提供在调试器下可用的全部信息，但通过选择要记录的内容，它可以提供足够的线索来解决许多问题。它也可以更容易地用于仅在生产过程中出现的问题，而不像在调试器下运行的方法那样。

## 抵制洒播打印的冲动

在开发服务器下运行时，`print`的输出会显示在控制台上，因此很容易访问。因此，当面对一些在开发过程中表现不佳的 Django 应用程序代码时，很容易就会诱惑地在关键点添加临时的`print`语句，试图弄清楚代码内部发生了什么。虽然非常诱人，但通常是一个坏主意。

为什么这是一个坏主意？首先，问题很少会仅凭一个或两个`print`语句就变得明显。起初似乎只要知道代码是否到达这里或那里，一切都会变得清晰。但事实并非如此，我们最终会添加更多的`print`语句，也许打印出变量的值，代码本身和开发服务器控制台都变成了临时调试信息的一团糟。

然后，一旦问题解决了，所有那些`print`语句都需要被移除。我们通常不希望它们在代码或控制台中弄乱输出。移除它们都是一件麻烦事，但是必要的，因为一些生产环境不允许访问`sys.stdout`。因此，从开发调试中留下的`print`可能会在生产过程中导致服务器错误。

然后，当出现相同或类似的问题时，如果以前通过“sprinkle `print`”方法解决了问题，那么几乎所有之前的工作可能需要重新做，以便找出这次出了什么问题。以前的经验可能会给我们一个更好的主意，即在哪里放置`print`语句，但如果在解决第一个问题后已经删除了它们，那么可能需要重新做基本相同的工作，以解决出现的下一个问题变体。这是一种浪费。

这个序列突出了“sprinkle `print`”方法在开发调试中的一些主要问题。首先，开发人员需要在添加`print`的地方立即决定在什么条件下它应该被产生以及输出应该去哪里。可以使用条件语句（如`if settings.DEBUG`）来给添加的`print`语句加上括号，这可能允许添加的调试支持长期保留在代码中，但这很麻烦并且会给代码增加杂乱，因此通常不会这样做。也可以在`print`中指定输出应该被路由到除了默认的`sys.stdout`之外的其他地方，但同样这需要更多的工作，通常也不会这样做。

这些问题导致了“sprinkle `print`”语句的出现，当问题解决后立即被删除，使得代码默认情况下不报告其操作。然后，当下一个问题出现时，开发人员必须重新开始添加调试信息的报告。

更好的方法是在开发过程中使用一些有纪律的日志记录，这样，至少在`DEBUG`被打开时，默认情况下，代码会报告它正在做什么。如果是这样，那么很可能不需要收集额外的调试信息来解决出现的问题。此外，使用日志记录设施允许配置在什么条件下输出消息，以及它们应该去哪里，与实际的日志记录语句分开。

## 开发的简单日志配置

因此，与`print`语句相比，一种更好的调试选择是使用 Python 的`logging`模块。实际的日志调用与`print`一样容易。例如，用于跟踪对`display_active_survey`的调用的`print`可能如下所示：

```py
def display_active_survey(request, survey): 
    print 'display_active_survey called for a %s of survey '\'with pk %s' % (request.method, survey.pk) 
```

这里的`print`报告了已被调用的函数；以及`request.method`和它所传递的调查的主键。在开发服务器控制台上，获取活动调查页面的输出将是：

```py
Django version 1.1.1, using settings 'marketr.settings' 
Development server is running at http://0.0.0.0:8000/ 
Quit the server with CONTROL-C. 
display_active_survey called for a GET of survey with pk 1 
[04/Nov/2009 19:14:10] "GET /1/ HTTP/1.1" 200 2197 

```

只使用 Python 的`logging`的等效调用可能是：

```py
import logging 
def display_active_survey(request, survey): 
    logging.debug('display_active_survey called for a %s of ''survey with pk %s', request.method, survey.pk) 
```

这里使用`logging.debug`调用来指定传递的字符串是调试级别的消息。级别的概念允许调用代码为消息分配重要性的度量，而不实际在当前情况下做出任何关于消息是否应该输出的决定。相反，这个决定是由日志记录设施基于当前设置的日志记录阈值级别做出的。

Python 的`logging`模块提供了一组方便的方法来记录消息，具有默认定义的级别。这些级别依次增加：`debug`、`info`、`warning`、`error`和`critical`。因此，只有在`logging`模块的级别阈值已设置为包括调试级别的消息时，才会输出`logging.debug`消息。

使用`logging.debug`语句代替`print`的唯一问题是，默认情况下，日志模块的级别阈值设置为`warning`。因此，默认情况下只输出`warning`、`error`和`critical`消息。我们需要配置`logging`模块以输出调试级别的语句，以便此消息出现在控制台上。一个简单的方法是在`settings.py`文件中添加对`logging.basicConfig`的调用。我们可以使调用依赖于`DEBUG`是否打开：

```py
import logging
if DEBUG: 
    logging.basicConfig(level=logging.DEBUG)
```

通过将该代码添加到`settings.py`中，并在`display_active_survey`函数中调用`logging.debug`，开发控制台现在将在进入`display_active_survey`函数时显示消息。

```py
Django version 1.1.1, using settings 'marketr.settings' 
Development server is running at http://0.0.0.0:8000/ 
Quit the server with CONTROL-C. 
DEBUG:root:display_active_survey called for a GET of survey with pk 1 
[04/Nov/2009 19:24:14] "GET /1/ HTTP/1.1" 200 2197 

```

请注意，消息上的`DEBUG:root:`前缀是应用于记录消息的默认格式的结果。`DEBUG`表示与消息关联的级别，`root`标识用于记录消息的记录器。由于`logging.debug`调用没有指定任何特定的记录器，因此使用了`root`的默认值。

`logging.basicConfig`的其他参数可用于更改消息的格式，但是在这里我们需要覆盖的 Python 日志的所有功能超出了范围。对于我们的目的，默认格式将很好。

日志配置中可以指定消息的路由。我们在这里没有这样做，因为默认的`sys.stderr`对于开发调试目的已经足够了。

## 决定记录什么

通过从`print`切换到`logging`，我们消除了开发人员添加日志时需要决定在什么条件下产生记录信息以及应该将记录信息放在何处的需要。开发人员只需要确定与消息相关联的重要性级别，然后日志设施本身将决定如何处理记录的信息。那么，接下来应该记录什么呢？

一般来说，在编写代码时很难知道记录哪些信息最有用。作为开发人员，我们可能会猜测一些，但在实际运行代码时，直到我们对代码有了一些经验，才能确定。然而，正如之前提到的，让代码具有一些内置的基本信息报告可能非常有帮助。因此，在最初编写代码时，最好有一些记录的指南要遵循。

这样的一个指南可能是记录所有“重要”函数的进入和退出。输入日志消息应包括任何关键参数的值，退出日志消息应该给出函数返回的一些指示。只有这种类型的输入和退出日志（假设代码合理地分割为可管理的函数），我们将能够清楚地了解代码的控制流。

然而，手动添加条目和退出日志是一件麻烦事。这也会给代码增加混乱。实际上，很少有指南会愉快地遵循记录所有重要函数的进入和退出，除非它比为`display_active_survey`输入先前记录的日志消息更容易。

幸运的是，Python 提供了便利设施，使得我们可以轻松地做到我们在这里寻找的事情。函数可以包装在其他函数中，允许包装函数执行诸如记录输入和输出以及参数和返回信息等操作。此外，Python 装饰器语法允许以最少的额外代码混乱来实现这种包装。在下一节中，我们将为现有的调查应用程序代码开发一些简单的日志包装器。

## 装饰器记录函数的输入和输出

使用通用包装器而不是将输入/输出日志嵌入函数本身的一个缺点是，它使得更难以对记录的参数和返回信息进行精细控制。编写一个记录所有参数或不记录任何参数的通用包装器很容易，但很难或不可能编写一个记录参数的子集的包装器，例如。

为什么不记录所有参数？问题在于 Django 应用程序中一些常用的参数，例如请求对象，具有非常冗长的表示。记录它们的完整值会产生太多的输出。最好从一个不记录任何参数值的通用包装记录器开始，可能还有一个或多个专用包装记录器，用于记录这些参数中的关键信息。

例如，一个用于记录视图函数的进入和退出的专用包装器可能是值得的。视图总是将`HttpRequest`对象作为其第一个参数。虽然记录完整对象并不有用，但记录请求方法既简短又有用。此外，由于视图函数的其他参数来自请求的 URL，它们可能也不会太冗长。

返回值呢？它们应该被记录吗？对于 Django 应用程序来说，通常不会记录，因为它们经常返回`HttpResponse`对象。这些对象通常太大，无法在记录时提供帮助。但是，记录返回值的一些信息，例如它们的类型，通常是有用的。

我们首先提出了两个包装器。第一个将被命名为`log_call`，将记录函数的进入和退出。`log_call`不会记录任何输入参数信息，但它将记录返回结果的类型。第二个包装器将更加专业化，并且将用于包装视图函数。这个将被命名为`log_view`。它将记录请求方法和传递给包装视图的任何额外参数，以及其返回值的类型。

这段代码应该放在哪里？再次强调，它与调查应用程序没有任何关联，因此将其放在`gen_utils`中是有意义的。然后我们将在`gen_utils`中创建一个名为`logutils.py`的文件，该文件可以保存任何通用的日志记录实用程序代码。我们将从先前描述的`log_call`包装器的实现开始：

```py
import logging 

class LoggingDecorator(object): 
    def __init__(self, f): 
        self.f = f 

class log_call(LoggingDecorator): 
    def __call__(self, *args, **kwargs): 
       f = self.f 
       logging.debug("%s called", f.__name__) 
       rv = f(*args, **kwargs) 
       logging.debug("%s returned type %s", f.__name__, type(rv)) 
       return rv 
```

这个实现使用了基于类的编写包装函数的风格。使用这种风格，包装器被定义为一个实现`__init__`和`__call__`方法的类。`__init__`方法在包装器创建时被调用，并且传递了它所包装的函数。`__call__`方法在实际调用包装函数时被调用。`__call__`的实现负责执行包装函数所需的任何操作，调用包装函数，并返回其结果。

在这里，实现分为两个类：基本的`LoggingDecorator`实现`__init__`，然后`log_call`继承自`LoggingDecorator`并实现`__call__`。这种分割的原因是我们可以为多个日志记录包装器共享通用的`__init__`。`__init__`只是保存对稍后在调用`__call__`时使用的包装函数的引用。

然后，`log_call __call__`的实现首先记录一个消息，指出函数已被调用。包装函数的名称可以在其`__name__`属性中找到。然后调用包装函数，并将其返回值保存在`rv`中。然后记录第二个消息，指出被调用函数返回的类型。最后，返回包装函数返回的值。

`log_view`包装器与`log_call`非常相似，只是在记录的细节上有所不同：

```py
class log_view(LoggingDecorator): 
    def __call__(self, *args, **kwargs): 
        f = self.f 
        logging.debug("%s called with method %s, kwargs %s", 
            f.__name__, args[0].method, kwargs) 
        rv = f(*args, **kwargs) 
        logging.debug("%s returned type %s", f.__name__, type(rv)) 
        return rv 
```

在这里，第一个记录的消息包括包装函数的名称，第一个位置参数的`method`属性和传递给包装函数的关键字参数。由于这个包装器是用于包装视图函数的，它假定第一个位置参数是一个`HttpRequest`对象，该对象具有`method`属性。

此外，此代码假定所有其他参数将作为关键字参数传递。我们知道这将是调查应用程序代码的情况，因为所有调查 URL 模式都指定了命名组。如果要支持 URL 模式配置中使用的非命名组，更通用的视图包装器将需要记录`args`（除了第一个参数，即`HttpRequest`对象）。对于调查应用程序，这只会导致记录始终相同的信息，因此在此处已被省略。

## 将装饰器应用于调查代码

现在让我们将这些装饰器添加到调查视图函数中，并看看浏览的一些典型输出是什么样子。添加装饰器很容易。首先，在`views.py`中，在文件顶部附近添加装饰器的导入：

```py
from gen_utils.logutils import log_view, log_call 
```

然后，对于所有实际视图函数，将`@log_view`添加到函数定义之上。（此语法假定正在使用的 Python 版本为 2.4 或更高版本。）例如，对于主页，视图定义如下：

```py
@log_view 
def home(request): 
```

对于`survey_detail`和`survey_thanks`也是一样。对于实用函数`display_active_survey`和`display_completed_survey`，使用`@log_call`。例如：

```py
@log_call 
def display_active_survey(request, survey): 
```

现在当我们在调查网站上浏览时，我们将在控制台上记录有关所调用代码的基本信息的消息。例如，我们可能会看到：

```py
DEBUG:root:home called with method GET, kwargs {} 
DEBUG:root:home returned type <class 'django.http.HttpResponse'> 
[05/Nov/2009 10:46:48] "GET / HTTP/1.1" 200 1184 

```

这显示调用了主页视图，并返回了一个`HttpResponse`。在调查应用程序的日志消息中，我们看到开发服务器的正常打印输出，指出对`/`的`GET`返回了一个带有代码`200`（HTTP OK）和包含`1184`字节的响应。接下来，我们可能会看到：

```py
DEBUG:root:survey_detail called with method GET, kwargs {'pk': u'1'} 
DEBUG:root:display_active_survey called 
DEBUG:root:display_active_survey returned type <class 'django.http.
HttpResponse'> 
DEBUG:root:survey_detail returned type <class 'django.http.HttpResponse'> 
[05/Nov/2009 10:46:49] "GET /1/ HTTP/1.1" 200 2197 

```

这显示了使用`GET`调用`survey_detail`视图，很可能是从先前响应返回的主页上的链接。此外，我们可以看到所请求的特定调查具有主键`1`。下一条日志消息揭示了这必须是一个活动调查，因为调用了`display_active_survey`。它返回了一个`HttpResponse`，与`survey_detail`视图一样，最后的调查日志消息后面又是 Django 自己的打印输出，总结了请求及其结果。

接下来，我们可能会看到：

```py
DEBUG:root:survey_detail called with method POST, kwargs {'pk': u'1'} 
DEBUG:root:display_active_survey called 
DEBUG:root:display_active_survey returned type <class 'django.http.HttpResponse'> 
DEBUG:root:survey_detail returned type <class 'django.http.HttpResponse'> 
[05/Nov/2009 10:46:52] "POST /1/ HTTP/1.1" 200 2466 

```

再次，这看起来像是对先前响应的自然进展：对先前请求检索到的相同调查的`POST`。 `POST`表示用户正在提交调查响应。然而，记录的`HttpResponse`的返回类型表明提交存在问题。（我们知道`HttpResponse`只有在在`display_active_survey`中发现表单无效时才会对`POST`进行响应。）

这可能是我们希望在进入/退出信息之外添加额外日志记录的地方，以跟踪被认为无效的已发布表单的具体原因。在其当前形式中，我们只能知道返回的响应，因为它比原始响应略大（2466 比 2197 字节），很可能包含了一个错误注释，指出需要在表单上修复什么才能使其有效。

接下来，我们可能会看到：

```py
DEBUG:root:survey_detail called with method POST, kwargs {'pk': u'1'} 
DEBUG:root:display_active_survey called 
DEBUG:root:display_active_survey returned type <class 'django.http.HttpResponseRedirect'> 
DEBUG:root:survey_detail returned type <class 'django.http.HttpResponseRedirect'> 
[05/Nov/2009 10:46:56] "POST /1/ HTTP/1.1" 302 0 

```

这开始是对先前请求的重复，对具有主键`1`的调查的`survey_detail`视图的`POST`。然而，这次返回了一个`HttpResponseRedirect`，表明用户必须纠正第一次提交中存在的任何问题。

在此之后，我们可能会看到：

```py
DEBUG:root:survey_thanks called with method GET, kwargs {'pk': u'1'} 
DEBUG:root:survey_thanks returned type <class 'django.http.HttpResponse'> 
[05/Nov/2009 10:46:56] "GET /thanks/1/ HTTP/1.1" 200 544 

```

这显示了浏览器在接收到先前请求返回的重定向时将自动执行的请求。我们看到`survey_thanks`视图记录了与所有先前请求相同的调查的`GET`，并返回了一个`HttpResponse`。

因此，我们可以看到，通过很少的努力，我们可以添加一些基本的日志记录，提供对 Django 应用程序代码控制流的概述。请注意，这里定义的日志装饰器并不完美。例如，它们不支持装饰方法而不是函数，即使不需要日志记录，它们也会带来一些开销，并且由于将函数转换为类而产生一些副作用。

所有这些缺点都可以通过在包装器的开发中进行一些小心处理来克服。然而，这些细节超出了我们在这里可以涵盖的范围。这里介绍的方法具有相对简单的理解优势，足够功能，希望能够展示具有易于使用的内置日志记录机制的控制流以及代码中的一些关键参数的有用性。

## 调试工具栏中的日志记录

回想一下，由于调查应用程序代码中没有日志记录，我们跳过了对调试工具栏的日志面板的任何检查。现在让我们返回调试工具栏，看看添加的日志记录是如何显示的。

首先，让我们添加一个额外的日志消息，以记录导致活动调查的 POST 请求失败的原因。正如在前面的部分中提到的，这可能是有用的信息。因此，在`display_active_survey`函数中，在找到一个无效的表单后添加一个日志调用：

```py
        for qf in qforms: 
            if not qf.is_valid(): 
                logging.debug("form failed validation: %r", qf.errors) 
                break; 
```

（请注意，在使用`logging`之前，还需要添加`import logging`。）有了额外的日志消息，我们应该能够获取有关为什么特定调查提交被视为无效的具体信息。

现在取消`settings.py`中调试工具栏的中间件的注释，重新激活调试工具栏，浏览到一个活动的调查页面，并尝试通过提交不完整的调查来强制生成该日志消息。当返回响应时，单击工具栏的**日志**面板将显示如下页面：

![调试工具栏中的日志记录](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_08_20.jpg)

在这个页面上，我们可以看到除了消息本身及其分配的级别之外，工具栏还报告了它们被记录的日期和时间，以及它们在代码中生成的位置。由于大多数这些日志消息来自包装函数，这里的位置信息并不特别有用。然而，新添加的日志消息正确地匹配了它在代码中的位置。事实上，记录的消息清楚地表明表单的问题是缺少一个答案的选择。

# 总结

我们现在已经讨论完了如何获取有关 Django 应用程序代码运行情况的更多信息的技术。在本章中，我们：

+   开发了一些模板实用程序代码，以跟踪在生成页面时进行了哪些 SQL 请求

+   了解到创建可重用的通用实用程序代码可能会比起初看起来需要更多的工作

+   学习了 Django 调试工具栏如何可以用更少的工作量获得与我们自己编写的代码中相同的信息，以及更多的信息。

+   讨论了在代码开发过程中应用通用日志框架的有用性，而不是依赖于临时的“添加`print`”方法来调试问题

通过使用这些工具和技术，我们能够获取关于代码运行情况的大量信息。当代码正常运行时，对代码行为有很好的理解，这样在出现问题时更容易调试。此外，即使在所有外观上看起来代码正常运行时，检查代码确切的运行情况可能会揭示潜在的问题，这些问题在代码从开发转移到生产过程中可能会变成重大问题。

然而，有时候，即使利用这些技术获得的所有信息也不足以解决手头的问题。在这种情况下，下一步可能是在调试器下运行代码。这是下一章的主题。


# 第九章：当你甚至不知道要记录什么时：使用调试器

对于开发中遇到的许多问题，调试器是最有效的工具，可以帮助弄清楚发生了什么。调试器可以让您逐步查看代码的确切操作，如果需要的话。它可以让您查看并更改沿途的变量值。有了调试器，甚至可以在对源代码进行更改之前测试潜在的代码修复。

本章重点介绍如何使用调试器来帮助调试 Django 应用程序的开发过程。具体来说，在本章中我们将：

+   继续开发调查应用程序，看看 Python 调试器 pdb 如何帮助弄清楚出现的任何问题

+   学习如何使用调试器来验证受多进程竞争条件影响的代码的正确操作

+   简要讨论使用图形调试器调试 Django 应用程序

# 实施调查结果显示

调查应用程序还有一个主要部分尚未实施：显示已完成调查的结果。这种显示应该采取什么形式？对于调查中每个问题的每个答案收到的投票，仅以文本形式进行计数将很容易编写，但不太能有效地传达结果。结果的图形表示，如饼图，将更有效地传达投票的分布情况。

在本章中，我们将探讨几种不同的方法来实施调查结果视图，其中包括使用饼图来显示投票分布。在此过程中，我们将遇到一些困难，并看到 Python 调试器如何帮助弄清楚出了什么问题。

在开始实施用于显示调查结果的代码之前，让我们设置一些测试数据，以便在进行结果测试时使用。我们可以使用现有的**电视趋势**调查，只需调整其数据以反映我们想要测试的内容。首先，我们需要将其“关闭”日期更改为过去两周，这样它将显示为已完成的调查，而不是活动中的调查。

其次，我们需要设置问题答案的“投票”计数，以确保我们测试任何特殊情况。这个“调查”有两个问题，因此我们可以用它来测试答案中有一个明显的单一赢家和答案平局的情况。

我们可以使用管理应用程序在第一个问题上设置获胜者平局：

![实施调查结果显示](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_01.jpg)

在这里，我们已经将**喜剧**和**戏剧**设置为获胜答案的平局。为简单起见，投票总数（5）被保持在较低水平。当扇形应包含总数的五分之一和五分之二时，验证饼图的外观将很容易。

对于第二个问题，我们可以设置数据，以便有一个明显的单一赢家：

![实施调查结果显示](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_02.jpg)

对于这个问题，我们的结果显示应该只列出**几乎没有：我已经看太多电视了！**作为唯一的获胜答案。

# 使用 pygooglechart 显示结果

一旦我们决定要创建饼图，下一个问题是：我们该如何做到这一点？图表创建并不内置于 Python 语言中。但是，有几个附加库提供了这个功能。我们将首先尝试使用最简单的替代方案之一，即`pygooglechart`，它是围绕 Google 图表 API 的 Python 包装器。

`pygooglechart`包可以在 Python 包索引网站[`pypi.python.org/pypi/pygooglechart`](http://pypi.python.org/pypi/pygooglechart)上找到。有关基础 Google 图表 API 的信息可以在[`code.google.com/apis/chart/`](http://code.google.com/apis/chart/)上找到。本章中使用的`pygooglechart`版本是 0.2.0。

使用`pygooglechart`的一个原因非常简单，对于 Web 应用程序来说，构建图表的结果只是一个 URL，可以用来获取图表图像。我们不需要从我们的应用程序生成或提供图像文件。相反，所有的工作都可以推迟到 Google 图表 API，并且我们的应用程序只需包含引用由 Google 提供的图像的 HTML `img`标签。

然后让我们从显示调查结果的模板开始。当前的模板`survey/completed_survey.html`的实现只是打印一个标题，指出调查的标题：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>Survey results for {{ survey.title }}</h1> 
{% endblock content %} 
```

我们现在想要改变这一点，并添加模板代码，循环遍历调查中的问题，并打印出每个问题的结果。请记住，`Question`模型有一个方法（在第三章中实现，*测试 1, 2, 3：基本单元测试*），该方法返回获胜的答案：

```py
class Question(models.Model): 
    question = models.CharField(max_length=200) 
    survey = models.ForeignKey(Survey) 

    def winning_answers(self): 
        max_votes = self.answer_set.aggregate(Max('votes')).values()[0]
        if max_votes and max_votes > 0: 
            rv = self.answer_set.filter(votes=max_votes) 
        else: 
            rv = self.answer_set.none() 
        return rv 
```

然后，在模板中，我们可以使用这个方法来访问获胜的答案（或者在平局的情况下是答案）。对于`Survey`中的每个`Question`，我们将打印出问题文本，获胜答案的列表，以及显示每个`Answer`的投票结果的饼图。执行此操作的模板代码如下：

```py
{% extends "survey/base.html" %} 
{% block content %} 
<h1>Survey results for {{ survey.title }}</h1> 
{% for q in survey.question_set.all %} 
{% with q.winning_answers as winners %} 
{% if winners %} 
<h2>{{ q.question }}</h2> 
<p>Winner{{ winners|length|pluralize }}:</p> 
<ul> 
{% for answer in winners %} 
<li>{{ answer.answer }}</li> 
{% endfor %} 
</ul> 
<p><img src="img/{{ q.get_piechart_url }}" alt="Pie Chart"/></p> 
{% endif %} 
{% endwith %} 
{% endfor %} 
{% endblock content %} 
```

在这里，我们添加了一个`{% for %}`块，它循环遍历传递的调查中的问题。对于每个问题，使用`winning_answers`方法检索获胜答案的列表，并将其缓存在`winners`模板变量中。然后，如果`winners`中有任何内容，则显示以下项目：

+   问题文本，作为二级标题。

+   获胜者列表的标题段落，根据`winners`的长度正确使用复数形式。

+   获胜答案的文本列表，格式为无序列表。

+   一个嵌入式图像，将是答案投票的饼图分解。使用需要在`Question`模型上实现的例程检索此图像的 URL：`get_piechart_url`。

请注意，整个项目列表的显示受到`{% if winners %}`块的保护，以防止尝试为未收到答案的`Question`显示结果的边缘情况。这可能不太可能，但最好永远不要为用户显示可能看起来奇怪的输出，因此在这里的模板级别上，我们在这种情况下简单地避免显示任何内容。

接下来，我们需要为`Question`模型实现`get_piechart_url`方法。在阅读了`pygooglechart` API 之后，初始实现可能是：

```py
    def get_piechart_url(self): 
        from pygooglechart import PieChart3D 
        answer_set = self.answer_set.all() 
        chart = PieChart3D(500, 230) 
        chart.set_data([a.votes for a in answer_set]) 
        chart.set_pie_labels([a.answer for a in answer_set]) 
        return chart.get_url() 
```

此代码检索与`Question`相关联的答案集，并将其缓存在本地变量`answer_set`中。（这是因为在接下来的代码中，该集合被多次迭代，将其缓存在本地变量中可以确保数据只从数据库中获取一次。）然后，调用`pygooglechart` API 创建一个三维饼图`chart`，宽度为 500 像素，高度为 230 像素。然后，为饼图楔设置数据值：这些数据值是集合中每个答案的`votes`计数。接下来，为每个楔设置标签为`answer`值。最后，该方法使用`get_url`方法返回构建图表的 URL。

那效果如何？当我们导航到调查应用程序的主页时，**电视趋势**调查现在应该（因为它的`closes`日期已经设置为已经过去）在指示我们可以看到其结果的标题下列出：

![使用 pygooglechart 显示结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_03.jpg)

现在点击**电视趋势**链接将显示一个已完成的调查结果页面：

![使用 pygooglechart 显示结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_04.jpg)

这不太对。虽然获胜答案列表的文本显示正常，但饼图没有出现。相反，浏览器显示了为图像定义的替代文本**饼图**，这意味着在检索指定图像时出现了问题。

查看页面的 HTML 源代码，我们发现包含图像标签的两个段落看起来像这样：

```py
<p><img src="img/" alt="Pie Chart"/></p>
```

不知何故，`get_piechart_url`方法返回了一个空字符串而不是一个值。我们可能首先要在`get_piechart_url`中添加一些日志，以尝试弄清楚原因：

```py
    def get_piechart_url(self): 
        from pygooglechart import PieChart3D 
        import logging 
        logging.debug('get_piechart_url called for pk=%d', self.pk) 
        answer_set = self.answer_set.all() 
        chart = PieChart3D(500, 230) 
        chart.set_data([a.votes for a in answer_set]) 
        chart.set_pie_labels([a.answer for a in answer_set]) 
        logging.debug('get_piechart_url returning: %s', chart.get_url()) 
        return chart.get_url() 
```

我们已经在进入时添加了一个日志记录，记录了`Question`实例的主键，以及在退出之前记录了方法即将返回的内容。然而，重新加载包含日志的页面会在服务器控制台上产生混乱的输出：

```py
DEBUG:root:survey_detail called with method GET, kwargs {'pk': u'1'} 
DEBUG:root:display_completed_survey called 
DEBUG:root:get_piechart_url called for pk=1 
DEBUG:root:get_piechart_url called for pk=2 
DEBUG:root:display_completed_survey returned type <class 'django.http.HttpResponse'> 
DEBUG:root:survey_detail returned type <class 'django.http.HttpResponse'> 
[14/Nov/2009 11:29:08] "GET /1/ HTTP/1.1" 200 2573 

```

我们可以看到`survey_detail`调用了`display_completed_survey`，并且`get_piechart_url`被调用了两次，但是两次都没有显示它返回了什么消息。发生了什么？在两个`logging.debug`调用之间的代码中没有分支，那么一个是如何执行的，另一个被跳过的呢？

我们可以尝试添加更多的日志调用，插入到每行代码之间。然而，虽然这可能会揭示方法在意外离开之前执行了多远，但它不会提供任何关于为什么执行停止继续到下一行的线索。即使对于像这样小的方法，每行代码之后都添加日志也是一种麻烦。对于这样的问题，调试器是弄清楚发生了什么的更有效的方法。

# 使用调试器入门

调试器是一个强大的开发工具，可以让我们在代码运行时查看代码的运行情况。当程序在调试器的控制下运行时，用户可以暂停执行，检查和更改变量的值，灵活地继续执行到下一行或其他明确设置的“断点”，等等。Python 有一个名为 pdb 的内置调试器，它提供了一个用户界面，本质上是一个增强的 Python shell。除了正常的 shell 命令，pdb 还支持各种特定于调试器的命令，其中许多我们将在本章中进行实验，因为我们调试调查结果显示代码。

那么，我们如何使用 pdb 来帮助弄清楚这里发生了什么？我们想进入调试器并逐步执行代码，看看发生了什么。首先要做的任务是进入调试器，可以通过在我们想要调试器控制的地方添加`import pdb; pdb.set_trace()`来完成。`set_trace()`调用在我们的程序中设置了一个显式断点，执行将在调试器控制下暂停，以便我们可以调查当前状态并控制代码的执行方式。因此，我们可以像这样更改`get_piechart_url`方法来在进入时调用调试器：

```py
    def get_piechart_url(self): 
        from pygooglechart import PieChart3D 
        import logging 
        import pdb; pdb.set_trace() 
        logging.debug('get_piechart_url called for pk=%d', self.pk) 
        answer_set = self.answer_set.all() 
        chart = PieChart3D(500, 230) 
        chart.set_data([a.votes for a in answer_set]) 
        chart.set_pie_labels([a.answer for a in answer_set]) 
        logging.debug('get_piechart_url returning: %s', chart.get_url()) 
        return chart.get_url() 
```

现在，当我们重新加载调查结果页面时，浏览器将在尝试加载页面时出现挂起的情况：

![使用调试器入门](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_05.jpg)

当我们切换到包含`runserver`控制台的窗口时，我们看到：

```py
DEBUG:root:survey_detail called with method GET, kwargs {'pk': u'1'} 
DEBUG:root:display_completed_survey called 
> /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> logging.debug('get_piechart_url called for pk=%d', self.pk) 
(Pdb) 

```

在这里，我们看到对`survey_detail`视图的另一个调用已经完成，它将请求转发到`display_completed_survey`函数。然后，由于在`get_piechart_url`中放置的`pdb.set_trace()`调用，进入了调试器。进入时，调试器打印出两行标识下一行要执行的代码的位置以及该行的内容。因此，我们可以看到我们正在`survey/models.py`文件的第 71 行，在`get_piechart_url`方法中，即将发出调用以记录方法的日志。在两行指出执行停止的地方之后，调试器打印出其提示符`(Pdb)`，并等待用户输入。

在继续逐步执行代码并查看代码运行时发生了什么之前，让我们先看看我们能了解到关于我们所处的位置和当前状态的信息。Pdb 支持许多命令，并不是所有命令都会在这里介绍，而只会演示最常用的一些。我们将从一些有助于了解代码所在位置、如何到达该位置以及传递给当前函数的参数的命令开始。

## list 命令

例如，如果调试器进入时提供的单行上下文不足够，可以使用`list`命令看到更多周围的代码。这个命令，像大多数 pdb 命令一样，可以缩写为它的首字母。在这里使用它我们看到：

```py
(Pdb
) l
 66
 67         def get_piechart_url(self):
 68             from pygooglechart import PieChart3D
 69             import logging
 70             import pdb; pdb.set_trace()
 71  ->         logging.debug('get_piechart_url called for pk=%d', self.pk)
 72             answer_set = self.answer_set.all()
 73             chart = PieChart3D(500, 230)
 74             chart.set_data([a.votes for a in answer_set])
 75             chart.set_pie_labels([a.answer for a in answer_set])
 76             logging.debug('get_piechart_url returning: %s', 
(Pdb)
 77                chart.get_url())
 78             return chart.get_url()
 79
 80     class Answer(models.Model):
 81         answer = models.CharField(max_length=200)
 82         question = models.ForeignKey(Question)
 83         votes = models.IntegerField(default=0)
 84
 85         def __unicode__(self):
 86             return self.answer
 87
(Pdb)

```

在这里，我们看到`list`命令的响应首先显示了当前执行行上面的五行，然后是当前执行行（由`->`前缀标记），然后是当前行之后的五行。在`(Pdb)`提示符下，然后输入了一个空行，这会导致重复输入的最后一个命令。对于`list`，重复命令会导致显示比之前显示的多 11 行。

可以传递参数给`list`命令，以指定要显示的确切行，例如`l 1,5`将显示当前文件中的前五行。

```py
(Pdb) l 1,5
 1     # -*- encoding: utf-8 -*-
 2
 3     import datetime
 4     from django.db import models
 5     from django.db.models import Max
(Pdb)

```

`list`命令最有用，可以看到当前停止执行的代码周围的行。如果需要更多上下文，我发现在编辑器中打开文件比尝试使用带参数的`list`命令更容易获得文件的更完整的图像。

## where 命令

`w` `here`命令（可以缩写为`w`）打印当前的堆栈跟踪。在这种情况下，关于代码如何到达当前位置并没有特别的神秘之处，但检查细节仍然是有益的。

`get_piechart_url`方法在模板渲染期间被调用，这意味着由于模板节点的递归渲染方式，它将具有很长的堆栈跟踪。起初，响应的长度和打印出的内容密度可能会让人感到不知所措，但通过忽略大部分细节，只关注文件和函数的名称，你可以对整体代码流程有一个很好的了解。例如，在响应的开始，这里的`where`命令是：

```py
(Pdb) w 
 /usr/lib/python2.5/site-packages/django/core/management/commands/runserver.py(60)inner_run() 
-> run(addr, int(port), handler) 
 /usr/lib/python2.5/site-packages/django/core/servers/basehttp.py(698)run() 
-> httpd.serve_forever() 
 /usr/lib/python2.5/SocketServer.py(201)serve_forever() 
-> self.handle_request() 
 /usr/lib/python2.5/SocketServer.py(222)handle_request() 
-> self.process_request(request, client_address) 
 /usr/lib/python2.5/SocketServer.py(241)process_request() 
-> self.finish_request(request, client_address) 
 /usr/lib/python2.5/SocketServer.py(254)finish_request() 
-> self.RequestHandlerClass(request, client_address, self) 
 /usr/lib/python2.5/site-packages/django/core/servers/basehttp.py(560)__init__() 
-> BaseHTTPRequestHandler.__init__(self, *args, **kwargs) 
 /usr/lib/python2.5/SocketServer.py(522)__init__() 
-> self.handle() 
 /usr/lib/python2.5/site-packages/django/core/servers/basehttp.py(605)handle() 
-> handler.run(self.server.get_app()) 
 /usr/lib/python2.5/site-packages/django/core/servers/basehttp.py(279)run() 
-> self.result = application(self.environ, self.start_response) 
 /usr/lib/python2.5/site-packages/django/core/servers/basehttp.py(651)__call__() 
-> return self.application(environ, start_response) 
 /usr/lib/python2.5/site-packages/django/core/handlers/wsgi.py(241)__call__() 
-> response = self.get_response(request) 
 /usr/lib/python2.5/site-packages/django/core/handlers/base.py(92)get_response() 
-> response = callback(request, *callback_args, **callback_kwargs) 

```

我们可能并不完全确定所有这些代码在做什么，但像`serve_forever()`、`handle_request()`、`process_request()`、`finish_request()`和`get_response()`这样的名称，似乎这都是标准服务器请求处理循环的一部分。特别是`get_response()`听起来像是代码接近完成为请求生成响应的真正工作的地方。接下来，我们看到：

```py
 /dj_projects/marketr/gen_utils/logutils.py(21)__call__() 
-> rv = f(*args, **kwargs) 
 /dj_projects/marketr/survey/views.py(30)survey_detail() 
-> return display_completed_survey(request, survey) 
 /dj_projects/marketr/gen_utils/logutils.py(11)__call__() 
-> rv = f(*args, **kwargs) 
 /dj_projects/marketr/survey/views.py(40)display_completed_survey() 
-> RequestContext(request)) 

```

实际上，在`get_response`函数中，在调用`callback()`的地方，代码从 Django 代码（`/usr/lib/python2.5/site-packages/django`中的文件）转换为我们自己的代码`/dj_projects`。然后我们看到我们在跟踪中引入了自己的噪音，使用了日志包装函数——在`logutils.py`中的`__call__`的引用。

这些并没有传达太多信息，只是表明正在记录所做的函数调用。但是忽略噪音，我们仍然可以看到`survey_detail`被调用，然后调用了`display_completed_survey`，它运行到即将返回的地方（在`display_completed_survey`中多行调用`render_to_response`的最后一行是结束）。对`render_to_response`的调用又回到了 Django 代码：

```py
 /usr/lib/python2.5/site-packages/django/shortcuts/__init__.py(20)render_to_response() 
-> return HttpResponse(loader.render_to_string(*args, **kwargs), **httpresponse_kwargs) 
 /usr/lib/python2.5/site-packages/django/template/loader.py(108)render_to_string() 
-> return t.render(context_instance) 
 /usr/lib/python2.5/site-packages/django/template/__init__.py(178)render() 
-> return self.nodelist.render(context) 
 /usr/lib/python2.5/site-packages/django/template/__init__.py(779)render() 
-> bits.append(self.render_node(node, context)) 
 /usr/lib/python2.5/site-packages/django/template/debug.py(71)render_node() 
-> result = node.render(context) 
 /usr/lib/python2.5/site-packages/django/template/loader_tags.py(97)render() 
-> return compiled_parent.render(context) 

```

我们可以从这里以及接下来的`render()`和`render_node()`调用中得到的信息是，Django 代码正在处理模板的渲染。最终，一些略有不同的调用开始出现：

```py
 /usr/lib/python2.5/site-packages/django/template/debug.py(87)render() 
-> output = force_unicode(self.filter_expression.resolve(context)) 
 /usr/lib/python2.5/site-packages/django/template/__init__.py(546)resolve() 
-> obj = self.var.resolve(context) 
 /usr/lib/python2.5/site-packages/django/template/__init__.py(687)resolve() 
-> value = self._resolve_lookup(context) 
 /usr/lib/python2.5/site-packages/django/template/__init__.py(722)_resolve_lookup() 
-> current = current() 
> /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> logging.debug('get_piechart_url called for pk=%d', self.pk) 
(Pdb) 

```

在渲染过程中，代码最终到达需要在模板中渲染`{{ q.get_piechart_url }}`值的点。最终，这被路由到了`Question`模型的`get_piechart_url`方法的调用，我们在那里放置了进入调试器的调用，这就是我们现在所处的位置。

## args 命令

`args`命令，缩写为`a`，可用于查看传递给当前执行函数的参数的值：

```py
(Pdb) a 
self = Television Trends (opens 2009-09-10, closes 2009-11-10): What is your favorite type of TV show? 
(Pdb) 

```

## whatis 命令

`whatis`命令显示其参数的类型。例如：

```py
(Pdb) whatis self 
<class 'survey.models.Question'> 
(Pdb) 

```

回想一下，pdb 也像 Python shell 会话一样运行，因此可以通过获取`self`的`type`来获得相同的结果：

```py
(Pdb) type(self) 
<class 'survey.models.Question'> 
(Pdb) 

```

我们还可以查询变量的单个属性，这可能会有所帮助。这里对于`args`命令显示的`self`的值包括了该模型的所有单个属性，但不包括其主键值。我们可以找出它是什么：

```py
(Pdb) self.pk 
1L 
(Pdb) 

```

## print 和 pp 命令

`print`命令，缩写为`p`，打印变量的表示：

```py
(Pdb) p self 
<Question: Television Trends (opens 2009-09-10, closes 2009-11-10): What is your favorite type of TV show?> 
(Pdb)

```

对于大型数据结构，如果`print`的输出跨越了行边界，可能会难以阅读。替代的`pp`命令使用 Python 的`pprint`模块对输出进行漂亮打印。这可能会导致更容易阅读的输出。例如：

```py
(Pdb) p locals() 
{'PieChart3D': <class 'pygooglechart.PieChart3D'>, 'self': <Question: Television Trends (opens 2009-09-10, closes 2009-11-10): What is your favorite type of TV show?>, 'logging': <module 'logging' from '/usr/lib/python2.5/logging/__init__.pyc'>, 'pdb': <module 'pdb' from '/usr/lib/python2.5/pdb.pyc'>} 

```

将`print`输出与`pp`输出进行对比：

```py
(Pdb) pp locals() 
{'PieChart3D': <class 'pygooglechart.PieChart3D'>, 
 'logging': <module 'logging' from '/usr/lib/python2.5/logging/__init__.pyc'>, 
 'pdb': <module 'pdb' from '/usr/lib/python2.5/pdb.pyc'>, 
 'self': <Question: Television Trends (opens 2009-09-10, closes 2009-11-10): What is your favorite type of TV show?>} 
(Pdb) 

```

# 调试 pygooglechart 结果显示

此时我们知道代码处于`get_piechart_url`方法的处理开始阶段，而`self`的当前值表明我们被调用的`Question`实例是询问“你最喜欢的电视节目类型是什么？”这是好事，但我们真正想要了解的是随着执行的继续会发生什么。

## 步骤和下一步命令

我们现在想要指示调试器继续执行，但保持调试器处于活动状态。通常在这里使用两个命令：`step`（缩写为`s`）和`next`（缩写为`n`）。

`step`命令开始执行当前行，并在第一个可用的机会返回到调试器。`next`命令也开始执行当前行，但直到当前函数中的下一行即将执行时才返回到调试器。因此，如果当前行包含函数或方法调用，`step`用于进入该函数并跟踪其执行，而`next`用于执行被调用的函数并在其完成时才返回到调试器。

对于我们现在所处的位置，`next`是我们想要使用的命令，因为我们不特别想要进入日志记录代码并跟踪其执行过程：

```py
(Pdb) n 
DEBUG:root:get_piechart_url called for pk=1 
> /dj_projects/marketr/survey/models.py(72)get_piechart_url() 
-> answer_set = self.answer_set.all() 
(Pdb) 

```

在这里，`next`导致执行`logging.debug`调用，导致记录的消息被打印到控制台。然后调试器再次停止，就在当前函数中的下一行执行之前。输入 nothing 会再次执行`next`命令，导致`answer_set`被赋予`self.answer_set.all()`的值。我们可以使用`print`命令查看结果：

```py
(Pdb) 
> /dj_projects/marketr/survey/models.py(73)get_piechart_url() 
-> chart = PieChart3D(500, 230) 
(Pdb) p answer_set 
[<Answer: Comedy>, <Answer: Drama>, <Answer: Reality>] 
(Pdb) 

```

到目前为止一切看起来都很好，所以我们继续：

```py
(Pdb) n
> /dj_projects/marketr/survey/models.py(74)get_piechart_url() 
-> chart.set_data([a.votes for a in answer_set]) 
(Pdb) 
AttributeError: "'PieChart3D' object has no attribute 'set_data'" 
> /dj_projects/marketr/survey/models.py(74)get_piechart_url() 
-> chart.set_data([a.votes for a in answer_set]) 
(Pdb) 

```

有一个问题：对`chart`上的`set_data`的调用引发了一个属性错误，错误消息指示图表没有这样的属性。我们在实现这个例程时犯了一个错误。虽然`pygooglechart`的许多方法以`set_`开头，但设置图表数据的调用实际上命名为`add_data`。因此，尝试指定图表的数据失败了。但为什么我们没有看到该错误反映为返回的调试页面，而只是从`get_piechart_url`返回了一个空字符串？我们可以通过继续跟踪代码的执行来得到这个问题的答案：

```py
(Pdb) 
--Return-- 
> /dj_projects/marketr/survey/models.py(74)get_piechart_url()->None 
-> chart.set_data([a.votes for a in answer_set]) 

```

这表明`get_piechart_url`方法在引发`AttributeError`时返回`None`。由于我们没有将`get_piechart_url`中的代码包含在`try/except`块中，因此错误正在向上传播调用堆栈。

```py
(Pdb) 
AttributeError: "'PieChart3D' object has no attribute 'set_data'" 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(722)_resolve_lookup() 
-> current = current() 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(723)_resolve_lookup() 
-> except TypeError: # arguments *were* required 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(727)_resolve_lookup() 
-> except Exception, e: 

```

在这里，我们看到调用`get_piechart_url`的代码被包含在`try/except`块中，并且正在测试`except`子句是否与实际引发的异常匹配。第一个子句`except TypeError`没有匹配`AttributeError`。第二个子句`except Exception`匹配，因为`AttributeError`是从基类`Exception`派生的。因此，代码应该继续运行此`except`子句中的任何代码。记住我们可以使用`list`命令来查看那是什么：

```py
(Pdb) l
722                          current = current()
723                      except TypeError: # arguments *were* required
724                          # GOTCHA: This will also catch any TypeError
725                          # raised in the function itself.
726 
current = settings.TEMPLATE_STRING_IF_INVALID #
 invalid method call
727  ->                  except Exception, e:
728                          if getattr(e, 'silent_variable_failure', False
):
729 
current = settings.TEMPLATE_STRING_IF_INVALID
730                          else:
731                             raise
732                      except (TypeError, AttributeError):

```

这些`except`子句似乎在测试特殊情况，其中引发的异常将被抑制，并且产生的结果将被设置为`settings.TEMPLATE_STRING_IF_INVALID`的值。这暗示了这个异常最终不会在调试页面中反映出来，尽管可能不会立即发生在即将执行的`except`子句中：

```py
(Pdb) n
> /usr/lib/python2.5/site-packages/django/template/__init__.py(728)_resolve_lookup() 
-> if getattr(e, 'silent_variable_failure', False): 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(731)_resolve_lookup() 
-> raise 

```

实际上，此时代码正在重新引发异常，只是立即再次被捕获：

```py
(Pdb) n
> /usr/lib/python2.5/site-packages/django/template/__init__.py(732)_resolve_lookup() 
-> except (TypeError, AttributeError): 

```

此时的`list`命令显示了这个`except`子句将要做什么：

```py
(Pdb) l
727                                 except Exception, e:
728                                     if getattr(e, 'silent_variable_failure', False):
729                                         current = settings.TEMPLATE_STRING_IF_INVALID
730                                     else:
731                                         raise
732  ->                 except (TypeError, AttributeError):
733                         try: # list-index lookup
734                             current = current[int(bit)]
735                         except (IndexError, # list index out of range
736                                 ValueError, # invalid literal for int()
737                                 KeyError,   # current is a dict without `int(bit)` key
(Pdb)
738                                 TypeError,  # unsubscriptable object
739                                 ):
740                             raise VariableDoesNotExist("Failed lookup for key [%s] in %r", (bit, current)) # missing attribute
741                     except Exception, e:
742                         if getattr(e, 'silent_variable_failure', False):
743                             current = settings.TEMPLATE_STRING_IF_INVALID
744                         else:
745                             raise
746
747             return current
748
(Pdb)

```

在这里，有必要回想一下在模板渲染期间如何处理`{{ q.get_piechart_url }}`等结构。Django 模板处理尝试使用以下四种方法按顺序解析点号右侧的值：

+   字典查找

+   属性查找

+   方法调用

+   列表索引查找

我们在方法调用尝试的中间进入了调试器，前两个选项失败后。尝试方法调用的代码不区分由于方法不存在而导致的`AttributeError`和由调用方法引发的`AttributeError`，因此下一步将尝试进行列表索引查找。这也将失败：

```py
(Pdb) n
> /usr/lib/python2.5/site-packages/django/template/__init__.py(733)_resolve_lookup() 
-> try: # list-index lookup 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(734)_resolve_lookup() 
-> current = current[int(bit)] 
(Pdb) 
ValueError: "invalid literal for int() with base 10: 'get_piechart_url'" 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(734)_resolve_lookup() 
-> current = current[int(bit)] 

```

具体来说，列表索引查找尝试引发了`ValueError`，我们可以从先前的代码中看到，它将被特殊处理并转换为`VariableDoesNotExist`异常。我们可以继续跟踪代码，但在这一点上很明显会发生什么。无效的变量将被转换为`TEMPLATE_STRING_IF_INVALID`设置分配的内容。由于调查项目将此设置设置为默认的空字符串，因此空字符串是`{{ q.get_piechart_url }}`的渲染的最终结果。

## 继续命令

此时，我们知道问题是什么，问题是如何导致模板中出现空字符串而不是调试页面的问题，我们已经准备好去修复代码。我们可以使用`continue`命令，缩写为`c`，告诉调试器退出并让程序执行正常继续。当我们在这里这样做时，我们看到：

```py
(Pdb) c 
> /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> logging.debug('get_piechart_url called for pk=%d', self.pk) 
(Pdb)

```

发生了什么？我们又回到了起点。原因是调查中有两个问题，模板循环遍历它们。`get_piechart_url`方法为每个问题调用一次。当我们在弄清楚第一个问题发生了什么后退出调试器时，模板处理继续进行，很快又调用了`get_piechart_url`，再次导致`pdb.set_trace()`调用进入调试器。我们可以通过看到`self`现在指的是调查中的第二个问题来确认这一点：

```py
(Pdb) self 
<Question: Television Trends (opens 2009-09-10, closes 2009-11-10): How many new shows will you try this Fall?> 
(Pdb) 

```

我们可以再次`continue`并继续修复我们的 Python 源文件，但这实际上提供了一个机会来使用一些额外的调试器命令，所以我们将这样做。

## 跳转命令

首先，使用`next`来继续到即将在`chart`上调用错误方法的代码行：

```py
(Pdb) n 
DEBUG:root:get_piechart_url called for pk=2 
> /dj_projects/marketr/survey/models.py(72)get_piechart_url() 
-> answer_set = self.answer_set.all() 
(Pdb) n 
> /dj_projects/marketr/survey/models.py(73)get_piechart_url() 
-> chart = PieChart3D(700, 230) 
(Pdb) n 
> /dj_projects/marketr/survey/models.py(74)get_piechart_url() 
-> chart.set_data([a.votes for a in answer_set]) 
(Pdb) 

```

现在，手动发出应该存在的调用，`chart.add_data`：

```py
(Pdb) chart.add_data([a.votes for a in answer_set]) 
0 
(Pdb) 

```

该调用返回了`0`，这比引发属性错误要好得多。现在我们想要跳过错误的代码行。我们可以看到`set_data`调用在`models.py`的第`74`行；我们想要跳过第`74`行，而是直接到第`75`行。我们可以使用`jump`命令，可以缩写为`j`：

```py
(Pdb) j 75 
> /dj_projects/marketr/survey/models.py(75)get_piechart_url() 
-> chart.set_pie_labels([a.answer for a in answer_set]) 
(Pdb)

```

这似乎已经奏效。我们可以通过`next`继续进行，以确认我们在代码中没有错误地前进：

```py
(Pdb) n 
> /dj_projects/marketr/survey/models.py(75)get_piechart_url() 
-> chart.set_pie_labels([a.answer for a in answer_set]) 
(Pdb) n 
> /dj_projects/marketr/survey/models.py(75)get_piechart_url() 
-> chart.set_pie_labels([a.answer for a in answer_set]) 
(Pdb)

```

除了我们似乎没有在前进，我们似乎卡在一行上。不过我们并没有。请注意，该行包括一个列表推导式：`[a.answer for a in answer_set]`。`next`命令将避免跟踪调用的函数，但对于列表推导式却不会。包含推导式的行将对列表中每个项目的添加看起来被执行一次。这可能会变得乏味，特别是对于长列表。在这种情况下，列表只有三个元素，因为集合中只有三个答案，所以我们可以轻松地按回车键继续。但是，也有一种方法可以解决这个问题，我们可能也会学到。

## 断点命令

`break`命令，可以缩写为`b`，在指定的行上设置断点。由于`next`没有像我们希望的那样快速地将我们超过第 75 行，我们可以在第 76 行设置断点，并使用`continue`一步到位地通过第 75 行的列表推导：

```py
(Pdb) b 76 
Breakpoint 1 at /dj_projects/marketr/survey/models.py:76 
(Pdb) c 
> /dj_projects/marketr/survey/models.py(76)get_piechart_url() 
-> logging.debug('get_piechart_url returning: %s', chart.get_url()) 
(Pdb) 

```

这对于跳过除列表推导之外的其他循环结构，或者在代码中快速前进到不需要逐行跟踪的点时，但您确实想要停在稍后的某个地方并查看事物的状态，这将非常有用。

没有参数发出的`break`命令会打印出当前设置的断点列表，以及它们被触发的次数：

```py
(Pdb) b
Num Type         Disp Enb   Where
1   breakpoint   keep yes   at /dj_projects/marketr/survey/models.py:76
 breakpoint already hit 1 time
(Pdb)

```

请注意，由`pdb.set_trace()`产生的断点在此处不包括在内，此显示仅显示通过`break`命令设置的断点。

`break`命令还支持除简单行号之外的其他参数。您可以指定函数名称或另一个文件中的行。此外，您还可以指定必须满足的断点触发条件。这里没有详细介绍这些更高级的选项。然而，Python 文档提供了完整的细节。

## 清除命令

设置断点后，可能会有一段时间你想要清除它。这可以通过`clear`命令来完成，可以缩写为`cl`（不是`c`，因为那是`continue`）：

```py
(Pdb) cl 1 
Deleted breakpoint 1 
(Pdb) 

```

现在调试器将不再停在`models.py`的第 76 行。在这一点上，我们可能已经看到了各种调试器命令，只需输入`c`让代码继续执行：

```py
(Pdb) c 
DEBUG:root:get_piechart_url returning: http://chart.apis.google.com/chart?cht=p3&chs=700x230&chd=s:9UU&chl=Hardly%20any%3A%20I%20already%20watch%20too%20much%20TV%21|Maybe%203-5|I%27m%20a%20TV%20fiend%2C%20I%27ll%20try%20them%20all%20at%20least%20once%21 
DEBUG:root:display_completed_survey returned type <class 'django.http.HttpResponse'> 
DEBUG:root:survey_detail returned type <class 'django.http.HttpResponse'> 
[14/Nov/2009 18:03:38] "GET /1/ HTTP/1.1" 200 2989 

```

在那里，我们看到代码继续处理，记录了从`get_piechart_url`返回的值，并退出了`display_completed_survey`和`survey_detail`。最终，对于此请求返回了一个`2989`字节的响应。切换回到网页浏览器窗口，我们看到浏览器等待了那么长时间才收到响应。此外，我们手动调用了正确的方法并跳过了错误的方法。浏览器显示它能够成功地检索到第二个问题的饼图：

![清除命令](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_06.jpg)

不幸的是，尽管图表已经生成，但标签太长无法正确显示。为了解决这个问题，我们可以尝试使用图例而不是标签。我们将尝试这样做，并将`set_data`更改为`add_data`。

# 修复 pygooglechart 结果显示

我们似乎已经接近了为结果显示创建饼图的工作实现。我们可以更新`get_piechart_url`方法，使其如下所示：

```py
    def get_piechart_url(self): 
        import pdb; pdb.set_trace() 
        answer_set = self.answer_set.all() 
        chart = PieChart3D(500, 230) 
        chart.add_data([a.votes for a in answer_set]) 
        chart.set_legend([a.answer for a in answer_set]) 
        return chart.get_url() 
```

与上一个版本的更改首先是删除了日志调用（因为它们并不特别有用），还删除了日志的导入。`PieChart3D`的导入已经移动到文件顶部，与其他导入一起。对`chart.set_data`的错误调用已被正确的`chart.add_data`替换。最后，对`chart.set_pie_labels`的调用已被替换为`chart.set_legend`，希望当答案被安排为图例时，它们将能够适合图表而不会溢出边缘。

这样做效果如何？如果我们重新加载浏览器页面，浏览器似乎又卡住了，因为`get_piechart_url`方法仍然有`pdb.set_trace()`调用，这会打断调试器。我们可能已经删除了它以及其他更改，希望相信新版本的代码肯定会起作用，但往往这样的希望都会落空，我们发现自己不得不重新添加调用以弄清楚接下来出了什么问题。在这种情况下，还有一些调试器命令可以尝试，我们接下来会做。

## 上下命令

当我们切换到`runserver`控制台窗口时，我们再次发现代码坐在`get_piechart_url`的开头：

```py
DEBUG:root:survey_detail called with method GET, kwargs {'pk': u'1'} 
DEBUG:root:display_completed_survey called 
> /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> answer_set = self.answer_set.all() 
(Pdb) 

```

我们可以继续看看新代码的行为如何，但是有一些调试器命令我们还没有尝试过，所以让我们先做这个。其中一个是`step`命令，之前提到过，但从来没有使用过，因为我们一直使用`next`来逐步执行代码。如果我们在这里尝试`step`几次，我们会看到：

```py
(Pdb) s 
--Call-- 
> /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(319)__get__() 
-> def __get__(self, instance, instance_type=None): 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(320)__get__() 
-> if instance is None: 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(323)__get__() 
-> return self.create_manager(instance, 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(324)__get__() 
-> self.related.model._default_manager.__class__) 
(Pdb) 
--Call-- 
> /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(346)create_manager() 
-> def create_manager(self, instance, superclass): 
(Pdb) 
> /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(350)create_manager() 
-> rel_field = self.related.field 
(Pdb) 

```

在这里，我们单步执行了六次，结果现在嵌套了几个调用级别深入到 Django 代码中。我们是故意这样做的，这通常是了解 Django（或其他支持库）代码工作原理的有用方式。但是在调试时，当我们真正只想单步执行我们自己的代码时，很常见的是错误地开始单步执行支持库代码。然后我们突然发现自己可能深入了几个完全陌生的代码层次，我们想要回到逐步执行我们正在开发的代码。

一种实现这一点的方法是使用`up`命令，可以缩写为`u`。`up`命令将当前堆栈帧上移一个级别：

```py
(Pdb) u 
> /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(324)__get__() 
-> self.related.model._default_manager.__class__) 
(Pdb) u 
> /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> answer_set = self.answer_set.all() 
(Pdb) u 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(722)_resolve_lookup() 
-> current = current() 
(Pdb) 

```

在这里，我们上移了三个级别。原始的当前堆栈帧是调用`create_manager`的堆栈帧。第一个`up`命令将当前堆栈帧切换到`__get__`的堆栈帧，下一个切换到`get_piechart_url`，第三个则回到了`get_piechart_url`的调用者`_resolve_lookup`的堆栈帧。切换当前堆栈帧不会执行任何代码，它只是改变了命令的上下文。例如，现在当前堆栈帧为`_resolve_lookup`，我们可以检查存在于该堆栈帧中的变量：

```py

(Pdb) whatis current 
Function get_piechart_url 
(Pdb) 

```

此外，`list`现在将显示与当前堆栈帧相关联的代码：

```py
(Pdb) l
717                         if callable(current):
718 
if getattr(current, 'alters_data', False):
719                                 current = settings.TEMPLATE_STRING_IF_INVALID
720                             else:
721                                 try: # method call (assuming no args required)
722  ->                                 current = current()
723                                 except TypeError: # arguments *were* required
724                                     # GOTCHA: This will also catch any TypeError
725                                     # raised in the function itself.
726                                     current = settings.TEMPLATE_STRING_IF_INVALID # invalid method call
727                                 except Exception, e:
(Pdb)

```

如果我们切换了堆栈帧，并想知道当前堆栈帧相对于当前执行点的位置，`where`命令会显示出来。在这种情况下，`where`命令的输出看起来像这样：

```py

 /usr/lib/python2.5/site-packages/django/template/__init__.py(687)resolve() 
-> value = self._resolve_lookup(context) 
> /usr/lib/python2.5/site-packages/django/template/__init__.py(722)_resolve_lookup() 
-> current = current() 
 /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> answer_set = self.answer_set.all() 
 /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(324)__get__() 
-> self.related.model._default_manager.__class__) 
 /usr/lib/python2.5/site-packages/django/db/models/fields/related.py(350)create_manager() 
-> rel_field = self.related.field 
(Pdb) 

```

列出的最后一行始终是当前执行点，而当前堆栈帧由第一列中的`>`表示。在这里，它表示当前堆栈帧是`_resolve_lookup`的堆栈帧。

在这种情况下，我们上移了一个堆栈帧，比我们真正想要的多了一个。要回到我们自己的代码，我们需要下移一个级别。这是通过使用`down`命令（可以缩写为`d`）来完成的：

```py

(Pdb) d 
> /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> answer_set = self.answer_set.all() 
(Pdb) 

```

现在，如果我们想要继续从这里运行到下一行，我们可以使用`next`命令：

```py
(Pdb) n 
> /dj_projects/marketr/survey/models.py(72)get_piechart_url() 
-> chart = PieChart3D(500, 230) 
(Pdb) 

```

现在我们回到了熟悉的领域，可以继续调试我们自己的代码。

## 返回命令

第二种实现相同功能的方法是使用`return`命令，可以缩写为`r`。该命令会继续执行，直到当前函数返回，然后再次进入调试器。让我们来看看它的运行情况，让我们步入`PieChart3D`的调用：

```py

(Pdb) s 
--Call-- 
> /var/lib/python-support/python2.5/pygooglechart.py(820)__init__() 
-> def __init__(self, *args, **kwargs): 
(Pdb) 
> /var/lib/python-support/python2.5/pygooglechart.py(821)__init__() 
-> assert(type(self) != PieChart)  # This is an abstract class 
(Pdb) 
> /var/lib/python-support/python2.5/pygooglechart.py(822)__init__() 
-> Chart.__init__(self, *args, **kwargs) 
(Pdb) 

```

我们已经进入了该方法的几个步骤，但只进行了一个调用，因此单个`return`应该让我们回到我们的调查代码：

```py
(Pdb) r 
--Return-- 
> /var/lib/python-support/python2.5/pygooglechart.py(823)__init__()->None 
-> self.pie_labels = [] 
(Pdb) 

```

这种方法显然没有显式的返回行，因此显示的代码行是该方法中的最后一行。输出中的`->None`显示了该方法的返回值。如果我们从这里步进：

```py
(Pdb) s 
> /dj_projects/marketr/survey/models.py(73)get_piechart_url() 
-> chart.add_data([a.votes for a in answer_set]) 
(Pdb) 

```

现在我们回到了创建饼图后的下一行代码。从这里，我们可以使用 return 来查看`get_piechart_url`方法将返回什么：

```py
(Pdb) r 
--Return-- 
> /dj_projects/marketr/survey/models.py(75)get_piechart_url()->'http://chart...Drama|Reality' 
-> return chart.get_url() 
(Pdb) 

```

看起来不错；函数已经完成运行并返回一个值。此外，似乎 pdb 会缩短显示的返回值，如果它们很长，因为显示的值看起来不太对。我们可以用任何一个`print`命令来确认这一点，这些命令显示实际值要长得多：

```py
(Pdb) pp chart.get_url() 
'http://chart.apis.google.com/chart?cht=p3&chs=500x230&chd=s:99f&chdl=Comedy|Drama|Reality' 
(Pdb)

```

目前看来一切都很正常，所以我们可以使用`continue`让程序继续运行，然后当第二个饼图的调试器再次进入时再次使用`continue`：

```py
(Pdb) c 
> /dj_projects/marketr/survey/models.py(71)get_piechart_url() 
-> answer_set = self.answer_set.all() 
(Pdb) c 
DEBUG:root:display_completed_survey returned type <class 'django.http.HttpResponse'> 
DEBUG:root:survey_detail returned type <class 'django.http.HttpResponse'> 
[15/Nov/2009 11:48:07] "GET /1/ HTTP/1.1" 200 3280 

```

这一切看起来都很好。浏览器显示了什么？切换到它的窗口，我们看到以下内容：

![return 命令](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_07.jpg)

这比以前好。从标签切换到图例解决了答案文本溢出图形的问题。然而，饼图本身的大小因答案长度不同而有所不同，这有点令人不安。此外，如果饼图楔形能够用表示每个楔形所代表的总数的百分比进行标记，那就更好了。

在 Google 图表 API 上的更多研究并没有揭示任何控制图例放置的方法，也没有说明如何用信息注释楔形图，比如总百分比。虽然使用起来相当简单和直接，但这个 API 在定制生成的图表方面并没有提供太多功能。因此，我们可能需要调查其他生成图表的替代方法，这将是我们接下来要做的事情。

我们将保留`get_piechart_url`的当前实现，因为在这一点上我们不知道我们是否真的要切换到另一种方法。在继续下一步之前，最好将该函数中的导入`pdb; pdb.set_trace()`删除。该例程现在正在运行，如果我们以后返回使用它，最好是它在没有用户干预的情况下完成运行，而不是进入调试器中断。

# 使用 matplotlib 显示结果

`matplotlib`库提供了另一种从 Python 生成图表的方法。它可以在 Python 软件包索引网站[`pypi.python.org/pypi/matplotlib`](http://pypi.python.org/pypi/matplotlib)上找到。本章中使用的`matplotlib`版本是 0.98.3。

使用`matplotlib`，我们的应用程序不能简单地构造一个 URL 并将生成和提供图像数据的任务交给另一个主机。相反，我们需要编写一个视图来生成和提供图像数据。经过对`matplotlib`API 的一些调查，一个初始实现（在`survey/views.py`中）可能是：

```py
from django.http import HttpResponse 
from survey.models import Question 
from matplotlib.figure import Figure 
from matplotlib.backends.backend_agg import FigureCanvasAgg as \FigureCanvas 

@log_view 
def answer_piechart(request, pk): 
    q = get_object_or_404(Question, pk=pk) 
    answer_set = q.answer_set.all() 
    x = [a.votes for a in answer_set] 
    labels = [a.answer for a in answer_set] 

    fig = Figure() 
    axes = fig.add_subplot(1, 1, 1) 
    patches, texts, autotexts = axes.pie(x, autopct="%.0f%%") 
    legend = fig.legend(patches, labels, 'lower left') 

    canvas = FigureCanvas(fig) 
    response = HttpResponse(content_type='image/png') 
    canvas.print_png(response) 
    return response 
```

这比`pygooglechart`版本要复杂一些。首先，我们需要从`matplotlib`导入两个内容：基本的`Figure`类和一个适合用于渲染图形的后端。在这里，我们选择了`agg`（Anti-Grain Geometry）后端，因为它支持渲染为 PNG 格式。

在`answer_piechart`视图中，前四行很简单。从传递给视图的主键值中检索`Question`实例。该问题的答案集被缓存在本地变量`answer_set`中。然后从答案集创建了两个数据数组：`x`包含每个答案的投票计数值，`labels`包含答案文本值。

接下来，创建了一个基本的`matplotlib Figure`。`matplotlib Figure`支持包含多个子图。对于`Figure`只包含单个图的简单情况，仍然需要调用`add_subplot`来创建子图，并返回一个`Axes`实例，用于在图上绘制。`add_subplot`的参数是子图网格中的行数和列数，然后是要添加到`Figure`的图的编号。这里的参数`1, 1, 1`表示 1 x 1 网格中的单个子图。

然后在返回的子图`axes`上调用`pie`方法生成饼图图。第一个参数`x`是饼图楔形的数据值数组。`autopct`关键字参数用于指定一个格式字符串，用于注释每个饼图楔形的百分比。值`%.0f%%`指定浮点百分比值应该以小数点后零位数字的格式显示，后跟一个百分号。

`pie`方法返回三个数据序列。其中第一个`patches`描述了饼图楔形，需要传递给图例的`legend`方法，以创建一个与楔形相关联的答案值的图例。在这里，我们指定图例应放置在图的左下角。

`pie`返回的另外两个序列描述了文本标签（这里将为空，因为在调用`pie`时未指定`labels`）和楔形图的`autopct`注释。这里的代码不需要使用这些序列做任何事情。

有了图例，图就完成了。使用先前导入的`agg`后端`FigureCanvas`创建了一个`canvas`。创建了一个内容类型为`image/png`的`HttpResponse`，并使用`print_png`方法以 PNG 格式将图像写入响应。最后，`answer_piechart`视图返回此响应。

视图代码完成后，我们需要更新`survey/urls.py`文件，包括一个映射，将请求路由到该视图：

```py
urlpatterns = patterns('survey.views', 
    url(r'^$', 'home', name='survey_home'), 
    url(r'^(?P<pk>\d+)/$', 'survey_detail', name='survey_detail'), 
    url(r'^thanks/(?P<pk>\d+)/$', 'survey_thanks', name='survey_thanks'),
    url(r'^piechart/(?P<pk>\d+)\.png/$', 'answer_piechart', name='survey_answer_piechart'), 
) 
```

在这里，我们添加了最后一个模式。这个模式匹配以`piechart/`开头，后跟一个或多个数字（主键），以`.png`结尾的 URL 路径。这些 URL 被路由到`survey.views.answer_piechart`视图，传递捕获的主键值作为参数。该模式被命名为`survey_answer_piechart`。

切换到使用`matplotlib`而不是`pygooglechart`所需的最后一步是更新`survey/completed_survey.html`模板，以使用这个模式生成 URL。唯一需要的更改是更新包含`img`标签的行：

```py
<p><img src="img/{% url survey_answer_piechart q.pk %}" alt="Pie Chart"/></p> 
```

在这里，我们用引用新添加的模式的`url`模板标签替换了对问题的`get_piechart_url`方法的调用。

这是如何工作的？相当不错。我们没有为图形指定大小，而`matplotlib`的默认大小比我们为`pygooglechart`指定的要大一些，所以我们不能在不滚动的情况下看到整个页面。然而，每个单独的图看起来都很不错。例如，第一个看起来像这样：

![使用 matplotlib 显示结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_08.jpg)

第二个看起来像这样：

![使用 matplotlib 显示结果](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_09.jpg)

`matplotlib` API 支持的定制化远远超出了我们在这里使用的范围。图形的大小可以改变，饼图的位置可以改变，楔形图块的颜色和文本的字体属性也可以改变。获胜答案的饼图楔形可以通过从饼图的其余部分爆炸出来来强调。然而，所有这些项目都是装饰性的，超出了我们将在这里涵盖的范围。回到调试的主题，我们将在下一节中将注意力转向删除一些浪费的重复处理，这是由于切换到`matplotlib`而引入的。

# 改进 matplotlib 方法

考虑一下当浏览器请求完成调查的页面时会发生什么。对于调查中的每个问题，返回的完成调查页面都有一个嵌入的图像，当获取时，将触发对`answer_piechart`视图的调用。该视图动态生成图像，计算成本很高。实际上，根据您的硬件，如果您尝试逐步执行该视图，您可能会观察到在跨越一些`matplotlib`调用时出现明显的暂停。

现在考虑当许多不同的用户请求相同的完成调查页面时会发生什么。这将触发对计算成本高昂的`answer_piechart`视图的多次调用。最终，所有用户将得到完全相同的数据，因为在调查关闭之前不会显示结果，因此用于创建饼图的基础投票计数不会发生变化。然而，`answer_piechart`将一遍又一遍地被调用，以重新做相同数量的工作来产生完全相同的结果。这是对服务器容量的浪费。

我们如何消除这种浪费？有（至少）三种可能的方法：

+   引入缓存，并缓存`answer_piechart`视图的结果。

+   设置一些外部进程，在调查关闭时预先计算所有饼图，并将它们保存在磁盘的某个地方。将完成调查响应模板中的`img`标签更改为引用这些静态文件，而不是动态生成图像的视图。

+   当第一次请求完成调查时，动态生成饼图，并将其保存到磁盘上。这与第二种方法本质上是相同的，因为完成调查响应中的`img`标签现在将引用静态文件，但是图表的计算从某个外部进程移动到了 Web 服务器中。

这些方法各有利弊。我们要追求的是最后一种方法，仅仅是因为它提供了学习一些新东西的最大机会。具体来说，在实现这种第三种方法时，我们将看到如何设置开发服务器以提供静态文件，并且我们将看到如何使用 pdb 来确保代码在面对多进程竞争条件时能够正常运行。

## 设置静态文件服务

到目前为止，在调查应用程序的开发中，我们完全集中在提供动态内容上。虽然动态内容当然是 Django 应用程序的重点，但实际上，即使是最动态的应用程序也会有一些需要从文件中提供的数据。在这里，调查应用程序遇到了一个情况，我们希望从磁盘中提供图像文件。大多数应用程序还将具有最好直接从磁盘而不是通过 Django 视图代码提供的 CSS 和可能是 JavaScript 文件。

Django 是用于提供动态内容的框架。虽然它不直接支持从文件中提供数据，但有一些设置可以方便地将一些静态文件合并到项目中。这些是`MEDIA_ROOT`和`MEDIA_URL`。

`MEDIA_ROOT`是文件系统路径，即项目的静态文件所在目录的路径。Django 在内部使用它作为保存上传到包含`FileField`的模型的文件的基本路径。对于调查应用程序，我们将使用它作为保存动态生成的饼图图像文件的基本路径。

该设置的默认值为空字符串，因此我们现在需要将其设置为其他值：

```py
MEDIA_ROOT = '/dj_projects/marketr/site_media/'
```

在这里，我们将`MEDIA_ROOT`设置为指向主`marketr`项目目录下的`site_media`目录（我们必须创建）。

`MEDIA_URL`也默认为空字符串，是用于引用静态文件的基本 URL 路径。Django 在内部使用它来生成`FileField`模型引用的文件的`url`属性。

此外，`django.core.context_processors.media`上下文处理器通过在模板上设置`MEDIA_URL`，使得该设置的值在模板中可用。此上下文处理器默认启用，因此使用`RequestContext`渲染的任何模板都可以访问`MEDIA_URL`。

让我们在`settings.py`中设置`MEDIA_URL`如下：

```py
MEDIA_URL = '/site_media/' 
```

请注意，不应将`'/media/'`用作`MEDIA_URL`的值。这是`ADMIN_MEDIA_PREFIX`的默认设置，它定义了管理界面使用的静态文件的根 URL。尝试将两个不同的静态文件树放置在 URL 层次结构中的相同位置是行不通的，最简单的方法是将`MEDIA_URL`设置为`'/media/'`以外的其他值。

请注意，尽管这些设置是根据在 URL 路径和磁盘文件之间建立映射的术语定义的，但 Django 不会自动根据该映射来提供文件。在 URL 解析期间，Django 不会测试请求的 URL 是否以`MEDIA_URL`开头，如果是，则提供`MEDIA_ROOT`下找到的相应文件。相反，Django 假设指向磁盘上静态文件的 URL 将直接由 Web 服务器提供，而不会通过 Django 代码路由。

然而，到目前为止，在开发过程中，我们除了 Django 自己的开发服务器之外，没有使用任何其他 Web 服务器。如果我们想继续使用开发服务器，我们需要以某种方式让它提供由调查应用程序创建的图像文件。我们该怎么做呢？

Django 确实提供了静态文件服务功能，特别是在开发过程中使用。要使用它，我们需要更新项目的`urls.py`文件，将以`'site_media/'`开头的 URL 请求路由到 Django 的静态文件服务视图。因此，我们需要更改`urls.py`文件以包含：

```py
from django.conf.urls.defaults import * 

# Uncomment the next two lines to enable the admin: 
from django.contrib import admin 
admin.autodiscover() 

from django.conf import settings 

urlpatterns = patterns('', 
    # Example: 
    # (r'^marketr/', include('marketr.foo.urls')), 

    # Uncomment the admin/doc line below and add # 'django.contrib.admindocs' 
    # to INSTALLED_APPS to enable admin documentation: 
    # (r'^admin/doc/', include('django.contrib.admindocs.urls')), 

    # Uncomment the next line to enable the admin: 
    (r'^admin/', include(admin.site.urls)), 
    (r'^site_media/(.*)$', 'django.views.static.serve', 
        {'document_root': settings.MEDIA_ROOT, 'show_indexes': True}), 
    (r'', include('survey.urls')), 
) 
```

与以前版本的第一个变化是从`django.conf`中添加`settings`的`import`。第二个是添加引用以`site_media/`开头的 URL 的模式。这些 URL 被路由到`django.views.static.serve`。两个参数传递给此视图：`document_root`和`show_indexes`。对于`document_root`，指定了`MEDIA_ROOT`设置，这意味着静态服务器将在`MEDIA_ROOT`下查找请求的文件。对于`show_indexes`，指定了`True`，这意味着当请求的 URL 引用目录而不是文件时，静态服务器将返回文件列表。

## 动态生成图像文件

现在，我们已经设置好了从磁盘提供图像文件的一切，我们可以开始进行必要的代码更改。首先，我们应该从`survey/urls.py`文件中删除`piechart`模式，因为它不再需要。

其次，我们可以更新`views.py`中的`display_completed_survey`函数，以包含在返回完成的调查响应之前确保为调查中的每个问题生成了饼图图像文件的代码：

```py
@log_call 
def display_completed_survey(request, survey): 
    for q in survey.question_set.all(): 
        q.check_piechart() 
    return render_to_response('survey/completed_survey.html', {'survey': survey}, 
        RequestContext(request)) 
```

在这里，我们添加了 `for` 循环，循环遍历调查中的所有问题。对于每个问题，它调用问题的一个新方法 `check_piechart`。此例程将负责确保饼图文件存在，如有必要则创建它。

接下来，我们可以继续移动到 `survey/models.py` 文件，并更新 `Question` 模型以包含 `check_piechart` 的实现以及支持新方法所需的其他任何内容。还需要什么？为了从模板引用饼图 URL，如果 `Question` 模型支持返回相对于 `MEDIA_URL` 的饼图文件的路径，那将会很方便。因此，我们需要在 `Question` 模型中添加两个新方法：

```py
from survey import pie_utils
class Question(models.Model): 
    [… other code unchanged ...]

    @property 
    def piechart_path(self): 
        if self.pk and self.survey.closes < datetime.date.today():
            return pie_utils.PIE_PATH + '%d.png' % self.pk 
        else: 
            raise AttributeError 

    def check_piechart(self): 
        pie_utils.make_pie_if_necessary(self.piechart_path, self.answer_set.all())
```

在 `survey/models.py` 中，我们选择不直接包含大量文件检查和创建代码，而是将该工作分解到 `survey/pie_utils.py` 中的一个新的独立模块中。然后，这里实现的两个例程可以保持非常简单。

`piechart_path` 作为只读属性实现，返回饼图的路径。此值可以与 `MEDIA_URL` 设置结合使用以创建 URL 路径，或者与 `MEDIA_ROOT` 设置结合使用以创建文件系统路径。由于从长远来看，我们期望在树中不仅有饼图图像，因此将饼图放在树的根部是不合适的。因此，`pie_utils.PIE_PATH` 值用于在静态文件树中划出一个子树来容纳饼图。

请注意，如果模型实例尚未保存到数据库，或者引用了尚未关闭的调查，此例程将实现引发 `AttributeError`。在这些情况下，饼图文件不应存在，因此任何尝试引用它都应触发错误。

`check_piechart` 方法被实现为将调用转发到 `pie_utils make_pie_if_necessary` 函数。此函数接受两个参数：饼图的路径和问题的答案集。

在我们继续实现 `pie_utils` 模块之前，我们可以对 `survey/completed_survey.html` 模板进行简单更新。包含 `img` 标签的行需要更改为在创建引用饼图图像的 URL 时使用 `Question` 模型的 `piechart_path`：

```py
<p><img src="img/{{ MEDIA_URL }}{{ q.piechart_path }}" alt="Pie Chart"/></p> 
```

在这里，`piechart_path` 与 `MEDIA_URL`（在调用 `render_to_response` 时，`display_completed_survey` 指定了 `RequestContext`，因此在模板中可用）结合起来构建图像的完整 URL。

最后，我们需要实现 `survey/pie_utils.py` 代码。此模块必须定义 `PIE_PATH` 的值，并实现 `make_pie_if_necessary` 函数。第一个任务是微不足道的，并且可以通过以下方式完成：

```py
import os
from django.conf import settings 
PIE_PATH = 'piecharts/' 
if not os.path.exists(settings.MEDIA_ROOT + PIE_PATH): 
    os.mkdir(settings.MEDIA_ROOT + PIE_PATH)    
```

此代码定义了 `PIE_PATH` 的值，并确保项目的 `MEDIA_ROOT` 下的结果子目录存在，如有必要则创建它。有了这段代码和先前提到的 `MEDIA_ROOT` 设置，调查应用程序的饼图图像文件将放置在 `/dj_projects/marketr/site-media/piecharts/` 中。

完成 `pie_utils` 模块所需的第二部分，`make_pie_if_necessary` 函数的实现，乍看起来也可能很简单。如果文件已经存在，`make_pie_if_necessary` 就不需要做任何事情，否则它需要创建文件。然而，当考虑到这段代码的部署环境最终将是一个潜在的多进程多线程的 Web 服务器时，情况就变得更加复杂了。这引入了竞争条件的机会，我们将在下面讨论。

## 处理竞争条件

`make_pie_if_necessary` 模块的天真实现可能是：

```py
def make_pie_if_necessary(rel_path, answer_set): 
    fname = settings.MEDIA_ROOT + rel_path 
    if not os.path.exists(fname): 
        create_piechart(fname, answer_set) 
```

在这里，`make_pie_if_necessary`通过将传递的相对路径与设置的`MEDIA_ROOT`值相结合来创建完整的文件路径。然后，如果该文件不存在，它调用`create_piechart`，传递文件名和答案集，以创建饼图文件。这个例程可以这样实现：

```py
from matplotlib.figure import Figure 
from matplotlib.backends.backend_agg import FigureCanvasAgg as \FigureCanvas 

def create_piechart(f, answer_set): 
    x = [a.votes for a in answer_set] 
    labels = [a.answer for a in answer_set] 

    fig = Figure() 
    axes = fig.add_subplot(1, 1, 1) 
    patches, texts, autotexts = axes.pie(x, autopct="%.0f%%") 
    legend = fig.legend(patches, labels, 'lower left') 

    canvas = FigureCanvas(fig) 
    canvas.print_png(f) 
```

这段代码基本上是原始`matplotlib`实现中`answer_piechart`视图的修改，以考虑直接传递的答案集，以及应该写入图像数据的文件。

这个`make_pie_if_necessary`的实现，在开发服务器上测试时，可以正常工作。甚至在轻负载的生产环境中，它看起来也可以正常工作。然而，如果考虑到一个高负载的生产环境，其中一个多进程的 Web 服务器可能会几乎同时收到对同一页面的请求，就会出现潜在的问题。没有什么可以阻止几乎同时调用`make_pie_if_necessary`导致多次几乎同时调用`canvas.print_png`来创建相同的文件。

很明显，这种情况在多处理器机器上可能会发生，因为很容易看到两个同时的请求可能会分派到不同的处理器，并导致相同的代码同时在每个处理器上运行。两个进程都检查文件是否存在，都发现不存在，并都开始创建文件。

即使在单处理器机器上，由于操作系统的抢占式调度，也可能出现相同的情况。一个进程可能会检查文件是否存在，发现不存在，然后开始创建文件。然而，在这段代码真正开始创建文件之前，操作系统的抢占式调度器将其挂起，并让处理第二个几乎同时的请求的进程运行。这个进程在检查时也找不到文件，并开始创建文件的路径。

如果发生这种情况，最终结果会是什么？会很糟糕吗？也许不会。可能一个进程会完成创建和写入文件的工作，然后第二个进程会覆盖第一个进程的结果。可能会有一些重复的工作，但最终结果可能还不错：磁盘上包含饼图 PNG 图像的文件。

然而，有没有保证两个几乎同时的调用的工作会像那样被串行化？没有。`matplotlib` API 没有提供任何这样的保证。没有深入研究实现，很难确定，但似乎写出图像文件的任务可能会被拆分成几个不同的单独的写入调用。这为来自引用相同文件的不同进程的随机交错调用提供了充分的机会，最终导致在磁盘上写出损坏的图像文件。

为了防止这种情况发生，我们需要改变`make_pie_if_necessary`函数，使用原子方法检查文件是否存在，并在必要时创建文件。

```py
import errno
def make_pie_if_necessary(rel_path, answer_set): 
    fname = settings.MEDIA_ROOT + rel_path 
    try: 
        fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
        try: 
            f = os.fdopen(fd, 'wb') 
            create_piechart(f, answer_set) 
        finally: 
            f.close() 
    except OSError, e: 
        if e.errno == errno.EEXIST: 
            pass 
        else: 
            raise 
```

这段代码使用传递给`os.open`例程的标志的组合来原子性地创建文件。`os.O_WRONLY`指定文件仅用于写入，`os.O_CREAT`指定如果文件不存在则创建文件，`os.O_EXCL`与`os.O_CREAT`结合使用，指定如果文件存在则引发错误。即使多个进程同时发出这个`os.open`调用，底层实现保证只有一个会成功，其他的会引发错误。因此，只有一个进程将继续执行创建饼图的代码。

请注意，在 Windows 上运行时，`os.O_BINARY`也需要包含在传递给`os.open`的标志集中。如果没有这个标志，Python 会将文件数据视为文本，并在遇到换行符时自动插入回车符。这种行为会导致无法显示的损坏的 PNG 图像文件。

这个改变引入的一个问题是，`os.open`返回的文件描述符不能作为 PNG 数据的目标文件传递给`matplotlib`。`matplotlib`库接受文件名或 Python 文件对象，但不支持`os.open`返回的文件描述符。因此，这里的代码使用`os.fdopen`将文件描述符转换为 Python 文件对象，并将返回的文件传递给`create_piechart`例程。

在`os.open`调用引发`OSError`的情况下，将测试异常的`errno`属性是否等于`errno.EEXIST`。这是文件已经存在时将引发的特定错误，不应该作为错误反映出来，而应该被忽略。任何其他错误都会反映给`make_pie_if_necessary`的调用者。

这些更改确保图像文件只会被创建一次，这是好的。然而，还有另一个潜在的问题。考虑一下现在同时进行多个请求会发生什么。只有一个请求会继续创建文件。其他所有请求都会看到文件已经存在，然后简单地发送一个引用它的响应。

但请注意，文件的存在并不能保证图像数据已经被写入其中：首先需要进行相当多的处理来创建图像，然后才会将其写入文件。有没有保证这个处理会在收到和处理文件请求之前完成？没有。根据客户端的速度和图像生成的速度，有可能在图像数据实际写入文件之前，文件的请求已经到达并被处理。

这可能会发生吗？可能不会。如果发生了会有什么影响？可能没有什么可怕的。可能浏览器会显示一个部分图像或者**饼图**的替代文本。用户可能会尝试重新加载页面，看看第二次是否更好，那时图像文件可能会被正确地提供。

考虑到这种情况发生的可能性似乎很小，而且影响也相当小，我们可能选择不修复这个特定的问题。然而，在某些情况下，可能需要确保文件不仅存在，而且还包含数据。调查修复这个潜在问题可能是值得的。一种方法是修改`make_pie_if_necessary`如下：

```py
import fcntl
def make_pie_if_necessary(rel_path, answer_set): 
    fname = settings.MEDIA_ROOT + rel_path 
    try: 
        fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
        try: 
            f = os.fdopen(fd, 'wb') 
            fcntl.flock(f, fcntl.LOCK_EX) 
            create_piechart(f, answer_set) 
        finally: 
            fcntl.flock(f, fcntl.LOCK_UN) 
            f.close() 
    except OSError, e: 
        if e.errno == errno.EEXIST: 
            wait_for_data(fname) 
        else: 
            raise 
```

这里的第一个改变是在调用`create_piechart`之前，使用`fcntl.flock`在文件上获取独占锁。（注意，`fcntl`是一个仅适用于 Unix 的 Python 模块。因此，这段代码在 Windows 上不起作用。有一些附加包可以在 Windows 上获得文件锁定功能，但具体使用它们的细节超出了本文的范围。）第二，这个文件锁在`create_piechart`返回后关闭文件之前被释放。第三，在发现文件已经存在的情况下，不是立即返回，而是调用一个新的`wait_for_data`函数。`wait_for_data`的实现是：

```py
import time
def wait_for_data(fname): 
    try: 
        fd = os.open(fname, os.O_RDONLY) 
        empty = True 
        while empty: 
            fcntl.flock(fd, fcntl.LOCK_SH) 
            st = os.fstat(fd) 
            if st.st_size > 0: 
                empty = False 
            fcntl.flock(fd, fcntl.LOCK_UN) 
            if empty: 
                time.sleep(.5) 
    finally: 
        if fd: 
            os.close(fd) 
```

这段代码首先打开文件进行读取。然后假设文件为空，并进入一个循环，只要文件保持为空就会继续进行。在循环中，代码获取文件的共享锁，然后调用`os.fstat`来确定文件的大小。如果返回的大小不为零，则将`empty`设置为`False`，这将在此迭代结束时终止循环。在此之前，文件锁被释放，如果文件实际上为空，代码会在继续下一次循环之前睡眠半秒钟。这个睡眠是为了给另一个进程，可能正忙于创建和写入数据，完成工作的时间。在返回之前，文件被关闭（如果它曾经成功打开）。

这一切看起来都很好，在我们尝试在浏览器中测试时似乎运行良好。然而，仅仅通过对这样的代码进行视觉检查，很难确定它是否完全正确。在这里使用调试器人为地创建我们试图防范的竞争条件可能会有所帮助。我们接下来将这样做。

## 使用调试器来强制发生竞争情况

仅仅使用开发服务器是无法强制发生竞争条件的：它是单线程和单进程的。然而，我们可以将开发服务器与`manage.py shell`会话结合使用，通过调试器断点和单步执行，来强制进行任何我们想要测试的多进程交错执行的组合。

例如，我们可以在`make_pie_if_necessary`函数的顶部附近插入一个断点：

```py
def make_pie_if_necessary(rel_path, answer_set): 
    fname = settings.MEDIA_ROOT + rel_path 
    try: 
        import pdb; pdb.set_trace()
        fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
```

现在，我们需要从磁盘中删除任何已经生成的图像文件，这样当这个函数首次被调用时，它将沿着尝试创建文件的路径进行：

```py
rm /dj_projects/marketr/site_media/piecharts/*

```

接下来，我们确保开发服务器正在运行，并从浏览器中重新加载**电视趋势**调查的结果页面。浏览器将会出现卡住的情况，在开发服务器控制台中我们将看到调试器已进入：

```py
> /dj_projects/marketr/survey/pie_utils.py(13)make_pie_if_necessary() 
-> fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
(Pdb) 

```

如果我们使用`next`来跳过这个调用，我们将看到：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(14)make_pie_if_necessary() 
-> try: 
(Pdb) 

```

代码执行到了下一行，所以`os.open`调用是成功的。这个线程现在被冻结在文件已经被创建但尚未写入数据的地方。我们希望验证另一个调用相同函数的进程是否会正确地等待文件数据被写入后再继续。为了测试这一点，我们可以在一个单独的窗口中启动`manage.py shell`，手动检索适当的问题，并调用它的`check_piechart`方法：

```py
kmt@lbox:/dj_projects/marketr$ python manage.py shell 
Python 2.5.2 (r252:60911, Oct  5 2008, 19:24:49) 
[GCC 4.3.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information. 
(InteractiveConsole) 
>>> from survey.models import Question 
>>> q = Question.objects.get(pk=1) 
>>> q.check_piechart() 
> /dj_projects/marketr/survey/pie_utils.py(13)make_pie_if_necessary() 
-> fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
(Pdb) 

```

`make_pie_if_necessary`中的断点再次在调用打开文件之前停止执行。在这种情况下，当我们使用 next 来跳过调用时，我们应该看到代码走了不同的路径，因为文件已经存在：

```py
(Pdb) n 
OSError: (17, 'File exists', '/dj_projects/marketr/site_media/piecharts/1.png') 
> /dj_projects/marketr/survey/pie_utils.py(13)make_pie_if_necessary() 
-> fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(21)make_pie_if_necessary() 
-> except OSError, e: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(22)make_pie_if_necessary() 
-> if e.errno == errno.EEXIST: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(23)make_pie_if_necessary() 
-> wait_for_data(fname) 
(Pdb) 

```

看起来不错。通过逐步执行代码，我们看到`os.open`引发了一个`OSError`，其`errno`属性为`errno.EEXIST`，正如预期的那样。然后，shell 线程将继续等待文件有数据。如果我们进入该例程，我们可以看到它是否按我们的预期运行：

```py
(Pdb) s 
--Call-- 
> /dj_projects/marketr/survey/pie_utils.py(43)wait_for_data() 
-> def wait_for_data(fname): 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(44)wait_for_data() 
-> try: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(45)wait_for_data() 
-> fd = os.open(fname, os.O_RDONLY) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(46)wait_for_data() 
-> empty = True 
(Pdb) 

```

此时，我们已经在这个例程中进行了初步处理。文件现在已经打开，并且`empty`已经被初始化为`True`。我们准备进入循环的第一次迭代。应该发生什么？由于另一个控制线程仍然被阻塞，甚至在获得文件的独占锁之前，这个线程应该能够获得文件的共享锁，测试文件大小，并最终因为空文件而睡眠半秒钟。通过逐步执行，我们看到确实发生了这种情况：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(47)wait_for_data() 
-> while empty: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(48)wait_for_data() 
-> fcntl.flock(fd, fcntl.LOCK_SH) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(49)wait_for_data() 
-> st = os.fstat(fd) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(50)wait_for_data() 
-> if st.st_size > 0: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(52)wait_for_data() 
-> fcntl.flock(fd, fcntl.LOCK_UN) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(53)wait_for_data() 
-> if empty: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(54)wait_for_data() 
-> time.sleep(.5) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(47)wait_for_data() 
-> while empty: 
(Pdb) 

```

由于文件尚未被另一个线程锁定，`fcntl.flock`立即返回。这段代码发现文件大小为零，继续睡眠半秒钟，现在开始第二次循环的迭代。让我们将它推进到它再次获得文件的共享锁的地方：

```py
> /dj_projects/marketr/survey/pie_utils.py(48)wait_for_data() 
-> fcntl.flock(fd, fcntl.LOCK_SH) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(49)wait_for_data() 
-> st = os.fstat(fd) 
(Pdb) 

```

我们现在将让这个线程在这里被冻结，返回到开发服务器线程，并尝试在其中继续前进：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(15)make_pie_if_necessary() 
-> f = os.fdopen(fd, 'wb') 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(16)make_pie_if_necessary() 
-> fcntl.flock(f, fcntl.LOCK_EX) 
(Pdb) n 

```

这段代码无法继续很远。它确实将文件描述符转换为 Python 文件对象，但接下来的调用是对文件获取独占锁，而该调用已被阻塞——在最后的`n`命令中没有`(Pdb)`提示，因此执行已在调用内的某个地方停止。这很好，因为调用获取独占锁不应该在其他线程释放锁之前返回。

我们可以切换回到该线程，并将其推进到释放锁的地方：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(50)wait_for_data() 
-> if st.st_size > 0: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(52)wait_for_data() 
-> fcntl.flock(fd, fcntl.LOCK_UN) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(53)wait_for_data() 
-> if empty: 
(Pdb) 

```

当我们跳过释放锁的调用时，开发服务器控制台立即返回到`(Pdb)`提示符：

```py
> /dj_projects/marketr/survey/pie_utils.py(17)make_pie_if_necessary() 
-> create_piechart(f, answer_set) 
(Pdb) 

```

这个线程现在对文件有独占锁，如果我们保持它在这一点上被冻结，我们应该看到另一个线程在尝试获取共享锁时会被阻塞：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(54)wait_for_data() 
-> time.sleep(.5) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(47)wait_for_data() 
-> while empty: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(48)wait_for_data() 
-> fcntl.flock(fd, fcntl.LOCK_SH) 
(Pdb) n 

```

看起来很好，这个线程已经被阻塞。现在它应该无法获得锁，直到开发服务器线程释放它，此时文件将有数据。让我们推进开发服务器线程：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(19)make_pie_if_necessary() 
-> fcntl.flock(f, fcntl.LOCK_UN) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(20)make_pie_if_necessary() 
-> f.close() 
(Pdb) 

```

在这里，我们跳过了创建饼图的调用，以及解锁文件的调用。在那时，shell 线程停止了阻塞：

```py
> /dj_projects/marketr/survey/pie_utils.py(49)wait_for_data() 
-> st = os.fstat(fd) 
(Pdb) 

```

这个线程现在应该看到文件有数据：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(50)wait_for_data() 
-> if st.st_size > 0: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(51)wait_for_data() 
-> empty = False 
(Pdb) 

```

看起来不错；代码将`empty`设置为`False`，这应该在释放共享锁的任务完成后触发循环的结束：

```py
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(52)wait_for_data() 
-> fcntl.flock(fd, fcntl.LOCK_UN) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(53)wait_for_data() 
-> if empty: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(47)wait_for_data() 
-> while empty: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(56)wait_for_data() 
-> if fd: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(57)wait_for_data() 
-> os.close(fd) 
(Pdb) n 
--Return-- 
> /dj_projects/marketr/survey/pie_utils.py(57)wait_for_data()->None 
-> os.close(fd) 
(Pdb) 

```

确实，代码继续退出循环，关闭文件并返回。我们可以输入`c`来继续这里，并获得常规的 shell 提示符。此时我们也可以让开发服务器继续，它将重新进入调试器以处理第二个饼图：

```py
(Pdb) c 
> /dj_projects/marketr/survey/pie_utils.py(13)make_pie_if_necessary() 
-> fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
(Pdb)

```

我们完成了吗？或者在这一点上我们可能还想测试其他东西吗？一切看起来都很好，但你可能已经注意到在代码中跟踪时的一件事是，等待文件数据的第二个线程在第一个线程实际关闭文件之前被允许继续。这可能是个问题吗？在没有显式调用将数据刷新到磁盘的情况下，可能会在内存中缓冲数据，并且直到文件关闭才会实际写入。根据这需要多长时间，假设文件现在已经准备好供另一个线程读取，那么可能会遇到麻烦，因为实际上并非所有数据都可以供单独的线程读取。

我们可以测试一下这种情况吗？是的，我们可以使用开发服务器的第二个请求来看看是否可能存在问题。在这种情况下，我们在调用创建文件之前让开发服务器被阻塞，然后从 shell 会话中继续检索第二个问题并调用其`check_piechart`方法：

```py
>>> q = Question.objects.get(pk=2) 
>>> q.check_piechart() 
> /dj_projects/marketr/survey/pie_utils.py(13)make_pie_if_necessary() 
-> fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(14)make_pie_if_necessary() 
-> try: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(15)make_pie_if_necessary() 
-> f = os.fdopen(fd, 'wb') 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(16)make_pie_if_necessary() 
-> fcntl.flock(f, fcntl.LOCK_EX) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(17)make_pie_if_necessary() 
-> create_piechart(f, answer_set) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(19)make_pie_if_necessary() 
-> fcntl.flock(f, fcntl.LOCK_UN) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(20)make_pie_if_necessary() 
-> f.close() 
(Pdb) 

```

在这里，我们在 shell 会话中一直进行到锁定文件、创建饼图和解锁文件。我们还没有关闭文件。现在，如果我们在开发服务器中继续，它将看到文件存在并且有数据：

```py
(Pdb) n 
OSError: (17, 'File exists', '/dj_projects/marketr/site_media/piecharts/2.png') 
> /dj_projects/marketr/survey/pie_utils.py(13)make_pie_if_necessary() 
-> fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(21)make_pie_if_necessary() 
-> except OSError, e: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(22)make_pie_if_necessary() 
-> if e.errno == errno.EEXIST: 
(Pdb) n 
> /dj_projects/marketr/survey/pie_utils.py(23)make_pie_if_necessary() 
-> wait_for_data(fname) 
(Pdb) n 
--Return-- 
> /dj_projects/marketr/survey/pie_utils.py(23)make_pie_if_necessary()->None 
-> wait_for_data(fname) 
(Pdb) n 
--Return-- 
(Pdb)

```

看起来不错；在这种情况下，代码走了正确的路径。但是如果我们从这里继续，仍然没有给 shell 线程关闭文件的机会，那么浏览器对这个图像文件的后续请求是否会成功呢？我们可以通过在这里输入`c`来测试一下，并检查浏览器对第二个饼图的显示。看起来我们有问题：

![使用调试器来强制竞争情况](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/dj11-test-dbg/img/7566_09_10.jpg)

要么我们破坏了生成饼图的代码，要么这是为了提供一个尚未完全写入磁盘的图像文件的结果。后者似乎更有可能。我们该如何解决这个问题？我们可以更改`make_pie_if_necessary`函数，在释放独占锁之前将数据刷新到磁盘：

```py
def make_pie_if_necessary(rel_path, answer_set): 
    fname = settings.MEDIA_ROOT + rel_path 
    try: 
        import pdb; pdb.set_trace() 
        fd = os.open(fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL) 
        try: 
            f = os.fdopen(fd, 'wb') 
            fcntl.flock(f, fcntl.LOCK_EX) 
            create_piechart(f, answer_set) 
        finally: 
            f.flush() 
            os.fsync(f.fileno()) 
            fcntl.flock(f, fcntl.LOCK_UN) 
            f.close() 
    except OSError, e: 
       if e.errno == errno.EEXIST: 
            wait_for_data(fname) 
       else: 
            raise 
```

查阅 Python 文档显示，需要对文件进行`flush`和调用`os.fsync`，以确保所有文件数据实际上被写入磁盘，因此我们在解锁文件之前添加了这两个调用。

这样行得通吗？测试它意味着再次删除图像文件，再次强制我们要进行的竞争条件。这里没有包括详细的输出，但确实，如果我们强制一个新的 shell 会话成为创建第二个图像文件的线程，在它关闭文件之前停止它，并让开发服务器线程继续发送完成的调查响应页面，然后提供图像文件，我们会在浏览器中看到完整的第二个图像。因此，添加`flush`和`os.fsync`的调用似乎可以解决问题。

这个练习展示了编写正确处理竞争条件的代码有多么困难。不幸的是，这种竞争条件通常无法在 Web 应用程序中避免，因为它们通常会部署在多线程、多进程的 Web 服务器中。调试器是确保处理这些条件的代码按预期工作的宝贵工具。

# 使用图形调试器的注意事项

在本章中，我们专注于使用 Python 命令行调试器 pdb。图形集成开发环境，如 Eclipse、NetBeans 和 Komodo 也提供了可以用于 Django 应用程序代码的调试器（尽管有些需要安装特定插件来支持 Python 代码的开发）。设置和使用这些环境的细节超出了本文的范围，但下面将包括一些关于在 Django 应用程序中使用图形调试器的一般说明。

首先，使用图形调试器有一些明显的优势。通常，图形调试器会提供单独的窗格，显示当前执行的源代码、程序堆栈跟踪、本地变量和程序输出。这可以让您快速地对程序的状态有一个整体的感觉。在 pdb 中做到这一点往往更难，您必须运行单独的命令来获取相同的信息，并且在它们从屏幕上滚动出去后能够记住结果。

图形调试器的第二个优势是，通常可以通过在调试器中选择代码行并选择菜单项来设置断点。因此，您可以轻松地进行调试，而无需更改源代码以包含显式的断点进入调试器。

图形调试器中断点的一个要求是，在调试器中启动开发服务器的`runserver`命令必须指定`--noreload`选项。没有这个选项，当检测到磁盘上的运行代码已更改时，开发服务器会自动重新加载自身。这种重新加载机制会干扰图形调试器用于触发断点激活调试器的方法，因此在运行服务器时必须通过指定`--noreload`来禁用它。

当然，这样做的一个缺点是，集成开发环境中运行的开发服务器在代码更改后不会自动重新加载。如果你已经习惯了从简单命令行运行时的自动重新加载功能，可能很难记住在进行代码更改后需要手动重新启动服务器。

使用图形调试器时需要注意的另一件事是调试器本身可能会触发意外行为。例如，为了显示本地变量的值，调试器必须询问它们的值。对于`QuerySets`这样的本地变量，这可能意味着调试器会导致数据库交互，而应用程序本身永远不会发起。因此，调试器在尝试显示本地变量的值时，可能会在应用程序本身不会触发的地方触发`QuerySets`的评估。

`QuerySets`只是调试器可能引入意外行为的一个例子。基本上，调试器可能需要在幕后运行大量代码才能完成其工作，而这些幕后工作可能会产生副作用。这些副作用可能会干扰或不干扰调试应用程序代码的任务。如果它们干扰了（通常是在调试器下运行时出现意外结果），与其试图弄清楚调试器幕后到底发生了什么，不如换用不同的调试技术可能更有效。

# 总结

这就是我们讨论开发 Django 应用程序代码时使用调试器的结束。在本章中，我们：

+   使用`pygooglechart`实现了显示调查结果的功能，以创建饼图。当我们在这个过程中遇到一些麻烦时，我们看到了 Python 调试器 pdb 如何帮助我们找出问题出在哪里。我们尝试了许多最有用的 pdb 命令。我们学会了查看正在运行的代码的上下文，检查和更改变量的值，并灵活地控制代码在调试器中的执行过程的命令。

+   使用`matplotlib`库重新实现了显示调查结果的功能。对于这种替代实现，我们最终需要编写容易受到多进程竞争条件影响的代码。在这里，我们看到了 pdb 如何帮助验证这种类型代码的正确行为，因为它允许我们强制出现问题的竞争条件，然后验证代码对这种情况的行为是否正确。

+   最后，讨论了使用图形调试器来开发 Django 应用程序代码的一些利弊。

在下一章中，我们将学习在开发过程中遇到问题时该怎么办，而目前讨论的调试技术似乎都无法解决这些问题。
