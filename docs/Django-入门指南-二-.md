# Django 入门指南（二）

> 原文：[`zh.annas-archive.org/md5/2CE5925D7287B88DF1D43517EEF98569`](https://zh.annas-archive.org/md5/2CE5925D7287B88DF1D43517EEF98569)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Django 表单

我们都知道 HTML 表单。这是一个包含`<input>`和`<select>`标签的`<form>`标签。用户可以填写或编辑这些项目并将它们返回到服务器。这是存储客户端提供的数据的首选方式。像 Django 这样的框架利用了 HTML 表单来使其更好。

Django 表单继承自`Form`类对象。这是一个我们将设置属性的对象。这些属性将是表单中的字段，我们将定义它们的类型。

在本章中，我们将学习如何执行以下操作：

+   创建 HTML 表单

+   处理表单发送的数据

+   创建 Django 表单

+   验证和操作从 Django 表单发送的数据

+   基于模型创建表单

+   自定义错误消息并使用小部件

Django 表单的优点如下：

+   对抗 CSRF 漏洞可以很容易地实现。我们将在此后讨论 CSRF 漏洞。

+   数据验证是自动的。

+   表单可以很容易地定制。

但比较标准 HTML 表单和 Django 表单的最佳方法是通过一个例子来练习：添加开发者的表单。

# 不使用 Django 表单添加开发者

在本节中，我们将向您展示如何在不使用 Django 表单的情况下添加开发者。这个例子将展示使用 Django 可以节省多少时间。

将以下 URL 添加到您的`urls.py`文件中：

```py
url(r'^create-developer$', 'TasksManager.views.create_developer.page', name="create_developer"),
```

## HTML 表单模板

我们将在视图之前创建一个模板。实际上，我们将用包含表单的模板填充视图。我们没有把所有字段都放在模型中，因为代码太长了。使用更短的代码学习更好。以下是我们的模板`template/en/public/create_developer.html`：

```py
{% extends "base.html" %}
{% block title_html %}
  Create Developer 
{% endblock %}
{% block h1 %}
  Create Developer
{% endblock %}
{% block article_content %}
  <form method="post" action="{% url "create_developer" %}" >
    <table>
      <tr>
        <td>Name</td>
        <td>
          <input type="text" name="name" />
        </td>
      </tr>
      <tr>
        <td>Login</td>
        <td>
          <input type="text" name="login" />
        </td>
      </tr>
      <tr>
        <td>Password</td>
        <td>
          <input type="text" name="password" />
        </td>
      </tr>
      <tr>
        <td>Supervisor</td>
        <td>
          <select name="supervisor">
            {% for supervisor in supervisors_list %}
              <option value="{{ supervisor.id }}">{{ supervisor.name }}</option>
            {% endfor %}
          </select>
        </td>
      </tr>
      <tr>
        <td></td>
        <td>
          <input type="submit" value="Valid" />
          </td>
      </tr>
    </table>
  </form>
{% endblock %}
```

请注意，模板令人印象深刻，但它是一个极简的表单。

## 视图使用 POST 数据接收

以下截图显示了我们将创建的网页：

![使用 POST 数据接收的视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00020.jpeg)

将处理此表单的视图如下。将视图保存在文件`views/create_developer.py`中：

```py
from django.shortcuts import render
from django.http import HttpResponse
from TasksManager.models import Supervisor, Developer
# View for create_developer
def page(request):
  error = False
  # If form has posted
  if request.POST: 
  # This line checks if the data was sent in POST. If so, this means that the form has been submitted and we should treat it.
    if 'name' in request.POST: 
    # This line checks whether a given data named name exists in the POST variables.
      name = request.POST.get('name', '')
      # This line is used to retrieve the value in the POST dictionary. Normally, we perform filters to recover the data to avoid false data, but it would have required many lines of code.
    else:
      error=True
    if 'login' in request.POST:
      login = request.POST.get('login', '')
    else:
      error=True
    if 'password' in request.POST:
      password = request.POST.get('password', '')
    else:
      error=True
    if 'supervisor' in request.POST:
      supervisor_id = request.POST.get('supervisor', '')
    else:
      error=True
    if not error:
      # We must get the supervisor
      supervisor = Supervisor.objects.get(id = supervisor_id)
      new_dev = Developer(name=name, login=login, password=password, supervisor=supervisor)
      new_dev.save()
      return HttpResponse("Developer added")
    else:
      return HttpResponse("An error as occured")
  else:
    supervisors_list = Supervisor.objects.all()
    return render(request, 'en/public/create_developer.html')
```

在这个视图中，我们甚至没有检查监督员是否存在。即使代码是功能性的，注意它需要很多行，而且我们没有验证传输数据的内容。

我们使用`HttpResponse()`方法，这样我们就不必创建额外的模板。当字段输入不正确时，我们也没有关于客户端错误的详细信息。

如果您想验证您的代码是否正常工作，请不要忘记在管理模块中检查数据。

要尝试这个表单，您可以在`index.html`文件的`article_content`块中添加以下行：

```py
<a href="{% url "create_developer" %}">Create developer</a>
```

# 使用 Django 表单添加开发者

Django 表单使用从`Form`类继承的对象。这个对象将处理我们在前面的例子中手动完成的大部分工作。

在显示表单时，它将生成表单模板的内容。如果需要，我们可以更改对象发送到模板的字段类型。

在接收数据时，对象将检查每个表单元素的内容。如果有错误，对象将向客户端发送明确的错误。如果没有错误，我们可以确定表单数据是正确的。

## CSRF 保护

**跨站请求伪造**（**CSRF**）是一种针对加载包含恶意请求的页面的用户的攻击。恶意脚本利用受害者的身份验证执行不需要的操作，如更改数据或访问敏感数据。

在 CSRF 攻击期间执行以下步骤：

1.  攻击者进行脚本注入。

1.  执行 HTTP 查询以获取网页。

1.  下载包含恶意脚本的网页。

1.  恶意脚本执行。![CSRF 保护](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00021.jpeg)

在这种攻击中，黑客还可以修改对网站用户可能至关重要的信息。因此，对于 Web 开发人员来说，了解如何保护他们的网站免受这种攻击是非常重要的，而 Django 将在此方面提供帮助。

要重新启用 CSRF 保护，我们必须编辑`settings.py`文件，并取消以下行的注释：

```py
'django.middleware.csrf.CsrfViewMiddleware',
```

此保护确保已发送的数据确实是从特定属性页面发送的。您可以通过两个简单的步骤来检查：

1.  在创建 HTML 或 Django 表单时，我们插入一个将存储在服务器上的 CSRF 令牌。当表单被发送时，CSRF 令牌也将被发送。

1.  当服务器接收到来自客户端的请求时，它将检查 CSRF 令牌。如果有效，它将验证请求。

不要忘记在启用保护的站点的所有表单中添加 CSRF 令牌。HTML 表单也涉及其中，我们刚刚创建的表单不包括令牌。为了使先前的表单与 CSRF 保护一起工作，我们需要在标签和`<form> </form>`中添加以下行：

```py
{% csrf_token %}
```

## 带有 Django 表单的视图

我们将首先编写包含表单的视图，因为模板将显示在视图中定义的表单。Django 表单可以存储在项目文件的根目录下的`forms.py`等其他文件中。我们直接将它们包含在视图中，因为表单只会在此页面上使用。根据项目，您必须选择最适合您的架构。我们将在`views/create_developer.py`文件中创建我们的视图，代码如下：

```py
from django.shortcuts import render
from django.http import HttpResponse
from TasksManager.models import Supervisor, Developer
from django import forms
# This line imports the Django forms package
class Form_inscription(forms.Form):  
# This line creates the form with four fields. It is an object that inherits from forms.Form. It contains attributes that define the form fields.
  name = forms.CharField(label="Name", max_length=30)
  login      = forms.CharField(label="Login", max_length=30)
  password   = forms.CharField(label="Password", widget=forms.PasswordInput)
  supervisor = forms.ModelChoiceField(label="Supervisor", queryset=Supervisor.objects.all())
# View for create_developer
def page(request):
  if request.POST:
    form = Form_inscription(request.POST)
    # If the form has been posted, we create the variable that will contain our form filled with data sent by POST form.
    if form.is_valid():
    # This line checks that the data sent by the user is consistent with the field that has been defined in the form.
      name          = form.cleaned_data['name']
    # This line is used to retrieve the value sent by the client. The collected data is filtered by the clean() method that we will see later. This way to recover data provides secure data.
      login         = form.cleaned_data['login']
      password      = form.cleaned_data['password']
      supervisor    = form.cleaned_data['supervisor'] 
      # In this line, the supervisor variable is of the Supervisor type, that is to say that the returned data by the cleaned_data dictionary will directly be a model.
      new_developer = Developer(name=name, login=login, password=password, email="", supervisor=supervisor)
      new_developer.save()
      return HttpResponse("Developer added")
    else:
      return render(request, 'en/public/create_developer.html', {'form' : form})
      # To send forms to the template, just send it like any other variable. We send it in case the form is not valid in order to display user errors:
    else:
    form = Form_inscription()
    # In this case, the user does not yet display the form, it instantiates with no data inside.
    return render(request, 'en/public/create_developer.html', {'form' : form})
```

此截图显示了表单的显示以及错误消息的显示：

![带有 Django 表单的视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00022.jpeg)

## Django 表单的模板

我们为此视图设置模板。模板将会更短：

```py
{% extends "base.html" %}
{% block title_html %}
  Create Developer
{% endblock %}
{% block h1 %}
  Create Developer
{% endblock %}
{% block article_content %}
  <form method="post" action="{% url "create_developer" %}" >
    {% csrf_token %} 
    <!-- This line inserts a CSRF token. -->
    <table>
      {{ form.as_table }}
    <!-- This line displays lines of the form.-->
    </table>
    <p><input type="submit" value="Create" /></p>
  </form>
{% endblock %}
```

由于完整的表单操作在视图中，模板只需执行`as_table()`方法来生成 HTML 表单。

先前的代码以表格形式显示数据。生成 HTML 表单结构的三种方法如下：

+   `as_table`：这会在`<tr> <td>`标签中显示字段

+   `as_ul`：这会在`<li>`标签中显示表单字段

+   `as_p`：这会在`<p>`标签中显示表单字段

因此，我们通过 Django 表单快速编写了一个带有错误处理和 CSRF 保护的安全表单。在附录中，*速查表*，您可以找到表单中不同可能的字段。

# 基于模型的表单

ModelForms 是基于模型的 Django 表单。这些表单的字段是从我们定义的模型自动生成的。实际上，开发人员经常需要创建与数据库中的字段对应的表单，以适应非 MVC 网站。

这些特殊的表单有一个`save()`方法，将在新记录中保存表单数据。

## 监督员创建表单

首先，我们将以添加监督员为例。为此，我们将创建一个新页面。为此，我们将创建以下 URL：

```py
url(r'^create-supervisor$', 'TasksManager.views.create_supervisor.page', name="create_supervisor"),
```

我们的视图将包含以下代码：

```py
from django.shortcuts import render
from TasksManager.models import Supervisor
from django import forms
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
def page(request):
  if len(request.POST) > 0:
    form = Form_supervisor(request.POST)
    if form.is_valid():
      form.save(commit=True) 
      # If the form is valid, we store the data in a model record in the form.
      return HttpResponseRedirect(reverse('public_index'))
      # This line is used to redirect to the specified URL. We use the reverse() function to get the URL from its name defines urls.py.
    else:
      return render(request, 'en/public/create_supervisor.html', {'form': form})
  else:
    form = Form_supervisor()
    return render(request, 'en/public/create_supervisor.html', {'form': form})
class Form_supervisor(forms.ModelForm): 
# Here we create a class that inherits from ModelForm.
  class Meta:
  # We extend the Meta class of the ModelForm. It is this class that will allow us to define the properties of ModelForm.
    model = Supervisor
    # We define the model that should be based on the form.
    exclude = ('date_created', 'last_connexion', )
    # We exclude certain fields of this form. It would also have been possible to do the opposite. That is to say with the fields property, we have defined the desired fields in the form.
```

如在`exclude = ('date_created', 'last_connexion', )`行中所示，可以限制表单字段。`exclude`和`fields`属性都必须正确使用。实际上，这些属性接收要排除或包括的字段的元组作为参数。它们可以描述如下：

+   `exclude`：这在管理员可访问的表单的情况下使用。因为，如果您在模型中添加一个字段，它将包含在表单中。

+   `fields`：这在表单对用户可访问的情况下使用。实际上，如果我们在模型中添加一个字段，用户将看不到它。

例如，我们有一个网站，销售免版税图像，其中有一个基于 ModelForm 的注册表单。管理员在用户的扩展模型中添加了一个信用字段。如果开发人员在某些字段中使用了`exclude`属性，并且没有添加信用，用户将能够获取他/她想要的信用。

我们将恢复我们之前的模板，在那里我们将更改`<form>`标签的`action`属性中存在的 URL：

```py
{% url "create_supervisor" %}
```

这个例子向我们展示了 ModelForms 可以通过拥有一个可以定制的表单（例如修改验证）来节省大量开发时间。

在下一章中，我们将看到如何通过基于类的视图更快。

# Django 表单的高级用法

我们已经学习了允许您创建简单表单并进行少量定制的表单的基础知识。有时，定制数据验证和错误显示，或使用特殊图形等方面是有用的。

## 扩展验证表单

对表单字段执行特定验证是有用的。Django 使这变得容易，同时提醒您表单的优势。我们将以添加开发者表单的例子来说明密码的审核。

为此，我们将以以下方式更改我们视图中的表单（在`create_developer.py`文件中）：

```py
class Form_inscription(forms.Form):
  name       = forms.CharField(label="Name", max_length=30)
  login = forms.CharField(label = "Login")
  password = forms.CharField(label = "Password", widget = forms.PasswordInput)
  # We add another field for the password. This field will be used to avoid typos from the user. If both passwords do not match, the validation will display an error message
  password_bis = forms.CharField(label = "Password", widget = forms.PasswordInput) 
  supervisor = forms.ModelChoiceField(label="Supervisor", queryset=Supervisor.objects.all())
  def clean(self): 
  # This line allows us to extend the clean method that is responsible for validating data fields.
    cleaned_data = super (Form_inscription, self).clean()
    # This method is very useful because it performs the clean() method of the superclass. Without this line we would be rewriting the method instead of extending it.
    password = self.cleaned_data.get('password') 
    # We get the value of the field password in the variable.
    password_bis = self.cleaned_data.get('password_bis')
    if password and password_bis and password != password_bis:
      raise forms.ValidationError("Passwords are not identical.") 
      # This line makes us raise an exception. This way, when the view performs the is_valid() method, if the passwords are not identical, the form is not validated .
    return self.cleaned_data
```

通过这个例子，我们可以看到 Django 在表单和审核管理方面非常灵活。它还允许您定制错误的显示。

## 定制错误的显示

有时，显示特定于用户的错误消息可能很重要。例如，公司可能要求密码必须包含某些类型的字符；例如，密码必须至少包含一个数字和多个字母。在这种情况下，最好也在错误消息中指出这一点。实际上，用户更仔细地阅读错误消息而不是帮助消息。

要做到这一点，您必须在表单字段中使用`error_messages`属性，并将错误消息设置为文本字符串。

还可以根据错误类型定义不同的消息。我们将创建一个包含两种常见错误的字典，并为它们提供消息。我们可以定义这个字典如下：

```py
error_name = {
  'required': 'You must type a name !',
  'invalid': 'Wrong format.'
}
```

我们将修改`create_developer.py`中`Form_inscription`表单的名称字段：

```py
name = forms.CharField(label="Name", max_length=30, error_messages=error_name)
```

这样，如果用户没有填写`name`字段，他/她将看到以下消息：**您必须输入一个名称！**。

要将此消息应用于 ModelForm，我们必须转到`models.py`文件并修改包含`name`字段的行。

```py
name = models.CharField(max_length=50, verbose_name="Name", error_messages=error_name)
```

在编辑`models.py`时，我们不应忘记指定`error_name`字典。

这些错误消息通过通知用户他/她的错误来提高网站的质量。当验证复杂时，使用自定义字段上的自定义错误非常重要。然而，不要在基本字段上过度使用，因为这对开发人员来说会浪费时间。

## 使用小部件

小部件是定制表单元素显示的有效方式。实际上，在某些情况下，指定具有特定尺寸的文本区域字段在 ModelForm 中可能是有帮助的。

为了学习使用小部件的实践并继续开发我们的应用程序，我们将创建项目创建页面。这个页面将包含一个 Django 表单，并且我们将在 HTML 的`<textarea>`标签中设置`description`字段。

我们需要将以下 URL 添加到`urls.py`文件中：

```py
url(r'^create_project$', ' TasksManager.views.create_project.page', name='create_project'),
```

然后，在`create_project.py`文件中创建我们的视图，代码如下：

```py
from django.shortcuts import render
from TasksManager.models import Project
from django import forms
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
class Form_project_create(forms.Form):
  title = forms.CharField(label="Title", max_length=30)
  description = forms.CharField(widget= forms.Textarea(attrs={'rows': 5, 'cols': 100,}))
  client_name = forms.CharField(label="Client", max_length=50)
def page(request):
  if request.POST:
    form = Form_project_create(request.POST)
    if form.is_valid(): 
      title = form.cleaned_data['title'] 
      description = form.cleaned_data['description']
      client_name = form.cleaned_data['client_name']
      new_project = Project(title=title, description=description, client_name=client_name)
      new_project.save()
      return HttpResponseRedirect(reverse('public_index')) 
    else:
      return render(request, 'en/public/create_project.html', {'form' : form}) 
  else:
    form = Form_project_create() 
  return render(request, 'en/public/create_project.html', {'form' : form})
```

可以使用我们创建和调整的模板之一。这个表单将与我们创建的所有 Django 表单一样工作。在复制我们已经创建的模板之后，我们只需要更改`<form>`标签的`action`属性的标题和 URL。通过访问页面，我们注意到小部件运行良好，并显示更适合长文本的文本区域。

有许多其他小部件可以定制表单。Django 的一个很大的特点是它是通用的，并且随着时间的推移完全可适应。

## 在表单中设置初始数据

有两种方法可以使用 Django 声明表单字段的初始值。以下示例发生在`create_developer.py`文件中。

### 在实例化表单时

以下代码将在`name`字段中显示`new`，并在定义主管的`<select>`字段中选择第一个主管。这些字段可由用户编辑：

```py
form = Form_inscription(initial={'name': 'new', 'supervisor': Supervisor.objects.all()[:1].get().id})
```

这一行必须替换`create_developer.py`视图中的以下行：

```py
form = Form_inscription()
```

### 在定义字段时

要达到与上一节相同的效果，在`name`字段中显示`new`并选择相应字段中的第一个主管；您必须使用以下代码更改声明`name`和`supervisor`字段：

```py
name = forms.CharField(label="Name", max_length=30, initial="new")
supervisor = forms.ModelChoiceField(label="Supervisor", queryset=Supervisor.objects.all(), initial=Supervisor.objects.all()[:1].get().id)
```

# 摘要

在本章中，我们学习了如何使用 Django 表单。这些表单可以通过自动数据验证和错误显示来节省大量时间。

在下一章中，我们将进一步探讨通用操作，并通过表单节省更多时间。


# 第八章：通过 CBV 提高生产力

**基于类的视图**（**CBV**）是从模型生成的视图。简单来说，我们可以说这些就像 ModelForms，因为它们简化了视图并适用于常见情况。

CRUD 是我们在提到数据库上执行的四个主要操作时使用的简写：创建、读取、更新和删除。CBV 是创建执行这些操作的页面的最佳方式。

为创建和编辑模型或数据库表数据创建表单是开发人员工作中非常重复的部分。他们可能会花费很多时间来做这件事（验证、预填字段等）。使用 CBV，Django 允许开发人员在不到 10 分钟内执行模型的 CRUD 操作。它们还有一个重要的优势：如果模型发生变化并且 CBV 做得很好，更改模型将自动更改网站内的 CRUD 操作。在这种情况下，在我们的模型中添加一行代码就可以节省数十甚至数百行代码。

CBV 仍然有一个缺点。它们不太容易使用高级功能或未提供的功能进行自定义。在许多情况下，当您尝试执行具有某些特殊性的 CRUD 操作时，最好创建一个新视图。

您可能会问为什么我们没有直接研究它们-我们本可以节省很多时间，特别是在数据库中添加开发人员时。这是因为这些视图是通用的。它们适用于不需要很多更改的简单操作。当我们需要一个复杂的表单时，CBV 将不起作用，甚至会延长编程时间。

我们应该使用 CBV，因为它们可以节省大量通常用于运行模型上的 CRUD 操作的时间。

在本章中，我们将充分利用我们的`TasksManager`应用程序。事实上，我们将享受 CBV 所提供的时间节省，以便快速推进这个项目。如果你不能立即理解 CBV 的运作方式，没关系。在前几章中我们已经可以制作网站了。

在本章中，我们将尝试通过以下主题来提高我们的生产力：

+   我们将使用`CreateView` CBV 快速构建添加项目页面

+   我们稍后将看到如何显示对象列表并使用分页系统

+   然后我们将使用`DetailView` CBV 来显示项目信息

+   然后，我们将学习如何使用`UpdateView` CBV 更改记录中的数据

+   我们将学习如何更改 CBV 生成的表单

+   然后，我们将创建一个页面来删除记录

+   然后，我们最终将创建`UpdateView`的子类，以使其在我们的应用程序中更加灵活

# CreateView CBV

`CreateView` CBV 允许您创建一个视图，该视图将根据模型自动生成一个表单，并自动保存该表单中的数据。它可以与 ModelForm 进行比较，只是我们不需要创建一个视图。实际上，除了特殊情况外，所有这些代码都将放在`urls.py`文件中。

## 极简用法示例

我们将创建一个 CBV，允许我们创建一个项目。这个例子旨在表明，您可以比使用 Django 表单节省更多的时间。我们将能够使用上一章项目中用于创建表单的模板。现在，我们将更改我们的`create_project` URL 如下：

```py
url (r'^create_project$', CreateView.as_view(model=Project, template_name="en/public/create_project.html", success_url = 'index'), name="create_project"),
```

我们将在`urls.py`文件的开头添加以下行：

```py
from django.views.generic import CreateView
from TasksManager.models import Project
```

在我们的新 URL 中，我们使用了以下新功能：

+   `CreateView.as_view`：我们调用 CBV`CreateView`的`as_view`方法。这个方法将返回一个完整的视图给用户。此外，我们在这个方法中返回多个参数。

+   `model`：这定义了将应用 CBV 的模型。

+   `template_name`：这定义了将显示表单的模板。由于 CBV 使用`ModelForm`，我们不需要更改我们的`create_project.html`模板。

+   `success_url`：这定义了一旦更改已经被考虑到我们将被重定向到的 URL。这个参数不是很 DRY，因为我们不能使用 URL 的`name`属性。当我们扩展我们的 CBV 时，我们将看到如何使用 URL 的名称进行重定向。

就是这样！我们已经添加到`urls.py`文件中的三行将执行以下操作：

+   生成表单

+   生成将表单发送到模板的视图，无论是否有错误。

+   用户发送数据

我们刚刚使用了 Django 最有趣的功能之一。事实上，仅用三行代码，我们就完成了一个没有任何框架需要超过一百行的工作。我们还将编写一个 CBV，它将允许我们添加一个任务。看一下以下代码：

```py
from TasksManager.models import Project, Task
url (r'^create_task$', CreateView.as_view(model=Task, template_name="en/public/create_task.html", success_url = 'index'), name="create_task"),
```

然后我们需要复制`create_project.html`模板并更改`base.html`模板中的链接。我们的新视图是功能性的，并且我们使用了相同的模板来创建项目。这是一种常见的方法，因为它为开发人员节省了大量时间，但是有一种更严谨的方法可以进行。

要测试代码，我们可以在`index.html`模板的`article_content`块的末尾添加以下链接：

```py
<a href="{% url "create_task" %}">Create task</a>
```

# 使用 ListView

`ListView`是一个 CBV，用于显示给定模型的记录列表。该视图生成以发送模板对象，从中我们查看列表。

## 极简用法示例

我们将看一个显示项目列表并创建指向项目详情的链接的示例。为此，我们必须在`urls.py`文件中添加以下行：

```py
from TasksManager.models import Project
from django.views.generic.list import ListView
```

在文件中添加以下 URL：

```py
url (r'^project_list$', ListView.as_view(model=Project, template_name="en/public/project_list.html"), name="project_list"),
```

我们将通过在`article_content`块中添加以下行来创建用于以表格形式显示结果的模板，这些行是在扩展`base.html`模板之后添加的：

```py
<table>
<tr>
  <th>Title</th>
  <th>Description</th>
  <th>Client name</th>
</tr>
{% for project in object_list %}
  <tr>
    <td>{{ project.title }}</td>
    <td>{{ project.description }}</td>
    <td>{{ project.client_name }}</td>
  </tr>
{% endfor %}
</table>
```

我们创建了与第六章中相同的列表，关于查询集。优点是我们使用了更少的行，并且没有使用任何视图来创建它。在下一部分中，我们将通过扩展此 CBV 来实现分页。

## 扩展 ListView

可以扩展 ListView CBV 的功能并对其进行自定义。这使我们能够根据网站的需求来调整 CBV。我们可以在`as_view`方法中定义与参数中相同的元素，但这样更易读，我们还可以覆盖方法。根据 CBV 的类型，将它们分开可以让您：

+   像我们在 URL 中所做的那样更改模型和模板

+   更改要执行的查询集

+   更改发送到模板的对象的名称

+   指定将重定向用户的 URL

我们将通过修改我们已完成的项目列表来扩展我们的第一个 CBV。我们将对此列表进行两项更改，按标题排序并添加分页。我们将在`views/cbv`模块中创建`ListView.py`文件。该文件将包含我们定制的`listView`。也可以选择架构。例如，我们可以创建一个名为`project.py`的文件来存储所有关于项目的 CBV。该文件将包含以下代码：

```py
from django.views.generic.list import ListView 
# In this line, we import the ListView class
from TasksManager.models import Project

class Project_list(ListView): 
# In this line, we create a class that extends the ListView class.
  model=Project
  template_name = 'en/public/project_list.html' 
# In this line, we define the template_name the same manner as in the urls.py file.
  paginate_by = 5 
In this line, we define the number of visible projects on a single page.
  def get_queryset(self): 
In this line, we override the get_queryset() method to return our queryset.
    queryset=Project.objects.all().order_by("title")
    return queryset
```

```py
ListView.py file:
```

```py
url (r'^project_list$', Project_list.as_view(), name="project_list"),
```

从现在开始，新页面是功能性的。如果我们测试它，我们会意识到只有前五个项目被显示。的确，在`Project_list`对象中，我们定义了每页五个项目的分页。要浏览列表，我们需要在模板的`article_content`块结束之前添加以下代码：

```py
{% if is_paginated %}
  <div class="pagination">
    <span>
    {% if page_obj.has_previous %}
      <a href="{% url "project_list" %}?page={{ page_obj.previous_page_number }}">Previous</a>
    {% endif %}
    <span style="margin-left:15px;margin-right:15px;">
      Page {{ page_obj.number }} of {{ page_obj.paginator.num_pages }}.
    </span>
    {% if page_obj.has_next %}
      <a href="{% url "project_list" %}?page={{ page_obj.next_page_number }}">Next</a>
    {% endif %}
    </span>
  </div>
{% endif %}
```

模板的这一部分允许我们在页面底部创建到前后页面的链接。通过这个示例，我们非常快速地创建了一个带分页的项目排序列表。扩展 CBV 非常方便，可以让我们适应更复杂的用途。在完成此完整示例后，我们将创建一个 CBV 来显示开发人员列表。这个列表将在本书的后面很有用。在导入`ListView`类之后，我们必须添加以下 URL：

```py
url (r'^developer_list$', ListView.as_view(model=Developer, template_name="en/public/developer_list.html"), name="developer_list"),
```

然后我们使用`base.html`的继承模板，并将以下代码放入`article_content`块中：

```py
<table>
  <tr>
    <td>Name</td>
    <td>Login</td>
    <td>Supervisor</td>
  </tr>
  {% for dev in object_list %}
    <tr>
      <td><a href="">{{ dev.name }}</a></td>
      <td>{{ dev.login }}</td>
      <td>{{ dev.supervisor }}</td>
    </tr>
  {% endfor %}
</table>
```

我们会注意到开发人员的名字是一个空链接。当我们创建显示开发人员详细信息的页面时，您应该重新填写它。这就是我们将在下一节中使用`DetailView`来做的。

# DetailView CBV

`DetailView` CBV 允许我们显示来自注册模型的信息。这是我们将学习的第一个具有 URL 参数的 CBV。为了查看记录的详细信息，它将发送其 ID 到 CBV。我们将学习一些例子。

## 极简主义用法示例

首先，我们将创建一个页面，显示任务的详细信息。为此，我们将通过在`urls.py`文件中添加以下行来创建 URL：

```py
from django.views.generic import DetailView
from TasksManager.models import Task
url (r'^task_detail_(?P<pk>\d+)$', DetailView.as_view(model=Task, template_name="en/public/task_detail.html"), name="task_detail"),
```

在这个 URL 中，我们添加了参数发送方面。我们已经在早期的章节中讨论过这种类型的 URL，当时我们涵盖了查询集。

### 注意

这一次，我们真的需要命名参数`pk`；否则，CBV 将无法工作。`pk`表示主键，它将包含您想要查看的记录的 ID。

关于模板，我们将创建`en/public/task_detail.html`模板，并将以下代码放置在`article_content`块中：

```py
<h4>
  {{ object.title }}
</h4>
<table>
  <tr>
    <td>Project : {{ object.project }}</td>
    <td>Developer : {{ object.app_user }}</td>
  </tr>
  <tr>
    <td>Importence : {{ object.importence }}</td>
    <td>Time elapsed : {{ object.time_elapsed }}</td>
  </tr>
</table>
<p>
  {{ object.description }}
</p>
```

在这段代码中，我们引用了外键`Developer`和`Project`。在模板中使用这种语法，我们调用了相关模型的`__unicode__()`。这使得项目的标题能够显示出来。为了测试这段代码，我们需要创建一个参数化 URL 的链接。将这行添加到您的`index.html`文件中：

```py
<a href="{% url "task_detail" "1" %}">Detail first view</a><br />
```

这行将允许我们查看第一个任务的细节。您可以尝试在表格的每一行中创建任务列表和`DetailView`的链接。这就是我们要做的。

## 扩展 DetailView

现在我们将创建一个页面，显示开发人员及其任务的详细信息。为了完成这个任务，我们将通过在`views/cbv`模块中创建一个`DetailView.py`文件来覆盖`DetailView`类，并添加以下代码行：

```py
from django.views.generic import DetailView
from TasksManager.models import Developer, Task

class Developer_detail(DetailView): 
  model=Developer
  template_name = 'en/public/developer_detail.html'
  def get_context_data(self, **kwargs):
    # This overrides the get_context_data() method.
    context = super(Developer_detail, self).get_context_data(**kwargs) 
    # This allows calling the method of the super class. Without this line we would not have the basic context.
    tasks_dev = Task.objects.filter(developer = self.object) 
    # This allows us to retrieve the list of developer tasks. We use self.object, which is a Developer type object already defined by the DetailView class.
    context['tasks_dev'] = tasks_dev 
    # In this line, we add the task list to the context.
    return context
```

我们需要在`urls.py`文件中添加以下行：

```py
from TasksManager.views.cbv.DetailView import Developer_detail 
url (r'^developer_detail_(?P<pk>\d+)$', Developer_detail.as_view(), name="developer_detail"),
```

为了查看主要数据和开发任务，我们创建`developer_detail.html`模板。在从`base.html`扩展后，我们必须在`article_content`块中输入以下行：

```py
<h4>
  {{ object.name }}
</h4>
<span>Login : {{ object.login }}</span><br />
<span>Email : {{ object.email }}</span>
<h3>Tasks</h3>
<table>
  {% for task in tasks_dev %}
  <tr>
    <td>{{ task.title }}</td>
    <td>{{ task.importence }}</td>
    <td>{{ task.project }}</td>
  </tr>
  {% endfor %}
</table>
```

这个例子让我们看到了如何在使用 CBV 时向模板发送数据。

# UpdateView CBV

`UpdateView`是将轻松创建和编辑表单的 CBV。与没有 MVC 模式的开发相比，这是节省更多时间的 CBV。与`DetailView`一样，我们将不得不将记录的登录信息发送到 URL。为了解决`UpdateView`，我们将讨论两个例子：

+   为了让主管能够编辑任务，改变任务

+   减少执行任务所需的时间

## 极简主义用法示例

这个示例将展示如何创建一个页面，允许主管修改任务。与其他 CBV 一样，我们将在`urls.py`文件中添加以下行：

```py
from django.views.generic import UpdateView
url (r'^update_task_(?P<pk>\d+)$', UpdateView.as_view(model=Task, template_name="en/public/update_task.html", success_url="index"), name="update_task"),
```

我们将编写一个与我们用于`CreateView`的模板非常相似的模板。唯一的区别（除了按钮文本之外）将是表单的`action`字段，我们将其定义为空。我们将看到如何在本章末尾填写该字段。现在，我们将利用浏览器在字段为空时提交表单到当前页面的事实。它仍然可见，因此用户可以编写要包含在我们的`article_content`块中的内容。看一下以下代码：

```py
<form method="post" action="">
  {% csrf_token %} 
  <table>
    {{ form.as_table }} 
  </table>
  <p><input type="submit" value="Update" /></p>
</form>
```

这个例子真的很简单。如果我们在`success_url`属性中输入了 URL 的名称，它本来可以更加 DRY。

## 扩展 UpdateView CBV

在我们的应用程序中，任务的生命周期如下：

+   主管创建任务而不设置任何持续时间

+   当开发人员完成任务时，他们会保存他们的工作时间。

我们将在后者上工作，开发者只能更改任务的持续时间。在这个例子中，我们将覆盖`UpdateView`类。为此，我们将在`views/cbv`模块中创建一个`UpdateView.py`文件。我们需要添加以下内容：

```py
from django.views.generic import UpdateView
from TasksManager.models import Task
from django.forms import ModelForm
from django.core.urlresolvers import reverse

class Form_task_time(ModelForm): 
# In this line, we create a form that extends the ModelForm. The UpdateView and CreateView CBV are based on a ModelForm system.
  class Meta:
    model = Task
    fields = ['time_elapsed'] 
    # This is used to define the fields that appear in the form. Here there will be only one field.

class Task_update_time(UpdateView):
  model = Task
  template_name = 'en/public/update_task_developer.html'
form_class = Form_task_time 
# In this line, we impose your CBV to use the ModelForm we created. When you do not define this line, Django automatically generates a ModelForm.
  success_url = 'public_empty' 
  # This line sets the name of the URL that will be seen once the change has been completed.
  def get_success_url(self): 
  # In this line, when you put the name of a URL in the success_url property, we have to override this method. The reverse() method returns the URL corresponding to a URL name.
    return reverse(self.success_url)
```

我们可以使用以下 URL 来使用这个 CBV：

```py
from TasksManager.views.cbv.UpdateView import Task_update_time
url (r'^update_task_time_(?P<pk>\d+)$', Task_update_time.as_view(), name = "update_task_time"),
```

对于`update_task_developer.html`模板，我们只需要复制`update_task.html`模板并修改其标题。

# DeleteView CBV

`DeleteView` CBV 可以轻松删除记录。与普通视图相比，它并不节省很多时间，但它不会受到不必要视图的负担。我们将展示一个任务删除的例子。为此，我们需要在`views/cbv`模块中创建`DeleteView.py`文件。事实上，我们需要覆盖它，因为我们将输入我们想要重定向的 URL 的名称。我们只能将 URL 放在`success_url`中，但我们希望我们的 URL 尽可能 DRY。我们将在`DeleteView.py`文件中添加以下代码：

```py
from django.core.urlresolvers import reverse
from django.views.generic import DeleteView
from TasksManager.models import Task

class Task_delete(DeleteView):
  model = Task
  template_name = 'en/public/confirm_delete_task.html'
  success_url = 'public_empty'
  def get_success_url(self):
    return reverse(self.success_url)
```

在上述代码中，该模板将用于确认删除。事实上，`DeleteView` CBV 将在删除之前要求用户确认。我们将在`urls.py`文件中添加以下行，以添加删除的 URL：

```py
from TasksManager.views.cbv.DeleteView import Task_delete
url(r'task_delete_(?P<pk>\d+)$', Task_delete.as_view(), name="task_delete"),
```

为了完成我们的任务抑制页面，我们将通过在`article_content`块中扩展`base.html`创建`confirm_delete_task.html`模板，并添加以下内容：

```py
<h3>Do you want to delete this object?</h3>
<form method="post" action="">
  {% csrf_token %} 
  <table>
    {{ form.as_table }} 
  </table>
  <p><input type="submit" value="Delete" /></p>
</form>
```

# 通过扩展 CBV 进一步

通过扩展它们，CBV 允许我们在页面创建过程中节省大量时间，通过对我们的模型执行 CRUD 操作。通过扩展它们，可以将它们适应我们的使用，并节省更多时间。

## 使用自定义类 CBV 更新

为了完成我们的抑制页面，在本章中，我们已经看到 CBV 允许我们不受不必要的视图的负担。然而，我们创建了许多相似的模板，并且我们只是为了使用 DRY URL 而覆盖了 CBV。我们将修复这些小缺陷。在本节中，我们将创建一个 CBV 和通用模板，使我们能够：

+   直接在`urls.py`文件中使用这个 CBV

+   输入重定向的 URL 的`name`属性

+   从一个模板中受益，用于这些 CBV 的所有用途

在编写我们的 CBV 之前，我们将修改`models.py`文件，为每个模型赋予`verbose_name`属性和`verbose_name_plural`。为此，我们将使用`Meta`类。例如，`Task`模型将变成以下内容：

```py
class Task(models.Model):
  # fields
  def __str__(self):
    return self.title
  class Meta:
    verbose_name = "task"
    verbose_name_plural = "tasks"
```

我们将在`views/cbv`文件夹中创建一个`UpdateViewCustom.py`文件，并添加以下代码：

```py
from django.views.generic import UpdateView
from django.core.urlresolvers import reverse

class UpdateViewCustom(UpdateView):
  template_name = 'en/cbv/UpdateViewCustom.html' 
  # In this line, we define the template that will be used for all the CBVs that extend the UpdateViewCustom class. This template_name field can still be changed if we need it.
  url_name="" 
  # This line is used to create the url_name property. This property will help us to define the name of the current URL. In this way, we can add the link in the action attribute of the form.
  def get_success_url(self):
  # In this line, we override the get_success_url() method by default, this method uses the name URLs.
    return reverse(self.success_url)
  def get_context_data(self, **kwargs): 
  # This line is the method we use to send data to the template.
    context = super(UpdateViewCustom, self).get_context_data(**kwargs) 
    # In this line, we perform the super class method to send normal data from the CBV UpdateView.
    model_name = self.model._meta.verbose_name.title() 
    # In this line, we get the verbose_name property of the defined model.
    context['model_name'] = model_name 
    # In this line, we send the verbose_name property to the template.
    context['url_name'] = self.url_name \
    # This line allows us to send the name of our URL to the template.
    return context
```

然后，我们需要创建显示表单的模板。为此，我们需要创建`UpdateViewCustom.html`文件，并添加以下内容：

```py
{% extends "base.html" %}
{% block title_html %}
  Update a {{ model_name }} 
  <!-- In this line, we show the type of model we want to change here. -->
{% endblock %}
{% block h1 %}
  Update a {{ model_name }} 
{% endblock %}
{% block article_content %}
  <form method="post" action="{% url url_name object.id %}"> <!-- line 2 -->
  <!-- In this line, we use our url_name property to redirect the form to the current page. -->
    {% csrf_token %} 
    <table>
      {{ form.as_table }} 
    </table>
    <p><input type="submit" value="Update" /></p>
  </form>
{% endblock %}
```

为了测试这些新的 CBV，我们将以以下方式更改`update_task` URL：

```py
url (r'^update_task_(?P<pk>\d+)$', UpdateViewCustom.as_view(model=Task, url_name="update_task", success_url="public_empty"), name="update_task"),
```

以下是一个屏幕截图，显示了 CBV 将显示的内容：

![使用自定义类 CBV 更新](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00023.jpeg)

# 摘要

在本章中，我们学会了如何使用 Django 最强大的功能之一：CBV。借助它们，开发人员可以运行高效的 CRUD 操作。

我们还学会了如何通过在项目列表上添加分页或在显示有关用户信息的页面上显示开发者的工作来改变 CBV 以适应我们的使用。

在下一章中，我们将学习如何使用会话变量。我们将通过一个实际的例子来探讨这个问题。在这个例子中，我们将修改任务列表，以显示最后访问的任务。


# 第九章：使用会话

会话是根据用户存储在服务器上的变量。在许多网站上，将用户数据保留为标识符、购物篮或配置项是有用的。为此，Django 将这些信息存储在数据库中。然后，它随机生成一个字符串作为哈希码，传输给客户端作为 cookie。这种工作方式允许您存储有关用户的大量信息，同时最大限度地减少服务器和客户端之间的数据交换，例如服务器可以生成的标识符类型。

在本章中，我们将做以下事情：

+   研究会话变量在 Django 框架中的工作方式

+   学习如何创建和检索会话变量

+   通过一个实际而有用的例子来研究会话变量

+   让我们意识到使用会话变量的安全性

Firebug 是 Firefox 的一个插件。这是一个对于 Web 开发人员来说非常方便的工具；它允许您做以下事情：

+   显示 JavaScript 控制台以读取错误

+   从浏览器中读取和编辑页面的 HTML 代码

+   查看网站使用的 cookies

![使用会话](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00024.jpeg)

使用 Firebug 实现的 cookies

在使用 Firebug 实现的这个截图中，我们注意到我们有两个 cookies：

+   `sessionid`：这是我们的会话 ID。Django 将通过这个标识符知道它正在处理哪个用户。

+   `csrftoken`：这个 cookie 是典型的 Django。我们在关于表单的章节中已经谈到过它。它在本章中不会被使用。

以下是存储会话数据的表的截图：

![使用会话](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00025.jpeg)

会话对于认证系统特别有用。实际上，在许多情况下，当用户连接到网站时，我们会将他们的标识符记录在会话变量中。因此，每个 HTTP 请求，用户都会发送这个标识符来通知网站他们的状态。这也是使管理模块工作的重要系统，我们将在后面的章节中看到。然而，如果会话不经常被删除，它们有一个缺点：它们会在数据库中占用更多的空间。要在 Django 中使用会话，必须启用`django.contrib.sessions.middleware.SessionMiddleware`中间件，并且浏览器必须接受 cookies。

会话的生命周期如下所述：

1.  没有任何会话的用户向网站发出 HTTP 请求。

1.  服务器生成一个会话标识符，并将其与用户请求的页面一起发送到浏览器。

1.  每当浏览器发出请求时，它将自动发送会话标识符。

1.  根据系统管理员的配置，服务器定期检查是否有过期的会话。如果是这种情况，它可能会被删除。

![使用会话](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00026.jpeg)

# 创建和获取会话变量

使用 Django，存储在数据库中、生成哈希码并与客户端交换将是透明的。会话存储在由`request`变量表示的上下文中。要在会话变量中保存一个值，我们必须使用以下语法：

```py
request.session['session_var_name'] = "Value"
```

一旦会话变量被注册，您必须使用以下语法来恢复它：

```py
request.session['session_var_name']
```

要使用这些行，我们必须确保与请求上下文进行交互。实际上，在某些情况下，比如 CBV，我们无法简单地访问请求上下文。

## 一个例子 - 显示最后一个被查看的任务

在这个例子中，我们将展示一个使用会话变量的实际例子。一般来说，开发人员会查看要做的任务。他/她选择一个任务，研究它，然后记录和注明花费的时间。我们将在会话变量中存储最后访问的任务的标识符，并将其显示在待完成任务列表的顶部。

为此，我们将不再使用`DetailView` CBV 来显示任务的详细信息，而是使用一个真正的视图。首先，我们必须定义一个 URL，以便查看我们的视图。为此，我们将使用以下代码修改`task_detail` URL：

```py
url (r'^task_detail_(?P<pk>\d+)$', 'TasksManager.views.task_detail.page', name="task_detail"),
```

我们将在`views/task_detail.py`文件中创建我们的视图，使用以下代码：

```py
from django.shortcuts import render
from TasksManager.models import Task
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
def page(request, pk):
  check_task = Task.objects.filter(id = pk) 
  # This line is used to retrieve a queryset of the elements whose ID property matches to the parameter pk sent to the URL. We will use this queryset in the following line : task = check_task.get().

  try:
  # This is used to define an error handling exception to the next line.
    task = check_task.get()
    # This line is used to retrieve the record in the queryset.
  except (Task.DoesNotExist, Task.MultipleObjectsReturned):
  # This allows to process the two kind of exceptions: DoesNotExist and MultipleObjectsReturned. The DoesNotExist exception type is raised if the queryset has no records. The MultipleObjectsReturned exception type is raised if queryset contains multiple records.
    return HttpResponseRedirect(reverse('public_empty'))
    # This line redirects the user if an exception is thrown. We could also redirect to an error page.
  else:
    request.session['last_task'] = task.id
    # This line records the ID property of the task in a session variable named last_task.
    #In this line, we use the same template that defines the form CBV DetailView. Without having to modify the template, we send our task in a variable named object.
  return render(request, 'en/public/task_detail.html', {'object' : task})
```

然后，我们将使用`ListView` CBV 创建任务列表。为此，我们必须将以下 URL 添加到`urls.py`文件中：

```py
url (r'^task_list$', 'TasksManager.views.task_list.page', name="task_list"),
```

该 URL 的相应视图如下：

```py
from django.shortcuts import render
from TasksManager.models import Task
from django.core.urlresolvers import reverse
def page(request):
  tasks_list = Task.objects.all() 
  # This line is used to retrieve all existing tasks databases.
  last_task = 0 
  # In this line, we define last_task variable with a null value without generating a bug when using the render() method.
  if 'last_task' in request.session: 
  # This line is used to check whether there is a session variable named last_task.
    last_task = Task.objects.get(id = request.session['last_task'])
    # In this line, we get the recording of the last task in our last_task variable.
    tasks_list = tasks_list.exclude(id = request.session['last_task'])
    # In this line, we exclude the last task for the queryset to not have duplicates.
  return render(request, 'en/public/tasks_list.html', {'tasks_list': tasks_list, 'last_task' : last_task})
```

然后，我们将为我们的列表创建模板。这个例子将是完整的，因为这个列表将创建、读取、更新和删除任务。以下代码必须放在`tasks_list.html`文件中：

```py
{% extends "base.html" %}
{% block title_html %}
  Tasks list
{% endblock %}
{% block article_content %}
  <table>
  <tr>
    <th>Title</th>
    <th>Description</th>
    <th colspan="2"><a href="{% url "create_task" %}">Create</a></th>
  </tr>
  {% if last_task %} 
  <!-- This line checks to see if we have a record in the last_task variable. If this variable has kept the value 0, the condition will not be validated. In this way, the last accessed task will display at the beginning of the list.-->
    <tr class="important">
      <td><a href="{% url "task_detail" last_task.id %}">{{ last_task.title }}</a></td>
      <td>{{ last_task.description|truncatechars:25 }}</td>
      <td><a href="{% url "update_task" last_task.id %}">Edit</a></td>
      <td><a href="{% url "task_delete" last_task.id %}">Delete</a></td>
    </tr>
  {% endif %}
  {% for task in tasks_list %}
  <!-- This line runs through the rest of the tasks and displays. -->
    <tr>
      <td><a href="{% url "task_detail" task.id %}">{{ task.title }}</a></td>
      <td>{{ task.description|truncatechars:25 }}</td>
      <td><a href="{% url "update_task" task.id %}">Edit</a></td>
      <td><a href="{% url "task_delete" task.id %}">Delete</a></td>
    </tr>
  {% endfor %}
  </table>
{% endblock %}
```

为了使这个例子完整，我们必须在我们创建的`style.css`文件中添加以下行：

```py
tr.important td {
  font-weight:bold;
}
```

这些行用于突出显示最后一个被查询的任务的行。

# 关于会话安全

会话变量不可被用户修改，因为它们是由服务器存储的，除非在您的网站中选择存储客户端发送的数据。然而，有一种利用系统会话的缺陷。事实上，如果用户无法更改他们的会话变量，他们可能会尝试篡夺另一个用户的会话。

我们将想象一个现实的攻击场景。我们在一家公司，该公司使用网站来集中每个员工的电子邮件和日程安排。我们指定的员工 Bob 对他的同事 Alicia 非常感兴趣。他想读她的电子邮件以了解更多关于她的信息。有一天，当她去休息室喝咖啡时，Bob 坐在 Alicia 的电脑前。像所有员工一样，他使用相同的密码以便于管理，并且可以轻松地连接到 Alicia 的 PC。幸运的是，浏览器已经打开。此外，浏览器定期联系服务器以查看是否有新消息到达，以便会话没有时间过期。他下载了一个工具，比如 Firebug，可以读取 cookies。他检索哈希值，擦除痕迹，然后返回到他的电脑。他更改了浏览器中的`ID`会话 cookies；因此，他可以访问关于 Alicia 的所有信息。此外，在没有加密的情况下，这种攻击可以在嗅探网络流量的本地网络中远程执行。这被称为会话固定。为了保护自己免受这种攻击，可以采取一些措施：

+   使用 SSL 等加密通信服务器和客户端之间的通信。

+   要求用户在访问敏感信息之前输入密码，例如银行信息。

+   对 IP 地址和会话号码进行审计。如果用户更改 IP 地址，则断开用户的连接。尽管有这个措施，攻击者仍然可以进行 IP 欺骗来窃取受害者的 IP。

# 摘要

在本章中，我们成功保存了与用户相关的数据。这些数据将在整个会话期间存储。用户无法直接修改它。

我们还研究了安全会话。请记住，用户会话可能会被攻击者窃取。根据项目的规模，有必要采取措施来保护网站。

在下一章中，我们将学习如何使用认证模块。它将允许我们创建用户并限制已登录用户访问某些页面。


# 第十章：认证模块

认证模块在为用户创建空间时节省了大量时间。以下是该模块的主要优势：

+   与用户相关的主要操作得到了简化（连接、帐户激活等）

+   使用该系统可以确保一定级别的安全性

+   页面的访问限制可以很容易地完成

这是一个非常有用的模块，我们甚至在不知不觉中已经使用了它。事实上，对管理模块的访问是通过认证模块执行的。我们在生成数据库时创建的用户是站点的第一个用户。

这一章大大改变了我们之前编写的应用程序。在本章结束时，我们将有：

+   修改我们的 UserProfile 模型，使其与模块兼容

+   创建了一个登录页面

+   修改了添加开发人员和监督员页面

+   增加对连接用户的访问限制

# 如何使用认证模块

在本节中，我们将学习如何通过使我们的应用程序与模块兼容来使用认证模块。

## 配置 Django 应用程序

通常情况下，我们不需要为管理模块在我们的`TasksManager`应用程序中工作做任何特殊的操作。事实上，默认情况下，该模块已启用，并允许我们使用管理模块。但是，可能会在禁用了 Web Django 认证模块的站点上工作。我们将检查模块是否已启用。

在`settings.py`文件的`INSTALLED_APPS`部分中，我们必须检查以下行：

```py
'django.contrib.auth',
```

## 编辑 UserProfile 模型

认证模块有自己的用户模型。这也是我们创建`UserProfile`模型而不仅仅是用户的原因。它是一个已经包含一些字段的模型，比如昵称和密码。要使用管理模块，必须在`Python33/Lib/site-package/django/contrib/auth/models.py`文件中使用用户模型。

我们将修改`models.py`文件中的`UserProfile`模型，将其变为以下内容：

```py
class UserProfile(models.Model):
  user_auth = models.OneToOneField(User, primary_key=True)
  phone = models.CharField(max_length=20, verbose_name="Phone number", null=True, default=None, blank=True)
  born_date = models.DateField(verbose_name="Born date", null=True, default=None, blank=True)
  last_connexion = models.DateTimeField(verbose_name="Date of last connexion", null=True, default=None, blank=True)
years_seniority = models.IntegerField(verbose_name="Seniority", default=0)
def __str__(self):
  return self.user_auth.username
```

我们还必须在`models.py`中添加以下行：

```py
from django.contrib.auth.models import User
```

在这个新模型中，我们有：

+   创建了与导入的用户模型的`OneToOneField`关系

+   删除了用户模型中不存在的字段

`OneToOne`关系意味着对于每个记录的`UserProfile`模型，都会有一个用户模型的记录。在做所有这些的过程中，我们深度修改了数据库。鉴于这些变化，并且因为密码以哈希形式存储，我们将不使用 South 进行迁移。

可以保留所有数据并使用 South 进行迁移，但是我们应该开发一个特定的代码来将`UserProfile`模型的信息保存到用户模型中。该代码还应该为密码生成哈希，但这将是很长的过程，而且不是本书的主题。要重置 South，我们必须执行以下操作：

+   删除`TasksManager/migrations`文件夹以及该文件夹中包含的所有文件

+   删除`database.db`文件

要使用迁移系统，我们必须使用关于模型的章节中已经使用过的以下命令：

```py
manage.py schemamigration TasksManager --initial
manage.py syncdb –migrate
```

删除数据库后，我们必须删除`create_developer.py`中的初始数据。我们还必须删除`developer_detail`的 URL 和`index.html`中的以下行：

```py
<a href="{% url "developer_detail" "2" %}">Detail second developer (The second user must be a developer)</a><br />
```

# 添加用户

允许您添加开发人员和监督员的页面不再起作用，因为它们与我们最近的更改不兼容。我们将更改这些页面以整合我们的样式更改。`create_supervisor.py`文件中包含的视图将包含以下代码：

```py
from django.shortcuts import render
from TasksManager.models import Supervisor
from django import forms
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User
def page(request):
  if request.POST:
    form = Form_supervisor(request.POST)
    if form.is_valid(): 
      name           = form.cleaned_data['name']
      login          = form.cleaned_data['login']
      password       = form.cleaned_data['password']
      specialisation = form.cleaned_data['specialisation']
      email          = form.cleaned_data['email']
      new_user = User.objects.create_user(username = login, email = email, password=password)
      # In this line, we create an instance of the User model with the create_user() method. It is important to use this method because it can store a hashcode of the password in database. In this way, the password cannot be retrieved from the database. Django uses the PBKDF2 algorithm to generate the hash code password of the user.
      new_user.is_active = True
      # In this line, the is_active attribute defines whether the user can connect or not. This attribute is false by default which allows you to create a system of account verification by email, or other system user validation.
      new_user.last_name=name
      # In this line, we define the name of the new user.
      new_user.save()
      # In this line, we register the new user in the database.
      new_supervisor = Supervisor(user_auth = new_user, specialisation=specialisation)
      # In this line, we create the new supervisor with the form data. We do not forget to create the relationship with the User model by setting the property user_auth with new_user instance.
      new_supervisor.save()
      return HttpResponseRedirect(reverse('public_empty')) 
    else:
      return render(request, 'en/public/create_supervisor.html', {'form' : form})
  else:
    form = Form_supervisor()
  form = Form_supervisor()
  return render(request, 'en/public/create_supervisor.html', {'form' : form})
class Form_supervisor(forms.Form):
  name = forms.CharField(label="Name", max_length=30)
  login = forms.CharField(label = "Login")
  email = forms.EmailField(label = "Email")
  specialisation = forms.CharField(label = "Specialisation")
  password = forms.CharField(label = "Password", widget = forms.PasswordInput)
  password_bis = forms.CharField(label = "Password", widget = forms.PasswordInput) 
  def clean(self): 
    cleaned_data = super (Form_supervisor, self).clean() 
    password = self.cleaned_data.get('password') 
    password_bis = self.cleaned_data.get('password_bis')
    if password and password_bis and password != password_bis:
      raise forms.ValidationError("Passwords are not identical.") 
    return self.cleaned_data
```

`create_supervisor.html`模板保持不变，因为我们正在使用 Django 表单。

您可以更改`create_developer.py`文件中的`page()`方法，使其与认证模块兼容（您可以参考可下载的 Packt 代码文件以获得进一步的帮助）：

```py
def page(request):
  if request.POST:
    form = Form_inscription(request.POST)
    if form.is_valid():
      name          = form.cleaned_data['name']
      login         = form.cleaned_data['login']
      password      = form.cleaned_data['password']
      supervisor    = form.cleaned_data['supervisor'] 
      new_user = User.objects.create_user(username = login, password=password)
      new_user.is_active = True
      new_user.last_name=name
      new_user.save()
      new_developer = Developer(user_auth = new_user, supervisor=supervisor)
      new_developer.save()
      return HttpResponse("Developer added")
    else:
      return render(request, 'en/public/create_developer.html', {'form' : form})
  else:
    form = Form_inscription()
    return render(request, 'en/public/create_developer.html', {'form' : form})
```

我们还可以修改`developer_list.html`，内容如下：

```py
{% extends "base.html" %}
{% block title_html %}
    Developer list
{% endblock %}
{% block h1 %}
    Developer list
{% endblock %}
{% block article_content %}
    <table>
        <tr>
            <td>Name</td>
            <td>Login</td>
            <td>Supervisor</td>
        </tr>
        {% for dev in object_list %}
            <tr>
                <!-- The following line displays the __str__ method of the model. In this case it will display the username of the developer -->
                <td><a href="">{{ dev }}</a></td>
                <!-- The following line displays the last_name of the developer -->
                <td>{{ dev.user_auth.last_name }}</td>
                <!-- The following line displays the __str__ method of the Supervisor model. In this case it will display the username of the supervisor -->
                <td>{{ dev.supervisor }}</td>
            </tr>
        {% endfor %}
    </table>
{% endblock %}
```

# 登录和注销页面

现在您可以创建用户，必须创建一个登录页面，以允许用户进行身份验证。我们必须在`urls.py`文件中添加以下 URL：

```py
url(r'^connection$', 'TasksManager.views.connection.page', name="public_connection"),
```

然后，您必须创建`connection.py`视图，并使用以下代码：

```py
from django.shortcuts import render
from django import forms
from django.contrib.auth import authenticate, login
# This line allows you to import the necessary functions of the authentication module.
def page(request):
  if request.POST:
  # This line is used to check if the Form_connection form has been posted. If mailed, the form will be treated, otherwise it will be displayed to the user.
    form = Form_connection(request.POST) 
    if form.is_valid():
      username = form.cleaned_data["username"]
      password = form.cleaned_data["password"]
      user = authenticate(username=username, password=password)
      # This line verifies that the username exists and the password is correct.
      if user:
      # In this line, the authenticate function returns None if authentication has failed, otherwise it returns an object that validates the condition.
        login(request, user)
        # In this line, the login() function allows the user to connect.
    else:
      return render(request, 'en/public/connection.html', {'form' : form})
  else:
    form = Form_connection()
  return render(request, 'en/public/connection.html', {'form' : form})
class Form_connection(forms.Form):
  username = forms.CharField(label="Login")
  password = forms.CharField(label="Password", widget=forms.PasswordInput)
  def clean(self):
    cleaned_data = super(Form_connection, self).clean()
    username = self.cleaned_data.get('username')
    password = self.cleaned_data.get('password')
    if not authenticate(username=username, password=password):
      raise forms.ValidationError("Wrong login or password")
    return self.cleaned_data
```

然后，您必须创建`connection.html`模板，并使用以下代码：

```py
{% extends "base.html" %}
{% block article_content %}
  {% if user.is_authenticated %}
  <-- This line checks if the user is connected.-->
    <h1>You are connected.</h1>
    <p>
      Your email : {{ user.email }}
      <-- In this line, if the user is connected, this line will display his/her e-mail address.-->
    </p>
  {% else %}
  <!-- In this line, if the user is not connected, we display the login form.-->
    <h1>Connexion</h1>
    <form method="post" action="{{ public_connection }}">
      {% csrf_token %}
      <table>
        {{ form.as_table }}
      </table>
      <input type="submit" class="button" value="Connection" />
    </form>
  {% endif %}
{% endblock %}
```

当用户登录时，Django 将在会话变量中保存他/她的数据连接。此示例已经允许我们验证登录和密码对用户是透明的。确实，`authenticate()`和`login()`方法允许开发人员节省大量时间。Django 还为开发人员提供了方便的快捷方式，例如`user.is_authenticated`属性，用于检查用户是否已登录。用户更喜欢网站上有注销链接，特别是在从公共计算机连接时。我们现在将创建注销页面。

首先，我们需要创建带有以下代码的`logout.py`文件：

```py
from django.shortcuts import render
from django.contrib.auth import logout
def page(request):
    logout(request)
    return render(request, 'en/public/logout.html')
```

在先前的代码中，我们导入了身份验证模块的`logout()`函数，并将其与请求对象一起使用。此函数将删除请求对象的用户标识符，并删除其会话数据。

当用户注销时，他/她需要知道网站实际上已断开连接。让我们在`logout.html`文件中创建以下模板：

```py
{% extends "base.html" %}
{% block article_content %}
  <h1>You are not connected.</h1>
{% endblock %}
```

# 限制对已连接成员的访问

当开发人员实现身份验证系统时，通常是为了限制匿名用户的访问。在本节中，我们将看到控制对我们网页访问的两种方式。

## 限制对视图的访问

身份验证模块提供了简单的方法来防止匿名用户访问某些页面。确实，有一个非常方便的装饰器来限制对视图的访问。这个装饰器称为`login_required`。

在接下来的示例中，我们将使用设计师以以下方式限制对`create_developer`模块中的`page()`视图的访问： 

1.  首先，我们必须使用以下行导入装饰器：

```py
from django.contrib.auth.decorators import login_required
```

1.  然后，我们将在视图声明之前添加装饰器：

```py
@login_required
def page(request): # This line already exists. Do not copy it.
```

1.  通过添加这两行，只有已登录用户才能访问添加开发人员的页面。如果尝试在未连接的情况下访问页面，您将意识到这并不是很实用，因为获得的页面是 404 错误。要改进此问题，只需告诉 Django 连接 URL 是什么，通过在`settings.py`文件中添加以下行：

```py
LOGIN_URL = 'public_connection'
```

1.  通过这一行，如果用户尝试访问受保护的页面，他/她将被重定向到登录页面。您可能已经注意到，如果您未登录并单击**创建开发人员**链接，则 URL 包含一个名为 next 的参数。以下是 URL 的屏幕截图：![限制对视图的访问](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/gtst-dj/img/00027.jpeg)

1.  此参数包含用户尝试查看的 URL。身份验证模块在用户连接时将用户重定向到该页面。为此，我们将修改我们创建的`connection.py`文件。我们添加导入`render()`函数以导入`redirect()`函数的行：

```py
from django.shortcuts import render, redirect
```

1.  要在用户登录后重定向用户，我们必须在包含代码 login(request, user)的行之后添加两行。需要添加两行：

```py
if request.GET.get('next') is not None:
  return redirect(request.GET['next'])
```

当用户会话已过期并且希望查看特定页面时，此系统非常有用。

## 限制对 URL 的访问

我们所见的系统不仅仅限制对 CBV 生成的页面的访问。为此，我们将使用相同的装饰器，但这次是在`urls.py`文件中。

我们将添加以下行以导入装饰器：

```py
from django.contrib.auth.decorators import login_required
```

我们需要更改对应于名为`create_project`的 URL 的行：

```py
url (r'^create_project$', login_required(CreateView.as_view(model=Project, template_name="en/public/create_project.html", success_url = 'index')), name="create_project"),
```

使用`login_required`装饰器非常简单，可以让开发人员不浪费太多时间。

# 摘要

在本章中，我们修改了我们的应用程序，使其与认证模块兼容。我们创建了允许用户登录和注销的页面。然后，我们学习了如何限制已登录用户对某些页面的访问。

在下一章中，我们将通过添加 AJAX 请求来提高应用程序的可用性。我们将学习 jQuery 的基础知识，然后学习如何使用它来向服务器发出异步请求。此外，我们还将学习如何处理来自服务器的响应。


# 第十一章：在 Django 中使用 AJAX

AJAX 是异步 JavaScript 和 XML 的缩写。这项技术允许浏览器使用 JavaScript 与服务器异步通信。不一定需要刷新网页来执行服务器上的操作。

已发布许多基于 AJAX 的 Web 应用程序。Web 应用程序通常被描述为只包含一个页面的网站，并且使用 AJAX 服务器执行所有操作。

如果不使用库，使用 AJAX 需要大量代码行才能与多个浏览器兼容。包含 jQuery 后，可以轻松进行 AJAX 请求，同时与许多浏览器兼容。

在本章中，我们将涵盖：

+   使用 JQuery

+   JQuery 基础

+   在任务管理器中使用 AJAX

# 使用 jQuery

jQuery 是一个旨在有效操作 HTML 页面的 DOM 的 JavaScript 库。**DOM**（**文档对象模型**）是 HTML 代码的内部结构，jQuery 极大地简化了处理过程。

以下是 jQuery 的一些优点：

+   DOM 操作可以使用 CSS 1-3 选择器

+   它集成了 AJAX

+   可以使用视觉效果来使页面动画化

+   良好的文档，有许多示例

+   围绕 jQuery 创建了许多库

# jQuery 基础

在本章中，我们使用 jQuery 进行 AJAX 请求。在使用 jQuery 之前，让我们先了解其基础知识。

## jQuery 中的 CSS 选择器

在样式表中使用的 CSS 选择器可以有效地检索具有非常少代码的项目。这是一个非常有趣的功能，它以以下语法实现在 HTML5 选择器 API 中：

```py
item = document.querySelector('tag#id_content');
```

jQuery 还允许我们使用 CSS 选择器。要使用 jQuery 执行相同的操作，必须使用以下语法：

```py
item = $('tag#id_content');
```

目前，最好使用 jQuery 而不是选择器 API，因为 jQuery 1.x.x 保证与旧版浏览器的兼容性很好。

## 获取 HTML 内容

可以使用`html()`方法获取两个标签之间的 HTML 代码：

```py
alert($('div#div_1').html());
```

这行将显示一个警报，其中包含`<div id="div_1">`标签的 HTML 内容。关于输入和文本区域标签，可以以与`val()`方法相同的方式恢复它们的内容。

## 在元素中设置 HTML 内容

更改标签的内容非常简单，因为我们使用了与恢复相同的方法。两者之间的主要区别在于我们将一个参数发送到方法。

因此，以下指令将在 div 标签中添加一个按钮：

```py
$('div#div_1').html($('div#div_1').html()+'<button>JQuery</button>');
```

## 循环元素

jQuery 还允许我们循环所有与选择器匹配的元素。为此，您必须使用`each()`方法，如下例所示：

```py
var cases = $('nav ul li').each(function() {
  $(this).addClass("nav_item");
});
```

## 导入 jQuery 库

要使用 jQuery，必须首先导入库。将 jQuery 添加到网页有两种方法。每种方法都有其自己的优势，如下所述：

+   下载 jQuery 并从我们的 Web 服务器导入。使用此方法，我们可以控制库，并确保文件在我们自己的网站上也是可访问的。

+   使用 Google 托管书店的托管库，可从任何网站访问。优点是我们避免向我们的服务器发出 HTTP 请求，从而节省了一些功率。

在本章中，我们将在我们的 Web 服务器上托管 jQuery，以免受主机的限制。

我们将在应用程序的所有页面中导入 jQuery，因为我们可能需要多个页面。此外，浏览器的缓存将保留 jQuery 一段时间，以免频繁下载。为此，我们将下载 jQuery 1.11.0 并保存在`TasksManager/static/javascript/lib/jquery-1.11.0.js`文件中。

然后，您必须在`base.html`文件的 head 标签中添加以下行：

```py
<script src="img/jquery-1.11.0.js' %}"></script>
{% block head %}{% endblock %}
```

通过这些更改，我们可以在网站的所有页面中使用 jQuery，并且可以在扩展`base.html`的模板中的`head`块中添加行。

# 在任务管理器中使用 AJAX

在这一部分，我们将修改显示任务列表的页面，以便在 AJAX 中执行删除任务。为此，我们将执行以下步骤：

1.  在`task_list`页面上添加一个`删除`按钮。

1.  创建一个 JavaScript 文件，其中包含 AJAX 代码和处理 AJAX 请求返回值的函数。

1.  创建一个 Django 视图来删除任务。

我们将通过修改`tasks_list.html`模板来添加删除按钮。为此，您必须将`tasks_list`中的`for`任务循环更改为以下内容：

```py
{% for task in tasks_list %}
  <tr id="task_{{ task.id }}">
    <td><a href="{% url "task_detail" task.id %}">{{ task.title }}</a></td>
    <td>{{ task.description|truncatechars:25 }}</td>
    <td><a href="{% url "update_task" task.id %}">Edit</a></td>
    <td><button onclick="javascript:task_delete({{ task.id }}, '{% url "task
_delete_ajax" %}');">Delete</button></td>
  </tr>
{% endfor %}
```

在上面的代码中，我们向`<tr>`标签添加了一个`id`属性。这个属性将在 JavaScript 代码中很有用，当页面接收到 AJAX 响应时，它将删除任务行。我们还用一个执行 JavaScript `task_delete()` 函数的**删除**按钮替换了**删除**链接。新按钮将调用`task_delete()`函数来执行 AJAX 请求。这个函数接受两个参数：

+   任务的标识符

+   AJAX 请求的 URL

我们将在`static/javascript/task.js`文件中创建这个函数，添加以下代码：

```py
function task_delete(id, url){
  $.ajax({
    type: 'POST', 
    // Here, we define the used method to send data to the Django views. Other values are possible as POST, GET, and other HTTP request methods.
    url: url, 
    // This line is used to specify the URL that will process the request.
    data: {task: id}, 
    // The data property is used to define the data that will be sent with the AJAX request.
    dataType:'json', 
    // This line defines the type of data that we are expecting back from the server. We do not necessarily need JSON in this example, but when the response is more complete, we use this kind of data type.
    success: task_delete_confirm,
    // The success property allows us to define a function that will be executed when the AJAX request works. This function receives as a parameter the AJAX response.
    error: function () {alert('AJAX error.');} 
    // The error property can define a function when the AJAX request does not work. We defined in the previous code an anonymous function that displays an AJAX error to the user.
  });
}
function task_delete_confirm(response) {
  task_id = JSON.parse(response); 
  // This line is in the function that receives the AJAX response when the request was successful. This line allows deserializing the JSON response returned by Django views.
  if (task_id>0) {
    $('#task_'+task_id).remove(); 
    // This line will delete the <tr> tag containing the task we have just removed
  }
  else {
    alert('Error');
  }
}
```

我们必须在`tasks_list.html`模板中的`title_html`块之后添加以下行，以在模板中导入`task.js`：

```py
{% load static %}
{% block head %}
  <script src="img/task.js' %}"></script>
{% endblock %}
```

我们必须在`urls.py`文件中添加以下 URL：

```py
  url(r'^task-delete-ajax$', 'TasksManager.views.ajax.task_delete_ajax.page', name="task_delete_ajax"),
```

这个 URL 将使用`view/ajax/task_delete_ajax.py`文件中包含的视图。我们必须创建带有`__init__.py`文件的 AJAX 模块，以及我们的`task_delete_ajax.py`文件，内容如下：

```py
from TasksManager.models import Task
from django.http import HttpResponse
from django import forms
from django.views.decorators.csrf import csrf_exempt
# We import the csrf_exempt decorator that we will use to line 4.
import json
# We import the json module we use to line 8.
class Form_task_delete(forms.Form):
# We create a form with a task field that contains the identifier of the task. When we create a form it allows us to use the Django validators to check the contents of the data sent by AJAX. Indeed, we are not immune that the user sends data to hack our server.
  task       = forms.IntegerField()
@csrf_exempt
# This line allows us to not verify the CSRF token for this view. Indeed, with AJAX we cannot reliably use the CSRF protection.
def page(request):
  return_value="0"
  # We create a variable named return_value that will contain a code returned to our JavaScript function. We initialize the value 0 to the variable.
  if len(request.POST) > 0:
    form = Form_task_delete(request.POST)
    if form.is_valid():
    # This line allows us to verify the validity of the value sent by the AJAX request.
      id_task = form.cleaned_data['task']
      task_record = Task.objects.get(id = id_task)
      task_record.delete()
      return_value=id_task
      # If the task been found, the return_value variable will contain the value of the id property after removing the task. This value will be returned to the JavaScript function and will be useful to remove the corresponding row in the HTML table.
  # The following line contains two significant items. The json.dumps() function will return a serialized JSON object. Serialization allows encoding an object sequence of characters. This technique allows different languages to share objects transparently. We also define a content_type to specify the type of data returned by the view.
  return HttpResponse(json.dumps(return_value), content_type = "application/json")
```

# 总结

在本章中，我们学习了如何使用 jQuery。我们看到了如何使用这个库轻松访问 DOM。我们还在我们的`TasksManager`应用程序上创建了一个 AJAX 请求，并编写了处理这个请求的视图。

在下一章中，我们将学习如何部署基于 Nginx 和 PostgreSQL 服务器的 Django 项目。我们将逐步看到并讨论安装步骤。


# 第十二章：使用 Django 进行生产

当网站的开发阶段完成并且您希望使其对用户可访问时，您必须部署它。以下是要执行此操作的步骤：

+   完成开发

+   选择物理服务器

+   选择服务器软件

+   选择服务器数据库

+   安装 PIP 和 Python 3

+   安装 PostgreSQL

+   安装 Nginx

+   安装 virtualenv 并创建虚拟环境

+   安装 Django，South，Gunicorn 和 psycopg2

+   配置 PostgreSQL

+   将 Work_manager 调整为生产

+   初始 South 迁移

+   使用 Gunicorn

+   启动 Nginx

# 完成开发

在部署之前进行一些测试非常重要。实际上，当网站部署后，问题更难解决；这对开发人员和用户来说可能是巨大的时间浪费。这就是为什么我再次强调：您必须进行充分的测试！

# 选择物理服务器

物理服务器是托管您的网站的机器。在家中托管自己的网站是可能的，但这不适合专业网站。事实上，由于许多网站用户使用该网站，因此需要使用网络主机。有许多不同类型的住宿，如下所示：

+   **简单托管**：这种类型的托管适用于需要高质量服务但没有很多功率的网站。通过这种住宿，您无需处理系统管理，但它不允许与专用服务器一样的灵活性。这种类型的托管在 Django 网站上也有另一个缺点：尚未有许多提供与 Django 兼容的住宿。

+   **专用服务器**：这是最灵活的住宿类型。我们租用（或购买）一台服务器，由提供互联网连接和其他服务的网络主机提供。根据所需的配置不同，价格也不同，但功能强大的服务器非常昂贵。这种类型的住宿要求您处理系统管理，除非您订阅外包服务。外包服务允许您使用系统管理员来照顾服务器，并获得报酬。

+   **虚拟服务器**：虚拟服务器与专用服务器非常相似。它们通常价格较低，因为一些虚拟服务器可以在单个物理服务器上运行。主机经常提供额外的服务，如服务器热备份或复制。

选择住宿类型应基于您的需求和财政资源。

以下是提供 Django 的主机的非详尽列表：

+   alwaysdata

+   WebFaction

+   DjangoEurope

+   DjangoFoo Hosting

# 选择服务器软件

在开发阶段，我们使用了 Django 附带的服务器。该服务器在开发过程中非常方便，但不适合生产网站。事实上，开发服务器既不高效也不安全。您必须选择另一种类型的服务器来安装它。有许多 Web 服务器；我们选择了其中两个：

+   **Apache HTTP 服务器**：根据 Netcraft 的数据，自 1996 年以来，这一直是最常用的 Web 服务器。这是一个模块化服务器，允许您安装模块而无需编译服务器。近年来，它的使用越来越少。根据 Netcraft 的数据，2013 年 4 月，市场份额为 51％。

+   **Nginx**：Nginx 以其性能和低内存消耗而闻名。它也是模块化的，但模块需要在编译中集成。2013 年 4 月，Netcraft 知道的所有网站中有 14％使用了 Nginx 作为其 Web 服务器。

# 选择服务器数据库

选择服务器数据库非常重要。实际上，该服务器将存储网站的所有数据。在数据库中寻求的主要特征是性能，安全性和可靠性。

选择取决于以下三个标准的重要性：

+   **Oracle**：这个数据库是由 Oracle Corporation 开发的系统数据库。有这个数据库的免费开源版本，但其功能有限。这不是一个免费的数据库。

+   **MySQL**：这是属于 Oracle 的数据库系统（自从收购 Sun Microsystems 以来）。它是 Web 上广泛使用的数据库，包括**LAMP**（**Linux Apache MySQL PHP**）平台。它以双 GPL 和专有许可证进行分发。

+   **PostgreSQL**：这是一个根据 BSD 许可证分发的免费数据库系统。这个系统被认为是稳定的，并提供高级功能（如数据类型的创建）。

+   **SQLite**：这是我们在开发网站期间使用的系统。它不适合访问量很大的网站。事实上，整个数据库都在一个 SQLite 文件中，并且不允许竞争对手访问数据。此外，没有用户或系统没有安全机制。但是，完全可以用它来向客户演示。

+   **MongoDB**：这是一个面向文档的数据库。这个数据库系统被归类为 NoSQL 数据库，因为它使用了使用**BSON**（**二进制 JSON**）格式的存储架构。这个系统在数据库分布在多台服务器之间的环境中很受欢迎。

# 部署 Django 网站

在本书的其余部分，我们将使用 HTTP Nginx 服务器和 PostgreSQL 数据库。本章的解释将在 GNU / Linux Debian 7.3.0 32 位系统上进行。我们将从一个没有任何安装的新的 Debian 操作系统开始。

## 安装 PIP 和 Python 3

对于以下命令，您必须使用具有与超级用户帐户相同特权的用户帐户登录。为此，请运行以下命令：

```py
su

```

在此命令之后，您必须输入 root 密码。

首先，我们更新 Debian 存储库：

```py
apt-get update

```

然后，我们安装 Python 3 和 PIP，就像在第二章中所做的那样，*创建一个 Django 项目*：

```py
apt-get install python3
apt-get install python3-pip
alias pip=pip-3.2

```

## 安装 PostgreSQL

我们将安装四个软件包以便使用 PostgreSQL：

```py
apt-get install libpq-dev python-dev postgresql postgresql-contrib

```

然后，我们将安装我们的 web Nginx 服务器：

```py
apt-get install nginx

```

## 安装 virtualenv 并创建虚拟环境

我们已经像在第二章中所做的那样安装了 Python 和 PIP，但在安装 Django 之前，我们将安装 virtualenv。这个工具用于为 Python 创建虚拟环境，并在同一个操作系统上拥有不同的库版本。事实上，在许多 Linux 系统中，Debian 已经安装了 Python 2 的一个版本。建议您不要卸载它以保持系统的稳定。我们将安装 virtualenv 来设置我们自己的环境，并简化我们未来的 Django 迁移：

```py
pip install virtualenv

```

然后，您必须创建一个将托管您的虚拟环境的文件夹：

```py
mkdir /home/env

```

以下命令在`/home/env/`文件夹中创建一个名为`django1.6`的虚拟环境：

```py
virtualenv /home/env/django1.6

```

然后，我们将通过发出以下命令为所有用户提供访问环境文件夹的所有权限。从安全的角度来看，最好限制用户或组的访问，但这将花费很多时间：

```py
cd /home/
chmod -R 777 env/
exit

```

# 安装 Django、South、Gunicorn 和 psycopg2

我们将安装 Django 和所有 Nginx 和 Django 通信所需的组件。我们首先激活我们的虚拟环境。以下命令将连接我们到虚拟环境。因此，从此环境中执行的所有 Python 命令只能使用此环境中安装的软件包。在我们的情况下，我们将安装四个仅安装在我们的虚拟环境中的库。对于以下命令，您必须以没有超级用户特权的用户登录。我们不能从 root 帐户执行以下命令，因为我们需要 virtualenv。但是，root 帐户有时会覆盖虚拟环境，以使用系统中的 Python，而不是虚拟环境中存在的 Python。

```py
source /home/env/django1.6/bin/activate
pip install django=="1.6"
pip install South

```

Gunicorn 是一个扮演 Python 和 Nginx 之间 WSGI 接口角色的 Python 包。要安装它，请发出以下命令：

```py
pip install gunicorn 

```

psycopg2 是一个允许 Python 和 PostgreSQL 相互通信的库：

```py
pip install psycopg2

```

要重新连接为超级用户，我们必须断开与虚拟环境的连接：

```py
deactivate

```

## 配置 PostgreSQL

对于以下命令，您必须使用具有与超级用户相同特权的用户帐户登录。我们将连接到 PostgreSQL 服务器：

```py
su
su - postgres

```

以下命令创建一个名为`workmanager`的数据库：

```py
createdb workmanager

```

然后，我们将为 PostgreSQL 创建一个用户。输入以下命令后，会要求更多信息：

```py
createuser -P 

```

以下行是 PostgreSQL 要求的新用户信息和响应（用于本章）：

```py
Role name : workmanager
Password : workmanager
Password confirmation : workmanager
Super user : n
Create DB : n
Create new roles : n

```

然后，我们必须连接到 PostgreSQL 解释器：

```py
psql 

```

我们在新数据库上给予新用户所有权限：

```py
GRANT ALL PRIVILEGES ON DATABASE workmanager TO workmanager;

```

然后，我们退出 SQL 解释器和与 PostgreSQL 的连接：

```py
\q
exit

```

## 将 Work_manager 适应到生产环境

对于以下命令，您必须以没有超级用户特权的用户登录。

在部署的这个阶段，我们必须复制包含我们的 Django 项目的文件夹。要复制的文件夹是`Work_manager`文件夹（其中包含`Work_manager`和`TasksManager`文件夹以及`manage.py`文件）。我们将其复制到虚拟环境的根目录，即`/home/env/django1.6`。

要复制它，您可以使用您拥有的手段：USB 键，SFTP，FTP 等。然后，我们需要编辑项目的`settings.py`文件以使其适应部署。

定义数据库连接的部分变为以下内容：

```py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2', 
        'NAME':  'workmanager',      
        'USER': 'workmanager',                     
        'PASSWORD': 'workmanager',                 
        'HOST': '127.0.0.1',                     
        'PORT': '',                     
    }
}
```

我们必须修改`ALLOWED_HOSTS`行如下：

```py
ALLOWED_HOSTS = ['*']
```

另外，重要的是不要使用`DEBUG`模式。实际上，`DEBUG`模式可以为黑客提供宝贵的数据。为此，我们必须以以下方式更改`DEBUG`和`TEMPLATE_DEBUG`变量：

```py
DEBUG = False
TEMPLATE_DEBUG = False
```

## 初始 South 迁移

我们激活我们的虚拟环境以执行迁移并启动 Gunicorn：

```py
cd /home/env/django1.6/Work_manager/
source /home/env/django1.6/bin/activate
python3.2 manage.py schemamigration TasksManager --initial
python3.2 manage.py syncdb -–migrate

```

有时，使用 PostgreSQL 创建数据库时会出现错误，即使一切顺利。要查看数据库的创建是否顺利，我们必须以 root 用户身份运行以下命令，并验证表是否已创建：

```py
su
su - postgres
psql -d workmanager
\dt
\q
exit

```

如果它们被正确创建，您必须进行一个虚假的 South 迁移，手动告诉它一切顺利：

```py
python3.2 manage.py migrate TasksManager --fake

```

## 使用 Gunicorn

然后，我们启动我们的 WSGI 接口，以便 Nginx 进行通信：

```py
gunicorn Work_manager.wsgi

```

## 启动 Nginx

另一个命令提示符作为 root 用户必须使用以下命令运行 Nginx：

```py
su
service nginx start

```

现在，我们的 Web 服务器是功能性的，并且已准备好与许多用户一起工作。

# 总结

在本章中，我们学习了如何使用现代架构部署 Django 网站。此外，我们使用了 virtualenv，它允许您在同一系统上使用多个版本的 Python 库。

在这本书中，我们学习了什么是 MVC 模式。我们已经为我们的开发环境安装了 Python 和 Django。我们学会了如何创建模板、视图和模型。我们还使用系统来路由 Django 的 URL。我们还学会了如何使用一些特定的元素，比如 Django 表单、CBV 或认证模块。然后，我们使用了会话变量和 AJAX 请求。最后，我们学会了如何在 Linux 服务器上部署 Django 网站。
