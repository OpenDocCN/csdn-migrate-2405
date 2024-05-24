# Flask 框架学习手册（二）

> 原文：[`zh.annas-archive.org/md5/A6963809F66F360038656FE5292ADA55`](https://zh.annas-archive.org/md5/A6963809F66F360038656FE5292ADA55)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：表单和验证

在本章中，我们将学习如何使用表单直接通过网站修改博客上的内容。这将是一个有趣的章节，因为我们将添加各种新的与网站交互的方式。我们将创建用于处理 Entry 模型的表单，学习如何接收和验证用户数据，并最终更新数据库中的值。表单处理和验证将由流行的 WTForms 库处理。我们将继续构建视图和模板来支持这些新的表单，并在此过程中学习一些新的 Jinja2 技巧。

在本章中，我们将：

+   安装 WTForms 并创建一个用于处理 Entry 模型的表单

+   编写视图来验证和处理表单数据，并将更改持久化到数据库中

+   创建模板来显示表单和验证错误

+   使用 Jinja2 宏来封装复杂的模板逻辑

+   向用户显示闪存消息

+   创建一个图片上传器，并学习如何安全处理文件上传

+   学习如何存储和提供静态资产，如 JavaScript、样式表和图像上传

# 开始使用 WTForms

**WTForms**是 Flask 社区中处理表单和验证的流行选择。它使用一种声明性的方法来构建表单（类似于我们定义 SQLAlchemy 模型的方式），并支持各种不同的字段类型和验证器。

### 注意

在撰写本书时，WTForms 2.0 仍然是一个开发版本，但应该很快就会成为官方版本。因此，我们将在本书中使用版本 2.0。

让我们开始通过将 WTForms 安装到我们的博客项目`virtualenv`中：

```py
(blog) $ pip install "wtforms>=2.0"
Successfully installed wtforms
Cleaning up...

```

我们可以通过打开一个 shell 并检查项目版本来验证安装是否成功：

```py
(blog) $ ./manage.py shell
In [1]: import wtforms

In [2]: wtforms.__version__
Out[2]: '2.0dev'

```

我的版本显示了开发版本，因为 2.0 尚未正式发布。

## 为 Entry 模型定义一个表单

我们的目标是能够直接通过我们的网站创建和编辑博客条目，因此我们需要回答的第一个问题是——我们将如何输入我们的新条目的数据？答案当然是使用表单。表单是 HTML 标准的一部分，它允许我们使用自由格式的文本输入、大型多行文本框、下拉选择、复选框、单选按钮等。当用户提交表单时，表单会指定一个 URL 来接收表单数据。然后该 URL 可以处理数据，然后以任何喜欢的方式做出响应。

对于博客条目，让我们保持简单，只有三个字段：

+   `标题`，显示为简单的文本输入

+   `正文`，显示为大型自由格式文本框

+   `状态`，将显示为下拉选择

在`entries`目录中，创建一个名为`forms.py`的新 Python 文件。我们将定义一个简单的表单类，其中包含这些字段。打开`forms.py`并添加以下代码：

```py
import wtforms

from models import Entry

class EntryForm(wtforms.Form):
    title = wtforms.StringField('Title')
    body = wtforms.TextAreaField('Body')
    status = wtforms.SelectField(
        'Entry status',
        choices=(
            (Entry.STATUS_PUBLIC, 'Public'),
            (Entry.STATUS_DRAFT, 'Draft')),
        coerce=int)
```

这应该看起来与我们的模型定义非常相似。请注意，我们正在使用模型中列的名称作为表单字段的名称：这将允许 WTForms 自动在 Entry 模型字段和表单字段之间复制数据。

前两个字段，`标题`和`正文`，都指定了一个参数：在渲染表单时将显示的标签。`状态`字段包含一个标签以及两个额外的参数：`choices`和`coerce`。`choices`参数由一个 2 元组的列表组成，其中第一个值是我们感兴趣存储的实际值，第二个值是用户友好的表示。第二个参数，`coerce`，将把表单中的值转换为整数（默认情况下，它将被视为字符串，这是我们不想要的）。

## 一个带有视图的表单

为了开始使用这个表单，我们需要创建一个视图，该视图将显示表单并在提交时接受数据。为此，让我们打开`entries`蓝图模块，并定义一个新的 URL 路由来处理条目创建。在`blueprint.py`文件的顶部，我们需要从`forms`模块导入`EntryForm`类：

```py
from app import db
from helpers import object_list
from models import Entry, Tag
from entries.forms import EntryForm

```

然后，在`detail`视图的定义之上，我们将添加一个名为`create`的新视图，该视图将通过导航到`/entries/create/`来访问。我们必须将其放在`detail`视图之上的原因是因为 Flask 将按照定义的顺序搜索 URL 路由。由于`/entries/create/`看起来非常像一个条目详细信息 URL（想象条目的标题是`create`），如果首先定义了详细信息路由，Flask 将在那里停止，永远不会到达创建路由。

在我们的创建视图中，我们将简单地实例化表单并将其传递到模板上下文中。添加以下视图定义：

```py
@entries.route('/create/')
def create():
    form = EntryForm()
    return render_template('entries/create.html', form=form)
```

在我们添加代码将新条目保存到数据库之前，让我们构建一个模板，看看我们的表单是什么样子。然后我们将回过头来添加代码来验证表单数据并创建新条目。

## create.html 模板

让我们为我们的新表单构建一个基本模板。在其他条目模板旁边创建一个名为`create.html`的新模板。相对于应用程序目录，该文件的路径应为`entries/templates/entries/create.html`。我们将扩展基本模板并覆盖内容块以显示我们的表单。由于我们使用的是 bootstrap，我们将使用特殊的 CSS 类来使我们的表单看起来漂亮。添加以下 HTML 代码：

```py
{% extends "base.html" %}

{% block title %}Create new entry{% endblock %}

{% block content_title %}Create new entry{% endblock %}

{% block content %}
  <form action="{{ url_for('entries.create') }}" class="form form-horizontal" method="post">
    {% for field in form %}
      <div class="form-group">
        {{ field.label(class='col-sm-3 control-label') }}
        <div class="col-sm-9">
          {{ field(class='form-control') }}
        </div>
      </div>
    {% endfor %}
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-default">Create</button>
        <a class="btn" href="{{ url_for('entries.index') }}">Cancel</a>
      </div>
    </div>
  </form>
{% endblock %}
```

通过迭代我们传入上下文的表单，我们可以渲染每个单独的字段。要渲染字段，我们首先通过简单调用`field.label()`并传入所需的 CSS 类来渲染字段的标签。同样，要渲染字段，我们调用`field()`，再次传入 CSS 类。还要注意的是，除了`submit`按钮，我们还添加了一个`Cancel`链接，该链接将返回用户到条目列表。

启动开发服务器并导航到`http://127.0.0.1:5000/entries/create/`以查看以下表单：

![create.html 模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_04_01.jpg)

尝试提交表单。当您点击**创建**按钮时，您应该会看到以下错误消息：

![create.html 模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_04_02.jpg)

您看到此消息的原因是因为默认情况下，Flask 视图只会响应 HTTP `GET`请求。当我们提交表单时，浏览器会发送`POST`请求，而我们的视图目前不接受。让我们返回`create`视图并添加代码来正确处理`POST`请求。

### 提示

每当表单对数据进行更改（创建、编辑或删除某些内容）时，该表单应指定`POST`方法。其他表单，例如我们的搜索表单，不进行任何更改，应使用`GET`方法。此外，当使用`GET`方法提交表单时，表单数据将作为查询字符串的一部分提交。

## 处理表单提交

在修改视图之前，让我们向我们的`EntryForm`添加一个辅助方法，我们将使用该方法将数据从表单复制到我们的`Entry`对象中。打开`forms.py`并进行以下添加：

```py
class EntryForm(wtforms.Form):
    ...
    def save_entry(self, entry):
 self.populate_obj(entry)
 entry.generate_slug()
 return entry

```

这个辅助方法将用表单数据填充我们传入的`entry`，根据标题重新生成条目的 slug，然后返回`entry`对象。

现在表单已配置为填充我们的`Entry`模型，我们可以修改视图以接受和处理`POST`请求。我们将使用两个新的 Flask 辅助函数，因此修改`blueprint.py`顶部的导入，添加`redirect`和`url_for`：

```py
from flask import Blueprint, redirect, render_template, request, url_for

```

添加导入后，更新`blueprint.py`中`create`视图的以下更改：

```py
from app import db
@entries.route('/create/', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        form = EntryForm(request.form)
        if form.validate():
            entry = form.save_entry(Entry())
            db.session.add(entry)
            db.session.commit()
            return redirect(url_for('entries.detail', slug=entry.slug))
    else:
        form = EntryForm()

    return render_template('entries/create.html', form=form)
```

这是相当多的新代码，让我们仔细看看发生了什么。首先，我们在路由装饰器中添加了一个参数，指示此视图接受`GET`和`POST`请求。这将消除当我们提交表单时出现的**方法不允许**错误。

在视图的主体中，我们现在正在检查`request`方法，并根据这一点做两件事中的一件。让我们首先看看'else'子句。当我们收到`GET`请求时，比如当有人打开他们的浏览器并导航到`/entries/create/`页面时，代码分支将执行。当这种情况发生时，我们只想显示包含表单的 HTML 页面，因此我们将实例化一个表单并将其传递到模板上下文中。

如果这是一个`POST`请求，当有人提交表单时会发生，我们想要实例化`EntryForm`并传入原始表单数据。Flask 将原始的 POST 数据存储在特殊属性`request.form`中，这是一个类似字典的对象。WTForms 知道如何解释原始表单数据并将其映射到我们定义的字段。

在用原始表单数据实例化我们的表单之后，我们需要检查并确保表单有效，通过调用`form.validate()`。如果表单由于某种原因未能验证，我们将简单地将无效的表单传递到上下文并呈现模板。稍后您将看到我们如何在用户的表单提交出现问题时向用户显示错误消息。

如果表单验证通过，我们最终可以继续保存条目。为此，我们将调用我们的`save_entry`辅助方法，传入一个新的`entry`实例。WTForms 将使用表单数据填充`Entry`对象，然后将其返回给我们，在那里我们将其添加到数据库会话中，提交并重定向。重定向助手将发出 HTTP 302 重定向，将用户的浏览器从`/entries/create/`发送到新创建的博客文章的详细页面。

打开你的浏览器，试一试。

![处理表单提交](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_04_03.jpg)

## 验证输入并显示错误消息

我们的表单存在一个明显的问题：现在没有任何东西可以阻止我们意外地提交一个空的博客条目。为了确保在保存时有标题和内容，我们需要使用一个名为验证器的 WTForm 对象。验证器是应用于表单数据的规则，WTForms 附带了许多有用的验证器。一些常用的验证器列在下面：

+   `DataRequired`：此字段不能为空

+   `Length(min=?, max=?)`：验证输入的数据的长度是否超过最小值，或者是否不超过最大值

+   `NumberRange(min=?, max=?)`：验证输入的数字是否在给定范围内

+   `Email`：验证数据是否为有效的电子邮件地址

+   `URL`：验证输入的数据是否为有效的 URL

+   `AnyOf(values=?)`：验证输入的数据是否等于提供的值之一

+   `NoneOf(values=?)`：验证输入的数据是否不等于提供的任何值

对于博客条目表单，我们将只使用`DataRequired`验证器来确保条目不能在没有标题或正文内容的情况下创建。让我们打开`forms.py`并将验证器添加到我们的表单定义中。总的来说，我们的表单模块应该如下所示：

```py
import wtforms
from wtforms.validators import DataRequired

from models import Entry

class EntryForm(wtforms.Form):
    title = wtforms.StringField(
        'Title',
        validators=[DataRequired()])
    body = wtforms.TextAreaField(
        'Body',
        validators=[DataRequired()])
    status = wtforms.SelectField(
        'Entry status',
        choices=(
            (Entry.STATUS_PUBLIC, 'Public'),
            (Entry.STATUS_DRAFT, 'Draft')),
        coerce=int)

    def save_entry(self, entry):
        self.populate_obj(entry)
        entry.generate_slug()
        return entry
```

启动开发服务器，现在尝试提交一个空表单。正如你所期望的那样，由于对`form.validate()`的调用返回`False`，它将无法保存。不幸的是，前端没有任何指示我们的表单为什么没有保存。幸运的是，WTForms 将使验证错误在模板中可用，我们所需要做的就是修改我们的模板来显示它们。

为了显示验证错误，我们将使用几个 bootstrap CSS 类和结构，但最终结果将非常好看，如下面的截图所示：

![验证输入并显示错误消息](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_04_04.jpg)

对`create.html`模板中的字段显示代码进行以下更改：

```py
{% for field in form %}
  <div class="form-group{% if field.errors %} has-error has-feedback{% endif %}">
    {{ field.label(class='col-sm-3 control-label') }}
    <div class="col-sm-9">
      {{ field(class='form-control') }}
      {% if field.errors %}
        <span class="glyphicon glyphicon-warning-sign form-control-feedback"></span>
      {% endif %}
      {% for error in field.errors %}<span class="help-block">{{ error }}</span>{% endfor %}
    </div>
  </div>
{% endfor %}
```

我们通过查看`field.errors`属性来检查字段是否有任何错误。如果有任何错误，那么我们会做以下事情：

+   向`form-group` div 添加 CSS 类

+   添加一个特殊的图标表示有错误发生

+   在表单字段下方显示每个错误的`<span>`。由于`field.errors`是一个列表，可能包含多个验证错误，我们将使用 for 循环来遍历这些错误。

现在，您可以使用表单创建有效的博客条目，该表单还会执行一些验证，以确保您不会提交空白表单。在下一节中，我们将描述如何重复使用相同的表单来编辑现有条目。

## 编辑现有条目

信不信由你，我们实际上可以使用相同的表单来编辑现有条目。我们只需要对视图和模板逻辑进行一些微小的更改，所以让我们开始吧。

为了编辑条目，我们将需要一个视图，因此我们将需要一个 URL。因为视图需要知道我们正在编辑哪个条目，所以将其作为 URL 结构的一部分传达是很重要的，因此我们将在`/entries/<slug>/edit/`设置`edit`视图。打开`entries/blueprint.py`，在详细视图下方，添加以下代码以获取`edit`视图。请注意与`create`视图的相似之处：

```py
@entries.route('/<slug>/edit/', methods=['GET', 'POST'])
def edit(slug):
    entry = Entry.query.filter(Entry.slug == slug).first_or_404()
    if request.method == 'POST':
        form = EntryForm(request.form, obj=entry)
        if form.validate():
            entry = form.save_entry(entry)
            db.session.add(entry)
            db.session.commit()
            return redirect(url_for('entries.detail', slug=entry.slug))
    else:
        form = EntryForm(obj=entry)

    return render_template('entries/edit.html', entry=entry, form=form)
```

就像我们在`create`视图中所做的那样，我们检查`request`方法，并根据它，我们将验证和处理表单，或者只是实例化它并将其传递给模板。

最大的区别在于我们如何实例化`EntryForm`。我们向它传递了一个额外的参数，`obj=entry`。当 WTForms 接收到一个`obj`参数时，它将尝试使用从`obj`中获取的值（在本例中是我们的博客条目）预填充表单字段。

我们还将在模板上下文中传递一个额外的值，即我们正在编辑的条目。我们这样做是为了能够向用户显示条目的标题；这样，我们可以使表单的**取消**按钮链接回条目详细视图。

### 编辑.html 模板

正如您可能猜到的，`edit.html`模板几乎与`create.html`相同。由于字段渲染逻辑的复杂性，复制并粘贴所有代码似乎是一个坏主意。如果我们决定更改表单字段的显示方式，我们将发现自己需要修改多个文件，这应该始终是一个很大的警告信号。

为了避免这种情况，我们将使用一个强大的 Jinja2 功能，称为宏，来渲染我们的字段。字段渲染代码将在宏中定义，然后，无论我们想要渲染一个字段的地方，我们只需调用我们的宏。这样可以很容易地更改我们的字段样式。

### 提示

宏是 Jinja2 的一个功能，允许您将模板的一部分视为函数，因此可以使用不同的参数多次调用它，并生成基本相似的 HTML。您可以在 Jinja 文档网站上查看更多内容：[`jinja.pocoo.org/docs/dev/templates/`](http://jinja.pocoo.org/docs/dev/templates/)

由于这个宏对于我们可能希望显示的任何表单字段都是有用的，我们将把它放在我们应用程序的模板目录中。在应用程序的模板目录中，创建一个名为`macros`的新目录，并添加一个字段`form_field.html`。相对于应用程序目录，该文件的路径是`templates/macros/form_field.html`。添加以下代码：

```py
{% macro form_field(field) %}
  <div class="form-group{% if field.errors %} has-error has-feedback{% endif %}">
    {{ field.label(class='col-sm-3 control-label') }}
    <div class="col-sm-9">
      {{ field(class='form-control', **kwargs) }}
      {% if field.errors %}<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span>{% endif %}
      {% for error in field.errors %}<span class="help-block">{{ error }}</span>{% endfor %}
    </div>
  </div>
{% endmacro %}
```

在大部分情况下，我们只是从`create`模板中复制并粘贴了字段渲染代码，但有一些区别我想指出：

+   模板以`macro`模板标签开头，定义了`macro`的名称和它接受的任何参数。

+   当我们渲染字段时，我们传入`**kwargs`。WTForms 字段可以接受任意关键字参数，然后将其转换为 HTML 标记上的属性。虽然我们目前不打算使用这个功能，但我们将在后面的章节中使用它。

+   我们使用`endmacro`标记表示宏的结束。

现在让我们更新`create.html`以使用新的宏。为了使用这个宏，我们必须首先`import`它。然后我们可以用一个简单的宏调用替换所有的字段标记。通过这些更改，`create.html`模板应该是这样的：

```py
{% extends "base.html" %}
{% from "macros/form_field.html" import form_field %}

{% block title %}Create new entry{% endblock %}

{% block content_title %}Create new entry{% endblock %}

{% block content %}
  <form action="{{ url_for('entries.create') }}" class="form form-horizontal" method="post">
    {% for field in form %}
      {{ form_field(field) }}
    {% endfor %}
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-default">Create</button>
        <a class="btn" href="{{ url_for('entries.index') }}">Cancel</a>
      </div>
    </div>
  </form>
{% endblock %}
```

搞定这些之后，我们可以继续创建我们的`edit.html`模板。它看起来几乎和`create`模板一样，只是我们将在`app/entries/templates/entries`目录中显示文本，以指示用户他们正在编辑一个现有条目：

```py
{% extends "base.html" %}
{% from "macros/form_field.html" import form_field %}

{% block title %}Edit {{ entry.title }}{% endblock %}

{% block content_title %}Edit {{ entry.title }}{% endblock %}

{% block content %}
  <form action="{{ url_for('entries.edit', slug=entry.slug) }}" class="form form-horizontal" method="post">
    {% for field in form %}
      {{ form_field(field) }}
    {% endfor %}
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-default">Save</button>
        <a class="btn" href="{{ url_for('entries.detail', slug=entry.slug) }}">Cancel</a>
      </div>
    </div>
  </form>
{% endblock %}
```

为了结束这一部分，在条目详细页面上，让我们在侧边栏中添加一个链接，可以带我们到`Edit`页面。在`detail.html`的侧边栏中添加以下链接：

```py
<a href="{{ url_for('entries.edit', slug=entry.slug) }}">Edit</a>
```

## 删除条目

为了完成这一部分，我们将添加一个用于删除条目的视图。我们将设计这个视图，当用户去删除一个条目时，他们会被带到一个确认页面。只有通过提交确认表单（一个`POST`请求），他们才能真正删除条目。因为这个表单不需要任何字段，我们不需要一个特殊的 WTForms 类，可以直接使用 HTML 创建它。

在`create.html`和`edit.html`模板旁边创建一个名为`delete.html`的模板，并添加以下 HTML：

```py
{% extends "base.html" %}

{% block title %}{{ entry.title }}{% endblock %}

{% block content_title %}{{ entry.title }}{% endblock %}

{% block content %}
  <form action="{{ url_for('entries.delete', slug=entry.slug) }}" method="post">
    <fieldset>
      <legend>Delete this entry?</legend>
      <button class="btn btn-danger" type="submit">Delete</button>
      <a class="btn" href="{{ url_for('entries.detail', slug=entry.slug) }}">Cancel</a>
    </fieldset>
  </form>
{% endblock %}
```

现在我们需要定义`entries.delete`视图。与`edit`视图一样，删除条目的 URL 需要条目 slug 作为 URL 结构的一部分。因此，我们将使用`/entries/<slug>/delete/`。

当表单提交时，我们可以简单地从数据库中删除条目，但根据我的经验，我通常会后悔永久删除内容。我们不会真正从数据库中删除条目，而是给它一个`_DELETED`状态；我们将把它的状态改为`STATUS_DELETED`。然后我们将修改我们的视图，以便具有这种状态的条目永远不会出现在网站的任何部分。在所有方面，条目都消失了，但是，如果我们将来需要它，我们可以从数据库中检索它。在`edit`视图下面添加以下视图代码：

```py
@entries.route('/<slug>/delete/', methods=['GET', 'POST'])
def delete(slug):
    entry = Entry.query.filter(Entry.slug == slug).first_or_404()
    if request.method == 'POST':
        entry.status = Entry.STATUS_DELETED
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for('entries.index'))

    return render_template('entries/delete.html', entry=entry)
```

我们还需要在 model.py 中的 Entries 模型中添加 STATUS_DELETED：

```py
class Entry(db.Model):
    STATUS_PUBLIC = 0
    STATUS_DRAFT = 1
    STATUS_DELETED = 2
```

与编辑链接一样，花点时间在详细视图侧边栏中添加一个`delete`链接。

## 清理

让我们花点时间重构我们的蓝图。由于我们不想在网站上显示已删除的条目，我们需要确保通过状态筛选我们的条目。此外，看着`detail`、`edit`和`delete`视图，我看到了三个我们复制并粘贴查询条目的代码的实例。让我们也将其移动到一个辅助函数中。

首先，让我们更新`entry_list`辅助函数，以筛选出公共或草稿条目。

### 提示

在下一章中，我们将为网站添加登录功能。一旦我们有了这个功能，我们将添加逻辑，只向创建它们的用户显示草稿条目。

```py
def entry_list(template, query, **context):
    valid_statuses = (Entry.STATUS_PUBLIC, Entry.STATUS_DRAFT)
    query = query.filter(Entry.status.in_(valid_statuses))
    if request.args.get('q'):
        search = request.args['q']
        query = query.filter(
            (Entry.body.contains(search)) |
            (Entry.title.contains(search)))

    return object_list(template, query, **context)
```

现在我们可以确信，无论我们在哪里显示条目列表，都不会显示已删除的条目。

现在让我们添加一个新的辅助函数来通过其 slug 检索`Entry`。如果找不到条目，我们将返回 404。在`entry_list`下面添加以下代码：

```py
def get_entry_or_404(slug):
  valid_statuses = (Entry.STATUS_PUBLIC, Entry.STATUS_DRAFT) (Entry.query
          .filter(
              (Entry.slug == slug) &
              (Entry.status.in_(valid_statuses)))
          .first_or_404())
```

用`get_entry_or_404`替换`detail`、`edit`和`delete`视图中的`Entry.query.filter()`调用。以下是更新后的 detail 视图：

```py
@entries.route('/<slug>/')
def detail(slug):
    entry = get_entry_or_404(slug)
    return render_template('entries/detail.html', entry=entry)
```

# 使用闪存消息

当用户在网站上执行操作时，通常会在随后的页面加载时显示一次性消息，指示他们的操作已成功。这些称为闪存消息，Flask 带有一个辅助函数来显示它们。为了开始使用闪存消息，我们需要在`config`模块中添加一个秘钥。秘钥是必要的，因为闪存消息存储在会话中，而会话又存储为加密的 cookie。为了安全地加密这些数据，Flask 需要一个秘钥。

打开`config.py`并添加一个秘钥。可以是短语、随机字符，任何你喜欢的东西：

```py
class Configuration(object):
    APPLICATION_DIR = current_directory
    DEBUG = True
    SECRET_KEY = 'flask is fun!'  # Create a unique key for your app.
    SQLALCHEMY_DATABASE_URI = 'sqlite:///%s/blog.db' % APPLICATION_DIR
```

现在，无论我们的用户在哪个页面上执行操作，我们都希望向他们显示一个消息，指示他们的操作成功。 这意味着我们将在`create`，`edit`和`delete`视图中添加一个消息。 打开条目蓝图并将闪存函数添加到模块顶部的 flask 导入列表中：

```py
from flask import Blueprint, flash, redirect, render_template, request, url_for
```

然后，在每个适当的视图中，让我们调用`flash`并显示一个有用的消息。 在重定向之前应该发生调用：

```py
def create():
        ...
            db.session.commit()
            flash('Entry "%s" created successfully.' % entry.title, 'success')
            return redirect(url_for('entries.detail', slug=entry.slug))
        ...

def edit(slug):
        ...
        db.session.commit()
        flash('Entry "%s" has been saved.' % entry.title, 'success')
        return redirect(url_for('entries.detail', slug=entry.slug))
        ...

def delete(slug):
        ...
        db.session.commit()
        flash('Entry "%s" has been deleted.' % entry.title, 'success')
        return redirect(url_for('entries.index'))
        ...
```

## 在模板中显示闪存消息

因为我们并不总是知道在需要显示闪存消息时我们将在哪个页面上，所以将显示逻辑添加到基本模板是一种标准做法。 Flask 提供了一个 Jinja2 函数`get_flashed_messages`，它将返回一个待显示的消息列表。

打开`base.html`并添加以下代码。 我已经将我的代码放在`content_title`块和`content`块之间：

```py
<h1>{% block content_title %}{% endblock %}</h1>
{% for category, message in get_flashed_messages(with_categories=true) %}
 <div class="alert alert-dismissable alert-{{ category }}">
 <button type="button" class="close" data-dismiss="alert">&times;</button>
 {{ message }}
 </div>
{% endfor %}
{% block content %}{% endblock %}
```

让我们试试看！ 启动开发服务器并尝试添加一个新条目。 保存后，您应该被重定向到新条目，并看到一个有用的消息，如下面的屏幕截图所示：

![在模板中显示闪存消息](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_04_05.jpg)

# 保存和修改帖子上的标签

我们已经讨论了如何保存和修改条目上的标签。 管理标签的最常见方法之一是使用逗号分隔的文本输入，因此我们可以将标签列为*Python*，*Flask*，*Web-development*。 使用 WTForms 似乎非常简单，因为我们只需使用`StringField`。 然而，由于我们正在处理数据库关系，这意味着我们需要在`Tag`模型和逗号分隔的字符串之间进行一些处理。

虽然我们可以通过许多方式来实现这一点，但我们将实现一个自定义字段类`TagField`，它将封装在逗号分隔的标签名称和`Tag`模型实例之间进行转换的所有逻辑。

### 提示

另一个选项是在`Entry`模型上创建一个*property*。 属性看起来像一个普通的对象属性，但实际上是 getter 和（有时）setter 方法的组合。 由于 WTForms 可以自动处理我们的模型属性，这意味着，如果我们在 getter 和 setter 中实现我们的转换逻辑，WTForms 将正常工作。

让我们首先定义我们的标签字段类。 我们需要重写两个重要的方法：

+   `_value()`: 将`Tag`实例列表转换为逗号分隔的标签名称列表

+   `process_formdata(valuelist)`: 接受逗号分隔的标签列表并将其转换为`Tag`实例的列表

以下是`TagField`的实现。 请注意，我们在处理用户输入时要特别小心，以避免在`Tag`表中创建重复行。 我们还使用 Python 的`set()`数据类型来消除用户输入中可能的重复项。 将以下类添加到`forms.py`中的`EntryForm`上方：

```py
from models import Tag
class TagField(wtforms.StringField):
    def _value(self):
        if self.data:
            # Display tags as a comma-separated list.
            return ', '.join([tag.name for tag in self.data])
        return ''

    def get_tags_from_string(self, tag_string):
        raw_tags = tag_string.split(',')

        # Filter out any empty tag names.
        tag_names = [name.strip() for name in raw_tags if name.strip()]

        # Query the database and retrieve any tags we have already saved.
        existing_tags = Tag.query.filter(Tag.name.in_(tag_names))

        # Determine which tag names are new.
        new_names = set(tag_names) - set([tag.name for tag in existing_tags])

        # Create a list of unsaved Tag instances for the new tags.
        new_tags = [Tag(name=name) for name in new_names]

        # Return all the existing tags + all the new, unsaved tags.
        return list(existing_tags) + new_tags

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = self.get_tags_from_string(valuelist[0])
        else:
            self.data = []
```

现在，我们只需要将字段添加到`EntryForm`中。 在`status`字段下面添加以下字段。 请注意`description`关键字参数的使用：

```py
class EntryForm(wtforms.Form):
    ...
    tags = TagField(
        'Tags',
        description='Separate multiple tags with commas.')
```

为了显示这个有用的`description`文本，让我们对`form_field`宏进行快速修改：

```py
{% macro form_field(field) %}
  <div class="form-group{% if field.errors %} has-error has-feedback{% endif %}">
    {{ field.label(class='col-sm-3 control-label') }}
    <div class="col-sm-9">
      {{ field(class='form-control', **kwargs) }}
      {% if field.errors %}<span class="glyphicon glyphicon-warning-sign form-control-feedback"></span>{% endif %}
      {% if field.description %}<span class="help-block">{{ field.description|safe }}</span>{% endif %}
      {% for error in field.errors %}<span class="help-block">{{ error }}</span>{% endfor %}
    </div>
  </div>
{% endmacro %}
```

启动开发服务器，并尝试保存一些标签。 您的表单应该看起来像下面的屏幕截图：

![保存和修改帖子上的标签](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_04_06.jpg)

## 图像上传

我们将通过为网站添加一个图片上传功能来完成表单处理章节。 这个功能将是一个简单的视图，接受一个图像文件并将其存储在服务器上的上传目录中。 这将使我们能够轻松在博客条目中显示图像。

第一步是创建一个处理图像上传的表单。 除了`EntryForm`，让我们添加一个名为`ImageForm`的新表单。 这个表单将非常简单，包含一个文件输入。 我们将使用自定义验证器来确保上传的文件是有效的图像。 将以下代码添加到`forms.py`中：

```py
class ImageForm(wtforms.Form):
    file = wtforms.FileField('Image file')
```

在我们添加一个视图来保存表单之前，我们需要知道我们将在哪里保存文件。通常，应用程序的资源（如图像、JavaScript 和样式表）都是从一个名为`static`的单个目录中提供的。通常的做法是在 web 服务器中覆盖此目录的路径，以便它可以在不经过 Python 中介的情况下传输此文件，从而使访问速度更快。我们利用`static`目录来存储我们的图像上传。在博客项目的`app`目录中，让我们创建一个名为`static`的新目录和一个子目录`images`：

```py
(blog) $ cd ~/projects/blog/blog/app
(blog) $ mkdir -p static/images

```

现在让我们向配置文件中添加一个新值，这样我们就可以轻松地引用磁盘上图像的路径。这样可以简化我们的代码，以后如果我们选择更改此位置，也会更加方便。打开`config.py`并添加以下值：

```py
class Configuration(object):
    ...
    STATIC_DIR = os.path.join(APPLICATION_DIR, 'static')
    IMAGES_DIR = os.path.join(STATIC_DIR, 'images')
```

## 处理文件上传

我们现在准备创建一个用于处理图像上传的视图。逻辑将与我们的其他表单处理视图非常相似，唯一的区别是，在验证表单后，我们将把上传的文件保存到磁盘上。由于这些图像是用于我们博客条目的，我将视图添加到 entries blueprint 中，可在`/entries/image-upload/`访问。

我们需要导入我们的新表单以及其他辅助工具。打开`blueprint.py`并在模块顶部添加以下导入：

```py
import os

from flask import Blueprint, flash, redirect, render_template, request, url_for
from werkzeug import secure_filename

from app import app, db
from helpers import object_list
from models import Entry, Tag
from entries.forms import EntryForm, ImageForm

```

在视图列表的顶部，让我们添加新的`image-upload`视图。重要的是它出现在`detail`视图之前，否则 Flask 会错误地将`/image-upload/`视为博客条目的 slug。添加以下视图定义：

```py
@entries.route('/image-upload/', methods=['GET', 'POST'])
def image_upload():
    if request.method == 'POST':
        form = ImageForm(request.form)
        if form.validate():
            image_file = request.files['file']
            filename = os.path.join(app.config['IMAGES_DIR'],
                                    secure_filename(image_file.filename))
            image_file.save(filename)
            flash('Saved %s' % os.path.basename(filename), 'success')
            return redirect(url_for('entries.index'))
    else:
        form = ImageForm()

    return render_template('entries/image_upload.html', form=form)
```

这里的大部分代码可能看起来很熟悉，值得注意的例外是使用`request.files`和`secure_filename`。当文件上传时，Flask 会将其存储在`request.files`中，这是一个特殊的字典，以表单字段的名称为键。我们使用`secure_filename`进行一些路径连接，以防止恶意文件名，并生成到`static/images`目录的正确路径，然后将上传的文件保存到磁盘上。就是这么简单。

### 图片上传模板

让我们为我们的图片上传表单创建一个简单的模板。在 entries 模板目录中创建一个名为`image_upload.html`的文件，并添加以下代码：

```py
{% extends "base.html" %}
{% from "macros/form_field.html" import form_field %}

{% block title %}Upload an image{% endblock %}

{% block content_title %}Upload an image{% endblock %}

{% block content %}
  <form action="{{ url_for('entries.image_upload') }}" enctype="multipart/form-data" method="post">
    {% for field in form %}
      {{ form_field(field) }}
    {% endfor %}
    <div class="form-group">
      <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-default">Upload</button>
        <a class="btn" href="{{ url_for('entries.index') }}">Cancel</a>
      </div>
    </div>
  </form>
{% endblock %}
```

为了让 Flask 处理我们上传的文件，我们必须在定义`<form>`元素时指定`enctype="multipart/form-data"`。这是一个非常常见的错误，所以我会再次重复：每当您接受文件上传时，您的表单元素必须指定`enctype="multipart/form-data"`。

继续尝试图片上传。您应该在应用程序中的`static/images/directory`中看到您上传的文件。您还可以通过浏览器导航到`http://127.0.0.1:5000/static/images/the-file-name.jpg`来查看图像。

# 提供静态文件

Flask 将自动从我们的`/static/`目录中提供文件。当我们在第十章部署我们的网站时，*部署您的应用程序*，我们将使用**Nginx** web 服务器来提供静态资产，但是对于本地开发，Flask 使事情变得非常简单。

除了我们的图像上传，让我们还从`/static/`提供我们网站的 JavaScript 和样式表。下载 jQuery 和 Bootstrap，并将 JavaScript 文件（`jquery-<version>.min.js`和`boostrap.min.js`）放在`static/js`中。将压缩的 bootstrap CSS 文件（`bootstrap.min.css`）放在`static/css`中。Bootstrap 还带有一些用于图标的特殊字体。将 bootstrap 字体目录也复制到 static 目录中。现在，您的应用程序的 static 目录中应该有四个目录：`css`、`fonts`、`images`和`js`，每个目录中都包含相关文件：

```py
(blog) $ cd static/ && find . -type f
./fonts/glyphicons-halflings-regular.woff
./fonts/glyphicons-halflings-regular.ttf
./fonts/glyphicons-halflings-regular.eot
./fonts/glyphicons-halflings-regular.svg
./images/2012-07-17_16.18.18.jpg
./js/jquery-1.10.2.min.js
./js/bootstrap.min.js
./css/bootstrap.min.css

```

为了将我们的基本模板指向这些文件的本地版本，我们将使用`url_for`助手来生成正确的 URL。打开`base.html`，删除旧的样式表和 JavaScript 标签，并用本地版本替换它们：

```py
<head>
  <meta charset="utf-8">
  <title>{% block title %}{% endblock %} | My Blog</title>

  <link rel="stylesheet" href="{{="{{ url_for('static', filename='css/bootstrap.min.css') }}">
  <style type="text/css">
    body { padding-top: 60px; }
  </style>
  {% block extra_styles %}{% endblock %}

  <script src="img/jquery-1.10.2.min.js') }}"></script>
  <script src="img/bootstrap.min.js') }}"></script>
  {% block extra_scripts %}{% endblock %}
</head>
```

如果您愿意，可以在`static/css`目录中创建一个`site.css`文件，并将`<style>`标签替换为指向`site.css`的链接。

# 摘要

在本章中，我们添加了各种与网站交互的新方法。现在可以直接通过网站创建和修改内容。我们讨论了如何使用 WTForms 创建面向对象的表单，包括从视图处理和验证表单数据，以及将表单数据写入数据库。我们还创建了模板来显示表单和验证错误，并使用 Jinja2 宏来删除重复的代码，使代码更加模块化。然后，我们能够向用户显示单次使用的闪存消息，当他们执行操作时。最后，我们还解释了如何使用 WTForms 和 Flask 处理文件上传，并提供静态资产，如 JavaScript、样式表和图像上传。

在跳转到下一章之前，花一些时间尝试一下我们在网站中添加的新功能。以下是一些可以改进本章内容的方法：

+   在页眉中添加一个链接到图像上传表单。

+   在图像上传视图中，验证文件的扩展名是否是已识别的图像扩展名（.png、.jpg、.gif）。

+   添加一个只读的 StringField 来显示条目的 slug。

+   我们的标签索引视图将显示与零个条目关联的标签（如果我们添加了一个标签，然后从条目中删除它，这可能是这种情况）。改进查询，只列出具有一个或多个关联条目的标签。提示：`Tag.query.join(entry_tags).distinct()`。

+   在标签索引中显示与标签关联的条目数量。高级：在单个查询中完成。

+   高级：创建一个图像模型和用于创建、编辑和删除图像的视图。

在下一章中，我们将为我们的网站添加身份验证，以便只有受信任的用户才能创建和修改内容。我们将构建一个模型来代表博客作者，添加登录/注销表单，并防止未经身份验证的用户访问网站的某些区域。


# 第五章：用户身份验证

在本章中，我们将向我们的网站添加用户身份验证。能够区分一个用户和另一个用户使我们能够开发一整套新功能。例如，我们将看到如何限制对创建、编辑和删除视图的访问，防止匿名用户篡改网站内容。我们还可以向用户显示他们的草稿帖子，但对其他人隐藏。本章将涵盖向网站添加身份验证层的实际方面，并以讨论如何使用会话跟踪匿名用户结束。

在本章中，我们将：

+   创建一个数据库模型来表示用户

+   安装 Flask-Login 并将 LoginManager 助手添加到我们的站点

+   学习如何使用加密哈希函数安全存储和验证密码

+   构建用于登录和退出网站的表单和视图

+   查看如何在视图和模板中引用已登录用户

+   限制对已登录用户的视图访问

+   向 Entry 模型添加作者外键

+   使用 Flask 会话对象跟踪网站的任何访问者

# 创建用户模型

构建我们的身份验证系统的第一步将是创建一个表示单个用户帐户的数据库模型。我们将存储用户的登录凭据，以及一些额外的信息，如用户的显示名称和他们的帐户创建时间戳。我们的模型将具有以下字段：

+   `email`（唯一）：存储用户的电子邮件地址，并将其用于身份验证

+   `password_hash`: 不是将每个用户的密码作为明文串联起来，而是使用单向加密哈希函数对密码进行哈希处理

+   `name`: 用户的名称，这样我们就可以在他们的博客条目旁边显示它

+   `slug`: 用户名称的 URL 友好表示，也是唯一的

+   `active`: 布尔标志，指示此帐户是否处于活动状态。只有活动用户才能登录网站

+   `created_timestamp`: 用户帐户创建的时间

### 提示

如果您认为还有其他字段可能有用，请随意向此列表添加自己的内容。

现在我们有了字段列表，让我们创建`model`类。打开`models.py`，在`Tag`模型下面，添加以下代码：

```py
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(255))
    name = db.Column(db.String(64))
    slug = db.Column(db.String(64), unique=True)
    active = db.Column(db.Boolean, default=True)
    created_timestamp = db.Column(db.DateTime, default=datetime.datetime.now)

    def __init__(self, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)
        self.generate_slug()

    def generate_slug(self):
        if self.name:
            self.slug = slugify(self.name)
```

正如您在第二章中所记得的，*使用 SQLAlchemy 的关系数据库*，我们需要创建一个迁移，以便将这个表添加到我们的数据库中。从命令行，我们将使用`manage.py`助手来审查我们的模型并生成迁移脚本：

```py
(blog) $ python manage.py db migrate
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added table 'user'
 Generating /home/charles/projects/blog/app/migrations/versions/40ce2670e7e2_.py ... done

```

生成迁移后，我们现在可以运行`db upgrade`来进行模式更改：

```py
(blog) $ python manage.py db upgrade
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.migration] Running upgrade 2ceb72931f66 -> 40ce2670e7e2, empty message

```

现在我们有了用户，下一步将允许他们登录网站。

# 安装 Flask-Login

Flask-Login 是一个轻量级的扩展，用于处理用户登录和退出网站。根据项目的文档，Flask-Login 将执行以下操作：

+   登录和退出网站的用户

+   将视图限制为已登录用户

+   管理 cookie 和“记住我”功能

+   帮助保护用户会话 cookie 免受盗窃

另一方面，Flask-Login 不会做以下事情：

+   对用户帐户的存储做出任何决定

+   管理用户名、密码、OpenID 或任何其他形式的凭据

+   处理分层权限或任何超出已登录或已注销的内容

+   帐户注册、激活或密码提醒

从这些列表中得出的结论是，Flask-Login 最好被认为是一个会话管理器。它只是管理用户会话，并让我们知道哪个用户正在发出请求，以及该用户是否已登录。

让我们开始吧。使用`pip`安装 Flask-Login：

```py
(blog) $ pip install Flask-Login
Downloading/unpacking Flask-Login
...
Successfully installed Flask-Login
Cleaning up...

```

为了开始在我们的应用程序中使用这个扩展，我们将创建一个`LoginManager`类的实例，这是由 Flask-Login 提供的。除了创建`LoginManager`对象之外，我们还将添加一个信号处理程序，该处理程序将在每个请求之前运行。这个信号处理程序将检索当前登录的用户并将其存储在一个名为`g`的特殊对象上。在 Flask 中，`g`对象可以用来存储每个请求的任意值。

将以下代码添加到`app.py`。导入放在模块的顶部，其余部分放在末尾：

```py
from flask import Flask, g
from flask.ext.login import LoginManager, current_user

# Add to the end of the module.
login_manager = LoginManager(app)
login_manager.login_view = "login"

@app.before_request
def _before_request():
    g.user = current_user
```

现在我们已经创建了我们的`login_manager`并添加了一个信号处理程序来加载当前用户，我们需要告诉 Flask-Login 如何确定哪个用户已登录。Flask-Login 确定这一点的方式是将当前用户的 ID 存储在会话中。我们的用户加载器将接受存储在会话中的 ID 并从数据库返回一个`User`对象。

打开`models.py`并添加以下代码行：

```py
from app import login_manager

@login_manager.user_loader
def _user_loader(user_id):
    return User.query.get(int(user_id))
```

现在 Flask-Login 知道如何将用户 ID 转换为 User 对象，并且该用户将作为`g.user`对我们可用。

## 实现 Flask-Login 接口

为了让 Flask-Login 与我们的`User`模型一起工作，我们需要实现一些特殊方法，这些方法构成了 Flask-Login 接口。通过实现这些方法，Flask-Login 将能够接受一个`User`对象并确定他们是否可以登录网站。

打开`models.py`并向`User`类添加以下方法：

```py
class User(db.Model):
    # ... column definitions, etc ...

    # Flask-Login interface..
    def get_id(self):
        return unicode(self.id)

    def is_authenticated(self):
        return True

    def is_active(self):
        return self.active

    def is_anonymous(self):
        return False
```

第一个方法`get_id()`指示 Flask-Login 如何确定用户的 ID，然后将其存储在会话中。它是我们用户加载器函数的反向，它给我们一个 ID 并要求我们返回一个`User`对象。其余的方法告诉 Flask-Login，数据库中的`User`对象不是匿名的，并且只有在`active`属性设置为`True`时才允许登录。请记住，Flask-Login 对我们的`User`模型或数据库一无所知，因此我们必须非常明确地告诉它。

现在我们已经配置了 Flask-Login，让我们添加一些代码，以便我们可以创建一些用户。

# 创建用户对象

创建新用户就像创建条目或标签一样，只有一个例外：我们需要安全地对用户的密码进行哈希处理。您永远不应该以明文形式存储密码，并且由于黑客的技术日益复杂，最好使用强大的加密哈希函数。我们将使用**Flask-Bcrypt**扩展来对我们的密码进行哈希处理和检查，因此让我们使用`pip`安装这个扩展：

```py
(blog) $ pip install flask-bcrypt
...
Successfully installed Flask-Bcrypt
Cleaning up...

```

打开`app.py`并添加以下代码来注册扩展到我们的应用程序：

```py
from flask.ext.bcrypt import Bcrypt

bcrypt = Bcrypt(app)
```

现在让我们为`User`对象添加一些方法，以便创建和检查密码变得简单：

```py
from app import bcrypt

class User(db.Model):
    # ... column definitions, other methods ...

    @staticmethod
    def make_password(plaintext):
        return bcrypt.generate_password_hash(plaintext)

    def check_password(self, raw_password):
        return bcrypt.check_password_hash(self.password_hash, raw_password)

    @classmethod
    def create(cls, email, password, **kwargs):
        return User(
            email=email,
            password_hash=User.make_password(password),
            **kwargs)

    @staticmethod
    def authenticate(email, password):
        user = User.query.filter(User.email == email).first()
        if user and user.check_password(password):
            return user
        return False
```

`make_password`方法接受明文密码并返回哈希版本，而`check_password`方法接受明文密码并确定它是否与数据库中存储的哈希版本匹配。然而，我们不会直接使用这些方法。相反，我们将创建两个更高级的方法，`create`和`authenticate`。`create`方法将创建一个新用户，在保存之前自动对密码进行哈希处理，而`authenticate`方法将根据用户名和密码检索用户。

通过创建一个新用户来尝试这些方法。打开一个 shell，并使用以下代码作为示例，为自己创建一个用户：

```py
In [1]: from models import User, db

In [2]: user = User.create("charlie@gmail.com", password="secret",
name="Charlie")

In [3]: print user.password
$2a$12$q.rRa.6Y2IEF1omVIzkPieWfsNJzpWN6nNofBxuMQDKn.As/8dzoG

In [4]: db.session.add(user)

In [5]: db.session.commit()

In [6]:  User.authenticate("charlie@gmail.com", "secret")
Out[6]:  <User u"Charlie">

In [7]: User.authenticate("charlie@gmail.com", "incorrect")
Out[7]: False
```

现在我们有了一种安全地存储和验证用户凭据的方法，我们可以开始构建登录和注销视图了。

# 登录和注销视图

用户将使用他们的电子邮件和密码登录我们的博客网站；因此，在我们开始构建实际的登录视图之前，让我们从`LoginForm`开始。这个表单将接受`用户名`、`密码`，并且还会呈现一个复选框来指示网站是否应该`记住我`。在`app`目录中创建一个`forms.py`模块，并添加以下代码：

```py
import wtforms
from wtforms import validators
from models import User

class LoginForm(wtforms.Form):
    email = wtforms.StringField("Email",
        validators=[validators.DataRequired()])
    password = wtforms.PasswordField("Password",
        validators=[validators.DataRequired()])
    remember_me = wtforms.BooleanField("Remember me?",
        default=True)
```

### 提示

请注意，WTForms 还提供了一个电子邮件验证器。但是，正如该验证器的文档所告诉我们的那样，它非常原始，可能无法捕获所有边缘情况，因为完整的电子邮件验证实际上是非常困难的。

为了在正常的 WTForms 验证过程中验证用户的凭据，我们将重写表单的`validate()`方法。如果找不到电子邮件或密码不匹配，我们将在电子邮件字段下方显示错误。将以下方法添加到`LoginForm`类：

```py
def validate(self):
    if not super(LoginForm, self).validate():
        return False

    self.user = User.authenticate(self.email.data, self.password.data)
    if not self.user:
        self.email.errors.append("Invalid email or password.")
        return False

    return True
```

现在我们的表单已经准备好了，让我们创建登录视图。我们将实例化`LoginForm`并在`POST`时对其进行验证。此外，当用户成功验证时，我们将重定向他们到一个新页面。

当用户登录时，将其重定向回用户先前浏览的页面是一个很好的做法。为了实现这一点，我们将在查询字符串值`next`中存储用户先前所在页面的 URL。如果在该值中找到了 URL，我们可以将用户重定向到那里。如果未找到 URL，则用户将默认被重定向到主页。

在`app`目录中打开`views.py`并添加以下代码：

```py
from flask import flash, redirect, render_template, request, url_for
from flask.ext.login import login_user

from app import app
from app import login_manager
from forms import LoginForm

@app.route("/")
def homepage():
    return render_template("homepage.html")

@app.route("/login/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        form = LoginForm(request.form)
        if form.validate():
            login_user(form.user, remember=form.remember_me.data)
            flash("Successfully logged in as %s." % form.user.email, "success")
            return redirect(request.args.get("next") or url_for("homepage"))
    else:
        form = LoginForm()
    return render_template("login.html", form=form)
```

魔法发生在我们成功验证表单（因此验证了用户身份）后的`POST`上。我们调用`login_user`，这是 Flask-Login 提供的一个辅助函数，用于设置正确的会话值。然后我们设置一个闪存消息并将用户送上路。

## 登录模板

`login.html`模板很简单，除了一个技巧，一个例外。在表单的 action 属性中，我们指定了`url_for('login')`，但我们还传递了一个额外的值`next`。这允许我们在用户登录时保留所需的下一个 URL。将以下代码添加到`templates/login.html`：

```py
{% extends "base.html" %}
{% from "macros/form_field.html" import form_field %}
{% block title %}Log in{% endblock %}
{% block content_title %}Log in{% endblock %}
{% block content %}
<form action="{{ url_for('login', next=request.args.get('next','')) }}" class="form form-horizontal" method="post">
{{ form_field(form.email) }}
{{ form_field(form.password) }}
<div class="form-group">
    <div class="col-sm-offset-3 col-sm-9">
        <div class="checkbox">
            <label>{{ form.remember_me() }} Remember me</label>
        </div>
    </div>
</div>
<div class="form-group">
    <div class="col-sm-offset-3 col-sm-9">
        <button type="submit" class="btn btn-default">Log in</button>
        <a class="btn" href="{{ url_for('homepage') }}">Cancel</a>
    </div>
</div>
</form>
{% endblock %}
```

当您访问登录页面时，您的表单将如下截图所示：

![登录模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_05_01.jpg)

## 注销

最后让我们添加一个视图，用于将用户从网站中注销。有趣的是，此视图不需要模板，因为用户将简单地通过视图，在其会话注销后被重定向。将以下`import`语句和注销视图代码添加到`views.py`：

```py
# Modify the import at the top of the module.
from flask.ext.login import login_user, logout_user  # Add logout_user

@app.route("/logout/")
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(request.args.get('next') or url_for('homepage'))
```

再次说明，我们接受`next` URL 作为查询字符串的一部分，默认为主页，如果未指定 URL。

# 访问当前用户

让我们在导航栏中创建登录和注销视图的链接。为此，我们需要检查当前用户是否已经通过身份验证。如果是，我们将显示一个指向注销视图的链接；否则，我们将显示一个登录链接。

正如您可能还记得本章早些时候所说的，我们添加了一个信号处理程序，将当前用户存储为 Flask `g`对象的属性。我们可以在模板中访问这个对象，所以我们只需要在模板中检查`g.user`是否已经通过身份验证。

打开`base.html`并对导航栏进行以下添加：

```py
<ul class="nav navbar-nav">
    <li><a href="{{ url_for('homepage') }}">Home</a></li>
    <li><a href="{{ url_for('entries.index') }}">Blog</a></li>
    {% if g.user.is_authenticated %}
    <li><a href="{{ url_for('logout', next=request.path) }}">Log
out</a></li>
    {% else %}
    <li><a href="{{ url_for('login', next=request.path) }}">Log
in</a></li>
    {% endif %}
  {% block extra_nav %}{% endblock %}
</ul>
```

注意我们如何调用`is_authenticated()`方法，这是我们在`User`模型上实现的。Flask-Login 为我们提供了一个特殊的`AnonymousUserMixin`，如果当前没有用户登录，将使用它。

还要注意的是，除了视图名称，我们还指定了`next=request.path`。这与我们的登录和注销视图配合使用，以便在单击登录或注销后将用户重定向到其当前页面。

# 限制对视图的访问

目前，我们所有的博客视图都是不受保护的，任何人都可以访问它们。为了防止恶意用户破坏我们的条目，让我们为实际修改数据的视图添加一些保护。Flask-Login 提供了一个特殊的装饰器`login_required`，我们将使用它来保护应该需要经过身份验证的视图。

让我们浏览条目蓝图并保护所有修改数据的视图。首先在`blueprint.py`模块的顶部添加以下导入：

```py
from flask.ext.login import login_required
```

`login_required`是一个装饰器，就像`app.route`一样，所以我们只需包装我们希望保护的视图。例如，这是如何保护`image_upload`视图的方法：

```py
@entries.route('/image-upload/', methods=['GET', 'POST'])
@login_required
def image_upload():
    ...
```

浏览模块，并在以下视图中添加`login_required`装饰器，注意要在路由装饰器下面添加：

+   `image_upload`

+   `create`

+   `edit`

+   `删除`

当匿名用户尝试访问这些视图时，他们将被重定向到`login`视图。作为额外的奖励，Flask-Login 将在重定向到`login`视图时自动处理指定下一个参数，因此用户将返回到他们试图访问的页面。

## 存储条目的作者

正如您可能还记得我们在第一章中创建的规范，*创建您的第一个 Flask 应用程序*，我们的博客网站将支持多个作者。当创建条目时，我们将把当前用户存储在条目的作者列中。为了存储编写给定`Entry`的`User`，我们将在用户和条目之间创建一个*一对多*的关系，以便一个用户可以有多个条目：

![存储条目的作者](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_05_02.jpg)

为了创建*一对多*的关系，我们将在`Entry`模型中添加一个指向`User`表中用户的列。这个列将被命名为`author_id`，因为它引用了一个`User`，我们将把它设为外键。打开`models.py`并对`Entry`模型进行以下修改：

```py
class Entry(db.Model):
    modified_timestamp = ...
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    tags = ...
```

由于我们添加了一个新的列，我们需要再次创建一个迁移。从命令行运行`db migrate`和`db upgrade`：

```py
(blog) $ python manage.py db migrate
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added column 'entry.author_id'
 Generating /home/charles/projects/blog/app/migrations/versions/33011181124e_.py ... done

(blog) $ python manage.py db upgrade
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.migration] Running upgrade 40ce2670e7e2 -> 33011181124e, empty message

```

就像我们对标签所做的那样，最后一步将是在用户模型上创建一个反向引用，这将允许我们访问特定用户关联的`Entry`行。因为用户可能有很多条目，我们希望对其执行额外的过滤操作，我们将把反向引用暴露为一个查询，就像我们为标签条目所做的那样。

在`User`类中，在`created_timestamp`列下面添加以下代码行：

```py
entries = db.relationship('Entry', backref='author', lazy='dynamic')
```

现在我们有能力将`User`作为博客条目的作者存储起来，下一步将是在创建条目时填充这个列。

### 注意

如果数据库中有任何博客条目，我们还需要确保它们被分配给一个作者。从交互式 shell 中，让我们手动更新所有现有条目上的作者字段：

```py
In [8]: Entry.query.update({"author_id": user.id})
Out[8]: 6
```

这个查询将返回更新的行数，在这种情况下是数据库中的条目数。要保存这些更改，再次调用`commit()`：

```py
In [9]: db.session.commit()
```

## 设置博客条目的作者

现在我们有一个适合存储`Entry`作者的列，并且能够访问当前登录的用户，我们可以通过在创建条目时设置条目的作者来利用这些信息。在每个请求之前，我们的信号处理程序将把当前用户添加到 Flask `g`对象上，由于`create`视图受`login_required`装饰器保护，我们知道`g.user`将是来自数据库的`User`。

因为我们正在使用`g 对象`来访问用户，所以我们需要导入它，所以在条目蓝图的顶部添加以下导入语句：

```py
from flask import g
```

在条目蓝图中，我们现在需要修改`Entry`对象的实例化，手动设置作者属性。对`create`视图进行以下更改：

```py
if form.validate():
 entry = form.save_entry(Entry(author=g.user))
    db.session.add(entry)
```

当您要创建一个条目时，您现在将被保存在数据库中作为该条目的作者。试一试吧。

## 保护编辑和删除视图

如果多个用户能够登录到我们的网站，没有什么可以阻止恶意用户编辑甚至删除另一个用户的条目。这些视图受`login_required`装饰器保护，但我们需要添加一些额外的代码来确保只有作者可以编辑或删除他们自己的条目。

为了清晰地实现此保护，我们将再次重构条目蓝图中的辅助函数。对条目蓝图进行以下修改：

```py
def get_entry_or_404(slug, author=None):
    query = Entry.query.filter(Entry.slug == slug)
    if author:
        query = query.filter(Entry.author == author)
    else:
        query = filter_status_by_user(query)
    return query.first_or_404()
```

我们引入了一个新的辅助函数`filter_status_by_user`。此函数将确保匿名用户无法看到草稿条目。在`get_entry_or_404`下方的条目蓝图中添加以下函数：

```py
def filter_status_by_user(query):
    if not g.user.is_authenticated:
        return query.filter(Entry.status == Entry.STATUS_PUBLIC)
    else:
        return query.filter(
            Entry.status.in_((Entry.STATUS_PUBLIC,
Entry.STATUS_DRAFT)))
```

为了限制对`edit`和`delete`视图的访问，我们现在只需要将当前用户作为作者参数传递。对编辑和删除视图进行以下修改：

```py
entry = get_entry_or_404(slug, author=None)
```

如果您尝试访问您未创建的条目的`edit`或`delete`视图，您将收到`404`响应。

最后，让我们修改条目详细模板，以便除了条目的作者之外，所有用户都无法看到*编辑*和*删除*链接。在您的`entries`应用程序中编辑模板`entries/detail.html`，您的代码可能如下所示：

```py
{% if g.user == entry.author %}
  <li><h4>Actions</h4></li>
  <li><a href="{{ url_for('entries.edit', slug=entry.slug)
}}">Edit</a></li>
<li><a href="{{ url_for('entries.delete', slug=entry.slug)
}}">Delete</a></li>
{% endif %}
```

## 显示用户的草稿

我们的条目列表仍然存在一个小问题：草稿条目显示在普通条目旁边。我们不希望向任何人显示未完成的条目，但同时对于用户来说，看到自己的草稿将是有帮助的。因此，我们将修改条目列表和详细信息，只向条目的作者显示公共条目。

我们将再次修改条目蓝图中的辅助函数。我们将首先修改`filter_status_by_user`函数，以允许已登录用户查看自己的草稿（但不是其他人的）：

```py
def filter_status_by_user(query):
    if not g.user.is_authenticated:
        query = query.filter(Entry.status == Entry.STATUS_PUBLIC)
    else:
        # Allow user to view their own drafts.
 query = query.filter(
 (Entry.status == Entry.STATUS_PUBLIC) |
 ((Entry.author == g.user) &
 (Entry.status != Entry.STATUS_DELETED)))
 return query

```

新的查询可以解析为：“给我所有公共条目，或者我是作者的未删除条目。”

由于`get_entry_or_404`已经使用了`filter_status_by_user`辅助函数，因此`detail`、`edit`和`delete`视图已经准备就绪。我们只需要处理使用`entry_list`辅助函数的各种列表视图。让我们更新`entry_list`辅助函数以使用新的`filter_status_by_user`辅助函数：

```py
    query = filter_status_by_user(query)

    valid_statuses = (Entry.STATUS_PUBLIC, Entry.STATUS_DRAFT)
    query = query.filter(Entry.status.in_(valid_statuses))
    if request.args.get("q"):
        search = request.args["q"]
        query = query.filter(
            (Entry.body.contains(search)) |
            (Entry.title.contains(search)))
    return object_list(template, query, **context)
```

就是这样！我希望这展示了一些辅助函数在正确的位置上是如何真正简化开发者生活的。在继续进行最后一节之前，我建议创建一个或两个用户，并尝试新功能。

如果您计划在您的博客上支持多个作者，您还可以添加一个作者索引页面（类似于标签索引），以及列出与特定作者相关联的条目的作者详细页面（`user.entries`）。

# 会话

当您通过本章工作时，您可能会想知道 Flask-Login（以及 Flask）是如何能够在请求之间确定哪个用户已登录的。Flask-Login 通过将用户的 ID 存储在称为会话的特殊对象中来实现这一点。会话利用 cookie 来安全地存储信息。当用户向您的 Flask 应用程序发出请求时，他们的 cookie 将随请求一起发送，Flask 能够检查 cookie 数据并将其加载到会话对象中。同样，您的视图可以添加或修改存储在会话中的信息，从而在此过程中更新用户的 cookie。

Flask 会话对象的美妙之处在于它可以用于站点的任何访问者，无论他们是否已登录。会话可以像普通的 Python 字典一样处理。以下代码显示了您如何使用会话跟踪用户访问的最后一个页面：

```py
from flask import request, session

@app.before_request
def _last_page_visited():
    if "current_page" in session:
        session["last_page"] = session["current_page"]
    session["current_page"] = request.path
```

默认情况下，Flask 会话只持续到浏览器关闭。如果您希望会话持久存在，即使在重新启动之间也是如此，只需设置`session.permanent = True`。

### 提示

与`g`对象一样，`session`对象可以直接从模板中访问。

作为练习，尝试为您的网站实现一个简单的主题选择器。创建一个视图，允许用户选择颜色主题，并将其存储在会话中。然后，在模板中，根据用户选择的主题应用额外的 CSS 规则。

# 总结

在本章中，我们为博客应用程序添加了用户身份验证。我们创建了一个`User`模型，安全地将用户的登录凭据存储在数据库中，然后构建了用于登录和退出站点的视图。我们添加了一个信号处理程序，在每个请求之前运行并检索当前用户，然后学习如何在视图和模板中使用这些信息。在本章的后半部分，我们将`User`模型与 Entry 模型集成，从而在过程中使我们的博客更加安全。本章以对 Flask 会话的简要讨论结束。

在下一章中，我们将构建一个管理仪表板，允许超级用户执行诸如创建新用户和修改站点内容等操作。我们还将收集和显示各种站点指标，如页面浏览量，以帮助可视化哪些内容驱动了最多的流量。


# 第六章：构建管理仪表板

在本章中，我们将为我们的网站构建一个管理仪表板。我们的管理仪表板将使特定的、选择的用户能够管理整个网站上的所有内容。实质上，管理站点将是数据库的图形前端，支持在应用程序表中创建、编辑和删除行的操作。优秀的 Flask-Admin 扩展几乎提供了所有这些功能，但我们将超越默认值，扩展和定制管理页面。

在本章中，我们将：

+   安装 Flask-Admin 并将其添加到我们的网站

+   添加用于处理`Entry`、`Tag`和`User`模型的视图

+   添加管理网站静态资产的视图

+   将管理与 Flask-Login 框架集成

+   创建一个列来标识用户是否为管理员

+   为管理仪表板创建一个自定义索引页面

# 安装 Flask-Admin

Flask-Admin 为 Flask 应用程序提供了一个现成的管理界面。Flask-Admin 还与 SQLAlchemy 很好地集成，以提供用于管理应用程序模型的视图。

下面的图像是对本章结束时**Entry**管理员将会是什么样子的一个 sneak preview：

![安装 Flask-Admin](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_01.jpg)

虽然这种功能需要相对较少的代码，但我们仍然有很多内容要涵盖，所以让我们开始吧。首先使用`pip`将`Flask-Admin`安装到`virtualenv`中。在撰写本文时，Flask-Admin 的当前版本是 1.0.7。

```py
(blog) $ pip install Flask-Admin
Downloading/unpacking Flask-Admin
...
Successfully installed Flask-Admin
Cleaning up...

```

如果您希望测试它是否安装正确，可以输入以下代码：

```py
(blog) $ python manage.py shell
In [1]: from flask.ext import admin
In [2]: print admin.__version__
1.0.7

```

## 将 Flask-Admin 添加到我们的应用程序

与我们应用程序中的其他扩展不同，我们将在其自己的模块中设置管理扩展。我们将编写几个特定于管理的类，因此将它们放在自己的模块中是有意义的。在`app`目录中创建一个名为`admin.py`的新模块，并添加以下代码：

```py
from flask.ext.admin import Admin
from app import app

admin = Admin(app, 'Blog Admin')
```

因为我们的`admin`模块依赖于`app`模块，为了避免循环导入，我们需要确保在`app`之后加载`admin`。打开`main.py`模块并添加以下内容：

```py
from flask import request, session

from app import app, db
import admin  # This line is new, placed after the app import.
import models
import views
```

现在，您应该能够启动开发服务器并导航到`/admin/`以查看一个简单的管理员仪表板-默认的仪表板，如下图所示：

![将 Flask-Admin 添加到我们的应用程序](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_02.jpg)

随着您在本章中的进展，我们将把这个无聊和普通的管理界面变成一个丰富而强大的仪表板，用于管理您的博客。

# 通过管理公开模型

Flask-Admin 带有一个`contrib`包，其中包含专门设计用于与 SQLAlchemy 模型一起工作的特殊视图类。这些类提供开箱即用的创建、读取、更新和删除功能。

打开`admin.py`并更新以下代码：

```py
from flask.ext.admin import Admin
from flask.ext.admin.contrib.sqla import ModelView

from app import app, db
from models import Entry, Tag, User

admin = Admin(app, 'Blog Admin')
admin.add_view(ModelView(Entry, db.session))
admin.add_view(ModelView(Tag, db.session))
admin.add_view(ModelView(User, db.session))
```

请注意我们如何调用`admin.add_view()`并传递`ModelView`类的实例，以及`db`会话，以便它可以访问数据库。Flask-Admin 通过提供一个中央端点来工作，我们开发人员可以向其中添加我们自己的视图。

启动开发服务器并尝试再次打开您的管理站点。它应该看起来像下面的截图：

![通过管理公开模型](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_03.jpg)

尝试通过在导航栏中选择其链接来点击我们模型的视图之一。点击**Entry**链接以干净的表格格式显示数据库中的所有条目。甚至有链接可以创建、编辑或删除条目，如下一个截图所示：

![通过管理公开模型](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_04.jpg)

Flask-Admin 提供的默认值很好，但是如果您开始探索界面，您会开始注意到一些微妙的东西可以改进或清理。例如，可能不需要将 Entry 的正文文本包括在列中。同样，**状态**列显示状态为整数，但我们更希望看到与该整数相关联的名称。我们还可以单击每个`Entry`行中的*铅笔*图标。这将带您到默认的编辑表单视图，您可以使用它来修改该条目。

所有看起来都像下面的截图：

![通过管理员公开模型](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_05.jpg)

如前面的截图所示，Flask-Admin 在处理我们的外键到键和多对多字段（作者和标签）方面做得非常出色。它还相当不错地选择了要为给定字段使用哪个 HTML 小部件，如下所示：

+   标签可以使用漂亮的多选小部件添加和删除

+   作者可以使用下拉菜单选择

+   条目正文方便地显示为文本区域

不幸的是，这个表单存在一些明显的问题，如下所示：

+   字段的排序似乎是任意的。

+   **Slug**字段显示为可编辑文本输入，因为这是由数据库模型管理的。相反，此字段应该从 Entry 的标题自动生成。

+   **状态**字段是一个自由格式的文本输入字段，但应该是一个下拉菜单，其中包含人类可读的状态标签，而不是数字。

+   **创建时间戳**和**修改时间戳**字段看起来是可编辑的，但应该自动生成。

在接下来的部分中，我们将看到如何自定义`Admin`类和`ModelView`类，以便管理员真正为我们的应用程序工作。

## 自定义列表视图

让我们暂时把表单放在一边，专注于清理列表。为此，我们将创建一个 Flask-Admin 的子类`ModelView`。`ModelView`类提供了许多扩展点和属性，用于控制列表显示的外观和感觉。

我们将首先通过手动指定我们希望显示的属性来清理列表列。此外，由于我们将在单独的列中显示作者，我们将要求 Flask-Admin 从数据库中高效地获取它。打开`admin.py`并更新以下代码：

```py
from flask.ext.admin import Admin
from flask.ext.admin.contrib.sqla import ModelView

from app import app, db
from models import Entry, Tag, User

class EntryModelView(ModelView):
    column_list = [
        'title', 'status', 'author', 'tease', 'tag_list', 'created_timestamp',
    ]
    column_select_related_list = ['author']  # Efficiently SELECT the author.

admin = Admin(app, 'Blog Admin')
admin.add_view(EntryModelView(Entry, db.session))
admin.add_view(ModelView(Tag, db.session))
admin.add_view(ModelView(User, db.session))
```

您可能会注意到`tease`和`tag_list`实际上不是我们`Entry`模型中的列名。Flask-Admin 允许您使用任何属性作为列值。我们还指定要用于创建对其他模型的引用的列。打开`models.py`模块，并向`Entry`模型添加以下属性：

```py
@property
def tag_list(self):
    return ', '.join(tag.name for tag in self.tags)

@property
def tease(self):
    return self.body[:100]
```

现在，当您访问**Entry**管理员时，您应该看到一个干净、可读的表格，如下图所示：

![自定义列表视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_06.jpg)

让我们也修复**状态**列的显示。这些数字很难记住 - 最好显示人类可读的值。Flask-Admin 带有*枚举*字段（如**状态**）的辅助程序。我们只需要提供要显示值的状态值的映射，Flask-Admin 就会完成剩下的工作。在`EntryModelView`中进行以下添加：

```py
class EntryModelView(ModelView):
    _status_choices = [(choice, label) for choice, label in [
 (Entry.STATUS_PUBLIC, 'Public'),
 (Entry.STATUS_DRAFT, 'Draft'),
 (Entry.STATUS_DELETED, 'Deleted'),
 ]]

 column_choices = {
 'status': _status_choices,
 }
    column_list = [
        'title', 'status', 'author', 'tease', 'tag_list', 'created_timestamp',
    ]
    column_select_related_list = ['author']
```

我们的`Entry`列表视图看起来好多了。现在让我们对`User`列表视图进行一些改进。同样，我们将对`ModelView`进行子类化，并指定要覆盖的属性。在`admin.py`中在`EntryModelView`下面添加以下类：

```py
class UserModelView(ModelView):
    column_list = ['email', 'name', 'active', 'created_timestamp']

# Be sure to use the UserModelView class when registering the User:
admin.add_view(UserModelView(User, db.session))
```

以下截图显示了我们对`User`列表视图的更改：

![自定义列表视图](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_07.jpg)

## 向列表视图添加搜索和过滤

除了显示我们的模型实例列表外，Flask-Admin 还具有强大的搜索和过滤功能。假设我们有大量条目，并且想要找到包含特定关键字（如 Python）的条目。如果我们能够在列表视图中输入我们的搜索，并且 Flask-Admin 只列出标题或正文中包含单词'Python'的条目，那将是有益的。

正如您所期望的那样，这是非常容易实现的。打开`admin.py`并添加以下行：

```py
class EntryModelView(ModelView):
    _status_choices = [(choice, label) for choice, label in [
        (Entry.STATUS_PUBLIC, 'Public'),
        (Entry.STATUS_DRAFT, 'Draft'),
        (Entry.STATUS_DELETED, 'Deleted'),
    ]]

    column_choices = {
        'status': _status_choices,
    }
    column_list = [
        'title', 'status', 'author', 'tease', 'tag_list', 'created_timestamp',
    ]
    column_searchable_list = ['title', 'body']
    column_select_related_list = ['author']
```

当您重新加载`Entry`列表视图时，您将看到一个新的文本框，允许您搜索`title`和`body`字段，如下面的屏幕截图所示：

![向列表视图添加搜索和过滤](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_08.jpg)

尽管全文搜索可能非常有用，但对于**状态**或**创建时间戳**等非文本字段，拥有更强大的过滤能力会更好。再次，Flask-Admin 提供了易于使用、易于配置的过滤选项，来拯救我们。

让我们通过向`Entry`列表添加几个过滤器来看看过滤器是如何工作的。我们将再次修改`EntryModelView`如下：

```py
class EntryModelView(ModelView):
    _status_choices = [(choice, label) for choice, label in [
        (Entry.STATUS_PUBLIC, 'Public'),
        (Entry.STATUS_DRAFT, 'Draft'),
        (Entry.STATUS_DELETED, 'Deleted'),
    ]]

    column_choices = {
        'status': _status_choices,
    }
    column_filters = [
 'status', User.name, User.email, 'created_timestamp'
 ]
    column_list = [
        'title', 'status', 'author', 'tease', 'tag_list', 'created_timestamp',
    ]
    column_searchable_list = ['title', 'body']
    column_select_related_list = ['author']
```

`column_filters`属性包含`Entry`模型上的列名称，以及来自`User`的*相关*模型的字段：

```py
column_filters = [
    'status', User.name, User.email, 'created_timestamp'
]
```

当您访问`Entry`列表视图时，您现在将看到一个名为**添加过滤器**的新下拉菜单。尝试各种数据类型。请注意，当您尝试在**状态**列上进行过滤时，Flask-Admin 会自动使用`Public`、`Draft`和`Deleted`标签。还要注意，当您在**创建时间戳**上进行过滤时，Flask-Admin 会呈现一个漂亮的日期/时间选择器小部件。在下面的屏幕截图中，我设置了各种过滤器：

![向列表视图添加搜索和过滤](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_09.jpg)

此时，`Entry`列表视图非常实用。作为练习，为`User` `ModelView`设置`column_filters`和`column_searchable_list`属性。

## 自定义管理模型表单

我们将通过展示如何自定义表单类来结束模型视图的讨论。您会记得，默认表单由 Flask-Admin 提供的有一些限制。在本节中，我们将展示如何自定义用于创建和编辑模型实例的表单字段的显示。

我们的目标是删除多余的字段，并为**状态**字段使用更合适的小部件，实现以下屏幕截图中所示的效果：

![自定义管理模型表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_10.jpg)

为了实现这一点，我们首先手动指定我们希望在表单上显示的字段列表。这是通过在`EntryModelView 类`上指定`form_columns`属性来完成的：

```py
class EntryModelView(ModelView):
    ...
    form_columns = ['title', 'body', 'status', 'author', 'tags']
```

此外，我们希望`status`字段成为一个下拉小部件，使用各种状态的可读标签。由于我们已经定义了状态选择，我们将指示 Flask-Admin 使用 WTForms `SelectField`覆盖`status`字段，并传入有效选择的列表：

```py
from wtforms.fields import SelectField  # At top of module.

class EntryModelView(ModelView):
    ...
    form_args = {
        'status': {'choices': _status_choices, 'coerce': int},
    }
    form_columns = ['title', 'body', 'status', 'author', 'tags']
    form_overrides = {'status': SelectField}
```

默认情况下，用户字段将显示为一个带有简单类型的下拉菜单。不过，想象一下，如果此列表包含数千个用户！这将导致一个非常大的查询和一个慢的渲染时间，因为需要创建所有的`<option>`元素。

当包含外键的表单呈现到非常大的表时，Flask-Admin 允许我们使用 Ajax 来获取所需的行。将以下属性添加到`EntryModelView`，现在您的用户将通过 Ajax 高效加载：

```py
form_ajax_refs = {
    'author': {
        'fields': (User.name, User.email),
    },
}
```

这个指令告诉 Flask-Admin，当我们查找**作者**时，它应该允许我们在作者的姓名或电子邮件上进行搜索。以下屏幕截图显示了它的外观：

![自定义管理模型表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_11.jpg)

我们现在有一个非常漂亮的`Entry`表单。

## 增强用户表单

因为密码在数据库中以哈希形式存储，直接显示或编辑它们的价值很小。然而，在`User`表单上，我们将使输入新密码来替换旧密码成为可能。就像我们在`Entry`表单上对`status`字段所做的那样，我们将指定一个表单字段覆盖。然后，在模型更改处理程序中，我们将在保存时更新用户的密码。

对`UserModelView`模块进行以下添加：

```py
from wtforms.fields import PasswordField  # At top of module.

class UserModelView(ModelView):
    column_filters = ('email', 'name', 'active')
    column_list = ['email', 'name', 'active', 'created_timestamp']
    column_searchable_list = ['email', 'name']

    form_columns = ['email', 'password', 'name', 'active']
    form_extra_fields = {
 'password': PasswordField('New password'),
 }

    def on_model_change(self, form, model, is_created):
 if form.password.data:
 model.password_hash = User.make_password(form.password.data)
 return super(UserModelView, self).on_model_change(
 form, model, is_created)

```

以下截图显示了新的`User`表单的样子。如果您希望更改用户的密码，只需在**新密码**字段中输入新密码即可。

![增强用户表单](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_12.jpg)

## 生成 slug

仍然有一个方面需要解决。当创建新的`Entry`、`User`或`Tag`对象时，Flask-Admin 将无法正确生成它们的`slug`。这是由于 Flask-Admin 在保存时实例化新模型实例的方式。为了解决这个问题，我们将创建一些`ModelView`的子类，以确保为`Entry`、`User`和`Tag`对象正确生成`slug`。

打开`admin.py`文件，并在模块顶部添加以下类：

```py
class BaseModelView(ModelView):
    pass

class SlugModelView(BaseModelView):
    def on_model_change(self, form, model, is_created):
        model.generate_slug()
        return super(SlugModelView, self).on_model_change(
            form, model, is_created)
```

这些更改指示 Flask-Admin，每当模型更改时，应重新生成 slug。

为了开始使用这个功能，更新`EntryModelView`和`UserModelView`模块以扩展`SlugModelView`类。对于`Tag`模型，直接使用`SlugModelView`类进行注册即可。

总结一下，您的代码应该如下所示：

```py
from flask.ext.admin import Admin
from flask.ext.admin.contrib.sqla import ModelView
from wtforms.fields import SelectField

from app import app, db
from models import Entry, Tag, User, entry_tags

class BaseModelView(ModelView):
    pass

class SlugModelView(BaseModelView):
    def on_model_change(self, form, model, is_created):
        model.generate_slug()
        return super(SlugModelView, self).on_model_change(
            form, model, is_created)

class EntryModelView(SlugModelView):
    _status_choices = [(choice, label) for choice, label in [
        (Entry.STATUS_PUBLIC, 'Public'),
        (Entry.STATUS_DRAFT, 'Draft'),
        (Entry.STATUS_DELETED, 'Deleted'),
    ]]

    column_choices = {
        'status': _status_choices,
    }
    column_filters = ['status', User.name, User.email, 'created_timestamp']
    column_list = [
        'title', 'status', 'author', 'tease', 'tag_list', 'created_timestamp',
    ]
    column_searchable_list = ['title', 'body']
    column_select_related_list = ['author']

    form_ajax_refs = {
        'author': {
            'fields': (User.name, User.email),
        },
    }
    form_args = {
        'status': {'choices': _status_choices, 'coerce': int},
    }
    form_columns = ['title', 'body', 'status', 'author', 'tags']
    form_overrides = {'status': SelectField}

class UserModelView(SlugModelView):
    column_filters = ('email', 'name', 'active')
    column_list = ['email', 'name', 'active', 'created_timestamp']
    column_searchable_list = ['email', 'name']

    form_columns = ['email', 'password', 'name', 'active']
    form_extra_fields = {
        'password': PasswordField('New password'),
    }

    def on_model_change(self, form, model, is_created):
        if form.password.data:
            model.password_hash = User.make_password(form.password.data)
        return super(UserModelView, self).on_model_change(
            form, model, is_created)

admin = Admin(app, 'Blog Admin')
admin.add_view(EntryModelView(Entry, db.session))
admin.add_view(SlugModelView(Tag, db.session))
admin.add_view(UserModelView(User, db.session))
```

这些更改确保正确生成 slug，无论是保存现有对象还是创建新对象。

# 通过管理员管理静态资产

Flask-Admin 提供了一个方便的界面，用于管理静态资产（或磁盘上的其他文件），作为管理员仪表板的扩展。让我们向我们的网站添加一个`FileAdmin`，它将允许我们上传或修改应用程序的`static`目录中的文件。

打开`admin.py`文件，并在文件顶部导入以下模块：

```py
from flask.ext.admin.contrib.fileadmin import FileAdmin
```

然后，在各种`ModelView`实现下，添加以下突出显示的代码行：

```py
class BlogFileAdmin(FileAdmin):
 pass

admin = Admin(app, 'Blog Admin')
admin.add_view(EntryModelView(Entry, db.session))
admin.add_view(SlugModelView(Tag, db.session))
admin.add_view(UserModelView(User, db.session))
admin.add_view(
 BlogFileAdmin(app.config['STATIC_DIR'], '/static/', name='Static Files'))

```

在浏览器中打开管理员，您应该会看到一个名为**静态文件**的新选项卡。单击此链接将带您进入一个熟悉的文件浏览器，如下截图所示：

![通过管理员管理静态资产](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_13.jpg)

### 提示

如果您在管理文件时遇到问题，请确保为`static`目录及其子目录设置了正确的权限。

# 保护管理员网站

当您测试新的管理员网站时，您可能已经注意到它没有进行任何身份验证。为了保护我们的管理员网站免受匿名用户（甚至某些已登录用户）的侵害，我们将向`User`模型添加一个新列，以指示用户可以访问管理员网站。然后，我们将使用 Flask-Admin 提供的钩子来确保请求用户具有权限。

第一步是向我们的`User`模型添加一个新列。将`admin`列添加到`User`模型中，如下所示：

```py
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(255))
    name = db.Column(db.String(64))
    slug = db.Column(db.String(64), unique=True)
    active = db.Column(db.Boolean, default=True)
 admin = db.Column(db.Boolean, default=False)
    created_timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
```

现在我们将使用 Flask-Migrate 扩展生成模式迁移：

```py
(blog) $ python manage.py db migrate
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added column 'user.admin'
 Generating /home/charles/projects/blog/app/migrations/versions/33011181124e_.py ... done

(blog) $ python manage.py db upgrade
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.migration] Running upgrade 40ce2670e7e2 -> 33011181124e, empty message

```

让我们还向`User`模型添加一个方法，用于告诉我们给定的用户是否是管理员。将以下方法添加到`User`模型中：

```py
class User(db.Model):
    # ...

    def is_admin(self):
        return self.admin
```

这可能看起来很傻，但如果您希望更改应用程序确定用户是否为管理员的语义，这是很好的代码规范。

在继续下一节之前，您可能希望修改`UserModelView`类，将`admin`列包括在`column_list`、`column_filters`和`form_columns`中。

## 创建身份验证和授权混合

由于我们在管理员视图中创建了几个视图，我们需要一种可重复使用的表达我们身份验证逻辑的方法。我们将通过组合实现此重用。您已经在视图装饰器（`@login_required`）的形式中看到了组合-装饰器只是组合多个函数的一种方式。Flask-Admin 有点不同，它使用 Python 类来表示单个视图。我们将使用一种友好于类的组合方法，称为**mixins**，而不是函数装饰器。

mixin 是提供方法覆盖的类。在 Flask-Admin 的情况下，我们希望覆盖的方法是`is_accessible`方法。在这个方法内部，我们将检查当前用户是否已经验证。

为了访问当前用户，我们必须在`admin`模块的顶部导入特殊的`g`对象：

```py
from flask import g, url_for
```

在导入语句下面，添加以下类：

```py
class AdminAuthentication(object):
    def is_accessible(self):
        return g.user.is_authenticated and g.user.is_admin()
```

最后，我们将通过 Python 的多重继承将其与其他几个类*混合*在一起。对`BaseModelView 类`进行以下更改：

```py
class BaseModelView(AdminAuthentication, ModelView):
    pass
```

还有`BlogFileAdmin 类`：

```py
class BlogFileAdmin(AdminAuthentication, FileAdmin):
    pass
```

如果尝试访问/admin/entry/等管理员视图 URL 而不符合`is_accessible`条件，Flask-Admin 将返回 HTTP 403 Forbidden 响应，如下截图所示：

![创建身份验证和授权 mixin](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_14.jpg)

### 注意

由于我们没有对`Tag`管理员模型进行更改，因此仍然可以访问。我们将由您来解决如何保护它。

## 设置自定义首页

我们的管理员着陆页（/admin/）非常无聊。实际上，除了导航栏之外，它根本没有任何内容。Flask-Admin 允许我们指定自定义索引视图，我们将使用它来显示一个简单的问候语。

为了添加自定义索引视图，我们需要导入几个新的帮助程序。将以下突出显示的导入添加到`admin`模块的顶部：

```py
from flask.ext.admin import Admin, AdminIndexView, expose

```

`from flask import redirect`请求提供`@expose`装饰器，就像 Flask 本身使用`@route`一样。由于这个视图是索引，我们将要暴露的 URL 是`/`。以下代码将创建一个简单的索引视图，用于呈现模板。请注意，在初始化`Admin`对象时，我们将索引视图指定为参数：

```py
class IndexView(AdminIndexView):
    @expose('/')
    def index(self):
        return self.render('admin/index.html')

admin = Admin(app, 'Blog Admin', index_view=IndexView())
```

最后还缺少一件事：身份验证。由于用户通常会直接访问/admin/来访问管理员，因此检查索引视图中当前用户是否经过身份验证将非常方便。我们可以通过以下方式来检查：当前用户是否经过身份验证。

```py
class IndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not (g.user.is_authenticated and g.user.is_admin()):
 return redirect(url_for('login', next=request.path))
        return self.render('admin/index.html')
```

## Flask-Admin 模板

Flask-Admin 提供了一个简单的主模板，您可以扩展它以创建统一的管理员站点外观。Flask-Admin 主模板包括以下区块：

| 区块名称 | 描述 |
| --- | --- |
| `head_meta` | 头部页面元数据 |
| `title` | 页面标题 |
| `head_css` | 头部的 CSS 链接 |
| `head` | 文档头部的任意内容 |
| `page_body` | 页面布局 |
| `brand` | 菜单栏中的标志 |
| `main_menu` | 主菜单 |
| `menu_links` | 导航栏 |
| `access_control` | 菜单栏右侧的区域，可用于添加登录/注销按钮 |
| `messages` | 警报和各种消息 |
| `body` | 主内容区域 |
| `tail` | 内容下方的空白区域 |

对于这个示例，`body`块对我们来说最有趣。在应用程序的`templates`目录中，创建一个名为`admin`的新子目录，其中包含一个名为`index.html`的空文件。

让我们自定义管理员着陆页，以在服务器上显示当前日期和时间。我们将扩展 Flask-Admin 提供的`master`模板，仅覆盖`body`块。在模板中创建`admin`目录，并将以下代码添加到`templates/admin/index.html`：

```py
{% extends "admin/master.html" %}

{% block body %}
  <h3>Hello, {{ g.user.name }}</h3>
{% endblock %}
```

以下是我们新着陆页的截图：

![Flask-Admin 模板](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_06_15.jpg)

这只是一个例子，用来说明扩展和定制管理面板是多么简单。尝试使用各种模板块，看看是否可以在导航栏中添加一个注销按钮。

# 阅读更多

Flask-Admin 是一个多才多艺、高度可配置的 Flask 扩展。虽然我们介绍了 Flask-Admin 的一些常用功能，但是要讨论的功能实在太多，无法在一个章节中全部涵盖。因此，我强烈建议您访问该项目的文档，如果您想继续学习。文档可以在[`flask-admin.readthedocs.org/`](https://flask-admin.readthedocs.org/)上找到。

# 总结

在本章中，我们学习了如何使用 Flask-Admin 扩展为我们的应用程序创建管理面板。我们学习了如何将我们的 SQLAlchemy 模型公开为可编辑对象的列表，以及如何定制表格和表单的外观。我们添加了一个文件浏览器，以帮助管理应用程序的静态资产。我们还将管理面板与我们的身份验证系统集成。

在下一章中，我们将学习如何向我们的应用程序添加 API，以便可以通过编程方式访问它。
