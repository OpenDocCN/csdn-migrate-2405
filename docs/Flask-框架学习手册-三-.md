# Flask 框架学习手册（三）

> 原文：[`zh.annas-archive.org/md5/A6963809F66F360038656FE5292ADA55`](https://zh.annas-archive.org/md5/A6963809F66F360038656FE5292ADA55)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：AJAX 和 RESTful API

在本章中，我们将使用 Flask-Restless 为博客应用创建一个 RESTful API。RESTful API 是以编程方式访问您的博客的一种方式，通过提供代表您的博客的高度结构化的数据。Flask-Restless 非常适用于我们的 SQLAlchemy 模型，并且还处理复杂的任务，如序列化和结果过滤。我们将使用我们的 REST API 为博客条目构建一个基于 AJAX 的评论功能。在本章结束时，您将能够为您的 SQLAlchemy 模型创建易于配置的 API，并在您的 Flask 应用中进行 AJAX 请求的创建和响应。

在本章中，我们将：

+   创建一个模型来存储博客条目上的评论

+   安装 Flask-Restless

+   为评论模型创建一个 RESTful API

+   构建一个用于使用 Ajax 与我们的 API 进行通信的前端

# 创建评论模型

在我们开始创建 API 之前，我们需要为我们希望共享的资源创建一个数据库模型。我们正在构建的 API 将用于使用 AJAX 创建和检索评论，因此我们的模型将包含存储未经身份验证用户在我们条目中的评论的所有相关字段。

对于我们的目的，以下字段应该足够：

+   `name`，发表评论的人的姓名

+   `email`，评论者的电子邮件地址，我们将仅使用它来显示他们在**Gravatar**上的图片

+   `URL`，评论者博客的 URL

+   `ip_address`，评论者的 IP 地址

+   `body`，实际评论

+   `status`，其中之一是`Public`，`Spam`或`Deleted`

+   `created_timestamp`，评论创建的时间戳

+   `entry_id`，评论相关的博客条目的 ID

让我们通过在我们的应用程序的`models.py`模块中创建`Comment`模型定义来开始编码：

```py
class Comment(db.Model):
    STATUS_PENDING_MODERATION = 0
    STATUS_PUBLIC = 1
    STATUS_SPAM = 8
    STATUS_DELETED = 9

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    email = db.Column(db.String(64))
    url = db.Column(db.String(100))
    ip_address = db.Column(db.String(64))
    body = db.Column(db.Text)
    status = db.Column(db.SmallInteger, default=STATUS_PUBLIC)
    created_timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    entry_id = db.Column(db.Integer, db.ForeignKey('entry.id'))

    def __repr__(self):
        return '<Comment from %r>' % (self.name,)
```

在添加`Comment`模型定义之后，我们需要设置`Comment`和`Entry`模型之间的 SQLAlchemy 关系。您会记得，我们在设置`User`和`Entry`之间的关系时曾经做过一次，通过 entries 关系。我们将通过在`Entry`模型中添加一个 comments 属性来为`Comment`做这个。 

在`tags`关系下面，添加以下代码到`Entry`模型定义中：

```py
class Entry(db.Model):
    # ...
    tags = db.relationship('Tag', secondary=entry_tags,
        backref=db.backref('entries', lazy='dynamic'))
    comments = db.relationship('Comment', backref='entry', lazy='dynamic')

```

我们已经指定了关系为`lazy='dynamic'`，正如您从第五章*验证用户*中所记得的那样，这意味着在任何给定的`Entry`实例上，`comments`属性将是一个可过滤的查询。

## 创建模式迁移

为了开始使用我们的新模型，我们需要更新我们的数据库模式。使用`manage.py`助手，为`Comment`模型创建一个模式迁移：

```py
(blog) $ python manage.py db migrate
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.autogenerate.compare] Detected added table 'comment'
 Generating /home/charles/projects/blog/app/migrations/versions/490b6bc5f73c_.py ... done

```

然后通过运行`upgrade`来应用迁移：

```py
(blog) $ python manage.py db upgrade
INFO  [alembic.migration] Context impl SQLiteImpl.
INFO  [alembic.migration] Will assume non-transactional DDL.
INFO  [alembic.migration] Running upgrade 594ebac9ef0c -> 490b6bc5f73c, empty message

```

`Comment`模型现在已经准备好使用了！在这一点上，如果我们使用常规的 Flask 视图来实现评论，我们可能会创建一个评论蓝图并开始编写一个视图来处理评论的创建。然而，我们将使用 REST API 公开评论，并直接从前端使用 AJAX 创建它们。

# 安装 Flask-Restless

有了我们的模型，我们现在准备安装 Flask-Restless，这是一个第三方 Flask 扩展，可以简单地为您的 SQLAlchemy 模型构建 RESTful API。确保您已经激活了博客应用的虚拟环境后，使用`pip`安装 Flask-Restless：

```py
(blog) $ pip install Flask-Restless

```

您可以通过打开交互式解释器并获取已安装的版本来验证扩展是否已安装。不要忘记，您的确切版本号可能会有所不同。

```py
(blog) $ ./manage.py shell

In [1]: import flask_restless

In [2]: flask_restless.__version__
Out[2]: '0.13.0'

```

现在我们已经安装了 Flask-Restless，让我们配置它以使其与我们的应用程序一起工作。

## 设置 Flask-Restless

像其他 Flask 扩展一样，我们将从`app.py`模块开始，通过配置一个将管理我们新 API 的对象。在 Flask-Restless 中，这个对象称为`APIManager`，它将允许我们为我们的 SQLAlchemy 模型创建 RESTful 端点。将以下行添加到`app.py`：

```py
# Place this import at the top of the module alongside the other extensions.
from flask.ext.restless import APIManager

# Place this line below the initialization of the app and db objects.
api = APIManager(app, flask_sqlalchemy_db=db)
```

因为 API 将依赖于我们的 Flask API 对象和我们的`Comment`模型，所以我们需要确保我们不创建任何循环模块依赖关系。我们可以通过在应用程序目录的根目录下创建一个新模块“api.py”来避免引入循环导入。

让我们从最基本的开始，看看 Flask-Restless 提供了什么。在`api.py`中添加以下代码：

```py
from app import api
from models import Comment

api.create_api(Comment, methods=['GET', 'POST'])
```

`api.py`中的代码调用了我们的`APIManager`对象上的`create_api()`方法。这个方法将用额外的 URL 路由和视图代码填充我们的应用程序，这些代码一起构成了一个 RESTful API。方法参数指示我们只允许`GET`和`POST`请求（意味着评论可以被读取或创建，但不能被编辑或删除）。

最后的操作是在`main.py`中导入新的 API 模块，这是我们应用程序的入口点。我们导入模块纯粹是为了它的副作用，注册 URL 路由。在`main.py`中添加以下代码：

```py
from app import app, db
import admin
import api
import models
import views

...
```

## 发出 API 请求

在一个终端中，启动开发服务器。在另一个终端中，让我们看看当我们向我们的 API 端点发出`GET`请求时会发生什么（注意没有尾随的斜杠）：

```py
$ curl 127.0.0.1:5000/api/comment
{
 "num_results": 0,
 "objects": [],
 "page": 1,
 "total_pages": 0
}

```

数据库中没有评论，所以没有对象被序列化和返回给我们。然而，有一些有趣的元数据告诉我们数据库中有多少对象，我们在哪一页，以及有多少总页的评论存在。

让我们通过向我们的 API POST 一些 JSON 数据来创建一个新的评论（我将假设你的数据库中的第一个条目的 id 为`1`）。我们将使用`curl`提交一个包含新评论的 JSON 编码表示的`POST`请求：

```py
$ curl -X POST -H "Content-Type: application/json" -d '{
 "name": "Charlie",
 "email": "charlie@email.com",
 "url": "http://charlesleifer.com",
 "ip_address": "127.0.0.1",
 "body": "Test comment!",
 "entry_id": 1}' http://127.0.0.1:5000/api/comment

```

假设没有拼写错误，API 将以以下数据回应，确认新的`Comment`的创建：

```py
{
  "body": "Test comment!",
  "created_timestamp": "2014-04-22T19:48:33.724118",
  "email": "charlie@email.com",
  "entry": {
    "author_id": 1,
    "body": "This is an entry about Python, my favorite programming language.",
    "created_timestamp": "2014-03-06T19:50:09",
    "id": 1,
    "modified_timestamp": "2014-03-06T19:50:09",
    "slug": "python-entry",
    "status": 0,
    "title": "Python Entry"
  },
  "entry_id": 1,
  "id": 1,
  "ip_address": "127.0.0.1",
  "name": "Charlie",
  "status": 0,
  "url": "http://charlesleifer.com"
}
```

正如你所看到的，我们 POST 的所有数据都包含在响应中，除了其余的字段数据，比如新评论的 id 和时间戳。令人惊讶的是，甚至相应中已经序列化并包含了相应的`Entry`对象。

现在我们在数据库中有了一个评论，让我们尝试向我们的 API 发出另一个`GET`请求：

```py
$ curl 127.0.0.1:5000/api/comment
{
 "num_results": 1,
 "objects": [
 {
 "body": "Test comment!",
 "created_timestamp": "2014-04-22T19:48:33.724118",
 "email": "charlie@email.com",
 "entry": {
 "author_id": 1,
 "body": "This is an entry about Python, my favorite programming language.",
 "created_timestamp": "2014-03-06T19:50:09",
 "id": 1,
 "modified_timestamp": "2014-03-06T19:50:09",
 "slug": "python-entry",
 "status": 0,
 "title": "Python Entry"
 },
 "entry_id": 1,
 "id": 1,
 "ip_address": "127.0.0.1",
 "name": "Charlie",
 "status": 0,
 "url": "http://charlesleifer.com"
 }
 ],
 "page": 1,
 "total_pages": 1
}

```

第一个对象包含了当我们进行`POST`请求时返回给我们的完全相同的数据。此外，周围的元数据已经改变，以反映数据库中现在有一个评论的事实。

# 使用 AJAX 创建评论

为了允许用户发表评论，我们首先需要一种捕获他们输入的方法，我们将通过使用`wtforms`创建一个`Form`类来实现这一点。这个表单应该允许用户输入他们的姓名、电子邮件地址、一个可选的 URL 和他们的评论。

在条目蓝图的表单模块中，添加以下表单定义：

```py
class CommentForm(wtforms.Form):
    name = wtforms.StringField('Name', validators=[validators.DataRequired()])
    email = wtforms.StringField('Email', validators=[
        validators.DataRequired(),
        validators.Email()])
    url = wtforms.StringField('URL', validators=[
        validators.Optional(),
        validators.URL()])
    body = wtforms.TextAreaField('Comment', validators=[
        validators.DataRequired(),
        validators.Length(min=10, max=3000)])
    entry_id = wtforms.HiddenField(validators=[
        validators.DataRequired()])

    def validate(self):
        if not super(CommentForm, self).validate():
            return False

        # Ensure that entry_id maps to a public Entry.
        entry = Entry.query.filter(
            (Entry.status == Entry.STATUS_PUBLIC) &
            (Entry.id == self.entry_id.data)).first()
        if not entry:
            return False

        return True
```

你可能会想为什么我们要指定验证器，因为 API 将处理 POST 的数据。我们这样做是因为 Flask-Restless 不提供验证，但它提供了一个我们可以执行验证的钩子。这样，我们就可以在我们的 REST API 中利用 WTForms 验证。

为了在条目详细页面使用表单，我们需要在渲染详细模板时将表单传递到上下文中。打开条目蓝图并导入新的`CommentForm`：

```py
from entries.forms import EntryForm, ImageForm, CommentForm

```

然后修改“详细”视图，将一个表单实例传递到上下文中。我们将使用请求的条目的值预填充`entry_id`隐藏字段：

```py
@entries.route('/<slug>/')
def detail(slug):
    entry = get_entry_or_404(slug)
    form = CommentForm(data={'entry_id': entry.id})
    return render_template('entries/detail.html', entry=entry, form=form)
```

现在表单已经在详细模板上下文中，剩下的就是渲染表单。在`entries/templates/entries/includes/`中创建一个空模板，命名为`comment_form.html`，并添加以下代码：

```py
{% from "macros/form_field.html" import form_field %}
<form action="/api/comment" class="form form-horizontal" id="comment-form" method="post">
  {{ form_field(form.name) }}
  {{ form_field(form.email) }}
  {{ form_field(form.url) }}
  {{ form_field(form.body) }}
  {{ form.entry_id() }}
  <div class="form-group">
    <div class="col-sm-offset-3 col-sm-9">
      <button type="submit" class="btn btn-default">Submit</button>
    </div>
  </div>
</form>
```

值得注意的是，我们没有使用`form_field`宏来处理`entry_id`字段。这是因为我们不希望评论表单显示一个对用户不可见的字段的标签。相反，我们将用这个值初始化表单。

最后，我们需要在`detail.html`模板中包含评论表单。在条目正文下面，添加以下标记：

```py
{% block content %}
  {{ entry.body }}

  <h4 id="comment-form">Submit a comment</h4>
 {% include "entries/includes/comment_form.html" %}
{% endblock %}
```

使用开发服务器，尝试导航到任何条目的详细页面。你应该会看到一个评论表单：

![使用 AJAX 创建评论](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_07_01.jpg)

## AJAX 表单提交

为了简化进行 AJAX 请求，我们将使用 jQuery 库。如果你愿意，可以随意替换为其他 JavaScript 库，但是由于 jQuery 如此普遍（并且与 Bootstrap 兼容），我们将在本节中使用它。如果你一直在跟着代码进行开发，那么 jQuery 应该已经包含在所有页面中。现在我们需要创建一个 JavaScript 文件来处理评论提交。

在`statics/js/`中创建一个名为`comments.js`的新文件，并添加以下 JavaScript 代码：

```py
Comments = window.Comments || {};

(function(exports, $) { /* Template string for rendering success or error messages. */
  var alertMarkup = (
    '<div class="alert alert-{class} alert-dismissable">' +
    '<button type="button" class="close" data-dismiss="alert" aria-hidden="true">&times;</button>' +
    '<strong>{title}</strong> {body}</div>');

  /* Create an alert element. */
  function makeAlert(alertClass, title, body) {
    var alertCopy = (alertMarkup
                     .replace('{class}', alertClass)
                     .replace('{title}', title)
                     .replace('{body}', body));
    return $(alertCopy);
  }

  /* Retrieve the values from the form fields and return as an object. */
  function getFormData(form) {
    return {
      'name': form.find('input#name').val(),
      'email': form.find('input#email').val(),
      'url': form.find('input#url').val(),
      'body': form.find('textarea#body').val(),
      'entry_id': form.find('input[name=entry_id]').val()
    }
  }

  function bindHandler() {
    /* When the comment form is submitted, serialize the form data as JSON
             and POST it to the API. */
    $('form#comment-form').on('submit', function() {
      var form = $(this);
      var formData = getFormData(form);
      var request = $.ajax({
        url: form.attr('action'),
        type: 'POST',
        data: JSON.stringify(formData),
        contentType: 'application/json; charset=utf-8',
        dataType: 'json'
      });
      request.success(function(data) {
        alertDiv = makeAlert('success', 'Success', 'your comment was posted.');
        form.before(alertDiv);
        form[0].reset();
      });
      request.fail(function() {
        alertDiv = makeAlert('danger', 'Error', 'your comment was not posted.');
        form.before(alertDiv);
      });
      return false;
    });
  }

  exports.bindHandler = bindHandler;
})(Comments, jQuery);
```

`comments.js`代码处理将表单数据序列化为 JSON 后，提交到 REST API。它还处理 API 响应，并显示成功或错误消息。

在`detail.html`模板中，我们只需要包含我们的脚本并绑定提交处理程序。在详细模板中添加以下块覆盖： 

```py
{% block extra_scripts %}
  <script type="text/javascript" src="img/comments.js') }}"></script>
  <script type="text/javascript">
    $(function() {
      Comments.bindHandler();
    });
  </script>
{% endblock %}
```

试着提交一两条评论。

## 在 API 中验证数据

不幸的是，我们的 API 没有对传入数据进行任何类型的验证。为了验证`POST`数据，我们需要使用 Flask-Restless 提供的一个钩子。Flask-Restless 将这些钩子称为请求预处理器和后处理器。

让我们看看如何使用 POST 预处理器对评论数据进行一些验证。首先打开`api.py`并进行以下更改：

```py
from flask.ext.restless import ProcessingException

from app import api
from entries.forms import CommentForm
from models import Comment

def post_preprocessor(data, **kwargs):
    form = CommentForm(data=data)
    if form.validate():
        return form.data
    else:
        raise ProcessingException(
            description='Invalid form submission.',
            code=400)

api.create_api(
    Comment,
    methods=['GET', 'POST'],
    preprocessors={
        'POST': [post_preprocessor],
    })
```

我们的 API 现在将使用来自`CommentForm`的验证逻辑来验证提交的评论。我们通过为`POST`方法指定一个预处理器来实现这一点。我们已经实现了`post_preprocessor`作为`POST`预处理器，它接受反序列化的`POST`数据作为参数。然后我们可以将这些数据传递给我们的`CommentForm`并调用它的`validate()`方法。如果验证失败，我们将引发一个`ProcessingException`，向 Flask-Restless 发出信号，表明这些数据无法处理，并返回一个`400` Bad Request 响应。

在下面的截图中，我没有提供必需的**评论**字段。当我尝试提交评论时，我收到了一个错误消息：

![在 API 中验证数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_07_02.jpg)

## 预处理器和后处理器

我们刚刚看了一个使用 Flask-Restless 的`POST`方法预处理器的示例。在下表中，你可以看到其他可用的钩子：

| 方法名称 | 描述 | 预处理器参数 | 后处理器参数 |
| --- | --- | --- | --- |
| `GET_SINGLE` | 通过主键检索单个对象 | `instance_id`，对象的主键 | `result`，对象的字典表示 |
| `GET_MANY` | 检索多个对象 | `search_params`，用于过滤结果集的搜索参数字典 | `result`，对象的`search_params`表示 |
| `PUT_SINGLE` | 通过主键更新单个对象 | `instance_id`数据，用于更新对象的数据字典 | `result`，更新后对象的字典表示 |
| `PUT_MANY` | 更新多个对象 | `search_params`，用于确定要更新哪些对象的搜索参数字典。data，用于更新对象的数据字典。 | `query`，表示要更新的对象的 SQLAlchemy 查询。`data``search_params` |
| `POST` | 创建新实例 | `data`，用于填充新对象的数据字典 | `result`，新对象的字典表示 |
| `DELETE` | 通过主键删除实例 | `instance_id`，要删除的对象的主键 | `was_deleted`，一个布尔值，指示对象是否已被删除 |

# 使用 AJAX 加载评论

现在我们能够使用 AJAX 创建经过验证的评论，让我们使用 API 来检索评论列表，并在博客条目下方显示它们。为此，我们将从 API 中读取值，并动态创建 DOM 元素来显示评论。您可能还记得我们之前检查的 API 响应中返回了相当多的私人信息，包括每条评论相关联的整个序列化表示的`Entry`。对于我们的目的来说，这些信息是多余的，而且还会浪费带宽。

让我们首先对评论端点进行一些额外的配置，以限制我们返回的`Comment`字段。在`api.py`中，对`api.create_api()`的调用进行以下添加：

```py
api.create_api(
    Comment,
    include_columns=['id', 'name', 'url', 'body', 'created_timestamp'],
    methods=['GET', 'POST'],
    preprocessors={
        'POST': [post_preprocessor],
    })
```

现在请求评论列表会给我们一个更易管理的响应，不会泄露实现细节或私人数据：

```py
$ curl http://127.0.0.1:5000/api/comment
{
 "num_results": 1,
 "objects": [
 {
 "body": "Test comment!",
 "created_timestamp": "2014-04-22T19:48:33.724118",
 "name": "Charlie",
 "url": "http://charlesleifer.com"
 }
 ],
 "page": 1,
 "total_pages": 1
}

```

一个很好的功能是在用户的评论旁边显示一个头像。Gravatar 是一个免费的头像服务，允许用户将他们的电子邮件地址与图像关联起来。我们将使用评论者的电子邮件地址来显示他们关联的头像（如果存在）。如果用户没有创建头像，将显示一个抽象图案。

让我们在`Comment`模型上添加一个方法来生成用户 Gravatar 图像的 URL。打开`models.py`并向`Comment`添加以下方法：

```py
def gravatar(self, size=75):
    return 'http://www.gravatar.com/avatar.php?%s' % urllib.urlencode({
        'gravatar_id': hashlib.md5(self.email).hexdigest(),
        'size': str(size)})
```

您还需要确保在模型模块的顶部导入`hashlib`和`urllib`。

如果我们尝试在列的列表中包括 Gravatar，Flask-Restless 会引发异常，因为`gravatar`实际上是一个方法。幸运的是，Flask-Restless 提供了一种在序列化对象时包含方法调用结果的方法。在`api.py`中，对`create_api()`的调用进行以下添加：

```py
api.create_api(
    Comment,
    include_columns=['id', 'name', 'url', 'body', 'created_timestamp'],
    include_methods=['gravatar'],
    methods=['GET', 'POST'],#, 'DELETE'],
    preprocessors={
        'POST': [post_preprocessor],
    })
```

继续尝试获取评论列表。现在你应该看到 Gravatar URL 包含在序列化响应中。

## 检索评论列表

现在我们需要返回到我们的 JavaScript 文件，并添加代码来检索评论列表。我们将通过向 API 传递搜索过滤器来实现这一点，API 将仅检索与请求的博客条目相关联的评论。搜索查询被表示为一系列过滤器，每个过滤器指定以下内容：

+   列的名称

+   操作（例如，等于）

+   要搜索的值

打开`comments.js`并在以下行之后添加以下代码：

```py
(function(exports, $) {:
function displayNoComments() {
  noComments = $('<h3>', {
    'text': 'No comments have been posted yet.'});
  $('h4#comment-form').before(noComments);
}

/* Template string for rendering a comment. */
var commentTemplate = (
  '<div class="media">' +
    '<a class="pull-left" href="{url}">' +
      '<img class="media-object" src="img/{gravatar}" />' +
    '</a>' +
    '<div class="media-body">' +
    '<h4 class="media-heading">{created_timestamp}</h4>{body}' +
  '</div></div>'
);

function renderComment(comment) {
  var createdDate = new Date(comment.created_timestamp).toDateString();
  return (commentTemplate
          .replace('{url}', comment.url)
          .replace('{gravatar}', comment.gravatar)
          .replace('{created_timestamp}', createdDate)
          .replace('{body}', comment.body));
}

function displayComments(comments) {
  $.each(comments, function(idx, comment) {
    var commentMarkup = renderComment(comment);
    $('h4#comment-form').before($(commentMarkup));
  });
}

function load(entryId) {
  var filters = [{
    'name': 'entry_id',
    'op': 'eq',
    'val': entryId}];
  var serializedQuery = JSON.stringify({'filters': filters});

  $.get('/api/comment', {'q': serializedQuery}, function(data) {
    if (data['num_results'] === 0) {
      displayNoComments();
    } else {
      displayComments(data['objects']);
    }
  });
}
```

然后，在文件底部附近，导出`load`函数以及`bindHandler`导出，如下所示：

```py
exports.load = load;
exports.bindHandler = bindHandler;
```

我们添加的新 JavaScript 代码会向 API 发出 AJAX 请求，以获取与给定条目相关联的评论。如果没有评论存在，将显示一条消息，指示尚未发表评论。否则，条目将作为列表呈现在`Entry`正文下方。

最后的任务是在页面呈现时在详细模板中调用`Comments.load()`。打开`detail.html`并添加以下突出显示的代码：

```py
<script type="text/javascript">
  $(function() {
    Comments.load({{ entry.id }});
    Comments.bindHandler();
  });
</script>
```

在发表了一些评论之后，评论列表看起来如下图所示：

![检索评论列表](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_07_03.jpg)

作为练习，看看你是否能够编写代码来呈现用户发表的任何新评论。您会记得，当成功创建评论时，新数据将作为 JSON 对象返回。

# 阅读更多

Flask-Restless 支持许多配置选项，由于篇幅原因，本章未能涵盖。搜索过滤器是一个非常强大的工具，我们只是触及了可能性的表面。此外，预处理和后处理钩子可以用于实现许多有趣的功能，例如以下功能：

+   可以在预处理器中实现的身份验证

+   `GET_MANY`的默认过滤器，可以用于限制评论列表，例如只显示公开的评论

+   向序列化响应添加自定义或计算值

+   修改传入的`POST`值以在模型实例上设置默认值

如果 REST API 是您的应用程序中的关键组件，我强烈建议花时间阅读 Flask-Restless 文档。文档可以在网上找到：[`flask-restless.readthedocs.org/en/latest/`](https://flask-restless.readthedocs.org/en/latest/)。

# 总结

在本章中，我们使用 Flask-Restless 扩展为我们的应用程序添加了一个简单的 REST API。然后，我们使用 JavaScript 和 Ajax 将我们的前端与 API 集成，允许用户查看和发布新评论，而无需编写一行视图代码。

在下一章中，我们将致力于创建可测试的应用程序，并找到改进我们代码的方法。这也将使我们能够验证我们编写的代码是否按照我们的意愿进行操作；不多，也不少。自动化这一过程将使您更有信心，并确保 RESTful API 按预期工作。


# 第八章：测试 Flask 应用

在本章中，我们将学习如何编写覆盖博客应用程序所有部分的单元测试。我们将利用 Flask 的测试客户端来模拟实时请求，并了解 Mock 库如何简化测试复杂交互，比如调用数据库等第三方服务。

在本章中，我们将学习以下主题：

+   Python 的单元测试模块和测试编写的一般指导

+   友好的测试配置

+   如何使用 Flask 测试客户端模拟请求和会话

+   如何使用 Mock 库测试复杂交互

+   记录异常和错误邮件

# 单元测试

单元测试是一个让我们对代码、bug 修复和未来功能有信心的过程。单元测试的理念很简单；你编写与你的功能代码相辅相成的代码。

举个例子，假设我们设计了一个需要正确计算一些数学的程序；你怎么知道它成功了？为什么不拿出一个计算器，你知道计算机是什么吗？一个大计算器。此外，计算机在乏味的重复任务上确实非常擅长，那么为什么不编写一个单元测试来为你计算出答案呢？对代码的所有部分重复这种模式，将这些测试捆绑在一起，你就对自己编写的代码完全有信心了。

### 注意

有人说测试是代码“味道”的标志，你的代码如此复杂，以至于需要测试来证明它的工作。这意味着代码应该更简单。然而，这真的取决于你的情况，你需要自己做出判断。在我们开始简化代码之前，单元测试是一个很好的起点。

单元测试的巧妙之处在于测试与功能代码相辅相成。这些方法证明了测试的有效性，而测试证明了方法的有效性。它减少了代码出现重大功能错误的可能性，减少了将来重新编写代码的头痛，并允许你专注于你想要处理的新功能的细枝末节。

### 提示

单元测试的理念是验证代码的小部分，或者说是测试简单的功能部分。这将构建成应用程序的整体。很容易写出大量测试代码，测试的是代码的功能而不是代码本身。如果你的测试看起来很大，通常表明你的主要代码应该被分解成更小的方法。

## Python 的单元测试模块

幸运的是，几乎总是如此，Python 有一个内置的单元测试模块。就像 Flask 一样，很容易放置一个简单的单元测试模块。在你的主要博客应用程序中，创建一个名为`tests`的新目录，并在该目录中创建一个名为`test.py`的新文件。现在，使用你喜欢的文本编辑器，输入以下代码：

```py
import unittest

class ExampleTest(unittest.TestCase):
  def setUp(self):
    pass

  def tearDown(self):
    pass

  def test_some_functionality(self):
    pass

  def test_some_other_functionality(self):
    pass

if __name__ == "__main__":
  unittest.main()
```

前面的片段演示了我们将编写的所有单元测试模块的基本框架。它简单地利用内置的 Python 模块`unittest`，然后创建一个包装特定测试集的类。在这个例子中，测试是以单词`test`开头的方法。单元测试模块将这些方法识别为每次调用`unittest.main`时应该运行的方法。此外，`TestCase`类（`ExampleTest`类在这里继承自它）具有一些特殊方法，单元测试将始终尝试使用。其中之一是`setUp`，这是在运行每个测试方法之前运行的方法。当您想要在隔离环境中运行每个测试，但是，例如，要在数据库中建立连接时，这可能特别有用。

另一个特殊的方法是`tearDown`。每次运行测试方法时都会运行此方法。同样，当我们想要维护数据库时，这对于每个测试都在隔离环境中运行非常有用。

显然，这个代码示例如果运行将不会做任何事情。要使其处于可用状态，并且遵循**测试驱动开发**（**TDD**）的原则，我们首先需要编写一个测试，验证我们即将编写的代码是否正确，然后编写满足该测试的代码。

## 一个简单的数学测试

在这个示例中，我们将编写一个测试，验证一个方法将接受两个数字作为参数，从第二个参数中减去一个，然后将它们相乘。看一下以下示例：

| 参数 1 | 参数 2 | 答案 |
| --- | --- | --- |
| `1` | `1` | `1 * (1-1) = 0` |
| `1` | `2` | `1 * (2-1) = 1` |
| `2` | `3` | `2 * (3-1) = 4` |

在你的`test.py`文件中，你可以创建一个在`ExampleTest`类中表示前面表格的方法，如下所示：

```py
  def test_minus_one_multiplication(self):
    self.assertEqual(my_multiplication(1,1), 0)
    self.assertEqual(my_multiplication(1,2), 1)
    self.assertEqual(my_multiplication(2,3), 4)
    self.assertNotEqual(my_multiplication(2,2), 3)
```

前面的代码创建了一个新的方法，使用 Python 的`unittest`模块来断言问题的答案。`assertEqual`函数将`my_multiplication`方法返回的响应作为第一个参数，并将其与第二个参数进行比较。如果通过了，它将什么也不做，等待下一个断言进行测试。但如果不匹配，它将抛出一个错误，并且你的测试方法将停止执行，告诉你出现了错误。

在前面的代码示例中，还有一个`assertNotEqual`方法。它的工作方式与`assertEqual`类似，但是检查值是否不匹配。还有一个好主意是检查你的方法何时可能失败。如果你只检查了方法将起作用的情况，那么你只完成了一半的工作，并且可能会在边缘情况下遇到问题。Python 的`unittest`模块提供了各种各样的断言方法，这将是有用的去探索。

现在我们可以编写将给出这些结果的方法。为简单起见，我们将在同一个文件中编写该方法。在文件中，创建以下方法：

```py
def my_multiplication(value1, value2):
  return value1 * value2 – 1
```

保存文件并使用以下命令运行它：

```py
python test.py

```

![一个简单的数学测试](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_08_01.jpg)

哎呀！它失败了。为什么？嗯，回顾`my_multiplication`方法发现我们漏掉了一些括号。让我们回去纠正一下：

```py
def my_multiplication(value1, value2):
  return value1 * (value2 – 1)
```

现在让我们再次运行它：

![一个简单的数学测试](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_08_02.jpg)

成功了！现在我们有了一个正确的方法；将来，我们将知道它是否被更改过，以及在以后需要如何更改。现在来用这个新技能与 Flask 一起使用。

# Flask 和单元测试

你可能会想：“单元测试对于代码的小部分看起来很棒，但是如何为整个 Flask 应用程序进行测试呢？”嗯，正如之前提到的一种方法是确保所有的方法尽可能离散——也就是说，确保你的方法尽可能少地完成它们的功能，并避免方法之间的重复。如果你的方法不是离散的，现在是整理它们的好时机。

另一件有用的事情是，Flask 已经准备好进行单元测试。任何现有应用程序都有可能至少可以应用一些单元测试。特别是，任何 API 区域，例如无法验证的区域，都可以通过利用 Flask 中已有的代表 HTTP 请求的方法来进行极其容易的测试。以下是一个简单的示例：

```py
import unittest
from flask import request
from main import app

class AppTest(unittest.TestCase):
  def setUp(self):
    self.app = app.test_client()

  def test_homepage_works(self):
    response = self.app.get("/")
    self.assertEqual(response.status_code, 200)

if __name__ == "__main__":
  unittest.main()
```

这段代码应该看起来非常熟悉。它只是重新编写了前面的示例，以验证主页是否正常工作。Flask 公开的`test_client`方法允许通过代表 HTTP 调用的方法简单访问应用程序，就像`test`方法的第一行所示。`test`方法本身并不检查页面的内容，而只是检查页面是否成功加载。这可能听起来微不足道，但知道主页是否正常工作是很有用的。结果呢？你可以在这里看到：

![Flask 和单元测试](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_08_03.jpg)

### 提示

需要注意的一件事是，我们不需要测试 Flask 本身，必须避免测试它，以免为自己创造太多工作。

## 测试一个页面

关于运行先前的测试的一件事需要注意的是，它们非常简单。实际上没有浏览器会以这种方式行事。浏览器会执行诸如存储用于登录的 cookie、请求 JavaScript、图像和 CSS 文件等静态文件，以及请求特定格式的数据等操作。不知何故，我们需要模拟这种功能，并测试结果是否正确。

### 提示

这是单元测试开始变成功能测试的部分。虽然这本身并没有什么错，但值得注意的是，较小的测试更好。

幸运的是，Flask 通过使用先前的`app.get`方法来为您完成所有这些工作，但是您可以使用一些技巧来使事情变得更容易。例如，向`TestCase`类添加登录和退出功能将使事情变得简单得多：

```py
    LOGIN_URL = "/login/"
    LOGOUT_URL = "/logout/"

    def login (self, email, password):
        return self.app.post(self.LOGIN_URL, data={
            "email": email,
            "password": password
        }, follow_redirects=True)
```

前面的代码是未来测试用例的框架。每当我们有一个需要登录和退出的测试用例时，只需将此`Mixin`添加到继承列表中，它就会自动可用：

```py
class ExampleFlaskTest(unittest.TestCase, FlaskLoginMixin):
  def setUp(self):
    self.app = app.test_client()

  def test_login(self):
    response = self.login("admin", "password")
    self.assertEqual(response.status_code, 200)
    self.assertTrue("Success" in response.data)

  def test_failed_login(self):
    response = self.login("admin", "PASSWORD")
        self.assertEqual(response.status_code, 200)
        self.assertTrue("Invalid" in response.data)

  def test_logout(self):
    response = self.logout()
    self.assertEqual(response.status_code, 200)
    self.assertTrue("logged out" in response.data)
```

我们刚刚解释的测试用例使用了`FlaskLoginMixin`，这是一组方法，可以帮助检查登录和退出是否正常工作。这是通过检查响应页面是否发送了正确的消息，并且页面内容中是否有正确的警告来实现的。我们的测试还可以进一步扩展，以检查用户是否可以访问他们不应该访问的页面。Flask 会为您处理会话和 cookie，所以只需使用以下代码片段即可：

```py
class ExampleFlaskTest(unittest.TestCase, FlaskLoginMixin):
  def setUp(self):
    self.app = app.test_client()

  def test_admin_can_get_to_admin_page(self):
    self.login("admin", "password")
    response = self.app.get("/admin/")
    self.assertEqual(response.status_code, 200)
    self.assertTrue("Hello" in response.data)

  def test_non_logged_in_user_can_get_to_admin_page(self):
    response = self.app.get("/admin/")
    self.assertEqual(response.status_code, 302)
    self.assertTrue("redirected" in response.data)

  def test_normal_user_cannot_get_to_admin_page(self):
    self.login("user", "password")
    response = self.app.get("/admin/")
    self.assertEqual(response.status_code, 302)
    self.assertTrue("redirected" in response.data)

  def test_logging_out_prevents_access_to_admin_page(self):
    self.login("admin", "password")
    self.logout()
    response = self.app.get("/admin/")
    self.assertEqual(response.status_code, 302)
    self.assertTrue("redirected" in response.data)
```

前面的代码片段显示了如何测试某些页面是否受到正确保护。这是一个非常有用的测试。它还验证了，当管理员注销时，他们将无法再访问他们在登录时可以访问的页面。方法名称是自解释的，因此如果这些测试失败，很明显可以知道正在测试什么。

## 测试 API

测试 API 甚至更容易，因为它是程序干预。使用第七章中设置的先前评论 API，*AJAX 和 RESTful API*，我们可以很容易地插入和检索一些评论，并验证它是否正常工作。为了测试这一点，我们需要`import` json 库来处理我们的基于`JSON`的 API：

```py
class ExampleFlaskAPITest(unittest.TestCase, FlaskLoginMixin):
  def setUp(self):
    self.app = app.test_client()
    self.comment_data = {
      "name": "admin",
      "email": "admin@example.com",
      "url": "http://localhost",
      "ip_address": "127.0.0.1",
      "body": "test comment!",
      "entry_id": 1
    }

  def test_adding_comment(self):
    self.login("admin", "password")
      data=json.dumps(self.comment_data), content_type="application/json")
    self.assertEqual(response.status_code, 200)
    self.assertTrue("body" in response.data)
    self.assertEqual(json.loads(response.data)['body'], self.comment_data["body"])

  def test_getting_comment(self):
            result = self.app.post("/api/comment",
            data=json.dumps(self.comment_data), content_type="application/json")
        response = self.app.get("/api/comment")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(result.data) in json.loads(response.data)['objects'])
```

前面的代码示例显示了创建一个评论字典对象。这用于验证输入的值与输出的值是否相同。因此，这些方法测试将评论数据发布到`/api/comment`端点，验证服务器返回的数据是否正确。`test_getting_comment`方法再次检查是否将评论发布到服务器，但更关心所请求的结果，通过验证发送的数据是否与输出的数据相同。

# 测试友好的配置

在团队中编写测试或在生产环境中编写测试时遇到的第一个障碍之一是，我们如何确保测试在不干扰生产甚至开发数据库的情况下运行。您肯定不希望尝试修复错误或试验新功能，然后发现它所依赖的数据已经发生了变化。有时，只需要在本地数据库的副本上运行一个快速测试，而不受任何其他人的干扰，Flask 应用程序知道如何使用它。

Flask 内置的一个功能是根据环境变量加载配置文件。

```py
app.config.from_envvar('FLASK_APP_BLOG_CONFIG_FILE')
```

前面的方法调用通知您的 Flask 应用程序应该加载在环境变量`FLASK_APP_BLOG_CONFIG_FILE`中指定的文件中的配置。这必须是要加载的文件的绝对路径。因此，当您运行测试时，应该在这里引用一个特定于运行测试的文件。

由于我们已经为我们的环境设置了一个配置文件，并且正在创建一个测试配置文件，一个有用的技巧是利用现有的配置并覆盖重要的部分。首先要做的是创建一个带有 __init__.py 文件的 config 目录。然后可以将我们的 testing.py 配置文件添加到该目录中，并覆盖 config.py 配置文件的一些方面。例如，你的新测试配置文件可能如下所示：

```py
TESTING=True
DATABASE="sqlite://
```

上面的代码添加了 TESTING 属性，可以用来确定你的应用程序当前是否正在进行测试，并将 DATABASE 值更改为更适合测试的数据库，一个内存中的 SQLite 数据库，不必在测试结束后清除。

然后这些值可以像 Flask 中的任何其他配置一样使用，并且在运行测试时，可以指定环境变量指向该文件。如果我们想要自动更新测试的环境变量，我们可以在`test`文件夹中的`test.py`文件中更新 Python 的内置 OS 环境变量对象：

```py
import os
os.environ['FLASK_APP_BLOG_CONFIG_FILE'] = os.path.join(os.getcwd(), "config", "testing.py")
```

# 模拟对象

模拟是测试人员工具箱中非常有用的一部分。模拟允许自定义对象被一个对象覆盖，该对象可以用来验证方法对其参数是否执行正确的操作。有时，这可能需要重新构想和重构你的应用程序，以便以可测试的方式工作，但是概念很简单。我们创建一个模拟对象，将其运行通过方法，然后对该对象运行测试。它特别适用于数据库和 ORM 模型，比如`SQLAlchemy`。

有很多模拟框架可用，但是在本书中，我们将使用`Mockito`：

```py
pip install mockito

```

这是最简单的之一：

```py
>>> from mockito import *
>>> mock_object = mock()
>>> mock_object.example()
>>> verify(mock_object).example()
True

```

上面的代码从`Mockito`库导入函数，创建一个可以用于模拟的`mock`对象，对其运行一个方法，并验证该方法已经运行。显然，如果你希望被测试的方法在没有错误的情况下正常运行，你需要在调用模拟对象上的方法时返回一个有效的值。

```py
>>> duck = mock()
>>> when(duck).quack().thenReturn("quack")
>>> duck.quack()
"quack"

```

在上面的例子中，我们创建了一个模拟的`duck`对象，赋予它`quack`的能力，然后证明它可以`quack`。

### 注意

在 Python 这样的动态类型语言中，当你拥有的对象可能不是你期望的对象时，使用鸭子类型是一种常见的做法。正如这句话所说“如果它走起来像鸭子，叫起来像鸭子，那它一定是鸭子”。这在创建模拟对象时非常有用，因为很容易使用一个假的模拟对象而不让你的方法注意到切换。

当 Flask 使用其装饰器在你的方法运行之前运行方法，并且你需要覆盖它，例如，替换数据库初始化程序时，就会出现困难。这里可以使用的技术是让装饰器运行一个对模块全局可用的方法，比如创建一个连接到数据库的方法。

假设你的`app.py`看起来像下面这样：

```py
from flask import Flask, g

app = Flask("example")

def get_db():
  return {}

@app.before_request
def setup_db():
  g.db = get_db()

@app.route("/")
def homepage():
  return g.db.get("foo")
```

上面的代码设置了一个非常简单的应用程序，创建了一个 Python 字典对象作为一个虚假的数据库。现在要覆盖为我们自己的数据库如下：

```py
from mockito import *
import unittest
import app

class FlaskExampleTest(unittest.TestCase):
  def setUp(self):
    self.app = app.app.test_client()
    self.db = mock()
    def get_fake_db():
      return self.db
    app.get_db =  get_fake_db

  def test_before_request_override(self):
    when(self.db).get("foo").thenReturn("123")
    response = self.app.get("/")
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.data, "123")

if __name__ == "__main__":
  unittest.main()
```

上面的代码使用 Mockito 库创建一个虚假的数据库对象。它还创建了一个方法，覆盖了 app 模块中创建数据库连接的方法，这里是一个简单的字典对象。你会注意到，当使用 Mockito 时，你也可以指定方法的参数。现在当测试运行时，它会向数据库插入一个值，以便页面返回；然后进行测试。

# 记录和错误报告

记录和错误报告对于一个生产就绪的网络应用来说是内在的。即使你的应用程序崩溃，记录仍然会记录所有问题，而错误报告可以直接通知我们特定的问题，即使网站仍在运行。

在任何人报告错误之前发现错误可能是非常令人满意的。这也使得您能够在用户开始向您抱怨之前推出修复。然而，为了做到这一点，您需要知道这些错误是什么，它们是在什么时候发生的，以及是什么导致了它们。

幸运的是，现在您应该非常熟悉，Python 和 Flask 已经掌握了这一点。

## 日志记录

Flask 自带一个内置的记录器——Python 内置记录器的一个已定义实例。你现在应该对它非常熟悉了。默认情况下，每次访问页面时都会显示记录器消息。

![日志记录](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_08_04.jpg)

前面的屏幕截图显然显示了终端的输出。我们可以在这里看到有人在特定日期从`localhost`（`127.0.0.1`）访问了根页面，使用了`GET`请求，以及其他一些目录。服务器响应了一个“`200`成功”消息和两个“`404`未找到错误”消息。虽然在开发时拥有这个终端输出是有用的，但如果您的应用程序在生产环境中运行时崩溃，这并不一定很有用。我们需要从写入的文件中查看发生了什么。

### 记录到文件

有各种各样依赖于操作系统的将这样的日志写入文件的方法。然而，如前所述，Python 已经内置了这个功能，Flask 只是遵循 Python 的计划，这是非常简单的。将以下内容添加到`app.py`文件中：

```py
from logging.handlers import RotatingFileHandler
file_handler = RotatingFileHandler('blog.log')
app.logger.addHandler(file_handler)
```

需要注意的一点是，记录器使用不同的处理程序来完成其功能。我们在这里使用的处理程序是`RotatingFileHandler`。这个处理程序不仅会将文件写入磁盘（在这种情况下是`blog.log`），还会确保我们的文件不会变得太大并填满磁盘，潜在地导致网站崩溃。

### 自定义日志消息

在尝试调试难以追踪的问题时，一个非常有用的事情是我们可以向我们的博客应用程序添加更多的日志记录。这可以通过 Flask 内置的日志对象来实现，如下所示：

```py
@app.route("/")
def homepage():
  app.logger.info("Homepage has been accessed.")
```

前面的示例演示了如何创建自定义日志消息。然而，这样的消息实际上会相当大幅地减慢我们的应用程序，因为它会在每次访问主页时将该消息写入文件或控制台。幸运的是，Flask 也理解日志级别的概念，我们可以指定在不同环境中应记录哪些消息。例如，在生产环境中记录信息消息是没有用的，而用户登录失败则值得记录。

```py
app.logger.warning("'{user}' failed to login successfully.".format(user=user))
```

前面的命令只是记录了一个警告，即用户未能成功登录，使用了 Python 的字符串格式化方法。只要 Python 中的错误日志记录足够低，这条消息就会被显示。

### 级别

日志级别的原则是：日志的重要性越高，级别越高，根据您的日志级别，记录的可能性就越小。例如，要能够记录警告（以及以上级别，如`ERROR`），我们需要将日志级别调整为`WARNING`。我们可以在配置文件中进行这样的调整。编辑`config`文件夹中的`config.py`文件，添加以下内容：

```py
import logging
LOG_LEVEL=logging.WARNING
Now in your app.py add the line:
app.logger.setLevel(config['LOG_LEVEL'])
```

前面的代码片段只是使用内置的 Python 记录器告诉 Flask 如何处理日志。当然，您可以根据您的环境设置不同的日志级别。例如，在`config`文件夹中的`testing.py`文件中，我们应该使用以下内容：

```py
LOG_LEVEL=logging.ERROR
```

至于测试的目的，我们不需要警告。同样，我们应该为任何生产配置文件做同样的处理；对于任何开发配置文件，使用样式。

## 错误报告

在机器上记录错误是很好的，但如果错误直接发送到您的收件箱，您可以立即收到通知，那就更好了。幸运的是，像所有这些东西一样，Python 有一种内置的方法可以做到这一点，Flask 可以利用它。这只是另一个处理程序，比如`RotatingFileHandler`。

```py
from logging.handlers import SMTPHandler
email_handler = SMTPHandler("127.0.0.1", "admin@localhost", app.config['ADMIN_EMAILS'], "{appname} error".format(appname=app.name))
app.logger.addHandler(email_handler)
```

前面的代码创建了一个`SMTPHandler`，其中配置了邮件服务器的位置和发送地址，从配置文件中获取要发送邮件的电子邮件地址列表，并为邮件设置了主题，以便我们可以确定错误的来源。

# 阅读更多

单元测试是一个广阔而复杂的领域。Flask 在其他编写有效测试的技术方面有一些很好的文档：[`flask.pocoo.org/docs/0.10/testing/`](http://flask.pocoo.org/docs/0.10/testing/)。

当然，Python 有自己的单元测试文档：[`docs.python.org/2/library/unittest.html`](https://docs.python.org/2/library/unittest.html)。

Flask 使用 Python 的日志模块进行日志记录。这又遵循了 C 库结构的日志记录级别。更多细节可以在这里找到：[`docs.python.org/2/library/logging.html`](https://docs.python.org/2/library/logging.html)。

# 总结

在本章中，我们已经学会了如何为我们的博客应用创建一些测试，以验证它是否正确加载页面，以及登录是否正确进行。我们还设置了将日志记录到文件，并在发生错误时发送电子邮件。

在下一章中，我们将学习如何通过扩展来改进我们的博客，这些扩展可以在我们的部分付出最小的努力的情况下添加额外的功能。


# 第九章：优秀的扩展

在本章中，我们将学习如何通过一些流行的第三方扩展增强我们的 Flask 安装。扩展允许我们以非常少的工作量添加额外的安全性或功能，并可以很好地完善您的博客应用程序。我们将研究**跨站点请求伪造**（**CSRF**）保护您的表单，Atom 订阅源以便其他人可以找到您的博客更新，为您使用的代码添加语法高亮，减少渲染模板时的负载的缓存，以及异步任务，以便您的应用程序在进行密集操作时不会变得无响应。

在本章中，我们将学习以下内容：

+   使用 Flask-SeaSurf 进行 CSRF 保护

+   使用 werkzeug.contrib 生成 Atom 订阅源

+   使用 Pygments 进行语法高亮

+   使用 Flask-Cache 和 Redis 进行缓存

+   使用 Celery 进行异步任务执行

# SeaSurf 和表单的 CSRF 保护

CSRF 保护通过证明 POST 提交来自您的站点，而不是来自另一个站点上精心制作的恶意利用您博客上的 POST 端点的网络表单，为您的站点增加了安全性。这些恶意请求甚至可以绕过身份验证，如果您的浏览器仍然认为您已登录。

我们避免这种情况的方法是为站点上的任何表单添加一个特殊的隐藏字段，其中包含由服务器生成的值。当提交表单时，可以检查特殊字段中的值是否与服务器生成的值匹配，如果匹配，我们可以继续提交表单。如果值不匹配或不存在，则表单来自无效来源。

### 注意

CSRF 保护实际上证明了包含 CSRF 字段的模板用于生成表单。这可以减轻来自其他站点的最基本的 CSRF 攻击，但不能确定表单提交只来自我们的服务器。例如，脚本仍然可以屏幕抓取页面的内容。

现在，自己构建 CSRF 保护并不难，而且通常用于生成我们的表单的 WTForms 已经内置了这个功能。但是，让我们来看看 SeaSurf：

```py
pip install flask-seasurf

```

安装 SeaSurf 并使用 WTForms 后，将其集成到我们的应用程序中现在变得非常容易。打开您的`app.py`文件并添加以下内容：

```py
from flask.ext.seasurf import SeaSurf
csrf = SeaSurf(app)
```

这只是为您的应用程序启用了 SeaSurf。现在，要在您的表单中启用 CSRF，请打开`forms.py`并创建以下 Mixin：

```py
from flask.ext.wtf import HiddenField
import g

from app import app

class CSRFMixin(object):
  @staticmethod
  @app.before_request
  def add_csrf():
    self._csrf_token = HiddenField(default=g._csrf_token)
```

上述代码创建了一个简单的 CSRF Mixin，可以选择在所有表单中使用。装饰器确保在请求之前运行该方法，以便向您的表单添加具有随机生成的 CSRF 令牌值的`HiddenField`字段。要在您的表单中使用此 Mixin，在这种情况下是您的登录表单，更新类如下：

```py
class LoginForm(Form, CSRFMixin):
```

就是这样。我们需要对所有要保护的表单进行这些更改，通常是所有表单。

# 创建 Atom 订阅源

任何博客都非常有用的一个功能是让读者能够及时了解最新内容。这通常是通过 RSS 阅读器客户端来实现的，它会轮询您的 RSS 订阅源。虽然 RSS 被广泛使用，但更好、更成熟的订阅格式是可用的，称为 Atom。

这两个文件都可以由客户端请求，并且是标准和简单的 XML 数据结构。幸运的是，Flask 内置了 Atom 订阅源生成器；或者更具体地说，Flask 使用的 WSGI 接口中内置了一个贡献的模块，称为 Werkzeug。

让它运行起来很简单，我们只需要从数据库中获取最近发布的帖子。最好为此创建一个新的 Blueprint；但是，您也可以在`main.py`中完成。我们只需要利用一些额外的模块：

```py
from urlparse import urljoin
from flask import request, url_for
from werkzeug.contrib.atom import AtomFeed
from models import Entry
```

并创建一个新的路由：

```py
@app.route('/latest.atom')
def recent_feed():
    feed = AtomFeed(
        'Latest Blog Posts',
        feed_url=request.url,
         url=request.url_root,
         author=request.url_root
     )
    entries = EntrY.query.filter(Entry.status == Entry.STATUS_PUBLIC).order_by(EntrY.created_timestamp.desc()).limit(15).all()
    for entry in entries:
        feed.add(
            entry.title,
            entry.body,
            content_type='html',
            url=urljoin(request.url_root, url_for("entries.detail", slug=entry.slug) ),
            updated=entry.modified_timestamp,
            published=entry.created_timestamp
        )
    return feed.get_response()
```

现在运行您的 Flask 应用程序，Atom 订阅源将可以从`http://127.0.0.1:5000/latest.atom`访问

# 使用 Pygments 进行语法高亮

通常，作为编码人员，我们希望能够在网页上显示代码，虽然不使用语法高亮显示阅读代码是一种技能，但一些颜色可以使阅读体验更加愉快。

与 Python 一样，已经有一个模块可以为您完成这项工作，当然，您可以通过以下命令轻松安装它：

```py
pip install Pygments

```

### 注意

Pygments 仅适用于已知的代码部分。因此，如果您想显示代码片段，我们可以这样做。但是，如果您想突出显示代码的内联部分，我们要么遵循 Markdown 的下一节，要么需要使用一些在线 Javascript，例如`highlight.js`。

要创建代码片段，我们需要首先创建一个新的蓝图。让我们创建一个名为`snippets`的目录，然后创建一个`__init__.py`文件，接着创建一个名为`blueprint.py`的文件，其中包含以下代码：

```py
from flask import Blueprint, request, render_template, redirect, url_for
from helpers import object_list
from app import db, app

from models import Snippet
from forms import SnippetForm

from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter

snippets = Blueprint('snippets', __name__, template_folder='templates')

@app.template_filter('pygments')
def pygments_filter(code):
    return highlight(code, PythonLexer(), HtmlFormatter())

@snippets.route('/')
def index():
    snippets = Snippet.query.order_by(Snippet.created_timestamp.desc())
    return object_list('entries/index.html', snippets)

@snippets.route('/<slug>/')
def detail(slug):
    snippet = Snippet.query.filter(Snippet .slug == slug).first_or_404()
    return render_template('snippets/detail.html', entry=snippet)

@snippets.route('/create/', methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        form = SnippetForm(request.form)
        if form.validate():
            snippet = form.save_entry(Snippet())
            db.session.add(snippet)
            db.session.commit()
            return redirect(url_for('snippets.detail', slug=snippet.slug))
    else:
        form = SnippetForm()

    return render_template('snippets/create.html', form=form)

@snippets.route('/<slug>/edit/', methods=['GET', 'POST'])
def edit(slug):
    snippet = Snippet.query.filter(Snippet.slug == slug).first_or_404()
    if request.method == 'POST':
        form = SnippetForm(request.form, obj=snippet)
        if form.validate():
            snippet = form.save_entry(snippet)
            db.session.add(snippet)
            db.session.commit()
            return redirect(url_for('snippets.detail', slug=entry.slug))
    else:
        form = EntryForm(obj=entry)

    return render_template('entries/edit.html', entry=snippet, form=form)
```

在前面的示例中，我们设置了 Pygments 模板过滤器，允许将一串代码转换为 HTML 代码。我们还巧妙地利用了完全适合我们需求的条目模板。我们使用我们自己的`detail.html`，因为那里是 Pygments 发生魔法的地方。我们需要在 snippets 目录中创建一个 templates 目录，然后在 templates 中创建一个名为 snippets 的目录，这是我们存储 detail.html 的地方。因此，现在我们的目录结构看起来像 app/snippets/templates/snipperts/detail.html 现在让我们设置该文件，如下所示：

```py
{% extends "base.html" %}

{% block title %}{{ entry.title }} - Snippets{% endblock %}

{% block content_title %}Snippet{% endblock %}

{% block content %}
    {{ entry.body | pygments | safe}}
{% endblock %}
```

这基本上与我们在书中早期使用的`detail.html`相同，只是现在我们通过我们在应用程序中创建的 Pygments 过滤器传递它。由于我们早期使用的模板过滤器生成原始 HTML，我们还需要将其输出标记为安全。

我们还需要更新博客的 CSS 文件，因为 Pygments 使用 CSS 选择器来突出显示单词，而不是在页面上浪费地编写输出。它还允许我们根据需要修改颜色。要找出我们的 CSS 应该是什么样子，打开 Python shell 并运行以下命令：

```py
>>> from pygments.formatters import HtmlFormatter
>>> print HtmlFormatter().get_style_defs('.highlight')

```

前面的命令现在将打印出 Pygments 建议的示例 CSS，我们可以将其复制粘贴到`static`目录中的`.css`文件中。

这段代码的其余部分与之前的 Entry 对象没有太大不同。它只是允许您创建、更新和查看代码片段。您会注意到我们在这里使用了一个`SnippetForm`，我们稍后会定义。

还要创建一个`models.py`，其中包含以下内容：

```py
class Snippet(db.Model):
    STATUS_PUBLIC = 0
    STATUS_DRAFT = 1

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    slug = db.Column(db.String(100), unique=True)
    body = db.Column(db.Text)
    status = db.Column(db.SmallInteger, default=STATUS_PUBLIC)
    created_timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    modified_timestamp = db.Column(
        db.DateTime,
        default=datetime.datetime.now,
        onupdate=datetime.datetime.now)

    def __init__(self, *args, **kwargs):
        super(Snippet, self).__init__(*args, **kwargs)  # Call parent constructor.
        self.generate_slug()

    def generate_slug(self):
        self.slug = ''
        if self.title:
            self.slug = slugify(self.title)

    def __repr__(self):
        return '<Snippet: %s>' % self.title
```

现在我们必须重新运行`create_db.py`脚本以创建新表。

我们还需要创建一个新的表单，以便可以创建代码片段。在`forms.py`中添加以下代码：

```py
from models import Snippet

class SnippetForm(wtforms.Form):
    title = wtforms.StringField('Title', validators=[DataRequired()])
    body = wtforms.TextAreaField('Body', validators=[DataRequired()])
    status = wtforms.SelectField(
        'Entry status',
        choices=(
            (Snippet.STATUS_PUBLIC, 'Public'),
            (Snippet.STATUS_DRAFT, 'Draft')),
        coerce=int)

    def save_entry(self, entry):
        self.populate_obj(entry)
        entry.generate_slug()
        return entry
```

最后，我们需要确保通过编辑`main.py`文件使用此蓝图并添加以下内容：

```py
from snippets.blueprint import snippets
app.register_blueprint(snippets, url_prefix='/snippets')
```

一旦我们在这里添加了一些代码，使用`Snippet`模型，生成的代码将如下图所示呈现：

![使用 Pygments 进行语法高亮](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_09_01.jpg)

# 使用 Markdown 进行简单编辑

Markdown 是一种现在广泛使用的网络标记语言。它允许您以特殊格式编写纯文本，可以通过程序转换为 HTML。在从移动设备编辑文本时，这可能特别有用，例如，突出显示文本使其加粗比在 PC 上更加困难。您可以在[`daringfireball.net/projects/markdown/`](http://daringfireball.net/projects/markdown/)上查看如何使用 Markdown 语法。

### 注意

Markdown 的一个有趣之处在于，您仍然可以同时使用 HTML 和 Markdown。

当然，在 Python 中快速简单地运行这个是很容易的。我们按照以下步骤安装它：

```py
sudo pip install Flask-Markdown

```

然后我们可以将其应用到我们的蓝图或应用程序中，如下所示：

```py
from flaskext.markdown import Markdown
Markdown(app)
```

这将在我们的模板中创建一个名为`markdown`的新过滤器，并且在渲染模板时可以使用它：

```py
{{ entry.body | markdown }}
```

现在，您只需要在 Markdown 中编写并保存您的博客条目内容。

如前所述，您可能还希望美化代码块；Markdown 内置了这个功能，因此我们需要扩展先前的示例如下：

```py
from flaskext.markdown import Markdown
Markdown(app, extensions=['codehilite'])
```

现在可以使用 Pygments 来渲染 Markdown 代码块。但是，由于 Pygments 使用 CSS 为代码添加颜色，我们需要从 Pygments 生成我们的 CSS。但是，这次使用的父块具有一个名为`codehilite`的类（之前称为 highlight），因此我们需要进行调整。在 Python shell 中，键入以下内容：

```py
>>> from pygments.formatters import HtmlFormatter
>>> print HtmlFormatter().get_style_defs('.codehilite')

```

现在将输出添加到`static`目录中的`.css`文件中。因此，使用包含的 CSS，您的 Markdown 条目现在可能如下所示：

![使用 Markdown 进行简单编辑](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/lrn-flask-fw/img/1709_09_02.jpg)

还有许多其他内置的 Markdown 扩展可以使用；您可以查看它们，只需在初始化 Markdown 对象时使用它们的名称作为字符串。

# 使用 Flask-Cache 和 Redis 进行缓存

有时（我知道很难想象），我们会为我们的网站付出很多努力，添加功能，这通常意味着我们最终不得不为一个简单的静态博客条目执行大量数据库调用或复杂的模板渲染。现在数据库调用不应该很慢，大量模板渲染也不应该引人注目，但是，如果将其扩展到大量用户（希望您是在预期的），这可能会成为一个问题。

因此，如果网站大部分是静态的，为什么不将响应存储在单个高速内存数据存储中呢？无需进行昂贵的数据库调用或复杂的模板渲染；对于相同的输入或路径，获取相同的内容，而且更快。

正如现在已经成为一种口头禅，我们已经可以在 Python 中做到这一点，而且就像以下这样简单：

```py
sudo pip install Flask-Cache

```

要使其运行，请将其添加到您的应用程序或蓝图中：

```py
from flask.ext.cache import Cache

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'redis'})
```

当然，您还需要安装 Redis，这在 Debian 和 Ubuntu 系统上非常简单：

```py
sudo apt-get install redis-server

```

不幸的是，Redis 尚未在 Red Hat 和 CentOS 的打包系统中提供。但是，您可以从他们的网站上下载并编译 Redis

[`redis.io/download`](http://redis.io/download)

默认情况下，Redis 是不安全的；只要我们不将其暴露给我们的网络，这应该没问题，而且对于 Flask-Cache，我们不需要进行任何其他配置。但是，如果您希望对其进行锁定，请查看 Redis 的 Flask-Cache 配置。

现在我们可以在视图中使用缓存（以及任何方法）。这就像在路由上使用装饰器一样简单。因此，打开一个视图并添加以下内容：

```py
@app.route("/")
@cache.cached(timeout=600) # 10 minutes
def homepage():
…
```

您将在这里看到，缓存的装饰器在路由内部，并且我们有一个 10 分钟的超时值，以秒为单位。这意味着，无论您的主页的渲染有多繁重，或者它可能进行多少数据库调用，响应都将在该时间段内直接从内存中获取。

显然，缓存有其时间和地点，并且可能是一门艺术。如果每个用户都有一个自定义的主页，那么缓存将是无用的。但是，我们可以缓存模板的部分内容，因此诸如`<head>`中的所有`<link>`元素这样的常见区域很少会更改，但是`url_for('static', ...)`过滤器不必每次重新生成。例如，看下面的代码：

```py
{% cache 1800 %}
<link rel="stylesheet" href="{{ url_for('static', filename='css/blog.min.css') }}">
{% endcache %}
```

前面的代码部分表示链接元素应该缓存 30 分钟，以秒为单位。您可能还希望对脚本的引用进行相同的操作。我们也可以用它来加载最新博客文章的列表，例如。

# 通过创建安全、稳定的站点版本来创建静态内容

对于低动态内容的高流量网站的一种技术是创建一个简单的静态副本。这对博客非常有效，因为内容通常是静态的，并且每天最多更新几次。但是，您仍然需要为实际上没有变化的内容执行大量数据库调用和模板渲染。

当然，有一个 Flask 扩展程序可以解决这个问题：Frozen-Flask。Frozen-Flask 识别 Flask 应用程序中的 URL，并生成应该在那里的内容。

因此，对于生成的页面，它会生成 HTML，对于 JavaScript 和图像等静态内容，它会将它们提取到一个基本目录中，这是您网站的静态副本，并且可以由您的 Web 服务器作为静态内容提供。

这样做的另一个好处是，网站的*活动*版本更加安全，因为无法使用 Flask 应用程序或 Web 服务器更改它。

当然，这也有一些缺点。如果您的网站上有动态内容，例如评论，就不再可能以常规方式存储和呈现它们。此外，如果您的网站上有多个作者，您需要一种共享数据库内容的方式，以便它们不会生成网站的单独副本。解决方案将在本节末尾提出。但首先，让我们按照以下方式安装 Frozen-Flask：

```py
pip install Frozen-Flask

```

接下来，我们需要创建一个名为`freeze.py`的文件。这是一个简单的脚本，可以自动设置 Frozen-Flask：

```py
from flask_frozen import Freezer
from main import app

freezer = Freezer(app)

if __name__ == '__main__':
    freezer.freeze()
```

以上代码使用了 Frozen-Flask 的所有默认设置，并在以下方式运行：

```py
python freeze.py

```

将创建（或覆盖）包含博客静态副本的`build`目录。

Frozen-Flask 非常智能，将自动查找所有链接，只要它们是从根主页按层次引用的；对于博客文章，这样做效果很好。但是，如果条目从主页中删除，并且它们通过另一个 URL 上的存档页面访问，您可能需要向 Frozen-Flask 提供指针以找到它们的位置。例如，将以下内容添加到`freeze.py 文件`中：

```py
import models

@freezer.register_generator
def archive():
    for post in models.Entry.all():
        yield {'detail': product.id}
```

Frozen-Flask 很聪明，并使用 Flask 提供的`url_for`方法来创建静态文件。这意味着`url_for 方法`可用的任何内容都可以被 Frozen-Flask 使用，如果无法通过正常路由找到。

## 在静态站点上发表评论

因此，您可能已经猜到，通过创建静态站点，您会失去一些博客基本原理——这是鼓励交流和辩论的一个领域。幸运的是，有一个简单的解决方案。

博客评论托管服务，如 Disqus 和 Discourse，工作方式类似于论坛，唯一的区别是每个博客帖子都创建了一个主题。您可以免费使用它们的服务来进行讨论，或者使用 Discourse 在自己的平台上免费运行他们的服务器，因为它是完全开源的。

## 同步多个编辑器

Frozen-Flask 的另一个问题是，对于分布在网络上的多个作者，您如何管理存储帖子的数据库？每个人都需要相同的最新数据库副本；否则，当您生成站点的静态副本时，它将无法创建所有内容。

如果您都在同一个环境中工作，一个解决方案是在网络内的服务器上运行博客的工作副本，并且在发布时，它将使用集中式数据库来创建博客的已发布版本。

然而，如果您都在不同的地方工作，集中式数据库不是理想的解决方案或无法保护，另一个解决方案是使用基于文件系统的数据库引擎，如 SQLite。然后，当对数据库进行更新时，可以通过电子邮件、Dropbox、Skype 等方式将该文件传播给其他人。然后，他们可以从本地运行 Frozen-Flask 创建可发布内容的最新副本。

# 使用 Celery 进行异步任务

Celery 是一个允许您在 Python 中运行异步任务的库。这在 Python 中特别有帮助，因为 Python 是单线程运行的，您可能会发现自己有一个长时间运行的任务，您希望要么启动并丢弃；要么您可能希望向您网站的用户提供有关所述任务进度的反馈。

一个这样的例子是电子邮件。用户可能会请求发送电子邮件，例如重置密码请求，您不希望他们在生成和发送电子邮件时等待页面加载。我们可以将其设置为启动和丢弃操作，并让用户知道该请求正在处理中。

Celery 能够摆脱 Python 的单线程环境的方式是，我们必须单独运行一个 Celery 代理实例；这会创建 Celery 所谓的执行实际工作的工作进程。然后，您的 Flask 应用程序和工作进程通过消息代理进行通信。

显然，我们需要安装 Celery，我相信您现在可以猜到您需要的命令是以下命令：

```py
pip install celery

```

现在我们需要一个消息代理服务器。有很多选择；查看 Celery 的网站以获取支持的选择，但是，由于我们已经在 Flask-Cache 设置中设置了 Redis，让我们使用它。

现在我们需要告诉 Celery 如何使用 Redis 服务器。打开 Flask 应用程序配置文件并添加以下行：

```py
CELERY_BROKER_URL = 'redis://localhost:6379/0'
```

此配置告诉您的 Celery 实例在哪里找到它需要与 Celery 代理通信的消息代理。现在我们需要在我们的应用程序中初始化 Celery 实例。在`main.py 文件`中添加以下内容：

```py
from celery import Celery

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
```

这将使用来自 Flask 配置文件的配置创建一个`Celery`实例，因此我们还可以从 Celery 代理访问`celery`对象并共享相同的设置。

现在我们需要为 Celery 工作进程做一些事情。在这一点上，我们将利用 Flask-Mail 库：

```py
pip install Flask-Mail

```

我们还需要一些配置才能运行。将以下参数添加到您的 Flask 配置文件中：

```py
MAIL_SERVER = "example.com"
MAIL_PORT = 25
MAIL_USERNAME = "email_username"
MAIL_PASSWORD = "email_password"
```

此配置告诉 Flask-Mail 您的电子邮件服务器在哪里。很可能默认设置对您来说已经足够好，或者您可能需要更多选项。查看 Flask-Mail 配置以获取更多选项。

现在让我们创建一个名为`tasks.py`的新文件，并创建一些要运行的任务，如下所示：

```py
from flask_mail import Mail, Message
from main import app, celery

mail = Mail(app)

@celery.task
def send_password_verification(email, verification_code):
  msg = Message(
    "Your password reset verification code is: {0}".format(verification_code),
                  sender="from@example.com",
                  recipients=[email]
  )
  mail.send(msg)
```

这是一个非常简单的消息生成；我们只是生成一封电子邮件，内容是新密码是什么，电子邮件来自哪里（我们的邮件服务器），电子邮件发送给谁，以及假设是用户账户的电子邮件地址，然后发送；然后通过已设置的邮件实例发送消息。

现在我们需要让我们的 Flask 应用程序利用新的异步能力。让我们创建一个视图，监听被 POST 到它的电子邮件地址。这可以在与帐户或主应用程序有关的任何蓝图中进行。

```py
import tasks

@app.route("/reset-password", methods=['POST'])
def reset_password():
  user_email = request.form.get('email')
  user = db.User.query.filter(email=user_email).first()
  if user:
    new_password = db.User.make_password("imawally")
    user.update({"password_hash": new_password})
    user.commit()
    tasks.send_password_verification.delay(user.email, new_password)
    flash("Verification e-mail sent")
  else:
    flash("User not found.")
  redirect(url_for('homepage'))
```

前面的视图接受来自浏览器的 POST 消息，其中包含声称忘记密码的用户的电子邮件。我们首先通过他们的电子邮件地址查找用户，以查看用户是否确实存在于我们的数据库中。显然，在不存在的帐户上重置密码是没有意义的。当然，如果他们不存在，用户将收到相应的消息。

但是，如果用户帐户确实存在，首先要做的是为他们生成一个新密码。我们在这里使用了一个硬编码的示例密码。然后更新数据库中的密码，以便用户在收到电子邮件时可以使用它进行登录。一切都搞定后，我们就可以在之前创建的`任务`上运行.delay，并使用我们想要使用的参数。这会指示 Celery 在准备好时运行底层方法。

### 注意

请注意，这不是进行密码重置的最佳解决方案。这只是为了说明您可能希望以简洁的方式执行此操作。密码重置是一个令人惊讶地复杂的领域，有很多事情可以做来提高此功能的安全性和隐私性，例如检查 CSRF 值，限制调用方法的次数，并使用随机生成的 URL 供用户重置密码，而不是通过电子邮件发送的硬编码解决方案。

最后，当我们运行 Flask 应用程序时，我们需要运行 Celery 代理；否则，几乎不会发生任何事情。不要忘记，这个代理是启动所有异步工作者的进程。我们可以做的最简单的事情就是从 Flask 应用程序目录中运行以下命令：

```py
celeryd -A main worker

```

这很简单地启动了 Celery 代理，并告诉它查找`main`应用程序中的 celery 配置，以便它可以找到配置和应该运行的任务。

现在我们可以启动我们的 Flask 应用程序并发送一些电子邮件。

# 使用 Flask-script 创建命令行指令

使用 Flask 非常有用的一件事是创建一个命令行界面，这样当其他人使用您的软件时，他们可以轻松地使用您提供的方法，比如设置数据库、创建管理用户或更新 CSRF 密钥。

我们已经有一个类似的脚本，并且可以在这种方式中使用的脚本是第二章中的`create_db.py`脚本，*使用 SQLAlchemy 的关系数据库*。为此，再次有一个 Flask 扩展。只需运行以下命令：

```py
pip install Flask-Script

```

现在，Flask-Script 的有趣之处在于，命令的工作方式与 Flask 中的路由和视图非常相似。让我们看一个例子：

```py
from flask.ext.script import Manager
from main import app

manager = Manager(app)
@manager.command
def hello():
    print "Hello World"

if __name__ == "__main__":
    manager.run()
```

您可以在这里看到，Flask-Script 将自己称为 Manager，但管理器也将自己挂钩到 Flask 应用程序中。这意味着您可以通过使用`app`引用来对 Flask 应用程序执行任何操作。

因此，如果我们将`create_db.py`应用程序转换为 Flask-Script 应用程序，我们应该创建一个文件来完成这项工作。让我们称之为`manage.py`，并从文件`create_db.py`中插入：

```py
from main import db

@manager.command
def create_db():
    db.create_all()
```

所有这些只是设置一个装饰器，以便`manage.py`带有参数`create_db`将运行`create_db.py`中的方法。

现在我们可以从以下命令行运行：

```py
python manage.py create_db

```

# 参考

+   [`highlightjs.org/`](https://highlightjs.org/)

+   [`pythonhosted.org/Flask-Markdown/`](http://pythonhosted.org/Flask-Markdown/)

+   [`daringfireball.net/projects/markdown/`](http://daringfireball.net/projects/markdown/)

+   [`pythonhosted.org/Markdown/extensions`](http://pythonhosted.org/Markdown/extensions)

+   [`pythonhosted.org/Frozen-Flask/`](https://pythonhosted.org/Frozen-Flask/)

+   [`disqus.com/`](https://disqus.com/)

+   [`www.discourse.org`](http://www.discourse.org)

+   [`eviltrout.com/2014/01/22/embedding-discourse.html`](http://eviltrout.com/2014/01/22/embedding-discourse.html)

+   [`flask-script.readthedocs.org/en/latest/`](http://flask-script.readthedocs.org/en/latest/)

+   [`pythonhosted.org/Flask-Mail/`](https://pythonhosted.org/Flask-Mail/)

# 总结

在本章中，我们做了各种各样的事情。您已经看到如何创建自己的 Markdown 渲染器，以便编辑更容易，并将命令移动到 Flask 中，使其更易管理。我们创建了 Atom feeds，这样我们的读者可以在发布新内容时找到它，并创建了异步任务，这样我们就不会在等待页面加载时锁定用户的浏览器。

在我们的最后一章中，我们将学习如何将我们的简单应用程序转变为一个完全部署的博客，具有所有讨论的功能，已经得到保护，并且可以使用。


# 第十章：部署您的应用程序

在本章中，我们将学习如何以安全和自动化的可重复方式部署我们的 Flask 应用程序。我们将看到如何配置常用的**WSGI**（**Web 服务器网关接口**）能力服务器，如 Apache、Nginx，以及 Python Web 服务器 Gunicorn。然后，我们将看到如何使用 SSL 保护部分或整个站点，最后将我们的应用程序包装在配置管理工具中，以自动化我们的部署。

在本章中，我们将学习以下主题：

+   配置常用的 WSGI 服务器

+   高效地提供静态文件

+   使用 SSL 保护您的网站

+   使用 Ansible 自动化部署

# 使用 WSGI 服务器运行 Flask

重要的是要注意，Flask 本身并不是一个 Web 服务器。Web 服务器是面向互联网的工具，经过多年的开发和修补，并且可以同时运行多个服务。

在互联网上仅运行 Flask 作为 Web 服务器可能会很好，这要归功于 Werkzeug WSGI 层。然而，Flask 在页面路由和渲染系统上的真正重点是开发。作为 Web 服务器运行 Flask 可能会产生意想不到的影响。理想情况下，Flask 将位于 Web 服务器后面，并在服务器识别到对您的应用程序的请求时被调用。为此，Web 服务器和 Flask 需要能够使用相同的语言进行通信。

幸运的是，Flask 构建在 Werkzeug 堆栈之上，该堆栈旨在使用 WSGI 协议。WSGI 是一个常见的协议，被诸如 Apache 的 httpd 和 Nginx 之类的 Web 服务器使用。它可以用来管理 Flask 应用程序的负载，并以 Python 可以理解的方式传达关于请求来源和请求头的重要信息。

然而，要让 Werkzeug 使用 WSGI 协议与您的 Web 服务器通信，我们必须使用一个网关。这将接收来自您的 Web 服务器和 Python 应用程序的请求，并在它们之间进行转换。大多数 Web 服务器都会使用 WSGI，尽管有些需要一个模块，有些需要一个单独的网关，如 uWSGI。

首先要做的一件事是为 WSGI 网关创建一个 WSGI 文件以进行通信。这只是一个具有已知结构的 Python 文件，以便 WSGI 网关可以访问它。我们需要在与您的博客应用程序的其余部分相同的目录中创建一个名为`wsgi.py`的文件，它将包含：

```py
from app import app as application
```

Flask 默认是与 WSGI 兼容的，因此我们只需要以正确的方式声明对象，以便 WSGI 网关理解。现在，Web 服务器需要配置以找到此文件。

## Apache 的 httpd

Apache 的 httpd 目前可能是互联网上使用最广泛的 Web 服务器。该程序的名称实际上是 httpd，并由 Apache 软件基金会维护。然而，大多数人都将其称为*Apache*，因此我们也将称其为*Apache*。

要确保在基于 Debian 和 Ubuntu 的系统上安装了 Apache 和 WSGI 模块，请运行以下命令：

```py
sudo apt-get install apache2 libapache2-mod-wsgi

```

但是，在基于 Red Hat 和 Fedora 的系统上运行以下命令：

```py
sudo yum install httpd mod_wsgi

```

要设置 Apache 配置，我们必须创建一个指定新 VirtualHost 的配置文件。您必须找到系统上存放这些文件的目录。在基于 Debian 的系统（如 Ubuntu）中，这将在`/etc/apache2/sites-available`中；在基于 Red Hat/Fedora 的系统中，我们需要在`/etc/apache2/conf.d`目录中创建一个名为`blog.conf`的文件。

在该配置文件中，使用以下代码更新内容：

```py
<VirtualHost *:80>

    WSGIScriptAlias / <path to app>/wsgi.py

    <Directory <path to app>/>
        Order deny,allow
        Allow from all
    </Directory>

</VirtualHost>
```

此配置指示 Apache，对于对端口`80`上主机的每个请求，都要尝试从`wsgi.py`脚本加载。目录部分告诉 Apache 如何处理对该目录的请求，并且默认情况下，最好拒绝任何访问 Web 服务器的人对源目录中的文件的访问。请注意，在这种情况下，`<path to app>`是存储`wsgi.py`文件的目录的完整绝对路径。

现在我们需要为 Apache 的 httpd 服务器启用 WSGI 模块。这样 Apache 就知道在指定 WSGI 配置时要使用它。在基于 Debian 和 Ubuntu 的系统中，我们只需运行此命令：

```py
sudo a2enmod wsgi

```

然而，在 Red Hat 和 CentOS 系统上，情况会复杂一些。我们需要创建或修改文件`/etc/httpd/conf.d/wsgi.conf`，并包含以下行：

```py
LoadModule wsgi_module modules/mod_wsgi.so
```

现在我们需要通过运行以下命令在基于 Debian 和 Ubuntu 的系统上启用我们的新站点：

```py
sudo a2ensite blog

```

这指示 Apache 在`/etc/apache2/sites-available`和`/etc/apache2/sites-enabled`之间创建符号链接，Apache 实际上从中获取其配置。现在我们需要重新启动 Apache。在您的特定环境或分发中，可以以许多方式执行此操作。最简单的方法可能只是运行以下命令：

```py
sudo service apache2 restart

```

所以我们需要做的就是通过浏览器连接到 Web 服务器，访问`http://localhost/`。

在 Debian 和 Ubuntu 系统的`/var/log/apache2/error.log`和基于 Red Hat 和 CentOS 的系统的`/var/log/httpd/error_log`中检查是否有任何问题。

请注意，一些 Linux 发行版默认配置必须禁用。这可能可以通过在 Debian 和 Ubuntu 系统中输入以下命令来禁用：

```py
sudo a2dissite default

```

然而，在基于 Red Hat 和 CentOS 的系统中，我们需要删除`/etc/httpd/conf.d/welcome.conf`文件：

```py
sudo rm /etc/httpd/conf.d/welcome.conf

```

当然，我们需要再次重启 Debian 和 Ubuntu 系统的服务器：

```py
sudo service apache2 restart

```

在基于 Red Hat 和 CentOS 的系统中：

```py
sudo service httpd restart

```

Apache 还有一个重新加载选项，而不是重新启动。这告诉服务器再次查看配置文件并与其一起工作。这通常比重新启动更快，并且可以保持现有连接打开。而重新启动会退出服务器并重新启动，带走打开的连接。重新启动的好处是更明确，对于设置目的更一致。

### 提供静态文件

在使用 Flask 时，通过 Web 服务器，非常重要的一步是通过为站点的静态内容创建一个快捷方式来减少应用程序的负载。这将把相对琐碎的任务交给 Web 服务器，使得处理过程更快速、更响应。这也是一件简单的事情。

编辑您的`blog.conf`文件，在`<VirtualHost *:80>`标签内添加以下行：

```py
Alias /static <path to app>/static
```

在这里，`<path to app>`是静态目录存在的完整绝对路径。然后按照以下步骤重新加载 Debian 和 Ubuntu 系统的 Apache 配置：

```py
sudo service apache2 restart

```

对于基于 Red Hat 和 CentOS 的系统如下：

```py
sudo service httpd restart

```

这将告诉 Apache 在浏览器请求`/static`时在何处查找文件。您可以通过查看 Apache 日志文件来看到这一点，在 Debian 和 Ubuntu 系统中为`/var/log/apache2/access.log`，在基于 Red Hat 和 CentOS 的系统中为`/var/log/httpd/access.log`。

## Nginx

Nginx 正迅速成为取代 Apache 的 httpd 的事实标准 Web 服务器。它被证明更快，更轻量级，尽管配置有所不同，但更容易理解。

尽管 Nginx 已经支持 WSGI 有一段时间了，但即使是更新的 Linux 发行版也可能没有更新到它，因此我们必须使用一个称为 **uWSGI** 的接口层来访问 Python web 应用程序。uWSGI 是一个用 Python 编写的 WSGI 网关，可以通过套接字在 WSGI 和您的 Web 服务器之间进行翻译。我们需要安装 Nginx 和 uWSGI。在基于 Debian 和 Ubuntu 的系统中运行以下命令：

```py
sudo apt-get install nginx

```

在基于 Red Hat 或 Fedora 的系统中，以下

```py
sudo yum install nginx

```

现在由于 uWSGI 是一个 Python 模块，我们可以使用 `pip` 安装它：

```py
sudo pip install uwsgi

```

要在基于 Debian 和 Ubuntu 的系统中配置 Nginx，需要在 `/etc/nginx/sites-available` 中创建一个名为 `blog.conf` 的文件，或者在基于 Red Hat 或 Fedora 的系统中，在 `/etc/nginx/conf.d` 中创建文件，并添加以下内容：

```py
server {
    listen      80;
    server_name _;

    location / { try_files $uri @blogapp; }
    location @blogapp {
        include uwsgi_params;
        uwsgi_pass unix:/var/run/blog.wsgi.sock;
    }
}
```

这个配置与 Apache 配置非常相似，尽管是以 Nginx 形式表达的。它在端口 `80` 上接受连接，并且对于任何服务器名称，它都会尝试访问 `blog.wsgi.sock`，这是一个用于与 uWSGI 通信的 Unix 套接字文件。您会注意到 `@blogapp` 被用作指向位置的快捷方式引用。

只有在基于 Debian 和 Ubuntu 的系统中，我们现在需要通过从可用站点创建符号链接到已启用站点来启用新站点：

```py
sudo ln -s /etc/nginx/sites-available/blog.conf /etc/nginx/sites-enabled

```

然后我们需要告诉 uWSGI 在哪里找到套接字文件，以便它可以与 Nginx 通信。为此，我们需要在 `blog app` 目录中创建一个名为 `uwsgi.ini` 的 uWSGI 配置文件，其中包含以下内容：

```py
[uwsgi]
base = <path to app>
app = app
module = app
socket = /var/run/blog.wsgi.sock

```

您将需要将 `<path to app>` 更改为您的 `app.py` 文件存在的路径。还要注意套接字是如何设置在与 Nginx 站点配置文件中指定的相同路径中的。

### 注意

您可能会注意到 INI 文件的格式和结构非常类似于 Windows 的 INI 文件。

我们可以通过运行以下命令来验证此配置是否有效：

```py
uwsgi –ini uwsgi.ini

```

现在 Nginx 知道如何与网关通信，但还没有使用站点配置文件；我们需要重新启动它。在您特定的环境中可以通过多种方式执行此操作。最简单的方法可能就是运行以下命令：

```py
sudo service nginx restart

```

所以我们需要做的就是通过浏览器连接到 Web 服务器，访问 `http://localhost/`。

请注意，一些 Linux 发行版附带了必须禁用的默认配置。在基于 Debian 和 Ubuntu 的系统以及基于 Red Hat 和 CentOS 的系统中，通常可以通过删除 `/etc/nginx/conf.d/default.conf` 文件来完成此操作。

```py
sudo rm /etc/nginx/conf.d/default.conf

```

并重新启动 `nginx` 服务：

```py
sudo service nginx restart

```

### 注意

Nginx 还有一个重新加载选项，而不是重新启动。这告诉服务器再次查看配置文件并与其一起工作。这通常比重新启动更快，并且可以保持现有的连接打开。而重新启动会退出服务器并重新启动，带走打开的连接。重新启动的好处在于它更加明确，并且对于设置目的更加一致。

### 提供静态文件

在使用 Flask 通过 Web 服务器时，非常重要的一步是通过为站点上的静态内容创建一个快捷方式，以减轻应用程序的负载。这将使 Web 服务器从相对琐碎的任务中解脱出来，使得向最终浏览器提供基本文件的过程更快速、更响应。这也是一个简单的任务。

编辑您的 `blog.conf` 文件，在 server `{` 标签内添加以下行：

```py
location /static {
    root <path to app>/static;
}
```

其中 `<path to app>` 是静态目录存在的完整绝对路径。重新加载 Nginx 配置：

```py
sudo service nginx restart

```

这将告诉 Nginx 在浏览器请求 `/static` 时在哪里查找文件。您可以通过查看 Nginx 日志文件 `/var/log/nginx/access.log` 来看到这一点。

## Gunicorn

Gunicorn 是一个用 Python 编写的 Web 服务器。它已经理解了 WSGI，Flask 也是如此，因此让 Gunicorn 运行起来就像输入以下代码一样简单：

```py
pip install gunicorn
gunicorn app:app

```

其中`app:app`是您的应用程序，模块名称是我们在其中使用的（与 uWSGI 配置基本相同）。除此之外还有更多选项，但例如，从中工作并设置端口和绑定是有用的：

```py
gunicorn --bind 127.0.0.1:8000 app:app

```

`--bind`标志告诉 Gunicorn 要连接到哪个接口以及在哪个端口。如果我们只需要在内部使用 Web 应用程序，这是有用的。

另一个有用的标志是`--daemon`标志，它告诉 Gunicorn 在后台运行并与您的 shell 分离。这意味着我们不再直接控制该进程，但它正在运行，并且可以通过设置的绑定接口和端口进行访问。

# 使用 SSL 保护您的网站

在一个日益残酷的互联网上，通过证明其真实性来提高网站的安全性是很重要的。改善网站安全性的常用工具是使用 SSL，甚至更好的是 TLS。

SSL 和 TLS 证书允许您的服务器通过受信任的第三方基于您的浏览器连接的域名进行验证。这意味着，作为网站用户，我们可以确保我们正在交谈的网站在传输过程中没有被更改，是我们正在交谈的正确服务器，并且在服务器和我们的浏览器之间发送的数据不能被嗅探。当我们想要验证用户发送给我们的信息是否有效和受保护时，这显然变得重要，而我们的用户希望知道我们的数据在传输过程中受到保护。

## 获取您的证书

首先要做的是生成您的 SSL 证书请求。这与第三方一起使用，该第三方签署请求以验证您的服务器与任何浏览器。有几种方法可以做到这一点，取决于您的系统，但最简单的方法是运行以下命令：

```py
openssl req -nodes -newkey rsa:2048 -sha256 -keyout private.key -out public.csr

```

现在将询问您有关您所属组织的一些问题，但重要的是通用名称。这是您的服务器将被访问的域名（不带`https://`）：

```py
Country Name (2 letter code) [AU]: GB
State or Province Name (full name) [Some-State]: London
Locality Name (eg, city) []: London
Organization Name (eg, company) [Internet Widgits Pty Ltd]: Example Company
Organizational Unit Name (eg, section) []: IT
Common Name (eg, YOUR name) []: blog.example.com
Email Address []:
A challenge password []:
An optional company name []:
```

在这里，您可以看到我们使用`blog.example.com`作为我们示例域名，我们的博客应用将在该域名下访问。您必须在这里使用您自己的域名。电子邮件地址和密码并不是非常重要的，可以留空，但您应该填写“组织名称”字段，因为这将是您的 SSL 证书被识别为的名称。如果您不是一家公司，只需使用您自己的名字。

该命令为我们生成了两个文件；一个是`private.key`文件，这是我们的服务器用来与浏览器签署通信的文件，另一个是`public.csr`，这是发送给处理服务器和浏览器之间验证的第三方服务的证书请求文件。

### 注意

公钥/私钥加密是一个广泛但深入研究的主题。鉴于 Heartbleed 攻击，如果您希望保护服务器，了解这个是值得的。

下一步是使用第三方签署您的`public.csr`请求。有许多服务可以为您执行此操作，有些免费，有些略有成本；例如**Let's Encrypt**等一些服务可以完全免费地自动化整个过程。它们都提供基本相同的服务，但它们可能不会全部内置到所有浏览器中，并且为不同成本的不同程度的支持提供不同程度的支持。

这些服务将与您进行验证过程，要求您的`public.csr`证书请求，并为您的主机名返回一个已签名的`.crt`证书文件。

### 注意

请注意，将您的`.crt`和`.key`文件命名为其中申请证书的站点主机名可能会对您有所帮助。在我们的情况下，这将是`blog.example.com.crt`。

您的新`.crt`文件和现有的`.key`文件可以放在服务器的任何位置。但是，通常`.crt`文件放在`/etc/ssl/certs`中，而`.key`文件放在`/etc/ssl/private`中。

所有正确的文件都放在正确的位置后，我们需要重新打开用于我们的博客服务的现有 Apache 配置。最好运行一个正常的 HTTP 和 HTTPS 服务。但是，由于我们已经努力设置了 HTTPS 服务，强制执行它以重定向我们的用户是有意义的。这可以通过一个称为 HSTS 的新规范来实现，但并非所有的 Web 服务器构建都支持这一点，所以我们将使用重定向。

### 提示

您可以通过向操作系统的主机文件添加一个条目来在本地机器上运行带有 SSL 证书的测试域。只是不要忘记在完成后将其删除。

## Apache httpd

首先要更改的是`VirtualHost`行上的端口，从默认的 HTTP 端口`80`更改为默认的 HTTPS 端口`443`：

```py
<VirtualHost *:443>
```

我们还应该指定服务器的主机名正在使用的 SSL 证书；因此，在 VirtualHost 部分添加一个`ServerName`参数。这将确保证书不会在错误的域中使用。

```py
ServerName blog.example.com
```

您必须用您将要使用的主机名替换`blog.example.com`。

我们还需要设置 SSL 配置，以告诉 Apache 如何响应：

```py
SSLEngine on
SSLProtocol -all +TLSv1 +SSLv2
SSLCertificateFile /etc/ssl/certs/blog.example.com.crt
SSLCertificateKeyFile /etc/ssl/private/blog.example.com.key
SSLVerifyClient None
```

这里的情况是，Apache 中的 SSL 模块被启用，为该站点指定了公共证书和私钥文件，并且不需要客户端证书。禁用默认的 SSL 协议并启用 TLS 非常重要，因为 TLS 被认为比 SSL 更安全。但是，仍然启用 SSLv2 以支持旧版浏览器。

现在我们需要测试它。让我们重新启动 Apache：

```py
sudo service apache2 restart

```

尝试使用浏览器连接到 Web 服务器，不要忘记您现在正在使用`https://`。

现在它正在工作，最后一步是将普通的 HTTP 重定向到 HTTPS。在配置文件中，再次添加以下内容：

```py
<VirtualHost *:80>
  ServerName blog.example.com
  RewriteEngine On
  RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</VirtualHost>
```

我们为端口`80`创建一个新的`VirtualHost`，并指定它是为`ServerName blog.example.com`主机名而设的。然后我们使用 Apache 中的`Rewrite`模块简单地将浏览器重定向到相同的 URL，但是在开头使用 HTTPS。

再次重启 Apache：

```py
sudo service apache2 restart

```

现在在网站上用浏览器测试这个配置；验证您被重定向到 HTTPS，无论您访问哪个页面。

## Nginx

Nginx 的配置非常简单。与 Apache 配置非常相似，我们需要更改 Nginx 将监听我们站点的端口。由于 HTTPS 在端口`443`上运行，这里的区别在于告诉 Nginx 期望 SSL 连接。在配置中，我们必须更新以下行：

```py
listen   443 ssl;
```

现在要将 SSL 配置添加到配置的服务器元素中，输入以下内容：

```py
server_name blog.example.com;
ssl_certificate /etc/ssl/certs/blog.example.com.crt;
ssl_certificate_key /etc/ssl/private/blog.example.com.key;
ssl_protocols TLSv1 SSLv2;
```

这告诉 Nginx 将此配置应用于对`blog.example.com`主机名的请求（不要忘记用您自己的替换它），因为我们不希望为不适用的域发送 SSL 证书。我们还指定了公共证书文件位置和文件系统上的私有 SSL 密钥文件位置。最后，我们指定了要使用的 SSL 协议，这意味着启用 TLS（被认为比 SSL 更安全）。但是 SSLv2 仍然启用以支持旧版浏览器。

现在来测试它。让我们重新启动 Nginx 服务：

```py
sudo service nginx restart

```

尝试使用浏览器连接到 Web 服务器，不要忘记您现在正在使用`https://`。

一旦我们证明它正在工作，最后一步是将普通的 HTTP 重定向到 HTTPS。再次在配置文件中添加以下内容：

```py
server {
    listen 80;
    server_name blog.example.com;
    rewrite ^ https://$server_name$request_uri? permanent;
}
```

这与以前的普通 HTTP 配置基本相同；只是我们使用`rewrite`命令告诉 Nginx 捕获所有 URL，并向访问 HTTP 端口的浏览器发送重定向命令，以转到 HTTPS，使用他们在 HTTP 上尝试使用的确切路径。

最后一次，重新启动 Nginx：

```py
sudo service nginx restart

```

最后，在您被重定向到 HTTPS 的网站上测试您的浏览器，无论您访问哪个页面。

## Gunicorn

从 0.17 版本开始，Gunicorn 也添加了 SSL 支持。要从命令行启用 SSL，我们需要一些标志：

```py
gunicorn --bind 0.0.0.0:443 --certfile /etc/ssl/certs/blog.example.com.crt --keyfile /etc/ssl/private/blog.example.com.key --ssl-version 2 --ciphers TLSv1  app:app

```

这与 Nginx 和 Apache SSL 配置的工作方式非常相似。它指定要绑定的端口，以及在这种情况下的所有接口。然后，它将 Gunicorn 指向公共证书和私钥文件，并选择在旧版浏览器中使用 SSLv2 和（通常被认为更安全的）TLS 密码协议。

通过在浏览器中输入主机名和 HTTPS 来测试这个。

现在准备好了，让我们将端口`80`重定向到端口`443`。这在 Gunicorn 中相当复杂，因为它没有内置的重定向功能。一个解决方案是创建一个非常简单的 Flask 应用程序，在 Gunicorn 上的端口`80`启动，并重定向到端口`443`。这将是一个新的应用程序，带有一个新的`app.py`文件，其内容如下：

```py
from flask import Flask,request, redirect
import urlparse

app = Flask(__name__)

@app.route('/')
@app.route('/<path:path>')
def https_redirect(path='/'):
    url = urlparse.urlunparse((
        'https',
        request.headers.get('Host'),
        path,
        '','',''
    ))

    return redirect(url, code=301)
if __name__ == '__main__':
    app.run()
```

这是一个非常简单的 Flask 应用程序，可以在任何地方使用，将浏览器重定向到等效的 URL，但在前面加上 HTTPS。它通过使用标准的 Python `urlparse`库，使用浏览器发送到服务器的标头中的请求主机名，以及路由中的通用路径变量来构建 URL。然后，它使用 Flask 的`redirect`方法告诉浏览器它真正需要去哪里。

### 注意

请注意，空字符串对于 urlunparse 函数很重要，因为它期望一个完整的 URL 元组，就像由 urlparse 生成的那样。

您现在可能已经知道如何在 Gunicorn 中运行这个，尽管如此，要使用的命令如下：

```py
gunicorn --bind 0.0.0.0:80 app:app

```

现在使用浏览器连接到旧的 HTTP 主机，您应该被重定向到 HTTPS 版本。

# 使用 Ansible 自动化部署

Ansible 是一个配置管理工具。它允许我们以可重复和可管理的方式自动化部署我们的应用程序，而无需每次考虑如何部署我们的应用程序。

Ansible 可以在本地和通过 SSH 工作。您可以使用 Ansible 的一个聪明之处是让 Ansible 配置自身。根据您自己的配置，然后可以告诉它部署它需要的其他机器。

然而，我们只需要专注于使用 Apache、WSGI 和 Flask 构建我们自己的本地 Flask 实例。

首先要做的是在我们要部署 Flask 应用的机器上安装 Ansible。由于 Ansible 是用 Python 编写的，我们可以通过使用`pip`来实现这一点：

```py
sudo pip install ansible

```

现在我们有了一个配置管理器，既然配置管理器是用来设置服务器的，让我们建立一个 playbook，Ansible 可以用来构建整个机器。

在一个新项目或目录中，创建一个名为`blog.yml`的文件。我们正在创建一个 Ansible 称为 Playbook 的文件；它是一个按顺序运行的命令列表，并构建我们在 Apache 下运行的博客。为简单起见，在这个文件中假定您使用的是一个 Ubuntu 衍生操作系统：

```py
---

- hosts: webservers
  user: ubuntu
  sudo: True

  vars:
    app_src: ../blog
    app_dest: /srv/blog

  tasks:
    - name: install necessary packages
      action: apt pkg=$item state=installed
      with_items:
        - apache2
        - libapache2-mod-wsgi
        - python-setuptools
    - name: Enable wsgi module for Apache
      action: command a2enmod wsgi
    - name: Blog app configuration for Apache
      action: template src=templates/blog dest=/etc/apache/sites-available/blog
    - name: Copy blog app in
      action: copy src=${app_src} dest=${app_dest}
    - name: Enable site
 action: command a2ensite blog
    - name: Reload Apache
      action: service name=apache2 state=reloaded
```

Ansible Playbook 是一个 YAML 文件，包含几个部分；主要部分描述了“play”。`hosts`值描述了后续设置应该应用于哪组机器。`user`描述了 play 应该以什么用户身份运行；对于您来说，这应该是 Ansible 可以运行以安装您的应用程序的用户。`sudo`设置告诉 Ansible 以`sudo`权限运行此 play，而不是以 root 身份运行。

`vars`部分描述了 playbook 中常见的变量。这些设置很容易找到，因为它们位于顶部，但也可以在 playbook 配置中以`${example_variable}`的格式稍后使用，如果`example_variable`在这里的`vars`部分中定义。这里最重要的变量是`app_src`变量，它告诉 Ansible 在将应用程序复制到正确位置时在哪里找到我们的应用程序。在这个例子中，我们假设它在一个名为`blog`的目录中，但对于您来说，它可能位于文件系统的其他位置，您可能需要更新此变量。

最后一个最重要的部分是`tasks`部分。这告诉 Ansible 在更新它控制的机器时要运行什么。如果您熟悉 Ubuntu，这些任务应该有些熟悉。例如，`action: apt`告诉 apt 确保`with_items`列表中指定的所有软件包都已安装。您将注意到`$item`变量与`pkg`参数。`$item`变量由 Ansible 自动填充，因为它在`with_items`命令和`apt`命令上进行迭代，`apt`命令使用`pkg`参数来验证软件包是否已安装。

随后的任务使用命令行命令`a2enmod wsgi`启用 WSGI 模块，这是 Debian 系统中启用模块的简写，通过填充模板设置我们博客站点的 Apache 配置。幸运的是，Ansible 用于模板的语言是 Jinja，您很可能已经熟悉。我们的模板文件的内容应该与此`blog.yml`相关，在一个名为`templates`的目录中，一个名为`blog`的文件。内容应该如下所示：

```py
NameVirtualHost *:80

<VirtualHost *:80>
    WSGIScriptAlias / {{ app_dest }}/wsgi.py

    <Directory {{ app_dest }}/>
        Order deny,allow
        Allow from all
    </Directory>
</VirtualHost>
```

这应该很熟悉，这是 Apache 部分示例的直接剽窃；但是，我们已经利用了 Ansible 变量来填充博客应用程序的位置。这意味着，如果我们想将应用程序安装到另一个位置，只需更新`app_dest`变量即可。

最后，在 Playbook 任务中，它将我们非常重要的博客应用程序复制到机器上，使用 Debian 简写在 Apache 中启用站点，并重新加载 Apache，以便可以使用该站点。

所以剩下的就是在那台机器上运行 Ansible，并让它为您构建系统。

```py
ansible-playbook blog.yml --connection=local

```

这告诉 Ansible 运行我们之前创建的 Playbook 文件`blog.yml`，并在`local`连接类型上使用它，这意味着应用于本地机器。

### 提示

**Ansible 提示**

值得注意的是，这可能不是在大型分布式环境中使用 Ansible 的最佳方式。首先，您可能希望将其应用于远程机器，或者将 Apache 配置、Apache WSGI 配置、Flask 应用程序配置和博客配置分开成 Ansible 称为角色的单独文件；这将使它们可重用。

另一个有用的提示是指定使用的配置文件并在 Apache 中设置静态目录。阅读 Ansible 文档，了解更多有关改进部署的方法的想法：

[`docs.ansible.com/`](http://docs.ansible.com/)

# 阅读更多

有关如何在 Apache 和 WSGI 中更有效地保护您的 Flask 部署，通过创建只能运行 Flask 应用程序的无 shell 用户，详细信息请参见[`www.subdimension.co.uk/2012/04/24/Deploying_Flask_to_Apache.html`](http://www.subdimension.co.uk/2012/04/24/Deploying_Flask_to_Apache.html)。

此指南还提供了更多针对 CentOS 系统的示例，以及通过 Ansible 在 Lighttpd 和 Gunicorn 上部署的所有示例[`www.zufallsheld.de/2014/11/19/deploying-lighttpd-your-flask-apps-gunicorn-and-supervisor-with-ansible-on-centos/`](https://www.zufallsheld.de/2014/11/19/deploying-lighttpd-your-flask-apps-gunicorn-and-supervisor-with-ansible-on-centos/)。

# 摘要

在本章中，我们已经看到了许多运行 Flask 应用程序的方法，包括在多个 Web 服务器中保护隐私和安全，并提供静态文件以减少 Flask 应用程序的负载。我们还为 Ansible 制作了一个配置文件，以实现可重复的应用程序部署，因此，如果需要重新构建机器，这将是一个简单的任务。
