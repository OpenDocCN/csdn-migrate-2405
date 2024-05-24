# Django2 Web 应用构建指南（四）

> 原文：[`zh.annas-archive.org/md5/18689E1989723338A1936B680A71254B`](https://zh.annas-archive.org/md5/18689E1989723338A1936B680A71254B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：发送电子邮件的任务

现在我们有了我们的模型和视图，我们需要让 Mail Ape 发送电子邮件。我们将让 Mail Ape 发送两种类型的电子邮件，订阅者确认电子邮件和邮件列表消息。我们将通过创建一个名为`SubscriberMessage`的新模型来跟踪邮件列表消息的成功发送，以跟踪是否成功将消息发送给存储在`Subscriber`模型实例中的地址。由于向许多`Subscriber`模型实例发送电子邮件可能需要很长时间，我们将使用 Celery 在常规 Django 请求/响应周期之外作为任务发送电子邮件。

在本章中，我们将做以下事情：

+   使用 Django 的模板系统生成我们电子邮件的 HTML 主体

+   使用 Django 发送包含 HTML 和纯文本的电子邮件

+   使用 Celery 执行异步任务

+   防止我们的代码在测试期间发送实际电子邮件

让我们首先创建一些我们将用于发送动态电子邮件的常见资源。

# 创建电子邮件的常见资源

在本节中，我们将创建一个基本的 HTML 电子邮件模板和一个用于呈现电子邮件模板的`Context`对象。我们希望为我们的电子邮件创建一个基本的 HTML 模板，以避免重复使用样板 HTML。我们还希望确保我们发送的每封电子邮件都包含一个退订链接，以成为良好的电子邮件用户。我们的`EmailTemplateContext`类将始终提供我们的模板需要的常见变量。

让我们首先创建一个基本的 HTML 电子邮件模板。

# 创建基本的 HTML 电子邮件模板

我们将在`django/mailinglist/templates/mailinglist/email/base.html`中创建我们的基本电子邮件 HTML 模板：

```py
<!DOCTYPE html>
<html lang="en" >
<head >
<body >
{% block body %}
{% endblock %}

Click <a href="{{ unsubscription_link }}">here</a> to unsubscribe from this
mailing list.
Sent with Mail Ape .
</body >
</html >
```

前面的模板看起来像是`base.html`的一个更简单的版本，只有一个块。电子邮件模板可以扩展`email/base.html`并覆盖主体块，以避免样板 HTML。尽管文件名相同（`base.html`），Django 不会混淆两者。模板是通过它们的模板路径标识的，不仅仅是文件名。

我们的基本模板还期望`unsubscription_link`变量始终存在。这将允许用户取消订阅，如果他们不想继续接收电子邮件。

为了确保我们的模板始终具有`unsubscription_link`变量，我们将创建一个`Context`来确保始终提供它。

# 创建 EmailTemplateContext

正如我们之前讨论过的（参见第一章，*构建 MyMDB*），要呈现模板，我们需要为 Django 提供一个`Context`对象，其中包含模板引用的变量。在编写基于类的视图时，我们只需要在`get_context_data()`方法中提供一个字典，Django 会为我们处理一切。然而，当我们想要自己呈现模板时，我们将不得不自己实例化`Context`类。为了确保我们所有的电子邮件模板呈现代码提供相同的最小信息，我们将创建一个自定义模板`Context`。

让我们在`django/mailinglist/emails.py`中创建我们的`EmailTemplateContext`类：

```py
from django.conf import settings

from django.template import Context

class EmailTemplateContext(Context):

    @staticmethod
    def make_link(path):
        return settings.MAILING_LIST_LINK_DOMAIN + path

    def __init__(self, subscriber, dict_=None, **kwargs):
        if dict_ is None:
            dict_ = {}
        email_ctx = self.common_context(subscriber)
        email_ctx.update(dict_)
        super().__init__(email_ctx, **kwargs)

    def common_context(self, subscriber):
        subscriber_pk_kwargs = {'pk': subscriber.id}
        unsubscribe_path = reverse('mailinglist:unsubscribe',
                                   kwargs=subscriber_pk_kwargs)
        return {
            'subscriber': subscriber,
            'mailing_list': subscriber.mailing_list,
            'unsubscribe_link': self.make_link(unsubscribe_path),
        }
```

我们的`EmailTemplateContext`由以下三种方法组成：

+   `make_link()`: 这将 URL 的路径与我们项目的`MAILING_LIST_LINK_DOMAIN`设置连接起来。`make_link`是必要的，因为 Django 的`reverse()`函数不包括域。Django 项目可以托管在多个不同的域上。我们将在*配置电子邮件设置*部分更多地讨论`MAILING_LIST_LINK_DOMAIN`的值。

+   `__init__()`: 这覆盖了`Context.__init__(...)`方法，给了我们一个机会将`common_context()`方法的结果添加到`dict_`参数的值中。我们要小心让参数接收到的数据覆盖我们在`common_context`中生成的数据。

+   `common_context()`: 这返回一个字典，提供我们希望所有`EmailTemplateContext`对象可用的变量。我们始终希望有`subscriber`、`mailing_list`和`unsubscribtion_link`可用。

我们将在下一节中使用这两个资源，我们将向新的`Subscriber`模型实例发送确认电子邮件。

# 发送确认电子邮件

在本节中，我们将向新的`Subscriber`发送电子邮件，让他们确认对`MailingList`的订阅。

在本节中，我们将：

1.  将 Django 的电子邮件配置设置添加到我们的`settings.py`

1.  编写一个函数来使用 Django 的`send_mail()`函数发送电子邮件

1.  创建和渲染电子邮件正文的 HTML 和文本模板

1.  更新`Subscriber.save()`以在创建新的`Subscriber`时发送电子邮件

让我们从更新配置开始，使用我们邮件服务器的设置。

# 配置电子邮件设置

为了能够发送电子邮件，我们需要配置 Django 与**简单邮件传输协议**（**SMTP**）服务器进行通信。在开发和学习过程中，您可能可以使用与您的电子邮件客户端相同的 SMTP 服务器。对于发送大量生产电子邮件，使用这样的服务器可能违反您的电子邮件提供商的服务条款，并可能导致帐户被暂停。请注意您使用的帐户。

让我们在`django/config/settings.py`中更新我们的设置：

```py
EMAIL_HOST = 'smtp.example.com'
EMAIL_HOST_USER = 'username'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD')

MAILING_LIST_FROM_EMAIL = 'noreply@example.com'
MAILING_LIST_LINK_DOMAIN = 'http://localhost:8000'
```

在上面的代码示例中，我使用了很多`example.com`的实例，您应该将其替换为您的 SMTP 主机和域的正确域。让我们更仔细地看一下设置：

+   `EMAIL_HOST`: 这是我们正在使用的 SMTP 服务器的地址。

+   `EMAIL_HOST_USER`: 用于对 SMTP 服务器进行身份验证的用户名。

+   `EMAIL_PORT`: 连接到 SMTP 服务器的端口。

+   `EMAIL_USE_TLS`: 这是可选的，默认为`False`。如果您要通过 TLS 连接到 SMTP 服务器，请使用它。如果您使用 SSL，则使用`EMAIL_USE_SSL`设置。SSL 和 TLS 设置是互斥的。

+   `EMAIL_HOST_PASSWORD`: 主机的密码。在我们的情况下，我们将期望密码在环境变量中。

+   `MAILING_LIST_FROM_EMAIL`: 这是我们使用的自定义设置，用于设置我们发送的电子邮件的`FROM`标头。

+   `MAILING_LIST_LINK_DOMAIN`: 这是所有电子邮件模板链接的前缀域。我们在`EmailTemplateContext`类中看到了这个设置的使用。

接下来，让我们编写我们的创建函数来发送确认电子邮件。

# 创建发送电子邮件确认函数

现在，我们将创建一个实际创建并发送确认电子邮件给我们的`Subscriber`的函数。`email`模块将包含所有我们与电子邮件相关的代码（我们已经在那里创建了`EmailTemplateContext`类）。

我们的`send_confirmation_email()`函数将需要执行以下操作：

1.  为渲染电子邮件正文创建一个`Context`

1.  为电子邮件创建主题

1.  渲染 HTML 和文本电子邮件正文

1.  使用`send_mail()`函数发送电子邮件

让我们在`django/mailinglist/emails.py`中创建该函数：

```py
from django.conf import settings
from django.core.mail import send_mail
from django.template import engines, Context
from django.urls import reverse

CONFIRM_SUBSCRIPTION_HTML = 'mailinglist/email/confirmation.html'

CONFIRM_SUBSCRIPTION_TXT = 'mailinglist/email/confirmation.txt'

class EmailTemplateContext(Context):
    # skipped unchanged class

def send_confirmation_email(subscriber):
    mailing_list = subscriber.mailing_list
    confirmation_link = EmailTemplateContext.make_link(
        reverse('mailinglist:confirm_subscription',
                kwargs={'pk': subscriber.id}))
    context = EmailTemplateContext(
        subscriber,
        {'confirmation_link': confirmation_link}
    )
    subject = 'Confirming subscription to {}'.format(mailing_list.name)

    dt_engine = engines['django'].engine
    text_body_template = dt_engine.get_template(CONFIRM_SUBSCRIPTION_TXT)
    text_body = text_body_template.render(context=context)
    html_body_template = dt_engine.get_template(CONFIRM_SUBSCRIPTION_HTML)
    html_body = html_body_template.render(context=context)

    send_mail(
        subject=subject,
        message=text_body,
        from_email=settings.MAILING_LIST_FROM_EMAIL,
        recipient_list=(subscriber.email,),
        html_message=html_body)
```

让我们更仔细地看一下我们的代码：

+   `EmailTemplateContext()`: 这实例化了我们之前创建的`Context`类。我们为其提供了一个`Subscriber`实例和一个包含确认链接的`dict`。`confirmation_link`变量将被我们的模板使用，我们将在接下来的两个部分中创建。

+   `engines['django'].engine`: 这引用了 Django 模板引擎。引擎知道如何使用`settings.py`中`TEMPLATES`设置中的配置设置来查找`Template`。

+   `dt_engine.get_template()`: 这将返回一个模板对象。我们将模板的名称作为参数提供给`get_template()`方法。

+   `text_body_template.render()`: 这将模板（使用之前创建的上下文）渲染为字符串。

最后，我们使用`send_email()`函数发送电子邮件。`send_email()`函数接受以下参数：

+   `subject=subject`: 电子邮件消息的主题。

+   `message=text_body`: 电子邮件的文本版本。

+   `from_email=settings.MAILING_LIST_FROM_EMAIL`：发件人的电子邮件地址。如果我们不提供`from_email`参数，那么 Django 将使用`DEFAULT_FROM_EMAIL`设置。

+   `recipient_list=(subscriber.email,)`：收件人电子邮件地址的列表（或元组）。这必须是一个集合，即使您只发送给一个收件人。如果包括多个收件人，他们将能够看到彼此。

+   `html_message=html_body`：电子邮件的 HTML 版本。这个参数是可选的，因为我们不必提供 HTML 正文。如果我们提供 HTML 正文，那么 Django 将发送包含 HTML 和文本正文的电子邮件。电子邮件客户端将选择显示电子邮件的 HTML 或纯文本版本。

现在我们已经有了发送电子邮件的代码，让我们制作我们的电子邮件正文模板。

# 创建 HTML 确认电子邮件模板

让我们制作 HTML 订阅电子邮件确认模板。我们将在`django/mailinglist/templates/mailinglist/email_templates/confirmation.html`中创建模板：

```py
{% extends "mailinglist/email_templates/email_base.html" %}

{% block body %}
  <h1>Confirming subscription to {{ mailing_list }}</h1 >
  <p>Someone (hopefully you) just subscribed to {{ mailinglist }}.</p >
  <p>To confirm your subscription click <a href="{{ confirmation_link }}">here</a>.</p >
  <p>If you don't confirm, you won't hear from {{ mailinglist }} ever again.</p >
  <p>Thanks,</p >
  <p>Your friendly internet Mail Ape !</p>
{% endblock %}
```

我们的模板看起来就像一个 HTML 网页模板，但它将用于电子邮件。就像一个普通的 Django 模板一样，我们正在扩展一个基本模板并填写一个块。在我们的情况下，我们正在扩展的模板是我们在本章开始时创建的`email/base.html`模板。另外，请注意我们如何使用我们在`send_confirmation_email()`函数中提供的变量（例如`confirmation_link`）和我们的`EmailTemplateContext`（例如`mailing_list`）。

电子邮件可以包含 HTML，但并非总是由 Web 浏览器呈现。值得注意的是，一些版本的 Microsoft Outlook 使用 Microsoft Word HTML 渲染器来渲染电子邮件。即使是在运行在浏览器中的 Gmail 也会在呈现之前操纵它收到的 HTML。请小心在真实的电子邮件客户端中测试复杂的布局。

接下来，让我们创建这个模板的纯文本版本。

# 创建文本确认电子邮件模板

现在，我们将创建确认电子邮件模板的纯文本版本；让我们在`django/mailinglist/templates/mailinglist/email_templates/confirm_subscription.txt`中创建它：

```py
Hello {{subscriber.email}},

Someone (hopefully you) just subscribed to {{ mailinglist }}.

To confirm your subscription go to {{confirmation_link}}.

If you don't confirm you won't hear from {{ mailinglist }} ever again.

Thanks,

Your friendly internet Mail Ape !
```

在上述情况下，我们既不使用 HTML 也不扩展任何基本模板。

然而，我们仍在引用我们在`send_confirmation_email()`中提供的变量（例如`confirmation_link`）函数和我们的`EmailTemplateContext`类（例如`mailing_list`）。

现在我们已经有了发送电子邮件所需的所有代码，让我们在创建新的`Subscriber`模型实例时发送它们。

# 在新的 Subscriber 创建时发送

作为最后一步，我们将向用户发送确认电子邮件；我们需要调用我们的`send_confirmation_email`函数。基于 fat models 的理念，我们将从我们的`Subscriber`模型而不是视图中调用我们的`send_confirmation_email`函数。在我们的情况下，当保存新的`Subscriber`模型实例时，我们将发送电子邮件。

让我们更新我们的`Subscriber`模型，在保存新的`Subscriber`时发送确认电子邮件。为了添加这种新行为，我们需要编辑`django/mailinglist/models.py`：

```py
from django.db import models
from mailinglist import emails

class Subscriber(models.Model):
    # skipping unchanged model body

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        is_new = self._state.adding or force_insert
        super().save(force_insert=force_insert, force_update=force_update,
                     using=using, update_fields=update_fields)
        if is_new:
            self.send_confirmation_email()

    def send_confirmation_email(self):        
           emails.send_confirmation_email(self)
```

在创建模型时添加新行为的最佳方法是重写模型的`save()`方法。在重写`save()`时，非常重要的是我们仍然调用超类的`save()`方法，以确保模型保存。我们的新保存方法有三个作用：

+   检查当前模型是否为新模型

+   调用超类的`save()`方法

+   如果模型是新的，则发送确认电子邮件

要检查当前模型实例是否是新的，我们检查`_state`属性。`_state`属性是`ModelState`类的一个实例。通常，以下划线（`_`）开头的属性被认为是私有的，并且可能会在 Django 的不同版本中发生变化。但是，`ModelState`类在 Django 的官方文档中有描述，所以我们可以更放心地使用它（尽管我们应该密切关注未来版本的变化）。如果`self._state.adding`为`True`，那么`save()`方法将会将这个模型实例插入为新行。如果`self._state.adding`为`True`，那么`save()`方法将会更新现有行。

我们还将`emails.send_confirmation_email()`的调用包装在`Subscriber`方法中。如果我们想要重新发送确认电子邮件，这将非常有用。任何想要重新发送确认电子邮件的代码都不需要知道`emails`模块。模型是所有操作的专家。这是 fat model 哲学的核心。

# 本节的快速回顾

在本节中，我们学习了更多关于 Django 模板系统以及如何发送电子邮件。我们学会了如何渲染模板，而不是使用 Django 的内置视图来直接使用 Django 模板引擎为我们渲染它。我们使用了 Django 的最佳实践，创建了一个服务模块来隔离所有我们的电子邮件代码。最后，我们还使用了`send_email()`来发送一封带有文本和 HTML 正文的电子邮件。

接下来，让我们在向用户返回响应后使用 Celery 发送这些电子邮件。

# 使用 Celery 发送电子邮件

随着我们构建越来越复杂的应用程序，我们经常希望执行操作，而不强迫用户等待我们返回 HTTP 响应。Django 与 Celery 很好地配合，Celery 是一个流行的 Python 分布式任务队列，可以实现这一点。

Celery 是一个在代理中*排队* *任务*以供 Celery *工作者*处理的库。让我们更仔细地看看其中一些术语：

+   **Celery 任务**封装了我们想要异步执行的可调用对象。

+   **Celery 队列**是按照先进先出顺序存储在代理中的任务列表。

+   **Celery 代理**是提供快速高效的队列存储的服务器。流行的代理包括 RabbitMQ、Redis 和 AWS SQS。Celery 对不同代理有不同级别的支持。我们将在开发中使用 Redis 作为我们的代理。

+   **Celery 工作者**是单独的进程，它们检查任务队列以执行任务并执行它们。

在本节中，我们将做以下事情：

1.  安装 Celery

1.  配置 Celery 以与 Django 一起工作

1.  使用 Celery 队列发送确认电子邮件任务

1.  使用 Celery 工作者发送我们的电子邮件

让我们首先安装 Celery。

# 安装 celery

要安装 Celery，我们将使用这些新更改更新我们的`requirements.txt`文件：

```py
celery<4.2
celery[redis]
django-celery-results<2.0
```

我们将安装三个新包及其依赖项：

+   `celery`：安装主要的 Celery 包

+   `celery[redis]`：安装我们需要使用 Redis 作为代理的依赖项

+   `django-celery-results`：让我们将执行的任务结果存储在我们的 Django 数据库中；这只是存储和记录 Celery 结果的一种方式

接下来，让我们使用`pip`安装我们的新包：

```py
$ pip install -r requirements.txt
```

现在我们已经安装了 Celery，让我们配置 Mail Ape 来使用 Celery。

# 配置 Celery 设置

要配置 Celery，我们需要进行两组更改。首先，我们将更新 Django 配置以使用 Celery。其次，我们将创建一个 Celery 配置文件，供我们的工作者使用。

让我们首先更新`django/config/settings.py`：

```py
INSTALLED_APPS = [
    'user',
    'mailinglist',

    'crispy_forms',
    'markdownify',
    'django_celery_results',

    'django.contrib.admin',
    # other built in django apps unchanged.
]

CELERY_BROKER_URL = 'redis://localhost:6379/0'
CELERY_RESULT_BACKEND = 'django-db'
```

让我们更仔细地看看这些新设置：

+   `django_celery_results`：这是一个我们安装为 Django 应用程序的 Celery 扩展，让我们将 Celery 任务的结果存储在 Django 数据库中。

+   `CELERY_BROKER_URL`：这是我们的 Celery 代理的 URL。在我们的情况下，我们将在开发中使用本地的 Redis 服务器。

+   `CELERY_RESULT_BACKEND`：这表示存储结果的位置。在我们的情况下，我们将使用 Django 数据库。

由于`django_celery_results`应用程序允许我们在数据库中保存结果，因此它包括新的 Django 模型。为了使这些模型存在于数据库中，我们需要迁移我们的数据库：

```py
$ cd django
$ python manage.py migrate django_celery_results
```

接下来，让我们为我们的 Celery 工作程序创建一个配置文件。工作程序将需要访问 Django 和我们的 Celery 代理。

让我们在`django/config/celery.py`中创建 Celery 工作程序配置：

```py
import os
from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('mailape')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
```

Celery 知道如何与 Django 项目直接配合。在这里，我们根据 Django 配置配置了 Celery 库的一个实例。让我们详细审查这些设置：

+   `setdefault('DJANGO_SETTINGS_MODULE', ...)`：这确保我们的 Celery 工作程序知道如果未为`DJANGO_SETTINGS_MODULE`环境变量设置它，应该使用哪个 Django 设置模块。

+   `Celery('mailape')`：这实例化了 Mail Ape 的 Celery 库。大多数 Django 应用程序只使用一个 Celery 实例，因此`mailape`字符串并不重要。

+   `app.config_from_object('django.conf:settings', namespace='CELERY')`：这告诉我们的 Celery 库从`django.conf.settings`对象配置自身。`namespace`参数告诉 Celery 其设置以`CELERY`为前缀。

+   `app.autodiscover_tasks()`：这使我们可以避免手动注册任务。当 Celery 与 Django 一起工作时，它将检查每个已安装的应用程序是否有一个`tasks`模块。该模块中的任何任务都将被自动发现。

通过创建一个任务来发送确认电子邮件来了解更多关于任务的信息。

# 创建一个任务来发送确认电子邮件

现在 Celery 已配置好，让我们创建一个任务，向订阅者发送确认电子邮件。

Celery 任务是`Celery.app.task.Task`的子类。但是，当我们创建 Celery 任务时，大多数情况下，我们使用 Celery 的装饰器将函数标记为任务。在 Django 项目中，使用`shared_task`装饰器通常是最简单的。

创建任务时，将其视为视图是有用的。Django 社区的最佳实践建议*视图应该简单*，这意味着视图应该简单。它们不应该负责复杂的任务，而应该将该工作委托给模型或服务模块（例如我们的`mailinglist.emails`模块）。

任务函数保持简单，并将所有逻辑放在模型或服务模块中。

让我们在`django/mailinglist/tasks.py`中创建一个任务来发送我们的确认电子邮件：

```py
from celery import shared_task

from mailinglist import emails

@shared_task
def send_confirmation_email_to_subscriber(subscriber_id):
    from mailinglist.models import Subscriber
    subscriber = Subscriber.objects.get(id=subscriber_id)
    emails.send_confirmation_email(subscriber)
```

关于我们的`send_confirmation_email_to_subscriber`函数有一些独特的事情：

+   `@shared_task`：这是一个 Celery 装饰器，将函数转换为`Task`。`shared_task`对所有 Celery 实例都可用（在大多数 Django 情况下，通常只有一个）。

+   `def send_confirmation_email_to_subscriber(subscriber_id):`：这是一个常规函数，它以订阅者 ID 作为参数。Celery 任务可以接收任何可 pickle 的对象（包括 Django 模型）。但是，如果您传递的是可能被视为机密的内容（例如电子邮件地址），您可能希望限制存储数据的系统数量（例如，不要在代理商处存储）。在这种情况下，我们将任务函数传递给`Subscriber`的 ID，而不是完整的`Subscriber`。然后，任务函数查询相关的`Subscriber`实例的数据库。

在这个函数中最后要注意的一点是，我们在函数内部导入了`Subscriber`模型，而不是在文件顶部导入。在我们的情况下，我们的`Subscriber`模型将调用此任务。如果我们在`tasks.py`的顶部导入`models`模块，并在`model.py`的顶部导入`tasks`模块，那么就会出现循环导入错误。为了防止这种情况，我们在函数内部导入`Subscriber`。

接下来，让我们从`Subscriber.send_confirmation_email()`中调用我们的任务。

# 向新订阅者发送电子邮件

现在我们有了任务，让我们更新我们的`Subscriber`，使用任务发送确认电子邮件，而不是直接使用`emails`模块。

让我们更新`django/mailinglist/models.py`：

```py
from django.db import models
from mailinglist import tasks

class Subscriber(models.Model):
    # skipping unchanged model 

     def send_confirmation_email(self):
        tasks.send_confirmation_email_to_subscriber.delay(self.id)
```

在我们更新的`send_confirmation_email()`方法中，我们将看看如何异步调用任务。

Celery 任务可以同步或异步调用。使用常规的`()`运算符，我们将同步调用任务（例如，`tasks.send_confirmation_email_to_subscriber(self.id)`）。同步执行的任务就像常规的函数调用一样执行。

Celery 任务还有`delay()`方法来异步执行任务。当告诉任务要异步执行时，它将在 Celery 的消息代理中排队一条消息。然后 Celery 的 worker 将（最终）从代理的队列中拉取消息并执行任务。任务的结果存储在存储后端（在我们的情况下是 Django 数据库）中。

异步调用任务会返回一个`result`对象，它提供了一个`get()`方法。调用`result.get()`会阻塞当前线程，直到任务完成。然后`result.get()`返回任务的结果。在我们的情况下，我们的任务不会返回任何东西，所以我们不会使用`result`函数。

`task.delay(1, a='b')`实际上是`task.apply_async((1,), kwargs={'a':'b'})`的快捷方式。大多数情况下，快捷方法是我们想要的。如果您需要更多对任务执行的控制，`apply_async()`在 Celery 文档中有记录（[`docs.celeryproject.org/en/latest/userguide/calling.html`](http://docs.celeryproject.org/en/latest/userguide/calling.html)）。

现在我们可以调用任务了，让我们启动一个 worker 来处理我们排队的任务。

# 启动 Celery worker

启动 Celery worker 不需要我们编写任何新代码。我们可以从命令行启动一个：

```py
$ cd django
$ celery worker -A config.celery -l info
```

让我们看看我们给`celery`的所有参数：

+   `worker`: 这表示我们想要启动一个新的 worker。

+   `-A config.celery`: 这是我们想要使用的应用程序或配置。在我们的情况下，我们想要的应用程序在`config.celery`中配置。

+   `-l info`: 这是要输出的日志级别。在这种情况下，我们使用`info`。默认情况下，级别是`WARNING`。

我们的 worker 现在能够处理 Django 中我们的代码排队的任务。如果我们发现我们排队了很多任务，我们可以启动更多的`celery worker`进程。

# 快速回顾一下这一部分

在本节中，您学会了如何使用 Celery 来异步处理任务。

我们学会了如何在我们的`settings.py`中使用`CELERY_BROKER_URL`和`CELERY_RESULT_BACKEND`设置来设置代理和后端。我们还为我们的 celery worker 创建了一个`celery.py`文件。然后，我们使用`@shared_task`装饰器将函数变成了 Celery 任务。有了任务可用，我们学会了如何使用`.delay()`快捷方法调用 Celery 任务。最后，我们启动了一个 Celery worker 来执行排队的任务。

现在我们知道了基础知识，让我们使用这种方法向我们的订阅者发送消息。

# 向订阅者发送消息

在本节中，我们将创建代表用户想要发送到其邮件列表的消息的`Message`模型实例。

要发送这些消息，我们需要做以下事情：

+   创建一个`SubscriberMessage`模型来跟踪哪些消息何时发送

+   为与新的`Message`模型实例相关联的每个确认的`Subscriber`模型实例创建一个`SubscriberMessage`模型实例

+   让`SubscriberMessage`模型实例向其关联的`Subscriber`模型实例的电子邮件发送邮件。

为了确保即使有很多相关的`Subscriber`模型实例的`MailingList`模型实例也不会拖慢我们的网站，我们将使用 Celery 来构建我们的`SubscriberMessage`模型实例列表*并*发送电子邮件。

让我们首先创建一个`SubscriberManager`来帮助我们获取确认的`Subscriber`模型实例的列表。

# 获取确认的订阅者

良好的 Django 项目使用自定义模型管理器来集中和记录与其模型相关的`QuerySet`对象。我们需要一个`QuerySet`对象来检索属于给定`MailingList`模型实例的所有已确认`Subscriber`模型实例。

让我们更新`django/mailinglist/models.py`，添加一个新的`SubscriberManager`类，它知道如何为`MailingList`模型实例获取已确认的`Subscriber`模型实例：

```py
class SubscriberManager(models.Manager):

    def confirmed_subscribers_for_mailing_list(self, mailing_list):
        qs = self.get_queryset()
        qs = qs.filter(confirmed=True)
        qs = qs.filter(mailing_list=mailing_list)
        return qs

class Subscriber(models.Model):
    # skipped fields 

    objects = SubscriberManager()

    class Meta:
        unique_together = ['email', 'mailing_list', ]

    # skipped methods
```

我们的新`SubscriberManager`对象取代了`Subscriber.objects`中的默认管理器。`SubscriberManager`类提供了`confirmed_subscribers_for_mailing_list()`方法以及默认管理器的所有方法。

接下来，让我们创建`SubscriberMessage`模型。

# 创建 SubscriberMessage 模型

现在，我们将创建一个`SubscriberMessage`模型和管理器。`SubscriberMessage`模型将让我们跟踪是否成功向`Subscriber`模型实例发送了电子邮件。自定义管理器将具有一个方法，用于创建`Message`模型实例所需的所有`SubscriberMessage`模型实例。

让我们从`django/mailinglist/models.py`中创建我们的`SubscriberMessage`开始：

```py
import uuid

from django.conf import settings
from django.db import models

from mailinglist import tasks

class SubscriberMessage(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    message = models.ForeignKey(to=Message, on_delete=models.CASCADE)
    subscriber = models.ForeignKey(to=Subscriber, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    sent = models.DateTimeField(default=None, null=True)
    last_attempt = models.DateTimeField(default=None, null=True)

    objects = SubscriberMessageManager()

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        is_new = self._state.adding or force_insert
        super().save(force_insert=force_insert, force_update=force_update, using=using,
             update_fields=update_fields)
        if is_new:
            self.send()

    def send(self):
        tasks.send_subscriber_message.delay(self.id)
```

与我们其他大部分模型相比，我们的`SubscriberMessage`模型定制程度相当高：

+   `SubsriberMessage`字段将其连接到`Message`和`Subscriber`，让它跟踪创建时间、最后尝试发送电子邮件以及成功与否。

+   `SubscriberMessage.objects`是我们将在下一节中创建的自定义管理器。

+   `SubscriberMessage.save()`与`Subscriber.save()`类似。它检查`SubscriberMessage`是否是新的，然后调用`send()`方法。

+   `SubscriberMessage.send()`排队一个任务来发送消息。我们将在*向订阅者发送电子邮件*部分稍后创建该任务。

现在，让我们在`django/mailinglist/models.py`中创建一个`SubscriberMessageManager`：

```py
from django.db import models

class SubscriberMessageManager(models.Manager):

    def create_from_message(self, message):
        confirmed_subs = Subscriber.objects.\
            confirmed_subscribers_for_mailing_list(message.mailing_list)
        return [
            self.create(message=message, subscriber=subscriber)
            for subscriber in confirmed_subs
        ]
```

我们的新管理器提供了一个从`Message`创建`SubscriberMessages`的方法。`create_from_message()`方法返回使用`Manager.create()`方法创建的`SubscriberMessage`列表。

最后，为了使新模型可用，我们需要创建一个迁移并应用它：

```py
$ cd django
$ python manage.py makemigrations mailinglist
$ python manage.py migrate mailinglist
```

现在我们有了`SubscriberMessage`模型和表，让我们更新我们的项目，以便在创建新的`Message`时自动创建`SubscriberMessage`模型实例。

# 创建消息时创建 SubscriberMessages

Mail Ape 旨在在创建后立即发送消息。为了使`Message`模型实例成为订阅者收件箱中的电子邮件，我们需要构建一组`SubscriberMessage`模型实例。构建该组`SubscriberMessage`模型实例的最佳时间是在创建新的`Message`模型实例之后。

让我们在`django/mailinglist/models.py`中重写`Message.save()`：

```py
class Message(models.Model):
    # skipped fields

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        is_new = self._state.adding or force_insert
        super().save(force_insert=force_insert, force_update=force_update,
                     using=using, update_fields=update_fields)
        if is_new:
            tasks.build_subscriber_messages_for_message.delay(self.id)
```

我们的新`Message.save()`方法遵循了与之前类似的模式。`Message.save()`检查当前的`Message`是否是新的，然后是否将`build_subscriber_messages_for_message`任务排队等待执行。

我们将使用 Celery 异步构建一组`SubscriberMessage`模型实例，因为我们不知道有多少`Subscriber`模型实例与我们的`MailingList`模型实例相关联。如果有很多相关的`Subscriber`模型实例，那么可能会使我们的 Web 服务器无响应。使用 Celery，我们的 Web 服务器将在`Message`模型实例保存后立即返回响应。`SubscriberMessage`模型实例将由一个完全独立的进程创建。

让我们在`django/mailinglist/tasks.py`中创建`build_subscriber_messages_for_message`任务：

```py
from celery import shared_task

@shared_task
def build_subscriber_messages_for_message(message_id):
    from mailinglist.models import Message, SubscriberMessage
    message = Message.objects.get(id=message_id)
    SubscriberMessage.objects.create_from_message(message)
```

正如我们之前讨论的，我们的任务本身并不包含太多逻辑。`build_subscriber_messages_for_message`让`SubscriberMessage`管理器封装了创建`SubscriberMessage`模型实例的所有逻辑。

接下来，让我们编写发送包含用户创建的`Message`的电子邮件的代码。

# 向订阅者发送电子邮件

本节的最后一步将是根据`SubscriberMessage`发送电子邮件。早些时候，我们的`SubscriberMessage.save()`方法排队了一个任务，向`Subscriber`发送`Message`。现在，我们将创建该任务并更新`emails.py`代码以发送电子邮件。

让我们从更新`django/mailinglist/tasks.py`开始一个新的任务：

```py
from celery import shared_task

@shared_task
def send_subscriber_message(subscriber_message_id):
    from mailinglist.models import SubscriberMessage
    subscriber_message = SubscriberMessage.objects.get(
        id=subscriber_message_id)
    emails.send_subscriber_message(subscriber_message)
```

这个新任务遵循了我们之前创建的任务的相同模式：

+   我们使用`shared_task`装饰器将常规函数转换为 Celery 任务

+   我们在任务函数内导入我们的模型，以防止循环导入错误

+   我们让`emails`模块来实际发送邮件

接下来，让我们更新`django/mailinglist/emails.py`文件，根据`SubscriberMessage`发送电子邮件：

```py
from datetime import datetime

from django.conf import settings
from django.core.mail import send_mail
from django.template import engines 
from django.utils.datetime_safe import datetime

SUBSCRIBER_MESSAGE_TXT = 'mailinglist/email/subscriber_message.txt'

SUBSCRIBER_MESSAGE_HTML = 'mailinglist/email/subscriber_message.html'

def send_subscriber_message(subscriber_message):
    message = subscriber_message.message
    context = EmailTemplateContext(subscriber_message.subscriber, {
        'body': message.body,
    })

    dt_engine = engines['django'].engine
    text_body_template = dt_engine.get_template(SUBSCRIBER_MESSAGE_TXT)
    text_body = text_body_template.render(context=context)
    html_body_template = dt_engine.get_template(SUBSCRIBER_MESSAGE_HTML)
    html_body = html_body_template.render(context=context)

    utcnow = datetime.utcnow()
    subscriber_message.last_attempt = utcnow
    subscriber_message.save()

    success = send_mail(
        subject=message.subject,
        message=text_body,
        from_email=settings.MAILING_LIST_FROM_EMAIL,
        recipient_list=(subscriber_message.subscriber.email,),
        html_message=html_body)

    if success == 1:
        subscriber_message.sent = utcnow
        subscriber_message.save()
```

我们的新函数采取以下步骤：

1.  使用我们之前创建的`EmailTemplateContext`类构建模板的上下文

1.  使用 Django 模板引擎呈现电子邮件的文本和 HTML 版本

1.  记录当前发送尝试的时间

1.  使用 Django 的`send_mail()`函数发送电子邮件

1.  如果`send_mail()`返回发送了一封电子邮件，它记录了消息发送的时间

我们的`send_subscriber_message()`函数要求我们创建 HTML 和文本模板来渲染。

让我们在`django/mailinglist/templates/mailinglist/email_templates/subscriber_message.html`中创建我们的 HTML 电子邮件正文模板：

```py
{% extends "mailinglist/email_templates/email_base.html" %}
{% load markdownify %}

{% block body %}
  {{ body | markdownify }}
{% endblock %}
```

这个模板将`Message`的 markdown 正文呈现为 HTML。我们以前使用过`markdownify`标签库来将 markdown 呈现为 HTML。我们不需要 HTML 样板或包含退订链接页脚，因为`email_base.html`已经包含了。

接下来，我们必须在`mailinglist/templates/mailinglist/email_templates/subscriber_message.txt`中创建消息模板的文本版本：

```py
{{ body }}

---

You're receiving this message because you previously subscribed to {{ mailinglist }}.

If you'd like to unsubsribe go to {{ unsubscription_link }} and click unsubscribe.

Sent with Mail Ape .
```

这个模板看起来非常相似。在这种情况下，我们只是将正文输出为未呈现的 markdown。此外，我们没有一个用于文本电子邮件的基本模板，所以我们必须手动编写包含退订链接的页脚。

恭喜！您现在已经更新了 Mail Ape，可以向邮件列表订阅者发送电子邮件。

确保在更改代码时重新启动您的`celery worker`进程。`celery worker`不像 Django`runserver`那样包含自动重启。如果我们不重新启动`worker`，那么它就不会得到任何更新的代码更改。

接下来，让我们确保我们可以在不触发 Celery 或发送实际电子邮件的情况下运行我们的测试。

# 测试使用 Celery 任务的代码

在这一点上，我们的两个模型将在创建时自动排队 Celery 任务。这可能会给我们在测试代码时造成问题，因为我们可能不希望在运行测试时运行 Celery 代理。相反，我们应该使用 Python 的`mock`库来防止在运行测试时需要运行外部系统。

我们可以使用的一种方法是使用 Python 的`@patch()`装饰器来装饰使用`Subscriber`或`Message`模型的每个测试方法。然而，这个手动过程很可能出错。让我们来看看一些替代方案。

在本节中，我们将看一下使模拟 Celery 任务更容易的两种方法：

+   使用 mixin 来防止`send_confirmation_email_to_subscriber`任务在任何测试中被排队

+   使用工厂来防止`send_confirmation_email_to_subscriber`任务被排队

通过以两种不同的方式解决相同的问题，您将了解到哪种解决方案在哪种情况下更有效。您可能会发现在项目中同时拥有这两个选项是有帮助的。

我们可以使用完全相同的方法来修补对`send_mail`的引用，以防止在测试期间发送邮件。

让我们首先使用一个 mixin 来应用一个补丁。

# 使用 TestCase mixin 来修补任务

在这种方法中，我们将创建一个 mixin，`TestCase`作者在编写`TestCase`时可以选择使用。我们在我们的 Django 代码中使用了许多 mixin 来覆盖基于类的视图的行为。现在，我们将创建一个 mixin，它将覆盖`TestCase`的默认行为。我们将利用每个测试方法之前调用`setUp()`和之后调用`tearDown()`的特性来设置我们的修补程序和模拟。

让我们在`django/mailinglist/tests.py`中创建我们的 mixin：

```py
from unittest.mock import patch

class MockSendEmailToSubscriberTask:

    def setUp(self):
        self.send_confirmation_email_patch = patch(
            'mailinglist.tasks.send_confirmation_email_to_subscriber')
        self.send_confirmation_email_mock = self.send_confirmation_email_patch.start()
        super().setUp()

    def tearDown(self):
        self.send_confirmation_email_patch.stop()
        self.send_confirmation_email_mock = None
        super().tearDown()
```

我们的 mixin 的`setUp()`方法做了三件事：

+   创建一个修补程序并将其保存为对象的属性

+   启动修补程序并将生成的模拟对象保存为对象的属性，访问模拟是重要的，这样我们以后可以断言它被调用了

+   调用父类的`setUp()`方法，以便正确设置`TestCase`

我们的 mixin 的`tearDown`方法还做了以下三件事：

+   停止修补程序

+   删除对模拟的引用

+   调用父类的`tearDown`方法来完成任何其他需要发生的清理

让我们创建一个`TestCase`来测试`SubscriberCreation`，并看看我们的新`MockSendEmailToSubscriberTask`是如何工作的。我们将创建一个测试，使用其管理器的`create()`方法创建一个`Subscriber`模型实例。`create()`调用将进而调用新的`Subscriber`实例的`save()`。`Subscriber.save()`方法应该排队一个`send_confirmation_email`任务。

让我们将我们的测试添加到`django/mailinglist/tests.py`中：

```py
from mailinglist.models import Subscriber, MailingList

from django.contrib.auth import get_user_model
from django.test import TestCase

class SubscriberCreationTestCase(
    MockSendEmailToSubscriberTask,
    TestCase):

    def test_calling_create_queues_confirmation_email_task(self):
        user = get_user_model().objects.create_user(
            username='unit test runner'
        )
        mailing_list = MailingList.objects.create(
            name='unit test',
            owner=user,
        )
        Subscriber.objects.create(
            email='unittest@example.com',
            mailing_list=mailing_list)
        self.assertEqual(self.send_confirmation_email_mock.delay.call_count, 1)
```

我们的测试断言我们在 mixin 中创建的模拟已经被调用了一次。这让我们确信当我们创建一个新的`Subscriber`时，我们将排队正确的任务。

接下来，让我们看看如何使用 Factory Boy 工厂来解决这个问题。

# 使用工厂进行修补

我们在第八章中讨论了使用 Factory Boy 工厂，*测试 Answerly*。工厂使得创建复杂对象变得更容易。现在让我们看看如何同时使用工厂和 Python 的`patch()`来防止任务被排队。

让我们在`django/mailinglist/factories.py`中创建一个`SubscriberFactory`：

```py
from unittest.mock import patch

import factory

from mailinglist.models import Subscriber

class SubscriberFactory(factory.DjangoModelFactory):
    email = factory.Sequence(lambda n: 'foo.%d@example.com' % n)

    class Meta:
        model = Subscriber

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        with patch('mailinglist.models.tasks.send_confirmation_email_to_subscriber'):
            return super()._create(model_class=model_class, *args, **kwargs)
```

我们的工厂覆盖了默认的`_create()`方法，以在调用默认的`_create()`方法之前应用任务修补程序。当默认的`_create()`方法执行时，它将调用`Subscriber.save()`，后者将尝试排队`send_confirmation_email`任务。但是，该任务将被替换为模拟。一旦模型被创建并且`_create()`方法返回，修补程序将被移除。

现在我们可以在测试中使用我们的`SubscriberFactory`。让我们在`django/mailinglist/tests.py`中编写一个测试，以验证`SubscriberManager.confirmed_subscribers_for_mailing_list()`是否正确工作：

```py
from django.contrib.auth import get_user_model
from django.test import TestCase

from mailinglist.factories import SubscriberFactory
from mailinglist.models import Subscriber, MailingList

class SubscriberManagerTestCase(TestCase):

    def testConfirmedSubscribersForMailingList(self):
        mailing_list = MailingList.objects.create(
            name='unit test',
            owner=get_user_model().objects.create_user(
                username='unit test')
        )
        confirmed_users = [
            SubscriberFactory(confirmed=True, mailing_list=mailing_list)
            for n in range(3)]
        unconfirmed_users = [
            SubscriberFactory(mailing_list=mailing_list)
            for n in range(3)]
        confirmed_users_qs = Subscriber.objects.confirmed_subscribers_for_mailing_list(
            mailing_list=mailing_list)
        self.assertEqual(len(confirmed_users), confirmed_users_qs.count())
        for user in confirmed_users_qs:
            self.assertIn(user, confirmed_users)
```

现在我们已经看到了两种方法，让我们来看一下这两种方法之间的一些权衡。

# 在修补策略之间进行选择

Factory Boy 工厂和`TestCase` mixin 都帮助我们解决了如何测试排队 Celery 任务的代码而不排队 Celery 任务的问题。让我们更仔细地看一些权衡。

使用 mixin 时的一些权衡如下：

+   修补程序在整个测试期间保持不变

+   我们可以访问生成的模拟

+   修补程序将被应用在不需要它的测试上

+   我们`TestCase`中的 mixin 由我们在代码中引用的模型所决定，这对于测试作者来说可能是一种令人困惑的间接层次

使用工厂时的一些权衡如下：

+   如果需要，我们仍然可以访问测试中的基础函数。

+   我们无法访问生成的模拟来断言（我们通常不需要它）。

+   我们不将`TestCase`的`parent class`与我们在测试方法中引用的模型连接起来。对于测试作者来说更简单。

选择使用哪种方法的最终决定取决于我们正在编写的测试。

# 总结

在本章中，我们赋予了 Mail Ape 向我们用户的`MailingList`的确认`Subscribers`发送电子邮件的能力。我们还学会了如何使用 Celery 来处理 Django 请求/响应周期之外的任务。这使我们能够处理可能需要很长时间或需要其他资源（例如 SMTP 服务器和更多内存）的任务，而不会减慢我们的 Django Web 服务器。

本章我们涵盖了各种与电子邮件和 Celery 相关的主题。我们看到了如何配置 Django 来使用 SMTP 服务器。我们使用了 Django 的`send_email()`函数来发送电子邮件。我们使用`@shared_task`装饰器创建了一个 Celery 任务。我们使用了`delay()`方法将一个 Celery 任务加入队列。最后，我们探讨了一些有用的方法来测试依赖外部资源的代码。

接下来，让我们为我们的 Mail Ape 构建一个 API，这样我们的用户就可以将其集成到他们自己的网站和应用程序中。


# 第十二章：构建 API

现在 Mail Ape 可以向我们的订阅者发送电子邮件了，让我们让用户更容易地使用 API 与 Mail Ape 集成。在本章中，我们将构建一个 RESTful JSON API，让用户可以创建邮件列表并将订阅者添加到邮件列表中。为了简化创建我们的 API，我们将使用 Django REST 框架（DRF）。最后，我们将使用 curl 在命令行上访问我们的 API。

在本章中，我们将做以下事情：

+   总结 DRF 的核心概念

+   创建`Serializer`，定义如何解析和序列化`MailingList`和`Subscriber`模型

+   创建权限类以限制 API 对`MailingList`所有者的用户

+   使用 Django REST 框架的基于类的视图来创建我们 API 的视图

+   使用 curl 通过 HTTP 访问我们的 API

+   在单元测试中测试我们的 API

让我们从 DRF 开始这一章。

# 从 Django REST 框架开始

我们将首先安装 DRF，然后审查其配置。在审查 DRF 配置时，我们将了解使其有用的功能和概念。

# 安装 Django REST 框架

让我们首先将 DRF 添加到我们的`requirements.txt`文件中：

```py
djangorestframework<3.8
```

接下来，我们可以使用`pip`进行安装：

```py
$ pip install -r requirements.txt
```

现在我们已经安装了库，让我们在`django/mailinglist/settings.py`文件中的`INSTALLED_APPS`列表中添加 DRF：

```py
INSTALLED_APPS = [
# previously unchanged list
    'rest_framework',
]
```

# 配置 Django REST 框架

DRF 通过其视图类高度可配置。但是，我们可以使用`settings.py`文件中的 DRF 设置来避免在所有 DRF 视图中重复相同的常见设置。

DRF 的所有功能都源自 DRF 处理视图的方式。DRF 提供了丰富的视图集合，扩展了`APIView`（它又扩展了 Django 的`View`类）。让我们看看 APIView 的生命周期和相关设置。

DRF 视图的生命周期执行以下操作：

1.  **在 DRF 请求对象中包装 Django 的请求对象**：DRF 有一个专门的`Request`类，它包装了 Django 的`Request`类，将在下面的部分中讨论。

1.  **执行内容协商**：查找请求解析器和响应渲染器。

1.  **执行身份验证**：检查与请求相关联的凭据。

1.  **检查权限**：检查与请求相关联的用户是否可以访问此视图。

1.  **检查节流**：检查最近是否有太多请求由此用户发出。

1.  **执行视图处理程序**：执行与视图相关的操作（例如创建资源、查询数据库等）。

1.  **渲染响应**：将响应呈现为正确的内容类型。

DRF 的自定义`Request`类与 Django 的`Request`类非常相似，只是它可以配置为解析器。DRF 视图根据视图的设置和请求的内容类型在内容协商期间找到正确的解析器。解析后的内容可以像 Django 请求与`POST`表单提交一样作为`request.data`可用。

DRF 视图还使用一个专门的`Response`类，它使用渲染而不是 Django 模板。渲染器是在内容协商步骤中选择的。

大部分前面的步骤都是使用可配置的类来执行的。通过在项目的`settings.py`中创建一个名为`REST_FRAMEWORK`的字典，可以配置 DRF。让我们回顾一些最重要的设置：

+   `DEFAULT_PARSER_CLASSES`：默认支持 JSON、表单和多部分表单。其他解析器（例如 YAML 和 MessageBuffer）可作为第三方社区包提供。

+   `DEFAULT_AUTHENTICATION_CLASSES`：默认支持基于会话的身份验证和 HTTP 基本身份验证。会话身份验证可以使在应用的前端使用 API 更容易。DRF 附带了一个令牌身份验证类。OAuth（1 和 2）支持可通过第三方社区包获得。

+   `DEFAULT_PERMISSION_CLASSES`: 默认情况下允许任何用户执行任何操作（包括更新和删除操作）。DRF 附带了一组更严格的权限，列在文档中（[`www.django-rest-framework.org/api-guide/permissions/#api-reference`](https://www.django-rest-framework.org/api-guide/permissions/#api-reference)）。我们稍后还将看一下如何在本章后面创建自定义权限类。

+   `DEFAULT_THROTTLE_CLASSES`/`DEFAULT_THROTTLE_RATES`: 默认情况下为空（未限制）。DRF 提供了一个简单的节流方案，让我们可以在匿名请求和用户请求之间设置不同的速率。

+   `DEFAULT_RENDERER_CLASSES`: 这默认为 JSON 和*browsable*模板渲染器。可浏览的模板渲染器为视图和测试视图提供了一个简单的用户界面，适合开发。

我们将配置我们的 DRF 更加严格，即使在开发中也是如此。让我们在`django/config/settings.py`中更新以下新设置`dict`：

```py
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_THROTTLE_CLASSES': (
        'rest_framework.throttling.UserRateThrottle',
        'rest_framework.throttling.AnonRateThrottle',
    ),
    'DEFAULT_THROTTLE_RATES': {
        'user': '60/minute',
        'anon': '30/minute',
    },
}
```

这个配置默认将 API 限制为经过身份验证的用户，并对他们的请求设置了节流。经过身份验证的用户在被节流之前可以每分钟发出 60 个请求。未经身份验证的用户可以每分钟发出 30 个请求。DRF 接受`second`、`minute`、`hour`或`day`的节流周期。

接下来，让我们来看一下 DRF 的`Serializer`。

# 创建 Django REST Framework 序列化器

当 DRF 解析器解析请求的主体时，解析器基本上会返回一个 Python 字典。但是，在我们可以对数据执行任何操作之前，我们需要确认数据是否有效。在以前的 Django 视图中，我们会使用 Django 表单。在 DRF 中，我们使用`Serializer`类。

DRF 的`Serializer`类与 Django 表单类非常相似。两者都涉及接收验证数据和准备模型输出。但是，`Serializer`类不知道如何呈现其数据，而 Django 表单知道。请记住，在 DRF 视图中，渲染器负责将结果呈现为 JSON 或请求协商的任何其他格式。

就像 Django 表单一样，`Serializer`可以被创建来处理任意数据或基于 Django 模型。此外，`Serializer`由一组字段组成，我们可以用来控制序列化。当`Serializer`与模型相关联时，Django REST 框架知道为哪个模型`Field`使用哪个序列化器`Field`，类似于`ModelForm`的工作方式。

让我们在`django/mailinglist/serializers.py`中为我们的`MailingList`模型创建一个`Serializer`：

```py
from django.contrib.auth import get_user_model
from rest_framework import serializers

from mailinglist.models import MailingLIst

class MailingListSerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.PrimaryKeyRelatedField(
        queryset=get_user_model().objects.all())

    class Meta:
        model = MailingList
        fields = ('url', 'id', 'name', 'subscriber_set')
        read_only_fields = ('subscriber_set', )
        extra_kwargs = {
            'url': {'view_name': 'mailinglist:api-mailing-list-detail'},
            'subscriber_set': {'view_name': 'mailinglist:api-subscriber-detail'},
        }
```

这似乎与我们编写`ModelForm`的方式非常相似；让我们仔细看一下：

+   `HyperlinkedModelSerializer`: 这是显示到任何相关模型的超链接的`Serializer`类，因此当它显示`MailingList`的相关`Subscriber`模型实例时，它将显示一个链接（URL）到该实例的详细视图。

+   `owner = serializers.PrimaryKeyRelatedField(...)`: 这改变了序列化模型的`owner`字段。`PrimaryKeyRelatedField`返回相关对象的主键。当相关模型没有序列化器或相关 API 视图时（比如 Mail Ape 中的用户模型），这是有用的。

+   `model = MailingList`: 告诉我们的`Serializer`它正在序列化哪个模型

+   `fields = ('url', 'id', ...)`: 这列出了要序列化的模型字段。`HyperlinkedModelSerializer`包括一个额外的字段`url`，它是序列化模型详细视图的 URL。就像 Django 的`ModelForm`一样，`ModelSerializer`类（例如`HyperlinkedModelSerializer`）为每个模型字段有一组默认的序列化器字段。在我们的情况下，我们决定覆盖`owner`的表示方式（参考关于`owner`属性的前一点）。

+   `read_only_fields = ('subscriber_set', )`: 这简明地列出了哪些字段不可修改。在我们的情况下，这可以防止用户篡改`Subscriber`所在的邮件列表。

+   `extra_kwargs`: 这个字典让我们为每个字段的构造函数提供额外的参数，而不覆盖整个字段。通常是为了提供`view_name`参数，这是查找视图的 URL 所需的。

+   'url': {'view_name': '...'},: 这提供了`MailingList` API 详细视图的名称。

+   'subscriber_set': {'view_name': '...'},: 这提供了`Subscriber` API 详细视图的名称。

实际上有两种标记`Serializer`字段为只读的方法。一种是使用`read_only_fields`属性，就像前面的代码示例中那样。另一种是将`read_only=True`作为`Field`类构造函数的参数传递（例如，`email = serializers.EmailField(max_length=240, read_only=True)`）。

接下来，我们将为我们的`Subscriber`模型创建两个`Serializer`。我们的两个订阅者将有一个区别：`Subscriber.email`是否可编辑。当他们创建`Subscriber`时，我们需要让用户写入`Subscriber.email`。但是，我们不希望他们在创建用户后能够更改电子邮件。

首先，让我们在`django/mailinglist/serialiers.py`中为`Subscription`模型创建一个`Serializer`：

```py
from rest_framework import serializers

from mailinglist.models import Subscriber

class SubscriberSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Subscriber
        fields = ('url', 'id', 'email', 'confirmed', 'mailing_list')
        extra_kwargs = {
            'url': {'view_name': 'mailinglist:api-subscriber-detail'},
            'mailing_list': {'view_name': 'mailinglist:api-mailing-list-detail'},
        }
```

`SubscriberSerializer`与我们的`MailingListSerializer`类似。我们使用了许多相同的元素：

+   子类化`serializers.HyperlinkedModelSerializer`

+   使用内部`Meta`类的`model`属性声明相关模型

+   使用内部`Meta`类的`fields`属性声明相关模型的字段

+   使用`extra_kwargs`字典和`view_name`键提供相关模型的详细视图名称。

对于我们的下一个`Serializer`类，我们将创建一个与`SubscriberSerializer`类似的类，但将`email`字段设置为只读；让我们将其添加到`django/mailinglist/serialiers.py`中：

```py
from rest_framework import serializers

from mailinglist.models import Subscriber

class ReadOnlyEmailSubscriberSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Subscriber
        fields = ('url', 'id', 'email', 'confirmed', 'mailing_list')
        read_only_fields = ('email', 'mailing_list',)
        extra_kwargs = {
            'url': {'view_name': 'mailinglist:api-subscriber-detail'},
            'mailing_list': {'view_name': 'mailinglist:api-mailing-list-detail'},
        }
```

这个`Serializer`让我们更新`Subscriber`是否`confirmed`，但不会让`Subscriber`的`email`字段发生变化。

现在我们已经创建了一些`Serializer`，我们可以看到它们与 Django 内置的`ModelForm`有多么相似。接下来，让我们创建一个`Permission`类，以防止用户访问彼此的`MailingList`和`Subscriber`模型实例。

# API 权限

在本节中，我们将创建一个权限类，Django REST 框架将使用它来检查用户是否可以对`MailingList`或`Subscriber`执行操作。这将执行与我们在第十章中创建的`UserCanUseMailingList`混合类非常相似的角色，开始 Mail Ape。

让我们在`django/mailinglist/permissions.py`中创建我们的`CanUseMailingList`类：

```py
from rest_framework.permissions import BasePermission

from mailinglist.models import Subscriber, MailingList

class CanUseMailingList(BasePermission):

    message = 'User does not have access to this resource.'

    def has_object_permission(self, request, view, obj):
        user = request.user
        if isinstance(obj, Subscriber):
            return obj.mailing_list.user_can_use_mailing_list(user)
        elif isinstance(obj, MailingList):
            return obj.user_can_use_mailing_list(user)
        return False
```

让我们更仔细地看一下我们的`CanUseMailingList`类中引入的一些新元素：

+   `BasePermission`: 提供权限类的基本约定，实现`has_permission()`和`has_object_permission()`方法，始终返回`True`

+   `message`: 这是`403`响应体的消息

+   `def has_object_permission(...)`: 检查请求的用户是否是相关`MailingList`的所有者

`CanUseMailingList`类不覆盖`BasePermission.has_permission(self, request, view)`，因为我们系统中的权限都是在对象级别而不是视图或模型级别。

如果您需要更动态的权限系统，您可能希望使用 Django 的内置权限系统（[`docs.djangoproject.com/en/2.0/topics/auth/default/#permissions-and-authorization`](https://docs.djangoproject.com/en/2.0/topics/auth/default/#permissions-and-authorization)）或 Django Guardian（[`github.com/django-guardian/django-guardian`](https://github.com/django-guardian/django-guardian)）。

现在我们有了`Serializer`和权限类，我们将编写我们的 API 视图。

# 创建我们的 API 视图

在本节中，我们将创建定义 Mail Ape 的 RESTful API 的实际视图。Django REST 框架提供了一系列基于类的视图，这些视图类似于 Django 的一系列基于类的视图。DRF 通用视图与 Django 通用视图的主要区别之一是它们如何将多个操作组合在一个单一的视图类中。例如，DRF 提供了`ListCreateAPIView`类，但 Django 只提供了`ListView`类和`CreateView`类。DRF 提供了`ListCreateAPIView`类，因为在`/api/v1/mailinglists`上的资源预期将提供`MailingList`模型实例的列表和创建端点。

Django REST 框架还提供了一套函数装饰器（[`www.django-rest-framework.org/api-guide/views/#function-based-views`](http://www.django-rest-framework.org/api-guide/views/#function-based-views)），这样你也可以使用基于函数的视图。

通过创建我们的 API 来学习更多关于 DRF 视图的知识，首先从`MailingList` API 视图开始。

# 创建 MailingList API 视图

Mail Ape 将提供一个 API 来创建、读取、更新和删除`MailingList`。为了支持这些操作，我们将创建以下两个视图：

+   一个扩展了`ListCreateAPIView`的`MailingListCreateListView`

+   一个扩展了`RetrieveUpdateDestroyAPIView`的`MailingListRetrieveUpdateDestroyView`

# 通过 API 列出邮件列表

为了支持获取用户的`MailingList`模型实例列表和创建新的`MailingList`模型实例，我们将在`django/mailinglist/views.py`中创建`MailingListCreateListView`类：

```py
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from mailinglist.permissions import CanUseMailingList
from mailinglist.serializers import MailingListSerializer

class MailingListCreateListView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated, CanUseMailingList)
    serializer_class = MailingListSerializer

    def get_queryset(self):
        return self.request.user.mailinglist_set.all()

    def get_serializer(self, *args, **kwargs):
        if kwargs.get('data', None):
            data = kwargs.get('data', None)
            owner = {
                'owner': self.request.user.id,
            }
            data.update(owner)
        return super().get_serializer(*args, **kwargs)
```

让我们详细查看我们的`MailingListCreateListView`类：

+   `ListCreateAPIView`：这是我们扩展的 DRF 通用视图。它通过`get_queryset()`方法返回的序列化内容响应`GET`请求。当它收到`POST`请求时，它将创建并返回一个`MailingList`模型实例。

+   `permission_classes`：这是一组权限类，按顺序调用。如果`IsAuthenticated`失败，那么`IsOwnerPermission`将不会被调用。

+   `serializer_class = MailingListSerializer`：这是该视图使用的序列化器。

+   `def get_queryset(self)`: 用于获取要序列化和返回的模型的`QuerySet`。

+   `def get_serializer(...)`: 用于获取序列化器实例。在我们的情况下，我们正在用当前登录的用户覆盖（如果有的话）从请求中收到的 owner。通过这样做，我们确保用户不能创建属于其他用户的邮件列表。这与我们可能如何在 Django 表单视图中覆盖`get_initial()`非常相似（例如，参考第十章中的`CreateMessageView`类，*开始 Mail Ape*）。

既然我们有了我们的视图，让我们在`django/mailinglist/urls.py`中添加以下代码：

```py
   path('api/v1/mailing-list', views.MailingListCreateListView.as_view(),
         name='api-mailing-list-list'),
```

现在，我们可以通过向`/mailinglist/api/v1/mailing-list`发送请求来创建和列出`MailingList`模型实例。

# 通过 API 编辑邮件列表

接下来，让我们通过在`django/mailinglist/views.py`中添加一个新视图来查看、更新和删除单个`MailingList`模型实例。

```py
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from mailinglist.permissions import CanUseMailingList
from mailinglist.serializers import MailingListSerializer
from mailinglist.models import MailingList

class MailingListRetrieveUpdateDestroyView(
    generics.RetrieveUpdateDestroyAPIView):

    permission_classes = (IsAuthenticated, CanUseMailingList)
    serializer_class = MailingListSerializer
    queryset = MailingList.objects.all()
```

`MailingListRetrieveUpdateDestroyView`看起来与我们之前的视图非常相似，但是扩展了`RetrieveUpdateDestroyAPIView`类。像 Django 内置的`DetailView`一样，`RetrieveUpdateDestroyAPIView`期望它将在请求路径中接收到`MailingList`模型实例的`pk`。`RetrieveUpdateDestroyAPIView`知道如何处理各种 HTTP 方法：

+   在`GET`请求中，它检索由`pk`参数标识的模型

+   在`PUT`请求中，它用收到的参数覆盖`pk`标识的模型的所有字段

+   在`PATCH`请求中，仅覆盖请求中收到的字段

+   在`DELETE`请求中，它删除由`pk`标识的模型

任何更新（无论是通过`PUT`还是`PATCH`）都由`MailingListSerializer`进行验证。

另一个区别是，我们为视图定义了一个`queryset`属性（`MailingList.objects.all()`），而不是一个`get_queryset()`方法。我们不需要动态限制我们的`QuerySet`，因为`CanUseMailingList`类将保护我们免受用户编辑/查看他们没有权限访问的`MailingLists`。

就像以前一样，现在我们需要将我们的视图连接到我们应用的 URLConf 中的`django/mailinglist/urls.py`，使用以下代码：

```py
   path('api/v1/mailinglist/<uuid:pk>',
         views.MailingListRetrieveUpdateDetroyView.as_view(),
         name='api-mailing-list-detail'),
```

请注意，我们从请求的路径中解析出`<uuid:pk>`参数，就像我们在一些 Django 的常规视图中对单个模型实例进行操作一样。

现在我们有了我们的`MailingList` API，让我们也允许我们的用户通过 API 管理`Subscriber`。

# 创建订阅者 API

在这一部分，我们将创建一个 API 来管理`Subscriber`模型实例。这个 API 将由两个视图支持：

+   `SubscriberListCreateView`用于列出和创建`Subscriber`模型实例

+   `SubscriberRetrieveUpdateDestroyView`用于检索、更新和删除`Subscriber`模型实例

# 列出和创建订阅者 API

`Subscriber`模型实例与`MailingList`模型实例有一个有趣的区别，即`Subscriber`模型实例与用户没有直接关联。要获取`Subscriber`模型实例的列表，我们需要知道应该查询哪个`MailingList`模型实例。`Subscriber`模型实例的创建面临同样的问题，因此这两个操作都必须接收相关的`MailingList`的`pk`来执行。

让我们从在`django/mailinglist/views.py`中创建我们的`SubscriberListCreateView`开始。

```py
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from mailinglist.permissions import CanUseMailingList
from mailinglist.serializers import SubscriberSerializer
from mailinglist.models import MailingList, Subscriber

class SubscriberListCreateView(generics.ListCreateAPIView):
    permission_classes = (IsAuthenticated, CanUseMailingList)
    serializer_class = SubscriberSerializer

    def get_queryset(self):
        mailing_list_pk = self.kwargs['mailing_list_pk']
        mailing_list = get_object_or_404(MailingList, id=mailing_list_pk)
        return mailing_list.subscriber_set.all()

    def get_serializer(self, *args, **kwargs):
        if kwargs.get('data'):
            data = kwargs.get('data')
            mailing_list = {
                'mailing_list': reverse(
                    'mailinglist:api-mailing-list-detail',
                    kwargs={'pk': self.kwargs['mailing_list_pk']})
            }
            data.update(mailing_list)
        return super().get_serializer(*args, **kwargs)
```

我们的`SubscriberListCreateView`类与我们的`MailingListCreateListView`类有很多共同之处，包括相同的基类和`permission_classes`属性。让我们更仔细地看看一些区别：

+   `serializer_class`: 使用`SubscriberSerializer`。

+   `get_queryset()`: 在返回所有相关的`Subscriber`模型实例的`QuerySet`之前，检查 URL 中标识的相关`MailingList`模型实例是否存在。

+   `get_serializer()`: 确保新的`Subscriber`与 URL 中的`MailingList`相关联。我们使用`reverse()`函数来识别相关的`MailingList`模型实例，因为`SubscriberSerializer`类继承自`HyperlinkedModelSerializer`类。`HyperlinkedModelSerializer`希望相关模型通过超链接或路径（而不是`pk`）来识别。

接下来，我们将在`django/mailinglist/urls.py`的 URLConf 中为我们的`SubscriberListCreateView`类添加一个`path()`对象：

```py
   path('api/v1/mailinglist/<uuid:mailing_list_pk>/subscribers',
         views.SubscriberListCreateView.as_view(),
         name='api-subscriber-list'),
```

在为我们的`SubscriberListCreateView`类添加一个`path()`对象时，我们需要确保有一个`mailing_list_pk`参数。这让`SubscriberListCreateView`知道要操作哪些`Subscriber`模型实例。

我们的用户现在可以通过我们的 RESTful API 向他们的`MailingList`添加`Subscriber`。向我们的 API 添加用户将触发确认电子邮件，因为`Subscriber.save()`将由我们的`SubscriberSerializer`调用。我们的 API 不需要知道如何发送电子邮件，因为我们的*fat model*是`Subscriber`行为的专家。

然而，这个 API 在 Mail Ape 中存在潜在的错误。我们当前的 API 允许我们添加一个已经确认的`Subscriber`。然而，我们的`Subscriber.save()`方法将向所有新的`Subscriber`模型实例的电子邮件地址发送确认电子邮件。这可能导致我们向已经确认的`Subscriber`发送垃圾邮件。为了解决这个 bug，让我们在`django/mailinglist/models.py`中更新`Subscriber.save`：

```py
class Subscriber(models.Model):
    # skipping unchanged attributes and methods

    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        is_new = self._state.adding or force_insert
        super().save(force_insert=force_insert, force_update=force_update,
                     using=using, update_fields=update_fields)
        if is_new and not self.confirmed:
            self.send_confirmation_email()
```

现在，我们只有在保存新的*且*未确认的`Subscriber`模型实例时才调用`self.send_confirmation_email()`。

太棒了！现在，让我们创建一个视图来检索、更新和删除`Subscriber`模型实例。

# 通过 API 更新订阅者

现在，我们已经为 Subscriber 模型实例创建了列表 API 操作，我们可以创建一个 API 视图来检索、更新和删除单个`Subscriber`模型实例。

让我们将我们的视图添加到`django/mailinglist/views.py`中：

```py
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated

from mailinglist.permissions import CanUseMailingList
from mailinglist.serializers import ReadOnlyEmailSubscriberSerializer
from mailinglist.models import Subscriber

class SubscriberRetrieveUpdateDestroyView(
    generics.RetrieveUpdateDestroyAPIView):

    permission_classes = (IsAuthenticated, CanUseMailingList)
    serializer_class = ReadOnlyEmailSubscriberSerializer
    queryset = Subscriber.objects.all()
```

我们的`SubscriberRetrieveUpdateDestroyView`与我们的`MailingListRetrieveUpdateDestroyView`视图非常相似。两者都继承自相同的`RetrieveUpdateDestroyAPIView`类，以响应 HTTP 请求并使用相同的`permission_classes`列表提供核心行为。但是，`SubscriberRetrieveUpdateDestroyView`有两个不同之处：

+   `serializer_class = ReadOnlyEmailSubscriberSerializer`：这是一个不同的`Serializer`。在更新的情况下，我们不希望用户能够更改电子邮件地址。

+   `queryset = Subscriber.objects.all()`：这是所有`Subscribers`的`QuerySet`。我们不需要限制`QuerySet`，因为`CanUseMailingList`将防止未经授权的访问。

接下来，让我们确保我们可以通过将其添加到`django/mailinglist/urls.py`中的`urlpatterns`列表来路由到它：

```py
   path('api/v1/subscriber/<uuid:pk>',
         views.SubscriberRetrieveUpdateDestroyView.as_view(),
         name='api-subscriber-detail'),
```

现在我们有了我们的观点，让我们尝试在命令行上与它进行交互。

# 运行我们的 API

在本节中，我们将在命令行上运行 Mail Ape，并使用`curl`在命令行上与我们的 API 进行交互，`curl`是一个用于与服务器交互的流行命令行工具。在本节中，我们将执行以下功能：

+   在命令行上创建用户

+   在命令行上创建邮件列表

+   在命令行上获取`MailingList`列表

+   在命令行上创建`Subscriber`

+   在命令行上获取`Subscriber`列表

让我们首先使用 Django `manage.py shell`命令创建我们的用户：

```py
$ cd django
$ python manage.py shell
Python 3.6.3 (default) 
Type 'copyright', 'credits' or 'license' for more information
IPython 6.2.1 -- An enhanced Interactive Python. Type '?' for help.
In [1]: from django.contrib.auth import get_user_model

In [2]: user = get_user_model().objects.create_user(username='user', password='secret')
In [3]: user.id
2
```

如果您已经使用 Web 界面注册了用户，可以使用该用户。此外，在生产中永远不要使用`secret`作为您的密码。

现在我们有了一个可以在命令行上使用的用户，让我们启动本地 Django 服务器：

```py
$ cd django
$ python manage.py runserver
```

现在我们的服务器正在运行，我们可以打开另一个 shell 并获取我们用户的`MailingList`列表：

```py
$ curl "http://localhost:8000/mailinglist/api/v1/mailing-list" \
     -u 'user:secret'
[]
```

让我们仔细看看我们的命令：

+   `curl`：这是我们正在使用的工具。

+   `"http://... api/v1/mailing-list"`：这是我们发送请求的 URL。

+   `-u 'user:secret'`：这是基本的身份验证凭据。`curl`会正确地对这些进行编码。

+   `[]`：这是服务器返回的空 JSON 列表。在我们的情况下，`user`还没有任何`MailingList`。

我们得到了一个 JSON 响应，因为 Django REST 框架默认配置为使用 JSON 渲染。

要为我们的用户创建一个`MailingList`，我们需要发送这样的`POST`请求：

```py
$ curl -X "POST" "http://localhost:8000/mailinglist/api/v1/mailing-list" \
     -H 'Content-Type: application/json; charset=utf-8' \
     -u 'user:secret' \
     -d $'{
  "name": "New List"
}'
{"url":"http://localhost:8000/mailinglist/api/v1/mailinglist/cd983e25-c6c8-48fa-9afa-1fd5627de9f1","id":"cd983e25-c6c8-48fa-9afa-1fd5627de9f1","name":"New List","owner":2,"subscriber_set":[]}
```

这是一个更长的命令，结果也更长。让我们来看看每个新参数：

+   `-H 'Content-Type: application/json; charset=utf-8' \`：这添加了一个新的 HTTP `Content-Type`头，告诉服务器将正文解析为 JSON。

+   `-d $'{ ... }'`：这指定了请求的正文。在我们的情况下，我们正在发送一个 JSON 对象，其中包含新邮件列表的名称。

+   `"url":"http://...cd983e25-c6c8-48fa-9afa-1fd5627de9f1"`：这是新`MailingLIst`的完整详细信息的 URL。

+   `"name":"New List"`：这显示了我们请求的新列表的名称。

+   `"owner":2`：这显示了列表所有者的 ID。这与我们之前创建的用户的 ID 匹配，并包含在此请求中（使用`-u`）。

+   `"subscriber_set":[]`：这显示了此邮件列表中没有订阅者。

现在我们可以重复我们最初的请求来列出`MailingList`，并检查我们的新`MailingList`是否包含在内：

```py
$ curl "http://localhost:8000/mailinglist/api/v1/mailing-list" \
     -u 'user:secret'
[{"url":"http://localhost:8000/mailinglist/api/v1/mailinglist/cd983e25-c6c8-48fa-9afa-1fd5627de9f1","id":"cd983e25-c6c8-48fa-9afa-1fd5627de9f1","name":"New List","owner":2,"subscriber_set":[]}]
```

看到我们可以在开发中运行我们的服务器和 API 是很好的，但我们不想总是依赖手动测试。让我们看看如何自动化测试我们的 API。

如果您想测试创建订阅者，请确保您的 Celery 代理（例如 Redis）正在运行，并且您有一个工作程序来消耗任务以获得完整的体验。

# 测试您的 API

API 通过让用户自动化他们与我们服务的交互来为我们的用户提供价值。当然，DRF 也帮助我们自动化测试我们的代码。

DRF 为我们讨论的所有常见 Django 工具提供了替代品第八章，*测试 Answerly*：

+   Django 的`RequestFactory`类的`APIRequestFactory`

+   Django 的`Client`类的`APIClient`

+   Django 的`TestCase`类的`APITestCase`

`APIRequestFactory`和`APIClient`使得更容易发送格式化为我们的 API 的请求。例如，它们提供了一种简单的方法来为不依赖于基于会话的认证的请求设置凭据。否则，这两个类的作用与它们的默认 Django 等效类相同。

`APITestCase`类简单地扩展了 Django 的`TestCase`类，并用`APIClient`替换了 Django 的`Client`。

让我们看一个例子，我们可以添加到`django/mailinglist/tests.py`中：

```py
class ListMailingListsWithAPITestCase(APITestCase):

    def setUp(self):
        password = 'password'
        username = 'unit test'
        self.user = get_user_model().objects.create_user(
            username=username,
            password=password
        )
        cred_bytes = '{}:{}'.format(username, password).encode('utf-8')
        self.basic_auth = base64.b64encode(cred_bytes).decode('utf-8')

    def test_listing_all_my_mailing_lists(self):
        mailing_lists = [
            MailingList.objects.create(
                name='unit test {}'.format(i),
                owner=self.user)
            for i in range(3)
        ]

        self.client.credentials(
            HTTP_AUTHORIZATION='Basic {}'.format(self.basic_auth))

        response = self.client.get('/mailinglist/api/v1/mailing-list')

        self.assertEqual(200, response.status_code)
        parsed = json.loads(response.content)
        self.assertEqual(3, len(parsed))

        content = str(response.content)
        for ml in mailing_lists:
            self.assertIn(str(ml.id), content)
            self.assertIn(ml.name, content)
```

让我们更仔细地看一下在我们的`ListMailingListsWithAPITestCase`类中引入的新代码：

+   `class ListMailingListsWithAPITestCase(APITestCase)`: 这使得`APITestCase`成为我们的父类。`APITestCase`类基本上是一个`TestCase`类，只是用`APIClient`对象代替了常规的 Django `Client`对象分配给`client`属性。我们将使用这个类来测试我们的视图。

+   `base64.b64encode(...)`: 这对我们的用户名和密码进行了 base64 编码。我们将使用这个来提供一个 HTTP 基本认证头。我们必须使用`base64.b64encode()`而不是`base64.base64()`，因为后者会引入空格来视觉上分隔长字符串。此外，我们需要对我们的字符串进行`encode`/`decode`，因为`b64encode()`操作`byte`对象。

+   `client.credentials()`: 这让我们设置一个认证头，以便将来由这个`client`对象发送所有的请求。在我们的情况下，我们发送了一个 HTTP 基本认证头。

+   `json.loads(response.content)`: 这解析了响应内容体并返回一个 Python 列表。

+   `self.assertEqual(3, len(parsed))`: 这确认了解析列表中的项目数量是正确的。

如果我们使用`self.client`发送第二个请求，我们不需要重新认证，因为`client.credentials()`会记住它接收到的内容，并继续将其传递给所有请求。我们可以通过调用`client.credentials()`来清除凭据。

现在，我们知道如何测试我们的 API 代码了！

# 摘要

在本章中，我们介绍了如何使用 Django REST 框架为我们的 Django 项目创建 RESTful API。我们看到 Django REST 框架使用了与 Django 表单和 Django 通用视图类似的原则。我们还使用了 Django REST 框架中的一些核心类，我们使用了`ModelSerializer`来构建基于 Django 模型的`Serializer`，并使用了`ListCreateAPIView`来创建一个可以列出和创建 Django 模型的视图。我们使用了`RetrieveUpdateDestroyAPIView`来管理基于其主键的 Django 模型实例。

接下来，我们将使用亚马逊网络服务将我们的代码部署到互联网上。


# 第十三章：部署 Mail Ape

在本章中，我们将在**亚马逊网络服务**（**AWS**）云中的虚拟机上部署 Mail Ape。AWS 由许多不同的服务组成。我们已经讨论过使用 S3 和在 AWS 中启动容器。在本章中，我们将使用更多的 AWS 服务。我们将使用**关系数据库服务（RDS）**来运行 PostgreSQL 数据库服务器。我们将使用**简单队列服务（SQS）**来运行 Celery 消息队列。我们将使用**弹性计算云（EC2）**在云中运行虚拟机。最后，我们将使用 CloudFormation 来定义我们的基础设施为代码。

在本章中，我们将做以下事情：

+   分离生产和开发设置

+   使用 Packer 创建我们发布的 Amazon Machine Image

+   使用 CloudFormation 定义基础设施为代码

+   使用命令行将 Mail Ape 部署到 AWS

让我们首先分离我们的生产开发设置。

# 分离开发和生产

到目前为止，我们保留了一个需求文件和一个`settings.py`文件。这使得开发很方便。然而，我们不能在生产中使用我们的开发设置。

当前的最佳实践是每个环境使用单独的文件。然后每个环境的文件导入一个具有共享值的通用文件。我们将为我们的需求和设置文件使用这种模式。

让我们首先分离我们的需求文件。

# 分离我们的需求文件

为了分离我们的需求，我们将删除现有的`requirements.txt`文件，并用通用、开发和生产需求文件替换它。在删除`requirements.txt`之后，让我们在项目的根目录下创建`requirements.common.txt`：

```py
django<2.1
psycopg2<2.8
django-markdownify==0.3.0
django-crispy-forms==1.7.0
celery<4.2
django-celery-results<2.0
djangorestframework<3.8
factory_boy<3.0
```

接下来，让我们为`requirements.development.txt`创建一个需求文件：

```py
-r requirements.common.txt
celery[redis]
```

由于我们只在开发设置中使用 Redis，我们将在开发需求文件中保留该软件包。

我们将把我们的生产需求放在项目的根目录下的`requirements.production.txt`中：

```py
-r requirements.common.txt
celery[sqs]
boto3
pycurl
```

为了让 Celery 与 SQS（AWS 消息队列服务）配合工作，我们需要安装 Celery SQS 库（`celery[sqs]`）。我们还将安装`boto3`，Python AWS 库，和`pycurl`，Python 的`curl`实现。

接下来，让我们分离我们的 Django 设置文件。

# 创建通用、开发和生产设置

与我们之前的章节一样，在我们将设置分成三个文件之前，我们将通过将当前的`settings.py`重命名为`common_settings.py`然后进行一些更改来创建`common_settings.py`。

让我们将`DEBUG = False`更改为，以便没有新的设置文件可以*意外*处于调试模式。然后，让我们通过更新`SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')`从环境变量中获取密钥。

在数据库配置中，我们可以删除所有凭据，但保留`ENGINE`（以明确表明我们打算在所有地方使用 Postgres）：

```py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
    }
}
```

接下来，让我们在`django/config/development_settings.py`中创建一个开发设置文件：

```py
from .common_settings import *

DEBUG = True

SECRET_KEY = 'secret key'

DATABASES['default']['NAME'] = 'mailape'
DATABASES['default']['USER'] = 'mailape'
DATABASES['default']['PASSWORD'] = 'development'
DATABASES['default']['HOST'] = 'localhost'
DATABASES['default']['PORT'] = '5432'

MAILING_LIST_FROM_EMAIL = 'mailape@example.com'
MAILING_LIST_LINK_DOMAIN = 'http://localhost'

EMAIL_HOST = 'smtp.example.com'
EMAIL_HOST_USER = 'username'
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_PORT = 587
EMAIL_USE_TLS = True

CELERY_BROKER_URL = 'redis://localhost:6379/0'
```

记得你需要将你的`MAILING_LIST_FROM_EMAIL`，`EMAIL_HOST`和`EMAIL_HOST_USER`更改为正确的开发数值。

接下来，让我们将我们的生产设置放在`django/config/production_settings.py`中：

```py
from .common_settings import *

DEBUG = False

assert SECRET_KEY is not None, (
    'Please provide DJANGO_SECRET_KEY environment variable with a value')

ALLOWED_HOSTS += [
    os.getenv('DJANGO_ALLOWED_HOSTS'),
]

DATABASES['default'].update({
    'NAME': os.getenv('DJANGO_DB_NAME'),
    'USER': os.getenv('DJANGO_DB_USER'),
    'PASSWORD': os.getenv('DJANGO_DB_PASSWORD'),
    'HOST': os.getenv('DJANGO_DB_HOST'),
    'PORT': os.getenv('DJANGO_DB_PORT'),
})

LOGGING['handlers']['main'] = {
    'class': 'logging.handlers.WatchedFileHandler',
    'level': 'DEBUG',
    'filename': os.getenv('DJANGO_LOG_FILE')
}

MAILING_LIST_FROM_EMAIL = os.getenv('MAIL_APE_FROM_EMAIL')
MAILING_LIST_LINK_DOMAIN = os.getenv('DJANGO_ALLOWED_HOSTS')

EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
EMAIL_PORT = os.getenv('EMAIL_HOST_PORT')
EMAIL_USE_TLS = os.getenv('EMAIL_HOST_TLS', 'false').lower() == 'true'

CELERY_BROKER_TRANSPORT_OPTIONS = {
    'region': 'us-west-2',
    'queue_name_prefix': 'mailape-',
CELERY_BROKER_URL = 'sqs://'
}
```

我们的生产设置文件大部分数值都来自环境变量，这样我们就不会将生产数值提交到服务器中。有三个设置我们需要审查，如下：

+   `MAILING_LIST_LINK_DOMAIN`：这是我们邮件中链接的域。在我们的情况下，在前面的代码片段中，我们使用了与我们添加到`ALLOWED_HOSTS`列表中的相同域，确保我们正在为链接指向的域提供服务。

+   `CELERY_BROKER_TRANSPORT_OPTIONS`：这是一个配置 Celery 使用正确的 SQS 队列的选项字典。我们需要将区域设置为`us-west-2`，因为我们整个生产部署将在该区域。默认情况下，Celery 将希望使用一个名为`celery`的队列。然而，我们不希望该名称与我们可能部署的其他 Celery 项目发生冲突。为了防止名称冲突，我们将配置 Celery 使用`mailape-`前缀。

+   `CELERY_BROKER_URL`：这告诉 Celery 要使用哪个代理。在我们的情况下，我们使用 SQS。我们将使用 AWS 的基于角色的授权为我们的虚拟机提供对 SQS 的访问权限，这样我们就不必提供任何凭据。

现在我们已经创建了我们的生产设置，让我们在 AWS 云中创建我们的基础设施。

# 在 AWS 中创建基础设施堆栈

为了在 AWS 上托管应用程序，我们需要确保我们已经设置了一些基础设施。我们需要以下内容：

+   一个 PostgreSQL 服务器

+   安全组，以打开网络端口，以便我们可以访问我们的数据库和 Web 服务器

+   一个 InstanceProfile，为我们部署的虚拟机提供对 SQS 的访问权限

我们可以使用 AWS Web 控制台或使用命令行界面创建所有这些。然而，随着时间的推移，如果我们依赖运行时调整，很难跟踪我们的基础设施是如何配置的。如果我们能够描述我们需要的基础设施在文件中，就像我们跟踪我们的代码一样，那将会更好。

AWS 提供了一个名为 CloudFormation 的服务，它让我们可以将基础设施视为代码。我们将使用 YAML（也可以使用 JSON，但我们将使用 YAML）在 CloudFormation 模板中定义我们的基础设施。然后，我们将执行我们的 CloudFormation 模板来创建一个 CloudFormation 堆栈。CloudFormation 堆栈将与 AWS 云中的实际资源相关联。如果我们删除 CloudFormation 堆栈，相关资源也将被删除。这使我们可以简单地控制我们对 AWS 资源的使用。

让我们在`cloudformation/infrastructure.yaml`中创建我们的 CloudFormation 模板。每个 CloudFormation 模板都以`Description`和模板格式版本信息开始。让我们从以下内容开始我们的文件：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
```

我们的 CloudFormation 模板将包括以下三个部分：

+   `Parameters`：这是我们将在运行时传递的值。这个块是可选的，但很有用。在我们的情况下，我们将传递主数据库密码，而不是在我们的模板中硬编码它。

+   `Resources`：这是我们将描述的堆栈中包含的具体资源。这将描述我们的数据库服务器、SQS 队列、安全组和 InstanceProfile。

+   `Outputs`：这是我们将描述的值，以便更容易引用我们创建的资源。这个块是可选的，但很有用。我们将提供我们的数据库服务器地址和我们创建的 InstanceProfile 的 ID。

让我们从创建 CloudFormation 模板的`Parameters`块开始。

# 在 CloudFormation 模板中接受参数

为了避免在 CloudFormation 模板中硬编码值，我们可以接受参数。这有助于我们避免在模板中硬编码敏感值（如密码）。

让我们添加一个参数来接受数据库服务器主用户的密码：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
Parameters:
  MasterDBPassword:
    Description: Master Password for the RDS instance
    Type: String
```

这为我们的模板添加了一个`MasterDBPassword`参数。我们以后将能够引用这个值。CloudFormation 模板让我们为参数添加两个信息：

+   `Description`：这不被 CloudFormation 使用，但对于必须维护我们的基础设施的人来说是有用的。

+   `Type`：CloudFormation 在执行我们的模板之前使用这个来检查我们提供的值是否有效。在我们的情况下，密码是一个`String`。

接下来，让我们添加一个`Resources`块来定义我们基础设施中需要的 AWS 资源。

# 列出我们基础设施中的资源

接下来，我们将在`cloudformation/infrastructure.yaml`中的 CloudFormation 模板中添加一个`Resources`块。我们的基础设施模板将定义五个资源：

+   安全组，将打开网络端口，允许我们访问数据库和 Web 服务器

+   我们的数据库服务器

+   我们的 SQS 队列

+   允许访问 SQS 的角色

+   InstanceProfile，让我们的 Web 服务器假定上述角色

让我们首先创建安全组，这将打开我们将访问数据库和 Web 服务器的网络端口。

# 添加安全组

在 AWS 中，SecurityGroup 定义了一组网络访问规则，就像网络防火墙一样。默认情况下，启动的虚拟机可以*发送*数据到任何网络端口，但不能在任何网络端口上*接受*连接。这意味着我们无法使用 SSH 或 HTTP 进行连接；让我们解决这个问题。

让我们在`cloudformation/infrastructure.yaml`中的 CloudFormation 模板中更新三个新的安全组：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
Parameters:
  ...
Resources:
  SSHSecurityGroup:
    Type: "AWS::EC2::SecurityGroup"
    Properties:
      GroupName: ssh-access
      GroupDescription: permit ssh access
      SecurityGroupIngress:
        -
          IpProtocol: "tcp"
          FromPort: "22"
          ToPort: "22"
          CidrIp: "0.0.0.0/0"
  WebSecurityGroup:
    Type: "AWS::EC2::SecurityGroup"
    Properties:
      GroupName: web-access
      GroupDescription: permit http access
      SecurityGroupIngress:
        -
          IpProtocol: "tcp"
          FromPort: "80"
          ToPort: "80"
          CidrIp: "0.0.0.0/0"
  DatabaseSecurityGroup:
    Type: "AWS::EC2::SecurityGroup"
    Properties:
      GroupName: db-access
      GroupDescription: permit db access
      SecurityGroupIngress:
        -
          IpProtocol: "tcp"
          FromPort: "5432"
          ToPort: "5432"
          CidrIp: "0.0.0.0/0"
```

在前面的代码块中，我们定义了三个新的安全组，以打开端口`22`（SSH），`80`（HTTP）和`5432`（默认的 Postgres 端口）。

让我们更仔细地看一下 CloudFormation 资源的语法。每个资源块必须具有`Type`和`Properties`属性。`Type`属性告诉 CloudFormation 这个资源描述了什么。`Properties`属性描述了这个特定资源的设置。

我们使用以下属性的安全组：

+   `GroupName`：这提供了人性化的名称。这是可选的，但建议使用。 CloudFormation 可以为我们生成名称。安全组名称必须对于给定帐户是唯一的（例如，我不能有两个`db-access`组，但您和我每个人都可以有一个`db-access`组）。

+   `GroupDescription`：这是组用途的人性化描述。它是必需的。

+   `SecurityGroupIngress`：这是一个端口列表，用于接受此组中虚拟机的传入连接。

+   `FromPort`/`ToPort`：通常，这两个设置将具有相同的值，即您希望能够连接的网络端口。 `FromPort`是我们将连接的端口。 `ToPort`是服务正在监听的 VM 端口。

+   `CidrIp`：这是一个 IPv4 范围，用于接受连接。 `0.0.0.0/0`表示接受所有连接。

接下来，让我们将数据库服务器添加到我们的资源列表中。

# 添加数据库服务器

AWS 提供关系数据库服务器作为一种称为**关系数据库服务**（**RDS**）的服务。要在 AWS 上创建数据库服务器，我们将创建一个新的 RDS 虚拟机（称为*实例*）。一个重要的事情要注意的是，当我们启动一个 RDS 实例时，我们可以连接到服务器上的 PostgreSQL 数据库，但我们没有 shell 访问权限。我们必须在不同的虚拟机上运行 Django。

让我们在`cloudformation/infrastructure.yaml`中的 CloudFormation 模板中添加一个 RDS 实例：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
Parameters:
  ...
Resources:
  ...
  DatabaseServer:
    Type: AWS::RDS::DBInstance
    Properties:
      DBName: mailape
      DBInstanceClass: db.t2.micro
      MasterUsername: master
      MasterUserPassword: !Ref MasterDBPassword
      Engine: postgres
      AllocatedStorage: 20
      PubliclyAccessible: true
      VPCSecurityGroups: !GetAtt DatabaseSecurityGroup.GroupId
```

我们的新 RDS 实例条目是`AWS::RDS::DBInstance`类型。让我们回顾一下我们设置的属性：

+   `DBName`：这是*服务器*的名称，而不是其中运行的任何数据库的名称。

+   `DBInstanceClass`：这定义了服务器虚拟机的内存和处理能力。在撰写本书时，`db.t2.micro`是首年免费套餐的一部分。

+   `MasterUsername`：这是服务器上特权管理员帐户的用户名。

+   `MasterUserPassword`：这是特权管理员帐户的密码

+   `!Ref MasterDBPassword`：这是引用`MasterDBPassword`参数的快捷语法。这样可以避免硬编码数据库服务器的管理员密码。

+   `Engine`：这是我们想要的数据库服务器类型；在我们的情况下，`postgres`将为我们提供一个 PostgreSQL 服务器。

+   `AllocatedStorage`：这表示服务器应该具有多少存储空间，以 GB 为单位。

+   `PubliclyAccessible`：这表示服务器是否可以从 AWS 云外部访问。

+   `VPCSecurityGroups`：这是一个 SecurityGroups 列表，指示哪些端口是打开和可访问的。

+   `!GetAtt DatabaseSecurityGroup.GroupId`: 这返回`DatabaseSecurityGroup`安全组的`GroupID`属性。

这个块还向我们介绍了 CloudFormation 的`Ref`和`GetAtt`函数。这两个函数让我们能够引用我们 CloudFormation 堆栈的其他部分，这是非常重要的。`Ref`让我们使用我们的`MasterDBPassword`参数作为我们数据库服务器的`MasterUserPassword`的值。`GetAtt`让我们在我们的数据库服务器的`VPCSercurityGroups`列表中引用我们 AWS 生成的`DatabaseSecurityGroup`的`GroupId`属性。

AWS CloudFormation 提供了各种不同的函数，以使构建模板更容易。它们在 AWS 在线文档中有记录（[`docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference.html`](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference.html)）。

接下来，让我们创建 Celery 将使用的 SQS 队列。

# 为 Celery 添加队列

SQS 是 AWS 消息队列服务。使用 SQS，我们可以创建一个与 Celery 兼容的消息队列，而无需维护。SQS 可以快速扩展以处理我们发送的任何请求数量。

要定义我们的队列，请将其添加到`cloudformation/infrastructure.yaml`中的`Resources`块中：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
Parameters:
  ...
Resources:
  ...
  MailApeQueue:
    Type: "AWS::SQS::Queue"
    Properties:
      QueueName: mailape-celery
```

我们的新资源是`AWS::SQS::Queue`类型，并且有一个属性`QueueName`。

接下来，让我们创建一个角色和 InstanceProfile，让我们的生产服务器访问我们的 SQS 队列。

# 为队列访问创建角色

早些时候，在*添加安全组*部分，我们讨论了创建 SecurityGroups 以打开网络端口，以便我们可以进行网络连接。为了管理 AWS 资源之间的访问，我们需要使用基于角色的授权。在基于角色的授权中，我们定义一个角色，可以被分配该角色的人（假定该角色），以及该角色可以执行哪些操作。为了使我们的 Web 服务器使用该角色，我们需要创建一个与该角色关联的 EC2 实例配置文件。

让我们首先在`cloudformation/infrastructure.yaml`中添加一个角色：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
Parameters:
  ...
Resources:
  ...
   SQSAccessRole:
    Type: "AWS::IAM::Role"
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          -
            Effect: "Allow"
            Principal:
              Service:
                - "ec2.amazonaws.com"
            Action:
              - "sts:AssumeRole"
      Policies:
        -
          PolicyName: "root"
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              -
                Effect: Allow
                Action: "sqs:*"
                Resource: !GetAtt MailApeQueue.Arn
              -
                Effect: Allow
                Action: sqs:ListQueues
                Resource: "*"
```

我们的新块是`AWS::IAM::Role`类型。IAM 是 AWS 身份和访问管理服务的缩写。我们的角色由以下两个属性组成：

+   `AssumeRolePolicyDocument`：这定义了谁可以被分配这个角色。在我们的情况下，我们说这个角色可以被亚马逊的 EC2 服务中的任何对象假定。稍后，我们将在我们的 EC2 实例中使用它。

+   `Policies`：这是该角色允许（或拒绝）的操作列表。在我们的情况下，我们允许在我们之前定义的 SQS 队列上执行所有 SQS 操作（`sqs:*`）。我们通过使用`GetAtt`函数引用我们的队列来获取其`Arn`，Amazon 资源名称（ARN）。ARN 是亚马逊为亚马逊云上的每个资源提供全局唯一 ID 的方式。

现在我们有了我们的角色，我们可以将其与一个`InstanceProfile`资源关联起来，该资源可以与我们的 Web 服务器关联起来：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
Parameters:
  ...
Resources:
  ...
  SQSClientInstance:
    Type: "AWS::IAM::InstanceProfile"
    Properties:
      Roles:
        - !Ref SQSAccessRole
```

我们的新 InstanceProfile 是`AWS::IAM::InstanceProfile`类型，并且需要一个关联角色的列表。在我们的情况下，我们只需使用`Ref`函数引用我们之前创建的`SQSAccessRole`。

现在我们已经创建了我们的基础设施资源，让我们输出我们的数据库的地址和我们的`InstanceProfile`资源的 ARN。

# 输出我们的资源信息

CloudFormation 模板可以有一个输出块，以便更容易地引用创建的资源。在我们的情况下，我们将输出我们的数据库服务器的地址和`InstanceProfile`的 ARN。

让我们在`cloudformation/infrastructure.yaml`中更新我们的 CloudFormation 模板：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape Infrastructure
Parameters:
  ...
Resources:
  ...
Outputs:
  DatabaseDNS:
    Description: Public DNS of RDS database
    Value: !GetAtt DatabaseServer.Endpoint.Address
  SQSClientProfile:
    Description: Instance Profile for EC2 instances that need SQS Access
    Value: !GetAtt SQSClientInstance.Arn
```

在上述代码中，我们使用`GetAtt`函数返回我们的`DatabaseServer`资源的地址和我们的`SQSClientInstance` `InstanceProfile`资源的 ARN。

# 执行我们的模板以创建我们的资源

现在我们已经创建了我们的`CloudFormation`模板，我们可以创建一个`CloudFormation`堆栈。当我们告诉 AWS 创建我们的`CloudFormation`堆栈时，它将在我们的模板中创建所有相关资源。

要创建我们的模板，我们需要以下两件事情：

+   AWS 命令行界面（CLI）

+   AWS 访问密钥/秘密密钥对

我们可以使用`pip`安装 AWS CLI：

```py
$ pip install awscli
```

要获取（或创建）您的访问密钥/秘密密钥对，您需要访问 AWS 控制台的安全凭据部分。

然后我们需要使用我们的密钥和区域配置 AWS 命令行工具。`aws`命令提供了一个交互式的`configure`子命令来完成这个任务。让我们在命令行上运行它：

```py
$ aws configure
AWS Access Key ID [None]: <Your ACCESS key>
AWS Secret Access Key [None]: <Your secret key>
Default region name [None]: us-west-2
Default output format [None]: json
```

`aws configure`命令将您输入的值存储在主目录中的`.aws`目录中。

有了这些设置，我们现在可以创建我们的堆栈：

```py
$ aws cloudformation create-stack \
    --stack-name "infrastructure" \
    --template-body "file:///path/to/mailape/cloudformation/infrastrucutre.yaml" \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameters \
      "ParameterKey=MasterDBPassword,ParameterValue=password" \
    --region us-west-2
```

创建堆栈可能需要一些时间，因此该命令在等待成功时返回。让我们更仔细地看看我们的`create-stack`命令：

+   `--stack-name`：这是我们正在创建的堆栈的名称。堆栈名称必须在每个帐户中是唯一的。

+   `--template-body`：这要么是模板本身，要么是我们的情况下模板文件的`file://` URL。请记住，`file://` URL 需要文件的绝对路径。

+   `--capabilities CAPABILITY_NAMED_IAM`：这对于创建或影响**Identity and Access Management**（**IAM**）服务的模板是必需的。这可以防止意外影响访问管理服务。

+   `--parameters`：这允许我们传递模板参数的值。在我们的案例中，我们将数据库的主密码设置为`password`，这不是一个安全的值。

+   `--region`：AWS 云组织为世界各地的一组区域。在我们的案例中，我们使用的是位于美国俄勒冈州一系列数据中心的`us-west-2`。

请记住，您需要为数据库设置一个安全的主密码。

要查看堆栈创建的进度，我们可以使用 AWS Web 控制台（[`us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2`](https://us-west-2.console.aws.amazon.com/cloudformation/home?region=us-west-2)）或使用命令行进行检查：

```py
$ aws cloudformation describe-stacks \
    --stack-name "infrastructure" \
    --region us-west-2
```

当堆栈完成创建相关资源时，它将返回类似于这样的结果：

```py
{
    "Stacks": [
        {
            "StackId": "arn:aws:cloudformation:us-west-2:XXX:stack/infrastructure/NNN",
            "StackName": "infrastructure",
            "Description": "Mail Ape Infrastructure",
            "Parameters": [
                {
                    "ParameterKey": "MasterDBPassword",
                    "ParameterValue": "password"
                }
            ],
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [
                {
                    "OutputKey": "SQSClientProfile",
                    "OutputValue": "arn:aws:iam::XXX:instance-profile/infrastructure-SQSClientInstance-XXX",
                    "Description": "Instance Profile for EC2 instances that need SQS Access"
                },
                {
                    "OutputKey": "DatabaseDNS",
                    "OutputValue": "XXX.XXX.us-west-2.rds.amazonaws.com",
                    "Description": "Public DNS of RDS database"
                }
            ],
        }
    ]
}
```

在`describe-stack`结果中特别注意的两件事是：

+   `Parameters`键下的对象将以明文显示我们的主数据库密码

+   `Outputs`对象键显示了我们的`InstanceProfile`资源的 ARN 和数据库服务器的地址

在所有先前的代码中，我已经用 XXX 替换了特定于我的帐户的值。您的输出将有所不同。

如果您想要删除与您的堆栈关联的资源，您可以直接删除该堆栈：

```py
$ aws cloudformation delete-stack --stack-name "infrastructure"
```

接下来，我们将构建一个 Amazon Machine Image，用于在 AWS 中运行 Mail Ape。

# 使用 Packer 构建 Amazon Machine Image

现在我们的基础设施在 AWS 中运行，让我们构建我们的 Mail Ape 服务器。在 AWS 中，我们可以启动一个官方的 Ubuntu VM，按照第九章中的步骤，*部署 Answerly*，并让我们的 Mail Ape 运行。但是，AWS 将 EC2 实例视为*临时*。如果 EC2 实例被终止，那么我们将不得不启动一个新实例并重新配置它。有几种方法可以缓解这个问题。我们将通过为我们的发布构建一个新的**Amazon Machine Image**（**AMI**）来解决临时 EC2 实例的问题。然后，每当我们使用该 AMI 启动 EC2 实例时，它将已经完美地配置好。

我们将使用 HashiCorp 的 Packer 工具自动构建我们的 AMI。 Packer 为我们提供了一种从 Packer 模板创建 AMI 的方法。 Packer 模板是一个定义了配置 EC2 实例到我们期望状态并保存 AMI 所需步骤的 JSON 文件。为了运行我们的 Packer 模板，我们还将编写一系列 shell 脚本来配置我们的 AMI。使用 Packer 这样的工具，我们可以自动构建一个新的发布 AMI。

让我们首先在我们的机器上安装 Packer。

# 安装 Packer

从[`www.packer.io`](https://www.packer.io)下载页面获取 Packer。 Packer 适用于所有主要平台。

接下来，我们将创建一个脚本来创建我们在生产中依赖的目录。

# 创建一个脚本来创建我们的目录结构

我们将编写的第一个脚本将为我们的所有代码创建目录。让我们在`scripts/make_aws_directories.sh`中添加以下脚本到我们的项目中：

```py
#!/usr/bin/env bash
set -e

sudo mkdir -p \
    /mailape/ubuntu \
    /mailape/apache \
    /mailape/django \
    /var/log/celery \
    /etc/mailape \
    /var/log/mailape

sudo chown -R ubuntu /mailape
```

在上述代码中，我们使用`mkdir`来创建目录。接下来，我们希望让`ubuntu`用户可以写入`/mailape`目录，所以我们递归地`chown`了`/mailape`目录。

所以，让我们创建一个脚本来安装我们需要的 Ubuntu 软件包。

# 创建一个脚本来安装我们所有的软件包

在我们的生产环境中，我们将不仅需要安装 Ubuntu 软件包，还需要安装我们已经列出的 Python 软件包。首先，让我们在`ubuntu/packages.txt`中列出所有我们的 Ubuntu 软件包：

```py
python3
python3-pip
python3-dev
virtualenv
apache2
libapache2-mod-wsgi-py3
postgresql-client
libcurl4-openssl-dev
libssl-dev
```

接下来，让我们创建一个脚本来安装`scripts/install_all_packages`中的所有软件包：

```py
#!/usr/bin/env bash
set -e

sudo apt-get update
sudo apt install -y $(cat /mailape/ubuntu/packages.txt | grep -i '^[a-z]')

virtualenv -p $(which python3) /mailape/virtualenv
source /mailape/virtualenv/bin/activate

pip install -r /mailape/requirements.production.txt

sudo chown -R www-data /var/log/mailape \
    /etc/mailape \
    /var/run/celery \
    /var/log/celery
```

在上述脚本中，我们将安装我们上面列出的 Ubuntu 软件包，然后创建一个`virtualenv`来隔离我们的 Mail Ape Python 环境和软件包。最后，我们将一些目录的所有权交给 Apache（`www-data`用户），以便它可以写入这些目录。我们无法给`www-data`用户所有权，因为直到我们安装`apache2`软件包之前，它们可能并不存在。

接下来，让我们配置 Apache2 使用 mod_wsgi 来运行 Mail Ape。

# 配置 Apache

现在，我们将添加 Apache mod_wsgi 配置，就像我们在第九章中所做的那样，*部署 Answerly*。 mod_wsgi 配置不是本章的重点，所以请参考第九章，*部署 Answerly*，了解这个配置的工作原理。

让我们为 Mail Ape 在`apache/mailape.apache.conf`中创建一个虚拟主机配置文件：

```py
LogLevel info
WSGIRestrictEmbedded On

<VirtualHost *:80>

    WSGIDaemonProcess mailape \
        python-home=/mailape/virtualenv \
        python-path=/mailape/django \
        processes=2 \
        threads=2

    WSGIProcessGroup mailape

    WSGIScriptAlias / /mailape/django/config/wsgi.py
    <Directory /mailape/django/config>
        <Files wsgi.py>
            Require all granted
        </Files>
    </Directory>

    Alias /static/ /mailape/django/static_root
    <Directory /mailape/django/static_root>
        Require all granted
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

正如我们在第九章中所讨论的，*部署 Answerly*，我们无法将环境变量传递给我们的 mod_wsgi Python 进程，因此我们需要像在第九章中所做的那样更新项目的`wsgi.py`。

这是我们的新`django/config/wsgi.py`：

```py
import os
import configparser

from django.core.wsgi import get_wsgi_application

if not os.environ.get('DJANGO_SETTINGS_MODULE'):
    parser = configparser.ConfigParser()
    parser.read('/etc/mailape/mailape.ini')
    for name, val in parser['mod_wsgi'].items():
        os.environ[name.upper()] = val

application = get_wsgi_application()
```

我们在第九章*部署 Answerly*中讨论了上述脚本。这里唯一的区别是我们解析的文件，即`/etc/mailape/mailape.ini`。

接下来，我们需要将我们的虚拟主机配置添加到 Apache 的`sites-enabled`目录中。让我们在`scripts/configure_apache.sh`中创建一个脚本来做到这一点：

```py
#!/usr/bin/env bash

sudo rm /etc/apache2/sites-enabled/*
sudo ln -s /mailape/apache/mailape.apache.conf /etc/apache2/sites-enabled/000-mailape.conf
```

现在我们有了一个在生产环境中配置 Apache 的脚本，让我们配置我们的 Celery 工作进程开始。

# 配置 Celery

现在我们已经让 Apache 运行 Mail Ape，我们需要配置 Celery 来启动并处理我们的 SQS 队列。为了启动我们的 Celery 工作进程，我们将使用 Ubuntu 的 systemd 进程管理工具。

首先，让我们创建一个 Celery 服务文件，告诉 SystemD 如何启动 Celery。我们将在`ubuntu/celery.service`中创建服务文件：

```py
[Unit]
Description=Mail Ape Celery Service
After=network.target

[Service]
Type=forking
User=www-data
Group=www-data
EnvironmentFile=/etc/mailape/celery.env
WorkingDirectory=/mailape/django
ExecStart=/bin/sh -c '/mailape/virtualenv/bin/celery multi start worker \
    -A "config.celery:app" \
    --logfile=/var/log/celery/%n%I.log --loglevel="INFO" \
    --pidfile=/run/celery/%n.pid'
ExecStop=/bin/sh -c '/mailape/virtualenv/bin/celery multi stopwait worker \
    --pidfile=/run/celery/%n.pid'
ExecReload=/bin/sh -c '/mailape/virtualenv/bin/celery multi restart worker \
   -A "config.celery:app" \
   --logfile=/var/log/celery/%n%I.log --loglevel="INFO" \
   --pidfile=/run/celery/%n.pid'

[Install]
WantedBy=multi-user.target
```

让我们仔细看看这个文件中的一些选项：

+   `After=network.target`：这意味着 SystemD 在服务器连接到网络之前不会启动这个服务。

+   `Type=forking`：这意味着`ExecStart`命令最终将启动一个新进程，该进程将继续在自己的进程 ID（PID）下运行。

+   `User`: 这表示将拥有 Celery 进程的用户。在我们的情况下，我们将重用 Apache 的`www-data`用户。

+   `EnvironmentFile`: 这列出了一个将用于环境变量和所有`Exec`命令设置的值的文件。我们列出了一个与我们的 Celery 配置（`/mailape/ubuntu/celery.systemd.conf`）和一个与我们的 Mail Ape 配置（`/etc/mailape/celery.env`）的文件。

+   `ExecStart`: 这是将要执行的命令，用于启动 Celery。在我们的情况下，我们启动多个 Celery 工作者。我们所有的 Celery 命令将基于它们创建的进程 ID 文件来操作我们的工作者。Celery 将用工作者的 ID 替换`%n`。

+   `ExecStop`: 这是将根据它们的 PID 文件执行的命令，用于停止我们的 Celery 工作者。

+   `ExecReload`: 这是将执行的命令，用于重新启动我们的 Celery 工作者。Celery 支持`restart`命令，因此我们将使用它来执行重新启动。但是，此命令必须接收与我们的`ExecStart`命令相同的选项。

我们将把我们的 PID 文件放在`/var/run/celery`中，但我们需要确保该目录已创建。`/var/run`是一个特殊目录，不使用常规文件系统。我们需要创建一个配置文件，告诉 Ubuntu 创建`/var/run/celery`。让我们在`ubuntu/tmpfiles-celery.conf`中创建这个文件：

```py
d    /run/celery   0755 www-data www-data - -
```

这告诉 Ubuntu 创建一个由 Apache 用户（`www-data`）拥有的目录`/run/celery`。

最后，让我们创建一个脚本，将所有这些文件放在服务器的正确位置。我们将把这个脚本命名为`scripts/configure_celery.sh`：

```py
#!/usr/bin/env bash

sudo ln -s /mailape/ubuntu/celery.service /etc/systemd/system/celery.service
sudo ln -s /mailape/ubuntu/celery.service /etc/systemd/system/multi-user.target.wants/celery.service
sudo ln -s /mailape/ubuntu/tmpfiles-celery.conf /etc/tmpfiles.d/celery.conf
```

现在 Celery 和 Apache 已配置好，让我们确保它们具有正确的环境配置来运行 Mail Ape

# 创建环境配置文件

我们的 Celery 和 mod_wsgi Python 进程都需要从环境中提取配置信息，以连接到正确的数据库、SQS 队列和许多其他服务。这些是我们不想在版本控制系统中检查的设置和值（例如密码）。但是，我们仍然需要在生产环境中设置它们。为了创建定义我们的进程将在其中运行的环境的文件，我们将在`scripts/make_mailape_environment_ini.sh`中制作脚本：

```py
#!/usr/bin/env bash

ENVIRONMENT="
DJANGO_ALLOWED_HOSTS=${WEB_DOMAIN}
DJANGO_DB_NAME=mailape
DJANGO_DB_USER=mailape
DJANGO_DB_PASSWORD=${DJANGO_DB_PASSWORD}
DJANGO_DB_HOST=${DJANGO_DB_HOST}
DJANGO_DB_PORT=5432
DJANGO_LOG_FILE=/var/log/mailape/mailape.log
DJANGO_SECRET_KEY=${DJANGO_SECRET}
DJANGO_SETTINGS_MODULE=config.production_settings
MAIL_APE_FROM_EMAIL=admin@blvdplatform.com
EMAIL_HOST=${EMAIL_HOST}
EMAIL_HOST_USER=mailape
EMAIL_HOST_PASSWORD=${EMAIL_HOST_PASSWORD}
EMAIL_HOST_PORT=587
EMAIL_HOST_TLS=true

INI_FILE="[mod_wsgi]
${ENVIRONMENT}
"

echo "${INI_FILE}" | sudo tee "/etc/mailape/mailape.ini"
echo "${ENVIRONMENT}" | sudo tee "/etc/mailape/celery.env"
```

我们的`make_mailape_environment_ini.sh`脚本中有一些值是硬编码的，但引用了其他值（例如密码）作为环境变量。我们将在运行时将这些变量的值传递给 Packer。然后 Packer 将这些值传递给我们的脚本。

接下来，让我们制作 Packer 模板来构建我们的 AMI。

# 制作 Packer 模板

Packer 根据 Packer 模板文件中列出的指令创建 AMI。Packer 模板是一个由三个顶级键组成的 JSON 文件：

+   `variables`: 这将允许我们在运行时设置值（例如密码）

+   `builders`: 这指定了特定于云平台的详细信息，例如 AWS 凭据

+   `provisioners`: 这些是 Packer 将执行的指令，以制作我们的映像

让我们从`packer/web_worker.json`中创建我们的 Packer 模板，从`variables`部分开始：

```py
{
  "variables": {
    "aws_access_key": "",
    "aws_secret_key": "",
    "django_db_password":"",
    "django_db_host":"",
    "django_secret":"",
    "email_host":"",
    "email_host_password":"",
    "mail_ape_aws_key":"",
    "mail_ape_secret_key":"",
    "sqs_celery_queue":"",
    "web_domain":""
  }
}
```

在`variables`键下，我们将列出我们希望模板作为 JSON 对象键接受的所有变量。如果变量有默认值，那么我们可以将其作为该变量键的值提供。

接下来，让我们添加一个`builders`部分来配置 Packer 使用 AWS：

```py
{
  "variables": {...},
  "builders": [
    {
      "type": "amazon-ebs",
      "access_key": "{{user `aws_access_key`}}",
      "secret_key": "{{user `aws_secret_key`}}",
      "region": "us-west-2",
      "source_ami": "ami-78b82400",
      "instance_type": "t2.micro",
      "ssh_username": "ubuntu",
      "ami_name": "mailape-{{timestamp}}",
      "tags": {
        "project": "mailape"
      }
    }
  ]
}
```

`builders`是一个数组，因为我们可以使用相同的模板在多个平台上构建机器映像（例如 AWS 和 Google Cloud）。让我们详细看看每个选项：

+   `"type": "amazon-ebs"`: 告诉 Packer 我们正在创建一个带有弹性块存储的亚马逊机器映像。这是首选配置，因为它提供了灵活性。

+   `"access_key": "{{user aws_access_key }}"`: 这是 Packer 应该使用的访问密钥，用于与 AWS 进行身份验证。Packer 包含自己的模板语言，以便可以在运行时生成值。`{{ }}`之间的任何值都是由 Packer 模板引擎生成的。模板引擎提供了一个`user`函数，它接受用户提供的变量的名称并返回其值。例如，当运行 Packer 时，`{{user aws_access_key }}`将被用户提供给`aws_access_key`的值替换。

+   `"secret_key": "{{user aws_secret_key }}"`: 这与 AWS 秘钥相同。

+   `"region": "us-west-2"`: 这指定了 AWS 区域。我们所有的工作都将在`us-west-2`中完成。

+   `"source_ami": "ami-78b82400"`: 这是我们要定制的镜像，以制作我们的镜像。在我们的情况下，我们使用官方的 Ubuntu AMI。Ubuntu 提供了一个 EC2 AMI 定位器（[`cloud-images.ubuntu.com/locator/ec2/`](http://cloud-images.ubuntu.com/locator/ec2/)）来帮助找到他们的官方 AMI。

+   `"instance_type": "t2.micro"`: 这是一个小型廉价的实例，在撰写本书时，属于 AWS 免费套餐。

+   `"ssh_username": "ubuntu"`: Packer 通过 SSH 在虚拟机上执行所有操作。这是它应该用于身份验证的用户名。Packer 将为身份验证生成自己的密钥对，因此我们不必担心指定密码或密钥。

+   `"ami_name": "mailape-{{timestamp}}"`: 结果 AMI 的名称。`{{timestamp}}`是一个返回自 Unix 纪元以来的 UTC 时间的函数。

+   `"tags": {...}`: 标记资源可以更容易地在 AWS 中识别资源。这是可选的，但建议使用。

现在我们已经指定了我们的 AWS 构建器，我们将需要指定我们的配置程序。

Packer 配置程序是定制服务器的指令。在我们的情况下，我们将使用以下两种类型的配置程序：

+   `file`配置程序用于将我们的代码上传到服务器。

+   `shell`配置程序用于执行我们的脚本和命令

首先，让我们添加我们的`make_aws_directories.sh`脚本，因为我们需要它首先运行：

```py
{
  "variables": {...},
  "builders": [...],
  "provisioners": [
    {
      "type": "shell",
      "script": "{{template_dir}}/../scripts/make_aws_directories.sh"
    }
  ]
}
```

具有`script`属性的`shell`配置程序将上传，执行和删除脚本。Packer 提供了`{{template_dir}}`函数，它返回模板目录的目录。这使我们可以避免硬编码绝对路径。我们执行的第一个配置程序将执行我们在本节前面创建的`make_aws_directories.sh`脚本。

现在我们的目录存在了，让我们使用`file`配置程序将我们的代码和文件复制过去：

```py
{
  "variables": {...},
  "builders": [...],
  "provisioners": [
    ...,
    {
      "type": "file",
      "source": "{{template_dir}}/../requirements.common.txt",
      "destination": "/mailape/requirements.common.txt"
    },
    {
      "type": "file",
      "source": "{{template_dir}}/../requirements.production.txt",
      "destination": "/mailape/requirements.production.txt"
    },
    {
      "type": "file",
      "source": "{{template_dir}}/../ubuntu",
      "destination": "/mailape/ubuntu"
    },
    {
      "type": "file",
      "source": "{{template_dir}}/../apache",
      "destination": "/mailape/apache"
    },
    {
      "type": "file",
      "source": "{{template_dir}}/../django",
      "destination": "/mailape/django"
    },
  ]
}
```

`file`配置程序将本地文件或由`source`定义的目录上传到`destination`服务器上。

由于我们从工作目录上传了 Python 代码，我们需要小心旧的`.pyc`文件是否还存在。让我们确保在我们的生产服务器上删除这些文件：

```py
{
  "variables": {...},
  "builders": [...],
  "provisioners": [
    ...,
   {
      "type": "shell",
      "inline": "find /mailape/django -name '*.pyc' -delete"
   },
   ]
}
```

`shell`配置程序可以接收`inline`属性。然后，配置程序将在服务器上执行`inline`命令。

最后，让我们执行我们创建的其余脚本：

```py
{
  "variables": {...},
  "builders": [...],
  "provisioners": [
    ...,
    {
      "type": "shell",
      "scripts": [
        "{{template_dir}}/../scripts/install_all_packages.sh",
        "{{template_dir}}/../scripts/configure_apache.sh",
        "{{template_dir}}/../scripts/make_mailape_environment_ini.sh",
        "{{template_dir}}/../scripts/configure_celery.sh"
        ],
      "environment_vars": [
        "DJANGO_DB_HOST={{user `django_db_host`}}",
        "DJANGO_DB_PASSWORD={{user `django_db_password`}}",
        "DJANGO_SECRET={{user `django_secret`}}",
        "EMAIL_HOST={{user `email_host`}}",
        "EMAIL_HOST_PASSWORD={{user `email_host_password`}}",
        "WEB_DOMAIN={{user `web_domain`}}"
      ]
}
```

在这种情况下，`shell`配置程序已收到`scripts`和`environment_vars`。`scripts`是指向 shell 脚本的路径数组。数组中的每个项目都将被上传和执行。在执行每个脚本时，此`shell`配置程序将添加`environment_vars`中列出的环境变量。`environment_vars`参数可选地提供给所有`shell`配置程序，以提供额外的环境变量。

随着我们的最终配置程序添加到我们的文件中，我们现在已经完成了我们的 Packer 模板。让我们使用 Packer 来执行模板并构建我们的 Mail Ape 生产服务器。

# 运行 Packer 来构建 Amazon Machine Image

安装了 Packer 并创建了 Mail Ape 生产服务器 Packer 模板，我们准备构建我们的**Amazon Machine Image** (**AMI**)。

让我们运行 Packer 来构建我们的 AMI：

```py
$ packer build \
    -var "aws_access_key=..." \
    -var "aws_secret_key=..." \
    -var "django_db_password=..." \
    -var "django_db_host=A.B.us-west-2.rds.amazonaws.com" \
    -var "django_secret=..." \
    -var "email_host=smtp.example.com" \
    -var "email_host_password=..." \
    -var "web_domain=mailape.example.com" \
    packer/web_worker.json
Build 'amazon-ebs' finished.

==> Builds finished. The artifacts of successful builds are:
--> amazon-ebs: AMIs were created:
us-west-2: ami-XXXXXXXX
```

Packer 将输出我们新 AMI 镜像的 AMI ID。我们将能够使用这个 AMI 在 AWS 云中启动 EC2 实例。

如果您的模板由于缺少 Ubuntu 软件包而失败，请重试构建。在撰写本书时，Ubuntu 软件包存储库并不总是能够成功更新。

现在我们有了 AMI，我们可以部署它了。

# 在 AWS 上部署可扩展的自愈 Web 应用程序

现在我们有了基础架构和可部署的 AMI，我们可以在 AWS 上部署 Mail Ape。我们将使用 CloudFormation 定义一组资源，让我们根据需要扩展我们的应用程序。我们将定义以下三个资源：

+   一个弹性负载均衡器来在我们的 EC2 实例之间分发请求

+   一个 AutoScaling Group 来启动和终止 EC2 实例

+   一个 LaunchConfig 来描述要启动的 EC2 实例的类型

首先，让我们确保如果需要访问任何 EC2 实例来排除部署后出现的任何问题，我们有一个 SSH 密钥。

# 创建 SSH 密钥对

要在 AWS 中创建 SSH 密钥对，我们可以使用以下 AWS 命令行：

```py
$ aws ec2 create-key-pair --key-name mail_ape_production --region us-west-2
{
    "KeyFingerprint": "XXX",
    "KeyMaterial": "-----BEGIN RSA PRIVATE KEY-----\nXXX\n-----END RSA PRIVATE KEY-----",
    "KeyName": "tom-cli-test"
}
```

确保将`KeyMaterial`的值复制到您的 SSH 客户端的配置目录（通常为`~/.ssh`）-记得用实际的新行替换`\n`。

接下来，让我们开始我们的 Mail Ape 部署 CloudFormation 模板。

# 创建 Web 服务器 CloudFormation 模板

接下来，让我们创建一个 CloudFormation 模板，将 Mail Ape 服务器部署到云中。我们将使用 CloudFormation 告诉 AWS 如何扩展我们的服务器并在灾难发生时重新启动它们。我们将告诉 CloudFormation 创建以下三个资源：

+   一个**弹性负载均衡器**（**ELB**），它将能够在我们的服务器之间分发请求

+   一个 LaunchConfig，它将描述我们想要使用的 EC2 实例的 AMI、实例类型和其他细节。

+   一个自动扩展组，它将监视以确保我们拥有正确数量的健康 EC2 实例。

这三个资源是构建任何类型的可扩展自愈 AWS 应用程序的核心。

让我们从`cloudformation/web_worker.yaml`开始构建我们的 CloudFormation 模板。我们的新模板将与`cloudformation/infrastracture.yaml`具有相同的三个部分：`Parameters`、`Resources`和`Outputs`。

让我们从添加`Parameters`部分开始。

# 在 web worker CloudFormation 模板中接受参数

我们的 web worker CloudFormation 模板将接受 AMI 和 InstanceProfile 作为参数进行启动。这意味着我们不必在 Packer 和基础架构堆栈中分别硬编码我们创建的资源的名称。

让我们在`cloudformation/web_worker.yaml`中创建我们的模板：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape web worker
Parameters:
  WorkerAMI:
    Description: Worker AMI
    Type: String
  InstanceProfile:
    Description: the instance profile
    Type: String
```

现在我们有了 AMI 和 InstanceProfile 用于我们的 EC2 实例，让我们创建我们的 CloudFormation 堆栈的资源。

# 在我们的 web worker CloudFormation 模板中创建资源

接下来，我们将定义**弹性负载均衡器**（**ELB**）、启动配置和自动扩展组。这三个资源是大多数可扩展的 AWS Web 应用程序的核心。在构建模板时，我们将看看它们是如何交互的。

首先，让我们添加我们的负载均衡器：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape web worker
Parameters:
  ...
Resources:
  LoadBalancer:
    Type: "AWS::ElasticLoadBalancing::LoadBalancer"
    Properties:
      LoadBalancerName: MailApeLB
      Listeners:
        -
          InstancePort: 80
          LoadBalancerPort: 80
          Protocol: HTTP
```

在上述代码中，我们正在添加一个名为`LoadBalancer`的新资源，类型为`AWS::ElasticLoadBalancing::LoadBalancer`。ELB 需要一个名称（`MailApeLB`）和一个`Listeners`列表。每个`Listeners`条目应定义我们的 ELB 正在监听的端口（`LoadBalancerPort`）、请求将被转发到的实例端口（`InstancePort`）以及端口将使用的协议（在我们的情况下是`HTTP`）。

一个 ELB 将负责在我们启动来处理负载的任意数量的 EC2 实例之间分发 HTTP 请求。

接下来，我们将创建一个 LaunchConfig，告诉 AWS 如何启动一个新的 Mail Ape web worker：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape web worker
Parameters:
  ...
Resources:
  LoadBalancer:
    ...
  LaunchConfig:
    Type: "AWS::AutoScaling::LaunchConfiguration"
    Properties:
      ImageId: !Ref WorkerAMI
      KeyName: mail_ape_production
      SecurityGroups:
        - ssh-access
        - web-access
      InstanceType: t2.micro
      IamInstanceProfile: !Ref InstanceProfile
```

Launch Config 是`AWS::AutoScaling::LaunchConfiguration`类型的，描述了自动扩展组应该启动的新 EC2 实例的配置。让我们逐个查看所有的`Properties`，以确保我们理解它们的含义：

+   `ImageId`：这是我们希望实例运行的 AMI 的 ID。在我们的情况下，我们使用`Ref`函数从`WorkerAMI`参数获取 AMI ID。

+   `KeyName`：这是将添加到此机器的 SSH 密钥的名称。如果我们需要实时排除故障，这将非常有用。在我们的情况下，我们使用了本章早期创建的 SSH 密钥对的名称。

+   `SecurityGroups`：这是一个定义 AWS 要打开哪些端口的安全组名称列表。在我们的情况下，我们列出了我们在基础架构堆栈中创建的 web 和 SSH 组的名称。

+   `InstanceType`：这表示我们的 EC2 实例的实例类型。实例类型定义了可用于我们的 EC2 实例的计算和内存资源。在我们的情况下，我们使用的是一个非常小的经济实惠的实例，（在撰写本书时）在第一年内由 AWS 免费使用。

+   `IamInstanceProfile`：这表示我们的 EC2 实例的`InstanceProfile`。在这里，我们使用`Ref`函数来引用`InstanceProfile`参数。当我们创建我们的堆栈时，我们将使用我们早期创建的 InstanceProfile 的 ARN，该 ARN 为我们的 EC2 实例访问 SQS 提供了访问权限。

接下来，我们将定义启动由 ELB 转发的请求的 EC2 实例的 AutoScaling 组：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape web worker
Parameters:
  ...
Resources:
  LoadBalancer:
    ...
  LaunchConfig:
    ...
  WorkerGroup:
    Type: "AWS::AutoScaling::AutoScalingGroup"
    Properties:
      LaunchConfigurationName: !Ref LaunchConfig
      MinSize: 1
      MaxSize: 3
      DesiredCapacity: 1
      LoadBalancerNames:
        - !Ref LoadBalancer
```

我们的新**自动扩展组**（**ASG**）是`AWS::AutoScaling::AutoScalingGroup`类型。让我们来看看它的属性：

+   `LaunchConfigurationName`：这是此 ASG 在启动新实例时应该使用的`LaunchConfiguration`的名称。在我们的情况下，我们使用`Ref`函数来引用我们上面创建的`LaunchConfig`，即启动配置。

+   `MinSize`/`MaxSize`：这些是所需的属性，设置此组可能包含的实例的最大和最小数量。这些值可以保护我们免受意外部署太多实例可能对我们的系统或每月账单产生负面影响。在我们的情况下，我们确保至少有一个（`1`）实例，但不超过三（`3`）个。

+   `DesiredCapacity`：这告诉我们的系统应该运行多少 ASG 和多少健康的 EC2 实例。如果一个实例失败并将健康实例的数量降到`DesiredCapacity`值以下，那么 ASG 将使用其启动配置来启动更多实例。

+   `LoadBalancerNames`：这是一个 ELB 的列表，可以将请求路由到由此 ASG 启动的实例。当新的 EC2 实例成为此 ASG 的一部分时，它也将被添加到命名 ELB 路由请求的实例列表中。在我们的情况下，我们使用`Ref`函数来引用我们在模板中早期定义的 ELB。

这三个工具共同帮助我们快速而顺利地扩展我们的 Django 应用程序。ASG 为我们提供了一种说出我们希望运行多少 Mail Ape EC2 实例的方法。启动配置描述了如何启动新的 Mail Ape EC2 实例。然后 ELB 将把请求分发到 ASG 启动的所有实例。

现在我们有了我们的资源，让我们输出一些最相关的数据，以使我们的部署其余部分变得容易。

# 输出资源名称

我们将添加到我们的 CloudFormation 模板的最后一部分是`Outputs`，以便更容易地记录我们的 ELB 的地址和我们的 ASG 的名称。我们需要我们 ELB 的地址来向`mailape.example.com`添加 CNAME 记录。如果我们需要访问我们的实例（例如，运行我们的迁移），我们将需要我们 ASG 的名称。

让我们用一个`Outputs`部分更新`cloudformation/web_worker.yaml`：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape web worker
Parameters:
  ...
Resources:
  LoadBalancer:
    ...
  LaunchConfig:
    ...
  WorkerGroup:
    ...
Outputs:
  LoadBalancerDNS:
    Description: Load Balancer DNS name
    Value: !GetAtt LoadBalancer.DNSName
  AutoScalingGroupName:
    Description: Auto Scaling Group name
    Value: !Ref WorkerGroup
```

`LoadBalancerDNS`的值将是我们上面创建的 ELB 的 DNS 名称。`AutoScalingGroupName`的值将是我们的 ASG，返回 ASG 的名称。

接下来，让我们为我们的 Mail Ape 1.0 版本创建一个堆栈。

# 创建 Mail Ape 1.0 版本堆栈

现在我们有了我们的 Mail Ape web worker CloudFormation 模板，我们可以创建一个 CloudFormation 堆栈。创建堆栈时，堆栈将创建其相关资源，如 ELB、ASG 和 Launch Config。我们将使用 AWS CLI 来创建我们的堆栈：

```py
$ aws cloudformation create-stack \
    --stack-name "mail_ape_1_0" \
    --template-body "file:///path/to/mailape/cloudformation/web_worker.yaml" \
    --parameters \
      "ParameterKey=WorkerAMI,ParameterValue=AMI-XXX" \
      "ParameterKey=InstanceProfile,ParameterValue=arn:aws:iam::XXX:instance-profile/XXX" \
    --region us-west-2
```

前面的命令看起来与我们执行创建基础设施堆栈的命令非常相似，但有一些区别：

+   --stack-name：这是我们正在创建的堆栈的名称。

+   --template-body "file:///path/..."：这是一个`file://` URL，其中包含我们的 CloudFormation 模板的绝对路径。由于路径前缀以两个`/`和 Unix 路径以`/`开头，因此这里会出现一个奇怪的三重`/`。

+   --parameters：这个模板需要两个参数。我们可以以任何顺序提供它们，但必须同时提供。

+   `"ParameterKey=WorkerAMI, ParameterValue=`：对于`WorkerAMI`，我们必须提供 Packer 给我们的 AMI ID。

+   `"ParameterKey=InstanceProfile,ParameterValue`：对于 InstanceProfile，我们必须提供我们的基础设施堆栈输出的 Instance Profile ARN。

+   --region us-west-2：我们所有的工作都在`us-west-2`地区进行。

要查看我们堆栈的输出，我们可以使用 AWS CLI 的`describe-stack`命令：

```py
$ aws cloudformation describe-stacks \
    --stack-name mail_ape_1_0 \
    --region us-west-2
```

结果是一个大的 JSON 对象；这里是一个略有缩短的示例版本：

```py
{
    "Stacks": [
        {
            "StackId": "arn:aws:cloudformation:us-west-2:XXXX:stack/mail_ape_1_0/XXX",
            "StackName": "mail_ape_1_0",
            "Description": "Mail Ape web worker",
            "Parameters": [
                {
                    "ParameterKey": "InstanceProfile",
                    "ParameterValue": "arn:aws:iam::XXX:instance-profile/XXX"
                },
                {
                    "ParameterKey": "WorkerAMI",
                    "ParameterValue": "ami-XXX"
                }
            ],
            "StackStatus": "CREATE_COMPLETE",
            "Outputs": [
                {
                    "OutputKey": "AutoScalingGroupName",
                    "OutputValue": "mail_ape_1_0-WebServerGroup-XXX",
                    "Description": "Auto Scaling Group name"
                },
                {
                    "OutputKey": "LoadBalancerDNS",
                    "OutputValue": "MailApeLB-XXX.us-west-2.elb.amazonaws.com",
                    "Description": "Load Balancer DNS name"
                }
            ],
        }
    ]
}
```

我们的资源（例如 EC2 实例）直到`StackStatus`为`CREATE_COMPLETE`时才会准备就绪。创建所有相关资源可能需要几分钟。

我们特别关注`Outputs`数组中的对象：

+   第一个值给出了我们的 ASG 的名称。有了我们 ASG 的名称，我们就能够找到该 ASG 中的 EC2 实例，以防需要 SSH 到其中一个。

+   第二个值给出了我们 ELB 的 DNS 名称。我们将使用我们 ELB 的 DNS 来为我们的生产 DNS 记录创建 CNAME 记录，以便将我们的流量重定向到这里（例如，为`mailape.example.com`创建一个 CNAME 记录，将流量重定向到我们的 ELB）。

让我们看看如何 SSH 到我们的 ASG 启动的 EC2 实例。

# SSH 到 Mail Ape EC2 实例

AWS CLI 为我们提供了许多获取有关我们 EC2 实例信息的方法。让我们找到我们启动的 EC2 实例的地址：

```py
$ aws ec2 describe-instances \
 --region=us-west-2 \
 --filters='Name=tag:aws:cloudformation:stack-name,Values=mail_ape_1_0' 
```

`aws ec2 describe-instances`命令将返回关于所有 EC2 实例的大量信息。我们可以使用`--filters`命令来限制返回的 EC2 实例。当我们创建一个堆栈时，许多相关资源都带有堆栈名称的标记。这使我们可以仅筛选出我们`mail_ape_1_0`堆栈中的 EC2 实例。

以下是输出的（大大）缩短版本：

```py
{
  "Reservations": [
    {
      "Groups": [],
      "Instances": [
        {
          "ImageId": "ami-XXX",
          "InstanceId": "i-XXX",
          "InstanceType": "t2.micro",
          "KeyName": "mail_ape_production",
          "PublicDnsName": "ec2-XXX-XXX-XXX-XXX.us-west-2.compute.amazonaws.com",
          "PublicIpAddress": "XXX",
          "State": {
            "Name": "running"
          },
          "IamInstanceProfile": {
            "Arn": "arn:aws:iam::XXX:instance-profile/infrastructure-SQSClientInstance-XXX"
          },
          "SecurityGroups": [
            {
              "GroupName": "ssh-access"
            },
            {
              "GroupName": "web-access"
            }
          ],
          "Tags": [
            {
              "Key": "aws:cloudformation:stack-name",
              "Value": "mail_ape_1_0"
            } ] } ] } ] }
```

在前面的输出中，请注意`PublicDnsName`和`KeyName`。由于我们在本章前面创建了该密钥，我们可以 SSH 到这个实例：

```py
$ ssh -i /path/to/saved/ssh/key ubuntu@ec2-XXX-XXX-XXX-XXX.us-west-2.compute.amazonaws.com
```

请记住，您在前面的输出中看到的`XXX`将在您的系统中被实际值替换。

现在我们可以 SSH 到系统中，我们可以创建和迁移我们的数据库。

# 创建和迁移我们的数据库

对于我们的第一个发布，我们首先需要创建我们的数据库。为了创建我们的数据库，我们将在`database/make_database.sh`中创建一个脚本：

```py
#!/usr/bin/env bash

psql -v ON_ERROR_STOP=1 postgresql://$USER:$PASSWORD@$HOST/postgres <<-EOSQL
    CREATE DATABASE mailape;
    CREATE USER mailape;
    GRANT ALL ON DATABASE mailape to "mailape";
    ALTER USER mailape PASSWORD '$DJANGO_DB_PASSWORD';
    ALTER USER mailape CREATEDB;
EOSQL
```

此脚本使用其环境中的三个变量：

+   $USER：Postgres 主用户用户名。我们在`cloudformation/infrastructure.yaml`中将其定义为`master`。

+   $PASSWORD：Postgres 主用户的密码。我们在创建`infrastructure`堆栈时将其作为参数提供。

+   $DJANGO_DB_PASSWORD：这是 Django 数据库的密码。我们在创建 AMI 时将其作为参数提供给 Packer。

接下来，我们将通过提供变量来在本地执行此脚本：

```py
$ export USER=master
$ export PASSWORD=...
$ export DJANGO_DB_PASSWORD=...
$ bash database/make_database.sh
```

我们的 Mail Ape 数据库现在已经创建。

接下来，让我们 SSH 到我们的新 EC2 实例并运行我们的数据库迁移：

```py
$ ssh -i /path/to/saved/ssh/key ubuntu@ec2-XXX-XXX-XXX-XXX.us-west-2.compute.amazonaws.com
$ source /mailape/virtualenv/bin/activate
$ cd /mailape/django
$ export DJANGO_DB_NAME=mailape
$ export DJANGO_DB_USER=mailape
$ export DJANGO_DB_PASSWORD=...
$ export DJANGO_DB_HOST=XXX.XXX.us-west-2.rds.amazonaws.com
$ export DJANGO_DB_PORT=5432
$ export DJANGO_LOG_FILE=/var/log/mailape/mailape.log
$ export DJANGO_SECRET_KEY=...
$ export DJANGO_SETTINGS_MODULE=config.production_settings
$ python manage.py migrate
```

我们的`manage.py migrate`命令与我们在以前章节中使用的非常相似。这里的主要区别在于我们需要首先 SSH 到我们的生产 EC2 实例。

当`migrate`返回成功时，我们的数据库已经准备好，我们可以发布我们的应用程序了。

# 发布 Mail Ape 1.0

现在我们已经迁移了我们的数据库，我们准备更新`mailape.example.com`的 DNS 记录，指向我们 ELB 的 DNS 记录。一旦 DNS 记录传播，Mail Ape 就会上线。

恭喜！

# 使用 update-stack 进行扩展和缩小

使用 CloudFormation 和 Auto Scaling Groups 的一个很棒的地方是，很容易扩展我们的系统。在本节中，让我们更新我们的系统，使用两个运行 Mail Ape 的 EC2 实例。

我们可以在`cloudformation/web_worker.yaml`中更新我们的 CloudFormation 模板：

```py
AWSTemplateFormatVersion: "2010-09-09"
Description: Mail Ape web worker
Parameters:
  ..
Resources:
  LoadBalancer:
    ...
  LaunchConfig:
    ...
  WorkerGroup:
    Type: "AWS::AutoScaling::AutoScalingGroup"
    Properties:
      LaunchConfigurationName: !Ref LaunchConfig
      MinSize: 1
      MaxSize: 3
      DesiredCapacity: 2
      LoadBalancerNames:
        - !Ref LoadBalancer
Outputs:
  ..
```

我们已经将`DesiredCapacity`从 1 更新为 2。现在，我们不再创建新的堆栈，而是更新现有的堆栈：

```py
$ aws cloudformation update-stack \
    --stack-name "mail_ape_1_0" \
    --template-body "file:///path/to/mailape/cloudformation/web_worker.yaml" \
    --parameters \
      "ParameterKey=WorkerAMI,UsePreviousValue=true" \
      "ParameterKey=InstanceProfile,UsePreviousValue=true" \
    --region us-west-2
```

前面的命令看起来很像我们的`create-stack`命令。一个方便的区别是我们不需要再次提供参数值 - 我们可以简单地通知`UsePreviousValue=true`告诉 AWS 重用之前的相同值。

同样，`describe-stack`会告诉我们更新何时完成：

```py
aws cloudformation describe-stacks \
    --stack-name mail_ape_1_0 \
    --region us-west-2
```

结果是一个大型的 JSON 对象 - 这里是一个截断的示例版本：

```py
{
    "Stacks": [
        {
            "StackId": "arn:aws:cloudformation:us-west-2:XXXX:stack/mail_ape_1_0/XXX",
            "StackName": "mail_ape_1_0",
            "Description": "Mail Ape web worker",
            "StackStatus": "UPDATE_COMPLETE"
        }
    ]
}
```

一旦我们的`StackStatus`为`UPDATE_COMPLETE`，我们的 ASG 将使用新的设置进行更新。ASG 可能需要几分钟来启动新的 EC2 实例，但我们可以使用我们之前创建的`describe-instances`命令来查找它：

```py
$ aws ec2 describe-instances \
 --region=us-west-2 \
 --filters='Name=tag:aws:cloudformation:stack-name,Values=mail_ape_1_0'
```

最终，它将返回两个实例。以下是输出的高度截断版本：

```py
{
  "Reservations": [
    {
      "Groups": [],
      "Instances": [
        {
          "ImageId": "ami-XXX",
          "InstanceId": "i-XXX",
          "PublicDnsName": "ec2-XXX-XXX-XXX-XXX.us-west-2.compute.amazonaws.com",
          "State": { "Name": "running" }
        },
        {
          "ImageId": "ami-XXX",
          "InstanceId": "i-XXX",
          "PublicDnsName": "ec2-XXX-XXX-XXX-XXX.us-west-2.compute.amazonaws.com",
          "State": { "Name": "running" }
        } ] } ] }
```

要缩小到一个实例，只需更新您的`web_worker.yaml`模板并再次运行`update-stack`。

恭喜！您现在知道如何将 Mail Ape 扩展到处理更高的负载，然后在非高峰时期缩小规模。

请记住，亚马逊的收费是基于使用情况的。如果您在阅读本书的过程中进行了扩展，请记住要缩小规模，否则您可能会被收取比预期更多的费用。确保您阅读关于 AWS 免费套餐限制的信息[`aws.amazon.com/free/`](https://aws.amazon.com/free/)。

# 总结

在本章中，我们将我们的 Mail Ape 应用程序并在 AWS 云中的生产环境中启动。我们使用 AWS CloudFormation 将我们的 AWS 资源声明为代码，使得跟踪我们需要的内容和发生了什么变化就像在我们的代码库的其余部分一样容易。我们使用 Packer 构建了我们的 Mail Ape 服务器运行的镜像，再次使我们能够将我们的服务器配置作为代码进行跟踪。最后，我们将 Mail Ape 启动到云中，并学会了如何进行扩展和缩小。

现在我们已经完成了学习构建 Django Web 应用程序的旅程，让我们回顾一下我们学到的一些东西。在三个项目中，我们看到了 Django 如何将代码组织成模型、视图和模板。我们学会了如何使用 Django 的表单类和 Django Rest Framework 的序列化器类进行输入验证。我们审查了安全最佳实践、缓存以及如何发送电子邮件。我们看到了如何将我们的代码部署到 Linux 服务器、Docker 容器和 AWS 云中。

您已经准备好使用 Django 来实现您的想法了！加油！
