# Django2 Web 应用构建指南（三）

> 原文：[`zh.annas-archive.org/md5/18689E1989723338A1936B680A71254B`](https://zh.annas-archive.org/md5/18689E1989723338A1936B680A71254B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Elasticsearch 搜索问题

现在用户可以提问和回答问题，我们将为 Answerly 添加搜索功能，以帮助用户找到问题。我们的搜索将由 Elasticsearch 提供支持。Elasticsearch 是一个由 Apache Lucene 提供支持的流行的开源搜索引擎。

在本章中，我们将执行以下操作：

+   创建一个 Elasticsearch 服务来抽象我们的代码

+   批量加载现有的`Question`模型实例到 Elasticsearch

+   构建由 Elasticsearch 提供支持的搜索视图

+   自动将新模型保存到 Elasticsearch

让我们首先设置我们的项目以使用 Elasticsearch。

# 从 Elasticsearch 开始

Elasticsearch 由 Elastic 维护，尽管服务器是开源的。Elastic 提供专有插件，以使在生产中运行更容易。您可以自己运行 Elasticsearch，也可以使用 Amazon、Google 或 Elastic 等 SaaS 提供商。在开发中，我们将使用 Elastic 提供的 Docker 镜像运行 Elasticsearch。

Elasticsearch 由零个或多个索引组成。每个索引包含文档。文档是搜索的对象。文档由字段组成。字段由 Apache Lucene 索引。每个索引还分成一个或多个分片，通过在集群中的节点之间分发来加快索引和搜索速度。

我们可以使用其 RESTful API 与 Elasticsearch 进行交互。大多数请求和响应默认都是 JSON 格式。

首先，让我们通过在 Docker 中运行 Elasticsearch 服务器来开始。

# 使用 docker 启动 Elasticsearch 服务器

运行 Elasticsearch 服务器的最简单方法是使用 Elastic 提供的 Docker 镜像。

要获取并启动 Elasticsearch docker 镜像，请运行以下命令：

```py
$ docker run -d -p 9200:9200 -p 9300:9300 -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:6.0.0
```

以下命令执行四个操作，如下所示：

+   它从 Elastic 的服务器下载 Elasticsearch 6.0 docker 镜像

+   它使用 Elasticsearch 6.0 docker 镜像作为单节点集群运行容器

+   它将 docker 命令从运行的容器中分离（这样我们就可以在我们的 shell 中运行更多命令）

+   它在主机计算机上打开端口（`-p`）`9200`和`9300`，并将它们重定向到容器

要确认我们的服务器正在运行，我们可以向 Elasticsearch 服务器发出以下请求：

```py
$ curl http://localhost:9200/?pretty
{
  "name" : "xgf60cc",
  "cluster_name" : "docker-cluster",
  "cluster_uuid" : "HZAnjZefSjqDOxbMU99KOw",
  "version" : {
    "number" : "6.0.0",
    "build_hash" : "8f0685b",
    "build_date" : "2017-11-10T18:41:22.859Z",
    "build_snapshot" : false,
    "lucene_version" : "7.0.1",
    "minimum_wire_compatibility_version" : "5.6.0",
    "minimum_index_compatibility_version" : "5.0.0"
  },
  "tagline" : "You Know, for Search"
}
```

与 Elasticsearch 交互时，始终添加`pretty` `GET`参数，以便 Elasticsearch 打印 JSON。但是，在代码中不要使用此参数。

现在我们有了 Elasticsearch 服务器，让我们配置 Django 以了解我们的服务器。

# 配置 Answerly 以使用 Elasticsearch

接下来，我们将更新我们的`settings.py`和`requirements.txt`文件，以便与 Elasticsearch 一起使用。

让我们更新`django/config/settings.py`：

```py
ES_INDEX = 'answerly'
ES_HOST = 'localhost'
ES_PORT = '9200'
```

这些是我们的应用程序将使用的自定义设置。Django 没有内置对 Elasticsearch 的支持。相反，我们将在我们自己的代码中引用这些设置。

让我们将 Elasticsearch 库添加到我们的`requirements.txt`文件中：

```py
elasticsearch==6.0.0
```

这是由 Elastic 发布的官方 Elasticsearch Python 库。该库提供了一个低级接口，看起来很像我们可以用 cURL 与之一起使用的 RESTful API。这意味着我们可以轻松地在命令行上使用 cURL 构建查询，然后将 JSON 转换为 Python`dict`。

Elastic 还提供了一个更高级、更 Pythonic 的 API，称为`elasticsearch-dsl`。它包括一个伪 ORM，用于编写更 Pythonic 的持久层。如果您的项目包含大量 Elasticsearch 代码，这可能是一个不错的选择。但是，低级 API 与 RESTful API 密切对应，这使得重用代码并从 Elasticsearch 社区获得帮助更容易。

接下来，让我们在我们的 Elasticsearch 服务器中创建 Answerly 索引。

# 创建 Answerly 索引

让我们通过向服务器发送`PUT`请求来在 Elasticsearch 中创建索引：

```py
$ curl -XPUT "localhost:9200/answerly?pretty"
```

太好了！现在，我们可以将现有的`Question`模型实例加载到我们的 Elasticsearch 索引中。

# 将现有的问题加载到 Elasticsearch 中

添加搜索功能意味着我们需要将现有的`Question`模型实例加载到 Elasticsearch 中。解决这样的问题最简单的方法是添加一个`manage.py`命令。自定义的`manage.py`命令将普通 Python 脚本的简单性与 Django API 的强大功能结合起来。

在添加`manage.py`命令之前，我们需要编写我们的特定于 Elasticsearch 的代码。为了将 Elasticsearch 代码与 Django 代码分离，我们将在`qanda`应用程序中添加一个`elasticsearch`服务。

# 创建 Elasticsearch 服务

本章中我们将编写的大部分代码都是特定于 Elasticsearch 的。我们不希望将该代码放在我们的视图（或`manage.py`命令）中，因为这将在两个不相关的组件之间引入耦合。相反，我们将把 Elasticsearch 代码隔离到`qanda`中的自己的模块中，然后让我们的视图和`manage.py`命令调用我们的服务模块。

我们将创建的第一个函数将批量加载`Question`模型实例到 Elasticsearch 中。

让我们为我们的 Elastic 服务代码创建一个单独的文件。我们将把我们的批量插入代码放入`django/qanda/service/elasticsearch.py`中：

```py
import logging

from django.conf import settings
from elasticsearch import Elasticsearch, TransportError
from elasticsearch.helpers import streaming_bulk

FAILED_TO_LOAD_ERROR = 'Failed to load {}: {!r}'

logger = logging.getLogger(__name__)

def get_client():
    return Elasticsearch(hosts=[
        {'host': settings.ES_HOST, 'port': settings.ES_PORT,}
    ])

def bulk_load(questions):
    all_ok = True
    es_questions = (q.as_elasticsearch_dict() for q in questions)
    for ok, result in streaming_bulk(
            get_client(),
            es_questions,
            index=settings.ES_INDEX,
            raise_on_error=False,
    ):
        if not ok:
            all_ok = False
            action, result = result.popitem()
            logger.error(FAILED_TO_LOAD_ERROR.format(result['_id'], result))
    return all_ok
```

我们在新服务中创建了两个函数，`get_client()`和`bulk_load()`。

`get_client()`函数将返回一个从`settings.py`中配置的`Elasticcearch`客户端。

`bulk_load()`函数接受一个`Question`模型实例的可迭代集合，并使用`streaming_bulk()`助手将它们加载到 Elasticsearch 中。由于`bulk_load()`期望一个可迭代的集合，这意味着我们的`manage.py`命令将能够发送一个`QuerySet`对象。请记住，即使我们使用了生成器表达式（它是惰性的），我们的`questions`参数也会在我们尝试迭代它时执行完整的查询。只有`as_elasticsearch_dict()`方法的执行是惰性的。我们将在完成查看`bulk_load()`函数后编写并讨论新的`as_elasticsearch_dict()`方法。

接下来，`bulk_load()`函数使用`streaming_bulk()`函数。`streaming_bulk()`函数接受四个参数并返回一个用于报告加载进度的迭代器。四个参数如下：

+   一个`Elasticsearch`客户端

+   我们的`Question`生成器（迭代器）

+   索引名称

+   一个标志，告诉函数在出现错误时不要引发异常（这将导致`ok`变量在出现错误时为`False`）

我们的`for`循环的主体将在加载问题时出现错误时记录日志。

接下来，让我们给`Question`一个方法，可以将其转换为 Elasticsearch 可以正确处理的`dict`。

让我们更新`Question`模型：

```py
from django.db import models

class Question(models.Model):
    # fields and methods unchanged 

    def as_elasticsearch_dict(self):
        return {
            '_id': self.id,
            '_type': 'doc',
            'text': '{}\n{}'.format(self.title, self.question),
            'question_body': self.question,
            'title': self.title,
            'id': self.id,
            'created': self.created,
        }
```

`as_elasticsearch_dict()`方法将`Question`模型实例转换为适合加载到 Elasticsearch 中的字典。以下是我们特别添加到 Elasticsearch 字典中的三个字段，这些字段不在我们的模型中：

+   `_id`：这是 Elasticsearch 文档的 ID。这不一定要与模型 ID 相同。但是，如果我们想要能够更新代表“问题”的 Elasticsearch 文档，那么我们需要存储文档的`_id`或能够计算它。为简单起见，我们只使用相同的 ID。

+   `_type`：这是文档的映射类型。截至 Elasticsearch 6，Elasticsearch 索引只能存储一个映射类型。因此，索引中的所有文档应该具有相同的`_type`值。映射类型类似于数据库模式，告诉 Elasticsearch 如何索引和跟踪文档及其字段。Elasticsearch 的一个便利功能是，它不要求我们提前定义类型。Elasticsearch 会根据我们加载的数据动态构建文档的类型。

+   `text`：这是我们将在文档中创建的一个字段。对于搜索来说，将文档的标题和正文放在一个可索引的字段中是很方便的。

字典中的其余字段与模型的字段相同。

作为模型方法的`as_elasticsearch_dict()`的存在可能会有问题。`elasticsearch`服务不应该知道如何将`Question`转换为 Elasticsearch 字典吗？像许多设计问题一样，答案取决于各种因素。影响我将此方法添加到模型中的一个因素是 Django 的*fat models*哲学。通常，Django 鼓励在模型方法上编写操作。此外，此字典的属性与模型的字段耦合。将这两个字段列表保持紧密联系使未来的开发人员更容易保持两个列表同步。然而，在某些项目和环境中，将这种函数放在服务模块中可能是正确的选择。作为 Django 开发人员，我们的工作是评估权衡并为特定项目做出最佳决策。

现在我们的`elasticsearch`服务知道如何批量添加`Questions`，让我们用`manage.py`命令暴露这个功能。

# 创建一个 manage.py 命令

我们已经使用`manage.py`命令来启动项目和应用程序，以及创建和运行迁移。现在，我们将创建一个自定义命令，将我们项目中的所有问题加载到 Elasticsearch 服务器中。这将是对 Django 管理命令的简单介绍。我们将在第十二章中更详细地讨论这个主题，*构建 API*。

Django 管理命令必须位于应用程序的`manage/commands`子目录中。一个应用程序可以有多个命令。每个命令的名称与其文件名相同。文件内部应该有一个继承`django.core.management.BaseCommand`的`Command`类，它应该执行的代码应该在`handle()`方法中。

让我们在`django/qanda/management/commands/load_questions_into_elastic_search.py`中创建我们的命令：

```py
from django.core.management import BaseCommand

from qanda.service import elasticsearch
from qanda.models import Question

class Command(BaseCommand):
    help = 'Load all questions into Elasticsearch'

    def handle(self, *args, **options):
        queryset = Question.objects.all()
        all_loaded = elasticsearch.bulk_load(queryset)
        if all_loaded:
            self.stdout.write(self.style.SUCCESS(
                'Successfully loaded all questions into Elasticsearch.'))
        else:
            self.stdout.write(
                self.style.WARNING('Some questions not loaded '
                                   'successfully. See logged errors'))
```

在设计命令时，我们应该将它们视为视图，即*Fat models, thin commands*。这可能会更复杂一些，因为命令行输出没有单独的模板层，但我们的输出也不应该很复杂。

在我们的情况下，`handle()`方法获取所有`Questions`的`QuerySet`，然后将其传递给`elasticsearch.bulkload`。然后我们使用`Command`的辅助方法打印出是否成功或不成功。这些辅助方法优于直接使用`print()`，因为它们使编写测试更容易。我们将在下一章第八章中更详细地讨论这个主题，*测试 Answerly*。

让我们运行以下命令：

```py
$ cd django
$ python manage.py load_questions_into_elastic_search
Successfully loaded all questions into Elasticsearch.
```

当所有问题加载完毕后，让我们确认它们是否在我们的 Elasticsearch 服务器中。我们可以使用`curl`访问 Elasticsearch 服务器，以确认我们的问题已经加载：

```py
$ curl http://localhost:9200/answerly/_search?pretty
```

假设您的 ElasticSearch 服务器在本地主机的端口 9200 上运行，上述命令将返回`answerly`索引中的所有数据。我们可以查看结果来确认我们的数据已成功加载。

现在我们在 Elasticsearch 中有一些问题，让我们添加一个搜索视图。

# 创建一个搜索视图

在本节中，我们将创建一个视图，让用户搜索我们的`Question`并显示匹配的结果。为了实现这个结果，我们将做以下事情：

+   在我们的`elasticsearch`服务中添加一个`search_for_question()`函数

+   创建一个搜索视图

+   创建一个模板来显示搜索结果

+   更新基本模板以使搜索在任何地方都可用

让我们从为我们的`elasticsearch`服务添加搜索开始。

# 创建一个搜索功能

查询我们的 Elasticsearch 服务器以获取与用户查询匹配的问题列表的责任属于我们的`elasticsearch`服务。

让我们添加一个函数，将搜索查询发送到`django/qanda/service/elasticsearch.py`并解析结果：

```py
def search_for_questions(query):
    client = get_client()
    result = client.search(index=settings.ES_INDEX, body={
      'query': {
          'match': {
              'text': query,
          },
      },
    })
    return (h['_source'] for h in result['hits']['hits'])
```

连接客户端后，我们将发送我们的查询并解析结果。

使用客户端的`search()`方法，我们将查询作为 Python `dict`发送到 Elasticsearch Query DSL（领域特定语言）中。Elasticsearch Query DSL 提供了一个用于使用一系列嵌套对象查询 Elasticsearch 的语言。通过 HTTP 发送时，查询变成一系列嵌套的 JSON 对象。在 Python 中，我们使用`dict`。

在我们的情况下，我们在 Answerly 索引的文档的`text`字段上使用了`match`查询。`match`查询是一个模糊查询，检查每个文档的`text`字段是否匹配。查询 DSL 还支持许多配置选项，让您构建更复杂的查询。在我们的情况下，我们将接受默认的模糊配置。

接下来，`search_for_questions`遍历结果。Elasticsearch 返回了大量描述结果数量、匹配质量和结果文档的元数据。在我们的情况下，我们将返回匹配文档的迭代器（存储在`_source`中）。

现在我们可以从 Elasticsearch 获取结果，我们可以编写我们的`SearchView`。

# 创建 SearchView

我们的`SearchView`将使用`GET`参数`q`并使用我们的服务模块的`search_for_questions()`函数进行搜索。

我们将使用`TemplateView`构建我们的`SearchView`。`TemplateView`在响应`GET`请求时呈现模板。让我们将`SearchView`添加到`django/qanda/views.py`中：

```py
from django.views.generic import TemplateView

from qanda.service.elasticsearch import search_for_questions

class SearchView(TemplateView):
    template_name = 'qanda/search.html'

    def get_context_data(self, **kwargs):
        query = self.request.GET.get('q', None)
        ctx = super().get_context_data(query=query, **kwargs)
        if query:
            results = search_for_questions(query)
            ctx['hits'] = results
        return ctx
```

接下来，我们将在`django/qanda/urls.py`的 URLConf 中添加一个`path()`对象路由到我们的`SearchView`：

```py
from django.urls.conf import path, include

from qanda import views

app_name = 'qanda'

urlpatterns = [
    # skipping previous code
    path('q/search', views.SearchView.as_view(),
         name='question_search'),
]
```

现在我们有了我们的视图，让我们构建我们的`search.html`模板。

# 创建搜索模板

我们将把搜索模板放在`django/qanda/templates/qanda/search.html`中，如下所示：

```py
{% extends "base.html" %}

{% load markdownify %}

{% block body %}
  <h2 >Search</h2 >
  <form method="get" class="form-inline" >
    <input class="form-control mr-2"
           placeholder="Search"
           type="search"
           name="q" value="{{ query }}" >
    <button type="submit" class="btn btn-primary" >Search</button >
  </form >
  {% if query %}
    <h3>Results from search query '{{ query }}'</h3 >
    <ul class="list-unstyled search-results" >
      {% for hit in hits %}
        <li >
          <a href="{% url "qanda:question_detail" pk=hit.id %}" >
            {{ hit.title }}
          </a >
          <div >
            {{ hit.question_body|markdownify|truncatewords_html:20 }}
          </div >
        </li >
      {% empty %}
        <li >No results.</li >
      {% endfor %}
    </ul >
  {% endif %}
{% endblock %}
```

在模板的正文中，我们有一个显示查询的搜索表单。如果有`query`，那么我们也将显示其结果（如果有的话）。

我们之前在这里使用过许多标签（例如`for`，`if`，`url`和`markdownify`）。我们将添加一个新的过滤器`truncate_words_html`，它通过管道接收文本和一个数字作为参数。它将把文本截断为提供的单词数（不包括 HTML 标记），并关闭结果片段中的任何打开的 HTML 标记。

这个模板的结果是一个与我们的查询匹配的命中列表，每个问题的文本预览。由于我们在 Elasticsearch 中存储了问题的正文、标题和 ID，我们能够在不查询我们的常规数据库的情况下显示结果。

接下来，让我们更新基础模板，让用户可以从任何页面进行搜索。

# 更新基础模板

让我们更新基础模板，让用户可以从任何地方进行搜索。为此，我们需要编辑`django/templates/base.html`：

```py
{% load static %}
<!DOCTYPE html>
<html lang="en" >
<head >{# head unchanged #}</head >
<body >
<nav class="navbar navbar-expand-lg  bg-light" >
  <div class="container" >
    <a class="navbar-brand" href="/" >Answerly</a >
    <ul class="navbar-nav" >
      {# previous nav unchanged #}  
      <li class="nav-item" >
        <form class="form-inline"
              action="{% url "qanda:question_search" %}"
              method="get">
          <input class="form-control mr-sm-2" type="search"
                 name="q"
                 placeholder="Search">
          <button class="btn btn-outline-primary my-2 my-sm-0" 
                 type="submit" >
            Search
          </button >
        </form >
      </li >
    </ul >
  </div >
</nav >
{# rest of body unchanged #}
</body >
</html >
```

现在，我们在每个页面的页眉中有了搜索表单。

完成搜索后，让我们确保每个新问题都会自动添加到 Elasticsearch 中。

# 在保存时将问题添加到 Elasticsearch 中

每次保存模型时执行操作的最佳方法是覆盖模型从`Model`继承的`save()`方法。我们将提供自定义的`Question.save()`方法，以确保`Question`在被 Django ORM 保存时立即添加和更新到 ElasticSearch 中。

即使您不控制该模型的源代码，您仍然可以在保存 Django 模型时执行操作。Django 提供了一个信号分发器（[`docs.djangoproject.com/en/2.0/topics/signals/`](https://docs.djangoproject.com/en/2.0/topics/signals/)），让您可以监听您不拥有的模型上的事件。但是，信号会给您的代码引入大量复杂性。除非没有其他选择，否则*不建议*使用信号。

让我们更新`django/qanda/models.py`中的`Queston`模型：

```py
from django.db import models
from qanda.service import elasticsearch
class Question(models.Model):
    # other fields and methods unchanged. 
    def save(self, force_insert=False, force_update=False, using=None,
             update_fields=None):
        super().save(force_insert=force_insert,
                     force_update=force_update,
                     using=using,
                     update_fields=update_fields)
        elasticsearch.upsert(self)
```

`save()`方法被`CreateView`，`UpdateView`，`QuerySet.create()`，`Manager.create()`和大多数第三方代码调用以持久化模型。我们确保在原始`save()`方法返回后调用我们的`upsert()`方法，因为我们希望我们的模型有一个`id`属性。

现在，让我们创建我们的 Elasticsearch 服务的`upsert`方法。

# 测量代码覆盖率

**代码覆盖**测量了测试期间执行的代码行。理想情况下，通过跟踪代码覆盖，我们可以确保哪些代码经过了测试，哪些代码没有。由于 Django 项目主要是 Python，我们可以使用 Coverage.py 来测量我们的代码覆盖率。以下是 Django 项目的两个注意事项：

+   Coverage.py 无法测量我们的模板的覆盖范围（它们不是 Python）

+   未经测试的基于类的视图似乎比它们实际覆盖的要多

查找 Django 应用程序的覆盖范围是一个两步过程：

1.  使用`coverage`命令运行我们的测试

1.  使用`coverage report`或`coverage html`生成覆盖报告

让我们使用`coverage`运行 Django 的单元`test`命令，查看未经测试的项目的基线：

```py
$ coverage run --branch --source=qanda,user manage.py test 
Creating test database for alias 'default'...
System check identified no issues (0 silenced).

----------------------------------------------------------------------
Ran 0 tests in 0.000s

OK
Destroying test database for alias 'default'...
```

上述命令告诉`coverage`运行一个命令（在我们的情况下是`manage.py test`）来记录测试覆盖率。我们将使用此命令和以下两个选项：

+   `--branch`：跟踪分支语句的两个部分是否都被覆盖（例如，当`if`语句评估为`True`和`False`时）

+   `--source=qanda,user`：仅记录`qanda`和`user`模块（我们编写的代码）的覆盖范围

现在我们已经记录了覆盖率，让我们看一下没有任何测试的应用程序的覆盖率：

```py
$ coverage report 
Name                                 Stmts   Miss Branch BrPart  Cover
----------------------------------------------------------------------
qanda/__init__.py                      0      0      0      0   100%
qanda/admin.py                         1      0      0      0   100%
qanda/apps.py                          3      3      0      0     0%
qanda/forms.py                        19      0      0      0   100%
qanda/management/__init__.py           0      0      0      0   100%
qanda/migrations/0001_initial.py       7      0      0      0   100%
qanda/migrations/__init__.py           0      0      0      0   100%
qanda/models.py                       28      6      0      0    79%
qanda/search_indexes.py                0      0      0      0   100%
qanda/service/__init__.py              0      0      0      0   100%
qanda/service/elasticsearch.py        47     32     14      0    25%
qanda/tests.py                         1      0      0      0   100%
qanda/urls.py                          4      0      0      0   100%
qanda/views.py                        76     35     12      0    47%
user/__init__.py                         0      0      0      0   100%
user/admin.py                            4      0      0      0   100%
user/apps.py                             3      3      0      0     0%
user/migrations/__init__.py              0      0      0      0   100%
user/models.py                           1      0      0      0   100%
user/tests.py                            1      0      0      0   100%
user/urls.py                             5      0      0      0   100%
user/views.py                            5      0      0      0   100%
----------------------------------------------------------------------
TOTAL                                  205     79     26      0    55%
```

为了了解未经测试的项目为何覆盖率达到 55％，让我们看一下`django/qanda/views.py`的覆盖情况。让我们使用以下命令生成覆盖的 HTML 报告：

```py
$ cd django
$ coverage html
```

上述命令将创建一个`django/htmlcov`目录和 HTML 文件，显示覆盖报告和代码覆盖的可视化显示。让我们打开`django/htmlcov/qanda_views_py.html`并向下滚动到大约第 72 行：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/bd-dj20-webapp/img/3856b79c-6ff4-43ef-8f73-f774db940d2c.png)

上述屏幕截图显示`DailyQuestionList`完全被覆盖，但`QuestionDetailView.get_context_data()`没有被覆盖。在没有任何测试的情况下，这种差异似乎有违直觉。

让我们回顾一下代码覆盖的工作原理。代码覆盖工具检查在测试期间是否*执行*了特定行的代码。在上述屏幕截图中，`DailyQuestionList`类及其成员*已经*被执行。当测试运行程序启动时，Django 将构建根 URLConf，就像在开发或生产时启动一样。创建根 URLConf 时，它会导入其他引用的 URLConfs（例如`qanda.urls`）。这些 URLConfs 又会导入它们的视图。视图导入表单，模型和其他模块。

这个导入链意味着模块顶层的任何内容都会显示为覆盖的，无论是否经过测试。`DailyQuestionList`的类定义被执行。但是，类本身没有被实例化，也没有执行任何方法。这也解释了为什么`QuestionDetailView.get_context_data()`的主体部分没有被覆盖。`QuestionDetailView.get_context_data()`的主体部分从未被执行。这是代码覆盖工具在处理声明性代码（例如`DailyQuestionList`）时的一个限制。

现在我们了解了代码覆盖的一些限制，让我们为`qanda.models.Question.save()`编写一个单元测试。

# 向 Elasticsearch 插入数据

如果对象存在，则 upsert 操作将更新对象，如果不存在则插入。Upsert 是*update*和*insert*的合成词。Elasticsearch 支持开箱即用的 upsert 操作，这可以使我们的代码更简单。

让我们将我们的`upsert()`方法添加到`django/qanda/service/elastic_search.py`中：

```py
def upsert(question_model):
    client = get_client()
    question_dict = question_model.as_elasticsearch_dict()
    doc_type = question_dict['_type']
    del question_dict['_id']
    del question_dict['_type']
    response = client.update(
        settings.ES_INDEX,
        doc_type,
        id=question_model.id,
        body={
            'doc': question_dict,
            'doc_as_upsert': True,
        }
    )
    return response
```

我们在上述代码块中定义了我们的`get_client()`函数。

要执行 upsert，我们使用 Elasticsearch `client`的`update()`方法。我们将模型作为文档`dict`提供，在`doc`键下。为了强制 Elasticsearch 执行 upsert，我们将包含`doc_as_upsert`键，并赋予`True`值。`update()`方法和我们之前使用的批量插入函数之间的一个区别是，`update()`不会在文档中接受隐式 ID（`_id`）。但是，我们在`update()`调用中提供要 upsert 的文档的 ID 作为`id`参数。我们还从`question_model.as_elasticsearch_dict()`方法返回的`dict`中删除`_type`键和值，并将值（存储在`doc_type`变量中）作为参数传递给`client.update()`方法。

我们返回响应，尽管我们的视图不会使用它。

最后，我们可以通过运行开发服务器来测试我们的视图：

```py
$ cd django
$ python manage.py runserver
```

一旦我们的开发服务器启动，我们可以在[`localhost:8000/ask`](http://localhost:8000/ask)提出一个新问题，然后在[`localhost:8000/q/search`](http://localhost:8000/q/search)进行搜索。

现在，我们已经完成了向 Answerly 添加搜索功能！

# 摘要

在本章中，我们添加了搜索功能，以便用户可以搜索问题。我们使用 Docker 为开发设置了一个 Elasticsearch 服务器。我们创建了一个`manage.py`命令，将所有我们的`Question`加载到 Elasticsearch 中。我们添加了一个搜索视图，用户可以在其中看到他们问题的结果。最后，我们更新了`Question.save`以保持 Elasticsearch 和 Django 数据库同步。

接下来，我们将深入了解测试 Django 应用程序，以便在未来进行更改时可以有信心。


# 第八章：测试 Answerly

在上一章中，我们为我们的问题和答案网站 Answerly 添加了搜索功能。然而，随着我们网站功能的增长，我们需要避免破坏现有的功能。为了确保我们的代码保持正常运行，我们将更仔细地测试我们的 Django 项目。

在本章中，我们将做以下事情：

+   安装 Coverage.py 以测量代码覆盖率

+   测量我们的 Django 项目的代码覆盖率

+   为我们的模型编写单元测试

+   为视图编写单元测试

+   为视图编写 Django 集成测试

+   为视图编写 Selenium 集成测试

让我们从安装 Coverage.py 开始。

# 安装 Coverage.py

**Coverage.py**是目前最流行的 Python 代码覆盖工具。它非常容易安装，因为可以从 PyPI 获取。让我们将其添加到我们的`requirements.txt`文件中：

```py
$ echo "coverage==4.4.2" >> requirements.txt
```

然后我们可以使用 pip 安装 Coverage.py：

```py
$ pip install -r requirements.txt
```

现在我们已经安装了 Coverage.py，我们可以开始测量我们的代码覆盖率。

# 为 Question.save()创建一个单元测试

Django 帮助您编写单元测试来测试代码的各个单元。如果我们的代码依赖于外部服务，那么我们可以使用标准的`unittest.mock`库来模拟该 API，防止对外部系统的请求。

让我们为`Question.save()`方法编写一个测试，以验证当我们保存一个`Question`时，它将被插入到 Elasticsearch 中。我们将在`django/qanda/tests.py`中编写这个测试：

```py
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from elasticsearch import Elasticsearch

from qanda.models import Question

class QuestionSaveTestCase(TestCase):
    """
    Tests Question.save()
    """

    @patch('qanda.service.elasticsearch.Elasticsearch')
    def test_elasticsearch_upsert_on_save(self, ElasticsearchMock):
        user = get_user_model().objects.create_user(
            username='unittest',
            password='unittest',
        )
        question_title = 'Unit test'
        question_body = 'some long text'
        q = Question(
            title=question_title,
            question=question_body,
            user=user,
        )
        q.save()

        self.assertIsNotNone(q.id)
        self.assertTrue(ElasticsearchMock.called)
        mock_client = ElasticsearchMock.return_value
        mock_client.update.assert_called_once_with(
            settings.ES_INDEX,
            id=q.id,
            body={
                'doc': {
                    '_type': 'doc',
                    'text': '{}\n{}'.format(question_title, question_body),
                    'question_body': question_body,
                    'title': question_title,
                    'id': q.id,
                    'created': q.created,
                },
                'doc_as_upsert': True,
            }
        )
```

在上面的代码示例中，我们创建了一个带有单个测试方法的`TestCase`。该方法创建一个用户，保存一个新的`Question`，然后断言模拟行为是否正确。

像大多数`TestCase`一样，`QuestionSaveTestCase`既使用了 Django 的测试 API，也使用了 Python 的`unittest`库中的代码（例如，`unittest.mock.patch()`）。让我们更仔细地看看 Django 的测试 API 如何使测试更容易。

`QuestionSaveTestCase`扩展了`django.test.TestCase`而不是`unittest.TestCase`，因为 Django 的`TestCase`提供了许多有用的功能，如下所示：

+   整个测试用例和每个测试都是原子数据库操作

+   Django 在每次测试前后都会清除数据库

+   `TestCase`提供了方便的`assert*()`方法，比如`self.assertInHTML()`（在*为视图创建单元测试*部分中更多讨论）

+   一个虚假的 HTTP 客户端来创建集成测试（在*为视图创建集成测试*部分中更多讨论）

由于 Django 的`TestCase`扩展了`unittest.TestCase`，因此当它遇到常规的`AssertionError`时，它仍然能够理解并正确执行。因此，如果`mock_client.update.assert_called_once_with()`引发`AssertionError`异常，Django 的测试运行器知道如何处理它。

让我们用`manage.py`运行我们的测试：

```py
$ cd django
$ python manage.py test
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
.
----------------------------------------------------------------------
Ran 1 test in 0.094s

OK
Destroying test database for alias 'default'...
```

现在我们知道如何测试模型，我们可以继续测试视图。然而，在测试视图时，我们需要创建模型实例。使用模型的默认管理器来创建模型实例会变得太啰嗦。接下来，让我们使用 Factory Boy 更容易地创建测试所需的模型。

# 使用 Factory Boy 创建测试模型

在我们之前的测试中，我们使用`User.models.create_user`创建了一个`User`模型。然而，这要求我们提供用户名和密码，而我们并不真正关心。我们只需要一个用户，而不是特定的用户。对于我们的许多测试来说，`Question`和`Answer`也是如此。Factory Boy 库将帮助我们在测试中简洁地创建模型。

Factory Boy 对 Django 开发人员特别有用，因为它知道如何基于 Django 的`Model`类创建模型。

让我们安装 Factory Boy：

```py
$ pip install factory-boy==2.9.2
```

在这一部分，我们将使用 Factory Boy 创建一个`UserFactory`类和一个`QuestionFactory`类。由于`Question`模型必须在其`user`字段中有一个用户，`QuestionFactory`将向我们展示`Factory`类如何相互引用。

让我们从`UserFactory`开始。

# 创建一个 UserFactory

`Question`和`Answer`都与用户相关联。这意味着我们几乎在所有测试中都需要创建用户。使用模型管理器为每个测试生成所有相关模型非常冗长，并且分散了我们测试的重点。Django 为我们的测试提供了开箱即用的支持。但是，Django 的 fixtures 是单独的 JSON/YAML 文件，需要手动维护，否则它们将变得不同步并引起问题。Factory Boy 将通过让我们使用代码来帮助我们，即`UserFactory`，可以根据当前用户模型的状态在运行时简洁地创建用户模型实例。

我们的`UserFactory`将派生自 Factory Boy 的`DjangoModelFactory`类，该类知道如何处理 Django 模型。我们将使用内部`Meta`类告诉`UserFactory`它正在创建哪个模型（请注意，这与`Form`API 类似）。我们还将添加类属性以告诉 Factory Boy 如何设置模型字段的值。最后，我们将重写`_create`方法，使`UserFactory`使用管理器的`create_user()`方法而不是默认的`create()`方法。

让我们在`django/users/factories.py`中创建我们的`UserFactory`：

```py
from django.conf import settings

import factory

class UserFactory(factory.DjangoModelFactory):
    username = factory.Sequence(lambda n: 'user %d' % n)
    password = 'unittest'

    class Meta:
        model = settings.AUTH_USER_MODEL

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        manager = cls._get_manager(model_class)
        return manager.create_user(*args, **kwargs)
```

`UserFactory`是`DjangoModelFactory`的子类。`DjangoModelFactory`将查看我们类的`Meta`内部类（遵循与`Form`类相同的模式）。

让我们更仔细地看一下`UserFactory`的属性：

+   `password = 'unittest'`：这将为每个用户设置相同的密码。

+   `username = factory.Sequence(lambda n: 'user %d' % n)`: `Sequence`为每次工厂创建模型时的字段设置不同的值。`Sequence()`接受可调用对象，将其传递给工厂使用的次数，并使用可调用对象的返回值作为新实例的字段值。在我们的情况下，我们的用户将具有用户名，例如`user 0`和`user 1`。

最后，我们重写了`_create()`方法，因为`django.contrib.auth.models.User`模型具有异常的管理器。`DjangoModelFactory`的默认`_create`方法将使用模型的管理器的`create()`方法。对于大多数模型来说，这很好，但对于`User`模型来说效果不佳。要创建用户，我们应该真正使用`create_user`方法，以便我们可以传递明文密码并对其进行哈希处理以进行存储。这将让我们作为该用户进行身份验证。

让我们在 Django shell 中尝试一下我们的工厂：

```py
$ cd django
$ python manage.py shell
Python 3.6.3 (default, Oct 31 2017, 11:15:24) 
Type 'copyright', 'credits' or 'license' for more information
IPython 6.2.1 -- An enhanced Interactive Python. Type '?' for help.
In [1]: from user.factories import UserFactory
In [2]:  user = UserFactory()
In [3]: user.username
Out[3]: 'user 0'
In [4]:  user2 = UserFactory()
In [5]:  assert user.username != user2.username
In [6]: user3 = UserFactory(username='custom')
In [7]: user3.username
Out[7]: 'custom'
```

在这个 Django shell 会话中，我们将注意到如何使用`UserFactory`：

+   我们可以使用单个无参数调用创建新模型，`UserFactory()`

+   每次调用都会导致唯一的用户名，`assert user.username != user2.username`

+   我们可以通过提供参数来更改工厂使用的值，`UserFactory(username='custom')`

接下来，让我们创建一个`QuestionFactory`。

# 创建 QuestionFactory

我们的许多测试将需要多个`Question`实例。但是，每个`Question`必须有一个用户。这可能会导致大量脆弱和冗长的代码。创建`QuestionFactory`将解决这个问题。

在前面的示例中，我们看到了如何使用`factory.Sequence`为每个新模型的属性赋予不同的值。Factory Boy 还提供了`factory.SubFactory`，其中我们可以指示字段的值是另一个工厂的结果。

让我们将`QuestionFactory`添加到`django/qanda/factories.py`中：

```py
from unittest.mock import patch

import factory

from qanda.models import Question
from user.factories import UserFactory

class QuestionFactory(factory.DjangoModelFactory):
    title = factory.Sequence(lambda n: 'Question #%d' % n)
    question = 'what is a question?'
    user = factory.SubFactory(UserFactory)

    class Meta:
        model = Question

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        with patch('qanda.service.elasticsearch.Elasticsearch'):
            return super()._create(model_class, *args, **kwargs)
```

我们的`QuestionFactory`与`UserFactory`非常相似。它们有以下共同点：

+   派生自`factory.DjangoModelFactory`

+   有一个`Meta`类

+   使用`factory.Sequence`为字段提供自定义值

+   有一个硬编码的值

有两个重要的区别：

+   `QuestionFactory`的`user`字段使用`SubFactory`，为每个`Question`创建一个新的用户，该用户是使用`UserFactory`创建的。

+   `QuestionFactory`的`_create`方法模拟了 Elasticsearch 服务，以便在创建模型时不会尝试连接到该服务。否则，它调用默认的`_create()`方法。

为了看到我们的`QuestionFactory`的实际应用，让我们为我们的`DailyQuestionList`视图编写一个单元测试。

# 创建一个视图的单元测试

在这一部分，我们将为我们的`DailyQuestionList`视图编写一个视图单元测试。

对视图进行单元测试意味着直接向视图传递一个请求，并断言响应是否符合我们的期望。由于我们直接将请求传递给视图，我们还需要直接传递视图通常会接收的任何参数，这些参数从请求的 URL 中解析出来。从 URL 路径中解析值是请求路由的责任，在视图单元测试中我们不使用它。

让我们来看看`django/qanda/tests.py`中的`DailyQuestionListTestCase`类：

```py
from datetime import date

from django.test import TestCase, RequestFactory

from qanda.factories import QuestionFactory
from qanda.views import DailyQuestionList

QUESTION_CREATED_STRFTIME = '%Y-%m-%d %H:%M'

class DailyQuestionListTestCase(TestCase):
"""
Tests the DailyQuestionList view
"""
QUESTION_LIST_NEEDLE_TEMPLATE = '''
<li >
    <a href="/q/{id}" >{title}</a >
    by {username} on {date}
</li >
'''

REQUEST = RequestFactory().get(path='/q/2030-12-31')
TODAY = date.today()

def test_GET_on_day_with_many_questions(self):
    todays_questions = [QuestionFactory() for _ in range(10)]

    response = DailyQuestionList.as_view()(
        self.REQUEST,
        year=self.TODAY.year,
        month=self.TODAY.month,
        day=self.TODAY.day
    )

    self.assertEqual(200, response.status_code)
    self.assertEqual(10, response.context_data['object_list'].count())
    rendered_content = response.rendered_content
    for question in todays_questions:
        needle = self.QUESTION_LIST_NEEDLE_TEMPLATE.format(
            id=question.id,
            title=question.title,
            username=question.user.username,
            date=question.created.strftime(QUESTION_CREATED_STRFTIME)
        )
        self.assertInHTML(needle, rendered_content)
```

让我们更仔细地看一下我们见过的新 API：

+   `RequestFactory().get(path=...)`: `RequestFactory`是一个用于创建测试视图的 HTTP 请求的实用工具。注意这里我们请求的`path`是任意的，因为它不会被用于路由。

+   `DailyQuestionList.as_view()(...)`: 我们已经讨论过每个基于类的视图都有一个`as_view()`方法，它返回一个可调用对象，但我们以前没有使用过。在这里，我们传递请求、年、月和日来执行视图。

+   `response.context_data['object_list'].count()`:我们的视图返回的响应仍然保留了它的上下文。我们可以使用这个上下文来断言视图是否工作正确，比起评估 HTML 更容易。

+   `response.rendered_content`: `rendered_content`属性让我们可以访问响应的渲染模板。

+   `self.assertInHTML(needle, rendered_content)`: `TestCase.assertInHTML()`让我们可以断言一个 HTML 片段是否在另一个 HTML 片段中。`assertInHTML()`知道如何解析 HTML，不关心属性顺序或空白。在测试视图时，我们经常需要检查响应中是否存在特定的 HTML 片段。

现在我们已经为一个视图创建了一个单元测试，让我们看看通过为`QuestionDetailView`创建一个集成测试来创建一个视图的集成测试。

# 创建一个视图集成测试

视图集成测试使用与单元测试相同的`django.test.TestCase`类。集成测试将告诉我们我们的项目是否能够将请求路由到视图并返回正确的响应。集成测试请求将不得不通过项目配置的所有中间件和 URL 路由。为了帮助我们编写集成测试，Django 提供了`TestCase.client`。

`TestCase.client`是`TestCase`提供的一个实用工具，让我们可以向我们的项目发送 HTTP 请求（它不能发送外部 HTTP 请求）。Django 会正常处理这些请求。`client`还为我们提供了方便的方法，比如`client.login()`，一种开始认证会话的方法。一个`TestCase`类也会在每个测试之间重置它的`client`。

让我们在`django/qanda/tests.py`中为`QuestionDetailView`编写一个集成测试：

```py
from django.test import TestCase

from qanda.factories import QuestionFactory
from user.factories import UserFactory

QUESTION_CREATED_STRFTIME = '%Y-%m-%d %H:%M'

class QuestionDetailViewTestCase(TestCase):
    QUESTION_DISPLAY_SNIPPET = '''
    <div class="question" >
      <div class="meta col-sm-12" >
        <h1 >{title}</h1 >
        Asked by {user} on {date}
      </div >
      <div class="body col-sm-12" >
        {body}
      </div >
    </div >'''
    LOGIN_TO_POST_ANSWERS = 'Login to post answers.'

    def test_logged_in_user_can_post_answers(self):
        question = QuestionFactory()

        self.assertTrue(self.client.login(
            username=question.user.username,
            password=UserFactory.password)
        )
        response = self.client.get('/q/{}'.format(question.id))
        rendered_content = response.rendered_content

        self.assertEqual(200, response.status_code)

         self.assertInHTML(self.NO_ANSWERS_SNIPPET, rendered_content)

        template_names = [t.name for t in response.templates]
        self.assertIn('qanda/common/post_answer.html', template_names)

        question_needle = self.QUESTION_DISPLAY_SNIPPET.format(
            title=question.title,
            user=question.user.username,
            date=question.created.strftime(QUESTION_CREATED_STRFTIME),
            body=QuestionFactory.question,
        )
        self.assertInHTML(question_needle, rendered_content)
```

在这个示例中，我们登录然后请求`Question`的详细视图。我们对结果进行多次断言以确认它是正确的（包括检查使用的模板的名称）。

让我们更详细地检查一些代码：

+   `self.client.login(...)`: 这开始了一个认证会话。所有未来的请求都将作为该用户进行认证，直到我们调用`client.logout()`。

+   `self.client.get('/q/{}'.format(question.id))`: 这使用我们的客户端发出一个 HTTP `GET`请求。不同于我们使用`RequestFactory`时，我们提供的路径是为了将我们的请求路由到一个视图（注意我们在测试中从未直接引用视图）。这返回了我们的视图创建的响应。

+   `[t.name for t in response.templates]`: 当客户端的响应渲染时，客户端会更新响应的使用的模板列表。在详细视图的情况下，我们使用了多个模板。为了检查我们是否显示了发布答案的 UI，我们将检查`qanda/common/post_answer.html`文件是否是使用的模板之一。

通过这种类型的测试，我们可以非常有信心地确认我们的视图在用户发出请求时是否有效。然而，这确实将测试与项目的配置耦合在一起。即使是来自第三方应用的视图，集成测试也是有意义的，以确认它们是否被正确使用。如果你正在开发一个库应用，你可能会发现最好使用单元测试。

接下来，让我们通过使用 Selenium 来测试我们的 Django 和前端代码是否都正确工作，创建一个实时服务器测试用例。

# 创建一个实时服务器集成测试

我们将编写的最后一种类型的测试是实时服务器集成测试。在这个测试中，我们将启动一个测试 Django 服务器，并使用 Selenium 控制 Google Chrome 向其发出请求。

Selenium 是一个工具，它具有许多语言的绑定（包括 Python），可以让你控制一个网页浏览器。这样你就可以测试真实浏览器在使用你的项目时的行为，因为你是用真实浏览器测试你的项目。

这种类型的测试有一些限制：

+   实时测试通常需要按顺序运行

+   很容易在测试之间泄漏状态。

+   使用浏览器比`TestCase.client()`慢得多（浏览器会发出真正的 HTTP 请求）

尽管存在所有这些缺点，实时服务器测试在当前客户端网页应用如此强大的时代是一个非常宝贵的工具。

让我们首先设置 Selenium。

# 设置 Selenium

让我们通过使用`pip`来将 Selenium 添加到我们的项目中进行安装：

```py
$pip install selenium==3.8.0
```

接下来，我们需要特定的 webdriver，告诉 Selenium 如何与 Chrome 通信。Google 在[`sites.google.com/a/chromium.org/chromedriver/`](https://sites.google.com/a/chromium.org/chromedriver/)提供了一个**chromedriver**。在我们的情况下，让我们把它保存在项目目录的根目录下。然后，让我们在`django/conf/settings.py`中添加该驱动程序的路径：

```py
CHROMEDRIVER = os.path.join(BASE_DIR, '../chromedriver')
```

最后，请确保你的计算机上安装了 Google Chrome。如果没有，你可以在[`www.google.com/chrome/index.html`](https://www.google.com/chrome/index.html)下载它。

所有主要的浏览器都声称对 Selenium 有一定程度的支持。如果你不喜欢 Google Chrome，你可以尝试其他浏览器。有关详细信息，请参阅 Selenium 的文档（[`www.seleniumhq.org/about/platforms.jsp`](http://www.seleniumhq.org/about/platforms.jsp)）。

# 使用 Django 服务器和 Selenium 进行测试

现在我们已经设置好了 Selenium，我们可以创建我们的实时服务器测试。当我们的项目有很多 JavaScript 时，实时服务器测试特别有用。然而，Answerly 并没有任何 JavaScript。然而，Django 的表单确实利用了大多数浏览器（包括 Google Chrome）支持的 HTML5 表单属性。我们仍然可以测试我们的代码是否正确地使用了这些功能。

在这个测试中，我们将检查用户是否可以提交一个空的问题。`title`和`question`字段应该被标记为`required`，这样如果这些字段为空，浏览器就不会提交表单。

让我们在`django/qanda/tests.py`中添加一个新的测试：

```py
from django.contrib.staticfiles.testing import StaticLiveServerTestCase

from selenium.webdriver.chrome.webdriver import WebDriver

from user.factories import UserFactory

class AskQuestionTestCase(StaticLiveServerTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.selenium = WebDriver(executable_path=settings.CHROMEDRIVER)
        cls.selenium.implicitly_wait(10)

    @classmethod
    def tearDownClass(cls):
        cls.selenium.quit()
        super().tearDownClass()

    def setUp(self):
        self.user = UserFactory()

    def test_cant_ask_blank_question(self):
        initial_question_count = Question.objects.count()

        self.selenium.get('%s%s' % (self.live_server_url, '/user/login'))

        username_input = self.selenium.find_element_by_name("username")
        username_input.send_keys(self.user.username)
        password_input = self.selenium.find_element_by_name("password")
        password_input.send_keys(UserFactory.password)
        self.selenium.find_element_by_id('log_in').click()

        self.selenium.find_element_by_link_text("Ask").click()
        ask_question_url = self.selenium.current_url
        submit_btn = self.selenium.find_element_by_id('ask')
        submit_btn.click()
        after_empty_submit_click = self.selenium.current_url

        self.assertEqual(ask_question_url, after_empty_submit_click)
        self.assertEqual(initial_question_count, Question.objects.count())
```

让我们来看看这个测试中引入的一些新的 Django 特性。然后，我们将审查我们的 Selenium 代码：

+   `class AskQuestionTestCase(StaticLiveServerTestCase)`: `StaticLiveServerTestCase`启动了一个 Django 服务器，并确保静态文件被正确地提供。你不必运行`python manage.py collectstatic`。文件将被正确地路由，就像你运行`python manage.py runserver`一样。

+   `def setUpClass(cls)`: 所有的 Django 测试用例都支持`setUpClass()`、`setup()`、`teardown()`和`teardownClass()`方法，就像往常一样。`setUpClass`和`tearDownClass()`每个`TestCase`只运行一次（分别在之前和之后）。这使它们非常适合昂贵的操作，比如用 Selenium 连接到 Google Chrome。

+   `self.live_server_url`：这是实时服务器的 URL。

Selenium 允许我们使用 API 与浏览器进行交互。本书不侧重于 Selenium，但让我们来介绍一些`WebDriver`类的关键方法：

+   `cls.selenium = WebDriver(executable_path=settings.CHROMEDRIVER)`: 这实例化了一个 WebDriver 实例，其中包含到`ChromeDriver`可执行文件的路径（我们在前面的*设置 Selenium*部分中下载了）。我们将`ChromeDriver`可执行文件的路径存储在设置中，以便在这里轻松引用它。

+   `selenium.find_element_by_name(...)`: 这返回一个其`name`属性与提供的参数匹配的 HTML 元素。`name`属性被所有值由表单处理的`<input>`元素使用，因此对于数据输入特别有用。

+   `self.selenium.find_element_by_id(...)`: 这与前面的步骤类似，只是通过其`id`属性查找匹配的元素。

+   `self.selenium.current_url`: 这是浏览器的当前 URL。这对于确认我们是否在预期的页面上很有用。

+   `username_input.send_keys(...)`: `send_keys()`方法允许我们将传递的字符串输入到 HTML 元素中。这对于`<input type='text'>`和`<input type='password'>`元素特别有用。

+   `submit_btn.click()`: 这会触发对元素的点击。

这个测试以用户身份登录，尝试提交表单，并断言仍然在同一个页面上。不幸的是，虽然带有空的必填`input`元素的表单不会自行提交，但没有 API 直接确认这一点。相反，我们确认我们没有提交，因为浏览器仍然在与之前点击提交之前相同的 URL 上（根据`self.selenium.current_url`）。

# 总结

在本章中，我们学习了如何在 Django 项目中测量代码覆盖率，以及如何编写四种不同类型的测试——用于测试任何函数或类的单元测试，包括模型和表单；以及用于使用`RequestFactory`测试视图的视图单元测试。我们介绍了如何查看集成测试，用于测试请求路由到视图并返回正确响应，以及用于测试客户端和服务器端代码是否正确配合工作的实时服务器集成测试。

现在我们有了一些测试，让我们将 Answerly 部署到生产环境中。


# 第九章：部署 Answerly

在前一章中，我们了解了 Django 的测试 API，并为 Answerly 编写了一些测试。作为最后一步，让我们使用 Apache Web 服务器和 mod_wsgi 在 Ubuntu 18.04（Bionic Beaver）服务器上部署 Answerly。

本章假设您的服务器上有代码位于`/answerly`下，并且能够推送更新到该代码。您将在本章中对代码进行一些更改。尽管进行了更改，但您需要避免养成直接在生产环境中进行更改的习惯。例如，您可能正在使用版本控制系统（如 git）来跟踪代码的更改。然后，您可以在本地工作站上进行更改，将其推送到远程存储库（例如，托管在 GitHub 或 GitLab 上），并在服务器上拉取它们。这些代码在 GitHub 的版本控制中可用（[`github.com/tomarayn/Answerly`](https://github.com/tomarayn/Answerly)）。

在本章中，我们将做以下事情：

+   组织我们的配置代码以分离生产和开发设置

+   准备我们的 Ubuntu Linux 服务器

+   使用 Apache 和 mod_wsgi 部署我们的项目

+   看看 Django 如何让我们将项目部署为十二要素应用程序

让我们开始组织我们的配置，将开发和生产设置分开。

# 组织生产和开发的配置

到目前为止，我们一直保留了一个`requirements`文件和一个`settings.py`。这使得开发变得方便。但是，我们不能在生产中使用我们的开发设置。

当前的最佳实践是为每个环境单独创建一个文件。然后，每个环境的文件都导入具有共享值的公共文件。我们将使用这种模式来处理我们的要求和设置文件。

让我们首先拆分我们的要求文件。

# 拆分我们的要求文件

首先，让我们在项目的根目录创建`requirements.common.txt`：

```py
django<2.1
psycopg2==2.7.3.2
django-markdownify==0.2.2
django-crispy-forms==1.7.0
elasticsearch==6.0.0
```

无论我们的环境如何，这些都是我们运行 Answerly 所需的共同要求。然而，这个`requirements`文件从未直接使用过。我们的开发和生产要求文件将会引用它。

接下来，让我们在`requirements.development.txt`中列出我们的开发要求：

```py
-r requirements.common.txt
ipython==6.2.1
coverage==4.4.2
factory-boy==2.9.2
selenium==3.8.0
```

前面的文件将安装`requirements.common.txt`中的所有内容（感谢`-r`），以及我们的测试包（`coverage`，`factory-boy`和`selenium`）。我们将这些文件放在我们的开发文件中，因为我们不希望在生产环境中运行这些测试。如果我们在生产环境中运行测试，那么我们可能会将它们移动到`requirements.common.txt`中。

对于生产环境，我们的`requirements.production.txt`文件非常简单：

```py
-r requirements.common.txt
```

Answerly 不需要任何特殊的软件包。但是，为了清晰起见，我们仍将创建一个。

要在生产环境中安装软件包，我们现在执行以下命令：

```py
$ pip install -r requirements.production.txt
```

接下来，让我们按类似的方式拆分设置文件。

# 拆分我们的设置文件

同样，我们将遵循当前 Django 最佳实践，将我们的设置文件分成三个文件：`common_settings.py`，`production_settings.py`和`dev_settings.py`。

# 创建 common_settings.py

我们将通过重命名我们当前的`settings.py`文件并进行一些更改来创建`common_settings.py`。

让我们将`DEBUG = False`更改为不会*意外*处于调试模式的新设置文件。然后，让我们通过更新`SECRET_KEY = os.getenv('DJANGO_SECRET_KEY')`来从环境变量中获取密钥。

让我们还添加一个新的设置，`STATIC_ROOT`。`STATIC_ROOT`是 Django 将从我们安装的应用程序中收集所有静态文件的目录，以便更容易地提供它们：

```py
STATIC_ROOT = os.path.join(BASE_DIR, 'static_root')
```

在数据库配置中，我们可以删除所有凭据并保留`ENGINE`的值（以明确表明我们打算在任何地方使用 Postgres）：

```py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
    }
}
```

接下来，让我们创建一个开发设置文件。

# 创建 dev_settings.py

我们的开发设置将在`django/config/dev_settings.py`中。让我们逐步构建它。

首先，我们将从`common_settings`中导入所有内容：

```py
from config.common_settings import *
```

然后，我们将覆盖一些设置：

```py
DEBUG = True
SECRET_KEY = 'some secret'
```

在开发中，我们总是希望以调试模式运行。此外，我们可以放心地硬编码一个密钥，因为我们知道它不会在生产中使用：

```py
DATABASES['default'].update({
    'NAME': 'mymdb',
    'USER': 'mymdb',
    'PASSWORD': 'development',
    'HOST': 'localhost',
    'PORT': '5432',
})
```

由于我们的开发数据库是本地的，我们可以在设置中硬编码值，以使设置更简单。如果您的数据库不是本地的，请避免将密码检入版本控制，并像在生产中一样使用`os.getenv()`。

我们还可以添加我们的开发专用应用程序可能需要的更多设置。例如，在第五章中，*使用 Docker 部署*，我们有缓存和 Django Debug Toolbar 应用程序的设置。Answerly 目前不使用这些，所以我们不会包含这些设置。

接下来，让我们添加生产设置。

# 创建 production_settings.py

让我们在`django/config/production_settings.py`中创建我们的生产设置。

`production_settings.py`类似于`dev_settings.py`，但通常使用`os.getenv()`从环境变量中获取值。这有助于我们将机密（例如密码、API 令牌等）排除在版本控制之外，并将设置与特定服务器分离。我们将在*Factor 3 – config*部分再次提到这一点。

```py
from config.common_settings import * 
DEBUG = False
assert SECRET_KEY is not None, (
    'Please provide DJANGO_SECRET_KEY '
    'environment variable with a value')
ALLOWED_HOSTS += [
    os.getenv('DJANGO_ALLOWED_HOSTS'),
]
```

首先，我们导入通用设置。出于谨慎起见，我们确保调试模式关闭。

设置`SECRET_KEY`对于我们的系统保持安全至关重要。我们使用`assert`来防止 Django 在没有`SECRET_KEY`的情况下启动。`common_settings.py`文件应该已经从环境变量中设置了它。

生产网站将在`localhost`之外的域上访问。我们将通过将`DJANGO_ALLOWED_HOSTS`环境变量附加到`ALLOWED_HOSTS`列表来告诉 Django 我们正在提供哪些其他域。

接下来，让我们更新数据库配置：

```py
DATABASES['default'].update({
    'NAME': os.getenv('DJANGO_DB_NAME'),
    'USER': os.getenv('DJANGO_DB_USER'),
    'PASSWORD': os.getenv('DJANGO_DB_PASSWORD'),
    'HOST': os.getenv('DJANGO_DB_HOST'),
    'PORT': os.getenv('DJANGO_DB_PORT'),
})
```

我们使用环境变量的值更新了数据库配置。

现在我们的设置已经整理好了，让我们准备我们的服务器。

# 准备我们的服务器

现在我们的代码已经准备好投入生产，让我们准备我们的服务器。在本章中，我们将使用 Ubuntu 18.04（Bionic Beaver）。如果您使用其他发行版，则某些软件包名称可能不同，但我们将采取的步骤将是相同的。

为了准备我们的服务器，我们将执行以下步骤：

1.  安装所需的操作系统软件包

1.  设置 Elasticsearch

1.  创建数据库

让我们从安装我们需要的软件包开始。

# 安装所需的软件包

要在我们的服务器上运行 Answerly，我们需要确保正确的软件正在运行。

让我们创建一个我们将在`ubuntu/packages.txt`中需要的软件包列表：

```py
python3
python3-pip
virtualenv

apache2
libapache2-mod-wsgi-py3

postgresql
postgresql-client

openjdk-8-jre-headless
```

前面的代码将为以下内容安装软件包：

+   完全支持 Python 3

+   Apache HTTP 服务器

+   mod_wsgi，用于运行 Python Web 应用程序的 Apache HTTP 模块

+   PostgreSQL 数据库服务器和客户端

+   Java 8，Elasticsearch 所需

要安装软件包，请运行以下命令：

```py
$ sudo apt install -y $(cat /answerly/ubuntu/packages.txt)
```

接下来，我们将把我们的 Python 软件包安装到虚拟环境中：

```py
$ mkvirutalenv /opt/answerly.venv
$ source /opt/answerly.venv/bin/activate
$ pip install -r /answerly/requirements.production.txt
```

太好了！现在我们有了所有的软件包，我们需要设置 Elasticsearch。不幸的是，Ubuntu 没有提供最新版本的 Elasticsearch，所以我们将直接从 Elastic 安装它。

# 配置 Elasticsearch

我们将直接从 Elastic 获取 Elasticsearch。Elastic 通过在具有 Ubuntu 兼容的`.deb`软件包的服务器上运行来简化此过程（如果对您更方便，Elastic 还提供并支持 RPM）。最后，我们必须记住将 Elasticsearch 重新绑定到 localhost，否则我们将在开放的公共端口上运行一个不安全的服务器。

# 安装 Elasticsearch

让我们通过运行以下三个命令将 Elasticsearch 添加到我们信任的存储库中：

```py
$ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
$ sudo apt install apt-transport-https
$ echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
$ sudo apt update
```

前面的命令执行以下四个步骤：

1.  将 Elastic GPG 密钥添加到受信任的 GPG 密钥列表中

1.  通过安装`apt-transport-https`软件包，确保`apt`通过`HTTPS`获取软件包

1.  添加一个新的源文件，列出 Elastic 软件包服务器，以便`apt`知道如何从 Elastic 获取 Elasticsearch 软件包

1.  更新可用软件包列表（现在将包括 Elasticsearch）

现在我们有了 Elasticsearch，让我们安装它：

```py
$ sudo apt install elasticsearch
```

接下来，让我们配置 Elasticsearch。

# 运行 Elasticsearch

默认情况下，Elasticsearch 配置为绑定到公共 IP 地址，并且不包括身份验证。

要更改 Elasticsearch 运行的地址，让我们编辑`/etc/elasticsearch/elasticsearch.yml`。找到带有`network.host`的行并更新如下：

```py
network.host: 127.0.0.1
```

如果您不更改`network.host`设置，那么您将在公共 IP 上运行没有身份验证的 Elasticsearch。您的服务器被黑客攻击将是不可避免的。

最后，我们要确保 Ubuntu 启动 Elasticsearch 并保持其运行。为了实现这一点，我们需要告诉 systemd 启动 Elasticsearch：

```py
$ sudo systemctl daemon-reload
$ sudo systemctl enable elasticsearch.service
$ sudo systemctl start elasticsearch.service
```

上述命令执行以下三个步骤：

1.  完全重新加载 systemd，然后它将意识到新安装的 Elasticsearch 服务

1.  启用 Elasticsearch 服务，以便在服务器启动时启动（以防重新启动或关闭）

1.  启动 Elasticsearch

如果您需要停止 Elasticsearch 服务，可以使用`systemctl`：`sudo systemctl stop elasticsearch.service`。

现在我们已经运行了 Elasticsearch，让我们配置数据库。

# 创建数据库

Django 支持迁移，但不能自行创建数据库或数据库用户。我们现在将编写一个脚本来为我们执行这些操作。

让我们将数据库创建脚本添加到我们的项目中的`postgres/make_database.sh`：

```py
#!/usr/bin/env bash

psql -v ON_ERROR_STOP=1 <<-EOSQL
    CREATE DATABASE $DJANGO_DB_NAME;
    CREATE USER $DJANGO_DB_USER;
    GRANT ALL ON DATABASE $DJANGO_DB_NAME to "$DJANGO_DB_USER";
    ALTER USER $DJANGO_DB_USER PASSWORD '$DJANGO_DB_PASSWORD';
    ALTER USER $DJANGO_DB_USER CREATEDB;
EOSQL
```

要创建数据库，请运行以下命令：

```py
$ sudo su postgres
$ export DJANGO_DB_NAME=answerly
$ export DJANGO_DB_USER=answerly
$ export DJANGO_DB_PASSWORD=password
$ bash /answerly/postgres/make_database.sh
```

上述命令执行以下三件事：

1.  切换到`postgres`用户，该用户被信任可以连接到 Postgres 数据库而无需任何额外的凭据。

1.  设置环境变量，描述我们的新数据库用户和模式。**记得将`password`的值更改为一个强密码。**

1.  执行`make_database.sh`脚本。

现在我们已经配置了服务器，让我们使用 Apache 和 mod_wsgi 部署 Answerly。

# 使用 Apache 部署 Answerly

我们将使用 Apache 和 mod_wsgi 部署 Answerly。mod_wsgi 是一个开源的 Apache 模块，允许 Apache 托管实现**Web 服务器网关接口**（**WSGI**）规范的 Python 程序。

Apache web 服务器是部署 Django 项目的众多优秀选项之一。许多组织都有一个运维团队，他们部署 Apache 服务器，因此使用 Apache 可以消除在项目中使用 Django 时的一些组织障碍。Apache（带有 mod_wsgi）还知道如何运行多个 web 应用程序并在它们之间路由请求，与我们在第五章中的先前配置不同，*使用 Docker 部署*，我们需要一个反向代理（NGINX）和 web 服务器（uWSGI）。使用 Apache 的缺点是它比 uWSGI 使用更多的内存。此外，Apache 没有一种将环境变量传递给我们的 WSGI 进程的方法。总的来说，使用 Apache 进行部署可以成为 Django 开发人员工具中非常有用和重要的一部分。

要部署，我们将执行以下操作：

1.  创建虚拟主机配置

1.  更新`wsgi.py`

1.  创建一个环境配置文件

1.  收集静态文件

1.  迁移数据库

1.  启用虚拟主机

让我们为我们的 Apache web 服务器开始创建一个虚拟主机配置。

# 创建虚拟主机配置

一个 Apache web 服务器可以使用来自不同位置的不同技术托管许多网站。为了保持每个网站的独立性，Apache 提供了定义虚拟主机的功能。每个虚拟主机是一个逻辑上独立的站点，可以为一个或多个域和端口提供服务。

由于 Apache 已经是一个很好的 Web 服务器，我们将使用它来提供静态文件。提供静态文件的 Web 服务器和我们的 mod_wsgi 进程不会竞争，因为它们将作为独立的进程运行，这要归功于 mod_wsgi 的守护进程模式。mod_wsgi 守护进程模式意味着 Answerly 将在与 Apache 的其余部分分开的进程中运行。Apache 仍然负责启动/停止这些进程。

让我们在项目的`apache/answerly.apache.conf`下添加 Apache 虚拟主机配置：

```py
<VirtualHost *:80>

    WSGIDaemonProcess answerly \
        python-home=/opt/answerly.venv \
        python-path=/answerly/django \
        processes=2 \
        threads=15
    WSGIProcessGroup answerly
    WSGIScriptAlias / /answerly/django/config/wsgi.py

    <Directory /answerly/django/config>
        <Files wsgi.py>
            Require all granted
        </Files>
    </Directory>

    Alias /static/ /answerly/django/static_root
    <Directory /answerly/django/static_root>
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

让我们仔细看一下其中的一些指令：

+   `<VirtualHost *:80>`：这告诉 Apache，直到关闭的`</VirtualHost>`标签之前的所有内容都是虚拟主机定义的一部分。

+   `WSGIDaemonProcess`：这配置 mod_wsgi 以守护进程模式运行。守护进程将被命名为`answerly`。`python-home`选项定义了守护进程将使用的 Python 进程的虚拟环境。`python-path`选项允许我们将我们的模块添加到守护进程的 Python 中，以便它们可以被导入。`processes`和`threads`选项告诉 Apache 要维护多少个进程和线程。

+   `WSGIProcessGroup`：这将虚拟主机与 Answerly mod_wsgi 守护进程关联起来。记住要保持`WSGIDaemonProcess`名称和`WSGIProcessGroup`名称相同。

+   `WSGIScriptAlias`：这描述了应该将哪些请求路由到哪个 WSGI 脚本。在我们的情况下，所有请求都应该转到 Answerly 的 WSGI 脚本。

+   `<Directory /answerly/django/config>`：这个块允许所有用户访问我们的 WSGI 脚本。

+   `Alias /static/ /answerly/django/static_root`：这将任何以`/static/`开头的请求路由到我们的静态文件根目录，而不是 mod_wsgi。

+   `<Directory /answerly/django/static_root>`：这个块允许用户访问`static_root`中的文件。

+   `ErrorLog`和`CustomLog`：它们描述了 Apache 应该将其日志发送到这个虚拟主机的位置。在我们的情况下，我们希望将其记录在 Apache 的`log`目录中（通常是`/var/log/apache`）。

我们现在已经配置 Apache 来运行 Answerly。然而，如果你比较一下你的 Apache 配置和第五章中的 uWSGI 配置，*使用 Docker 部署*，你会注意到一个区别。在 uWSGI 配置中，我们提供了我们的`production_settings.py`依赖的环境变量。然而，mod_wsgi 并没有为我们提供这样的功能。相反，我们将更新`django/config/wsgi.py`，以提供`production_settings.py`需要的环境变量。

# 更新 wsgi.py 以设置环境变量

现在，我们将更新`django/config/wsgi.py`，以提供`production_settings.py`想要的环境变量，但 mod_wsgi 无法提供。我们还将更新`wsgi.py`，在启动时读取配置文件，然后自己设置环境变量。这样，我们的生产设置不会与 mod_wsgi 或配置文件耦合。

让我们更新`django/config/wsgi.py`：

```py
import os
import configparser
from django.core.wsgi import get_wsgi_application

if not os.environ.get('DJANGO_SETTINGS_MODULE'):
    parser = configparser.ConfigParser()
    parser.read('/etc/answerly/answerly.ini')
    for name, val in parser['mod_wsgi'].items():
        os.environ[name.upper()] = val

application = get_wsgi_application()
```

在更新的`wsgi.py`中，我们检查是否有`DJANGO_SETTINGS_MODULE`环境变量。如果没有，我们解析我们的配置文件并设置环境变量。我们的`for`循环将变量的名称转换为大写，因为`ConfigParser`默认会将它们转换为`小写`。

接下来，让我们创建我们的环境配置文件。

# 创建环境配置文件

我们将把环境配置存储在`/etc/answerly/answerly.ini`下。我们不希望它存储在`/answerly`下，因为它不是我们代码的一部分。这个文件描述了*只有*这台服务器的设置。我们永远不应该将这个文件提交到版本控制中。

让我们在服务器上创建`/etc/answerly/answerly.ini`：

```py
[mod_wsgi]
DJANGO_ALLOWED_HOSTS=localhost
DJANGO_DB_NAME=answerly
DJANGO_DB_USER=answerly
DJANGO_DB_PASSWORD=password
DJANGO_DB_HOST=localhost
DJANGO_DB_PORT=5432
DJANGO_ES_INDEX=answerly
DJANGO_ES_HOST=localhost
DJANGO_ES_PORT=9200
DJANGO_LOG_FILE=/var/log/answerly/answerly.log
DJANGO_SECRET_KEY=a large random value
DJANGO_SETTINGS_MODULE=config.production_settings
```

以下是关于这个文件的两件事需要记住的：

+   记得将`DJANGO_DB_PASSWORD`设置为你在运行`make_database.sh`脚本时设置的相同值。*记得确保这个密码是强大和保密的*。

+   记得设置一个强大的`DJANGO_SECRET_KEY`值。

我们现在应该已经为 Apache 设置好了环境。接下来，让我们迁移数据库。

# 迁移数据库

我们在之前的步骤中为 Answerly 创建了数据库，但我们没有创建表。现在让我们使用 Django 内置的迁移工具迁移数据库。

在服务器上，我们希望执行以下命令：

```py
$ cd /answerly/django
$ source /opt/answerly.venv/bin/activate
$ export DJANGO_SECRET_KEY=anything
$ export DJANGO_DB_HOST=127.0.0.1 
$ export DJANGO_DB_PORT=5432 
$ export DJANGO_LOG_FILE=/var/log/answerly/answerly.log 
$ export DJANGO_DB_USER=myqa 
$ export DJANGO_DB_NAME=myqa 
$ export DJANGO_DB_PASSWORD=password 
$ sudo python3 manage.py migrate --settings=config.production_settings
```

我们的`django/config/production_settings.py`将要求我们提供带有值的`DJANGO_SECRET_KEY`，但在这种情况下不会使用它。但是，为`DJANGO_DB_PASSWORD`和其他`DJANGO_DB`变量提供正确的值至关重要。

一旦我们的`migrate`命令返回成功，那么我们的数据库将拥有我们需要的所有表。

接下来，让我们让我们的静态（JavaScript/CSS/图像）文件对我们的用户可用。

# 收集静态文件

在我们的虚拟主机配置中，我们配置了 Apache 来提供我们的静态（JS，CSS，图像等）文件。为了让 Apache 提供这些文件，我们需要将它们全部收集到一个父目录下。让我们使用 Django 内置的`manage.py collectstatic`命令来做到这一点。

在服务器上，让我们运行以下命令：

```py
$ cd /answerly/django
$ source /opt/answerly.venv/bin/activate
$ export DJANGO_SECRET_KEY=anything
$ export DJANGO_LOG_FILE=/var/log/answerly/answerly.log
$ sudo python3 manage.py collectstatic --settings=config.production_settings --no-input
```

上述命令将从所有已安装的应用程序复制静态文件到`/answerly/django/static_root`（根据`production_settings.py`中的`STATIC_ROOT`定义）。我们的虚拟主机配置告诉 Apache 直接提供这些文件。

现在，让我们告诉 Apache 开始提供 Answerly。

# 启用 Answerly 虚拟主机

为了让 Apache 向用户提供 Answerly，我们需要启用我们在上一节创建的虚拟主机配置，创建虚拟主机配置。要在 Apache 中启用虚拟主机，我们将在虚拟主机配置上添加一个软链接指向 Apache 的`site-enabled`目录，并告诉 Apache 重新加载其配置。

首先，让我们将我们的软链接添加到 Apache 的`site-enabled`目录：

```py
$ sudo ln -s /answerly/apache/answerly.apache.conf /etc/apache/site-enabled/000-answerly.conf
```

我们使用`001`作为软链接的前缀来控制我们的配置加载顺序。Apache 按字符顺序加载站点配置文件（例如，在 Unicode/ASCII 编码中，`B`在`a`之前）。前缀用于使顺序更加明显。

Apache 经常与默认站点捆绑在一起。查看`/etc/apache/sites-enabled/`以查找不想运行的站点。由于其中的所有内容都应该是软链接，因此可以安全地删除它们。

要激活虚拟主机，我们需要重新加载 Apache 的配置：

```py
$ sudo systemctl reload  apache2.service
```

恭喜！您已经在服务器上部署了 Answerly。

# 快速回顾本节

到目前为止，在本章中，我们已经了解了如何使用 Apache 和 mod_wsgi 部署 Django。首先，我们通过从 Ubuntu 和 Elastic（用于 Elasticsearch）安装软件包来配置了我们的服务器。然后，我们配置了 Apache 以将 Answerly 作为虚拟主机运行。我们的 Django 代码将由 mod_wsgi 执行。

到目前为止，我们已经看到了两种非常不同的部署方式，一种使用 Docker，一种使用 Apache 和 mod_wsgi。尽管是非常不同的环境，但我们遵循了许多相似的做法。让我们看看 Django 最佳实践是如何符合流行的十二要素应用方法论的。

# 将 Django 项目部署为十二要素应用

*十二要素应用*文档解释了一种开发 Web 应用和服务的方法论。这些原则是由 Adam Wiggins 和其他人在 2011 年主要基于他们在 Heroku（一家知名的平台即服务提供商）的经验而记录的。Heroku 是最早帮助开发人员构建易于扩展的 Web 应用和服务的 PaaS 之一。自发布以来，十二要素应用的原则已经塑造了很多关于如何构建和部署 SaaS 应用（如 Web 应用）的思考。

十二要素提供了许多好处，如下：

+   使用声明性格式来简化自动化和入职

+   强调在部署环境中的可移植性

+   鼓励生产/开发环境的一致性和持续部署和集成

+   简化扩展而无需重新架构

然而，在评估十二因素时，重要的是要记住它们与 Heroku 的部署方法紧密相关。并非所有平台（或 PaaS 提供商）都有完全相同的方法。这并不是说十二因素是正确的，其他方法是错误的，反之亦然。相反，十二因素是要牢记的有用原则。您应该根据需要调整它们以帮助您的项目，就像您对待任何方法论一样。

单词*应用程序*的十二因素用法与 Django 的可用性不同：

+   Django 项目相当于十二因素应用程序

+   Django 应用程序相当于十二因素库

在本节中，我们将研究十二个因素的每个含义以及它们如何应用到您的 Django 项目中。

# 因素 1 - 代码库

“一个代码库在修订控制中跟踪，多个部署” - [12factor.net](http://12factor.net)

这个因素强调了以下两点：

+   所有代码都应该在版本控制的代码存储库（repo）中进行跟踪

+   每次部署都应该能够引用该存储库中的单个版本/提交

这意味着当我们遇到错误时，我们确切地知道是哪个代码版本负责。如果我们的项目跨越多个存储库，十二因素方法要求共享代码被重构为库并作为依赖项进行跟踪（参见*因素 2 - 依赖关系*部分）。如果多个项目使用同一个存储库，那么它们应该被重构为单独的存储库（有时称为*多存储库*）。自十二因素首次发布以来，多存储库与单存储库（一个存储库用于多个项目）的使用已经越来越受到争议。一些大型项目发现使用单存储库有益处。其他项目通过多个存储库取得了成功。

基本上，这个因素努力确保我们知道在哪个环境中运行什么。

我们可以以可重用的方式编写我们的 Django 应用程序，以便它们可以作为使用`pip`安装的库进行托管（多存储库样式）。或者，您可以通过修改 Django 项目的 Python 路径，将所有 Django 项目和应用程序托管在同一个存储库（单存储库）中。

# 因素 2 - 依赖关系

“明确声明和隔离依赖关系” - [12 factor.net](https://12factor.net)

十二因素应用程序不应假设其环境的任何内容。项目使用的库和工具必须由项目声明并作为部署的一部分安装（参见*因素 5 - 构建、发布和运行*部分）。所有运行的十二因素应用程序都应该相互隔离。

Django 项目受益于 Python 丰富的工具集。 “在 Python 中，这些步骤有两个单独的工具 - Pip 用于声明，Virtualenv 用于隔离”（[`12factor.net/dependencies`](https://12factor.net/dependencies)）。在 Answerly 中，我们还使用了一系列我们用`apt`安装的 Ubuntu 软件包。

# 因素 3 - 配置

将配置存储在环境中 - [12factor.net](http://12factor.net)

十二因素应用程序方法提供了一个有用的配置定义：

“应用程序的配置是在部署之间可能变化的所有内容（暂存、生产、开发环境等）” - [`12factor.net/config`](https://12factor.net/config)

十二因素应用程序方法还鼓励使用环境变量来传递配置值给我们的代码。这意味着如果出现问题，我们可以测试确切部署的代码（由因素 1 提供）以及使用的确切配置。我们还可以通过使用不同的配置部署相同的代码来检查错误是配置问题还是代码问题。

在 Django 中，我们的配置由我们的`settings.py`文件引用。在 MyMDB 和 Answerly 中，我们看到了一些常见的配置值，如`SECRET_KEY`、数据库凭据和 API 密钥（例如 AWS 密钥），通过环境变量传递。

然而，这是一个领域，Django 最佳实践与十二要素应用的最严格解读有所不同。Django 项目通常为分别用于分阶段、生产和本地开发的设置文件创建一个单独的设置文件，大多数设置都是硬编码的。主要是凭据和秘密作为环境变量传递。

# Factor 4 – 后备服务

"将后备服务视为附加资源" – [12factor.net](https://12factor.net)

十二要素应用不应关心后备服务（例如数据库）的位置，并且应始终通过 URL 访问它。这样做的好处是我们的代码不与特定环境耦合。这种方法还允许我们架构的每个部分独立扩展。

在本章中部署的 Answerly 与其数据库位于同一服务器上。然而，我们没有使用本地身份验证机制，而是向 Django 提供了主机、端口和凭据。这样，我们可以将数据库移动到另一台服务器上，而不需要更改任何代码。我们只需要更新我们的配置。

Django 的编写假设我们会将大多数服务视为附加资源（例如，大多数数据库文档都是基于这一假设）。在使用第三方库时，我们仍然需要遵循这一原则。

# Factor 5 – 构建、发布和运行

"严格分离构建和运行阶段" – [12factor.net](https://12factor.net)

十二要素方法鼓励将部署分为三个明确的步骤：

1.  **构建**：代码和依赖项被收集到一个单一的捆绑包中（一个*构建*）

1.  **发布**：构建与配置组合在一起，准备执行

1.  **运行**：组合构建和配置的执行位置

十二要素应用还要求每个发布都有一个唯一的 ID，以便可以识别它。

这种部署细节已经超出了 Django 的范围，对这种严格的三步模型的遵循程度有各种各样。在第五章中看到的使用 Django 和 Docker 的项目可能会非常严格地遵循这一原则。MyMDB 有一个清晰的构建，所有依赖项都捆绑在 Docker 镜像中。然而，在本章中，我们从未进行捆绑构建。相反，我们在代码已经在服务器上之后安装依赖项（运行`pip install`）。许多项目都成功地使用了这种简单的模型。然而，随着项目规模的扩大，这可能会引起复杂性。Answerly 的部署展示了十二要素原则如何可以被弯曲，但对于某些项目仍然有效。

# Factor 6 – 进程

"将应用程序作为一个或多个无状态进程执行" – [12factor.net](https://12factor.net)

这一因素的重点是应用进程应该是*无状态*的。每个任务都是在不依赖前一个任务留下数据的情况下执行的。相反，状态应该存储在后备服务中（参见*Factor 4 – 后备服务*部分），比如数据库或外部缓存。这使得应用能够轻松扩展，因为所有进程都同样有资格处理请求。

Django 是围绕这一假设构建的。即使是会话，用户的登录状态也不是保存在进程中，而是默认保存在数据库中。视图类的实例永远不会被重用。Django 接近违反这一点的唯一地方是缓存后端之一（本地内存缓存）。然而，正如我们讨论过的，那是一个低效的后端。通常，Django 项目会为它们的缓存使用一个后备服务（例如 memcached）。

# Factor 7 – 端口绑定

"通过端口绑定导出服务" – [12factor.net](https://12factor.net)

这个因素的重点是我们的进程应该通过其端口直接访问。访问一个项目应该是向`app.example.com:1234`发送一个正确形成的请求。此外，十二要素应用程序不应该作为 Apache 模块或 Web 服务器容器运行。如果我们的项目需要解析 HTTP 请求，应该使用库（参见*因素 2-依赖*部分）来解析它们。

Django 遵循这个原则的部分。用户通过 HTTP 端口使用 HTTP 访问 Django 项目。与十二要素有所不同的是，Django 的一个方面几乎总是作为 Web 服务器的子进程运行（无论是 Apache、uWSGI 还是其他什么）。进行端口绑定的是 Web 服务器，而不是 Django。然而，这种微小的差异并没有阻止 Django 项目有效地扩展。

# 因素 8-并发

“通过进程模型扩展”- [12factor.net](https://12factor.net)

十二要素应用程序的原则侧重于扩展（对于像 Heroku 这样的 PaaS 提供商来说是一个重要的关注点）。在因素 8 中，我们看到之前做出的权衡和决策如何帮助项目扩展。

由于项目作为无状态进程运行（参见*因素 6-进程*部分），作为端口（参见*因素 7-端口绑定*部分）可用，并发性只是拥有更多进程（跨一个或多个机器）的问题。进程不需要关心它们是否在同一台机器上，因为任何状态（比如问题的答案）都存储在后备服务（参见*因素 4-后备服务*部分）中，比如数据库。因素 8 告诉我们要相信 Unix 进程模型来运行服务，而不是创建守护进程或创建 PID 文件。

由于 Django 项目作为 Web 服务器的子进程运行，它们经常遵循这个原则。需要扩展的 Django 项目通常使用反向代理（例如 Nginx）和轻量级 Web 服务器（例如 uWSGI 或 Gunicorn）的组合。Django 项目不直接关注进程的管理方式，而是遵循它们正在使用的 Web 服务器的最佳实践。

# 因素 9-可处置性

“通过快速启动和优雅关闭来最大限度地提高鲁棒性”- [12factor.net](https://12factor.net)

可处置性因素有两个部分。首先，十二要素应用程序应该能够在进程启动后不久开始处理请求。记住，所有它的依赖关系（参见*因素 2-依赖*部分）已经被安装（参见*因素 5-构建、发布和运行*部分）。十二要素应用程序应该处理进程停止或优雅关闭。进程不应该使十二要素应用程序处于无效状态。

Django 项目能够优雅地关闭，因为 Django 默认会将每个请求包装在一个原子事务中。如果一个 Django 进程（无论是由 uWSGI、Apache 还是其他任何东西管理的）在处理请求时停止，事务将永远不会被提交。数据库将放弃该事务。当我们处理其他后备服务（例如 S3 或 Elasticsearch）不支持事务时，我们必须确保在设计中考虑到这一点。

# 因素 10-开发/生产对等性

“尽量使开发、分期和生产尽可能相似”- [12factor.net](https://12factor.net)

十二要素应用程序运行的所有环境应尽可能相似。当十二要素应用程序是一个简单的进程时（参见*因素 6-进程*部分），这就容易得多。这还包括十二要素应用程序使用的后备服务（参见*因素 4-后备服务*部分）。例如，十二要素应用程序的开发环境应该包括与生产环境相同的数据库。像 Docker 和 Vagrant 这样的工具可以使今天实现这一点变得更加容易。

Django 的一般最佳实践是在开发和生产中使用相同的数据库（和其他后端服务）。在本书中，我们一直在努力做到这一点。然而，Django 社区通常在开发中使用`manage.py runserver`命令，而不是运行 uWSGI 或 Apache。

# 11 因素 - 日志

"将日志视为事件流" - [12factor.net](https://12factor.net)

日志应该只作为无缓冲的`stdout`流输出，*十二因素应用程序永远不会关心其输出流的路由或存储*（[`12factor.net/logs`](https://12factor.net/logs)）。当进程运行时，它应该只输出无缓冲的内容到`stdout`。然后启动进程的人（无论是开发人员还是生产服务器的 init 进程）可以适当地重定向该流。

Django 项目通常使用 Python 的日志模块。这可以支持写入日志文件或输出无缓冲流。一般来说，Django 项目会追加到一个文件中。该文件可以单独处理或旋转（例如，使用`logrotate`实用程序）。

# 12 因素 - 管理流程

"将管理/管理任务作为一次性进程运行" - [12factor.net](https://12factor.net)

所有项目都需要不时运行一次性任务（例如，数据库迁移）。当十二因素应用程序的一次性任务运行时，它应该作为一个独立的进程运行，而不是处理常规请求的进程。但是，一次性进程应该与所有其他进程具有相同的环境。

在 Django 中，这意味着在运行我们的`manage.py`任务时使用相同的虚拟环境、设置文件和环境变量作为我们的正常进程。这就是我们之前迁移数据库时所做的。

# 快速审查本节

在审查了十二因素应用程序的所有原则之后，我们将看看 Django 项目如何遵循这些原则，以帮助我们的项目易于部署、扩展和自动化。

Django 项目和严格的十二因素应用程序之间的主要区别在于，Django 应用程序是由 Web 服务器而不是作为独立进程运行的（因素 6）。然而，只要我们避免复杂的 Web 服务器配置（就像在本书中所做的那样），我们就可以继续获得作为十二因素应用程序的好处。

# 摘要

在本章中，我们专注于将 Django 部署到运行 Apache 和 mod_wsgi 的 Linux 服务器上。我们还审查了十二因素应用程序的原则以及 Django 应用程序如何使用它们来实现易于部署、扩展和自动化。

恭喜！您已经推出了 Answerly。

在下一章中，我们将看看如何创建一个名为 MailApe 的邮件列表管理应用程序。


# 第十章：启动 Mail Ape

在本章中，我们将开始构建 Mail Ape，一个邮件列表管理器，让用户可以开始邮件列表、注册邮件列表，然后给人发消息。订阅者必须确认他们对邮件列表的订阅，并且能够取消订阅。这将帮助我们确保 Mail Ape 不被用来向用户发送垃圾邮件。

在本章中，我们将构建 Mail Ape 的核心 Django 功能：

+   我们将构建描述 Mail Ape 的模型，包括`MailingList`和`Subscriber`

+   我们将使用 Django 的基于类的视图来创建网页

+   我们将使用 Django 内置的身份验证功能让用户登录

+   我们将确保只有`MailingList`模型实例的所有者才能给其订阅者发送电子邮件

+   我们将创建模板来生成 HTML 以显示订阅和给用户发送电子邮件的表单

+   我们将使用 Django 内置的开发服务器在本地运行 Mail Ape

该项目的代码可在[`github.com/tomaratyn/MailApe`](https://github.com/tomaratyn/MailApe)上找到。

Django 遵循**模型视图模板**（**MVT**）模式，以分离模型、控制和表示逻辑，并鼓励可重用性。模型代表我们将在数据库中存储的数据。视图负责处理请求并返回响应。视图不应该包含 HTML。模板负责响应的主体和定义 HTML。这种责任的分离已被证明使编写代码变得容易。

让我们开始创建 Mail Ape 项目。

# 创建 Mail Ape 项目

在本节中，我们将创建 MailApe 项目：

```py
$ mkdir mailape
$ cd mailape
```

本书中的所有路径都将相对于此目录。

# 列出我们的 Python 依赖项

接下来，让我们创建一个`requirements.txt`文件来跟踪我们的 Python 依赖项：

```py
django<2.1
psycopg2<2.8
django-markdownify==0.3.0
django-crispy-forms==1.7.0
```

现在我们知道我们的需求，我们可以按照以下方式安装它们：

```py
$ pip install -r requirements.txt
```

这将安装以下四个库：

+   `Django`：我们最喜欢的 Web 应用程序框架

+   `psycopg2`：Python PostgreSQL 库；我们将在生产和开发中都使用 PostgreSQL

+   `django-markdownify`：一个使在 Django 模板中呈现 markdown 变得容易的库

+   `django-crsipy-forms`：一个使在模板中创建 Django 表单变得容易的库

有了 Django 安装，我们可以使用`django-admin`实用程序来创建我们的项目。

# 创建我们的 Django 项目和应用程序

Django 项目由配置目录和一个或多个 Django 应用程序组成。已安装的应用程序封装了项目的实际功能。默认情况下，配置目录以项目命名。

Web 应用程序通常由远不止执行的 Django 代码组成。我们需要配置文件、系统依赖和文档。为了帮助未来的开发人员（包括我们未来的自己），我们将努力清晰地标记每个目录：

```py
$ django-admin startporject config
$ mv config django
$ tree django
django
├── config
│   ├── __init__.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
└── manage.py
```

通过这种方法，我们的目录结构清楚地指明了我们的 Django 代码和配置的位置。

接下来，让我们创建将封装我们功能的应用程序：

```py
$ python manage.py startapp mailinglist
$ python manage.py startapp user
```

对于每个应用程序，我们应该创建一个 URLConf。URLConf 确保请求被路由到正确的视图。URLConf 是路径列表，提供路径的视图和路径的名称。URLConfs 的一个很棒的功能是它们可以相互包含。当创建 Django 项目时，它会得到一个根 URLConf（我们的在`django/config/urls.py`）。由于 URLConf 可能包含其他 URLConfs，名称提供了一种重要的方式来引用 URL 路径到视图，而不需要知道视图的完整 URL 路径。

# 创建我们应用的 URLConfs

让我们为`mailinglist`应用程序创建一个 URLConf，位于`django/mailinglist/urls.py`中：

```py
from django.urls import path

from mailinglist import views

app_name = 'mailinglist'

urlpatterns = [
]
```

`app_name`变量用于在名称冲突的情况下限定路径。在解析路径名时，我们可以使用`mailinglist:`前缀来确保它来自此应用程序。随着我们构建视图，我们将向`urlpatterns`列表添加`path`。

接下来，让我们通过创建`django/user/urls.py`为`user`应用程序创建另一个 URLConf：

```py
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

import user.views

app_name = 'user'
urlpatterns = [
]
```

太棒了！现在，让我们将它们包含在位于`django/config/urls.py`中的根 ULRConf 中：

```py
from django.contrib import admin
from django.urls import path, include

import mailinglist.urls
import user.urls

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/', include(user.urls, namespace='user')),
    path('mailinglist/', include(mailinglist.urls, namespace='mailinglist')),
]
```

根 URLConf 就像我们应用程序的 URLConfs 一样。它有一个`path()`对象的列表。根 URLConfs 中的`path()`对象通常没有视图，而是`include()`其他 URLConfs。让我们来看看这里的两个新函数：

+   `path()`: 这需要一个字符串和一个视图或`include()`的结果。Django 将在 URLConf 中迭代`path()`，直到找到与请求路径匹配的路径。然后 Django 将请求传递给该视图或 URLConf。如果是 URLConf，则会检查`path()`的列表。

+   `include()`: 这需要一个 URLConf 和一个命名空间名称。命名空间将 URLConfs 相互隔离，以便我们可以防止名称冲突，确保我们可以区分`appA:index`和`appB:index`。`include()`返回一个元组；`admin.site.urls`上的对象已经是一个正确格式的元组，所以我们不必使用`include()`。通常，我们总是使用`include()`。

如果 Django 找不到与请求路径匹配的`path()`对象，那么它将返回 404 响应。

这个 URLConf 的结果如下：

+   任何以`admin/`开头的请求将被路由到管理员应用的 URLConf

+   任何以`mailinglist/`开头的请求将被路由到`mailinglist`应用的 URLConf

+   任何以`user/`开头的请求将被路由到`user`应用的 URLConf

# 安装我们项目的应用程序

让我们更新`django/config/settings.py`以安装我们的应用程序。我们将更改`INSTALLED_APPS`设置，如下面的代码片段所示：

```py
INSTALLED_APPS = [
    'user',
    'mailinglist',

    'crispy_forms',
    'markdownify',

    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]
```

现在我们已经配置好了我们的项目和应用程序，让我们为我们的`mailinglist`应用创建模型。

# 创建邮件列表模型

在这一部分，我们将为我们的`mailinglist`应用创建模型。Django 提供了丰富而强大的 ORM，让我们能够在 Python 中定义我们的模型，而不必直接处理数据库。ORM 将我们的 Django 类、字段和对象转换为关系数据库概念：

+   模型类映射到关系数据库表

+   字段映射到关系数据库列

+   模型实例映射到关系数据库行

每个模型还带有一个默认的管理器，可在`objects`属性中使用。管理器提供了在模型上运行查询的起点。管理器最重要的方法之一是`create()`。我们可以使用`create()`在数据库中创建模型的实例。管理器也是获取模型的`QuerySet`的起点。

`QuerySet`代表模型的数据库查询。`QuerySet`是惰性的，只有在迭代或转换为`bool`时才执行。`QuerySet` API 提供了大部分 SQL 的功能，而不与特定的数据库绑定。两个特别有用的方法是`QuerySet.filter()`和`QuerySet.exclude()`。`QuerySet.filter()`让我们将`QuerySet`的结果过滤为只匹配提供的条件的结果。`QuerySet.exclude()`让我们排除不匹配条件的结果。

让我们从第一个模型`MailingList`开始。

# 创建邮件列表模型

我们的`MailingList`模型将代表我们的一个用户创建的邮件列表。这将是我们系统中的一个重要模型，因为许多其他模型将引用它。我们还可以预期`MailingList`的`id`将需要公开暴露，以便将订阅者关联回来。为了避免让用户枚举 Mail Ape 中的所有邮件列表，我们希望确保我们的`MailingList` ID 是非顺序的。

让我们将我们的`MailingList`模型添加到`django/mailinglist/models.py`中：

```py
import uuid

from django.conf import settings
from django.db import models
from django.urls import reverse

class MailingList(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=140)
    owner = models.ForeignKey(to=settings.AUTH_USER_MODEL,
                              on_delete=models.CASCADE)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse(
            'mailinglist:manage_mailinglist',
            kwargs={'pk': self.id}
        )

    def user_can_use_mailing_list(self, user):
        return user == self.owner
```

让我们更仔细地看看我们的`MailingList`模型：

+   `class MailingList(models.Model):`：所有 Django 模型都必须继承自`Model`类。

+   `id = models.UUIDField`: 这是我们第一次为模型指定`id`字段。通常，我们让 Django 自动为我们提供一个。在这种情况下，我们想要非顺序的 ID，所以我们使用了一个提供**通用唯一标识符**（**UUID**）的字段。Django 将在我们生成迁移时创建适当的数据库字段（参考*创建数据库迁移*部分）。然而，我们必须在 Python 中生成 UUID。为了为每个新模型生成新的 UUID，我们使用了`default`参数和 Python 的`uuid4`函数。为了告诉 Django 我们的`id`字段是主键，我们使用了`primary_key`参数。我们进一步传递了`editable=False`以防止对`id`属性的更改。

+   `name = models.CharField`: 这将代表邮件列表的名称。`CharField`将被转换为`VARCHAR`列，所以我们必须为它提供一个`max_length`参数。

+   `owner = models.ForeignKey`: 这是对 Django 用户模型的外键。在我们的情况下，我们将使用默认的`django.contrib.auth.models.User`类。我们遵循 Django 避免硬编码这个模型的最佳实践。通过引用`settings.AUTH_USER_MODEL`，我们不会将我们的应用程序与项目过于紧密地耦合。这鼓励未来的重用。`on_delete=models.CASCADE`参数意味着如果用户被删除，他们的所有`MailingList`模型实例也将被删除。

+   `def __str__(self)`: 这定义了如何将邮件列表转换为`str`。当需要打印或显示`MailingList`时，Django 和 Python 都会使用这个方法。

+   `def get_absolute_url(self)`: 这是 Django 模型上的一个常见方法。`get_absolute_url()`返回代表模型的 URL 路径。在我们的情况下，我们返回这个邮件列表的管理页面。我们不会硬编码路径。相反，我们使用`reverse()`在运行时解析路径，提供 URL 的名称。我们将在*创建 URLConf*部分讨论命名 URL。

+   `def user_can_use_mailing_list(self, user)`: 这是我们为自己方便添加的一个方法。它检查用户是否可以使用（查看相关项目和/或发送消息）到这个邮件列表。Django 的*Fat models*哲学鼓励将这样的决策代码放在模型中，而不是在视图中。这为我们提供了一个决策的中心位置，确保**不要重复自己**（**DRY**）。

现在我们有了我们的`MailingList`模型。接下来，让我们创建一个模型来捕获邮件列表的订阅者。

# 创建`Subscriber`模型

在这一部分，我们将创建一个`Subscriber`模型。`Subscriber`模型只能属于一个`MailingList`，并且必须确认他们的订阅。由于我们需要引用订阅者以获取他们的确认和取消订阅页面，我们希望他们的`id`实例也是非顺序的。

让我们在`django/mailinglist/models.py`中创建`Subscriber`模型。

```py
class Subscriber(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField()
    confirmed = models.BooleanField(default=False)
    mailing_list = models.ForeignKey(to=MailingList, on_delete=models.CASCADE)

    class Meta:
        unique_together = ['email', 'mailing_list', ]
```

`Subscriber`模型与`MailingList`模型有一些相似之处。基类和`UUIDField`的功能相同。让我们看看一些不同之处：

+   `models.EmailField()`: 这是一个专门的`CharField`，但会进行额外的验证，以确保值是一个有效的电子邮件地址。

+   `models.BooleanField(default=False)`: 这让我们存储`True`/`False`值。我们需要使用这个来跟踪用户是否真的打算订阅邮件列表。

+   `models.ForeignKey(to=MailingList...)`: 这让我们在`Subscriber`和`MailingList`模型实例之间创建一个外键。

+   `unique_together`: 这是`Subscriber`的`Meta`内部类的一个属性。`Meta`内部类让我们可以在表上指定信息。例如，`unique_together`让我们在表上添加额外的唯一约束。在这种情况下，我们防止用户使用相同的电子邮件地址注册两次。

现在我们可以跟踪`Subscriber`模型实例了，让我们跟踪用户想要发送到他们的`MailingList`的消息。

# 创建`Message`模型

我们的用户将希望向他们的`MailingList`的`Subscriber`模型实例发送消息。为了知道要发送给这些订阅者什么，我们需要将消息存储为 Django 模型。

`Message`应该属于`MailingList`并具有非连续的`id`。我们需要保存这些消息的主题和正文。我们还希望跟踪发送开始和完成的时间。

让我们将`Message`模型添加到`django/mailinglist/models.py`中：

```py
class Message(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    mailing_list = models.ForeignKey(to=MailingList, on_delete=models.CASCADE)
    subject = models.CharField(max_length=140)
    body = models.TextField()
    started = models.DateTimeField(default=None, null=True)
    finished = models.DateTimeField(default=None, null=True)
```

再次，`Message`模型在其基类和字段上与我们之前的模型非常相似。我们在这个模型中看到了一些新字段。让我们更仔细地看看这些新字段：

+   `models.TextField()`: 用于存储任意长的字符数据。所有主要数据库都有`TEXT`列类型。这对于存储用户的`Message`的`body`属性非常有用。

+   `models.DateTimeField(default=None, null=True)`: 用于存储日期和时间值。在 Postgres 中，这将成为`TIMESTAMP`列。`null`参数告诉 Django 该列应该能够接受`NULL`值。默认情况下，所有字段都对它们有一个`NOT NULL`约束。

我们现在有了我们的模型。让我们使用数据库迁移在我们的数据库中创建它们。

# 使用数据库迁移

数据库迁移描述了如何将数据库转换为特定状态。在本节中，我们将做以下事情：

+   为我们的`mailinglist`应用程序模型创建数据库迁移

+   在 Postgres 数据库上运行迁移

当我们对模型进行更改时，我们可以让 Django 生成用于创建这些表、字段和约束的代码。Django 生成的迁移是使用 Django 开发人员也可以使用的 API 创建的。如果我们需要进行复杂的迁移，我们可以自己编写迁移。请记住，正确的迁移包括应用和撤消迁移的代码。如果出现问题，我们希望有一种方法来撤消我们的迁移。当 Django 生成迁移时，它总是为我们生成两个迁移。

让我们首先配置 Django 连接到我们的 PostgreSQL 数据库。

# 配置数据库

要配置 Django 连接到我们的 Postgres 数据库，我们需要更新`django/config/settings.py`中的`DATABASES`设置：

```py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'mailape',
        'USER': 'mailape',
        'PASSWORD': 'development',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

您不应该在`settings.py`文件中将密码硬编码到生产数据库中。如果您连接到共享或在线实例，请使用环境变量设置用户名、密码和主机，并使用`os.getenv()`访问它们，就像我们在之前的生产部署章节中所做的那样（第五章，“使用 Docker 部署”和第九章，*部署 Answerly*）。

Django 不能自行创建数据库和用户。我们必须自己做。您可以在本章的代码中找到执行此操作的脚本。

接下来，让我们为模型创建迁移。

# 创建数据库迁移

要创建我们的数据库迁移，我们将使用 Django 放在 Django 项目顶部的`manage.py`脚本（`django/manage.py`）：

```py
$ cd django
$ python manage.py makemigrations
Migrations for 'mailinglist':
  mailinglist/migrations/0001_initial.py
    - Create model MailingList
    - Create model Message
    - Create model Subscriber
    - Alter unique_together for subscriber (1 constraint(s))
```

太棒了！现在我们有了迁移，我们可以在我们的本地开发数据库上运行它们。

# 运行数据库迁移

我们使用`manage.py`将我们的数据库迁移应用到正在运行的数据库。在命令行上执行以下操作：

```py
$ cd django
$ python manage.py migrate
Operations to perform:
  Apply all migrations: admin, auth, contenttypes, mailinglist, sessions
Running migrations:
  Applying contenttypes.0001_initial... OK
  Applying auth.0001_initial... OK
  Applying admin.0001_initial... OK
  Applying admin.0002_logentry_remove_auto_add... OK
  Applying contenttypes.0002_remove_content_type_name... OK
  Applying auth.0002_alter_permission_name_max_length... OK
  Applying auth.0003_alter_user_email_max_length... OK
  Applying auth.0004_alter_user_username_opts... OK
  Applying auth.0005_alter_user_last_login_null... OK
  Applying auth.0006_require_contenttypes_0002... OK
  Applying auth.0007_alter_validators_add_error_messages... OK
  Applying auth.0008_alter_user_username_max_length... OK
  Applying auth.0009_alter_user_last_name_max_length... OK
  Applying mailinglist.0001_initial... OK
  Applying sessions.0001_initial... OK
```

当我们运行`manage.py migrate`而不提供应用程序时，它将在所有安装的 Django 应用程序上运行所有迁移。我们的数据库现在具有`mailinglist`应用程序模型和`auth`应用程序模型（包括`User`模型）的表。

现在我们有了我们的模型和数据库设置，让我们确保我们可以使用 Django 的表单 API 验证这些模型的用户输入。

# 邮件列表表单

开发人员必须解决的一个常见问题是如何验证用户输入。Django 通过其表单 API 提供输入验证。表单 API 可用于使用与模型 API 非常相似的 API 描述 HTML 表单。如果我们想创建描述 Django 模型的表单，那么 Django 表单的`ModelForm`为我们提供了一种快捷方式。我们只需要描述我们从默认表单表示中更改的内容。

当实例化 Django 表单时，可以提供以下三个参数中的任何一个：

+   `data`：最终用户请求的原始输入

+   `initial`：我们可以为表单设置的已知安全初始值

+   `instance`：表单描述的实例，仅在`ModelForm`中

如果表单提供了`data`，那么它被称为绑定表单。绑定表单可以通过调用`is_valid()`来验证它们的`data`。经过验证的表单的安全数据可以在`cleaned_data`字典下使用（以字段名称为键）。错误可以通过`errors`属性获得，它返回一个字典。绑定的`ModelForm`也可以使用`save()`方法创建或更新其模型实例。

即使没有提供任何参数，表单仍然能够以 HTML 形式打印自己，使我们的模板更简单。这种机制帮助我们实现了“愚蠢模板”的目标。

让我们通过创建`SubscriberForm`类来开始创建我们的表单。

# 创建订阅者表单

Mail Ape 必须执行的一个重要任务是接受新的`Subscriber`的邮件，用于`MailingList`。让我们创建一个表单来进行验证。

`SubscriberForm`必须能够验证输入是否为有效的电子邮件。我们还希望它保存我们的新`Subscriber`模型实例并将其与适当的`MailingList`模型实例关联起来。

让我们在`django/mailinglist/forms.py`中创建该表单：

```py
from django import forms

from mailinglist.models import MailingList, Subscriber

class SubscriberForm(forms.ModelForm):
    mailing_list = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=MailingList.objects.all(),
        disabled=True,
    )

    class Meta:
        model = Subscriber
        fields = ['mailing_list', 'email', ]
```

让我们仔细看看我们的`SubscriberForm`：

+   `class SubscriberForm(forms.ModelForm):`：这表明我们的表单是从`ModelForm`派生的。`ModelForm`知道要检查我们的内部`Meta`类，以获取关于可以用作此表单基础的模型和字段的信息。

+   `mailing_list = forms.ModelChoiceField`：这告诉我们的表单使用我们自定义配置的`ModelChoiceField`，而不是表单 API 默认使用的。默认情况下，Django 将显示一个`ModelChoiceField`，它将呈现为下拉框。用户可以使用下拉框选择相关的模型。在我们的情况下，我们不希望用户能够做出选择。当我们显示一个渲染的`SubscriberForm`时，我们希望它配置为特定的邮件列表。为此，我们将`widget`参数更改为`HiddenInput`类，并将字段标记为`disabled`。我们的表单需要知道对于该表单有效的`MailingList`模型实例。我们提供一个匹配所有`MailingList`模型实例的`QuerySet`对象。

+   `model = Subscriber`：这告诉表单的`Meta`内部类，这个表单是基于`Subscriber`模型的。

+   `fields = ['mailing_list', 'email', ]`：这告诉表单只包括模型中的以下字段。

接下来，让我们创建一个表单，用于捕获我们的用户想要发送到他们的`MailingList`的`Message`。

# 创建消息表单

我们的用户将希望向他们的`MailingList`发送`Message`。我们将提供一个网页，用户可以在其中创建这些消息的表单。在我们创建页面之前，让我们先创建表单。

让我们将我们的`MessageForm`类添加到`django/mailinglist/forms.py`中：

```py
from django import forms

from mailinglist.models import MailingList, Message

class MessageForm(forms.ModelForm):
    mailing_list = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=MailingList.objects.all(),
        disabled=True,
    )

    class Meta:
        model = Message
        fields = ['mailing_list', 'subject', 'body', ]
```

正如您在前面的代码中所注意到的，`MessageForm`的工作方式与`SubscriberFrom`相同。唯一的区别是我们在`Meta`内部类中列出了不同的模型和不同的字段。

接下来，让我们创建`MailingListForm`类，我们将用它来接受邮件列表的名称的输入。

# 创建邮件列表表单

现在，我们将创建一个`MailingListForm`，它将接受邮件列表的名称和所有者。我们将在`owner`字段上使用与之前相同的`HiddenInput`和`disabled`字段模式。我们希望确保用户无法更改邮件列表的所有者。

让我们将我们的表单添加到`django/mailinglist/forms.py`中：

```py
from django import forms
from django.contrib.auth import get_user_model

from mailinglist.models import MailingList

class MailingListForm(forms.ModelForm):
    owner = forms.ModelChoiceField(
        widget=forms.HiddenInput,
        queryset=get_user_model().objects.all(),
        disabled=True,
    )

    class Meta:
        model = MailingList
        fields = ['owner', 'name']
```

`MailingListForm`与我们之前的表单非常相似，但引入了一个新的函数`get_user_model()`。我们需要使用`get_user_model()`，因为我们不想将自己与特定的用户模型耦合在一起，但我们需要访问该模型的管理器以获取`QuerySet`。

现在我们有了我们的表单，我们可以为我们的`mailinglist` Django 应用程序创建视图。

# 创建邮件列表视图和模板

在前面的部分中，我们创建了可以用来收集和验证用户输入的表单。在本节中，我们将创建实际与用户通信的视图和模板。模板定义了文档的 HTML。

基本上，Django 视图是一个接受请求并返回响应的函数。虽然我们在本书中不会使用这些**基于函数的视图**（**FBVs**），但重要的是要记住，一个视图只需要满足这两个责任。如果处理视图还导致其他操作发生（例如，发送电子邮件），那么我们应该将该代码放在服务模块中，而不是直接放在视图中。

Web 开发人员面临的许多工作是重复的（例如，处理表单，显示特定模型，列出该模型的所有实例等）。Django 的“电池包含”哲学意味着它包含了工具，使这些重复的任务更容易。

Django 通过提供丰富的**基于类的视图**（**CBVs**）使常见的 Web 开发人员任务更容易。CBVs 使用**面向对象编程**（**OOP**）的原则来增加代码重用。Django 提供了丰富的 CBV 套件，使处理表单或为模型实例显示 HTML 页面变得容易。

HTML 视图返回的内容来自于渲染模板。Django 中的模板通常是用 Django 的模板语言编写的。Django 也可以支持其他模板语言（例如 Jinja）。通常，每个视图都与一个模板相关联。

让我们首先创建许多视图将需要的一些资源。

# 常见资源

在这一部分，我们将创建一些我们的视图和模板将需要的常见资源：

+   我们将创建一个基础模板，所有其他模板都可以扩展。在所有页面上使用相同的基础模板将给 Mail Ape 一个统一的外观和感觉。

+   我们将创建一个`MailingListOwnerMixin`类，它将让我们保护邮件列表消息免受未经授权的访问。

让我们从创建一个基础模板开始。

# 创建基础模板

让我们为 Mail Ape 创建一个基础模板。这个模板将被我们所有的页面使用，以给我们整个 Web 应用程序一个一致的外观。

**Django 模板语言**（**DTL**）让我们编写 HTML（或其他基于文本的格式），并让我们使用*标签*、*变量*和*过滤器*来执行代码以定制 HTML。让我们更仔细地看看这三个概念：

+   *标签*：它们被`{% %}`包围，可能（`{% block body%}{% endblock %}`）或可能不（`{% url "myurl" %}`）包含一个主体。

+   *variables*：它们被`{{ }}`包围，并且必须在模板的上下文中设置（例如，`{{ mailinglist }}`）。尽管 DTL 变量类似于 Python 变量，但也有区别。最关键的两个区别在于可执行文件和字典。首先，DTL 没有语法来传递参数给可执行文件（你永远不必使用`{{foo(1)}}`）。如果你引用一个变量并且它是可调用的（例如，一个函数），那么 Django 模板语言将调用它并返回结果（例如，`{{mailinglist.get_absolute_url}}`）。其次，DTL 不区分对象属性、列表中的项目和字典中的项目。所有这三个都使用点来访问：`{{mailinglist.name}}`，`{{mylist.1}}`和`{{mydict.mykey}}`。

+   *filters*：它们跟随一个变量并修改其值（例如，`{{ mailinglist.name | upper}}`将以大写形式返回邮件列表的名称）。

我们将在继续创建 Mail Ape 时查看这三个示例。

让我们创建一个公共模板目录—`django/templates`—并将我们的模板放在`django/templates/base.html`中：

```py
<!DOCTYPE html>
<html lang="en" >
<head >
  <meta charset="UTF-8" >
  <title >{% block title %}{% endblock %}</title >
  <link rel="stylesheet"
        href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta.3/css/bootstrap.min.css"
  />
</head >
<body >
<div class="container" >
  <nav class="navbar navbar-light bg-light" >
    <a class="navbar-brand" href="#" >Mail Ape </a >
    <ul class="navbar-nav" >
      <li class="nav-item" >
        <a class="nav-link"
           href="{% url "mailinglist:mailinglist_list" %}" >
          Your Mailing Lists
        </a >
      </li >
      {% if request.user.is_authenticated %}
        <li class="nav-item" >
          <a class="nav-link"
             href="{% url "user:logout" %}" >
            Logout
          </a >
        </li >
      {% else %}
        <li class="nav-item" >
          <a class="nav-link"
             href="{% url "user:login" %}" >
            Your Mailing Lists
          </a >
        </li >
        <li class="nav-item" >
          <a class="nav-link"
             href="{% url "user:register" %}" >
            Your Mailing Lists
          </a >
        </li >
      {% endif %}
    </ul >
  </nav >
  {% block body %}
  {% endblock %}
</div >
</body >
</html >
```

在我们的基本模板中，我们将注意以下三个标签的示例：

+   `{% url ... %}`：这返回到视图的路径。这与我们之前看到的`reverse()`函数在 Django 模板中的工作方式相同。

+   `{% if ... %} ... {% else %} ... {% endif %}`：这与 Python 开发人员期望的工作方式相同。`{% else %}`子句是可选的。Django 模板语言还支持`{% elif ... %}`，如果我们需要在多个选择中进行选择。

+   `{% block ... %}`：这定义了一个块，一个扩展`base.html`的模板可以用自己的内容替换。我们有两个块，`body`和`title`。

我们现在有一个基本模板，我们的其他模板可以通过提供 body 和 title 块来使用。

既然我们有了模板，我们必须告诉 Django 在哪里找到它。让我们更新`django/config/settings.py`，让 Django 知道我们的新`django/templates`目录。

在`django/config/settings.py`中，找到以`Templates`开头的行。我们需要将我们的`templates`目录添加到`DIRS`键下的列表中：

```py
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            # do not change OPTIONS, omitted for brevity
        },
    },
]
```

Django 让我们通过在运行时计算`BASE_DIR`来避免将路径硬编码到`django/templates`中。这样，我们可以在不同的环境中使用相同的设置。

我们刚刚看到的另一个重要设置是`APP_DIRS`。这个设置告诉 Django 在查找模板时检查每个安装的应用程序的`templates`目录。这意味着我们不必为每个安装的应用程序更新`DIRS`键，并且让我们将模板隔离在我们的应用程序下（增加可重用性）。最后，重要的是要记住应用程序按照它们在`INSTALLED_APPS`中出现的顺序进行搜索。如果有模板名称冲突（例如，两个应用程序提供名为`registration/login.html`的模板），那么将使用`INSTALLED_APPS`中列出的第一个。

接下来，让我们配置我们的项目在呈现 HTML 表单时使用 Bootstrap 4。

# 配置 Django Crispy Forms 以使用 Bootstrap 4

在我们的基本模板中，我们包含了 Bootstrap 4 的 css 模板。为了方便使用 Bootstrap 4 呈现表单并为其设置样式，我们将使用一个名为 Django Crispy Forms 的第三方 Django 应用程序。但是，我们必须配置 Django Crispy Forms 以告诉它使用 Bootstrap 4。

让我们在`django/config/settings.py`的底部添加一个新的设置：

```py
CRISPY_TEMPLATE_PACK = 'bootstrap4'
```

现在，Django Crispy Forms 配置为在呈现表单时使用 Bootstrap 4。我们将在本章后面的部分中查看它，在涵盖在模板中呈现表单的部分。

接下来，让我们创建一个 mixin，确保只有邮件列表的所有者才能影响它们。

# 创建一个 mixin 来检查用户是否可以使用邮件列表

Django 使用**基于类的视图**（**CBVs**）使代码重用更容易，简化重复的任务。在`mailinglist`应用程序中，我们将不得不做的重复任务之一是保护`MailingList`及其相关模型，以免被其他用户篡改。我们将创建一个 mixin 来提供保护。

mixin 是一个提供有限功能的类，旨在与其他类一起使用。我们之前见过`LoginRequired` mixin，它可以与视图类一起使用，以保护视图免受未经身份验证的访问。在本节中，我们将创建一个新的 mixin。

让我们在`django/mailinglist/mixins.py`中创建我们的`UserCanUseMailingList` mixin：

```py
from django.core.exceptions import PermissionDenied, FieldDoesNotExist

from mailinglist.models import MailingList

class UserCanUseMailingList:

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        user = self.request.user
        if isinstance(obj, MailingList):
            if obj.user_can_use_mailing_list(user):
                return obj
            else:
                raise PermissionDenied()

        mailing_list_attr = getattr(obj, 'mailing_list')
        if isinstance(mailing_list_attr, MailingList):
            if mailing_list_attr.user_can_use_mailing_list(user):
                return obj
            else:
                raise PermissionDenied()
        raise FieldDoesNotExist('view does not know how to get mailing '
                                   'list.')
```

我们的类定义了一个方法，`get_object(self, queryset=None)`。这个方法与`SingleObjectMixin.get_object()`具有相同的签名，许多 Django 内置的 CBV（例如`DetailView`）使用它。我们的`get_object()`实现不做任何工作来检索对象。相反，我们的`get_object`只是检查父对象检索到的对象，以检查它是否是或者拥有`MailingList`，并确认已登录的用户可以使用邮件列表。

mixin 的一个令人惊讶的地方是它依赖于一个超类，但不继承自一个。在`get_object()`中，我们明确调用`super()`，但`UserCanUseMailingList`没有任何基类。mixin 类不希望单独使用。相反，它们将被类使用，这些类子类化它们*和*一个或多个其他类。

我们将在接下来的几节中看看这是如何工作的。

# 创建 MailingList 视图和模板

现在，让我们来看看将处理用户请求并返回从我们的模板创建的 UI 的响应的视图。

让我们首先创建一个列出所有我们的`MailingList`的视图。

# 创建 MailingListListView 视图

我们将创建一个视图，显示用户拥有的邮件列表。

让我们在`django/mailinglist/views.py`中创建我们的`MailingListListView`：

```py
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from mailinglist.models import  MailingList

class MailingListListView(LoginRequiredMixin, ListView):

    def get_queryset(self):
        return MailingList.objects.filter(owner=self.request.user)
```

我们的观点源自两个视图，`LoginRequiredMixin`和`ListView`。`LoginRequiredMixin`是一个 mixin，确保未经身份验证的用户发出的请求被重定向到登录视图，而不是被处理。为了帮助`ListView`知道*要*列出什么，我们将重写`get_queryset()`方法，并返回一个包含当前登录用户拥有的`MailingList`的`QuerySet`。为了显示结果，`ListView`将尝试在`appname/modelname_list.html`渲染模板。在我们的情况下，`ListView`将尝试渲染`mailinglist/mailinglist_list.html`。

让我们在`django/mailinglist/templates/mailinglist/mailinglist_list.html`中创建该模板：

```py
{% extends "base.html" %}

{% block title %}
  Your Mailing Lists
{% endblock %}

{% block body %}
  <div class="row user-mailing-lists" >
    <div class="col-sm-12" >
      <h1 >Your Mailing Lists</h1 >
      <div >
        <a class="btn btn-primary"
           href="{% url "mailinglist:create_mailinglist" %}" >New List</a >
      </div >
      <p > Your mailing lists:</p >
      <ul class="mailing-list-list">
        {% for mailinglist in mailinglist_list %}
          <li class="mailinglist-item">
            <a href="{% url "mailinglist:manage_mailinglist" pk=mailinglist.id %}" >
              {{ mailinglist.name }}
            </a >
          </li >
        {% endfor %}
      </ul >
    </div >
  </div >
{% endblock %}
```

我们的模板扩展了`base.html`。当一个模板扩展另一个模板时，它只能将 HTML 放入先前定义的`block`中。我们还将看到许多新的 Django 模板标签。让我们仔细看看它们：

+   `{% extends "base.html" %}`：这告诉 Django 模板语言我们正在扩展哪个模板。

+   `{% block title %}… {% endblock %}`：这告诉 Django 我们正在提供新的代码，它应该放在扩展模板的`title`块中。该块中的先前代码（如果有）将被替换。

+   `{% for mailinglist in mailinglist_list %} ... {% endfor %}`：这为列表中的每个项目提供了一个循环。

+   `{% url … %}`：`url`标签将为命名的`path`生成 URL 路径。

+   `{% url ... pk=...%}`：这与前面的点一样工作，但在某些情况下，`path`可能需要参数（例如要显示的`MailingList`的主键）。我们可以在`url`标签中指定这些额外的参数。

现在我们有一个可以一起使用的视图和模板。

任何视图的最后一步都是将应用的 URLConf 添加到其中。让我们更新`django/mailinglist/urls.py`：

```py
from django.urls import path

from mailinglist import views

app_name = 'mailinglist'

urlpatterns = [
    path('',
         views.MailingListListView.as_view(),
         name='mailinglist_list'),
]
```

考虑到我们之前如何配置了根 URLConf，任何发送到`/mailinglist/`的请求都将被路由到我们的`MailingListListView`。

接下来，让我们添加一个视图来创建新的`MailingList`。

# 创建 CreateMailingListView 和模板

我们将创建一个视图来创建邮件列表。当我们的视图接收到`GET`请求时，视图将向用户显示一个表单，用于输入邮件列表的名称。当我们的视图接收到`POST`请求时，视图将验证表单，要么重新显示带有错误的表单，要么创建邮件列表并将用户重定向到列表的管理页面。

现在让我们在`django/mailinglist/views.py`中创建视图：

```py
class CreateMailingListView(LoginRequiredMixin, CreateView):
    form_class = MailingListForm
    template_name = 'mailinglist/mailinglist_form.html'

    def get_initial(self):
        return {
            'owner': self.request.user.id,
        }
```

`CreateMailingListView`派生自两个类：

+   `LoginRequiredMixin`会重定向未与已登录用户关联的请求，使其无法被处理（我们将在本章后面的*创建用户应用*部分进行配置）

+   `CreateView`知道如何处理`form_class`中指定的表单，并使用`template_name`中列出的模板进行渲染

`CreateView`是在不需要提供几乎任何额外信息的情况下完成大部分工作的类。处理表单，验证它，并保存它总是相同的，而`CreateView`有代码来执行这些操作。如果我们需要更改某些行为，我们可以重写`CreateView`提供的钩子之一，就像我们在`get_initial()`中所做的那样。

当`CreateView`实例化我们的`MailingListForm`时，`CreateView`调用其`get_initial()`方法来获取表单的`initial`数据（如果有的话）。我们使用这个钩子来确保表单的所有者设置为已登录用户的`id`。请记住，`MailingListForm`的`owner`字段已被禁用，因此表单将忽略用户提供的任何数据。

接下来，让我们在`django/mailinglist/templates/mailinglist/mailinglist_form.html`中创建我们的`CreateView`的模板：

```py
{% extends "base.html" %}

{% load crispy_forms_tags %}

{% block title %}
  Create Mailing List
{% endblock %}

{% block body %}
  <h1 >Create Mailing List</h1 >
  <form method="post" class="col-sm-4" >
    {% csrf_token %}
    {{ form | crispy }}
    <button class="btn btn-primary" type="submit" >Submit</button >
  </form >
{% endblock %}
```

我们的模板扩展了`base.html`。当一个模板扩展另一个模板时，它只能在已被扩展模板定义的块中放置 HTML。我们还使用了许多新的 Django 模板标签。让我们仔细看看它们：

+   `{% load crispy_forms_tags %}`：这告诉 Django 加载一个新的模板标签库。在这种情况下，我们将加载我们安装的 Django Crispy Forms 应用的`crispy_from_tags`。这为我们提供了稍后在本节中将看到的`crispy`过滤器。

+   `{% csrf_token %}`：Django 处理的任何表单都必须具有有效的 CSRF 令牌，以防止 CSRF 攻击（参见第三章，*海报、头像和安全*）。`csrf_token`标签返回一个带有正确 CSRF 令牌的隐藏输入标签。请记住，通常情况下，Django 不会处理没有 CSRF 令牌的 POST 请求。

+   `{{ form | crispy }}`：`form`变量是我们的视图正在处理的表单实例的引用，并且通过我们的`CreateView`将其传递到这个模板的上下文中。`crispy`是由`crispy_form_tags`标签库提供的过滤器，将使用 HTML 标签和 Bootstrap 4 中使用的 CSS 类输出表单。

我们现在有一个视图和模板可以一起使用。视图能够使用模板创建用户界面以输入表单中的数据。然后视图能够处理表单的数据并从有效的表单数据创建`MailingList`模型，或者如果数据有问题，则重新显示表单。Django Crispy Forms 库使用 Bootstrap 4 CSS 框架的 HTML 和 CSS 渲染表单。

最后，让我们将我们的视图添加到`mailinglist`应用的 URLConf 中。在`django/mailinglist/urls.py`中，让我们向 URLConf 添加一个新的`path()`对象：

```py
    path('new',
         views.CreateMailingListView.as_view(),
         name='create_mailinglist')
```

考虑到我们之前如何配置了根 URLConf，任何发送到`/mailinglist/new`的请求都将被路由到我们的`CreatingMailingListView`。

接下来，让我们创建一个视图来删除`MailingList`。

# 创建 DeleteMailingListView 视图

用户在`MailingList`不再有用后会想要删除它们。让我们创建一个视图，在`GET`请求上提示用户进行确认，并在`POST`上删除`MailingList`。

我们将把我们的视图添加到`django/mailinglist/views.py`中：

```py
class DeleteMailingListView(LoginRequiredMixin, UserCanUseMailingList,
                            DeleteView):
    model = MailingList
    success_url = reverse_lazy('mailinglist:mailinglist_list')
```

让我们仔细看看`DeleteMailingListView`从中派生的类：

+   `LoginRequiredMixin`：这与前面的代码具有相同的功能，确保未经身份验证的用户的请求不被处理。用户只是被重定向到登录页面。

+   `UserCanUseMailingList`：这是我们在前面的代码中创建的 mixin。`DeleteView`使用`get_object()`方法来检索要删除的模型实例。通过将`UserCanUseMailingList`混合到`DeleteMailingListView`类中，我们保护了每个用户的`MailingList`不被未经授权的用户删除。

+   `DeleteView`：这是一个 Django 视图，它知道如何在`GET`请求上呈现确认模板，并在`POST`上删除相关的模型。

为了使 Django 的`DeleteView`正常工作，我们需要正确配置它。`DeleteView`知道从其`model`属性中删除哪个模型。当我们路由请求到它时，`DeleteView`要求我们提供一个`pk`参数。为了呈现确认模板，`DeleteView`将尝试使用`appname/modelname_confirm_delete.html`。在`DeleteMailingListView`的情况下，模板将是`mailinglist/mailinglist_confirm_delete.html`。如果成功删除模型，那么`DeleteView`将重定向到`success_url`值。我们避免了硬编码`success_url`，而是使用`reverse_lazy()`来引用名称的 URL。`reverse_lazy()`函数返回一个值，直到用它来创建一个`Response`对象时才会解析。

让我们创建`DeleteMailingListView`在`django/mailinglist/templates/mailinglist/mailinglist_confirm_delete.html`中需要的模板：

```py
{% extends "base.html" %}

{% block title %}
  Confirm delete {{ mailinglist.name }}
{% endblock %}

{% block body %}
  <h1 >Confirm Delete?</h1 >
  <form action="" method="post" >
    {% csrf_token %}
    <p >Are you sure you want to delete {{ mailinglist.name }}?</p >
    <input type="submit" value="Yes" class="btn btn-danger btn-sm ">
    <a class="btn btn-primary btn-lg" href="{% url "mailinglist:manage_mailinglist" pk=mailinglist.id %}">No</a>
  </form >
{% endblock %}
```

在这个模板中，我们不使用任何表单，因为没有任何输入需要验证。表单提交本身就是确认。

最后一步将是将我们的视图添加到`django/mailinglist/urls.py`中的`urlpatterns`列表中：

```py
 path('<uuid:pk>/delete',
     views.DeleteMailingListView.as_view(),
     name='delete_mailinglist'),
```

这个`path`看起来不同于我们之前见过的`path()`调用。在这个`path`中，我们包含了一个命名参数，它将被解析出路径并传递给视图。我们使用`<converter:name>`格式来指定`path`命名参数。转换器知道如何匹配路径的一部分（例如，`uuid`转换器知道如何匹配 UUID；`int`知道如何匹配数字；`str`将匹配除了`/`之外的任何非空字符串）。然后匹配的文本将作为关键字参数传递给视图，并提供名称。在我们的情况下，要将请求路由到`DeleteMailingListView`，它必须有这样的路径：`/mailinglist/bce93fec-f9c6-4ea7-b1aa-348d3bed4257/delete`。

现在我们可以列出、创建和删除`MailingList`，让我们创建一个视图来管理其`Subscriber`和`Message`。

# 创建 MailingListDetailView

让我们创建一个视图，列出与`MailingList`相关的所有`Subscriber`和`Message`。我们还需要一个地方来向用户显示`MailingList`的订阅页面链接。Django 可以很容易地创建一个表示模型实例的视图。

让我们在`django/mailinglist/views.py`中创建我们的`MailingListDetailView`：

```py
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import DetailView

from mailinglist.mixins import UserCanUseMailingList
from mailinglist.models import MailingList

class MailingListDetailView(LoginRequiredMixin, UserCanUseMailingList,
                            DetailView):
    model = MailingList
```

我们以与之前相同的方式使用`LoginRequiredMixin`和`UserCanUseMailingList`，并且目的也是相同的。这次，我们将它们与`DetailView`一起使用，这是最简单的视图之一。它只是为其配置的模型实例呈现模板。它通过从`path`接收`pk`参数来检索模型实例，就像`DeleteView`一样。此外，我们不必显式配置它将使用的模板，因为按照惯例，它使用`appname/modelname_detail.html`。在我们的情况下，它将是`mailinglist/mailinglist_detail.html`。

让我们在`django/mailinglist/templates/mailinglist/mailinglist_detail.html`中创建我们的模板：

```py
{% extends "base.html" %}

{% block title %}
  {{ mailinglist.name }} Management
{% endblock %}

{% block body %}
  <h1 >{{ mailinglist.name }} Management
    <a class="btn btn-danger"
       href="{% url "mailinglist:delete_mailinglist" pk=mailinglist.id %}" >
      Delete</a >
  </h1 >

  <div >
    <a href="{% url "mailinglist:create_subscriber" mailinglist_pk=mailinglist.id %}" >Subscription
      Link</a >

  </div >

  <h2 >Messages</h2 >
  <div > Send new
    <a class="btn btn-primary"
       href="{% url "mailinglist:create_message" mailinglist_pk=mailinglist.id %}">
      Send new Message</a >
  </div >
  <ul >
    {% for message in mailinglist.message_set.all %}
      <li >
        <a href="{% url "mailinglist:view_message" pk=message.id %}" >{{ message.subject }}</a >
      </li >
    {% endfor %}
  </ul >

  <h2 >Subscribers</h2 >
  <ul >
    {% for subscriber in mailinglist.subscriber_set.all %}
      <li >
        {{ subscriber.email }}
        {{ subscriber.confirmed|yesno:"confirmed,unconfirmed" }}
        <a href="{% url "mailinglist:unsubscribe" pk=subscriber.id %}" >
          Unsubscribe
        </a >
      </li >
    {% endfor %}
  </ul >
{% endblock %}
```

上述代码模板只介绍了一个新项目（`yesno`过滤器），但确实展示了 Django 模板语言的所有工具是如何结合在一起的。

`yesno`过滤器接受一个值，如果该值评估为`True`，则返回`yes`，如果评估为`False`，则返回`no`，如果为`None`，则返回`maybe`。在我们的情况下，我们传递了一个参数，告诉`yesno`如果为`True`则返回`confirmed`，如果为`False`则返回`unconfirmed`。

`MailingListDetailView`类和模板说明了 Django 如何简洁地完成常见的 Web 开发人员任务：显示数据库中行的页面。

接下来，让我们在`mailinglist`的 URLConf 中为我们的视图创建一个新的`path()`对象：

```py
    path('<uuid:pk>/manage',
         views.MailingListDetailView.as_view(),
         name='manage_mailinglist')
```

接下来，让我们为我们的`Subscriber`模型实例创建视图。

# 创建 Subscriber 视图和模板

在本节中，我们将创建视图和模板，让用户与我们的`Subscriber`模型进行交互。这些视图与`MailingList`和`Message`视图的主要区别之一是，它们不需要任何混合，因为它们将被公开。它们免受篡改的主要保护是`Subscriber`由 UUID 标识，具有大的密钥空间，这意味着篡改是不太可能的。

让我们从`SubscribeToMailingListView`开始。

# 创建 SubscribeToMailingListView 和模板

我们需要一个视图来收集`Subscriber`到`MailingList`。让我们在`django/mailinglist/views.py`中创建一个`SubscribeToMailingListView`类。

```py
class SubscribeToMailingListView(CreateView):
    form_class = SubscriberForm
    template_name = 'mailinglist/subscriber_form.html'

    def get_initial(self):
        return {
            'mailing_list': self.kwargs['mailinglist_id']
        }

    def get_success_url(self):
        return reverse('mailinglist:subscriber_thankyou', kwargs={
            'pk': self.object.mailing_list.id,
        })

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        mailing_list_id = self.kwargs['mailinglist_id']
        ctx['mailing_list'] = get_object_or_404(
            MailingList,
            id=mailing_list_id)
        return ctx
```

我们的`SubscribeToMailingListView`类似于`CreateMailingListView`，但覆盖了一些新方法：

+   `get_success_url()`: 这是由`CreateView`调用的，用于获取重定向用户到已创建模型的 URL。在`CreateMailingListView`中，我们不需要覆盖它，因为默认行为使用模型的`get_absolute_url`。我们使用`reverse()`函数解析路径到感谢页面。

+   `get_context_data()`: 这让我们向模板的上下文中添加新变量。在这种情况下，我们需要访问用户可能订阅的`MailingList`以显示`MailingList`的名称。我们使用 Django 的`get_object_or_404()`快捷函数通过其 ID 检索`MailingList`或引发 404 异常。我们将这个视图的`path`从我们请求的路径中解析出`mailinglist_id`（参见本节末尾的内容）。

接下来，让我们在`mailinglist/templates/mailinglist/subscriber_form.html`中创建我们的模板：

```py
{% extends "base.html" %}
{% load crispy_forms_tags %}
{% block title %}
Subscribe to {{ mailing_list }}
{% endblock %}

{% block body %}
<h1>Subscribe to {{ mailing_list }}</h1>
<form method="post" class="col-sm-6 ">
  {% csrf_token %}
  {{ form | crispy }}
  <button class="btn btn-primary" type="submit">Submit</button>
</form>
{% endblock %}
```

这个模板没有引入任何标签，但展示了另一个例子，说明我们如何使用 Django 的模板语言和 Django Crispy Forms API 快速构建漂亮的 HTML 表单。我们像以前一样扩展`base.html`，以使我们的页面具有一致的外观和感觉。`base.html`还提供了我们要放入内容的块。在任何块之外，我们使用`{% load %}`加载 Django Crispy Forms 标签库，以便我们可以在我们的表单上使用`crispy`过滤器来生成兼容 Bootstrap 4 的 HTML。

接下来，让我们确保 Django 知道如何将请求路由到我们的新视图，通过向`mailinglist`应用的 URLConf 的`urlpatterns`列表添加一个`path()`：

```py
    path('<uuid:mailinglist_id>/subscribe',
         views.SubscribeToMailingListView.as_view(),
         name='subscribe'),
```

在这个`path()`中，我们需要匹配我们作为`mailinglist_pk`传递给视图的`uuid`参数。这是我们的`get_context_data()`方法引用的关键字参数。

接下来，让我们创建一个感谢页面，感谢用户订阅邮件列表。

# 创建感谢订阅视图

用户订阅邮件列表后，我们希望向他们显示一个*感谢*页面。这个页面对于订阅相同邮件列表的所有用户来说是相同的，因为它将显示邮件列表的名称（而不是订阅者的电子邮件）。为了创建这个视图，我们将使用之前看到的`DetailView`，但这次没有额外的混合（这里没有需要保护的信息）。

让我们在`django/mailinglist/views.py`中创建我们的`ThankYouForSubscribingView`：

```py
from django.views.generic import DetailView

from mailinglist.models import  MailingList

class ThankYouForSubscribingView(DetailView):
    model = MailingList
    template_name = 'mailinglist/subscription_thankyou.html'
```

Django 在`DetailView`中为我们完成所有工作，只要我们提供`model`属性。`DetailView`知道如何查找模型，然后为该模型呈现模板。我们还提供了`template_name`属性，因为`mailinglist/mailinglist_detail.html`模板（`DetailView`默认使用的）已经被`MailingListDetailView`使用。

让我们在`django/mailinglist/templates/mailinglist/subscription_thankyou.html`中创建我们的模板：

```py
{% extends "base.html" %}

{% block title %}
  Thank you for subscribing to {{ mailinglist }}
{% endblock %}

{% block body %}
  <div class="col-sm-12" ><h1 >Thank you for subscribing
    to {{ mailinglist }}</h1 >
    <p >Check your email for a confirmation email.</p >
  </div >
{% endblock %}
```

我们的模板只是显示一个感谢和模板名称。

最后，让我们在`mailinglist`应用的 URLConf 的`urlpatterns`列表中添加一个`path()`到`ThankYouForSubscribingView`：

```py
    path('<uuid:pk>/thankyou',
         views.ThankYouForSubscribingView.as_view(),
         name='subscriber_thankyou'),
```

我们的`path`需要匹配 UUID，以便将请求路由到`ThankYouForSubscribingView`。UUID 将作为关键字参数`pk`传递到视图中。这个`pk`将被`DetailView`用来找到正确的`MailingList`。

接下来，我们需要让用户确认他们是否要在这个地址接收电子邮件。

# 创建订阅确认视图

为了防止垃圾邮件发送者滥用我们的服务，我们需要向我们的订阅者发送一封电子邮件，确认他们确实想要订阅我们用户的邮件列表之一。我们将涵盖发送这些电子邮件，但现在我们将创建确认页面。

这个确认页面的行为会有点奇怪。简单地访问页面将会将`Subscriber.confirmed`修改为`True`。这是邮件列表确认页面的标准行为（我们希望避免为我们的订阅者创建额外的工作），但根据 HTTP 规范来说有点奇怪，因为`GET`请求不应该修改资源。

让我们在`django/mailinglist/views.py`中创建我们的`ConfirmSubscriptionView`：

```py
from django.views.generic import DetailView

from mailinglist.models import  Subscriber

class ConfirmSubscriptionView(DetailView):
    model = Subscriber
    template_name = 'mailinglist/confirm_subscription.html'

    def get_object(self, queryset=None):
        subscriber = super().get_object(queryset=queryset)
        subscriber.confirmed = True
        subscriber.save()
        return subscriber
```

`ConfirmSubscriptionView`是另一个`DetailView`，因为它显示单个模型实例。在这种情况下，我们重写`get_object()`方法以在返回之前修改对象。由于`Subscriber`不需要成为我们系统的用户，我们不需要使用`LoginRequiredMixin`。我们的视图受到暴力枚举的保护，因为`Subscriber.id`的密钥空间很大，并且是非顺序分配的。

接下来，让我们在`django/mailinglist/templates/mailinglist/confirm_subscription.html`中创建我们的模板：

```py
{% extends "base.html" %}

{% block title %}
  Subscription to {{ subscriber.mailing_list }} confirmed.
{% endblock %}

{% block body %}
  <h1 >Subscription to {{ subscriber.mailing_list }} confirmed!</h1 >
{% endblock %}
```

我们的模板使用在`base.html`中定义的块，简单地通知用户他们已确认订阅。

最后，让我们在`mailinglist`应用的 URLConf 的`urlpatterns`列表中添加一个`path()`到`ConfirmSubscriptionView`：

```py
    path('subscribe/confirmation/<uuid:pk>',
         views.ConfirmSubscriptionView.as_view(),
         name='confirm_subscription')
```

我们的`confirm_subscription`路径定义了要匹配的路径，以便将请求路由到我们的视图。我们的匹配表达式包括 UUID 的要求，这将作为关键字参数`pk`传递给我们的`ConfirmSubscriptionView`。`ConfirmSubscriptionView`的父类（`DetailView`）将使用它来检索正确的`Subscriber`。

接下来，让我们允许`Subscribers`自行取消订阅。

# 创建 UnsubscribeView

作为道德邮件提供者的一部分，让我们的`Subscriber`取消订阅。接下来，我们将创建一个`UnsubscribeView`，在`Subscriber`确认他们确实想要取消订阅后，将删除`Subscriber`模型实例。

让我们将我们的视图添加到`django/mailinglist/views.py`中：

```py
from django.views.generic import DeleteView

from mailinglist.models import Subscriber

class UnsubscribeView(DeleteView):
    model = Subscriber
    template_name = 'mailinglist/unsubscribe.html'

    def get_success_url(self):
        mailing_list = self.object.mailing_list
        return reverse('mailinglist:subscribe', kwargs={
            'mailinglist_pk': mailing_list.id
        })
```

我们的`UnsubscribeView`让 Django 内置的`DeleteView`实现来呈现模板，并找到并删除正确的`Subscriber`。`DeleteView`要求它接收一个`pk`作为关键字参数，从路径中解析出`Subscriber`的`pk`（就像`DetailView`一样）。当删除成功时，我们将使用`get_success_url()`方法将用户重定向到订阅页面。在执行`get_success_url()`时，我们的`Subscriber`实例已经从数据库中删除，但相应对象的副本将在`self.object`下可用。我们将使用内存中的（但不在数据库中的）实例来获取相关邮件列表的`id`属性。

要呈现确认表单，我们需要在`django/mailinglist/templates/mailinglist/unsubscribe.html`中创建一个模板：

```py
{% extends "base.html" %}

{% block title %}
  Unsubscribe?
{% endblock %}

{% block body %}
  <div class="col">
    <form action="" method="post" >
      {% csrf_token %}
      <p >Are you sure you want to unsubscribe
        from {{ subscriber.mailing_list.name }}?</p >
      <input class="btn btn-danger" type="submit"
             value="Yes, I want to unsubscribe " >
    </form >
  </div >
{% endblock %}
```

这个模板呈现了一个`POST`表单，它将作为`subscriber`希望取消订阅的确认。

接下来，让我们向`mailinglist`应用的 URLConf 的`urlpatterns`列表中添加一个`path()`到`UnsubscribeView`：

```py
     path('unsubscribe/<uuid:pk>',
         views.UnsubscribeView.as_view(),
         name='unsubscribe'),
```

在处理从`DetailView`或`DeleteView`派生的视图时，要记住将路径匹配器命名为`pk`是至关重要的。

现在，让我们允许用户开始创建他们将发送给他们的`Subscriber`的`Message`。

# 创建消息视图

我们在`Message`模型中跟踪我们的用户想要发送给他们的`Subscriber`的电子邮件。为了确保我们有一个准确的日志记录用户发送给他们的`Subscribers`的内容，我们将限制`Message`上可用的操作。我们的用户只能创建和查看`Message`。支持编辑是没有意义的，因为已发送的电子邮件无法修改。我们也不会支持删除消息，这样我们和用户都有一个准确的日志记录请求发送的内容。

让我们从创建`CreateMessageView`开始！

# 创建 CreateMessageView

我们的`CreateMessageView`将遵循类似于我们为 Answerly 创建的 markdown 表单的模式。用户将获得一个表单，他们可以提交以保存或预览。如果提交是预览，那么表单将与`Message`的渲染 markdown 预览一起呈现。如果用户选择保存，那么他们将创建他们的新消息。

由于我们正在创建一个新的模型实例，我们将使用 Django 的`CreateView`。

让我们在`django/mailinglist/views.py`中创建我们的视图：

```py
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import CreateView

from mailinglist.models import Message

class CreateMessageView(LoginRequiredMixin, CreateView):
    SAVE_ACTION = 'save'
    PREVIEW_ACTION = 'preview'

    form_class = MessageForm
    template_name = 'mailinglist/message_form.html'

    def get_success_url(self):
        return reverse('mailinglist:manage_mailinglist',
                       kwargs={'pk': self.object.mailing_list.id})

    def get_initial(self):
        mailing_list = self.get_mailing_list()
        return {
            'mailing_list': mailing_list.id,
        }

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        mailing_list = self.get_mailing_list()
        ctx.update({
            'mailing_list': mailing_list,
            'SAVE_ACTION': self.SAVE_ACTION,
            'PREVIEW_ACTION': self.PREVIEW_ACTION,
        })
        return ctx

    def form_valid(self, form):
        action = self.request.POST.get('action')
        if action == self.PREVIEW_ACTION:
            context = self.get_context_data(
                form=form,
                message=form.instance)
            return self.render_to_response(context=context)
        elif action == self.SAVE_ACTION:
            return super().form_valid(form)

    def get_mailing_list(self):
        mailing_list = get_object_or_404(MailingList,
                                         id=self.kwargs['mailinglist_pk'])
        if not mailing_list.user_can_use_mailing_list(self.request.user):
            raise PermissionDenied()
        return mailing_list
```

我们的视图继承自`CreateView`和`LoginRequiredMixin`。我们使用`LoginRequiredMixin`来防止未经身份验证的用户向邮件列表发送消息。为了防止已登录但未经授权的用户发送消息，我们将创建一个中心的`get_mailing_list()`方法，该方法检查已登录用户是否可以使用此邮件列表。`get_mailing_list()`期望`mailinglist_pk`将作为关键字参数提供给视图。

让我们仔细看看`CreateMessageView`，看看这些是如何一起工作的：

+   `form_class = MessageForm`：这是我们希望`CreateView`渲染、验证和用于创建我们的`Message`模型的表单。

+   `template_name = 'mailinglist/message_form.html'`：这是我们接下来要创建的模板。

+   `def get_success_url()`: 在成功创建`Message`后，我们将重定向用户到`MailingList`的管理页面。

+   `def get_initial():`：我们的`MessageForm`将其`mailing_list`字段禁用，以防用户试图偷偷地为另一个用户的`MailingList`创建`Message`。相反，我们使用我们的`get_mailing_list()`方法来根据`mailinglist_pk`参数获取邮件列表。使用`get_mailing_list()`，我们检查已登录用户是否可以使用`MailingList`。

+   `def get_context_data()`: 这提供了额外的变量给模板的上下文。我们提供了`MailingList`以及保存和预览的常量。

+   `def form_valid()`: 这定义了表单有效时的行为。我们重写了`CreateView`的默认行为来检查`action` POST 参数。`action`将告诉我们是要渲染`Message`的预览还是让`CreateView`保存一个新的`Message`模型实例。如果我们正在预览消息，那么我们将通过我们的表单构建一个未保存的`Message`实例传递给模板的上下文。

接下来，让我们在`django/mailinglist/templates/mailinglist/message_form.html`中制作我们的模板：

```py
{% extends "base.html" %}
{% load crispy_forms_tags %}
{% load markdownify %}
{% block title %}
  Send a message to {{ mailing_list }}
{% endblock %}

{% block body %}
  <h1 >Send a message to {{ mailing_list.name }}</h1 >
  {% if message %}
    <div class="card" >
      <div class="card-header" >
        Message Preview
      </div >
      <div class="card-body" >
        <h5 class="card-title" >{{ message.subject }}</h5 >
        <div>{{ message.body|markdownify }}</div>
      </div >
    </div >
  {% endif %}
  <form method="post" class="col-sm-12 col-md-9" >
    {% csrf_token %}
    {{ form | crispy }}
    <button type="submit" name="action"
            value="{{ SAVE_ACTION }}"
            class="btn btn-primary" >Save
    </button >
    <button type="submit" name="action"
            value="{{ PREVIEW_ACTION }}"
            class="btn btn-primary" >Preview
    </button >
  </form >
{% endblock %}
```

这个模板加载了第三方的 Django Markdownify 标签库和 Django Crispy Forms 标签库。前者给我们提供了`markdownify`过滤器，后者给我们提供了`crispy`过滤器。`markdownify`过滤器将接收到的 markdown 文本转换为 HTML。我们之前在我们的 Answerly 项目的第二部分中使用了 Django Markdownify。

这个模板表单有两个提交按钮，一个用于保存表单，一个用于预览表单。只有在我们传入`message`来预览时，预览块才会被渲染。

现在我们有了视图和模板，让我们在`mailinglist`应用的 URLConf 中为`CreateMessageView`添加一个`path()`：

```py
     path('<uuid:mailinglist_ipk>/message/new',
         views.CreateMessageView.as_view(),
         name='create_message'),
```

现在我们可以创建消息了，让我们创建一个查看我们已经创建的消息的视图。

# 创建消息 DetailView

为了让用户查看他们发送给他们的`Subscriber`的`Message`，我们需要一个`MessageDetailView`。这个视图将简单地显示一个`Message`，但应该只允许已登录并且可以使用`Message`的`MailingList`的用户访问该视图。

让我们在`django/mailinglist/views.py`中创建我们的视图：

```py
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import DetailView

from mailinglist.mixins import UserCanUseMailingList
from mailinglist.models import Message

class MessageDetailView(LoginRequiredMixin, UserCanUseMailingList,
                        DetailView):
    model = Message
```

顾名思义，我们将使用 Django 的`DetailView`。为了提供我们需要的保护，我们将添加 Django 的`LoginRequiredMixin`和我们的`UserCanUseMailingList`混合。正如我们以前看到的那样，我们不需要指定模板的名称，因为`DetailView`将根据应用和模型的名称假定它。在我们的情况下，`DetailView`希望模板被称为`mailinglist/message_detail.html`。

让我们在`mailinglist/message_detail.html`中创建我们的模板：

```py
{% extends "base.html" %}
{% load markdownify %}

{% block title %}
  {{ message.subject }}
{% endblock %}

{% block body %}
  <h1 >{{ message.subject }}</h1 >
  <div>
    {{ message.body|markdownify }}
  </div>
{% endblock %}
```

我们的模板扩展了`base.html`并在`body`块中显示消息。在显示`Message.body`时，我们使用第三方 Django Markdownify 标签库的`markdownify`过滤器将任何 markdown 文本呈现为 HTML。

最后，我们需要向`mailinglist`应用的 URLConf 的`urlpatterns`列表中添加一个`path()`到`MessageDetailView`：

```py
    path('message/<uuid:pk>', 
         views.MessageDetailView.as_view(), 
         name='view_message')
```

我们现在已经完成了我们的`mailinglist`应用的模型、视图和模板。我们甚至创建了一个`UserCanUseMailingList`来让我们的视图轻松地阻止未经授权的用户访问`MailingList`或其相关视图。

接下来，我们将创建一个`user`应用来封装用户注册和身份验证。

# 创建用户应用

要在 Mail Ape 中创建一个`MailingList`，用户需要拥有一个帐户并已登录。在本节中，我们将编写我们的`user` Django 应用的代码，它将封装与用户有关的一切。请记住，Django 应用应该范围严密。我们不希望将这种行为放在我们的`mailinglist`应用中，因为这是两个不同的关注点。

我们的`user`应用将与 MyMDB（第一部分）和 Answerly（第二部分）中看到的`user`应用非常相似。由于这种相似性，我们将略过一些主题。要深入研究该主题，请参阅第二章，*将用户添加到 MyMDb*。

Django 通过其内置的`auth`应用（`django.contrib.auth`）使用户和身份验证管理变得更加容易。`auth`应用提供了默认的用户模型、用于创建新用户的`Form`，以及登录和注销视图。这意味着我们的`user`应用只需要填写一些空白，就可以在本地完全实现用户管理。

让我们首先在`django/user/urls.py`中为我们的`user`应用创建一个 URLConf：

```py
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path

import user.views

app_name = 'user'

urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('register', user.views.RegisterView.as_view(), name='register'),
]
```

我们的 URLConf 由三个视图组成：

+   `LoginView.as_view()`: 这是`auth`应用的登录视图。`auth`应用提供了一个接受凭据的视图，但没有模板。我们需要创建一个名为`registration/login.html`的模板。默认情况下，它会在登录时将用户重定向到`settings.LOGIN_REDIRECT_URL`。我们还可以传递一个`next`的`GET`参数来取代该设置。

+   `LogoutView.as_view()`: 这是`auth`应用的注销视图。`LogoutView`是少数在`GET`请求上修改状态的视图之一，它会注销用户。该视图返回一个重定向响应。我们可以使用`settings.LOGOUT_REDIRECT_URL`来配置用户在注销时将被重定向到的位置。同样，我们可以使用`GET`参数`next`来自定义此行为。

+   `user.views.RegisterView.as_view()`: 这是我们将编写的用户注册视图。Django 为我们提供了`UserCreationForm`，但没有视图。

我们还需要添加一些设置，让 Django 正确使用我们的`user`视图。让我们在`django/config/settings.py`中更新一些新设置：

```py
LOGIN_URL = 'user:login'
LOGIN_REDIRECT_URL = 'mailinglist:mailinglist_list'
LOGOUT_REDIRECT_URL = 'user:login'
```

这三个设置告诉 Django 如何在不同的身份验证场景下重定向用户：

+   `LOGIN_URL`：当未经身份验证的用户尝试访问需要身份验证的页面时，`LoginRequiredMixin`使用此设置。

+   `LOGIN_REDIRECT_URL`：当用户登录时，我们应该将他们重定向到哪里？通常，我们将他们重定向到一个个人资料页面；在我们的情况下，是显示`MailingList`列表的页面。

+   `LOGOUT_REDIRECT_URL`：当用户注销时，我们应该将他们重定向到哪里？在我们的情况下，是登录页面。

我们现在还有两项任务：

+   创建登录模板

+   创建用户注册视图和模板

让我们从制作登录模板开始。

# 创建登录模板

让我们在`django/user/templates/registration/login.html`中制作我们的登录模板：

```py
{% extends "base.html" %}
{% load crispy_forms_tags %}

{% block title %} Login - {{ block.super }} {% endblock %}

{% block body %}
  <h1>Login</h1>
  <form method="post" class="col-sm-6">
    {% csrf_token %}
    {{ form|crispy }}
    <button type="submit" id="log_in" class="btn btn-primary">Log in</button>
  </form>
{% endblock %}
```

这个表单遵循了我们之前表单的所有做法。我们使用`csrf_token`来防止 CSRF 攻击。我们使用`crsipy`过滤器使用 Bootstrap 4 样式标签和类打印表单。

记住，我们不需要创建一个视图来处理我们的登录请求，因为我们正在使用`django.contrib.auth`中提供的视图。

接下来，让我们创建一个视图和模板来注册新用户。

# 创建用户注册视图

Django 没有为创建新用户提供视图，但它提供了一个用于捕获新用户注册的表单。我们可以将`UserCreationForm`与`CreateView`结合使用，快速创建一个`RegisterView`。

让我们在`django/user/views.py`中添加我们的视图：

```py
from django.contrib.auth.forms import UserCreationForm
from django.views.generic.edit import CreateView

class RegisterView(CreateView):
    template_name = 'user/register.html'
    form_class = UserCreationForm
```

这是一个非常简单的`CreateView`，就像我们在本章中已经看到的几次一样。

让我们在`django/user/templates/user/register.html`中创建我们的模板：

```py
{% extends "base.html" %}
{% load crispy_forms_tags %}
{% block body %}
  <div class="col-sm-12">
    <h1 >Register for Mail Ape</h1 >
    <form method="post" >
      {% csrf_token %}
      {{ form | crispy }}
      <button type="submit" class="btn btn-primary" >
        Register
      </button >
    </form >
  </div >
{% endblock %}
```

同样，该模板遵循了我们之前`CreateView`模板的相同模式。

现在，我们准备在本地运行 Mail Ape。

# 在本地运行 Mail Ape

Django 自带开发服务器。这个服务器不适合生产（甚至是暂存）部署，但适合本地开发。

让我们使用我们 Django 项目的`manage.py`脚本启动服务器：

```py
$ cd django
$ python manage.py runserver
Performing system checks...

System check identified no issues (0 silenced).
January 29, 2018 - 23:35:15
Django version 2.0.1, using settings 'config.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CONTROL-C.
```

我们现在可以在`http://127.0.0.1:8000`上访问我们的服务器。

# 总结

在本章中，我们启动了 Mail Ape 项目。我们创建了 Django 项目并启动了两个 Django 应用程序。`mailinglist`应用程序包含了我们的邮件列表代码的模型、视图和模板。`user`应用程序包含了与用户相关的视图和模板。`user`应用程序要简单得多，因为它利用了 Django 的`django.contrib.auth`应用程序。

接下来，我们将构建一个 API，以便用户可以轻松地与 Mail Ape 集成。
