# Flask 示例（三）

> 原文：[`zh.annas-archive.org/md5/93A989EF421129FF1EAE9C80E14340DD`](https://zh.annas-archive.org/md5/93A989EF421129FF1EAE9C80E14340DD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：在我们的服务员呼叫器项目中使用 MongoDB

我们的网络应用现在几乎具备了所有功能。如果我们计划对这个应用进行货币化，现在就是向潜在客户演示的时候。即使他们的数据（如他们的账户名称和虚拟表数据）每次我们不得不重新启动服务器时都会丢失，这些数据也足够微不足道，使得完全演示应用程序成为可能。

在本章中，我们将为生产环境添加一个适当的数据库。我们将使用 MongoDB——一个略具争议的 NoSQL 数据库管理系统，因其简单性而变得极其流行，可以说这主要是因为其简单性。我们将看看如何在我们的 VPS 上安装它，正确配置它，并使用 Python 驱动程序访问它。然后，我们将实现完整的`DBHelper`类来替换我们用于测试的`MockDBHelper`。最后，我们将看看如何向 MongoDB 添加索引和向我们的应用程序添加一个 favicon。

在本章中，我们将涵盖以下主题：

+   介绍 MongoDB

+   安装 MongoDB

+   使用 MongoDB shell

+   介绍 PyMongo

+   添加一些最后的修饰

# 介绍 MongoDB

MongoDB 是一个 NoSQL 数据库。这意味着与我们在犯罪地图项目中使用的 MySQL 数据库不同，它不是组织成表、行和列；相反，它是组织成集合、文档和字段。虽然将这些新术语视为我们用于关系数据库的一种翻译可能会有用，但这些概念并不完全相同。如果您有关系数据库的背景，可以在官方 MongoDB 网站上找到有关这些翻译的有用且更完整的参考资料[`docs.mongodb.org/manual/reference/sql-comparison/`](https://docs.mongodb.org/manual/reference/sql-comparison/)。

MongoDB 的结构比 SQL 数据库灵活得多——我们的所有数据都不必符合特定的模式，这可以节省开发时间。对于我们的犯罪地图项目，我们不得不花时间来查看我们的数据，并决定如何在数据库中表示它。然后，我们不得不设置一堆字段，指定数据类型、长度和其他约束。相比之下，MongoDB 不需要这些。它比关系数据库管理系统更灵活，并且使用文档来表示数据。文档本质上是类似于我们从使用的 API 中提取的数据的 JSON 数据。这意味着我们可以根据需要轻松添加或删除字段，并且我们不需要为我们的字段指定数据类型。

这样做的缺点是，由于不需要强制结构化和一致，我们很容易变得懒惰，并陷入在单个字段中混合不同数据类型和允许无效数据污染我们数据库的不良做法。简而言之，MongoDB 给了我们更多的自由，但这样做也将一些保持清洁和一致性的责任转移到了我们的肩上。

# 安装 MongoDB

MongoDB 可以在 Ubuntu 软件仓库中找到，但由于更新频繁且仓库版本往往滞后，强烈建议直接从官方 Mongo 软件包安装。

我们将逐步介绍如何做到这一点，但由于安装过程可能会发生变化，建议从官方安装指南中获取所需 URL 和步骤的更新版本[`docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/`](https://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/)。

首先，我们需要导入 MongoDB 的公钥，以便进行身份验证。仅在您的 VPS 上（与以前一样，我们不会在开发机器上安装数据库服务器），运行以下命令：

```py
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927

```

现在我们有了密钥，我们可以使用以下命令将 MongoDB 软件包的链接添加到我们的软件源。请注意，此命令特定于 Ubuntu 14.04“Trusty”，这是写作时最新的长期支持 Ubuntu 版本。如果您的 VPS 运行不同版本的 Ubuntu，请确保从前面提供的 MongoDB 文档链接中获取正确的命令。要发现您使用的 Ubuntu 版本，请在终端中运行`lsb_release -a`并检查版本号和名称的输出：

```py
echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list

```

现在，我们只需要通过运行以下命令来更新我们的源列表：

```py
sudo apt-get update

```

最后，通过运行以下命令进行实际安装：

```py
sudo apt-get install -y mongodb-org

```

前面的命令将使用一些合理的默认值安装 MongoDB 并启动服务器。它还会配置服务器，以便在重新启动 VPS 时自动启动。

# 使用 MongoDB shell

与我们在 MySQL 中讨论的类似，MongoDB 带有一个简单的 shell。这非常适合运行快速的一次性命令并熟悉语法。让我们运行基本的 CRUD 操作，以熟悉 MongoDB 的工作方式。

与我们之前的项目一样，一旦我们引入 MongoDB，我们将只通过 Python 代码来使用它；然而，首先我们将直接在 shell 中编写命令。这意味着语法上会有一些细微的差异，但由于几乎所有东西都是基于 JSON 的，这些差异不应该是问题。

## 启动 MongoDB shell

要启动 MongoDB shell，请在您的 VPS 上运行以下命令：

```py
mongo

```

这将启动交互式 MongoDB shell，如下图所示，您可以随时通过按*Ctrl + C*或在 shell 中输入`exit`并按*Enter*来退出。

![启动 MongoDB shell](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_01.jpg)

## 在 MongoDB shell 中运行命令

与 MySQL 一样，MongoDB 中的顶级概念是数据库。默认情况下，这将连接到名为`test`的数据库。我们可以使用`use`命令更改数据库。在 shell 中运行以下命令：

```py
use sandbox

```

您应该看到输出“**切换到 db sandbox**”。这是我们可以注意到 MySQL 和 MongoDB 之间的第一个重大差异。对于 MySQL，我们首先必须创建数据库。这是我们将在 MongoDB 中看到的一个常见模式；如果引用一个不存在的数据库、集合或字段，它将自动为您创建。

### 使用 MongoDB 创建数据

现在，让我们创建一个集合（类似于 Crime Map 项目中的 MySQL 数据库中的表）并向其中添加一个文档（类似于 MySQL 数据库中的表中的行）。在 MongoDB shell 中运行以下命令：

```py
db.people.insert({"name":"John Smith", "age": 35})

```

在前面的命令中，`db`指的是当前数据库。紧接着，`people`指的是这个名称的集合。由于它不存在，当我们尝试使用它时，它将被创建。接下来是`insert`，这意味着我们想要向数据库添加一些内容。我们将作为参数传递（在圆括号内），这是一个 JSON 结构。在我们的例子中，我们用一个包含人名和年龄的 JSON 对象表示一个人。请注意，除了`age`字段的值之外，所有内容都在引号中；再次，与 MySQL 不同，我们不必为这些数据指定类型。MongoDB 将把名称存储为字符串，将年龄存储为整数，但不对这些字段施加任何限制。

向数据库添加另一个人，以使我们将尝试的下一个操作更有意义。运行以下命令：

```py
db.people.insert({"name":"Mary Jones"})

```

### 使用 MongoDB 读取数据

MongoDB 使用`find()`命令而不是 SQL 中的`SELECT`语句。与 SQL 类似，我们可以指定要在数据中搜索的条件，并选择要返回的数据库字段。运行以下命令：

```py
db.people.find()

```

这是`find`操作的最基本版本。它将简单地*查找*或*检索*`people`集合中的所有数据和所有字段。您应该会看到 MongoDB 输出我们刚刚添加的两个人的所有信息。您会注意到每个人还添加了一个`ObjectId`字段；MongoDB 会自动为我们的每个文档添加唯一标识符字段，并且这些`ID`字段也会自动索引。

我们也可以使用单个参数的`find`。该参数指定条件，MongoDB 只返回与之匹配的文档。运行以下命令：

```py
db.people.find({"name":"John Smith"})

```

如果名称匹配`John Smith`，则此命令将返回所有记录的所有字段，因此您应该会看到返回一个单一结果并打印到 shell 中，如下面的截图所示：

![使用 MongoDB 读取数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_02.jpg)

最后，如果我们不想返回所有字段，可以运行`find`命令并传入第二个参数来指定我们想要的字段。运行以下命令，您应该会看到以下截图中的结果：

```py
db.people.find({"name":"John Smith"}, {"age":1})

```

![使用 MongoDB 读取数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_03.jpg)

第一个参数表示我们只对名为“John Smith”的人感兴趣。第二个参数表示我们只对他们的年龄感兴趣。这里，`1`是一个标志，表示我们想要这个字段。我们可以使用`0`来表示我们对一个字段不感兴趣，这样的话，除了这个字段之外，所有字段都会被返回。

请注意，即使我们说我们只对`age`字段感兴趣，上述命令返回了`_id`字段。除非明确排除，否则始终返回`_id`字段。例如，我们可以运行以下命令：

```py
db.people.find({"name":"John Smith"}, {"age":1, "_id": 0})

```

这将只返回约翰的年龄，没有其他内容。另外，请注意`_id`字段的键是`_id`而不是`id`；这是为了避免与许多编程语言中的`id`关键字发生冲突，包括 Python。

我们的每个示例都使用了非常基本的 JSON 对象，每个参数只有一个值，但我们可以为每个参数指定多个值。考虑以下命令之间的区别：

```py
db.people.find({"name":"John Smith", "age":1})
db.people.find({"name":"John Smith"}, {"age":1})

```

第一个命令使用带有单个参数的`find`，返回所有名为 John Smith 且年龄为 1 岁的人的所有记录。第二个命令使用带有两个参数的`find`，返回名为 John Smith 的人的`age`字段（和`_id`字段）。

与 MySQL 的最后一个区别是，不需要提交新数据。一旦我们运行`insert`语句，数据将保存在数据库中，直到我们将其删除。

### 使用 MongoDB 更新数据

更新现有记录稍微复杂一些。MongoDB 提供了一个`update`方法，可以与`insert`和`find`相同的方式调用。它也需要两个参数——第一个指定查找要更新的文档的条件，第二个提供一个新文档来替换它。运行以下命令：

```py
db.people.update({"name":"John Smith"}, {"name":"John Smith", "age":43})

```

这将找到名为 John Smith 的人，并用一个新的人替换他，新人也叫`John Smith`，年龄为 43 岁。如果有很多字段，我们只想更改一个字段，那么重新创建所有旧字段是繁琐和浪费的。因此，我们可以使用 MongoDB 的`$set`关键字，它只会替换文档中指定的字段，而不是替换整个文档。运行以下命令：

```py
db.people.update({"name":"John Smith"}, {$set: {"age":35}})

```

这将把约翰的年龄再次更新为 35 岁，这对他来说可能是一种解脱。我们只改变了`age`字段，而不是覆盖整个文档。我们在第二个参数中使用了`$set`关键字来实现这一点。请注意，`update`函数仍然需要两个参数，而第二个参数现在具有嵌套的 JSON 结构——输出的 JSON 对象将`$set`作为键，另一个 JSON 对象作为值。内部 JSON 对象指定了我们想要进行的更新。

### 使用 MongoDB 删除数据

删除数据就像查找数据一样简单。我们将简单地使用`remove`函数而不是`find`，然后在单个参数中指定匹配条件，就像我们在`find`中所做的那样。运行以下命令从我们的数据库中删除 John：

```py
db.people.remove({"name":"John Smith"})

```

您将看到一个确认，显示已删除一条记录，如下图所示：

![使用 MongoDB 删除数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_04.jpg)

您还可以通过运行以下命令来检查 John 是否已被删除：

```py
db.people.find()

```

现在，只有 Mary 将被返回，如下图所示：

![使用 MongoDB 删除数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_05.jpg)

要从集合中删除所有文档，我们可以传入一个空参数。运行以下命令以删除所有剩余的人：

```py
db.people.remove({})

```

在这里，`{}`指定了一个空的条件，因此匹配所有文档。通过再次运行`find`命令来检查我们的`people`集合是否为空，如下所示：

```py
db.people.find()

```

您将看不到任何输出，如下图所示（包括前面的示例，以便了解上下文），因为我们的`people`集合现在为空：

![使用 MongoDB 删除数据](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_06.jpg)

现在我们已经了解了 MongoDB 的基础知识，让我们看看如何使用 Python 而不是通过 shell 来运行类似的命令。

# 介绍 PyMongo

PyMongo 是一个实现了 MongoDB 驱动程序的库，它允许我们从应用程序代码中对数据库执行命令。像往常一样，使用以下命令通过 pip 安装它（请注意，与 MongoDB 类似，您只需要在服务器上安装此库）：

```py
pip install --user pymongo

```

现在，我们可以将这个库导入到我们的应用程序中，并构建我们真正的`DBHelper`类，实现我们在`MockDBHelper`类中使用的所有方法。

## 编写 DBHelper 类

我们需要的最后一个类是`DBHelper`类，它将包含我们的应用程序代码与数据库交互所需的所有函数。这个类将使用我们刚刚安装的`pymongo`库来运行 MongoDB 命令。在`waiter`目录中创建一个名为`dbhelper.py`的文件，并添加以下代码：

```py
import pymongo

DATABASE = "waitercaller"

class DBHelper:

  def __init__(self):
    client = pymongo.MongoClient()
    self.db = client[DATABASE]
```

这段代码导入了`pymongo`库，在构造函数中，它创建了一个客户端——一个 Python 对象，让我们可以在数据库上运行我们之前尝试过的 CRUD 操作。我们将我们的数据库名称定义为全局的，并在构造函数的第二行中，使用`client`连接到指定的数据库。

### 添加用户方法

对于用户管理，我们需要与我们的模拟类中相同的两个函数。第一个是从数据库中获取用户（以便登录此用户），第二个是向数据库中添加新用户（以便注册新用户）。将以下两个方法添加到`DBHelper`类中：

```py
    def get_user(self, email):
        return self.db.users.find_one({"email": email})

    def add_user(self, email, salt, hashed):
        self.db.users.insert({"email": email, "salt": salt, "hashed": hashed})
```

对于第一种方法，我们使用了 PyMongo 的`find_one()`函数。这类似于我们在 MongoDB shell 中使用的`find()`方法，但是它只返回单个匹配项，而不是所有匹配的结果。由于我们每个电子邮件地址只允许注册一个用户，所以匹配结果要么是一个，要么是零。在这里使用`find()`而不是`find_one()`也可以，但是我们会得到一个产生单个或零元素的 Python 生成器。使用`find_one()`，我们要么得到一个单个用户的结果，要么得到空，这正是我们的登录代码所需要的。

对于`add_user()`方法，我们使用了`insert()`，就像我们在使用 MongoDB shell 时讨论的那样，并插入了一个包含电子邮件地址、盐和密码的盐哈希的新文档。

### 添加表方法

我们需要处理我们的用户将创建的虚拟表的以下情况的方法：

+   一个用于添加新表

+   一个用于更新表（以便我们可以添加缩短的 bitly URL）

+   一个用于获取所有表（以便我们可以在**账户**页面中显示它们）

+   一个用于获取单个表（以便我们可以将本地表号添加到我们的请求中）

+   一个用于删除表

这是一组不错的方法，因为它演示了所有四种 CRUD 数据库操作。将以下代码添加到`DBHelper`类中：

```py
def add_table(self, number, owner):
    new_id = self.db.tables.insert({"number": number, "owner": owner})
    return new_id

def update_table(self, _id, url):
    self.db.tables.update({"_id": _id}, {"$set": {"url": url}})

def get_tables(self, owner_id):
    return list(self.db.tables.find({"owner": owner_id}))

def get_table(self, table_id):
    return self.db.tables.find_one({"_id": ObjectId(table_id)})

def delete_table(self, table_id):
    self.db.tables.remove({"_id": ObjectId(table_id)})
```

对于`add_table()`方法，每次插入表时，MongoDB 都会分配一个唯一标识符。这为我们提供了真正的多用户支持。我们的模拟代码使用用户选择的表号作为唯一标识符，并且在多个用户选择相同的表号时会出现问题。在`add_table()`方法中，我们将此唯一标识符返回给应用程序代码，然后可以用它来构建所需的 URL，以便为此特定表发出新的请求。

`update_table()`方法使用了我们之前讨论过的`insert()`函数。与我们之前的示例一样，我们使用了`$set`关键字来保持我们的原始数据完整，并且只编辑了特定字段（而不是覆盖整个文档）。

### 注意

请注意，与 MongoDB shell 示例不同，我们现在需要在`$set`周围加上引号；这使得它在语法上成为合法的 Python 代码（字典的所有键都必须是字符串），而 PyMongo 会在后台处理魔术，将我们的 Python 字典转换为 MongoDB 命令和对象。

`get_tables()`函数使用了`find()`函数，而不是我们用于用户代码的`find_one()`函数。这导致 PyMongo 返回一个 Python 生成器，可以生成与*find*条件匹配的所有数据。由于我们假设总是能够将所有表加载到内存中，因此我们将此生成器转换为列表，然后将其传递给我们的模板。

`get_table()`函数用于在我们只有访问表 ID 并且需要获取有关表的其他信息时使用。这正是我们处理请求时的情况；请求的 URL 包含了表的唯一 ID，但希望将表号添加到**Dashboard**页面。MongoDB 生成的唯一标识符实际上是对象而不是简单的字符串，但我们只有来自我们的 URL 的字符串。因此，在使用此 ID 查询数据库之前，我们创建了`ObjectId`并传入了字符串。`ObjectId`可以从自动安装的`bson`库中导入。这意味着我们还需要添加另一个导入语句。将以下行添加到`dbhelper.py`文件的顶部：

```py
from bson.objectid import ObjectId
```

最后，`delete_table()`方法使用了`remove()`函数，与之前完全相同。在这里，我们通过其唯一标识符删除了一个表，因此我们再次从之前的字符串创建了一个`ObjectId`对象，然后将其传递给数据库。

### 添加请求方法

我们需要将最后三个方法添加到`DBHelper`类中以处理关注请求。我们需要：

+   当顾客访问提供的 URL 时，添加一个请求

+   获取特定用户的所有请求，以在**Dashboard**页面上显示

+   当用户点击**解决**按钮时，从数据库中删除请求

将以下方法添加到`dbhelper.py`文件中：

```py
    def add_request(self, table_id, time):
        table = self.get_table(table_id)
        self.db.requests.insert({"owner": table['owner'], "table_number": table['number'],"table_id": table_id, "time": time})

    def get_requests(self, owner_id):
        return list(self.db.requests.find({"owner": owner_id}))

    def delete_request(self, request_id):
        self.db.requests.remove({"_id": ObjectId(request_id)})
```

## 更改应用程序代码

现在我们有了一个真正的`DBHelper`类，我们需要根据我们所处的环境有条件地导入它。将`waitercaller.py`文件中`MockDBHelper`类的导入更改为如下所示：

```py
if config.test
    from mockdbhelper import MockDBHelper as DBHelper
else:
    from dbhelper import DBHelper
```

确保在`config`导入下面添加前面四行。

此外，我们的`DBHelper`类主要处理许多`ObjectId`实例，而我们的`MockDBHelper`类使用字符串。因此，我们需要对我们的`account_createtable()`函数进行小的更改，将`ObjectId`转换为字符串。查看`waitercaller.py`中的以下行：

```py
new_url = BH.shorten_url(config.base_url + "newrequest/" + tableid)
```

现在，将其更改为以下内容：

```py
new_url = BH.shorten_url(config.base_url + "newrequest/" + str(tableid))
```

这将确保在我们将其连接到我们的 URL 之前，`tableid`始终是一个字符串。

我们生产环境需要的最后一次代码更改是一个不同的`config`文件，用于指定 VPS 的正确`base_url`并指示不应使用`MockDBHelper`类。由于我们不会将`config`文件检入`git`存储库，因此我们需要直接在 VPS 上创建这个文件。

# 在生产环境中测试我们的应用程序

一旦添加了上述代码，我们的应用程序现在应该是完全可用的！与我们的犯罪地图应用程序的数据库部分一样，这部分是最微妙的，因为我们无法在本地测试`DBHelper`代码，而必须直接在 VPS 上进行调试。然而，我们有信心，从我们的`MockDBHelper`类中，我们的应用程序逻辑都是有效的，如果新的数据库代码能够保持下来，其他一切应该都会按预期进行。让我们将代码推送到服务器上并进行测试。

在您的`waitercaller`目录中本地运行以下命令：

```py
git add .
git commit -m "DBHelper code"
git push origin master

```

在您的 VPS 上，切换到`WaiterCaller`目录，拉取新代码，并按以下方式重新启动 Apache：

```py
cd /var/www/waitercaller
git pull origin master

```

现在，通过运行以下命令使用 nano 创建生产`config`文件：

```py
nano config.py

```

在新的`config.py`文件中输入以下内容，将`base_url`中的 IP 地址替换为您的 VPS 的 IP 地址。

```py
test = False
base_url = "http://123.456.789.123/

```

然后，通过按*Ctrl* + *X*并在提示时输入*Y*来保存并退出文件。

现在，运行以下命令以使用新代码重新加载 Apache：

```py
sudo service apache2 reload 

```

在本地浏览器中访问您的 VPS 的 IP 地址，并对所有功能进行一次全面测试，以确保一切都按预期工作。这包括尝试使用无效数据注册、注册、尝试使用无效数据登录、登录、创建表、创建请求、查看仪表板、等待仪表板刷新、解决请求等。对于全面的测试，所有操作应该以不同的组合多次完成。

你可能会明白，即使对于我们相对简单的应用程序，这也变得很繁琐。对于更复杂的应用程序，值得花费精力创建自动测试——模拟用户在网站上的操作，但也具有内置的对每个步骤应该发生什么的期望。诸如 Selenium（[www.seleniumhq.org](http://www.seleniumhq.org)）之类的工具非常有用，可以用来构建这样的测试。

### 提示

与往常一样，如果出现任何问题，或者出现可怕的“500：内部服务器错误”，请检查`/etc/log/apache2/error.log`中的 Apache 错误文件以获取提示。

# 添加一些最后的修饰

最后，我们将向我们的数据库添加一些索引，以提高效率并防止为单个表打开多个请求。之后，我们将添加一个网站图标来个性化我们的 Web 应用程序。

## 向 MongoDB 添加索引

数据库索引用于提高效率。通常，要在数据库中找到与特定条件匹配的一组文档（也就是说，每当我们使用 MongoDB 的`find()`方法时），数据库引擎必须检查每条记录并添加与返回结果匹配的记录。如果我们向特定字段添加索引，数据库将存储更多的元数据，可以将其视为存储该字段的排序副本。在排序列表中查找`john@example.com`是否出现比在无序列表中查找要高效得多。然而，索引确实会占用额外的存储空间，因此选择在哪里添加索引是计算机科学中经典的“时空权衡”，无处不在。MongoDB 还可以使用索引对字段施加一些约束。在我们的情况下，我们将使用*唯一*索引，如果索引字段的值已经出现在此集合中的另一个文档中，则阻止向数据库添加新文档。

我们将在 MongoDB 中添加两个索引。我们将在`users`集合的`email`字段上添加一个索引，因为我们将使用此字段在登录时查找用户，并且我们希望查找尽可能快。我们还希望在数据库级别确保每个电子邮件地址都是唯一的。我们已经有两个检查：HTML5 字段进行前端检查，我们的应用程序代码进行后端检查。即使数据库检查可能看起来是不必要的，但设置起来很容易，并遵循内置安全性的良好原则（其中检查不仅仅是作为事后添加的，而是尽可能经常验证所有数据），以及应用程序的每个*层*（前端，应用程序层和数据库层在我们的情况下）都不应该盲目地信任从更高层传递的数据的原则。

我们还将在请求集合的`table_id`字段上添加唯一索引。这将防止单个不耐烦的桌子通过刷新创建新请求的页面来向仪表板发送多个请求。这也很有用，因为我们的请求是使用 GET 请求创建的，可以很容易地复制（通过浏览器预加载页面或社交网络抓取用户访问的链接以了解更多信息）。通过确保每个请求的`table_id`是唯一的，我们可以防止这两个问题。

### 我们在哪里添加索引？

当我们构建 MySQL 数据库时，我们有一个独立于我们的犯罪地图 Web 应用程序的设置脚本。此设置脚本构建了数据库的框架，我们用 Python 编写它，以便如果我们需要迁移到新服务器或重新安装我们的数据库，我们可以轻松地再次运行它。

由于 MongoDB 非常灵活，我们不需要设置脚本。我们可以在新服务器上启动我们的应用程序，并且只要安装了 MongoDB，数据库将会在添加新数据或从备份中恢复旧数据时从头开始重新创建。

缺少设置脚本意味着我们实际上没有一个很好的地方可以向我们的数据库添加索引。如果我们通过 MongoDB shell 添加索引，这意味着如果应用程序需要迁移到新服务器，有人必须记住再次添加它们。因此，我们将创建一个独立的 Python 脚本来创建索引。在您的本地计算机上，在`waitercaller`目录中创建一个 Python 文件，并将其命名为`create_mongo_indices.py`。添加以下代码：

```py
import pymongo
client = pymongo.MongoClient()
c = client['waitercaller']
print c.users.create_index("email", unique=True)
print c.requests.create_index("table_id", unique=True)
```

连接代码与我们以前使用的代码相同，用于创建索引的代码足够简单。我们在要在其上创建索引的集合上调用`create_index()`方法，然后传递要用于创建索引的字段名称。在我们的情况下，我们还传递了`unique=True`标志，以指定索引也应该添加唯一约束。

现在，我们需要对我们的应用程序进行一些小的更改，以便它可以处理已经打开的相同请求的情况。在`dbhelper.py`文件中，将`add_request()`方法更新为以下内容：

```py
    def add_request(self, table_id, time):
        table = self.get_table(table_id)
        try:
            self.db.requests.insert({"owner": table['owner'], "table_number": table['number'], "table_id": table_id, "time": time})
            return True
        except pymongo.errors.DuplicateKeyError:
            return False
```

如果我们尝试向数据库插入具有重复的`table_id`字段的请求，将抛出`DuplicateKeyError`。在更新的代码中，我们将捕获此错误并返回`False`以指示请求未成功创建。当请求成功时，我们现在也将返回`True`。为了在应用程序代码中利用这些信息，我们还需要更新`new_request()`方法。编辑该方法，使其类似于此：

```py
@app.route("/newrequest/<tid>")
def new_request(tid):
        if DB.add_request(tid, datetime.datetime.now()):
            return "Your request has been logged and a waiter will be with you shortly"
        return "There is already a request pending for this table. Please be patient, a waiter will be there ASAP"
```

现在，我们将检查新请求是否成功创建，或者现有请求是否阻止它。在后一种情况下，我们将返回不同的消息，要求顾客耐心等待。

为了测试新功能，将新的和修改后的文件添加到 Git（`waitercaller.py`，`dbhelper.py`，`create_mongo_indices.py`），提交，然后推送它们。在您的 VPS 上，拉取新的更改，重新启动 Apache，并运行以下命令：

```py
python create_mongo_indices.py

```

为了创建我们之前讨论过的索引，再次在浏览器中运行一些测试，确保没有出现任何问题，并验证当您重复访问相同的关注请求 URL 时是否显示了新消息，如下图所示：

![我们在哪里添加索引？](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_07.jpg)

你可能会发现，由于浏览器预取页面，当您首次通过帐户页面创建表格时，会自动发出关注请求。如果您在不期望时看到上图中显示的消息，请在仪表板页面上解决任何未处理的请求，并再次访问 newrequest URL。

## 添加网站图标

我们要添加到我们的应用程序的最后一件事是一个网站图标。*网站图标*是大多数浏览器在打开页面时在标签栏中显示的小图像，如果用户将网站加为书签，则会显示在书签栏上。它们为网站增添了友好的触感，并帮助用户更快地识别网站。

关于网站图标的棘手之处在于它们必须非常小。习惯上使用 16x16 像素的图像作为网站图标，这并不留下太多创意空间。有一些很好的网站可以帮助您为您的网站创建完美的网站图标。其中一个网站是[favicon.cc](http://favicon.cc)，它允许您从头开始创建网站图标（给您 16x16 的空白像素开始），或者可以导入图像。使用导入功能，您可以使用一个更大的图像，[favicon.cc](http://favicon.cc)会尝试将其缩小为 16x16 像素，这样做的效果参差不齐，通常对于简单的图像效果更好。代码包中包含一个示例网站图标，放在静态目录中，并在下图中显示了它的放大版本：

![添加网站图标](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_08.jpg)

一旦您有了一个图标（您可以使用代码包中提供的图标），就很容易告诉 Flask 将其与页面的其余部分一起提供。确保您的图标被命名为`favicon.ico`（图标文件的标准扩展名是`.ico`），并将其放在`waitercaller/static`目录中。然后，在`base.html`模板的`<head>`部分中添加以下行：

```py
<link rel="shortcut icon" href="{{ url_for('static', filename='favicon.ico') }}">
```

这将创建一个链接到`favicon.ico`文件，使用 Jinja 的`url_for`函数生成所需的完整 URL，以便指向静态目录，然后将其简单转换为 HTML（您可以通过浏览器中的**查看源代码**来查看）。看一下下面的内容：

```py
<link rel="shortcut icon" href="/static/favicon.ico">
```

现在，如果您再次重新加载页面，您将在标签标题中看到网站图标，如果您将页面加为书签，您也将在浏览器的书签工具栏中看到图标，如下图所示：

![添加网站图标](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/flask-ex/img/B04312_11_09.jpg)

这就是我们最后的项目。当然，没有一个 Web 应用程序是真正完整的，有无数的改进和功能可以添加。在本书的这个阶段，您将拥有足够的知识来开始添加自己的更改，并将您的原创想法变成现实，无论是作为我们在本书中介绍的项目的扩展，还是从头开始，作为全新的 Web 应用程序。

# 总结

在本章中，我们完成了我们的服务员呼叫器 Web 应用程序。我们在服务器上安装了 MongoDB，学习了如何通过 shell 使用它，然后安装了 PyMongo。使用 PyMongo，我们创建了一个新的数据库助手类，允许我们的应用程序代码在新数据库上运行操作。

最后，我们添加了一个网站图标，使我们的 Web 应用程序更加友好和美观。

在下一章和最后一章中，我们将看看我们的应用程序还可以添加什么来改善可用性和安全性，并以一些指针结束，指出接下来继续学习 Flask 和 Python 进行 Web 开发的地方。


# 附录 A. 未来的一瞥

在本书中，我们涵盖了各种主题，并且演示了构建三个功能齐全且有用的 Web 应用程序。然而，书籍本质上是有限的，而 Web 开发的世界趋向无限，因此我们无法添加所有内容。在本章中，我们将快速浏览我们无法详细介绍的技术。我们将首先看看可以直接用于扩展或改进本书中创建的项目的技术。然后，我们将研究一些更高级的 Flask 功能，这些功能在我们的项目中并不需要使用，但在其他项目中几乎肯定会有用。最后，我们将简要讨论对 Web 开发有用但不特定于我们在此构建的项目或 Flask 的技术。

# 扩展项目

我们构建的项目都是功能齐全的，但还不够准备好用于大规模、实时使用。如果它们要扩展到处理成千上万的用户或者是商业应用程序，它们需要一些更多的功能。这些将在接下来的部分中讨论。

## 添加域名

我们使用 VPS 的 IP 地址访问了所有项目。您几乎肯定习惯了使用域名而不是 IP 地址访问 Web 应用程序。当您使用域名（例如[`google.com`](http://google.com)）时，您的浏览器首先向 DNS 服务器发送请求，以找出与此域关联的 IP 地址是什么。DNS 服务器类似于巨大的自动电话簿，专门用于将人类更容易记住的域名（例如[`google.com`](http://google.com)）翻译成组织互联网的 IP 地址（例如 123.456.789.123）。

要使用域名而不是 IP 地址，您需要从注册商那里购买一个。通常，您的**互联网服务提供商**（**ISP**）可以帮助您购买域名（例如`yourname.com`）。域名通常价格不贵，您可以每年以几美元的价格购买。

一旦购买了域名，您需要正确设置 DNS 设置。大多数 ISP 都有在线控制面板，您可以自己完成这些设置，但您可能需要联系他们来协助您。您的域名需要指向您的 VPS。为此，您需要创建一个将域名映射到您的 IP 的“A”类型 DNS 记录。

一旦您的域名指向您的服务器，您可以配置 Apache 来识别它，而不是使用我们在 Apache 配置文件中放置的`example.com`占位符，例如`/etc/apache2/sites-available/waitercaller.conf`。

域名的更改也需要一段时间才能传播，即世界上的主要 DNS 服务器需要更新，以便当有人访问您的域名时，DNS 服务器可以将其重定向到您的 IP 地址。DNS 传播可能需要几个小时。

## 添加 HTTPS

您可能已经注意到，银行、谷歌和微软等大型公司以及越来越多的其他公司的网站都会自动重定向到**HTTPS**版本。这里的“S”代表*安全*，因此完整的缩写变成了**超文本传输安全协议**。每当您在浏览器的导航栏中看到 HTTPS（通常旁边有一个绿色的挂锁）时，这意味着您和服务器之间的所有流量都是加密的。这可以防止所谓的*中间人攻击*，即位于您和服务器之间的恶意人员可以查看或修改您和服务器交换的内容。

直到最近，这种加密是由网站所有者通过从**证书颁发机构**（**CA**）购买昂贵的证书来实现的。CA 的工作是充当您和服务器之间的可信第三方，向网站所有者签发一个签名证书。这个证书可以用来建立客户端和服务器之间的加密通道。由于成本过高，HTTPS 只在绝对必要的安全性场合（例如在线银行业务）和像谷歌这样能够支付高额费用的公司中使用。随着每个人开始意识到基于信任的万维网模型本质上存在缺陷，HTTPS 变得越来越受欢迎，即使是对于小型博客和个人网站也是如此。像 Let's Encrypt（[`letsencrypt.org`](https://letsencrypt.org)）这样的公司现在提供免费证书，这些证书可以轻松安装和配置以与流行的 Web 服务器（如 Apache）一起使用。

对于我们的最终项目，由于我们处理敏感数据（特别是密码），对于我们的应用程序的非平凡使用，使用 HTTPS 是必须的，对于我们的其他两个项目也是理想的（HTTPS 总是比 HTTP 更好）。尽管现在设置证书以与您的 Web 服务器一起使用的过程比几年前简单得多，但是如何设置 Apache2 以与 CA 证书一起使用的完整演练超出了本书的范围。

但是，如果您只花时间了解本章提到的技术中的一种，那么应该是这个。这是一个非常简单的 Digital Ocean 教程链接，向您展示如何在 Ubuntu 14.04 上设置证书以与 Apache2 一起使用（这是本书中使用的确切配置）：

[`www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu-14-04`](https://www.digitalocean.com/community/tutorials/how-to-secure-apache-with-let-s-encrypt-on-ubuntu-14-04)

## 新注册的电子邮件确认

在我们的第三个项目中，您可能注意到我们的注册流程有点不同寻常。新用户在网站上注册的正常方式如下：

1.  用户填写注册表并提交。

1.  服务器将数据保存在数据库中。

1.  服务器生成一个唯一且安全的令牌，并将该令牌与注册关联起来，并将其标记为不完整。

1.  服务器通过 URL 向用户发送一个唯一且安全的令牌，并请求用户点击该 URL 以确认账户。

1.  用户点击带有唯一令牌的 URL。

1.  服务器找到与此令牌关联的不完整注册，并将注册标记为已确认。

上述过程是为了证明用户向我们提供了一个真实的电子邮件地址，并且可以访问该地址。当然，用户不希望等待某人手动发送电子邮件，因此确认电子邮件必须自动发送。这会导致一些复杂情况，包括需要设置邮件服务器以及我们发送的自动确认电子邮件可能最终会出现在用户的垃圾邮件文件夹中，导致所有人都感到沮丧。另一个选择是使用*电子邮件作为服务*平台，例如亚马逊的**简单电子邮件服务**（**SES**）。但是，这些通常不是免费的。

一旦用户确认了电子邮件账户，我们也可以用它来允许用户重置忘记的密码。同样，这将涉及向想要重置密码的用户发送自动电子邮件。该电子邮件将再次包含 URL 中的安全唯一令牌，用户将点击该令牌以证明他或她确实发出了密码重置请求。然后，我们将允许用户输入新密码，并使用新的（散列和加盐的）密码更新数据库。请注意，我们不能也不应该发送用户自己的密码，因为我们只存储密码的加盐和散列版本；我们无法发现忘记的密码。

完整的用户帐户系统具有自动电子邮件确认和“忘记密码”功能是相当复杂的。我们可以使用 Python 和 Flask 以及电子邮件服务器来设置它，但在下一节中，我们还将讨论一些更多的 Flask 扩展，这些扩展可以使这个过程更容易。

## 谷歌分析

如果我们商业运行任何网络应用程序，我们可能会对实际使用它们的人数感兴趣。这将帮助我们决定如何（以及是否）为我们的应用程序收费，并提供其他有用的见解。

通过 Google Analytics 是实现这一目标的最常见方式。这是谷歌提供的一项服务，不仅可以追踪有多少人访问您的网站，还可以追踪他们在网站上花费的时间、他们是如何找到网站的、他们来自哪个国家、关于他们用于网页浏览的设备的信息，以及许多其他有见地的统计数据。Google Analytics 是免费的，要开始使用它，您只需要在[`analytics.google.com`](https://analytics.google.com)上创建一个帐户（或使用您现有的谷歌帐户）。在填写有关您的网站的一些信息后，您将获得一小段 JavaScript 代码。这段 JavaScript 代码包含一个分配给您的网站的唯一跟踪 ID。您需要将 JavaScript 代码添加到您的网站上，每当有人访问网站时，JavaScript 代码将加载到他们的网络浏览器中，并将有关他们的信息发送到谷歌，然后谷歌将使用唯一 ID 将信息与您关联起来。在 Google Analytics 仪表板上，您可以看到访问者数量、访问时间的图表，以及许多其他信息。

在我们的服务员呼叫项目中，我们将在`base.html`文件的末尾添加 JavaScript 代码以及 Bootstrap JavaScript 代码。

## 可扩展性

作为网络应用程序创建者最好的问题是创建了一个太受欢迎的应用程序。如果有很多人访问您的应用程序，这意味着您创造了一些好东西（并且可能开始向人们收费）。我们的小型 VPS 将无法处理大量流量。如果成千上万的人同时访问网站，我们将很快耗尽网络带宽、处理能力、内存和磁盘空间。

关于创建可扩展的 Web 应用程序的完整讨论将是一本专门的书。然而，我们需要采取的一些步骤包括：

+   **在专用机器上运行数据库**：目前，我们在同一台物理机器上运行我们的 Web 服务器和数据库。对于较大的 Web 应用程序，数据库将有自己的专用机器，以便大量的数据库使用（例如，许多餐厅顾客创建新请求）不会对只想浏览我们主页的人产生负面影响。通常情况下，数据库机器会有大量的磁盘空间和内存，而运行 Web 服务器的机器将更注重高带宽可用性和处理能力。

+   **运行负载均衡器**：如果我们有很多访问者，一台机器无论多么大和强大都无法跟上负载。因此，我们将运行几台重复的 Web 服务器。然后问题将是如何均匀地将新访问者分配到所有不同的机器中。为了解决这个问题，我们将使用一个叫做*负载均衡器*的东西，它负责接受用户的初始请求（也就是当用户访问您的主页时）并将这个用户分配给一个复制的 Web 服务器。

随着我们的规模越来越大，情况会变得越来越复杂，我们还会添加副本数据库机器。一个受欢迎的网站需要全天候维护，通常需要一个团队的人来维护，因为硬件会出现故障，恶意用户存在，而更新（为了减轻恶意用户的攻击而必要）往往会破坏软件之间的兼容性。好的一面是，如果任何 Web 应用程序变得足够受欢迎，需要上述的情况，那么这个应用程序可能也会产生足够的收入，以至于让所有讨论的问题成为“SEP”，或者是别人的问题。也就是说，我们可以雇佣一个系统管理员，一个数据库管理员和一位首席安全官，让他们解决问题，然后度过余生在海上巡航。在这一点上，让我们来看看一些关于 Flask 的特定扩展，以丰富我们的知识。

# 扩展你的 Flask 知识

你可能期望 Flask 作为一个微框架，可以在一本书中完整地介绍。然而，Flask 有一些潜在非常有用的部分，我们在我们的三个项目中都不需要。我们将在这里简要概述这些部分。

## VirtualEnv

第一个值得一提的库实际上并不是特定于 Flask 的，如果你之前在 Python 开发上花了一些时间，你几乎肯定会遇到它。`VirtualEnv`是一个 Python 库，它在你的机器上创建一个虚拟的 Python 环境。它可以与 Flask 一起在你的开发机器上使用，也可以在你的开发机器和服务器上同时使用。它的主要目的是将你的整个 Python 环境隔离成一个虚拟的环境，包括你使用的所有 Python 模块。这有两个主要的好处。第一个是有时你需要在同一台机器上运行两个不同的 Python 项目，但每个项目需要不同版本的相同库。使用`VirtualEnv`，每个项目都会有自己的虚拟化的 Python 设置，因此安装两个不同版本的相同库变得微不足道。第二个优势是你的环境变得更加可移植，理论上，很容易将在`VirtualEnv`环境中运行的应用程序迁移到另一台安装了`VirtualEnv`的机器上。

`VirtualEnv`环境在 Python 开发中被广泛使用，特别是在 Flask 中。我决定不将其包含在书的主体部分中，这一决定在审阅者中引起了很大的争议，其中许多人认为没有包含它的书是不完整的。我决定不包括它有两个原因。第一个原因是，当我学习 Flask 时，我阅读了许多教程和示例，其中包括了 VirtualEnv。我总是觉得为设置和解释`VirtualEnv`和虚拟环境所需的额外工作会分散教程的主要内容（即使用 Flask）。第二个原因是，即使在我今天构建的 Flask 项目中，我仍然经常不使用它。如果你不运行依赖于特定库的特定版本的旧软件，那么在系统范围内安装有用的 Python 库，以便它们可以被所有的 Python 应用程序使用，是很方便的。此外，有时，VirtualEnv 可能只是一项任务，而没有提供任何价值。

当然，你可能已经对 VirtualEnv 有自己的看法，如果是这样，你可以随意使用它。没有什么能阻止任何人在`VirtualEnv`环境中构建本书中的任何项目，如果他们有一点经验的话。如果你以前没有使用过，那么值得一试。你可以通过 pip 安装它并尝试一下，看看它到底是做什么的，以及它是否在你的特定场景中有用。你可以在这里阅读更多关于它以及如何使用它的信息：

[`docs.python-guide.org/en/latest/dev/virtualenvs/`](http://docs.python-guide.org/en/latest/dev/virtualenvs/)

## Flask Blueprints

也许我们在本书中没有提到的 Flask 最大的特性是 Flask 蓝图。在构建了三个 Flask 应用程序之后，您一定会注意到一些模式一次又一次地出现。重复的代码是糟糕的代码，即使在多个不同的应用程序中；如果您找到了更好的方法来做某事，或者需要对更新进行一些更改，您不希望在几个应用程序中进行相同的更改。

蓝图提供了一种指定 Flask 应用程序模式的方法。如果您有几个应用程序使用相同的代码来返回模板或连接到数据库，您可以将这些通用代码写在一个蓝图中，然后让所有应用程序注册该蓝图。

您可以在[`flask.pocoo.org/docs/0.10/blueprints/`](http://flask.pocoo.org/docs/0.10/blueprints/)了解更多关于 Flask 蓝图的信息，查看示例，并学习如何开始使用它们。

## Flask 扩展

在我们的三个项目过程中，我们看了很多不同的 Flask 扩展。但是，由于本书的教育重点，我们选择从头开始编写一些代码，可能更适合使用现有的扩展。（通常在开发时，我们希望避免重复造轮子。如果其他人已经考虑解决问题并提供了一个经过深思熟虑和良好维护的解决方案，最好使用他们的成果，而不是试图创建我们自己的。）特别感兴趣的是我们可以使用的扩展，使我们的用户帐户系统更简单更强大，以及那些为我们提供更抽象的方式与数据库交互的扩展。

### Flask-SQLAlchemy

本书中另一个有争议的决定是不介绍 Flask-SQLAlchemy 扩展与 MySQL 一起使用。SQLAlchemy 提供了一个 SQL 工具包和 ORM，使从 Python 环境与 SQL 数据库交互更容易和更安全。ORM 提供了另一层抽象，使 Web 应用程序与数据库之间的交互更加简单。与其直接编写 SQL 代码，不如使用 Python 对象调用数据库，然后 ORM 将其转换为 SQL。这样可以更轻松地编写和维护数据库，也更安全（ORM 通常非常擅长减轻潜在的 SQL 注入漏洞）。省略它的原因与省略 VirtualEnv 的原因类似——在学习时，太多的抽象层可能会带来更多的伤害，而且在盲目使用工具之前，首先亲身体验工具解决的问题总是有利的。

对于任何使用 MySQL 数据库的 Flask 应用程序，比如我们的犯罪地图项目，强烈建议使用 ORM，就像大多数 Flask 扩展一样。Flask-SQLAlchemy 只是一个现有的非 Flask 特定库的包装器。您可以在[`www.sqlalchemy.org/`](http://www.sqlalchemy.org/)找到更多关于 SQLAlchemy 的信息，以及关于 Flask-SQLAlchemy 的全面指南，包括常见的使用模式：

[`flask.pocoo.org/docs/0.10/patterns/sqlalchemy/`](http://flask.pocoo.org/docs/0.10/patterns/sqlalchemy/)

### Flask MongoDB 扩展

有几个 Flask 扩展旨在使与 MongoDB 的交互更容易。由于 MongoDB 相对较新，这些扩展都没有达到 SQLAlchemy 的成熟度，也没有被广泛使用；因此，如果您打算使用其中之一，建议您检查每个以决定哪一个最适合您的需求。

#### Flask-MongoAlchemy

也许最类似于 SQLAlchemy（不仅仅是名称）的是 Flask-MongoAlchemy。与 SQLAlchemy 类似，MongoAlchemy 也不是 Flask 特定的。您可以在[`www.mongoalchemy.org`](http://www.mongoalchemy.org)找到有关主项目的更多信息。Flask-MongoAlchemy 是 MongoAlchemy 的 Flask 包装器，您可以在这里找到更多信息：

[`pythonhosted.org/Flask-MongoAlchemy`](http://pythonhosted.org/Flask-MongoAlchemy)

#### Flask-PyMongo

一个更薄的 MongoDB 包装器，更接近于直接使用 PyMongo，就像我们在第三个项目中所做的那样，是 Flask-PyMongo。与 MongoAlchemy 不同，它不提供 ORM 等效；相反，它只是提供了一种通过 PyMongo 连接到 MongoDB 的方式，使用的语法更符合 Flask 通常处理外部资源的方式。您可以在其 GitHub 页面上快速了解 Flask-PyMongo：

[`github.com/dcrosta/flask-pymongo`](https://github.com/dcrosta/flask-pymongo)

### Flask-MongoEngine

使用 Flask 与 MongoDB 结合的另一个解决方案是 MongoEngine ([`mongoengine.org`](http://mongoengine.org))。这很显著，因为它与 WTForms 和 Flask-Security 集成，我们将在接下来的部分中讨论。您可以在[`pypi.python.org/pypi/flask-mongoengine`](https://pypi.python.org/pypi/flask-mongoengine)上了解有关 Mongo Engine 的 Flask 特定扩展的更多信息。

### Flask-Mail

如果我们想要实现自动发送电子邮件的解决方案，比如本章前面描述的那样，一个有用的扩展是 Flask-Mail。这允许您轻松地从 Flask 应用程序发送电子邮件，同时处理附件和批量邮寄。正如之前提到的，如今，考虑使用亚马逊的 SES 等第三方服务来发送电子邮件而不是自己发送是值得的。您可以在[`pythonhosted.org/Flask-Mail`](http://pythonhosted.org/Flask-Mail)上了解更多关于 Flask-Mail 的信息。

### Flask-Security

我们将讨论的最后一个扩展是 Flask-Security。这个扩展很显著，因为它的很大一部分实际上是通过组合其他 Flask 扩展构建的。在某种程度上，它偏离了 Flask 的哲学，即尽可能少地做事情，以便有用，并允许用户完全自由地进行自定义实现。它假设您正在使用我们描述的数据库框架之一，并从 Flask-Login、WTForms、Flask-Mail 和其他扩展中汇集功能，试图使构建用户帐户控制系统尽可能简单。如果我们使用这个，我们将有一个集中处理注册帐户、登录帐户、加密密码和发送电子邮件的方式，而不是必须分别实现登录系统的每个部分。您可以在这里了解更多关于 Flask-Security 的信息：

[`pythonhosted.org/Flask-Security`](https://pythonhosted.org/Flask-Security)

### 其他 Flask 扩展

有许多 Flask 扩展，我们只强调了我们认为在许多 Web 开发场景中通常适用的扩展。当然，当您开发一个独特的 Web 应用程序时，您将有更具体的需求，很可能已经有人有类似的需求并创建了解决方案。您可以在这里找到一个广泛的（但不完整）Flask 扩展列表：

[`flask.pocoo.org/extensions`](http://flask.pocoo.org/extensions)

# 扩展您的 Web 开发知识

在本书中，我们专注于后端开发——通过 Python 或 Flask 完成。开发 Web 应用程序的一个重要部分是构建一个功能强大、美观、直观的前端。虽然我们提供了 HTML、CSS 和 JavaScript 的坚实基础，但每个主题都足够大，可以有自己的书籍，而且有许多这样的书籍存在。

JavaScript 可能是这三种语言中最重要的。它被称为“Web 的语言”，在过去几年中稳步增长（尽管像所有语言一样，它也有其批评者）。有许多用于构建 JavaScript 密集型 Web 应用程序的框架（事实上，它们的数量之多以及新框架的发布频率已经成为开发人员之间的笑柄）。我们在本书中介绍了 Bootstrap，其中包括基本的 JavaScript 组件，但对于更加交互式的应用程序，存在着更大的框架。其中三个较受欢迎的前端框架包括 AngularJS（由 Google 开发）、React.js（由 Facebook 开发）和 Ember.js（由包括 Yahoo 在内的多家公司赞助）。学习其中任何一个框架或其他许多框架中的一个都将帮助您构建更大更复杂的 Web 应用程序，具有更丰富的前端。

JavaScript 也不再局限于前端，许多现代 Web 应用程序也使用 JavaScript 在服务器端构建。实现这一点的常见方法是通过 Node.js，在我们构建的任何项目中，它完全可以取代 Python 和 Flask。

HTML5 和 CSS3 比它们演变而来的旧技术强大得多。以前，HTML 用于内容，CSS 用于样式，JavaScript 用于操作，分工明确。现在，这三种技术的能力之间有了更多的重叠，一些令人印象深刻的交互式应用程序是仅使用 HTML5 和 CSS3 构建的，而没有通常的 JavaScript 补充。

# 总结

在这个附录中，我们展望未来，指出了一些关键领域和资源，这些将帮助您超越本书中详细介绍的内容。我们在三个主题中涵盖了这些领域：本书中我们所做的项目、我们没有使用的 Flask 资源以及 Web 开发的一般情况。

这就是结尾。然而，技术世界如此广阔，发展如此迅速，希望这更像是一个开始而不是结束。在您继续冒险，了解更多关于生活、Python 和 Web 开发的知识时，我希望本书中提出的一些想法能够留在您心中。
