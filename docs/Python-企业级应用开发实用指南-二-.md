# Python 企业级应用开发实用指南（二）

> 原文：[`zh.annas-archive.org/md5/B119EED158BCF8E2AB5D3F487D794BB2`](https://zh.annas-archive.org/md5/B119EED158BCF8E2AB5D3F487D794BB2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：示例 - 构建 BugZot

在过去的几章中，我们已经讨论了许多构建企业级应用程序的技术。但是，如果我们不知道在哪里应用这些知识，那么这些知识有什么用呢？

在本章的过程中，我们将学习构建一个企业级 Web 应用程序的过程，该应用程序将用于跟踪 Omega 公司销售的各种产品的各种利益相关者报告的错误。从现在开始，我们将称之为**BugZot**的系统旨在提供此功能。

该应用程序将使用各种概念构建系统，以便在用户与系统交互的数量增加时能够轻松扩展。我们将看到如何利用各种优化的数据访问和存储技术、高度可扩展的部署和缓存技术来构建一个性能良好的应用程序，即使在高负载情况下也能表现良好。

在本章的过程中，我们将学习以下内容：

+   利用现有的 Web 框架构建企业级 Web 应用程序

+   实现优化数据库访问以加快应用程序速度

+   实施缓存技术以减少应用程序后端的负载

+   利用多线程技术增加应用程序的并发性

+   以可扩展的方式部署应用程序以供生产使用

# 技术要求

本书中的代码清单可以在[`github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python`](https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python)的`chapter06`目录下找到。

可以通过运行以下命令克隆代码示例：

```py
git clone https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python
```

本章旨在构建一个可扩展的错误跟踪 Web 应用程序。为了实现这一目标，我们使用了许多现有的库和工具，这些库和工具是公开可用的，并经过了长时间的测试，以适应各种用例。构建和运行演示应用程序需要以下一组工具：

+   PostgreSQL 9.6 或更高版本

+   Python 3.6 或更高版本

+   Flask—Python 中的 Web 开发微框架...

# 定义需求

构建任何企业级应用程序的第一步是定义应用程序的目标。到目前为止，我们知道我们的应用程序将跟踪 Omega 公司销售的各种产品的错误。但是，我们的应用程序需要什么功能来进行错误跟踪呢？让我们来看一看，并尝试定义我们将要构建的应用程序的需求。

+   **支持多个产品**：我们的错误跟踪系统的一个基本要求是支持组织构建的多个产品的错误跟踪。考虑到组织的未来增长，这也是一个必需的功能。

+   **支持产品的多个组件**：虽然我们可以在产品级别上报告错误，但这将会太笨重，特别是考虑到大多数组织都有一个专门负责产品正交特性的团队。为了更容易地跟踪基于已提交的组件的错误，错误跟踪系统应支持基于组件的错误报告。

+   **附件支持**：很多时候，提交错误的用户，或者在错误生命周期中以任何方式参与的用户，可能希望附加显示错误效果的图像，或者可能希望附加错误的补丁，以便在合并到产品之前进行测试。这将需要错误跟踪系统提供支持，以将文件附加到错误报告中。

+   **支持评论**：一旦提交了 bug，负责解决该 bug 的用户可能需要有关该 bug 的其他信息，或者可能需要一些协作。这使得缺陷跟踪系统必须支持评论成为必须。此外，并非每条评论都可以公开。例如，如果开发人员可能已经附加到 bug 报告中以供原始提交者测试但尚未纳入主产品的补丁，开发人员可能希望保持补丁私有，以便只有特权访问的人才能看到。这也使得私人评论的功能的包含成为必要。

+   **支持多个用户角色**：组织中并非每个人对缺陷跟踪系统都具有相同级别的访问权限。例如，只有主管级别的人才能向产品添加新组件，只有员工才能看到 bug 的私人评论。这要求系统包含基于角色的访问权限作为要求。

这些是我们的缺陷跟踪系统特定的一些要求。然而，由于这些，显然还有一些其他要求需要包含在系统中。其中一些要求是：

+   **用户认证系统的要求**：系统应该提供一种根据一些简单机制对用户进行认证的机制。例如，用户应该能够通过提供他们的用户名和密码，或者电子邮件和密码组合来登录系统。

+   **用于提交新 bug 的 Web 界面**：应用程序应该提供一个简单易用的 Web 界面，用户可以用来提交新的 bug。

+   **支持 bug 生命周期**：一旦 bug 被提交到系统中，它的生命周期就从 NEW 状态开始。从那里，它可能转移到 ASSIGNED 状态，当组织中的某人接手验证和重现 bug 时。从那里，bug 可以进入各种状态。这被称为我们跟踪系统内的 bug 生命周期。我们的缺陷跟踪系统应该支持这种生命周期，并且应该如何处理当 bug 从一个状态转移到另一个状态。

因此，我们终于把我们的需求摆在了这里。当我们开始设计和定义我们的缺陷跟踪网络应用程序的构建方式时，这些需求将发挥重要作用。因此，有了需求，现在是时候开始定义我们的代码基础是什么样子了。

# 进入开发阶段

随着我们的项目结构定义并就位，现在是时候站起来开始开发我们的应用程序了。开发阶段涉及各种步骤，包括设置开发环境，开发模型，创建与模型相对应的视图，并设置服务器。

# 建立开发环境

在我们开始开发之前的第一步是建立我们的开发环境。这涉及到准备好所需的软件包，并设置环境。

# 建立数据库

我们的 Web 应用程序在管理与用户和已提交的 bug 相关的个人记录方面严重依赖数据库。对于演示应用程序，我们将选择 PostgreSQL 作为我们的数据库。要在基于 RPM 的发行版上安装它，例如 Fedora，需要执行以下命令：

```py
dnf install postgresql postgresql-server postgresql-devel
```

要在 Linux 的任何其他发行版或 Windows 或 Mac OS 等其他操作系统上安装`postgresql`，需要执行分发/操作系统的必需命令。

一旦我们安装了数据库，下一步就是初始化数据库，以便它可以用来存储我们的应用程序数据。用于设置...

# 建立虚拟环境

现在数据库已经就位，让我们设置虚拟环境，这将用于应用程序开发的目的。为了设置虚拟环境，让我们运行以下命令：

```py
virtualenv –python=python3 
```

这个命令将在我们当前的目录中设置一个虚拟环境。设置虚拟环境之后的下一步是安装应用程序开发所需的框架和其他包。

然而，在继续安装所需的包之前，让我们首先通过执行以下命令激活我们的虚拟环境：

```py
source bin/activate
```

作为一个设计决策，我们将基于 Python Flask 微框架进行 Web 应用程序开发。这个框架是一个开源框架，已经存在了相当多年，并且得到了各种插件的支持，这些插件可以很容易地与框架一起安装。该框架也是一个非常轻量级的框架，它只带有最基本的预打包模块，因此允许更小的占用空间。要安装`flask`，执行以下命令：

```py
pip install flask
```

一旦我们安装了 Flask，让我们继续设置我们将在 Web 应用程序开发中使用的其他一些必需的包，通过执行以下命令：

```py
pip install flask-sqlalchemy requests pytest flask-session
```

有了这个，我们现在已经完成了虚拟环境的设置。现在，让我们继续设置我们的代码库将是什么样子。

# 构建我们的项目

现在，我们处于一个需要决定我们的项目结构将是什么样子的阶段。项目结构非常重要，因为它决定了我们代码中不同组件之间的交互方式，以及什么地方将标志着我们应用程序的入口点。

一个结构良好的项目不仅有助于为项目提供更好的导航，而且还有助于提供代码不同部分之间的增强一致性。

所以，让我们来看看我们的代码结构将是什么样子，并理解特定目录或文件的意义：

```py
$ tree --dirsfirst├── bugzot│   ├── helpers│   │   └── __init__.py│   ├── models│   │   └── __init__.py│   ├── static│ ├── templates ...
```

# 初始化 Flask 项目

所以，我们终于进入了项目的有趣阶段，我们将从头开始构建这个项目。所以，让我们不要等太久，我们就可以看到一些行动。我们要做的第一件事是使用 Flask 设置一个基本项目并让它运行起来。为了做到这一点，让我们启动我们的代码编辑器并设置我们的初始代码库。

让我们打开文件`bugzot/application.py`并初始化我们的应用程序代码库：

```py
'''
File: application.py
Description: The file contains the application initialization
             logic that is used to serve the application.
'''
from flask import Flask, session
from flask_bcrypt import Bcrypt
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy

# Initialize our Flask application
app = Flask(__name__, instance_relative_config=True)

# Let's read the configuration
app.config.from_object('config')
app.config.from_pyfile('config.py')

# Let's setup the database
db = SQLAlchemy(app)

# Initializing the security configuration
bcrypt = Bcrypt(app)

# We will require sessions to store user activity across the application
Session(app)
```

现在我们已经完成了应用程序的非常基本的设置。让我们花一些时间来理解我们在这里做了什么。

在文件的开头，我们首先导入了我们将要构建项目的所需包。我们从`flask`包中导入`Flask`应用程序类。类似地，我们导入了代码哈希库`bcrypt`，`Flask`会话类，以及用于 Flask 的 SQLAlchemy 支持包，它提供了与 Flask 的 SQLAlchemy 集成。

一旦我们导入了所有必需的包，下一步就是初始化我们的 Flask 应用程序。为此，我们创建一个`Flask`类的实例，并将其存储在一个名为`app`的对象中。

```py
app = Flask(__name__, instance_relative_config=True)
```

在创建这个实例时，我们向类构造函数传递了两个参数。第一个参数用于表示 Flask 的应用程序名称。`__name__`提供了我们传递给构造函数的应用程序名称。第二个参数`instance_relative_config`允许我们从实例文件夹中覆盖应用程序配置。

有了这个，我们的 Flask 应用程序实例设置就完成了。接下来要做的是加载应用程序的配置，这将用于配置应用程序内部不同组件的行为，以及我们的应用程序将如何提供给用户。为了做到这一点，我们需要从配置文件中读取。以下两行实现了这一点：

```py
app.config.from_object('config')
app.config.from_pyfile('config.py')
```

第一行加载了我们项目根目录下的`config.py`文件，将其视为一个对象，并加载了它的配置。第二行负责读取实例目录下的`config.py`文件，并加载可能存在的任何配置。

一旦这些配置加载完成，它们就可以在`app.config`对象下使用。大多数 Flask 插件都配置为从`app.config`读取配置，因此减少了可能发生的混乱，如果每个插件都有不同的配置处理机制。

在我们的应用程序中加载配置后，我们现在可以继续初始化我们可能需要的其余模块。特别是，我们需要一些额外的模块来建立我们的应用程序功能。这些模块包括 SQLAlchemy 引擎，我们将使用它来构建和与我们的数据库模型交互，一个会话模块，它将被用来管理应用程序中的用户会话，以及一个`bcrypt`模块，它将被用来在整个应用程序中提供加密支持。以下代码提供了这些功能：

```py
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
Session(app)
```

从这些代码行中可以看出，要配置这些模块，我们所需要做的就是将 Flask 应用程序对象作为参数传递给各自的类构造函数，它们的配置将从那里自动获取。

现在，我们已经将应用程序初始化代码放在了适当的位置，我们需要做的下一件事是从我们的 BugZot 模块中导出所需的组件，以便可以从项目根目录调用应用程序。

为了实现这一点，我们需要做的就是将这些模块包含在模块入口点中。所以，让我们打开代码编辑器，打开`bugzot/__init__.py`，我们需要在那里获取这些对象。

```py
'''
File: __init__.py
Description: Bugzot application entrypoint file.
'''
from .application import app, bcrypt, db
```

好了，我们完成了。我们已经在 BugZot 模块中导出了所有必需的对象。现在，问题是如何启动我们的应用程序。因此，为了启动我们的应用程序并使其提供传入的请求，我们需要完成一些更多的步骤。所以，让我们打开项目根目录下的`run.py`文件，并添加以下行：

```py
'''
File: run.py
Description: Bugzot application execution point.
'''
from bugzot import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

好了，是不是很简单？我们在这里所做的就是导入我们在 BugZot 模块中创建的`flask`应用对象，并调用`app`对象的`run`方法，将应用程序将要提供给用户的`hostname`值和应用程序服务器应该绑定以监听请求的端口值传递给它。

我们现在已经准备好启动我们的应用程序服务器，并使其监听传入的请求。但是，在我们这样做之前，我们只需要完成一个步骤，即创建应用程序的配置。所以，让我们开始并创建配置。

# 创建配置

在我们启动应用程序之前，我们需要配置我们将在应用程序中使用的模块。因此，让我们首先打开代码编辑器中的`config.py`，并向其中添加以下内容，以创建我们应用程序的全局配置：

```py
'''File: config.pyDescription: Global configuration for Bugzot project'''DEBUG = FalseSECRET_KEY = 'your_application_secret_key'BCRYPT_LOG_ROUNDS = 5 # Increase this value as required for your applicationSQLALCHEMY_DATABASE_URI = "sqlite:///bugzot.db"SQLALCHEMY_ECHO = FalseSESSION_TYPE = 'filesystem'STATIC_PATH = 'bugzot/static'TEMPLATES_PATH = 'bugzot/templates'
```

有了这些，我们已经起草了全局应用程序配置。让我们尝试...

# 开发数据库模型

数据库模型构成了任何现实生活应用程序的重要部分。这是因为企业中的任何严肃应用程序肯定会处理需要在时间跨度内持久化的某种数据。

对于我们的 BugZot 也是一样的。BugZot 用于跟踪 Omega Corporation 产品中遇到的错误及其生命周期。此外，应用程序还需要记录在其上注册的用户。为了实现这一点，我们将需要多个模型，每个模型都有自己的用途。

为了开发这个应用程序，我们将所有相关的模型分组到它们自己的单独目录下，这样我们就可以清楚地知道每个模型的作用是什么。这也让我们能够保持代码库的整洁，避免开发人员在未来难以理解每个文件的作用。

因此，让我们首先开始开发管理用户账户相关信息所需的模型。

为了开始开发与用户账户相关的模型，我们首先创建一个名为`users`的目录，放在我们的模型目录下：

```py
mkdir bugzot/models/users
```

然后将其初始化为模型模块的子模块。

一旦我们完成了这一点，我们就可以开始创建我们的用户模型，其定义如下所示：

```py
'''
File: users.py
Description: The file contains the definition for the user data model
             that will be used to store the information related to the
             user accounts.
'''
from bugzot.application import db
from .roles import Role

class User(db.Model):
    """User data model for storing user account information.

    The model is responsible for storing the account information on a
    per user basis and providing access to it for authentication
    purposes.
    """

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, index=True, nullable=False)
    password = db.Column(db.String(512), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    user_role = db.Column(db.Integer, db.ForeignKey(Role.id))
    role = db.relationship("Role", lazy=False)
    joining_date = db.Column(db.DateTime, nullable=False)
    last_login = db.Column(db.DateTime, nullable=False)
    account_status= db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        """User model representation."""
        return "<User {}>".format(self.username)
```

有了这个，我们刚刚创建了我们的用户模型，可以用来存储与用户相关的信息。大多数列只是提供了我们期望存储在数据库中的数据的定义。然而，这里有一些有趣的地方，让我们来看看：

```py
index=True
```

我们可以看到这个属性在用户名和电子邮件列的定义中被提及。我们将索引属性设置为 True，因为这两列经常被用来访问与特定用户相关的数据，因此可以从索引带来的优化中受益。

这里的下一个有趣的信息是与角色模型的关系映射。

```py
role = db.relationship("Role", lazy=False)
```

由于我们数据库中的每个用户都有一个与之关联的角色，我们可以从我们的用户模型到角色模型添加一个一对一的关系映射。此外，如果我们仔细看，我们设置了`lazy=False`。我们之所以要避免懒加载，有一个小原因。角色模型通常很小，而且用户模型到角色模型只有一个一对一的映射。通过避免懒加载，我们节省了一些时间，因为我们的数据库访问层不再懒加载来自角色模型的数据。现在，问题是，角色模型在哪里？

角色模型的定义可以在`bugzot/models/users/roles.py`文件中找到，但我们明确地没有在书中提供该定义，以保持章节简洁。

此外，我们需要一种机制来验证用户的电子邮件地址。我们可以通过发送包含激活链接的小邮件给用户来实现这一点，他们需要点击该链接。为此，我们还需要为每个新用户生成并存储一个激活密钥。为此，我们利用了一个名为`ActivationKey`模型的新模型，其定义可以在`bugzot/models/users/activation_key.py`文件中找到。

一旦所有这些都完成了，我们现在可以准备将这些模型从用户模型子模块中导出。为了做到这一点，让我们打开代码编辑器中的模块入口文件，并通过向`bugzot/models/users/__init__.py`文件添加以下行来导出模型：

```py
from .activation_key import ActivationKey
from .roles import Role
from .users import User
```

有了这个，我们完成了与存储用户信息相关的数据模型的定义。

我们应用程序中的下一件事是定义与产品分类相关的数据模型，用于对可以提交 bug 的产品进行分类。因此，让我们开始创建与产品分类相关的模型。

为了创建与产品相关的模型，我们首先在`bugzot/models`模块下创建一个新的子模块目录并进行初始化。接下来，我们在`bugzot/models/products/products.py`下提供产品模型的定义，如下所示：

```py
'''
File: products.py
Description: The file contains the definition for the products
             that are supported for bug filing inside the bug tracker
'''
from bugzot.application import db
from .categories import Category

class Product(db.Model):
    """Product defintion model.

    The model is used to store the information related to the products
    for which the users can file a bug.
    """

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    product_name = db.Column(db.String(100), nullable=False, unique=True, index=True)
    category_id = db.Column(db.Integer, db.ForeignKey(Category.id))
    category = db.relationship("Category", lazy=True)

    def __repr__(self):
        """Product model representation."""
        return "<Product {}>".format(self.product_name)
```

有了这个，我们已经完成了产品模型的定义，该模型将用于跟踪产品，用户可以在我们的应用程序中提交 bug。

在我们的产品子模块中还有一些其他模型定义，如下所示：

+   **类别**：类别模型负责存储关于特定产品所属的产品类别的信息

+   **组件**：组件模型负责存储与产品组件相关的信息，其中一个错误可以被归类

+   **版本**：版本模型负责存储与产品版本相关的信息，其中一个错误可以被分类

一旦所有这些模型被定义，它们就可以从产品的子模块中导出，以便在应用程序中使用。

以类似的方式，我们定义了与系统内错误跟踪相关的模型。我们将跳过在本章节中提及这些模型的定义，以保持章节长度合理，但是，对于好奇的人来说，这些模型的定义可以很容易地在代码库中的`bugzot/models/bugs`目录中找到。

# 迁移数据库模型

有了我们创建的数据库模型并准备好使用，下一步是将这些数据库模型迁移到我们用来运行应用程序的数据库服务器。这个过程非常简单。

要将模型迁移到数据库服务器，我们首先将它们暴露到应用程序根目录中。例如，要迁移与用户和产品相关的数据库模型，我们只需要在`bugzot/__init__.py`文件中添加以下行：

```py
from bugzot.models import ActivationKey, Category, Component, Product, Role, User, Version
```

完成后，我们只需要调用我们创建的 SQLAlchemy 数据库对象的`create_all()`方法。这可以通过添加以下...来完成

# 构建视图

一旦模型生成并准备就绪，我们需要的下一步是拥有一种机制，通过该机制我们可以与这些模型进行交互，以便访问或修改它们。我们可以通过视图的使用来实现这种功能的一种方式。

使用 Flask，构建视图是相当容易的任务。Flask Web 框架提供了多种构建视图的方法。事实上，`/ping`端点也可以被称为使用过程式风格构建的视图之一。

在示例过程中，我们现在将尝试在定义应用程序中的任何资源时遵循面向对象的方法。因此，让我们继续并开始开发一些视图。

# 开发索引视图

每当用户访问我们的应用程序时，很可能用户会登陆到应用程序的主页上。因此，我们首先构建的是索引视图。这也是我们可以了解如何在 Flask 中构建简单视图的地方之一。

因此，作为第一步，让我们通过执行以下命令在项目工作空间的视图目录中创建一个新模块，用于索引模块：

```py
mkdir bugzot/views/indextouch bugzot/views/index/__init__.py
```

有了这个，我们现在准备编写我们的第一个视图，其代码如下：

```py
'''File: index.pyDescription: The file provides the definition for the index view             which is used to render the homepage of Bugzot.'''from bugzot.application ...
```

# 获取索引视图以渲染

现在，我们已经准备好了索引视图。但是，在此视图可以提供给用户之前，我们需要为 Flask 提供有关此视图将被渲染的端点的映射。为了实现这一点，让我们打开我们的代码编辑器并打开`bugzot/__init__.py`文件，并向文件中添加以下行：

```py
from bugzot.views import IndexView
app.add_url_rule('/', view_func=IndexView.as_view('index_view'))
```

在这里，我们的重点是第二行，它负责将我们的视图与 URL 端点进行映射。我们的 Flask 应用程序的`add_url_rule()`负责提供这些映射。该方法的第一个参数是视图应该在其上呈现的 URL 路径。提供给该方法的`view_func`参数接受需要在提供的 URL 端点上呈现的视图。 

完成后，我们现在准备好提供我们的索引页面。现在我们只需要运行以下命令：

```py
python run.py
```

然后在浏览器上访问[`localhost:8000/`](http://localhost:8000/)。

# 构建用户注册视图

现在，部署并准备好使用的索引视图，让我们继续构建一个更复杂的视图，在这个视图中，我们允许用户在 BugZot 上注册。

以下代码实现了一个名为`UserRegisterView`的视图，允许用户注册到 BugZot。

```py
'''File: user_registration.pyDescription: The file contains the definition for the user registration             view allowing new users to register to the BugZot.'''from bugzot.application import app, brcypt, dbfrom bugzot.models import User, Rolefrom flask.views import MethodViewfrom datetime import datetimefrom flask import render_template, sessionclass UserRegistrationView(MethodView):    """User registration view to allow new user registration. The user ...
```

# 部署以处理并发访问

到目前为止，我们处于开发阶段，可以轻松使用 Flask 自带的开发服务器快速测试我们的更改。但是，如果您计划在生产环境中运行应用程序，这个开发服务器并不是一个好选择，我们需要更专门的东西。这是因为在生产环境中，我们将更关注应用程序的并发性，以及其安全方面，比如启用 SSL 并为一些端点提供更受限制的访问。

因此，我们需要根据我们的应用需要处理大量并发访问的事实，同时不断保持对用户的良好响应时间，来确定一些选择。

考虑到这一点，我们最终得到了以下一系列选择，它们的性质在许多生产环境中也是相当常见的：

+   **应用服务器**：Gunicorn

+   **反向代理**：Nginx

在这里，Gunicorn 将负责处理由我们的 Flask 应用程序提供的请求，而 Nginx 负责请求排队和处理静态资产的分发。

那么，首先，让我们设置 Gunicorn 以及我们将如何通过它提供应用程序。

# 设置 Gunicorn

设置 Gunicorn 的第一步是安装，这是一个相当简单的任务。我们只需要运行以下命令：

```py
pip install gunicorn
```

一旦完成了这一步，我们就可以运行 Gunicorn 了。Gunicorn 通过**WSGI**运行应用程序，WSGI 代表 Web 服务器网关接口。为了让 Gunicorn 运行我们的应用程序，我们需要在项目工作空间中创建一个名为`wsgi.py`的额外文件，内容如下：

```py
'''File: wsgi.pyDescription: WSGI interface file to run the application through WSGI interface'''from bugzot import appif __name__ == '__main__':    app.run()
```

一旦我们定义了接口文件，我们只需要运行以下命令来使 Gunicorn...

# 设置 Nginx 作为反向代理

要将 Nginx 用作我们的反向代理解决方案，我们首先需要在系统上安装它。对于基于 Fedora 的发行版，可以通过使用`dnf`或`yum`软件包管理器轻松安装，只需运行以下命令：

```py
$ sudo dnf install nginx
```

对于其他发行版，可以使用它们的软件包管理器来安装 Nginx 软件包。

安装 Nginx 软件包后，我们现在需要进行配置，以使其能够与我们的应用服务器进行通信。

要配置 Nginx 将通信代理到我们的应用服务器，创建一个名为`bugzot.conf`的文件，放在`/etc/nginx/conf.d`目录下，内容如下：

```py
server {
    listen 80;
    server_name <your_domain> www.<your_domain>;

    location / {
        include proxy_params;
        proxy_pass http://unix:<path_to_project_folder>/bugzot.sock;
    }
}
```

现在 Nginx 配置完成后，我们需要建立我们的 Gunicorn 应用服务器和 Ngnix 之间的关系。所以，让我们来做吧。

# 建立 Nginx 和 Gunicorn 之间的通信

在我们刚刚完成的 Nginx 配置中需要注意的一点是`proxy_pass`行：

```py
proxy_pass http://unix:<path_to_project_folder>/bugzot.sock
```

这行告诉 Nginx 查找一个套接字文件，通过它 Nginx 可以与应用服务器通信。我们可以告诉 Gunicorn 为我们创建这个代理文件。执行以下命令即可完成：

```py
gunicorn –bind unix:bugzot.sock -m 007 wsgi:app
```

执行此命令后，我们的 Gunicorn Web 服务器将创建一个 Unix 套接字并绑定到它。现在，剩下的就是启动我们的 Nginx Web 服务器，只需执行以下命令即可轻松实现：

```py
systemctl start nginx.service
```

一旦完成了这一步，...

# 总结

在本章中，我们获得了如何开发和托管企业级网络应用程序的实际经验。为了实现这一目标，我们首先做出了一些关于要使用哪些网络框架和数据库的技术决策。然后，我们继续定义我们的项目结构以及它在磁盘上的外观。主要目标是实现高度模块化和代码之间的耦合度较低。一旦项目结构被定义，我们就初始化了一个简单的 Flask 应用程序，并实现了一个路由来检查我们的服务器是否正常工作。然后，我们继续定义我们的模型和视图。一旦这些被定义，我们就修改了我们的应用程序，以启用提供对我们视图的访问的新路由。一旦我们的应用程序开发周期结束，我们就开始了解如何使用 Gunicorn 和 Nginx 部署应用程序以处理大量请求。

现在，当我们进入下一章时，我们将看看如何开发优化的前端，以适应我们正在开发的应用程序，并且前端如何影响用户与我们的应用程序交互时的体验。

# 问题

+   Flask 提供了哪些其他预构建的视图类？

+   我们能否在不删除关系的情况下从用户表中删除到角色表的外键约束？

+   除了 Gunicorn 之外，还有哪些用于提供应用程序的其他选项？

+   我们如何增加 Gunicorn 工作进程的数量？


# 第七章：构建优化的前端

在本书中，我们已经在尝试了解如何在 Python 中为企业构建应用程序时走得很远。到目前为止，我们已经涵盖了如何为我们的企业应用程序构建一个可扩展和响应迅速的后端，以满足大量并发用户，以便我们的企业应用程序能够成功地为其用户提供服务。然而，在构建企业级应用程序时，有一个我们一直忽视的话题，通常在构建企业级应用程序时很少受到关注：应用程序的前端。

当用户与我们的应用程序交互时，他们很少关心后端发生了什么。用户的体验直接与应用程序的前端如何响应他们的输入相关。这使得应用程序的前端不仅是应用程序最重要的方面之一，也使其成为应用程序在用户中成功的主要决定因素之一。

在本章中，我们将看看如何构建应用程序前端，不仅提供易于使用的体验，还能快速响应他们的输入。

在阅读本章时，我们将学习以下主题：

+   优化应用前端的需求

+   优化前端所依赖的资源

+   利用客户端缓存来简化页面加载

+   利用 Web 存储持久化用户数据

# 技术要求

本书中的代码清单可以在`chapter06`中的`bugzot`应用程序目录下找到[`github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python`](https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python)。

可以通过运行以下命令克隆代码示例：

```py
git clone https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python
```

代码的执行不需要任何特定的特殊工具或框架，这是一个非常简单的过程。`README.md`文件指向了如何运行本章的代码示例。

# 优化前端的需求

应用的用户界面是最重要的用户界面组件之一。它决定了用户如何感知应用程序。一个流畅的前端在定义用户体验方面起着很大的作用。

这种对流畅用户体验的需求带来了优化应用前端的需求，它提供了一个易于使用的界面，快速的响应时间和操作的流畅性。如果我们继续向 Web 2.0 公司（如 Google、Facebook、LinkedIn 等）看齐，他们会花费大量资源来优化他们的前端，以减少几毫秒的渲染时间。这就是优化前端的重要性。

# 优化前端的组件

我们正在讨论优化前端。但是优化的前端包括什么？我们如何决定一个前端是否被优化了？让我们来看一下。

优化的前端有几个组件，不是每个组件都需要从前端反映出来。这些组件如下：

+   **快速渲染时间**：前端优化的首要重点之一是减少页面的渲染时间。虽然没有预定义的渲染时间可以被认为是好还是坏，但你可以认为一个好的渲染时间是用户在一个体面的互联网连接上不必等待太长时间页面加载的时间。另外，...

# 导致前端问题的原因

前端问题是一类问题，用户很容易察觉到，因为它们影响用户与应用程序的交互方式。在这里，为了清楚起见，当我们说企业 Web 应用的前端时，我们不仅谈论其用户界面，还谈论代码和模板，这些都是用来呈现所需用户界面的。现在，让我们继续了解前端特定问题的可能原因：

+   **过多的对象**：在大多数负责呈现前端的动态填充模板中，第一个问题出现在呈现过多对象时。当大量对象传递给需要呈现的模板时，页面响应时间往往会增加，导致过程明显减慢。

+   **过多的包含**：软件工程中关注的一个主要问题是如何增加代码库的模块化。模块化的增加有助于增加组件的可重用性。然而，过度的模块化可能是可能出现重大问题的信号。当前端模板被模块化到超出所需程度时，模板的呈现性能会降低。原因在于每个包含都需要从磁盘加载一个新文件，这是一个异常缓慢的操作。这里的一个反驳观点可能是，一旦模板加载了所有包含的内容，呈现引擎就可以缓存模板，并从缓存中提供后续请求。然而，大多数缓存引擎对它们可以缓存的包含深度有一个限制，超出这个限制，性能损失将是明显的。

+   **不必要的资源集**：一些前端可能加载了大量不在特定页面上使用的资源。这包括包含仅在少数页面上执行的函数的 JavaScript 文件。每个额外加载的文件不仅增加了带宽的消耗，还影响了前端的加载性能。

+   **强制串行加载代码**：现代大多数浏览器都经过优化，可以并行加载大量资源，以有效利用网络带宽并减少页面加载时间。然而，有时，我们用来减少代码量的一些技巧可能会强制页面按顺序加载，而不是并行加载。可能导致页面资源按顺序加载的最常见示例之一是使用 CSS 导入。尽管 CSS 导入提供了直接在另一个样式表中加载第三方 CSS 文件的灵活性，但它也减少了浏览器加载 CSS 文件内容的能力，因此增加了呈现页面所需的时间。

这一系列原因构成了可能导致页面呈现时间减慢的问题的非穷尽列表，因此给用户带来不愉快的体验。

现在，让我们看看如何优化我们的前端，使其具有响应性，并提供最佳的用户体验。

# 优化前端

到目前为止，我们了解了可能影响前端性能的各种问题。现在，是时候看看我们如何减少前端的性能影响，并使它们在企业级环境中快速响应。

# 优化资源

我们首先要看的优化是在请求特定页面时加载的资源。为此，请考虑管理面板中用户数据显示页面的以下代码片段，该页面负责显示数据库中的用户表：

```py
<table>
{% for user in users %}
  <tr>
    <td class="user-data-column">{{ user.username }}</td>
    <td class="user-data-column">{{ user.email }}</td>
    <td class="user-data-column">{{ user.status }}</td>
  </tr>
{% endfor %}
</table>
```

到目前为止，一切顺利。正如我们所看到的，代码片段只是循环遍历用户对象，并根据用户表中存储的记录数量来渲染表格。这对于大多数情况下用户记录只有少量（例如 100 条左右）的情况来说是很好的。但随着应用程序中用户数量的增长，这段代码将开始出现问题。想象一下尝试从应用程序数据库中加载 100 万条记录并在 UI 上显示它们。这会带来一些问题：

+   **数据库查询缓慢：**尝试同时从数据库加载 100 万条记录将会非常缓慢，并且可能需要相当长的时间，因此会阻塞视图很长时间。

+   **解码前端对象：**在前端，为了渲染页面，模板引擎必须解码所有对象的数据，以便能够在页面上显示数据。这种操作不仅消耗 CPU，而且速度慢。

+   **页面大小过大：**想象一下从服务器到客户端通过网络传输数百万条记录的页面。这个过程耗时且使页面不适合在慢速连接上加载。

那么，我们可以在这里做些什么呢？答案很简单：让我们优化将要加载的资源量。为了实现这一点，我们将利用一种称为分页的概念。

为了实现分页，我们需要对负责渲染前端模板的视图以及前端模板进行一些更改。以下代码描述了如果视图需要支持分页，它将会是什么样子：

```py
From bugzot.application import app, db
from bugzot.models import User
from flask.views import MethodView
from flask import render_template, session, request

class UserListView(MethodView):
    """User list view for displaying user data in admin panel.

      The user list view is responsible for rendering the table of users that are registered
      in the application.
    """

    def get(self):
        """HTTP GET handler."""

        page = request.args.get('next_page', 1) # get the page number to be displayed
        users = User.query.paginate(page, 20, False)
        total_records = users.total
        user_records = users.items

        return render_template('admin/user_list.html', users=user_records, next_page=page+1)
```

我们现在已经完成了对视图的修改，它现在支持分页。通过使用 SQLAlchemy 提供的设施，实现这种分页是一项相当容易的任务，使用`paginate()`方法从数据库表中分页结果。这个`paginate()`方法需要三个参数，即页面编号（应从 1 开始），每页记录数，以及`error_out`，它负责设置该方法的错误报告。在这里设置为`False`会禁用在`stdout`上显示错误。

开发支持分页的视图后，下一步是定义模板，以便它可以利用分页。以下代码显示了修改后的模板代码，以利用分页：

```py
<table>
{% for user in users %}
  <tr>
    <td class="user-data-column">{{ user.username }}</td>
    <td class="user-data-column">{{ user.email }}</td>
    <td class="user-data-column">{{ user.status }}</td>
  </tr>
{% endfor %}
</table>
<a href="{{ url_for('admin_user_list', next_page) }}">Next Page</a>

```

有了这个视图代码，我们的视图代码已经准备好了。这个视图代码非常简单，因为我们只是通过添加一个`href`来扩展之前的模板，该`href`加载下一页的数据。

现在我们已经优化了发送到页面的资源，接下来我们需要关注的是如何使我们的前端更快地加载更多资源。

# 通过避免 CSS 导入并行获取 CSS

CSS 是任何前端的重要组成部分，它帮助为浏览器提供样式信息，告诉浏览器如何对从服务器接收到的页面进行样式设置。通常，前端可能会有许多与之关联的 CSS 文件。我们可以通过使这些 CSS 文件并行获取来实现一些可能的优化。

所以，让我们想象一下我们有以下一组 CSS 文件，即`main.css`、`reset.css`、`responsive.css`和`grid.css`，我们的前端需要加载。我们允许浏览器并行加载所有这些文件的方式是通过使用 HTML 链接标签将它们链接到前端，而不是使用 CSS 导入，这会导致加载 CSS 文件...

# 打包 JavaScript

在当前时间和希望的未来，我们将不断看到网络带宽的增加，无论是宽带网络还是移动网络，都可以实现资源的并行更快下载。但是对于每个需要从远程服务器获取的资源，由于每个单独的资源都需要向服务器发出单独的请求，仍然涉及一些网络延迟。当需要加载大量资源并且用户在高延迟网络上时，这种延迟可能会影响。

通常，大多数现代 Web 应用程序广泛利用 JavaScript 来实现各种目的，包括输入验证、动态生成内容等。所有这些功能都分成多个文件，其中可能包括一些库、自定义代码等。虽然将所有这些拆分成不同的文件可以帮助并行加载，但有时 JavaScript 文件包含用于在网页上生成动态内容的代码，这可能会阻止网页的呈现，直到成功加载网页呈现所需的所有必要文件。

我们可以减少浏览器加载这些脚本资源所需的时间的一种可能的方法是将它们全部捆绑到一个单一文件中。这允许所有脚本组合成一个单一的大文件，浏览器可以在一个请求中获取。虽然这可能会导致用户在首次访问网站时体验有点慢，但一旦资源被获取和缓存，用户对网页的后续加载将会显著更快。

今天，有很多第三方库可用，可以让我们捆绑这些 JavaScript。让我们以一个名为 Browserify 的简单工具为例，它允许我们捆绑我们的 JavaScript 文件。例如，如果我们有多个 JavaScript 文件，如`jquery.js`、`image-loader.js`、`slideshow.js`和`input-validator.js`，并且我们想要使用 Browserify 将这些文件捆绑在一起，我们只需要运行以下命令：

```py
browserify jquery.js image-loader.js slideshow.js input-validator.js > bundle.js
```

这个命令将把这些 JavaScript 文件创建成一个称为`bundle.js`的公共文件包，现在可以通过简单的脚本标签包含在我们的 Web 应用程序中，如下所示：

```py
<script type="text/javascript" src="js/bundle.js"></script>
```

将 JavaScript 捆绑到一个请求中加载，我们可能会开始看到一些改进，以便页面在浏览器中快速获取和显示给用户。现在，让我们来看看另一个可能有用的有趣主题，它可能会在网站重复访问时对我们的 Web 应用程序加载速度产生真正的影响。

我们讨论的 JavaScript 捆绑技术也可以用于包含 CSS 文件的优化。

# 利用客户端缓存

缓存长期以来一直被用来加快频繁使用的资源的加载速度。例如，大多数现代操作系统利用缓存来提供对最常用应用程序的更快访问。Web 浏览器也利用缓存，在用户再次访问同一网站时，提供对资源的更快访问。这样做是为了避免如果文件没有更改就一遍又一遍地从远程服务器获取它们，从而减少可能需要的数据传输量，同时提高页面的呈现时间。

现在，在企业应用程序的世界中，像客户端缓存这样的东西可能会非常有用。这是因为...

# 设置应用程序范围的缓存控制

由于我们的应用程序基于 Flask，我们可以利用几种简单的机制来为我们的应用程序设置缓存控制。例如，将以下代码添加到我们的`bugzot/application.py`文件的末尾可以启用站点范围的缓存控制，如下所示：

```py
@app.after_request
def cache_control(response):
  """Implement side wide cache control."""
  response.cache_control.max_age = 300
  response.cache_control.public = True
  return response
```

在这个例子中，我们利用 Flask 内置的`after_request`装饰器钩子来设置 HTTP 响应头，一旦请求到达 Flask 应用程序，装饰的函数需要一个参数，该参数接收一个响应类的对象，并返回一个修改后的响应对象。

对于我们的用例，在`after_request`钩子的方法代码中，我们设置了`cache_control.max_age`头，该头指定了内容在再次从服务器获取之前从缓存中提供的时间的上限，以及`cache_control.public`头，该头定义了缓存响应是否可以与多个请求共享。

现在，可能会有时候我们想为特定类型的请求设置不同的缓存控制。例如，我们可能不希望为用户个人资料页面设置`cache_control.public`，以避免向不同的用户显示相同的个人资料数据。我们的应用程序允许我们相当快速地实现这些类型的场景。让我们来看一下。

# 设置请求级别的缓存控制

在 Flask 中，我们可以在将响应发送回客户端之前修改响应头。这可以相当容易地完成。以下示例显示了一个实现响应特定头控制的简单视图：

```py
from bugzot.application import app, dbfrom bugzot.models import Userfrom flask.views import MethodViewfrom flask import render_template, session, request, make_responseclass UserListView(MethodView):  """User list view for displaying user data in admin panel.  The user list view is responsible for rendering the table of users that are registered  in the application.  """  def get(self):    """HTTP GET handler."""        page = request.args.get('next_page', 1) # get the page number to be displayed users = User.query.paginate(page, ...
```

# 利用 Web 存储

任何曾经处理过即使是一点点用户管理的应用程序的 Web 应用程序开发人员肯定都听说过 Web cookies，它本质上提供了一种在客户端存储一些信息的机制。

利用 cookies 提供了一种简单的方式，通过它我们可以在客户端维护小量用户数据，并且可以多次读取，直到 cookies 过期。但是，尽管处理 cookies 很容易，但有一些限制限制了 cookies 的实用性，除了在客户端维护少量应用程序状态之外。其中一些限制如下：

+   cookies 随每个请求传输，因此增加了每个请求传输的数据量

+   Cookies 允许存储少量数据，最大限制为 4 KB

现在，出现的问题是，如果我们想存储更多的数据，或者我们想避免在每个请求中一遍又一遍地获取相同的存储数据，我们该怎么办？

为了处理这种情况，HTML 的最新版本 HTML 5 提供了各种功能，允许处理客户端 Web 存储。这种 Web 存储相对于基于 cookies 的机制提供了许多优点，例如：

+   由于 Web 存储直接在客户端上可用，因此不需要服务器一遍又一遍地将信息发送到客户端

+   Web 存储 API 提供了最多 10 MB 的存储空间，这是比使用 cookies 存储的多次更大的存储空间

+   Web 存储提供了在本地存储中存储数据的灵活性，例如，即使用户关闭并重新打开浏览器，数据也是可访问的，或者基于每个会话的基础上存储数据，其中存储在 Web 存储中的数据将在会话失效时被清除，无论是当用户会话被应用程序处理用户注销的处理程序销毁，还是浏览器关闭

这使得 Web 存储成为一个吸引人的地方，可以存放数据，避免一遍又一遍地加载

对于我们的企业应用程序，这可以通过仅在用户浏览器中存储中间步骤的结果，然后仅在填写完所有必需的输入字段时将它们提交回服务器，从而提供很大的灵活性。

另一个可能更适用于 Bugzot 的用例是，我们可以将用户提交的错误报告存储到 Web 存储中，并在完成错误报告时将其发送到服务器。在这种情况下，用户可以灵活地随时回到处理其错误报告，而不必担心再次从头开始。

现在我们知道了 Web 存储提供的好处，让我们看看如何利用 Web 存储的使用。

# 使用本地 Web 存储

使用 HTML 5 的本地 Web 存储非常容易，因为它提供了许多 API 来与 Web 存储交互。因此，让我们不浪费时间，看一下我们如何使用本地 Web 存储的一个简单例子。为此，我们将创建一个名为`localstore.js`的简单 JavaScript 文件，内容如下：

```py
// check if the localStorage is supported by the browser or notif(localStorage) {  // Put some contents inside the local storagelocalStorage.setItem("username", "joe_henry");  localStorage.setItem("uid", "28372");    // Retrieve some contents from the local storage  var user_email = localStorage.getItem("user_email");} else {  alert("The browser does not support local web storage");}
```

这是...

# 使用会话存储

使用本地存储同样简单，会话存储也不会增加任何复杂性。例如，让我们看看将我们的`localStorage`示例轻松转换为`sessionStorage`有多容易：

```py
// check if the sessionStorage is supported by the browser or not
if(sessionStorage) {
  // Put some contents inside the local storage
sessionStorage.setItem("username", "joe_henry");
  sessionStorage.setItem("uid", "28372");

  // Retrieve some contents from the session storage
  var user_email = sessionStorage.getItem("user_email");
} else {
  alert("The browser does not support session web storage");
}
```

从这个例子可以明显看出，从本地存储转移到会话存储非常容易，因为这两种存储选项都提供了类似的存储 API，唯一的区别在于存储中的数据保留时间有多长。

通过了解如何优化前端以提供完全可扩展和响应的企业 Web 应用程序，现在是时候我们访问一些确保我们构建的内容安全并符合预期的企业应用程序开发方面的内容，而不会带来意外惊喜。

# 摘要

在本章的过程中，我们了解了为企业应用程序拥有优化的前端的重要性，以及前端如何影响我们在企业内部使用应用程序。然后，我们继续了解通常会影响 Web 前端性能的问题类型，以及我们可以采取哪些可能的解决方案来改进应用程序前端。这包括减少前端加载的资源量，允许 CSS 并行加载，捆绑 JavaScript 等。然后，我们继续了解缓存如何在考虑企业 Web 应用程序的使用情况下证明是有用的。一旦我们了解了缓存的概念，我们就进入了领域...

# 问题

1.  CDN 的使用如何提高前端性能？

1.  我们能做些什么让浏览器利用现有的连接从服务器加载资源吗？

1.  我们如何从 Web 存储中删除特定键或清除 Web 存储的内容？


# 第八章：编写可测试的代码

通过本章，我们已经进入了本书的第二部分，涵盖了使用 Python 开发企业级应用程序的过程。而本书的第一部分侧重于如何构建具有可扩展性和性能的企业级应用程序，本书的第二部分侧重于应用程序的内部开发方面，例如我们如何确保我们的应用程序是安全的，它的性能如何，以及如何在生产阶段进行更高质量的检查，以最大程度地减少意外行为的发生。

在本章中，我们想要把您的注意力集中在企业应用程序开发或者说...

# 技术要求

本书中的代码清单可以在[`github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python`](https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python)的`chapter08`目录下找到。

与第六章中开发的 bugzot 应用程序相关的代码示例可以在`chapter06`目录下找到。

可以通过运行以下命令来克隆代码示例：

```py
git clone https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python
```

这包括了关于如何运行代码的说明。除此之外，本章还需要安装一个 Python 库，它可以简化我们的测试代码编写。可以通过运行以下命令来安装该库和所有相关依赖项：

```py
pip install -r requirements.txt
```

# 测试的重要性

作为开发人员，我们通常致力于解决具有挑战性的问题，试图穿越复杂的连接，并提出解决方案。但是我们有多少次关心过我们的代码可能失败以提供预期的结果的所有可能方式？尽管我们作为开发人员自己编写的东西很难去尝试破坏，但它构成了开发周期中最重要的方面之一。

这是测试成为开发生命周期中重要方面的时候。应用程序测试的目标可以通过回答以下问题来总结：

+   代码中的个别组件是否按预期执行？

+   代码的流程是否从...

# 不同种类的测试

当重点是交付质量应用程序时，无论是为一般客户还是企业，都需要执行多种测试。这些测试技术可能从应用程序开发生命周期的不同阶段开始，因此被相应地分类。

在本节中，我们不是专注于一些可以归为黑盒测试和白盒测试的测试方法，而是更加专注于理解与开发人员相关的术语。所以，让我们来看一下。

# 单元测试

当我们开始构建应用程序时，我们将应用程序划分为多个子模块。这些子模块包含了许多相互交互的类或方法，以实现特定的输出。

为了生成正确的输出，所有个别类和方法都需要正常工作，否则结果将有所不同。

现在，当我们的目标是检查代码库中个别组件的正确性时，我们通常编写针对这些个别组件的测试，独立于应用程序的其他组件。这种测试，其中一个个别组件独立于其他组件进行测试，被称为**单元测试**。

简而言之，以下是一些...

# 集成测试

一个应用程序不仅仅是在所有单独的组件都编写完成后就完成了。为了产生任何有意义的输出，这些单独的组件需要根据提供的输入类型以不同的方式相互交互。为了完全检查应用程序代码库，组成应用程序的组件不仅需要在隔离状态下进行测试，而且在它们相互交互时也需要进行测试。

集成测试是在应用程序经过单元测试阶段后开始的。在集成测试中，通过接口使单个组件相互交互，然后测试这种交互是否符合预期的结果。

在集成测试阶段，不仅测试应用程序组件之间的交互，还测试组件与任何其他外部服务（如第三方 API 和数据库）之间的交互。

简而言之，以下是一些集成测试的特点：

+   **专注于测试接口：**由于应用程序的不同组件通过组件提供的接口相互交互，集成测试的作用是验证这些接口是否按预期工作。

+   **通常在单元测试之后开始：**一旦组件通过了单元测试，它们就会被集成在一起相互连接，然后进行集成测试

+   **代码流测试：**与单元测试相反，单元测试通常侧重于从一个组件到另一个组件的数据流，因此还检查代码流的结果

正如我们所看到的，集成测试是应用测试过程的重要组成部分，其目的是验证应用程序的不同组件是否能够正确地相互交互。

一旦集成测试完成，测试过程的下一个阶段是进行系统测试，然后是最终的验收测试阶段。以下图片显示了从单元测试阶段到验收测试阶段的测试流程以及在应用程序开发过程中可能发生的不同类型的测试。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-etp-app-dev-py/img/41db4532-20e4-4094-9b2e-70b3b66500e8.png)

为了控制本书的长度，我们将跳过对这两种测试技术的解释，而是将本章的其余部分专注于实施一些实际的单元测试。

在本章的其余部分，我们将专注于单元测试实践以及如何在我们的演示应用程序中实现它们。

# 以测试为导向构建应用程序

因此，我们现在知道测试很重要，也了解了不同类型的测试。但是在构建应用程序时，我们需要做一些重要的事情，以便能够正确地测试它吗？

对这个问题的答案有点复杂。虽然我们可以轻松地按照任何我们想要的特定方式编写代码，并通过多种程序进行测试，例如单元测试，但最好还是遵循一般的一套指南，以便能够轻松高效地测试代码。因此，让我们继续看一下这些指南：

+   每个组件都应该有一个责任：为了测试的高效性和覆盖率...

# 测试驱动开发

测试驱动开发是一种软件开发过程，其中软件开发的过程首先涉及为单个需求编写测试，然后构建或改进能够通过这些测试的方法。这种过程通常有利于生成具有比在组件开发后编写测试时更少缺陷的应用程序。

在测试驱动开发过程中，遵循以下步骤：

1.  添加一个测试：一旦需求被指定，开发人员就会开始为先前组件的改进或新组件编写新的测试。这个测试设置了特定组件的预期结果。

1.  运行测试以查看新测试是否失败：当新测试被添加后，对代码运行测试，以查看新测试是否因预期原因而失败。这可以确保测试按预期工作，并且在不利条件下不会通过。

1.  编写/修改组件：一旦测试运行并且可以看到预期结果，我们就会继续编写新组件或修改现有组件，以使新添加的测试用例通过。

1.  运行测试：一旦对测试进行了必要的修改以使测试通过，就会再次运行测试套件，以查看之前失败的测试现在是否通过。这可以确保修改按预期工作。

1.  重构：随着应用程序开发生命周期的进展，会有时候会出现重复的测试或者可能承担相同责任的组件。为了消除这些问题，需要不断进行重构以减少重复。

现在，我们已经对测试在任何成功应用程序的开发中扮演重要角色有了相当的了解，也知道如何编写易于测试的代码。现在，是时候开始为我们在第六章中构建的应用程序编写一些测试了。

# 编写单元测试

因此，现在是时候开始编写我们的单元测试了。Python 库为我们提供了许多编写测试的选项，而且非常容易。我们通常会被选择所困扰。该库本身提供了一个单元测试模块，可用于编写单元测试，而且我们可以使用各种框架来更轻松地编写单元测试。

因此，让我们首先看一下如何使用 Python 的`unittest`模块编写一些简单的单元测试，然后我们将继续使用著名的 Python 测试框架为我们的应用程序编写单元测试。

# 使用 Python unittest 编写单元测试

Python 3 提供了一个非常好的、功能齐全的库，允许我们为应用程序编写单元测试。这个名为`unittest`的库用于编写单元测试，可以从非常简单的测试的复杂性到在运行单元测试之前进行适当设置的非常复杂的测试。

Python `unittest`库支持的一些功能包括：

+   面向对象：该库以面向对象的方式简化了单元测试的编写。这意味着，通过类和方法以面向对象的形式编写对象。这绝不意味着只有面向对象的代码才能使用该库进行测试。该库支持测试面向对象和非面向对象的代码。

+   测试夹具的能力：一些测试可能需要在运行测试之前以某种方式设置环境，并在测试完成执行后进行适当的清理。这称为测试夹具，Python 的`unittest`库完全支持这一特性。

+   **能够编写测试套件：**该库提供了编写完整功能的测试套件的功能，由多个测试用例组成。测试套件的结果被汇总并一次性显示。

+   **内置测试运行器：**测试运行器用于编排测试并编译执行测试的结果以生成报告。该库提供了一个内置的测试运行器来实现这个功能。

现在，让我们看一下以下代码，我们将使用它来编写我们的单元测试：

```py
import hashlib
import secrets

def strip_password(password):
    """Strip the trailing and leading whitespace.

    Returns:
        String
    """
    return password.strip()

def generate_salt(num_bytes=8):
    """Generate a new salt

    Keyword arguments:
    num_bytes -- Number of bytes of random salt to generate

    Returns:
        Bytes
    """

    return secrets.token_bytes(num_bytes)

def encrypt_password(password, salt):
    """Encrypt a provided password and return a hash.

    Keyword arguments:
    password -- The plaintext password to be encrypted
    salt -- The salt to be used for padding

    Returns:
        String
    """

    passwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 10000).hex()
    return passwd_hash
```

在这段代码中，我们定义了一些函数，旨在帮助我们生成可以安全存储在数据库中的密码哈希。

现在，我们的目标是利用 Python 的`unittest`库为前面的代码编写一些单元测试。

以下代码旨在为密码助手模块实现一小组单元测试：

```py
from helpers import strip_password, encrypt_password
import unittest

class TestPasswordHelpers(unittest.TestCase):
    """Unit tests for Password helpers."""

    def test_strip_password(self):
        """Test the strip password function."""

        self.assertEqual(strip_password(' saurabh '), 'saurabh')

    def test_encrypt_password(self):
        """Test the encrypt password function."""

        salt = b'\xf6\xb6(\xa1\xe8\x99r\xe5\xf6\xa5Q\xa9\xd5\xc1\xad\x08'
        encrypted_password = '2ba31a39ccd2fb7225d6b1ee564a6380713aa94625e275e59900ebb5e7b844f9'

        self.assertEqual(encrypt_password('saurabh', salt), encrypted_password)

if __name__ == '__main__':
    unittest.main()
```

我们创建了一个简单的文件来运行我们的单元测试。现在，让我们看看这个文件做了什么。

首先，我们从所需模块中导入我们要测试的函数。在本例中，我们将从名为`helpers.py`的文件中导入这些函数。接下来的导入让我们获得了 Python 的 unittest 库。

一旦我们导入了所需的内容，下一步就是开始编写单元测试。为此，我们首先定义一个名为`TestPasswordHelpers`的类，它继承自`unittest.TestCase`类。该类用于定义我们可能想要执行的一组测试用例，如下所示：

```py
class TestPasswordHelpers(unittest.TestCase):
```

在类定义内部，我们继续为我们想要测试的方法定义单独的测试用例。定义测试用例的方法必须以单词`test`开头，以表明这个特定的方法是一个测试，并且需要由测试运行器执行。例如，负责测试我们的`strip_password`方法的方法被命名为`test_strip_password()`：

```py
def test_strip_password(self):
```

在方法定义内部，我们使用断言来验证特定方法的输出是否符合我们的预期。例如，`assertEqual`方法用于断言参数 1 是否与参数 2 匹配：

```py
self.assertEqual(strip_password(' saurabh '), 'saurabh')
```

一旦这些测试被定义，下一步就是定义一个入口点，用于在终端运行我们的测试文件。这是通过从入口点调用`unittest.main()`方法来完成的。一旦调用完成，文件中提到的测试用例将被运行，并显示输出，如下所示：

```py
python helpers_test.py
..
----------------------------------------------------------------------
Ran 2 tests in 0.020s

OK
```

当你想要用 Python 编写单元测试时，这是最简单的方法。现在，是时候转向更重要的事情了。让我们为我们的演示应用程序编写一些单元测试。

# 使用 pytest 编写单元测试

正如我们讨论的那样，在 Python 中编写单元测试可以利用我们手头的许多选项。例如，在前一节中，我们利用了 Python 的`unittest`库来编写我们的单元测试。在本节中，我们将继续使用`pytest`来编写单元测试，这是一个用于编写应用程序单元测试的框架。

但是，`pytest`提供了哪些好处，使我们应该转向它呢？为什么我们不能坚持使用 Python 捆绑的`unittest`库呢？

尽管`unittest`库为我们提供了许多灵活性和易用性，但`pytest`仍然带来了一些改进，让我们来看看这些改进是什么：

# 设置 pytest

`pytest`框架是一个独立的框架，作为标准化 Python 发行版之外的一个单独库。在我们开始使用`pytest`编写测试之前，我们需要安装`pytest`。安装`pytest`并不是一件大事，可以通过运行以下命令轻松完成：

```py
pip install pytest
```

现在，在我们开始为应用程序编写测试之前，让我们首先在应用程序目录下创建一个名为*tests*的新目录，并与`run.py`位于同一级别，以存储这些测试用例，通过运行以下命令来创建：

```py
mkdir -p bugzot/tests
```

现在，是时候用`pytest`编写我们的第一个测试了。

# 使用 pytest 编写我们的第一个测试

在我们的演示应用程序中，我们定义了一些模型，用于在数据库中存储数据。作为我们的第一个测试，让我们着手编写一个针对我们模型的测试用例。

以下代码片段显示了我们的`User`模型的简单测试用例：

```py
'''File: test_user_model.pyDescription: Tests the User database model'''import sysimport pytest# Setup the import path for our applicationsys.path.append('.') # Add the current rootdir as the module path# import our bugzot model we want to testfrom bugzot.models import User@pytest.fixture(scope='module')def create_user():  user = User(username='joe', email='joe@gmail.com', password='Hello123')  return userdef test_user_creation(create_user): assert create_user.email ...
```

# 使用 pytest 编写功能测试

`pytest`框架以及其独特的装置和`flask`的强大功能，使我们能够轻松地为我们的应用程序编写功能测试。这使我们能够相当轻松地测试我们构建的 API 端点。

让我们看一下我们的索引 API 端点的一个示例测试，然后我们将深入了解我们如何编写测试。

以下代码片段显示了使用`pytest`编写的简单测试用例，用于测试索引 API 端点：

```py
'''
File: test_index_route.py
Description: Test the index API endpoint
'''
import os
import pytest
import sys
import tempfile

sys.path.append('.')
import bugzot

@pytest.fixture(scope='module')
def test_client():
  db, bugzot.app.config['DATABASE'] = tempfile.mkstemp()
  bugzot.app.config['TESTING'] = True
  test_client = bugzot.app.test_client()

  with bugzot.app.app_context():
    bugzot.db.create_all()

  yield test_client

  os.close(db)
  os.unlink(bugzot.app.config['DATABASE'])

def test_index_route(test_client):
  resp = test_client.get('/')
  assert resp.status_code == 200
```

这是我们为测试我们的索引 API 路由编写的一个非常简单的功能测试，以查看它是否正常工作。现在，让我们看看我们在这里做了什么来使这个功能测试起作用：

前几行代码或多或少是通用的，我们导入了一些构建测试所需的库。

有趣的工作从我们构建的`test_client()`装置开始。这个装置用于为我们获取一个基于 flask 的测试客户端，我们可以用它来测试我们的应用程序端点，以查看它们是否正常工作。

由于我们的应用程序是一个面向数据库的应用程序，需要数据库才能正常运行，我们需要为应用程序设置数据库配置。为了测试目的，我们可以使用在大多数操作系统中都可以轻松创建的 SQLite3 数据库。以下调用为我们提供了我们将用于测试目的的数据库：

```py
db, bugzot.app.config['DATABASE'] = tempfile.mkstemp()
```

调用返回一个文件描述符到数据库和一个 URI，我们将其存储在应用程序配置中。

数据库创建完成后，下一步是告诉我们的应用程序它正在测试环境中运行，以便禁用应用程序内部的错误处理，以改善测试的输出。这很容易通过将应用程序配置中的`TESTING`标志设置为`True`来实现。

Flask 为我们提供了一个简单的测试客户端，我们可以使用它来运行应用程序测试。通过调用应用程序的`test_client()`方法可以获得此客户端，如下所示：

```py
test_client = bugzot.app.test_client()
```

一旦获得了测试客户端，我们需要设置应用程序上下文，这是通过调用 Flask 应用程序的`app_context()`方法来实现的。

建立应用程序上下文后，我们通过调用`db.create_all()`方法创建我们的数据库。

一旦我们设置好应用程序上下文并创建了数据库，接下来要做的是开始测试。这是通过产生测试客户端来实现的：

```py
yield test_client
```

完成后，测试现在执行，控制权转移到`test_index_route()`方法，我们只需尝试通过调用`test_client`的`get`方法加载索引路由，如下所示：

```py
resp = test_client.get('/')
```

完成后，我们通过检查响应的 HTTP 状态码并验证其是否为`200`来检查 API 是否提供了有效的响应，如下所示：

```py
assert resp.status_code == 200
```

一旦测试执行完成，控制权就会转移到测试装置，我们通过关闭数据库文件描述符和删除数据库文件来进行清理，如下所示：

```py
os.close(db)
os.unlink(bugzot.app.config['DATABASE'])
```

相当简单，不是吗？这就是我们如何使用`pytest`和`Flask`编写简单的功能测试。我们甚至可以编写处理用户身份验证和数据库修改的测试，但我们将把这留给您作为读者来练习。

# 总结

在本章中，我们看到测试如何成为应用开发项目中重要的一部分，以及为什么它是必要的。在这里，我们看了通常在开发生命周期中使用的不同类型的测试以及不同技术的用途。然后，我们继续看如何以一种使测试变得简单和有效的方式来编写我们的代码。接着，我们开始深入研究 Python 语言，看看它提供了哪些用于编写测试的工具。在这里，我们发现了如何使用 Python 的 unittest 库来编写单元测试，以及如何运行它们。然后，我们看了如何利用像 pytest 这样的测试框架来编写测试用例...

# 问题

1.  单元测试和功能测试之间有什么区别？

1.  我们如何使用 Python 的 unittest 编写单元测试套件？

1.  在 pytest 中，固定装置的作用是什么？

1.  在编写固定装置时，pytest 中的作用域是什么？


# 第九章：为性能分析应用程序

在本书的过程中，我们已经看到了应用程序的性能和可扩展性在企业环境中有多么重要；考虑到这一点，我们在本书的相当大部分内容中致力于理解如何构建一个不仅性能良好而且可扩展的应用程序。

到目前为止，我们只是看到了一些构建高性能和可扩展应用程序的最佳实践，但并不知道如何找出我们应用程序中特定代码的执行速度慢以及可能导致它的原因。

对于任何企业级应用程序，提高其性能和可扩展性是一个持续的过程，因为应用程序的用户群不断增长，应用程序的…

# 技术要求

本书中的代码清单可以在[`github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python`](https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python)的`chapter09`目录下找到。

与 bugzot 示例应用程序的性能分析和基准测试相关的代码示例可以在代码库的测试模块下的`chapter06`目录中找到。

可以通过运行以下命令克隆代码示例：

```py
git clone https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python
```

这一章还依赖于第三方 Python 库，可以通过在开发系统上运行以下命令轻松安装：

```py
pip install memory_profiler
```

# 性能瓶颈的幕后

在应用程序进入开发阶段之前，会对应用程序应该做什么、如何做以及应用程序需要与之交互的第三方组件的类型进行彻底讨论。一旦所有这些都确定下来，应用程序就进入了开发阶段，在这个阶段，开发人员负责以尽可能高效的方式构建应用程序，以便应用程序执行的任务可以以最有效的方式完成。这种效率通常是以应用程序完成提供的任务所需的时间和应用程序在执行该任务时使用的资源数量来衡量的。

当应用程序部署到生产环境时，…

# 查看性能瓶颈的原因

通常，性能瓶颈可能是由许多因素引起的，这些因素可能包括部署应用程序的环境中物理资源的短缺，或者在处理特定工作负载时选择了不好的算法，而实际上有更好的算法可用。让我们看看可能导致部署应用程序性能瓶颈的一些可能问题：

+   **没有足够的硬件资源：** 最初，性能和可扩展性的大部分瓶颈是由于对运行应用程序所需的硬件资源的规划不足。这可能是由于估计不正确或应用程序用户群突然不经意地激增。当这种情况发生时，现有的硬件资源会受到压力，系统会变慢。

+   **不正确的设计选择：** 在第二章中，*设计模式-做出选择*，我们看到了对于任何企业级应用程序来说，设计选择是多么重要。不断为某些事情分配新对象，而本可以通过分配一个共享对象来完成，这将影响应用程序的性能，不仅会给可用资源带来压力，还会因为重复分配对象而导致不必要的延迟。

+   **低效的算法：** 在处理大量数据或进行大量计算以生成结果的系统中，由于选择了低效的算法，性能可能会下降。仔细研究可用的替代算法或现场算法优化的可用性可能有助于提高应用程序的性能。

+   **内存泄漏：** 在大型应用程序中，可能会出现内存泄漏的地方。尽管在 Python 等垃圾收集语言中这很困难，但仍然有可能发生。有时候，尽管对象不再使用，但由于它们在应用程序中的映射方式，它们仍然没有被垃圾收集。随着运行时间的延长，这将导致可用内存减少，并最终使应用程序停止运行。

这些是系统中性能瓶颈发生的几个原因。对于我们作为软件开发人员来说，幸运的是，我们有许多工具可以帮助我们找出瓶颈，以及发现诸如内存泄漏之类的问题，甚至只是对个别部分的内存使用进行分析。

有了关于为什么会出现性能瓶颈的知识，现在是时候学习如何在应用程序中寻找这些性能瓶颈，然后尝试理解我们可以减少它们影响的一些方法了。

# 探测应用程序的性能问题

性能是任何企业级应用程序的关键组成部分，您不能容忍应用程序经常变慢并影响整个组织的业务流程。不幸的是，性能问题也是最难理解和调试的问题之一。这种复杂性是因为没有标准的方法来访问应用程序中特定代码片段的性能，而且一旦应用程序开发完成，就需要理解代码的完整流程，以便找出可能导致特定性能问题的可能区域。

作为开发人员，我们可以通过以这种方式构建应用程序来减少这些困难...

# 编写性能基准测试

让我们从讨论开始，讨论我们作为软件开发人员如何构建应用程序，以帮助我们在开发周期的早期阶段标记性能瓶颈，以及如何在调试这些瓶颈方面使我们的生活变得更加轻松。

在应用程序开发周期中，我们可以做的第一件最重要的事情是为应用程序的各个组件编写基准测试。

基准测试是简单的测试，旨在通过多次迭代执行代码并计算这些迭代中执行代码所需的时间的平均值来评估特定代码片段的性能。您还记得听说过一个名为 Pytest 的库吗？我们在第八章中用它来编写单元测试，*编写可测试的代码*吗？

我们将利用相同的库来帮助我们编写性能基准测试。但是，在我们可以让 Pytest 用于编写基准测试之前，我们需要让它理解基准测试的概念，这在 Python 中非常容易，特别是因为有一个庞大的 Python 生态系统可用。为了让 Pytest 理解基准测试的概念，我们将导入一个名为`pytest-benchmark`的新库，它为 Pytest 添加了基准测试固定装置，并允许我们为我们的应用程序编写基准测试。为此，我们需要运行以下命令：

```py
pip install pytest-benchmark
```

一旦我们安装了库，我们就可以为我们的应用程序编写性能基准测试了。

# 编写我们的第一个基准测试

安装所需的库后，现在是时候为我们的第一个性能基准测试编写了。为此，我们将使用一个简单的示例，然后继续了解如何为我们的应用程序编写基准测试：

```py
'''File: sample_benchmark_test.pyDescription: A simple benchmark test'''import pytestimport timedef sample_method():  time.sleep(0.0001)  return 0def test_sample_benchmark(benchmark):  result = benchmark(sample_method)  assert result == 0if __name__ == '__main__':  pytest.main()
```

我们已经编写了我们的第一个基准测试。确实是一个非常简单的测试，但有很多事情我们需要了解，以便看清我们在这里做什么：

首先，当我们开始编写基准测试时，我们导入...

# 编写 API 基准测试

有了这个，我们知道如何编写一个简单的基准测试。那么，我们如何为我们的 API 编写类似的东西呢？让我们看看如何修改我们用于验证索引 API 端点功能的 API 测试之一，并看看如何在其中运行基准测试。

以下代码修改了我们现有的索引 API 测试用例，包括 API 的基准测试：

```py
'''
File: test_index_benchmark.py
Description: Benchmark the index API endpoint
'''
import os
import pytest
import sys
import tempfile

sys.path.append('.')
import bugzot

@pytest.fixture(scope='module')
def test_client():
  db, bugzot.app.config['DATABASE'] = tempfile.mkstemp()
  bugzot.app.config['TESTING'] = True
  test_client = bugzot.app.test_client()

  with bugzot.app.app_context():
    bugzot.db.create_all()

  yield test_client

  os.close(db)
  os.unlink(bugzot.app.config['DATABASE'])

def test_index_benchmark(test_client, benchmark):
  resp = benchmark(test_client.get, "/")
  assert resp.status_code == 200
```

在上述代码中，我们只需添加一个名为`test_index_benchmark()`的新方法，它接受两个 fixture 作为参数。其中一个 fixture 负责设置我们的应用程序实例，第二个 fixture——基准 fixture——用于在客户端 API 端点上运行基准测试并生成结果。

另一个重要的事情要注意的是，我们如何能够将单元测试代码与基准测试代码混合在一起，这样我们就不需要为每个测试类编写两种不同的方法；所有这些都是由 Pytest 实现的，它允许我们在方法上运行基准测试，并允许我们通过单个测试方法验证被测试的方法是否提供了正确的结果。

现在我们知道如何在应用程序中编写基准测试。但是，如果我们需要调试某些慢的东西，但基准操作并没有引发任何关注，我们该怎么办呢？幸运的是，Python 提供了许多选项，允许我们测试代码内部可能发生的任何性能异常。因此，让我们花一些时间来了解它们。

# 进行组件级性能分析

使用 Python，许多设施都是内置的，其他设施可以很容易地使用第三方库实现。因此，让我们看看 Python 为我们提供了哪些用于运行组件级性能分析的功能。

# 使用 timeit 测量慢操作

Python 提供了一个非常好的模块，称为`timeit`，我们可以使用它来对代码的小片段运行一些简单的时间分析任务，或者了解特定方法调用所花费的时间。

让我们来看一个简单的脚本，向我们展示了如何使用`timeit`来了解特定方法所花费的时间，然后我们将更多地了解如何使用`timeit`提供的功能来运行我们打算构建的应用程序的时间分析。

以下代码片段展示了在方法调用上运行`timeit`进行时间分析的简单用法：

```py
import timeit

def calc_sum():
    sum = 0
    for i in range(0, 100):
        sum = sum + i
    return sum

if __name__ == '__main__':
    setup = "from __main__ import calc_sum"
    print(timeit.timeit("calc_sum()", setup=setup))
```

运行此文件后，我们得到的输出如下：

```py
7.255408144999819
```

正如我们从上面的示例中看到的，我们可以使用`timeit`来对给定方法的执行进行简单的时间分析。

现在，这很方便，但是当我们需要对多个方法进行计时时，我们不能一直编写多个设置语句。在这里我们该怎么办呢？应该有一种简单的方法来实现这一点。

那么，我们可以创建一个简单的装饰器，用于对可能需要时间分析的方法进行计时。

让我们创建这个简单的装饰器方法。以下示例向我们展示了如何编写一个装饰器方法，以便以后在我们的方法上进行时间比较：

```py
import time
def time_profile(func):
  """Decorator for timing the execution of a method."""
  def timer_func(*args, **kwargs):
    start = time.time()
    value = func(*args, **kwargs)
    end = time.time()
    total_time = end – start
    output_msg = "The method {func} took {total_time} to execute"
    print(output_msg.format(func=func, total_time=total_time))
    return value
  return timer_func
```

这是一个我们创建的装饰器。在装饰器内部，我们将要分析的函数作为参数传入，以及传递给它的任何参数。现在，我们初始化函数的开始时间，然后调用函数，然后在函数返回执行后存储调用的结束时间。基于此，我们计算函数执行所花费的总时间。

但是我们如何使用这个装饰器来分析我们的方法呢？以下示例展示了一个示例：

```py
@time_profile
def calc_sum():
    sum = 0
    for i in range(100):
        sum = sum+i
    return sum
```

这非常简单，比一遍又一遍地导入单个方法进行时间分析要容易得多。

因此，我们的`timeit`方法是一个非常简单的方法，可以为我们提供有关特定方法执行所花费的时间的一些基本信息。我们甚至可以使用这些方法对单个语句进行分析。但是，如果我们想要更详细地了解特定方法内部单个语句花费了多少时间，或者了解是什么导致了给定方法变慢，我们的简单计时解决方案就不是一个理想的选择。我们需要更复杂的东西。

事实上，Python 为我们提供了一些内置的分析器，我们可以使用它们来对应用程序进行深入的性能分析。让我们看看如何做到这一点。

# 使用 cProfile 进行分析

Python 库为我们提供了一个应用程序分析器，可以通过它轻松地对整个应用程序以及应用程序的各个组件进行分析，从而简化开发人员的工作。

Profile 是一个内置的代码分析器，作为一些 Python 发行版的模块捆绑在一起。该模块能够收集有关已进行的单个方法调用的信息，以及对第三方函数的任何调用进行分析。

一旦收集了这些细节，该模块将为我们提供大量统计信息，可以帮助我们更好地了解组件内部发生了什么。在我们深入了解收集和表示的细节之前，...

# 使用 memory_profiler 进行内存使用分析

内存分析是应用程序性能分析的一个非常重要的方面。在构建应用程序时，有些地方我们可能会实现处理动态分配对象的不正确机制，因此可能会陷入这样一种情况：这些不再使用的对象仍然有一个指向它们的引用，从而阻止了垃圾收集器对它们的回收。

这导致应用程序内存使用随时间增长，导致应用程序在系统耗尽可分配给应用程序执行其常规活动所需的内存时停止运行。

现在，为了解决这些问题，我们不需要一个能帮助我们分析应用程序调用堆栈并提供有关单个调用花费了多少时间的分析器。相反，我们需要的是一个能告诉我们应用程序的内存趋势的分析器，比如单个方法可能消耗多少内存，以及随着应用程序继续运行，内存如何增长。

这就是`memory_profiler`发挥作用的地方，它是一个第三方模块，我们可以轻松地将其包含在我们的应用程序中以进行内存分析。但是，在深入了解如何使用`memory_profiler`之前，我们需要先将该模块引入我们的开发环境。以下代码行将所需的模块引入我们的开发环境：

```py
pip install memory_profiler
```

一旦内存分析器被获取到开发环境中，我们现在可以开始使用它了。让我们看一个示例程序，并了解如何使用`memory_profiler`来了解我们应用程序的内存使用模式。

以下代码片段向我们展示了如何使用`memory_profiler`的示例：

```py
from memory_profiler import profile

@profile
def calc_sum():
    sum = 0
    for i in range(100):
        sum = sum + i
    print(str(sum))

if __name__ == '__main__':
    calc_sum()
```

现在，代码已经就位，让我们试着理解我们在这里做了什么。

首先，我们导入了一个名为 profile 的装饰器，它是由`memory_profiler`库提供的。这个装饰器用于通知`memory_profiler`需要对内存使用情况进行分析的方法。

要为方法启用内存分析，我们只需要使用装饰器装饰该方法。例如，在我们的示例应用程序代码中，我们使用装饰器装饰了`calc_sum()`方法。

现在，让我们运行我们的示例代码，并通过运行以下命令查看输出结果：

```py
python3 memory_profile_example.py
```

一旦执行了命令，我们会得到以下输出：

```py
4950
Filename: memory_profile.py

Line # Mem usage Increment Line Contents
================================================
     3 11.6 MiB 11.6 MiB @profile
     4 def calc_sum():
     5 11.6 MiB 0.0 MiB sum = 0
     6 11.6 MiB 0.0 MiB for i in range(100):
     7 11.6 MiB 0.0 MiB sum = sum + i
     8 11.6 MiB 0.0 MiB print(str(sum))
```

从上述输出中可以看出，我们得到了有关该方法的内存分配的详细统计信息。输出为我们提供了有关应用程序使用了多少内存以及每个步骤导致应用程序增加了多少内存的信息。

现在，让我们举一个例子，看看当一个方法调用另一个方法时内存分配如何改变。以下代码展示了这一点：

```py
from memory_profiler import profile

@profile
def calc_sum():
    sum = 0
    for i in range(100):
        sum = sum + i
    say_hello()
    print(str(sum))

def say_hello():
    lst = []
    for i in range(10000):
        lst.append(i)

if __name__ == '__main__':
    calc_sum()
```

执行上述代码后，我们得到以下输出：

```py
Line # Mem usage Increment Line Contents
================================================
     3 11.6 MiB 11.6 MiB @profile
     4 def calc_sum():
     5 11.6 MiB 0.0 MiB sum = 0
     6 11.6 MiB 0.0 MiB for i in range(100):
     7 11.6 MiB 0.0 MiB sum = sum + i
     8 11.7 MiB 0.1 MiB say_hello()
     9 11.7 MiB 0.0 MiB print(str(sum))
```

正如我们所看到的，当调用`say_hello()`方法时，调用导致内存使用量增加了 0.1 MB。如果我们怀疑代码中可能存在内存泄漏，这个库就非常方便。

# 收集实时性能数据

到目前为止，我们已经看到了在需要时如何使用不同的性能分析工具来分析应用程序的性能，以帮助我们找出代码的哪一部分导致了性能瓶颈。但是，我们如何知道一个操作是否花费的时间比应该花费的时间长？

其中一个答案可能是用户报告的响应时间慢，但这可能有很多因素，可能只涉及用户端的减速。

我们可以使用一些其他机制来实时监控应用程序的性能问题。因此，让我们看看其中一种方法，它允许我们收集有关单个操作所需时间的信息...

# 记录性能指标

在应用程序中，可能有几个步骤。可以通过使用不同的工具来分析每个步骤的性能。其中最基本的工具之一是日志记录。在这种情况下，我们收集不同方法的执行时间，并将其记录在日志文件中。

以下代码片段展示了如何在我们在第六章中构建的演示应用程序中实现这一点，*示例-构建 BugZot*：

```py
@app.before_request
def before_request_handler():
    g.start_time = time.time()

@app.teardown_request
def teardown_request_handler(exception=None):
    execution_time = time.time() - g.start_time
    app.logger.info("Request URL: {} took {} seconds".format(request.url, str(execution_time)))
```

这是一个简单的代码，记录了请求中调用的每个 API 端点的执行时间。我们在这里做的非常简单。我们首先创建一个`before_request`处理程序，在 flask 全局命名空间中初始化一个属性`start_time`。一旦完成这一步，请求就被发送到处理程序。一旦请求被处理，它就会进入我们定义的`teardown`处理程序。

一旦请求到达这个`teardown`处理程序，我们计算处理请求所需的总时间，并将其记录在应用程序日志中。

这种方法允许我们查询或处理我们的日志文件，了解每个请求所需的时间以及哪些 API 端点花费了最长的时间。

# 避免性能瓶颈

在过去的几个部分中，我们看了一下我们可以对应用程序进行性能分析的不同方式，以便解决可能导致性能下降或内存泄漏的性能瓶颈。但是一旦我们意识到这些问题以及它们发生的原因，我们还有哪些其他选项可以防止它们再次发生呢？

幸运的是，我们有一些有用的准则可以帮助防止性能瓶颈，或者可以限制这些瓶颈可能产生的影响。因此，让我们看看其中一些准则：

+   **选择正确的设计模式：**设计模式在应用程序中是一个重要的选择。例如，日志对象不需要在应用程序的每个子模块中重新初始化...

# 总结

在本章中，我们看到应用程序的性能是软件开发中的重要方面，通常会导致应用程序出现性能瓶颈的问题。接下来，我们看了一下我们可以对应用程序进行性能分析的不同方式。首先，这涉及编写单个组件以及单个 API 的基准测试，然后转向更具体的组件级分析，我们看了不同的组件分析方法。这些分析技术包括使用 Python 的`timeit`模块对方法进行简单的时间分析，然后我们转向使用更复杂的技术，使用 Python cProfile 并进行内存分析。在我们的旅程中，我们还看了一下使用日志技术来帮助我们评估慢请求的一些主题。最后，我们看了一些通用原则，可以帮助我们预防应用程序内的性能瓶颈。

在下一章中，我们将看一下保护应用程序的重要性。如果不这样做，不仅会为严重的数据窃取铺平道路，还会产生许多责任，并可能侵蚀用户的信任。

# 问题

1.  应用部署时可能导致性能瓶颈的因素有哪些？

1.  我们可以通过哪些不同的方式来对方法进行时间分析？

1.  什么可能导致 Python 中的内存泄漏，Python 是一种垃圾收集语言？

1.  我们如何对 API 响应进行分析，找出其减慢的原因？

1.  选择错误的设计模式会导致性能瓶颈吗？


# 第十章：保护您的应用程序

在关于应用程序性能和可扩展性的讨论中，以及确保应用程序在企业环境中稳定的最佳实践中，我们已经涵盖了很多内容。我们了解到用户体验对于使应用程序在企业内部成功非常重要。但是你认为我们在这里漏掉了什么吗？

假设我们拥有构建成功企业应用程序的所有组件，并且能够使其扩展，同时为用户提供符合预期行为的响应时间。然而，任何人都可以轻易访问我们应用程序的记录。如果存在漏洞允许用户在不进行登录的情况下从应用程序中获取敏感数据怎么办？是的，这就是缺失的环节：应用程序安全。在企业内部，应用程序的安全性是一个非常重要的因素。一个不安全的应用程序可能会向未预期的方面泄露敏感和机密数据，并且还可能给组织带来法律上的麻烦。

应用程序安全是一个大课题，即使是一本 500 页的书也可能不足以深入涵盖这个主题。但在本章的过程中，我们将快速介绍如何处理应用程序安全，让我们的用户在使用我们的应用程序时感到安全。

作为读者，在本章结束时，您将学到以下内容：

+   企业应用程序安全的重要性

+   用于突破应用程序安全的不同类型攻击向量

+   导致泄露的应用程序开发常见错误

+   确保您的应用程序安全

# 技术要求

对于本章，我们期望用户具有基本的配置 Web 服务器和网络通信基础知识。

# 企业应用程序安全

应用程序安全是一个如此重要的课题，您可能会讨论如何防止机密数据泄露，以及使应用程序足够强大以应对篡改攻击。

在企业中，这个话题变得更加严肃。这是因为大多数企业处理大量个人数据，其中可能包括可用于识别个人用户或与其财务详情相关的信息，例如信用卡号码、CVV 码或支付记录。

大多数企业都会花费大量资金来提高业务安全性，因为他们无法承受链条中的薄弱环节可能导致机密信息泄露的风险。一旦发生泄露，对组织的影响将从对未能维护机密数据安全的组织处以罚款开始，一直延伸到失去信任可能导致组织破产。

安全性不是闹着玩的，也没有一种解决方案适用于所有情况。相反，为了使事情变得更加复杂，用于突破组织安全防线的攻击变得越来越复杂，更难以建立保护措施。如果我们回顾一下网络安全漏洞的历史，我们可以找到一些例子，展示了网络安全问题有多么严重。例如，近年来，我们看到了一些涉及主要组织的泄露事件，其中一家组织的用户账户泄露超过 30 亿个；在另一次攻击中，一个游戏网络遭受了安全漏洞，并且停机了大约一个月，给组织造成了巨大的财务损失。

网络安全领域清楚地表明了一件事：这是一个不断发展的领域，每天都会发现新的攻击类型，并且正在研究新的缓解措施以及及时地克服它们。

现在，让我们来了解为什么企业应用安全是一个重要的话题，不应该被 compromise。

# 企业安全的重要性

大多数企业，无论其规模大小，都处理大量用户数据。这些数据可能涉及用户的一些公开可用的信息，也可能涉及机密数据。一旦这些数据进入组织的存储系统，组织就有责任保护数据的机密性，以防止未经许可的任何未经授权的人访问。

为了实现这一点，大多数企业加强了他们的网络安全，并建立了多重屏障，以防止未经授权的访问其用户数据系统。因此，让我们来看看企业安全如此重要的一些原因：

+   **数据的机密性：**许多组织...

# 系统安全面临的挑战

信息技术领域正在以快速的速度增长，每天都会出现新的技术。两方之间的通信方式也在不断发展，提供更有效的远程通信。但这种演变也带来了一系列关于系统安全的挑战。让我们来看看使得组织的系统安全变得困难的挑战。

+   **数据量的增加：**大多数组织正在构建他们的系统，利用人工智能和机器学习为用户提供更个性化的体验，他们也正在收集大量关于用户的信息，以改进推荐。这大量的数据存储使得数据的安全性更难以维护，因为现在越来越多的机密信息被保留，使得系统对攻击者更具吸引力。

+   **数据分布在公共服务提供商之上：**许多企业现在正在削减其存储基础设施，并且越来越依赖第三方公共存储提供商，这些提供商以更低的成本提供相同数量的存储空间，以及降低的维护成本。这也会使企业的安全性面临风险，因为现在数据受第三方服务提供商的安全策略管辖，数据所有者对数据的安全策略几乎没有控制权。存储服务提供商的一次违规行为可能会暴露不同组织的多个用户的数据。

+   **连接到互联网的设备数量不断增加：**随着越来越多的设备加入互联网，攻击面也在增加。即使是单个设备内部存在弱点，无论是加密标准还是未实施适当的访问控制，整个系统的安全性都很容易被破坏。

+   **复杂的攻击：**攻击变得越来越复杂，攻击者现在利用系统中的零日漏洞，甚至利用组织尚未发现的漏洞。这些攻击危害了大量数据，并对整个系统构成了巨大的安全风险。更加复杂的是，由于漏洞是新的，它们没有即时解决方案，导致延迟的响应，甚至有时延迟识别攻击发生。

+   **国家赞助攻击的增加：**随着全球信息技术驱动的通信和流程不断增加，战争的背景也在改变。以往的战争是在地面上进行的，现在它们正在网络上进行，这导致了国家赞助的攻击。这些攻击通常针对企业，要么是为了收集情报，要么是为了造成重大破坏。国家赞助的攻击问题在于这些攻击本质上是高度复杂的，并利用了大量资源，这使得它们难以克服。

有了这些，我们现在知道了不同因素使企业难以提高其系统的安全性。这就是为什么网络安全总是在进行追赶，企业正在改进其安全性，以抵御攻击者利用不断变化的攻击向量攻击 IT 系统。

现在，有了这些知识，是时候让我们了解到底是什么影响了应用程序的安全性。只有了解了不同的攻击向量，我们才能继续前进，使我们的应用程序免受攻击。因此，让我们开始这段旅程。

# 看一下攻击向量

每次侵犯系统安全或使其崩溃的攻击，都会利用系统应用程序运行的一个或另一个漏洞。这些漏洞对每种类型的应用程序都是不同的。为系统本地构建的应用程序可能具有不同的攻击向量，而为网络开发的应用程序可能具有不同的攻击向量。

为了充分保护应用程序免受攻击，我们需要了解针对不同应用程序类型使用的不同攻击向量。

从现在开始，我们将简要介绍两种最常见的应用程序类型和可能用于针对这些应用程序的攻击向量。

# 本地应用程序的安全问题

本地应用程序是专门为其运行的平台构建的应用程序。这些应用程序利用所提供的库和功能，以充分利用平台功能。这些应用程序可能遇到的安全问题通常是影响这些应用程序运行的基础平台的安全问题，或者是由应用程序开发人员留下的漏洞造成的。因此，让我们来看看影响本地应用程序安全性的一些问题：

+   **基础平台的漏洞：**当应用程序在平台上运行时，其功能受基础平台公开的内容所支配。如果基础平台容易受到安全问题的影响，那么在平台上运行的应用程序也会容易受到影响，除非它们在应用程序级别实施适当的措施来减轻这些漏洞。这类问题可能涉及硬件问题，比如最近影响 x86 平台的 Spectre 和 Meltdown 漏洞。

+   **使用第三方库：**一些使用第三方库的应用程序，特别是用于在应用程序内部实现安全性的库，如果开发人员停止维护这些库，或者存在一些未修复的漏洞，确实会使应用程序更容易受到安全漏洞的影响。通常，更好的选择是至少针对在应用程序中实现安全性的用例使用平台本身提供的库，而不是使用未记录的平台 API，这可能对应用程序的使用具有未解释的安全影响。

+   **未加密的数据存储：**如果一个应用程序涉及存储和检索数据，以未加密的格式存储数据可能导致数据被不受信任的来源访问，并使数据容易被滥用。应用程序应确保其存储的数据是以加密形式存储的。

+   **与第三方的未加密通信：**如今，许多应用程序依赖于第三方服务来实现特定功能。即使在企业网络内部，应用程序可能也会调用网络内部的第三方身份验证服务器来验证用户的身份。如果这些应用程序之间的通信是未加密的，可能会导致攻击，如中间人攻击。

+   **避免边界检查：**那些实施自己的内存管理技术的本地应用程序，如果应用程序的开发人员忽略了可能的边界检查，可能会变得容易受到攻击者访问应用程序边界之外的数据的攻击。这可能会导致系统安全性的严重破坏，不仅受影响的应用程序的数据暴露，其他应用程序的数据也会暴露。

这是一个非详尽的可能影响本地应用程序安全性的问题列表。其中一些问题可以很容易地修复，而其他问题则需要应用程序开发人员和平台提供商付出大量努力来减轻可能的安全漏洞。

现在，了解可能影响本地应用程序的攻击向量的知识后，是时候让我们了解可能影响 Web 应用程序的攻击向量了。

# Web 应用程序的安全问题

Web 应用程序的使用量一直在不断增加。随着互联网的日益普及，越来越多的组织正在将日常办公工作转移到帮助不同地理位置的办公室之间建立联系的 Web 应用程序上。但是，这些优势也伴随着安全方面的成本。

由于 Web 应用程序可能发生的攻击方式之多，Web 应用程序的安全一直是一个具有挑战性的领域。因此，让我们来看看困扰 Web 应用程序安全的问题：

+   **SQL 注入：**由于使用 SQL 数据库支持的 Web 应用程序的常见攻击之一是使用 SQL 注入。

# 安全反模式

现在，我们需要了解通常会使应用程序处于安全漏洞区域的实践。可能有很多事情会导致应用程序遭受安全问题，当我们通过本节时，我们将看一些通常会使应用程序容易受到安全漏洞的错误。所以，让我们逐个看一下。

# 不过滤用户输入

作为应用程序开发人员，我们希望用户信任我们的应用程序。这是我们确保用户会使用我们的应用程序的唯一方式。但是，同样地，我们是否也应该信任我们的用户，并期望他们不会做任何错误的事情？具体来说，信任他们通过我们的应用程序向他们提供输入的输入机制。

以下代码片段展示了一个简单的例子，未过滤用户提供的输入：

```py
username = request.args.get('username')email = request.args.get('email')password = request.args.get('password')user_record = User(username=username, email=email, password=password) #Let's create an object to store in database ...
```

# 未加密存储敏感数据

现在，作为应用程序开发人员，我们喜欢在应用程序代码库中保持简单，以便以后可以轻松维护应用程序。在考虑这种简单性的同时，我们认为我们的应用程序已经在一个良好的防火墙后面运行，并且每次访问都经过了彻底检查，那么为什么不只是以明文形式在数据库中存储用户的密码呢？这将帮助我们轻松匹配它们，也将帮助我们节省大量的 CPU 周期。

有一天，当应用程序在生产中运行时，攻击者能够破坏数据库的安全性，并不知何故能够从用户表中获取详细信息。现在，我们面临的情况是用户的登录凭据不仅泄露了，而且还以明文格式可用。根据一般心理学，许多人会在许多服务上重复使用相同的密码。在这种情况下，我们不仅危及了我们应用程序用户的凭据，还危及了用户可能正在使用的其他应用程序的凭据。

这种试图在没有任何强大加密的情况下存储安全敏感数据的做法不仅使应用程序面临可能随时发生的安全问题，而且还使其用户面临风险。

# 忽略边界检查

与缺少边界检查相关的安全问题在软件应用程序中是相当常见的情况。这种情况发生在开发人员意外地忘记在他们正在实现的数据结构中实施边界检查时。

当程序尝试访问分配给它的内存区域之外的内存区域时，会导致程序发生缓冲区溢出。

例如，考虑以下代码片段：

```py
arr = [None] * 10for i in range(0,15):    arr[i] = i
```

当执行此程序时，程序会尝试更改实际上并非由其管理的内存内容。如果底层平台没有引发任何内存保护，此程序将成功地能够覆盖...

# 不保持库的更新

大多数生产应用程序依赖于第三方库来启用一些功能集。保持这些库过时可以节省一些额外的千字节的更新或维护软件，以便它继续使用更新的库。然而，这也可能导致应用程序存在未修复的安全漏洞，攻击者以后可能利用这些漏洞非法访问您的应用程序和应用程序管理的数据。

# 将数据库的完整权限赋予单个用户

许多应用程序实际上会给应用程序的单个用户完整的数据库权限。有时，这些权限足以让您的应用程序数据库用户具有与数据库的根用户相同的权限集。

现在，这种实现方式在解决验证某个用户是否具有执行数据库操作的特定权限的问题上有很大帮助，同时也为应用程序带来了巨大的漏洞。

想象一下，如果某个数据库用户的凭据不知何故泄露了。攻击者现在将完全访问您的数据库，这使他们...

# 改进应用程序的安全性

如果我们遵循软件安全的一些基本规则并且在应用程序的开发和生产周期中严格实施这些规则，就可以保持应用程序的安全性：

+   **永远不要相信用户输入：** 作为应用程序的开发人员，我们应该确保不相信任何用户输入。在应用程序存储或任何其他可能导致提供的输入被执行的操作之前，用户端可能提供的一切都应该得到适当的过滤。

+   **加密敏感数据：** 任何敏感数据都应具有强大的加密，以支持其存储和检索。在生成数据的加密版本时具有一定程度的随机性可以帮助防止攻击者从数据中获取有用信息，即使他们以某种方式获得了对数据的访问权限。

+   **妥善保护基础设施：** 用于运行应用程序的基础设施应该得到妥善保护，防火墙配置应限制对内部网络或节点的任何未经授权的访问。

+   **实施端到端加密：**两个服务之间发生的任何通信都应该进行端到端加密，以避免中间人攻击或信息被窃取。

+   **谨慎实施边界检查：**如果您的应用程序使用任何类型的数据结构，请确保适当的边界检查已经就位，以避免漏洞，比如缓冲区溢出，这可能允许恶意代码被执行。

+   **限制用户权限：**没有应用程序应该有一个拥有所有权限的单个用户。用户权限应该受到限制，以定义用户执行操作的边界。遵循这种建议可以帮助限制较低权限用户的凭据被泄露时可能造成的损害。

+   **保持依赖项更新：**应用程序的依赖项应该保持更新，以确保依赖项没有已知的安全漏洞。

遵循这些指南可以在改善应用程序安全性方面起到很大作用，并确保应用程序和数据都得到保护，从而保持用户信任和数据安全。

# 总结

随着我们在本章的进展，我们了解了管理软件应用程序开发和运营的不同安全原则。我们谈到了需要在企业应用程序方面保持高安全标准，以及应用程序安全被破坏后会发生什么。然后，我们了解了系统安全面临的挑战。然后，我们转向了用于危害应用程序安全的常见攻击向量。

一旦我们了解了攻击向量，我们就看了一些常见的安全反模式，这些反模式会危及您的应用程序以及与应用程序相关的数据的安全性。一旦我们了解了这些反模式，...

# 问题

1.  是什么不同的问题使应用程序安全变得困难？

1.  什么是 XSS 攻击？

1.  我们如何防止 DoS 攻击？

1.  一些危害应用程序安全的错误是什么？

# 进一步阅读

如果您觉得应用程序安全是一个有趣的话题，并且想要了解如何使用 Python 来提高应用程序的安全性，请看一下这个由 Manish Saini 撰写、Packt 制作的视频系列《Python 持续交付和应用程序安全》。


# 第十一章：采用微服务方法

到目前为止，在本书中，我们已经了解了如何开发企业级应用程序以及如何成熟我们的流程，以便我们交付的应用程序符合我们的质量标准，并为其用户提供强大而有韧性的体验。在本章中，我们将看看一种新的应用程序开发范式，其中应用程序不是一个单一的产品，而是多个产品相互交互，以提供统一的体验。

近年来，开发场景发生了快速变化。应用程序开发已经从开发大型单体转变为开发小型服务，所有这些服务相互交互，为用户提供所需的结果。这种变化是为了满足更快地发布项目的需求，以增加添加新功能和提高应用程序可扩展性的能力。

在本章中，我们将看看这种新的应用程序开发范式，团队变得更小，能够以越来越低的成本在应用程序中发布新功能已经成为新的标准。这种被称为微服务开发方法的范式彻底改变了应用程序开发周期的工作方式，并且还导致了与 DevOps、持续集成和部署相关的技术的当前趋势。

随着本章的进行，您将了解以下内容：

+   朝着微服务开发方法迈进

+   服务之间基于 API 的通信

+   构建健壮的微服务

+   处理微服务中的用户-服务器交互

+   微服务之间的异步通信

# 技术要求

本书中的代码清单可以在[`github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python`](https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python)的`chapter11`目录下找到。

可以通过运行以下命令克隆代码示例：

```py
git clone https://github.com/PacktPublishing/Hands-On-Enterprise-Application-Development-with-Python
```

设置和运行代码的步骤已包含在`README.md`文件中，以便更深入地了解代码示例。

# 向微服务开发方法转变

在过去几年里，开发人员一直在尝试用新的方式来开发应用程序。其目的是缩短开发生命周期，增加更快地将项目投入生产的能力，增加组件之间的解耦，使它们可以独立开发，并提高团队并行开发应用程序的能力。

随之而来的是使用微服务的开发技术，这有助于解决上述的用例。在这种方法中，应用程序不是一个单一的大型代码库，所有组件都放在一起，对任何组件的单一更改都需要再次部署整个应用程序。首先，让我们看看微服务模型与单体模型的不同之处，然后看看遵循微服务方法有哪些优势。

# 单体开发模型与微服务

我们都习惯于构建一个应用程序，其中单个代码库包含应用程序的所有功能组件，紧密地联系在一起，以实现特定的期望结果。这些应用程序遵循严格的开发方法，应用程序的功能和架构首先在初始需求收集和设计阶段进行思考，然后应用程序的严格开发开始。

只有在所有组件都经过开发和彻底测试后，应用程序才进入生产阶段，在那里它被部署在基础设施上供常规使用。这个模型在下图中显示：

这个过程...

# 微服务架构的优势

微服务架构为我们解决了许多问题，主要是因为我们开发和部署微服务的方式发生了变化。让我们来看看微服务架构为我们的开发过程带来的一些优势，如下列表所示：

+   **小团队：**由于一个特定的微服务通常专注于做一件事并且做得很好，负责构建该微服务的团队通常可以很小。一个团队可以全面拥有多个微服务，他们不仅负责开发，还负责部署和管理，从而形成良好的 DevOps 文化。

+   **增强了独立性：**在微服务架构中，负责开发一个微服务的团队不需要完全了解另一个微服务的内部工作方式。团队只需要关注微服务暴露的 API 端点，以便与其进行交互。这避免了团队在开展开发活动时对彼此的依赖。

+   **增强了对故障的韧性：**在微服务架构中，由于一个微服务的故障不会影响整个应用程序，而是会逐渐降低服务的性能，因此故障韧性相当高。在此期间，可能会启动一个新的失败服务实例，或者可以轻松地将失败服务隔离以进行调试，以减少影响。

+   **增强了可扩展性：**微服务架构为应用程序的可扩展性提供了很大的自由度。现在，随着负载的增加，可以独立地扩展各个微服务，而不是整体扩展应用程序。这种扩展可以以水平扩展的方式进行，根据应用程序所经历的负载，可以启动更多的特定微服务实例，或者可以使用垂直扩展的方式单独扩展这些服务，为特定服务分配更多资源，以便更好地处理不断增加的负载。

+   **简单集成：**使用微服务，不需要了解其他微服务内部的知识，因此不需要了解其他微服务的内部情况，不需要了解其他微服务的内部情况。所有的集成都是在假设其他微服务是黑匣子的情况下进行的。

+   **增强了可重用性：**一旦开发完成，一个微服务可以在不同的应用程序中被利用。例如，负责用户认证处理的微服务可以在多个应用程序中重复使用，而无需复制代码。

+   **轻松推出新功能的自由：**使用微服务架构，新功能可以轻松推出。在大多数情况下，特定功能被转换为自己的微服务，然后在经过适当测试后部署到生产环境。一旦服务在生产环境中上线，其功能就可以使用。这与整体式方法不同，整个应用程序需要在新功能或改进需要部署到生产环境时重新部署。

从这个列表中，我们可以看到微服务架构向我们提供了许多好处。从工具的选择到快速推出新功能的便利性，微服务架构使开发人员有利可图，并迅速开始推出新的微服务。

但所有这些优势并非免费。尽管有优势，但在微服务架构中工作时也有可能创建基础设施的混乱，这不仅会增加成本。然而，这也可能影响团队的整体生产力，他们可能更专注于解决因架构实施不当而可能出现的问题，而不是专注于改进和开发对应用程序用户至关重要的功能。

这并不是什么大问题。我们可以遵循一些简单的建议，在微服务架构的旅程中会有很大帮助。因此，让我们花些时间了解这些简单的技巧，这些技巧可以帮助我们顺利进行微服务的旅程。

# 微服务开发指南

微服务的开发是具有挑战性的，而且很难做到完美。有没有什么方法可以让这个过程变得更容易？事实证明，有一些指南，如果遵循，可以在微服务的开发中提供很大帮助。因此，让我们看一下以下列表中所示的这些指南：

+   **开发前的设计**：当进行微服务开发时，它们通常应该模拟特定的责任领域。但这也是最常出现最大错误的地方。通常情况下，服务的边界没有定义。在后期阶段，随着领域的发展，微服务也变得复杂，以处理增加的...

# 微服务中的服务发现

在应用程序开发的传统模型中，通常会以静态方式部署特定应用程序的服务，它们的网络位置不会自动更改。如果是这种情况，那么偶尔更新配置文件以反映服务的更改网络位置是完全可以的。

但在现代基于微服务的应用程序中，服务的数量可能会根据多种因素而上下波动，例如负载平衡、扩展、新功能的推出等，因此维护配置文件会变得有些困难。此外，如今大多数云环境都不提供这些服务的静态网络部署，这意味着服务的网络位置可能会不断变化，增加了维护配置文件的麻烦。

为了解决这些情况，我们需要有一些更加动态的东西，可以适应不断变化的环境。这就是服务发现的概念。服务发现允许动态解析所需服务的网络端点，并消除了手动更新配置文件的需要。

服务发现通常有以下两种方式：

+   客户端服务发现

+   服务器端服务发现

但在讨论这两种方法之前，我们需要了解服务发现系统的另一个重要组件。让我们看看这个重要组件是什么，以及它如何促进服务发现过程。

# 客户端服务发现

使用客户端服务发现方法，各个服务需要知道服务注册表。例如，在这种模型中，如果**服务实例 A**想要向**服务实例 C**发出请求，那么进行此请求的过程如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-etp-app-dev-py/img/87d24590-eb4f-4df1-822c-da856ddefd76.png)

请求的流程如下所示：

+   **服务实例 A**查询服务注册表以获取**服务实例 C**的网络地址。

+   **服务注册表**检查其数据库以获取**服务实例 C**的网络地址，并将其返回给**服务实例 A**。如果**服务实例 C**是负载平衡服务...

# 服务器端服务发现

使用服务器端服务发现模式，解析服务的网络地址的能力不在个体客户端内部——相反，这个逻辑被移动到负载均衡器中。在服务器端服务发现模式中，请求流程如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-etp-app-dev-py/img/2af7c994-b611-4963-8c6d-50a842bfaac0.png)

这个图表显示了以下过程：

1.  **客户端**发出对 API 端点的请求

1.  **负载均衡器**拦截请求并查询**服务注册表**以解析适当服务的网络地址

1.  **负载均衡器**然后将请求发送到适当的网络服务来处理请求

这种模式的优势在于通过从客户端中删除服务发现逻辑来减少代码重复，并且由于服务注册表不负担负载均衡算法的负载，因此负载均衡更好。

现在我们知道了微服务架构中服务发现是如何发生的，让我们把重点放在理解微服务中另一个有趣的概念上。

想象一下，你正在构建一个应用程序，该应用程序应该处理多个设备，并且每个设备提供的功能根据某些方面而有所不同，比如移动设备将不具备向其他用户发送直接消息的功能。在这种情况下，每个设备都需要一个不同的 API 端点，以便调用其特定的服务集。然而，在应用程序的维护阶段或某些 API 发生变化时，让客户端了解每个单独的 API 端点可能会成为一个问题。为了处理这种情况，我们需要有一些可以作为我们通信的中间层的东西。

幸运的是，在微服务架构中，我们有一些东西可以帮助我们解决这个问题。让我们看看我们可以利用什么。

# 微服务中的服务级别协议

在基于微服务架构的任何生产级应用程序的开发过程中，服务可能会在很大程度上依赖于生产环境中部署的其他服务的可用性。例如，为应用程序的管理面板提供功能的服务可能需要用户认证服务的可用性，以允许管理员登录和权限管理。如果用户管理服务出现故障，应用程序提供的操作的稳定性可能会受到严重影响。

为了保证这些要求，我们需要有作为团队之间特定微服务交付的合同的 SLA。这...

# 构建你的第一个微服务应用程序

我们现在准备使用微服务架构构建我们的第一个应用程序。在开发这个应用程序的过程中，我们将看到如何利用我们迄今为止所获得的知识来推出一个可工作的应用程序。

现在，关于我们的例子，为了保持这个应用程序简单，并且提供对微服务架构工作原理的简单理解，我们将构建一个简单的待办事项创建应用程序：让我们看看这个应用程序将会是什么样子，如下列表所规定的：

+   该应用程序将由两个微服务组成——即待办事项管理服务和用户认证服务

+   这些服务将使用 Python 开发

+   为了这个练习，服务将利用它们自己的 SQLite 数据库

+   待办事项服务将依赖用户服务来收集与用户操作相关的任何信息，包括用户认证、配置获取等

+   服务将通过使用 RESTful API 进行通信，每个服务提供 JSON 编码的响应

具体要求已经指定，现在是时候开始编写我们的微服务了。

# 用户微服务

用户微服务负责处理与用户配置文件管理相关的任何事务。该服务提供以下功能：

+   注册新用户

+   用户配置文件管理

+   现有用户的身份验证

+   为用户生成唯一的身份验证令牌以登录

+   为其他服务提供用户认证功能

为了使该服务运行，我们需要以下两个数据库模型：

+   **用户数据库模型：** 用户数据库模型负责管理用户记录，如他们的用户名、哈希密码等。

+   **令牌数据库模型：** 令牌数据库模型负责存储已生成的令牌的信息...

# 待办事项管理器服务

待办事项管理器服务是帮助用户管理其`todo`项目的服务。该服务提供了用户创建新列表并向列表添加项目的功能。为此，唯一的要求是用户应该经过身份验证。

为了正确工作，服务将需要存在一个列表数据库模型，用于存储用户创建的`todo`列表的信息，以及一个项目模型，其中将包含特定`todo`列表的项目列表。

以下代码片段实现了这些模型：

```py
'''
File: models.py
Description: The models for the todo service.
'''
from todo_service.todo_service import db
import datetime

class List(db.Model):
    """The list database model.

    The list database model is used to create a new todo list
    based on the input provided by the user.
    """

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    list_name = db.Column(db.String(25), nullable=False)
    db.UniqueConstraint('user_id', 'list_name', name='list_name_uiq')

    def __repr__(self):
        """Provide a representation of model."""
        return "<List {}>".format(self.list_name)

class Item(db.Model):
    """The item database model.

    The model is used to store the information about the items
    in a particular list maintained by the user.
    """

    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey(List.id))
    item_name = db.Column(db.String(50), nullable=False)
    db.UniqueConstraint('list_id', 'item_name', name='item_list_uiq')

    def __repr__(self):
        """Provide a representation of model."""
        return "<Item {}>".format(self.item_name)
```

一旦开发了这些模型，我们需要做的下一件事就是实现 API。

对于待办事项管理器服务，将设置以下 API，为服务提供交互端点：

+   `/list/new`：此 API 端点接受要创建的列表的名称并创建新列表。

+   `/list/add_item`：此 API 端点接受需要添加到列表中的项目列表以及应将项目添加到的列表的名称。一旦验证通过，项目将被添加到列表中。

+   `/list/view`：此 API 端点接受需要显示内容的列表的名称，并显示列表的内容。

以下代码片段显示了服务的端点实现：

```py
def check_required_fields(req_fields, input_list):
    """Check if the required fields are present or not in a given list.

    Keyword arguments:
    req_fields -- The list of fields required
    input_list -- The input list to check for

    Returns:
        Boolean
    """

    if all(field in req_fields for field in input_list):
        return True
    return False

def validate_user(auth_token):
    """Validates a user and returns it user id.

    Keyword arguments:
    auth_token -- The authentication token to be used

    Returns:
        Integer
    """

    endpoint = user_service + '/auth/validate'
    resp = requests.post(endpoint, json={"auth_token": auth_token})
    if resp.status_code == 200:
        user = resp.json()
        user_id = user['user_id']
        return user_id
    else:
        return None

@app.route('/list/new', methods=['POST'])
def new_list():
    """Handle the creation of new list."""

    required_fields = ['auth_token', 'list_name']
    response = {}
    list_data = request.get_json()
    if not check_required_fields(required_fields, list_data.keys()):
        response['message'] = 'The required parameters are not provided'
        return jsonify(response), 400

    auth_token = list_data['auth_token']

    # Get the user id for the auth token provided
    user_id = validate_user(auth_token)

    # If the user is not valid, return an error
    if user_id is None:
        response['message'] = "Unable to login user. Please check the auth token"
        return jsonify(response), 400

    # User token is valid, let's create the list
    list_name = list_data['list_name']
    new_list = List(user_id=user_id, list_name=list_name)
    db.session.add(new_list)
    try:
        db.session.commit()
    except Exception:
        response['message'] = "Unable to create a new todo-list"
        return jsonify(response), 500
    response['message'] = "List created"
    return jsonify(response), 200

@app.route('/list/add_item', methods=['POST'])
def add_item():
    """Handle the addition of new items to the list."""

    ...
    # The complete code for the service can be found inside the assisting code repository for the book
```

有了上述代码，我们现在已经准备好使用我们的待办事项管理器服务，它将通过 RESTful API 帮助我们创建和管理待办事项列表。

但在我们执行待办事项管理器服务之前，我们需要记住一件重要的事情。该服务依赖于用户服务来执行任何类型的用户认证并获取有关用户配置文件的信息。为了实现这一点，我们的待办事项管理器需要知道用户服务在哪里运行，以便可以与用户服务进行交互。在这个例子中，我们通过在待办事项管理器服务配置文件中设置用户服务端点的配置键来实现这一点。以下代码片段显示了待办事项管理器服务配置文件的内容：

```py
DEBUG = False
SECRET_KEY = 'du373r3uie3yf3@U#^$*EU9373^#'
BCRYPT_LOG_ROUNDS = 5
SQLALCHEMY_DATABASE_URI = 'sqlite:///todo_service.db'
SQLALCHEMY_ECHO = False
USER_SERVICE_ENDPOINT = 'http://localhost:5000'
```

要使待办事项管理器服务运行，需要从存储库的`todo_service`目录内执行以下命令：

```py
python3 run.py
```

一旦命令成功执行，待办事项管理器服务将在`http://localhost:5001/`上可用。

一旦服务启动运行，我们可以利用其 API 来管理我们的清单。例如，如果我们想要创建一个新的待办事项列表，我们只需要向`http://localhost:5001/list/new` API 端点发送 HTTP POST 请求，传递以下键作为 JSON 格式的输入：

+   `auth_token`**：** 这是用户在使用`http://localhost:5000/auth/login` API 端点成功登录用户服务后收到的身份验证令牌

+   `list_name`**：** 这是要创建的新列表的名称

一旦 API 端点调用完成，待办事项管理器服务首先尝试通过与用户服务交互来验证 API 调用中提供的`auth`令牌。如果`auth`令牌验证通过，待办事项管理器服务将接收一个用于识别用户的用户 ID。完成这一步后，待办事项管理器服务会在其数据库中为新的待办事项列表创建一个条目，并针对检索到的用户 ID。

这是待办事项管理器服务的简单工作流程。

现在我们了解了如何构建一个简单的微服务，我们现在可以专注于有关微服务架构的一些有趣的主题。你是否注意到我们如何告知待办事项管理器服务用户服务的存在？我们利用了配置密钥来实现这一点。当你只有两个或三个服务，无论发生什么，它们总是在相同的端点上运行时，使用配置密钥绝不是一个坏选择。然而，当微服务的数量甚至比两个或三个服务稍微多一点时，这种方法会严重崩溃，因为它们可能在基础设施的任何地方运行。

除此之外，如果新服务频繁投入生产以为应用程序添加新功能，问题会进一步加剧。在这一点上，我们需要更好的解决方案，不仅应提供一种简单的方式来识别新服务，还应自动解析它们的端点。

# 微服务内的服务注册表

假设有一场魔术表演将在礼堂内举行。这场表演对所有人开放，任何人都可以来礼堂参加。在礼堂的门口，有一个登记处，你需要在进入礼堂之前先登记。当观众开始到来时，他们首先去登记处，提供他们的信息，比如他们的姓名、地址等，然后被给予一张入场券。

服务注册表就像这样。它是一种特殊类型的数据库，记录了基础设施上运行的服务以及它们的位置。每当新服务启动时，它都会注册...

# 微服务中的 API 网关

在构建微服务架构时，我们有很多选择，大多数情况下可以自由选择最适合实现微服务的技术栈。除此之外，我们始终可以通过推出针对特定设备的不同微服务来为不同设备提供不同的功能。但是当我们这样做时，我们也给客户端增加了复杂性，现在客户端必须处理所有这些不同的情况。

因此，让我们首先看一下客户端可能面临的挑战，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-etp-app-dev-py/img/5a3e46ee-c709-497a-9ada-9dc57c1ad77c.png)

前面的图表显示了我们面临的挑战，如下列表所示：

+   **处理不同的 API：** 当每个设备都有一个特定的微服务，为其提供所需的功能集时，该设备的客户端需要了解与该特定服务相关的 API 端点。这增加了复杂性，因为现在负责处理客户端开发的团队需要了解可能会减慢客户端开发过程的微服务特定端点。

+   **更改 API 端点：** 随着时间的推移，我们可能会修改微服务内特定 API 端点的工作方式。这将要求我们更新所有利用微服务提供的服务的客户端，以反映这些更改。这是一个繁琐的过程，也可能引入错误或破坏现有功能。

+   **协议支持不足：**使用微服务架构，我们有权控制用于构建微服务的技术栈。有时，微服务可能由通常不受其他平台支持或在其他平台上实现不佳的协议驱动。例如，客户端运行的大多数平台可能不支持像 AMQP 这样的东西，这将使得客户端的开发变得困难，因为现在开发人员必须在每个客户端内构建处理 AMQP 协议的逻辑。这种要求不仅可能具有挑战性，而且如果平台无法处理所需的过多处理负载，可能也无法完成。

+   **安全性：**如果我们需要嵌入每个客户端支持的微服务的个别网络位置的细节，我们可能会在基础设施中打开安全漏洞，即使其中一个微服务未正确配置安全性。

这些只是在开发微服务应用程序过程中可能面临的一些挑战。但我们能做些什么来克服它们呢？

这个问题的答案在于使用 API 网关。

**API 网关**可以被视为客户端和应用程序通信之间的中介，处理客户端请求的路由以及将这些请求从客户端支持的协议转换为后端微服务支持的协议。它可以在不让客户端担心微服务可能运行的位置的情况下完成所有这些操作。

在使用 API 网关的基于微服务架构的应用程序中，从客户端到应用程序的请求流程可以描述如下：

1.  客户端有一组共同的端点，用于访问一定的功能集。

1.  客户端向 API 端点发送请求，以及需要传递的任何数据，以便完成请求。

1.  API 网关拦截客户端对 API 端点的请求。

1.  API 网关确定客户端类型和客户端支持的功能。

1.  然后 API 网关确定需要调用哪些个别微服务来完成请求。

1.  然后 API 网关将请求转发到后端运行的特定微服务。如果微服务接受的协议与客户端发出请求的协议不同，API 网关会将请求从客户端协议转换为微服务支持的协议，然后转发请求。

1.  一旦微服务完成生成响应，API 网关收集响应并将集体响应发送回请求的客户端。

这种过程有几个优点；让我们来看看其中的一些：

+   **简单客户端：**有了 API 网关，客户端无需知道它们可能需要调用的各个微服务。这里的客户端对特定功能调用一个共同的端点，然后 API 网关负责确定需要调用哪个服务来完成请求。这大大减少了正在开发的客户端的复杂性，并使其维护变得容易。

+   **更改 API 端点的便利性：**当后端微服务的特定 API 实现发生变化时，API 网关可以处理未更新的旧客户端的兼容性。这可以通过使 API 网关返回降级响应或自动更新其接收到的请求以适应新的 API 兼容层来实现，如果可能的话。

+   **更简单的协议支持：**有了 API 网关来处理微服务可能需要的任何协议转换，客户端就不需要担心如何处理它无法支持的协议，大大减少了引入不受平台支持的协议支持可能带来的复杂性和问题。

+   **改进的安全性：**通过 API 网关，客户端不需要知道特定微服务运行的个别网络位置。他们只需要知道 API 网关监听请求的位置，以便成功调用 API。一旦调用完成，API 网关负责确定提供该 API 的各个微服务的运行位置，然后将请求转发给它们。

+   **改进的故障处理：**如果特定的后端服务出现故障，API 网关也可以提供帮助。在这种情况下，如果后端微服务是非关键微服务，API 网关可以向客户端返回降级响应，而如果关键后端服务出现故障，API 网关可以立即返回错误响应，而不让请求排队，增加服务器的负载。

正如我们所看到的，使用 API 网关的好处是巨大的，并且极大地简化了微服务应用程序中客户端的开发。此外，通过利用 API 网关，可以轻松建立服务之间的通信。

为了使服务相互通信，它们只需调用 API 网关知道的适当端点，然后 API 网关负责确定适当的微服务及其网络地址，以完成对其发出的请求。

前面的方法确实很好，但有一个缺点：这里的一切都是串行和同步的。发出调用，然后调用客户端/服务等待直到生成响应。如果服务的负载很高，这些响应可能需要很长时间才能到达，这可能会导致大量请求在基础设施上排队，进一步增加基础设施的负载，或者可能导致大量请求超时。这可能会大大降低应用程序的吞吐量，甚至可能使整个基础设施崩溃，如果排队请求的数量变得非常大。

是否有一种服务之间可以相互交互的异步通信方法，而不需要一遍又一遍地进行 API 调用？让我们看看这样一种方法。

# 微服务中的异步通信

在微服务架构中，每个服务都有一个明确的职责，并且做得很好。为了实现业务应用的任何有意义的响应，这些服务需要相互通信。所有这些通信都发生在网络上。

在这里，一个服务向另一个服务发出请求，然后等待响应返回。但有一个问题。如果另一个服务花费很长时间来处理请求，或者服务宕机了呢？那时会发生什么？

大多数情况下，请求会超时。但如果这个服务是一个关键服务，那么可能会到达它的请求数量可能会很大，并且可能会不断排队。如果服务很慢，这将...

# 消息队列用于微服务通信

消息队列是一种相当古老的机制，用于在应用程序内的许多不同组件之间建立通信。这种古老的方法甚至适用于我们当前的微服务架构用例。但在我们深入研究如何使用消息队列使微服务通信异步之前，让我们首先看一下在处理这种通信方法时使用的一些行话：

+   **消息：**消息是特定服务生成的一种包，用于与另一个服务交流其想要实现的目标。

+   **队列：**队列是一种主题，特定消息可能会出现在其中。对于任何实际应用程序，可能会有许多队列，每个队列表示特定的通信主题。

+   **生产者：**生产者是生成消息并将其发送到特定主题的服务。

+   **消费者：**消费者是监听特定主题并处理可能到达的任何消息的服务。

+   **路由器：**路由器是消息队列内的一个组件，负责将特定主题的消息路由到适当的队列。

现在我们知道了行话，我们可以继续看看消息队列如何帮助我们建立微服务之间的通信。

当微服务利用诸如消息队列之类的东西时，它们会使用异步协议进行交互。例如，AMQP 是更著名的异步通信协议之一。

通过异步通信，微服务之间的通信将如下进行：

1.  建立一个消息代理，它将提供消息队列的管理功能，并将消息路由到适当的队列。

1.  新服务启动并注册它想要监听或发送消息的主题。消息代理为该主题创建适当的队列，并将请求服务添加为该队列的消费者或生产者。这个过程也会继续进行其他服务。

1.  现在，一个想要实现特定目标的服务将消息发送到主题，比如*Topic Authenticate*。

1.  监听*Topic Authenticate*的消费者收到有关新消息的通知并将其消耗掉。

1.  消费者处理它已经消费的消息，并将响应放回另一个主题*Topic Auth_Response*。

1.  原始消息的生产者是*Topic Auth_Response*的消费者，并收到有关新消息的通知。

1.  原始请求客户端然后读取此消息并完成请求-响应循环。

现在，我们知道了由异步消息队列驱动的微服务架构内部的通信是什么样子。但是除了异步通信之外，这种方法还有其他好处吗？

事实证明，我们可能会从这种通信模式中看到许多好处。以下列表显示了我们可能会体验到的一些好处：

+   **更好的请求分发：**由于可能有许多消费者可能会监听特定主题，因此消息可以并行处理，并且负载平衡可以通过在消费者之间平均分配消息来自动处理。

+   **更好的错误韧性：**在特定微服务宕机的情况下，需要由该微服务处理的消息可以在消息队列内排队一段时间，然后在服务恢复后进行处理，从而减少可能的数据丢失。

+   **减少重复响应：**由于消息只传递一次给单个消费者，并且在被消费后立即出列，因此很少有可能为单个请求产生重复响应。

+   **增加的容忍度：**在基础设施内部的不同微服务经历高负载时，消息队列系统提供了异步请求-响应循环，从而减少了请求排队的机会。

有了这个，我们现在知道了如何在微服务之间建立异步通信，并且使我们的基础设施随着时间的推移而发展，而不必担心如何处理新增的 API 端点以进行服务间通信。

# 总结

在本章中，我们看了一下如何使用微服务架构以及它与传统的单片式企业应用程序开发方式有何不同。然后，我们看了一下向微服务开发方式转变的优势，并了解了我们可以遵循的指南，使我们朝着微服务更顺利地前进。

一旦我们了解了微服务的基础知识，我们继续看了一下 SLA 如何保证我们在服务之间获得一定的期望功能集，并且它们作为合同来支持应用程序的顺畅服务。然后，我们进行了一个实践练习，编写了一个简单的待办事项管理应用程序...

# 问题

1.  服务导向架构与微服务架构有何不同？

1.  如何确保基于微服务的应用程序的高可用性？

1.  SLA 提供了什么样的保证？

1.  我们可以让 API 网关直接与服务注册表通信吗？

1.  我们可以使用哪些工具来实现微服务之间的异步通信？

# 进一步阅读

想了解更多关于微服务的知识吗？看看*Packt Publishing*的*Umesh Ram Sharma*的*Practical Microservices*。
