# Python 云原生教程（二）

> 原文：[`zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D`](https://zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：交互数据服务

在上一章中，我们使用 JavaScript/HTML 构建了我们的应用程序，并将其与 RESTful API 和 AJAX 集成。您还学习了如何在客户端设置 cookie 和在服务器端设置会话，以提供更好的用户体验。在本章中，我们将专注于通过使用 NoSQL 数据库（如 MongoDB）而不是我们目前使用的 SQLite 数据库或 MySQL 数据库来改进我们的后端数据库，并将我们的应用程序与之集成。

本章将涵盖的主题如下：

+   设置 MongoDB 服务

+   将应用程序与 MongoDB 集成

# MongoDB - 它的优势和我们为什么使用它？

在开始 MongoDB 安装之前，让我们了解为什么选择了 MongoDB 数据库以及它的需求。

让我们看看 MongoDB 相对于 RDBMS 的优势：

+   灵活的模式：MongoDB 是一个文档数据库，一个集合可以包含多个文档。我们不需要在插入数据之前定义文档的模式，这意味着 MongoDB 根据插入文档的数据来定义文档的模式；而在关系型数据库中，我们需要在插入数据之前定义表的模式。

+   **较少的复杂性**：在 MongoDB 中没有复杂的连接，就像在关系数据库管理系统中（例如：MySQL）数据库中一样。

+   **更容易扩展**：与关系数据库管理系统相比，MongoDB 的扩展非常容易。

+   **快速访问**：与 MySQL 数据库相比，MongoDB 中的数据检索速度更快。

+   **动态查询**：MongoDB 支持对文档进行动态查询，它是一种基于文档的查询语言，这使其比其他关系型数据库（如 MySQL）更具优势。

以下是我们应该使用 MongoDB 的原因：

+   MongoDB 以 JSON 样式文档存储数据，这使得它很容易与应用程序集成。

+   我们可以在任何文件和属性上设置索引

+   MongoDB 自动分片，这使得它易于管理并使其更快

+   MongoDB 在集群中使用时提供复制和高可用性

有不同的用例可以使用 MongoDB。让我们在这里检查它们：

+   大数据

+   用户数据管理

+   内容交付和管理

以下图片显示了 MongoDB 与您的 Web 应用程序集成的架构图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00046.jpeg)

# MongoDB 术语

让我们看看 MongoDB 的不同术语，接下来列出了它们：

+   **数据库**：这类似于我们在**关系数据库管理系统（RDBMS）**中拥有的数据库，但是在 MongoDB 中，数据库是集合的物理容器，而不是表。MongoDB 可以有多个数据库。

+   **集合**：这基本上是具有自己模式的文档的组合。集合不对文档的模式做出贡献。这与关系型数据库中的表相当。

+   **文档**：这类似于关系数据库管理系统中的元组/行。它是一组键值对。它们具有动态模式，其中每个文档在单个集合中可能具有相同或不同的模式。它们也可能具有不同的字段。

以下代码是您理解的一个示例集合：

```py
    {  
       _id : ObjectId(58ccdd1a19b08311417b14ee),  
       body : 'New blog post,Launch your app with the AWS Startup Kit!  
       #AWS', 
       timestamp : "2017-03-11T06:39:40Z", 
       id : 18, 
       tweetedby : "eric.strom" 
   } 

```

MongoDB 以一种名为**BSON**的二进制编码格式表示 JSON 文档。

# 设置 MongoDB

在当前情况下，我们正在使用 Ubuntu 工作站，因此让我们按照以下步骤在 Ubuntu 上安装 MongoDB。

我们将使用 Ubuntu 软件包管理工具，如`apt`，通过使用 GPG 密钥对经过分发者签名的软件包进行身份验证来安装 MongoDB 软件包。

要导入 GPG 密钥，请使用以下命令：

```py
$ sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv EA312927

```

接下来，我们需要将 MongoDB 存储库路径设置为我们的操作系统，如下所示：

```py
$ echo "deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/3.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-3.2.list

```

添加了这个之后，我们需要按照以下步骤更新我们的 Ubuntu 存储库：

```py
$ sudo apt-get update  

```

现在存储库已更新，让我们使用以下命令安装最新的稳定 MongoDB 版本：

```py
$ sudo apt-get install -y mongodb-org

```

安装后，MongoDB 服务应在端口`27017`上运行。我们可以使用以下命令检查服务状态：

```py
$ sudo service mongodb status

```

如果它没有运行，您可以通过执行以下命令来启动服务：

```py
$ sudo service mongodb start

```

太棒了！现在我们已经在本地机器上安装了 MongoDB。此时，我们只需要一个独立的 MongoDB 实例，但如果您想创建一个共享的 MongoDB 集群，那么可以按照以下链接中定义的步骤进行操作：

[`docs.mongodb.com/manual/tutorial/deploy-shard-cluster/`](https://docs.mongodb.com/manual/tutorial/deploy-shard-cluster/)

因此，现在我们已经在我们的机器上启用了 MongoDB 服务，我们可以开始在其上创建数据库。

# 初始化 MongoDB 数据库

以前，在 SQLite3 中创建数据库时，我们需要手动创建数据库并定义表的架构。由于 MongoDB 是无模式的，我们将直接添加新文档，并且集合将自动创建。在这种情况下，我们将仅使用 Python 初始化数据库。

在我们向 MongoDB 添加新文档之前，我们需要为其安装 Python 驱动程序，即`pymongo`。

将`pymongo`驱动程序添加到`requirements.txt`，然后使用`pip`软件包管理器进行安装，如下所示：

```py
$echo "pymongo==3.4.0" >> requirements.txt
$ pip install -r requirements.txt

```

安装后，我们将通过在`app.py`中添加以下行来导入它：

```py
from pymongo import MongoClient

```

现在我们已经为 Python 导入了 MongoDB 驱动程序，我们将在`app.py`中创建一个连接到 MongoDB 的连接，并定义一个函数，该函数将使用初始**数据文档**初始化数据库，如下所示：

```py
    connection = MongoClient("mongodb://localhost:27017/") 
    def create_mongodatabase(): 
    try: 
       dbnames = connection.database_names() 
       if 'cloud_native' not in dbnames: 
           db = connection.cloud_native.users 
           db_tweets = connection.cloud_native.tweets 
           db_api = connection.cloud_native.apirelease 

           db.insert({ 
           "email": "eric.strom@google.com", 
           "id": 33, 
           "name": "Eric stromberg", 
           "password": "eric@123", 
           "username": "eric.strom" 
           }) 

           db_tweets.insert({ 
           "body": "New blog post,Launch your app with the AWS Startup
           Kit! #AWS", 
           "id": 18, 
           "timestamp": "2017-03-11T06:39:40Z", 
           "tweetedby": "eric.strom" 
           }) 

           db_api.insert( { 
             "buildtime": "2017-01-01 10:00:00", 
             "links": "/api/v1/users", 
             "methods": "get, post, put, delete", 
             "version": "v1" 
           }) 
           db_api.insert( { 
             "buildtime": "2017-02-11 10:00:00", 
             "links": "api/v2/tweets", 
             "methods": "get, post", 
             "version": "2017-01-10 10:00:00" 
           }) 
           print ("Database Initialize completed!") 
       else: 
           print ("Database already Initialized!")
       except: 
           print ("Database creation failed!!") 

```

建议您使用一些文档初始化资源集合，以便在开始测试 API 时获得一些响应数据，否则，您可以在不初始化集合的情况下继续。

在启动应用程序之前应调用上述函数；我们的主要函数将如下所示：

```py
   if __name__ == '__main__': 
     create_mongodatabase() 
     app.run(host='0.0.0.0', port=5000, debug=True) 

```

# 将微服务与 MongoDB 集成

由于我们已经初始化了 MongoDB 数据库，现在是时候重写我们的微服务函数，以便从 MongoDB 而不是 SQLite 3 中存储和检索数据。

以前，我们使用`curl`命令从 API 获取响应；而现在，我们将使用一个名为**POSTMAN**（[`www.getpostman.com`](https://www.getpostman.com)）的新工具，该工具是一个可以帮助您更快地构建、测试和记录 API 的应用程序。

有关 POSTMAN 工作原理的更多信息，请阅读以下链接的文档：[`www.getpostman.com/docs/`](https://www.getpostman.com/docs/)

POSTMAN 支持 Chrome 和 Firefox，因为它可以很容易地集成为一个附加组件。

首先，我们将修改`api_version`信息 API，以从 MongoDB 中收集信息，而不是从 SQLite3 中收集，如下所示：

```py
    @app.route("/api/v1/info") 
    def home_index(): 
     api_list=[] 
     db = connection.cloud_native.apirelease 
     for row in db.find(): 
       api_list.append(str(row)) 
     return jsonify({'api_version': api_list}), 200 

```

现在，如果您使用 POSTMAN 进行测试，它应该会给出类似于以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00047.jpeg)

太棒了！它有效。现在，让我们更新微服务的其他资源。

# 处理用户资源

我们将按以下方式修改`app.py`中不同方法的用户资源 API 函数。

# GET api/v1/users

GET API 函数获取完整的用户列表。

为了从 MongoDB 数据库中获取完整的用户列表，我们将按以下方式重写`list_users()`函数：

```py
    def list_users(): 
     api_list=[] 
     db = connection.cloud_native.users 
     for row in db.find(): 
       api_list.append(str(row)) 
     return jsonify({'user_list': api_list}) 

```

让我们在 POSTMAN 上进行测试，看看 API 是否按预期响应：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00048.jpeg)

由于我们目前在 MongoDB 数据库的用户集合中只有一个文档，因此在上述屏幕截图中只能看到一个用户。

# GET api/v1/users/[user_id]

此 API 函数获取特定用户的详细信息。

为了从 MongoDB 数据库中列出特定用户的详细信息，请使用以下方式调用`modify list_user(user_id)`函数：

```py
    def list_user(user_id): 
     api_list=[] 
     db = connection.cloud_native.users 
     for i in db.find({'id':user_id}): 
       api_list.append(str(i)) 

     if api_list == []: 
       abort(404) 
     return jsonify({'user_details':api_list} 

```

让我们在 POSTMAN 上测试一下，看看它是否按预期工作：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00049.jpeg)

此外，我们需要测试用户条目不存在的情况；请尝试以下代码：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00050.jpeg)

# POST api/v1/users

该 API 函数用于将新用户添加到用户列表中。

在这段代码中，我们将重写`add_user(new_user)`函数与 MongoDB 进行交互，将用户添加到用户集合中：

```py
    def add_user(new_user): 
     api_list=[] 
     print (new_user) 
     db = connection.cloud_native.users 
     user = db.find({'$or':[{"username":new_user['username']}     ,  
    {"email":new_user['email']}]}) 
     for i in user: 
       print (str(i)) 
       api_list.append(str(i)) 

     if api_list == []: 
       db.insert(new_user) 
       return "Success" 
     else : 
       abort(409) 

```

现在我们已经修改了我们的函数，还有一件事需要做——之前，ID 是由 SQLite 3 生成的，但现在，我们需要通过将其添加到其路由函数中使用随机模块来生成它们，如下所示：

```py
    def create_user(): 
     if not request.json or not 'username' in request.json or not 
    'email' in request.json or not 'password' in request.json: 
       abort(400) 
     user = { 
       'username': request.json['username'], 
       'email': request.json['email'], 
       'name': request.json.get('name',""), 
       'password': request.json['password'], 
       'id': random.randint(1,1000) 
     } 

```

让我们向用户列表添加一条记录，以测试它是否按预期工作。

以下截图显示了在 MongoDB 中使用 POSTMAN 添加新记录的输出状态：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00051.jpeg)

让我们验证是否已在 MongoDB 集合中更新了属性。

以下截图验证了我们的新记录已成功添加：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00052.jpeg)

# PUT api/v1/users/[user_id]

该 API 函数用于更新 MongoDB 用户集合中用户的属性。

为了更新 MongoDB 用户集合中特定用户的文档，我们需要将`upd_user(user)`方法重写如下：

```py
    def upd_user(user): 
     api_list=[] 
     print (user) 
     db_user = connection.cloud_native.users 
     users = db_user.find_one({"id":user['id']}) 
     for i in users: 
       api_list.append(str(i)) 
      if api_list == []: 
       abort(409) 
      else: 
       db_user.update({'id':user['id']},{'$set': user}, upsert=False ) 
       return "Success" 

```

现在我们已经更新了方法，让我们在 POSTMAN 上测试一下，并检查响应。

以下截图显示了使用 POSTMAN 进行更新 API 请求的响应：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00053.jpeg)

让我们验证用户文档，检查字段是否已修改：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00054.jpeg)

# DELETE api/v1/users

该 API 从用户列表中删除特定用户。

在这种情况下，我们将修改`del_user(del_user)`方法，以从 MongoDB 用户集合中删除用户，如下所示：

```py
    def del_user(del_user): 
     db = connection.cloud_native.users 
    api_list = [] 
    for i in db.find({'username':del_user}): 
       api_list.append(str(i)) 

     if api_list == []: 
       abort(404) 
    else: 
      db.remove({"username":del_user}) 
      return "Success" 

```

让我们在 POSTMAN 上测试一下，看看响应是否符合预期：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00055.jpeg)

现在我们已经删除了一个用户，让我们看看是否对整体用户列表造成了任何更改：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00056.jpeg)

太棒了！我们已经对用户资源的所有 RESTful API URL 进行了更改，并进行了验证。

# 处理推文资源

现在我们的用户资源 API 在 MongoDB 作为数据库服务上运行良好，我们将对推文资源做同样的操作。

# GET api/v2/tweets

此函数从所有用户获取所有推文的完整列表。

让我们更新我们的`list_tweets()`方法，开始使用以下代码片段从 MongoDB 的推文集合中获取推文列表：

```py
def list_tweets(): 
   api_list=[] 
   db = connection.cloud_native.tweet 
   for row in db.find(): 
       api_list.append(str(row)) 
   return jsonify({'tweets_list': api_list}) 

```

现在我们已经更新了代码，让我们在 POSTMAN 上测试一下。以下截图列出了通过 POSTMAN 使用 API 请求的所有推文：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00057.jpeg)

# GET api/v2/tweets/[user_id]

此函数从特定用户获取推文。

为了从推文集合中获取特定用户的推文，我们需要修改我们当前的`list_tweet(user_id)`函数如下：

```py
    def list_tweet(user_id): 
     db = connection.cloud_native.tweets 
     api_list=[] 
     tweet = db.find({'id':user_id}) 
     for i in tweet: 
       api_list.append(str(i)) 
    if api_list == []: 
       abort(404) 
    return jsonify({'tweet': api_list}) 

```

让我们测试一下我们的 API，并验证它是否按预期工作：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00058.jpeg)

# POST api/v2/tweets

此函数从现有用户添加新推文。

在这种情况下，我们需要修改我们的`add_tweet(new_tweet)`方法与用户进行交互，并在 MongoDB 中的推文集合中添加新推文，如下所示：

```py
    def add_tweet(new_tweet): 
     api_list=[] 
     print (new_tweet) 
     db_user = connection.cloud_native.users 
     db_tweet = connection.cloud_native.tweets 
     user = db_user.find({"username":new_tweet['tweetedby']}) 
     for i in user: 
       api_list.append(str(i)) 
     if api_list == []: 
      abort(404) 
     else: 
       db_tweet.insert(new_tweet) 
       return "Success" 

```

现在我们已经修改了记录，让我们测试一下。以下截图显示了使用 POSTMAN 添加新推文的`POST`请求的成功状态：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00059.jpeg)

现在让我们验证新添加的推文是否在推文列表中更新，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00060.jpeg)

# 总结

在本章中，我们将基于文件的数据库服务（SQLite）迁移到 NoSQL 文档型数据库服务（MongoDB）。您将学习如何将 MongoDB 与您的 RESTful API 集成，以响应客户端的请求并保存数据。下一章将更有趣，因为我们将使用 React 构建我们的前端 Web 视图。


# 第五章：使用 React 构建 WebViews

到目前为止，我们一直在构建我们的微服务，并使我们的后端服务更加响应和高效。此外，我们一直在尝试不同的数据库服务，这些服务可以保护并提高数据的存储和检索性能，这在这里是至关重要的。

在本章中，我们将专注于使用 React 构建我们的前端页面，并将这些页面与后端集成以形成一个完整的应用程序。

本章将涵盖的主题如下：

+   设置 React 环境

+   创建用户认证面板

+   将 React 与后端 API 集成

# 理解 React

简单来说，React 是你的应用程序的 UI 层。它是一个用于构建快速和快速用户界面的 JavaScript 库。React 基本上帮助你为你的应用程序的每个状态创建令人惊叹的 web 视图。因此，我们将使用 React 来实现这个目的。但在我们这样做之前，让我们了解 React 的一些概念/关键点，下面列出了这些概念/关键点：

+   **组件**：你的 HTML 和 JavaScript 的所有集合都被称为**组件**。React 基本上提供了渲染启用 JavaScript 的 HTML 页面的钩子。这里的重要一点是，React 作为控制器，用于渲染应用程序的不同状态的不同网页。

+   **React 中静态版本的 Props**：通常，在 HTML 中，你需要大量的代码来在前端显示所有数据，而且这是重复的。React 的 props 帮助你解决了这个问题。props 基本上保持数据的状态，并从父级传递值给子级。

+   **识别最小状态**：为了正确构建你的应用程序，你首先需要考虑你的应用程序需要的最小可变状态集。比如，在我们的情况下，我们需要在应用程序的不同状态下始终保持用户状态可用。

+   **识别活动状态**：React 的核心是组件层次结构中的单向数据流。我们需要了解每个基于该状态渲染内容的组件。此外，我们需要了解组件层次结构中状态如何改变。

+   **React-DOM**：react-dom 是 React 和 DOM 的组合。React 包含在 Web 和移动应用程序中使用的功能。react-dom 功能仅在 Web 应用程序中使用。

# 设置 React 环境

为了运行 React，我们需要设置一个初始环境，其中包括安装一些`node.js`的库。

# 安装 node

在开始安装 React 和包列表之前，我们需要在系统上安装`node.js`。

在 Linux（基于 Debian 的系统）中，安装过程非常简单。

首先，我们需要使用以下命令从`node.js`官方网站添加 PPA：

```py
$ sudo apt-get install python-software-properties
$ curl -sL https://deb.nodesource.com/setup_7.x | sudo -E bash -

```

一旦设置好，我们可以使用以下命令安装`node.js`：

```py
$ apt-get install nodejs 

```

现在让我们检查`node`和`npm`的版本，如下所示：

```py
$ npm -v
 4.1.2 
$ node -v
  V7.7.4 

```

在我们的设置中，我们使用了上述版本，但是 v7.x 左右的 node 版本应该可以，对于 npm，v4.x 应该可以。

# 创建 package.json

这个文件基本上是你的应用程序的元数据，其中包含需要为你的应用程序安装的完整库/依赖项。另一个现实世界的优势是，它使你的构建可复制，这意味着与其他开发人员分享变得更容易。有不同的方式可以创建你定制的`package.json`。

以下是在`packages.json`中需要提供的最少信息：

```py
    "Name" - lowercase.
    "version"  - in the form of x.x.x

    For example:

    {
      "name": "my-twitter-package",
      "version": "1.0.0"
    } 

```

为了创建`package.json`模板，你可以使用以下命令：

```py
$ npm init              # in your workspace  

```

它会要求填写诸如名称、版本、描述、作者、许可证等值；填写这些值，它将生成`package.json`。

如果你现在不想填写信息，你可以使用`--yes`或`-y`属性使用默认值，如下所示：

```py
$npm init --yes

```

对于我们的应用程序，我已经生成了类似以下内容的`package.json`：

```py
    { 
      "name": "twitter", 
      "version": "1.0.0", 
      "description": "Twitter App", 
      "main": "index.js", 
      "dependencies": { 
        "babel-loader": "⁶.4.1", 
        "fbjs": "⁰.8.11", 
        "object-assign": "⁴.1.1", 
        "react": "¹⁵.4.2", 
        "react-dev": "0.0.1", 
        "react-dom": "⁰.14.7", 
        "requirejs": "².3.3" 
      }, 
     "devDependencies": { 
       "babel-core": "⁶.4.5", 
       "babel-loader": "⁶.2.1", 
       "babel-preset-es2015": "⁶.3.13", 
       "babel-preset-react": "⁶.3.13", 
       "webpack": "¹.12.12" 
      }, 
    "scripts": { 
      "test": "echo \"Error: no test specified\" && exit 1" 
     }, 
    "author": "Manish Sethi", 
    "license": "ISC" 
   } 

```

现在，我们已经生成了`package.json`，我们需要使用以下命令在我们的工作站上安装这些依赖项：

```py
$ npm install 

```

请确保在执行上述命令时，`package.json`应该在当前工作目录中。

# 使用 React 构建 webViews

首先，我们将创建一个主页视图，从中将调用 React。所以，让我们创建`index.html`，它在模板目录中有以下内容：

```py
    <!DOCTYPE html> 
    <html> 
     <head lang="en"> 
      <meta charset="UTF-8"> 
      <title>Flask react</title> 
    </head> 
   <body> 
     <div class="container"> 
       <h1></h1> 
       <br> 
       <div id="react"></div> 

    </div> 

   <!-- scripts --> 
    <script src="img/jquery-2.1.1.min.js"></script> 
    <script src="img/
      react/15.1.0/react.min.js"></script> 
    <script src="img/react-
      router@2.8.1/umd/ReactRouter.min.js"></script> 
    <script src="img/
      libs/react/15.1.0/react-dom.min.js"></script> 
    <script src="img/
      react/0.13.3/JSXTransformer.js"></script> 

    </body> 
   </html> 

```

正如你在前面的 HTML 页面中所看到的，我们已经定义了`id="react"`，我们将使用它来根据 ID 调用 React 的主要函数，并执行某些操作。

所以，让我们创建我们的`main.js`，它将发送一个响应，代码如下：

```py
    import Tweet from "./components/Tweet"; 
    class Main extends React.Component{ 
    render(){ 
      return ( 
      <div> 
        <h1>Welcome to cloud-native-app!</h1> 
      </div> 
      ); 
    } 
   } 

   let documentReady =() =>{ 
    ReactDOM.render( 
    <Main />, 
     document.getElementById('react') 
    ); 
  }; 

  $(documentReady); 

```

现在我们已经定义了 React 响应的基本结构。由于我们正在构建具有多个视图的应用程序，我们需要一个构建工具，它将帮助我们将所有资产，包括 JavaScript、图像、字体和 CSS，放在一个包中，并将其生成为一个单一的文件。

**Webpack**是将帮助我们解决这个问题的工具。

Webpack 应该已经可用，因为我们在`package.json`中定义了 Webpack 包，我们之前安装过了。

Webpack 基本上读取一个入口文件，它可以是`.js`文件，读取它的子组件，然后将它们转换成一个单一的`.js`文件。

由于我们已经在`package.json`中定义了它，它已经安装好了。

在 Webpack 中，我们需要定义一个配置，它将帮助它识别入口文件和要用于生成单一`.js`文件的加载器。此外，你需要定义生成代码的文件名。

我们的 Webpack 配置应该是这样的：

```py
    module.exports = { 
      entry: "./static/main.js", 
      output: { 
        path: __dirname + "/static/build/", 
        filename: "bundle.js" 
      }, 
     resolve: { 
       extensions: ['', '.js', '.jsx'] 
     }, 
     module: { 
        loaders: [ 
            { test: /\.js$/, exclude: /node_modules/, loader: "babel-
        loader", query:{presets:['react','es2015']} } 
        ] 
     } 
   }; 

```

你可以根据你的用例扩展前面的配置。有时，开发人员尝试使用*.html 作为入口点。在这种情况下，你需要做出适当的更改。

让我们继续使用以下命令构建我们的第一个 webView：

```py
$ webpack -d  

```

最后一个命令中的`-d`属性用于调试；它生成另一个文件`bundle.js.map`，显示 Webpack 的活动。

由于我们将重复构建应用程序，我们可以使用另一个标志`--watch`或`-w`，它将跟踪`main.js`文件的更改。

所以，现在我们的 Webpack 命令应该是这样的：

```py
$ webpack -d -w

```

现在我们已经构建了我们的应用程序。记得在`app.py`中更改你的路由，这样主页应该被导航如下：

```py
    @app.route('/index') 
    def index(): 
     return render_template('index.html') 

```

让我们检查一下我们的主页现在是什么样子的。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00061.jpeg)

你也可以检查一下我们是否在检查模式下后台运行着 React 和 react-dom。

这是一个非常基本的结构，用于理解 React 的工作原理。让我们继续我们的用例，我们已经创建了 tweet webViews，用户也可以查看旧的 tweets。

所以，让我们创建`Tweet.js`，它将有 tweets 的基本结构，比如一个用于内容的文本框，和一个用于发布 tweets 的按钮。将以下代码添加到`Tweet.js`：

```py
    export default class Tweet extends React.Component { 

    render(){ 
     return( 
        <div className="row"> 
                </nav> 
        <form > 
          <div > 
            <textarea ref="tweetTextArea" /> 
            <label>How you doing?</label> 
              <button >Tweet now</button> 
          </div> 
         </form> 
        </div> 
        ); 
      } 
   } 

```

让我们从`main.js`中调用这个函数，这样它就会在主页上加载，通过更新`render`函数如下：

```py
    import Tweet from "./components/Tweet"; 
    render(){ 
      return ( 
      <div> 
        <Tweet /> 
      </div> 
     ); 
    } 

```

如果你现在加载页面，它将会非常简单。由于我们想要创建一个吸引人的 web 应用程序，我们将在这里使用一些 CSS 来实现。在我们的情况下，我们使用 Materialize CSS ([`materializecss.com/getting-started.html`](http://materializecss.com/getting-started.html))。

在`index.html`中添加以下代码块：

```py
    <link rel="stylesheet"  
      href="https://cdnjs.cloudflare.com/ajax/libs/
      materialize/0.98.1/css/materialize.min.css"> 
   <script src="img/
     materialize/0.98.1/js/materialize.min.js"></script> 

   Also, we need to update Tweet.js as follows 

   render(){ 
    return( 
        <div className="row"> 
         <form > 
          <div className="input-field"> 
            <textarea ref="tweetTextArea" className="materialize-
             textarea" /> 
            <label>How you doing?</label> 
              <button className="btn waves-effect waves-light
               right">Tweet now <i className="material-icons 
               right">send</i></button> 
          </div> 
         </form> 
       </div> 
      ); 
    } 

```

让我们尝试添加 tweets，并通过状态发送它们，以便显示一些 tweets。

在`main.js`的`Main`类中，添加以下构造函数来初始化状态：

```py
    constructor(props){ 
     super(props); 
     this.state =  { userId: cookie.load('session') }; 
     this.state={tweets:[{'id': 1, 'name': 'guest', 'body': '"Listen to 
     your heart. It knows all things." - Paulo Coelho #Motivation' }]} 
    } 

```

现在按照以下方式更新`render`函数：

```py
    render(){ 
      return ( 
      <div> 
         <TweetList tweets={this.state.tweets}/> 
      </div> 
      ); 
     } 
    } 

```

让我们创建另一个文件`TweetList.js`，它将显示 tweets，代码如下：

```py
    export default class TweetList extends React.Component { 
     render(){ 
        return( 
        <div> 
          <ul className="collection"> 
           <li className="collection-item avatar"> 
           <i className="material-icons circle red">play_arrow</i> 
           <span className="title">{this.props.tweetedby}</span> 
          <p>{this.props.body}</p> 
          <p>{this.props.timestamp}</p> 
          </li> 
         </ul> 
        </div> 
       ); 
      } 
     } 

```

太棒了！现在我们已经添加了这个模板。让我们检查一下我们的主页，看看 CSS 是如何工作的。但在此之前，由于我们正在使用 Webpack 进行构建，请确保每次都添加以下行以加载`bundle.js`-这将在`index.html`文件中运行 webView。

```py
    <script type="text/javascript" src="img/bundle.js">
     </script> 

```

太棒了！主页应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00062.jpeg)

让我们继续发布推文-我们应该能够添加新的推文，并且它们也应该在`TweetList.js`中更新。

让我们更新我们的`Tweet.js`代码，以便将推文发送到`main.js`进行处理。现在，我们需要将我们的推文发送到`main.js`，为此，我们需要使用以下代码更新我们的`Tweet.js`文件：

```py
    sendTweet(event){ 
      event.preventDefault(); 
      this.props.sendTweet(this.refs.tweetTextArea.value); 
      this.refs.tweetTextArea.value = ''; 
     } 

```

还要确保使用以下`form onSubmit`属性更新`render`函数：

```py
    <form onSubmit={this.sendTweet.bind(this)}> 

```

因此，在向文本区域添加内容后，它还应该提交推文。

现在，让我们更新`main.js`的`render`函数以添加新的推文，如下所示：

```py
    <Tweet sendTweet={this.addTweet.bind(this)}/> 

```

我们还需要在以下定义的`Main`类中添加`addTweet`函数：

```py
    addTweet(tweet): 
     let newTweet = this.state.tweets; 
     newTweet.unshift({{'id': Date.now(), 'name': 'guest','body':
      tweet}) 
     this.setState({tweets: newTweet}) 

```

在添加新推文后，您的页面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00063.jpeg)

目前，我们正在使用 React 来保存数组中的数据。由于我们已经构建了我们的微服务来保存这种数据，我们应该将我们的 webView 与后端服务集成。

# 将 webView 与微服务集成

为了将我们的微服务与 webView 集成，我们将使用 AJAX 进行 API 调用。

```py
main.js to pull our entire tweet list:
```

```py
    componentDidMount() { 
      var self=this; 
      $.ajax({url: `/api/v2/tweets/`, 
      success: function(data) { 
        self.setState({tweets: data['tweets_list']}); 
        alert(self.state.tweets); 
        return console.log("success"); 
       }, 
     error: function() { 
      return console.log("Failed"); 
      } 
    }); 

```

同样，我们需要修改我们`main.js`中的`addTweet`函数，如下所示：

```py
   addTweet(tweet){ 
     var self = this; 
     $.ajax({ 
       url: '/api/v2/tweets/', 
       contentType: 'application/json', 
       type: 'POST', 
       data: JSON.stringify({ 
         'username': "Agnsur", 
      'body': tweet, 
       }), 
       success: function(data) { 
            return console.log("success"); 
       }, 
       error: function() { 
         return console.log("Failed"); 
       } 
     }); 
    } 

```

由于将有多条推文需要使用相似的推文模板进行迭代，让我们创建另一个名为`templatetweet.js`的组件，并使用以下代码：

```py
    export default class Tweettemplate extends React.Component { 
     render(props){ 
      return( 
      <li className="collection-item avatar"> 
        <i className="material-icons circle red">play_arrow</i> 
        <span className="title">{this.props.tweetedby}</span> 
        <p>{this.props.body}</p> 
        <p>{this.props.timestamp}</p> 
      </li> 

      ); 
     } 
    } 

```

请记住，我们已根据我们的数据库集合键更改了 props 字段。

此外，我们需要更新我们的`TweetList.js`，以使用前面的模板，通过以下方式添加它：

```py
    import Tweettemplate from './templatetweet' 

    export default class TweetList extends React.Component { 
    render(){ 
     let tweetlist = this.props.tweets.map(tweet => <Tweettemplate key=
     {tweet.id} {...tweet} />); 
    return( 
        <div> 
          <ul className="collection"> 
            {tweetlist} 
          </ul> 
        </div> 
      ); 
     } 
    } 

```

太棒了！您的主页现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00064.jpeg)

# 用户身份验证

我们所有的推文都是受保护的，应该只对我们想展示给他们的观众做出反应。此外，匿名用户不应被允许发推文。为此，我们将创建一个数据库和网页，以使新用户能够登录并在推文 webView 中登录。请记住，我们将使用 Flask 来验证用户，并将数据发布到后端用户。

# 登录用户

让我们创建我们的登录页面模板，现有用户需要填写他们的用户名和密码进行身份验证。以下是代码片段：

```py
    <form action="/login" method="POST"> 
     <div class="login"> 
     <div class="login-screen"> 
     <div class="app-title"> 
      <h1>Login</h1> 
     </div> 

     <div class="login-form"> 
     <div class="control-group"> 

      <input type="text" class="login-field" value="" 
       placeholder="username" name="username"> 
      <label class="login-field-icon fui-user" for="login-name">
      </label> 
     </div> 

    <div class="control-group"> 
      <input type="password" class="login-field" value=""
       placeholder="password" name="password"> 
      <label class="login-field-icon fui-lock" for="login-pass">
      </label> 
    </div> 
     <input type="submit" value="Log in" class="btn btn-primary btn-
     large btn-block" ><br> 
     Don't have an account? <a href="{{ url_for('signup') }}">Sign up
     here</a>. 
   </div> 

```

我们将向登录页面发布数据，我们将在`app.py`文件中定义。

但首先，检查会话是否存在。如果没有，那么您将被重定向到登录页面。将以下代码添加到`app.py`中，它将验证用户的会话详细信息：

```py
   @app.route('/') 
   def home(): 
     if not session.get('logged_in'): 
        return render_template('login.html') 
     else: 
        return render_template('index.html', session =   
     session['username']) 

```

让我们为登录创建路由，并验证凭据以对用户进行身份验证。

以下是代码片段：

```py
    @app.route('/login', methods=['POST']) 
    def do_admin_login(): 
      users = mongo.db.users 
      api_list=[] 
      login_user = users.find({'username': request.form['username']}) 
      for i in login_user: 
        api_list.append(i) 
      print (api_list) 
      if api_list != []: 
         if api_list[0]['password'].decode('utf-8') == 
         bcrypt.hashpw(request.form['password'].encode('utf-8'), 
         api_list[0]['password']).decode('utf-8'): 
            session['logged_in'] = api_list[0]['username'] 
            return redirect(url_for('index')) 
        return 'Invalid username/password!' 
      else: 
        flash("Invalid Authentication") 

    return 'Invalid User!' 

```

完成后，您的登录页面将显示在根 URL，并且应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00065.jpeg)

正如您所看到的，我们提供了一个链接“立即注册”，以为新用户创建帐户。

请记住，我们正在使用 API 来从我们的数据库中的用户集合对用户进行身份验证。

# 注册用户

让我们继续创建我们的注册页面，以帮助注册新用户，以便他们也可以发推文。

让我们创建`signup.html`，它将要求用户提供详细信息。检查以下代码片段：

```py
     <div class="container"> 
      <div class="row"> 
        <center><h2>Sign up</h2></center> 
          <div class="col-md-4 col-md-offset-4"> 
              <form method=POST action="{{ url_for('signup') }}"> 
                  <div class="form-group"> 
                      <label >Username</label> 
                      <input type="text" class="form-control"
                        name="username" placeholder="Username"> 
                  </div> 
                  <div class="form-group"> 
                      <label >Password</label> 
                      <input type="password" class="form-control" 
                      name="pass" placeholder="Password"> 
                  </div> 
                  <div class="form-group"> 
                      <label >Email</label> 
                      <input type="email" class="form-control" 
                     name="email" placeholder="email"> 
                  </div> 
                  <div class="form-group"> 
                      <label >Full Name</label> 
                      <input type="text" class="form-control" 
                      name="name" placeholder="name"> 
                  </div> 
                  <button type="submit" class="btn btn-primary btn-
                     block">Signup</button> 
               </form> 
               <br> 
            </div> 
          </div> 
      </div> 

```

上述代码基本上是需要后端 API 将数据提交给用户的模板。

```py
app.py:
```

```py
    @app.route('/signup', methods=['GET', 'POST']) 
    def signup(): 
      if request.method=='POST': 
        users = mongo.db.users 
        api_list=[] 
        existing_user = users.find({'$or':  
        [{"username":request.form['username']} ,
         {"email":request.form['email']}]}) 
            for i in existing_user: 
              api_list.append(str(i)) 
            if api_list == []: 
              users.insert({ 
              "email": request.form['email'], 
              "id": random.randint(1,1000), 
              "name": request.form['name'], 
              "password": bcrypt.hashpw(request.form['pass'].
                encode('utf-8'), bcrypt.gensalt()), 
              "username": request.form['username'] 
            }) 
            session['username'] = request.form['username'] 
            return redirect(url_for('home')) 

          return 'That user already exists' 
      else : 
        return render_template('signup.html') 

```

用户注册后，它将设置会话，并将其重定向到您的主页。

您的注册页面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00066.jpeg)

我们已经验证了用户，但如果他想要更新个人信息怎么办？让我们创建一个个人资料页面，以帮助他们这样做。

# 用户资料

让我们创建一个个人资料页面（`profile.html`），用户在主页登录后可以在导航面板中访问。

将以下代码添加到`profile.html`：

```py
     <div class="container"> 
      <div class="row"> 
        <center><h2>Profile</h2></center> 
          <div class="col-md-4 col-md-offset-4"> 
              <form method=POST action="{{ url_for('profile') }}"> 
                  <div class="form-group"> 
                      <label >Username</label> 
                      <input type="text" class="form-control"
                       name="username" value='{{username}}'> 
                  </div> 
                  <div class="form-group"> 
                      <label >Password</label> 
                      <input type="password" class="form-control"
                      name="pass" value='{{password}}'> 
                  </div> 
                  <div class="form-group"> 
                      <label >Email</label> 
                      <input type="email" class="form-control" 
                      name="email" value={{email}}> 
                  </div> 
                  <div class="form-group"> 
                      <label >Full Name</label> 
                      <input type="text" class="form-control" 
                      name="name" value={{name}}> 
                  </div> 
                  <button type="submit" class="btn btn-primary btn-
                   block">Update</button> 
                </form> 
              <br> 
           </div> 
       </div> 
     </div> 

```

由于我们已经创建了个人资料，我们需要为个人资料创建一个路由，它将读取数据库以获取用户详细信息，并将 POST 回数据库。

```py
app.py:
```

```py
    def profile(): 
       if request.method=='POST': 
         users = mongo.db.users 
         api_list=[] 
         existing_users = users.find({"username":session['username']}) 
         for i in existing_users: 
            api_list.append(str(i)) 
         user = {} 
         print (api_list) 
         if api_list != []: 
            print (request.form['email']) 
            user['email']=request.form['email'] 
            user['name']= request.form['name'] 
            user['password']=request.form['pass'] 
            users.update({'username':session['username']},{'$set':
          user} ) 
        else: 
            return 'User not found!' 
        return redirect(url_for('index')) 
      if request.method=='GET': 
        users = mongo.db.users 
        user=[] 
        print (session['username']) 
        existing_user = users.find({"username":session['username']}) 
        for i in existing_user: 
            user.append(i) 
        return render_template('profile.html', name=user[0]['name'], 
        username=user[0]['username'], password=user[0]['password'], 
        email=user[0]['email']) 

```

一旦添加了这最后一部分代码，您的个人资料页面应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00067.jpeg)

此外，我们应该在导航模板的`Tweet.js`中添加个人资料链接，添加以下几行：

```py
      <li><a href="/profile">Profile</a></li> 
      <li><a href="/logout">Logout</a></li> 

```

现在您的主页应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00068.jpeg)

# 登出用户

```py
app.py:
```

```py
    @app.route("/logout") 
    def logout(): 
      session['logged_in'] = False 
      return redirect(url_for('home')) 

```

现在我们的应用程序已经完全构建起来，从用户登录，到提交他们的推文，然后退出登录。

# 测试 React webViews

由于我们正在构建 webViews，我们需要测试它们以在发生之前捕捉一些错误。此外，测试将帮助您构建更好的代码。

有许多 UI 测试框架可以帮助您测试 Web 应用程序。以下部分讨论了其中两个。

# Jest

Jest 是一个单元测试框架，由 Facebook 提供用于测试 JavaScript。它用于测试单个组件。它简单、标准且独立。

它基于虚拟 DOM 实现测试组件，并运行不同的测试来检查功能。它会自动解决依赖关系。此外，您可以并行运行所有测试。

您可以参考以下链接，这可以帮助您为 React 应用编写测试用例：

[`facebook.github.io/jest/docs/tutorial-react.html`](https://facebook.github.io/jest/docs/tutorial-react.html)

# Selenium

Selenium 是一个开源的、可移植的自动化软件测试工具，用于测试 Web 应用程序。它提供端到端测试，这意味着它是针对真实浏览器执行测试场景来测试多层应用程序堆栈的过程。

它具有以下不同的组件：

+   **IDE**：这可以帮助您描述测试工作流程。

+   **Selenium WebDriver**：这可以自动化浏览器测试。它直接发送命令到浏览器并接收结果。

+   **Selenium RC**：这个远程控制器可以帮助您创建测试用例。

+   **网格**：这在不同浏览器和并行运行测试用例。

这是您可以用来测试我们的 Web 应用程序的最佳工具之一，我强烈推荐使用。

您可以在[`www.seleniumhq.org/docs/`](http://www.seleniumhq.org/docs/)了解更多关于 Selenium 的信息。

# 摘要

在本章中，我们的重点是创建前端用户 webViews 以及如何改进它们以吸引消费者。您还学会了 React 如何帮助我们构建这些 webViews 并实现与后端服务的交互。在接下来的章节中，事情将变得更有趣，因为我们将玩转我们的前端应用程序，并解释如何使用 Flux 来处理来自互联网的大量请求。


# 第六章：使用 Flux 创建可扩展的 UI

在上一章中，我们为我们的应用程序创建了 Web 视图，还看到了前端和后端应用程序之间的集成，这对理解是非常重要的。

在本章中，我们将专注于构建我们的前端。理想情况下，每个模块应该负责一件事。就像我们的主要组件一样，我们在单个模块中运行了太多操作。除了渲染不同的视图之外，我们还有代码来向端点发出 API 请求并接收、处理和格式化响应。

在本章中，我们将涵盖以下主题：

+   理解 Flux

+   在 React 上实现 Flux

# 理解 Flux

**Flux**是 Facebook 创建的一种模式，用于使用 React 构建一致和稳定的 Web 应用程序。React 并不给你管理数据的能力；相反，它只是通过 props 和组件接受数据，而组件进一步处理数据。

React 库并不真正告诉你如何获取组件，或者在哪里存储数据，这就是为什么它被称为**视图层**。在 React 中，我们没有像 Angular 或 Backbone 那样的框架。这就是 Flux 的用武之地。Flux 并不是一个真正的框架，而是一种模式，它将让你构建自己的视图。

什么是 Flux 模式？我们有你的 React 组件，比如 Tweet 组件等等，在 Flux 模式中，这些组件会做两件事--它们要么执行动作，要么监听存储器。在我们的用例中，如果用户想要发布推文，组件需要执行动作，然后动作与存储器交互，更新模式到 API，并将响应给组件。以下图表将让你更清楚地了解 Flux：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00069.jpeg)

# Flux 概念

在继续之前，以下是你需要了解的 Flux 概念：

+   **动作**：这是组件与 API 端点交互并更新它们的方式。在我们的情况下，我们使用它发布新推文。动作将动作传输到调度器。它可能创建多个动作。

+   **调度器**：这会分发每一个事件，并将其发送给每一个订阅者，基本上就是存储器。

+   **存储器**：这是 Flux 的一个重要部分。组件总是监听存储器的任何更改。比如，如果你写了一条新推文，那就是一个动作，无论推文在存储器中更新到哪里，都会触发一个事件，并且组件会意识到它必须使用最新的数据进行更新。如果你来自 AngularJS 世界，存储器就是一个服务，或者如果你是 Backbone.js 的话，存储器只是一个集合。

+   **组件**：这用于存储动作名称。

我们将使用`JSX`文件而不是`JS`，因为它们之间没有太大的区别--`JS`是标准的 Javascript，而`JSX`是一种类似 HTML 的语法，你可以在 React 中使用它来轻松而直观地创建 React 组件。

# 向 UI 添加日期

在我们深入研究 Flux 之前，我们需要向我们的视图添加一个小功能，即日期功能。之前，你看到的是存储在数据库中的推文的时间，格式为**TZ**；然而，理想情况下，它应该与当前时间进行比较，并应该以此为参考显示。

为了做到这一点，我们需要更新我们的`main.jsx`文件，以便它可以格式化我们的推文。将以下代码添加到`main.jsx`中：

```py
    updatetweets(tweets){ 
        let updatelist = tweets.map(tweet => { 
         tweet.updatedate = moment(tweet.timestamp).fromNow(); 
         return tweet; 
       }); 
   }

```

我们的工作到此为止。现在，我们的推文应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00070.jpeg)

# 使用 Flux 构建用户界面

在 Flux 中，我们将定义每个模块的责任，并且它也应该是单一的。React 的责任是在数据发生变化时重新渲染视图，这对我们来说是很好的。我们所需要做的就是使用类似 Flux 这样的东西来监听这些数据事件，它将管理我们的数据。

使用 Flux，你不仅分离了模块的责任，还可以在应用程序中实现单向流动，这就是为什么 Flux 如此受欢迎。

在 Flux 循环中，对于每个模块，总是有一个方向要遵循。这种对流程的有意约束是使 Flux 应用程序易于设计、易于增长、易于管理和维护的原因。

以下图表将让您更清楚地了解 Flux 架构：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00071.jpeg)

对于图表，我参考了 Flux 存储库（[`github.com/facebook/flux`](https://github.com/facebook/flux)）。

# Actions 和 dispatcher

要开始使用 Flux，我们必须选择一个起点。可以是任何东西。我发现从 actions 开始是个不错的选择。您还必须选择一个流向。您可以顺时针或逆时针。顺时针对您来说可能是一个不错的起点，所以我们将这样做。

不要忘记使用以下命令直接安装 Flux 库：

```py
$ npm install flux --save

```

请注意，上述命令应该从我们的应用程序目录中执行，或者您可以将其添加到`package.json`中，并执行`npm install`来安装包。

现在，让我们从 action 作为起点开始，我们将遵循单一职责原则。我们将创建一个 actions 库来与 API 通信，并创建另一个 action 来与 dispatcher 通信。

让我们从静态目录中创建`actions`文件夹开始。我们将在这个目录中保存所有的 actions。

由于我们有两个需要执行的 actions--可能是列出 tweets 或添加新 tweets--我们将从列出 tweets 开始。创建一个`Tactions`文件，其中包含`getAllTweets`函数，该函数应该调用 REST API 来获取所有的 tweets，如下所示：

```py
   export default{ 
    getAllTweets(){ 
    //API calls to get tweets. 
    } 
   } 

```

我提到过基于 Flux 的应用程序易于设计，对吧？这就是原因。因为我们知道这个 actions 模块具有单一职责和单一流程--要么我们在这里提供 API 调用，要么最好调用一个模块来为应用程序进行所有 API 调用。

更新`Tactions.jsx`文件如下：

```py
    import API from "../API" 
     export default{ 
      getAllTweets(){ 
       console.log(1, "Tactions for tweets"); 
        API.getAllTweets(); 
      }, 
    } 

```

如您所见，我们导入了 API 模块，它将调用 API 来获取 tweets。

因此，让我们在静态目录中创建`API.jsx`，其中包含以下代码片段来从后端服务器获取 tweets：

```py
    export default{ 
      getAllTweets(){ 
       console.log(2, "API get tweets"); 
       $.getJSON('/api/v2/tweets', function(tweetModels) { 
          var t = tweetModels 
        // We need to push the tweets to Server actions to dispatch 
        further to stores. 
       }); 
      } 

```

在 actions 目录中创建`Sactions`文件，它将调用 dispatcher 并定义`actionType`：

```py
    export default{ 
      receivedTweets(rawTweets){ 
       console.log(3, "received tweets"); 
      //define dispatcher.     
     } 
   } 

```

如您所见，我们仍然需要定义 dispatcher。幸运的是，Facebook 创建了一个随 Flux 包一起提供的 dispatcher。

如前所述，**Dispatcher**是您的应用程序的中央枢纽，它分发**Actions**和注册回调的数据。您可以参考以下图表更好地理解数据流：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00072.jpeg)

创建一个名为`dispatcher.jsx`的新文件，其中将使用以下代码创建一个 dispatcher 的实例：

```py
    import Flux from 'flux'; 

    export default new Flux.Dispatcher();   

```

就是这样。现在您可以在应用程序的任何地方导入这个 dispatcher。

因此，让我们更新我们的`Sactions.jsx`文件，其中您将找到`receivedTweets`函数，如下所示的代码片段：

```py
    import AppDispatcher from '../dispatcher'; 
    receivedTweets(rawTweets){ 
      console.log(3, "received tweets"); 
      AppDispatcher.dispatch({ 
        actionType: "RECEIVED_TWEETS", 
         rawTweets 
      }) 
     } 

```

在`receivedTweets`函数中，有三件事需要描述。首先，`rawTweets`将从`API.jsx`中的`getAllTweets`函数接收，我们需要按照以下方式进行更新：

```py
   import SActions from './actions/SActions'; 

   getAllTweets(){ 
     console.log(2, "API get tweets"); 
     $.getJSON('/api/v2/tweets', function(tweetModels) { 
        var t = tweetModels 
        SActions.receivedTweets(t) 
    }); 

```

# Stores

Stores 通过控制应用程序内的数据来管理应用程序状态，这意味着 stores 管理数据、数据检索方法、dispatcher 回调等。

为了更好地理解，请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00073.jpeg)

现在我们已经定义了我们的 dispatcher，接下来，我们需要确定订阅者对 dispatcher 提供的更改。

在静态目录中的 stores 中创建一个单独的目录，其中将包含所有的 store 定义。

让我们创建一个`TStore`文件，它将订阅 dispatcher 发出的任何更改。将以下代码添加到`TStore`文件中：

```py
    import AppDispatcher from "../dispatcher"; 

    AppDispatcher.register(action =>{ 
     switch (action.actionType) { 
     Case "RECEIVED_TWEETS" : 
    console.log(4, "Tstore for tweets"); 
     break; 
      default: 
    } 
  }); 

```

在这一点上，我们已经开始了推文操作，向 API 模块发送消息以获取所有推文。API 执行了这一操作，然后调用服务器操作将数据传递给调度程序。然后，调度程序标记了数据并将其分发。我们还创建了基本上管理数据并从调度程序请求数据的存储。

目前，您的存储尚未与我们的应用程序连接。存储应该在发生更改时发出更改，并且基于此，视图也将发生更改。

因此，我们的主要组件对存储发出的更改事件感兴趣。现在，让我们导入我们的存储。

在我们继续之前，让我们看看我们的应用程序的完整流程是否正常工作。应该是这样的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00074.jpeg)

在达到应用程序创建的一定稳定状态后，继续检查用户界面是一个很好的做法。

让我们继续。目前，我们只是分发推文，接下来，我们需要决定如何处理这些推文。因此，让我们首先接收推文，然后相应地向视图发出更改。我们将使用发射器来做到这一点。

**Emitter**是我们之前使用`npm`安装的事件库的一部分。因此，我们可以从那里导入它。请注意，它不是默认导出，而是它的解构属性。然后，我们的存储将是此推文`EventEmitter`类的实例。

让我们按照以下方式更新我们的`TStore.jsx`文件：

```py
    import { EventEmitter } from "events"; 

    let _tweets = [] 
     const CHANGE_EVENT = "CHANGE"; 

     class TweetEventEmitter extends EventEmitter{ 
     getAll(){ 
       let updatelist = _tweets.map(tweet => { 
          tweet.updatedate = moment(tweet.timestamp).fromNow(); 
         return tweet; 
        }); 
     return _tweets; 
     } 
     emitChange(){ 
       this.emit(CHANGE_EVENT); 
     } 

     addChangeListener(callback){ 
      this.on(CHANGE_EVENT, callback); 
     } 
     removeChangeListener(callback){ 
       this.removeListener(CHANGE_EVENT, callback); 
    } 
   } 
   let TStore = new TweetEventEmitter(); 

   AppDispatcher.register(action =>{ 
    switch (action.actionType) { 
      case ActionTypes.RECEIVED_TWEETS: 
        console.log(4, "Tstore for tweets"); 
        _tweets = action.rawTweets; 
        TStore.emitChange(); 
      break; 
     } 
     }); 
    export default TStore; 

```

哇，一次理解这么多代码！让我们一部分一部分地理解它，以及代码的流程。

首先，我们将使用以下导入实用程序从事件包中导入`EventEmitter`库：

```py
   import { EventEmitter } from "events"; 

```

接下来，我们将在`_tweets`中存储接收到的推文，并更新`getAll()`函数中的推文，以便在视图中显示推文的时间与当前系统时间的参考：

```py
   getAll(){ 
     let updatelist = _tweets.map(tweet => { 
         tweet.updatedate = moment(tweet.timestamp).fromNow(); 
         return tweet; 
       }); 
     return _tweets; 
   }

```

我们还为视图创建了添加和删除更改事件侦听器的函数。这两个函数也只是围绕`EventEmitter`语法的包装。

这些函数接受由视图发送的`callback`参数。这些函数基本上是为了向视图添加或删除侦听器，以便开始或停止监听存储中的这些更改。将以下代码添加到`TStore.jsx`中以执行此操作：

```py

    addChangeListener(callback){ 
      this.on(CHANGE_EVENT, callback); 
    } 
    removeChangeListener(callback){ 
     this.removeListener(CHANGE_EVENT, callback); 
    } 

```

确保在控制台中没有任何更新后的代码错误。

让我们继续前进，即在主要组件中创建一个函数，从存储中提取数据并为组件的状态准备一个对象。

让我们在`main.jsx`中编写`getAppState()`函数，该函数维护应用程序的状态，如下所示：

```py
    let getAppState = () =>{ 
      return { tweetslist: TStore.getAll()}; 
    } 

```

如前所述，文件扩展名实际上并不重要，无论是`.js`还是`.jsx`。

现在，我们将从`Main`类中调用此函数，并且还将调用我们在`main.jsx`中创建的添加和删除侦听器函数，使用以下代码块：

```py
   import TStore from "./stores/TStore"; 

   class Main extends React.Component{ 
     constructor(props){ 
      super(props); 
      this.state= getAppState(); 
      this._onChange = this._onChange.bind(this); 
      //defining the state of component. 
     } 
   // function to pull tweets 
     componentDidMount() { 
     TStore.addChangeListener(this._onChange); 
    } 
   componentWillUnMount() { 
     TStore.removeChangeListener(this._onChange); 
    } 

   _onChange(){ 
    this.setState(getAppState()); 
    } 

```

此外，我们必须更新`render`函数以获取`Tweetslist`状态以在视图中显示，可以使用以下代码片段完成：

```py
    render(){ 
      return ( 
       <div> 
       <Tweet sendTweet={this.addTweet.bind(this)}/> 
          <TweetList tweet={this.state.tweetslist}/> 
       </div> 
       ); 
      } 

```

很棒，我们现在已经做了几乎所有的事情；我们的推文应该可以正常显示，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00075.jpeg)

太棒了！我们的应用程序运行正常。

如果您查看 Flux 的架构图，我们已经完成了 Flux 的流程一次，但我们仍然需要通过创建 API 来完成循环，以添加新推文。

让我们通过使用 Flux 发送新推文功能来实现它。我们将在`main.jsx`中进行一些更改。在`render`函数中，将`Tweetcall`更改为以下行的`addTweet`函数：

```py
    <Tweet sendTweet={this.addTweet.bind(this)}/> 

```

而不是使用参数调用`Tweet`组件，如下所示：

```py
    <Tweet /> 

```

此外，在`Tweet`组件中，我们将调用`TActions`模块来添加新推文。更新`Tweet`组件中的代码如下：

```py
    import TActions from "../actions/Tactions" 
    export default class Tweet extends React.Component { 
     sendTweet(event){ 
      event.preventDefault(); 
      // this.props.sendTweet(this.refs.tweetTextArea.value); 
      TActions.sendTweet(this.refs.tweetTextArea.value); 
      this.refs.tweetTextArea.value = ''; 
     } 

    } 

```

`Tweet`组件中的`Render`函数保持不变。

让我们添加一个新的 `sendTweet` 函数，它将调用后端应用程序的端点 URL 进行 API 调用，并将其添加到后端数据库。

现在，我们的 `Taction.jsx` 文件应该是这样的：

```py
   import API from "../API" 

  export default{ 
    getAllTweets(){ 
     console.log(1, "Tactions for tweets"); 
     API.getAllTweets(); 
    }, 
    sendTweet(body){ 
      API.addTweet(body); 
     } 
   } 

```

现在，在 `API.jsx` 中添加 `API.addTweet` 函数，它将进行 API 调用，并且还会更新推文列表的状态。将以下 `addTweet` 函数添加到 `API.jsx` 文件中：

```py
   addTweet(body){ 
      $.ajax({ 
          url: '/api/v2/tweets', 
          contentType: 'application/json', 
          type: 'POST', 
          data: JSON.stringify({ 
         'username': "Pardisturn", 
         'body': body, 
          }), 
       success: function() { 
            rawTweet => SActions.receivedTweet({ tweetedby:
            "Pardisturn",body: tweet, timestamp: Date.now}) 
        }, 
        error: function() { 
               return console.log("Failed"); 
         } 
      }); 
     } 

```

此外，我们正在将新添加的推文传递给服务器操作，以便将它们分派并可用于存储。

让我们添加一个新的函数 `receivedTweet`，它将分派它们。使用以下代码片段来实现：

```py
    receivedTweet(rawTweet){ 
      AppDispatcher.dispatch({ 
        actionType: ActionTypes.RECEIVED_TWEET, 
        rawTweet 
       }) 
     } 

```

`ActionTypes` 经常在静态目录的 `constants.jsx` 中定义。

现在，让我们在推文存储中定义 `RECEIVED_TWEET` 的 `actiontype` case，以便发出更改，以便视图进一步采取行动。以下是在 `TStore.jsx` 中定义的更新的 `Appdispatcher.register` 函数：

```py
   AppDispatcher.register(action =>{ 
    switch (action.actionType) { 
         case ActionTypes.RECEIVED_TWEETS: 
         console.log(4, "Tstore for tweets"); 
         _tweets = action.rawTweets; 
         TStore.emitChange(); 
          break; 
        case ActionTypes.RECEIVED_TWEET: 
          _tweets.unshift(action.rawTweet); 
          TStore.emitChange(); 
          break; 
       default: 

      } 
    }); 

```

现在，我们基本上已经完成了使用 Flux 添加新的推文模块，它应该完全正常工作，如下面的截图所示：

！[](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00076.jpeg)

现在，如果我们点击“立即推文”按钮，推文应该被添加，并且应该在下面的面板中显示，如下所示：

！[](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00077.jpeg)

# 摘要

在本章中，您学习了如何使用 Flux 模式来构建我们的应用程序，并且我们也了解了 Flux 的不同概念，比如分发器、存储等。Flux 为您提供了良好的模式来在模块之间分配责任，这确实需要被理解，因为我们正在为云平台开发应用程序，比如 AWS、Azure 等，所以我们的应用程序应该具有高度的响应性。这就是我们从构建用户界面方面所拥有的一切，但在接下来的章节中，我们将了解一些重要的概念，比如事件溯源，以及如何通过使用不同的身份验证方法使应用程序更加安全。


# 第七章：学习事件溯源和 CQRS

在上一章中，我们看了看当前业务模型的缺点，现在，在本章中，我们将看看事件溯源（ES）和命令查询责任分离（CQRS）如何有助于克服这些问题。

在本章中，我们将讨论一些处理大规模可扩展性的架构设计。我们还将研究事件溯源和 CQRS 这两种模式，这些模式都是为了解决如此大量请求的问题响应行为。

我们许多人认为遵守十二要素应用程序将使我们的应用程序成为具有更高可扩展性的云原生应用程序，但是还有其他策略，比如 ES 和 CQRS，可以使我们的应用程序更可靠。

由于云原生应用程序面向互联网，我们期望来自不同来源的成千上万甚至数百万的请求。实施基础架构架构来处理请求的扩展或缩小是不够的。您需要使您的应用程序支持如此巨大的扩展。这就是这些模式出现的时候。

本章将涵盖的主题如下：

+   事件溯源介绍

+   介绍命令查询责任分离

+   实现 ES 和 CQRS 的示例代码

+   使用 Apache Kafka 进行事件溯源

# 介绍

让我们从审查*n*层架构开始，其中我们有一些客户端、网络、业务模型、一些业务逻辑、一些数据存储等等。这是一个基本模型，您会发现它作为任何架构设计的一部分。它看起来像下面的图表：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00078.jpeg)

正如您在这个架构中所看到的，我们有这些不同的模型在起作用：

+   视图模型：这基本上是为客户端交互而设计的

+   DTO 模型：这是客户端和 REST 端点之间的通信

+   业务模型：这是 DAO（数据访问对象）和业务服务的组合，解释用户请求，并与存储服务通信

+   E-R 模型：这定义了实体之间的关系（即 DTO 和 RDMS/NDMS）

现在您对架构有了一些了解，让我们了解其特点，如下所示：

+   应用程序的相同堆栈：在这个模型中，我们对所有读写操作使用相同的元素堆栈，从 REST API 到业务服务，然后访问存储服务等等，因为所有不同的组件代码都作为单个实体一起部署。

以下图表显示了通过不同模型的读/写操作流程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00079.jpeg)

+   相同的数据模型：在这种情况下，您会发现大多数情况下，我们用于业务逻辑处理或读写数据的数据模型相同或类似。

+   部署单元：我们使用粗粒度的部署单元，包括以下内容：

+   一个构建（一组可执行的组件）

+   文档（最终用户支持材料和发布说明）

+   安装工件，将读取和写入代码结合在一起

+   直接访问数据：如果我们想要更改数据，通常我们会继续。特别是在关系型数据库的情况下，我们直接更改数据，如下例--如果我们想要使用另一个数据集更新**用户 ID** **1**的行，我们通常会直接这样做。而且，一旦我们更新了这个值，旧值将从应用程序以及存储端无效，并且无法检索！[](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00080.jpeg)

到目前为止，我们一直在使用前面的方法，并且我会说，就用户请求的响应而言，它在很大程度上是经过验证和成功的。然而，与之相比，还有其他替代方法可以表现得更好。

让我们讨论上述业务架构方法的缺点，如下所示：

+   **无法独立扩展**：由于我们的读写操作代码驻留在同一位置，我们无法独立扩展应用程序的读取或写入。假设在特定时间点，应用程序的读取占 90%，写入占 10%，我们无法独立扩展读取。为了扩展读取，我们需要扩展整个架构，这是没有用的，还会增加资源的浪费。

+   **没有数据历史**：由于我们处理的是直接更新数据的情况，一旦数据更新，应用程序将在一段时间后开始显示最新的数据集。此外，一旦数据集更新，旧的数据值就不会被跟踪，因此会丢失。即使我们想要实现这种功能，我们也需要编写大量的代码来启用它。

+   **单片式方法**：这种方法往往是一种单片式方法，因为我们试图将事物合并在一起。此外，我们有粗粒度的部署单元，并且我们试图将不同组件的代码放在一起。因此，这种方法最终会导致一团糟，很难解决。

解决这些挑战的一种方法是事件溯源。

# 理解事件溯源

简单来说，事件溯源是一种架构模式，它通过一系列事件来确定应用程序的状态。

理解事件溯源的最佳方法是使用类比。其中一个最好的例子就是**在线购物**，这是一个事件处理系统。有人下订单，订单被注册到供应商订购系统的订单队列中。然后，订单在不同阶段被通知给客户。

所有这些事件一个接一个地发生，形成了一个称为事件流的事件序列，应该看起来像以下图表所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00081.jpeg)

因此，事件溯源考虑了过去发生的事件，并记录了基于某些交易进行处理。

理想的事件溯源系统是基于以下图表中显示的构建模块的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00082.jpeg)

前面的图表描述了一个理想的事件处理系统，从应用程序开始到创建与某个事件相关的**事件**，然后将它们放入**事件队列**进行进一步处理，由**事件处理程序**执行。根据**事件**的描述，**事件处理程序**相应地处理它们，并将它们注册到**存储**中。

事件溯源遵循某些法则/原则，这使得应用程序开发成为一个有结构和纪律的过程。大多数人通常觉得事件溯源很难，或者他们认为它是绝对的，因为这些原则不能被打破，否则会在应用程序中造成巨大的混乱。

# 事件溯源的法则

以下是一些事件溯源法则，需要在任何系统（即应用程序设计）中实施时保持：

+   **幂等性**：理想的事件溯源业务逻辑必须是幂等的。这意味着当您针对一系列数据执行业务逻辑时，应用程序的结果状态将始终保持不变。是的，无论您执行业务逻辑的次数如何，它的结果状态都将保持不变。

+   **隔离**：事件溯源不应依赖外部事件流。这是事件溯源的最重要原则之一。通常，业务逻辑很少在真空中执行。应用程序通常与外部实体进行交互以进行参考。此外，应用程序使用来自外部来源的缓存信息，即使开发人员没有考虑到这一点。现在，出现的问题是，如果您的业务逻辑使用外部输入来计算结果会发生什么？让我们以股票交易为例，股票价格不断变化，这意味着在状态计算时的股价在多次评估中不会相同，这违反了幂等规则。

根据开发人员的理解，这是一个非常难以满足的条件。然而，处理这个问题的解决方案是从外部事件向主事件流中注入通知。由于这些通知现在是主事件流的一部分，您将每次都得到预期的结果。

+   **质量保证**：一个经过完全开发的事件溯源应用程序应该是一个经过充分测试的应用程序。为事件溯源应用程序编写测试用例很容易--通常需要一系列输入并返回一些状态，考虑到您是按照先前定义的原则编写测试用例。

+   **可恢复性**：事件溯源应用程序应支持恢复和重放。如果您有一个符合十二要素应用程序所有指南的云原生应用程序，以创建适合云平台的应用程序，事件溯源在灾难恢复中发挥着重要作用。

假设事件流是持久的，事件溯源应用程序的初始优势是计算应用程序的状态。通常，在云环境中，由于多种原因可能导致应用程序崩溃；事件溯源可以帮助我们识别应用程序的最后状态，并快速恢复以减少停机时间。此外，事件溯源的重放功能使您能够在审计和故障排除时查看过去的状态。

+   **大数据**：事件溯源应用程序通常会生成大量数据。由于事件溯源应用程序跟踪每个事件，可能会生成大量数据。这取决于您有多少事件，它们多频繁到达，以及事件的数据负载有多大。

+   **一致性**：事件溯源应用程序通常会保持事件注册的一致性。想想银行交易--银行交易期间发生的每个事件都非常重要。应该注意，在记录时应保持一致性。

非常重要的是要理解这些事件是过去发生的事情，因为当我们命名这些事件时，它们应该是可以理解的。一些有效的事件名称示例可能如下：

+   `PackageDeliveredEvent`

+   `UserVerifiedEvent`

+   `PaymentVerifiedEvent`

无效的事件将被命名如下：

+   `CreateUserEvent`

+   `AddtoCartEvent`

以下是一个事件的示例代码：

```py
    class ExampleApplication(ApplicationWithPersistencePolicies): 
      def __init__(self, **kwargs): 
        super(ExampleApplication, self).__init__(**kwargs) 
       self.snapshot_strategy = None 
       if self.snapshot_event_store: 
           self.snapshot_strategy = EventSourcedStrategy( 
               event_store=self.snapshot_event_store, 
           ) 
       assert self.integer_sequenced_event_store is not None 
       self.example_repository = ExampleRepository( 
           event_store=self.integer_sequenced_event_store, 
           snapshot_strategy=self.snapshot_strategy, 
       ) 

```

有一些要注意的要点：

+   每个事件都是不可变的，这意味着一旦触发了事件，就无法撤销。

+   您永远不会删除事件。即使我们试图删除事件，我们也将删除视为一个事件。

+   事件流由消息代理架构驱动。一些消息代理包括 RabbitMQ、ActiveMQ 等。

现在，让我们讨论事件溯源的一些优点，如下所示：

+   事件溯源能够快速重建系统

+   事件溯源使您对数据具有控制权，这意味着我们需要的处理数据可以通过查看事件流轻松获取，比如审计、分析等

+   通过查看事件，很容易理解在一段时间内发生了什么错误，考虑到一组数据

+   事件重放在故障排除或错误修复期间会有优势

现在，问题出现了，由于我们生成了如此大量的事件，这是否会影响应用程序的性能？我会说，是的！

由于我们的应用程序为每个需要由事件处理程序处理的事务生成事件，因此应用程序的响应时间得到了缩短。解决这个问题的方法是 CQRS。

# CQRS 简介

命令查询职责分离是一个花哨的模式名称，意味着解耦系统的输入和输出。在 CQRS 中，我们主要讨论应用程序的读和写特性；因此，在 CQRS 的上下文中，命令主要是写操作，而查询是读操作，责任意味着我们分离了读和写操作。

如果我们看一下第一部分介绍中描述的架构，并应用 CQRS，那么架构将被分成两半，看起来会是这样的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00083.jpeg)

现在我们将看一些代码示例。

传统的接口模块会是这样的：

```py
    Class managementservice(interface): 
     Saveuser(userdata); 
    Updateuser(userid); 
    listuserbyusername(username); 
    listuserbyid(userid); 

```

分离，或者我更喜欢称之为 CQRS-化的接口，会是这样的：

```py
    Class managementcommandservice(interface): 
      Saveuser(userdata); 
    Updateuser(userid); 
    Class managementqueryservice(interface): 
    listuserbyusername(username); 
    listuserbyid(userid); 

```

因此，在实施 CQRS 和事件溯源后，整体架构会像下图所示的那样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00084.jpeg)

这是在实施事件溯源和 CQRS 后的完整架构。

在经典的单体应用中，您有写入数据库的端点和从中读取的端点。相同的数据库用于读取和写入操作，并且在从数据库接收到确认或提交之前，不会回复端点。

在大规模情况下，具有高入站事件吞吐量和复杂事件处理要求，您不能承受读取慢查询，也不能每次获得新的入站事件时等待处理。

读和写操作的流程如下：

+   **写模型**：在这种情况下，当从端点触发命令并在**命令业务服务**接收到时，首先为每个事件发出事件到**事件存储**。在**事件存储**中，您还有一个**命令处理器**，或者换句话说，事件处理程序，这个**命令处理器**能够将应用程序状态派生到一个单独的**存储**中，这可能是一个关系型存储。

+   **读模型**：在**读**模型的情况下，我们只需使用**查询端点**来查询客户端想要**读取**或检索的数据，以供应用程序使用。

最大的优势是我们不需要通过**写**模型（在前图的右侧）进行。在查询数据库时，这个过程使我们的查询执行更快，并减少了响应时间，从而提高了应用程序的性能。

# CQRS-化架构的优势

这种架构有以下优点：

+   **独立的可伸缩性和部署**：现在我们可以根据其使用情况扩展和部署单个组件。就像微服务的情况一样，我们现在可以为每个任务拥有单独的微服务，比如一个读微服务和一个写微服务，在这个架构堆栈中。

+   **技术选择**：在业务模型的不同部分选择技术的自由。例如，对于命令功能，我们可以选择 Scala 或类似的语言（假设我们有一个复杂的业务模型，并且有大量数据要写入）。在查询的情况下，我们可以选择，例如，ROR（Ruby on Rails）或 Python（我们已经在使用）。

这种类型的架构最适合于**DDD**（领域驱动设计）的有界上下文，因为我们可以为微服务定义业务上下文。

# 与 ES 和 CQRS 相关的挑战

每种架构设计模型在实施时都有自己的挑战。让我们讨论 ES 和 CQRS 的挑战：

+   **不一致性**：使用 ES 和 CQRS 开发的系统大多是一致的。然而，由于我们在**事件存储**中存储**命令业务服务**发出的事件，并且在主**存储**中也存储应用程序的状态，我会说这种系统并不完全一致。如果我们真的想使用 ES 和 CQRS 使我们的系统完全一致，我们需要将我们的**事件存储**和主**存储**放在一个单一的**关系数据库**上，我们的**命令处理器**应该处理所有我们的传入事件，并同时将它们存储在两个存储中，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00085.jpeg)

我认为一致性水平应该由对业务领域的理解来定义。需要了解事件中需要多少一致性，以及这些一致性会带来多大的成本。在检查业务领域之后，您将能够考虑上述因素做出这些决定。

+   **验证**：当我们谈论验证客户注册表单时，这非常容易，我们需要验证各个字段等等。但实际的验证是在我们需要基于唯一性进行验证时--比如说我们有一个具有特定用户凭据（用户名/密码）的客户。因此，确保用户名是唯一的是一个关键的验证，当我们有超过 200 万需要注册的客户时。在验证方面需要问一些问题，如下所示：

+   验证的数据需求是什么？

+   从哪里检索验证数据？

+   验证的概率是多少？

+   验证失败对业务的影响是什么？

+   **并行数据更新**：这在数据一致性方面非常重要。比如说，您有一个用户想要在同一时间或在纳秒的差距内更新某些记录。在这种情况下，一致性和验证检查的可能性是具有挑战性的，因为有可能一个用户可能会覆盖另一个用户的信息，这可能会造成混乱。

# 克服挑战

在事件源中解决这样的问题的一种方法是在事件中添加版本，这将作为对数据进行更改的处理，并确保它得到充分验证的处理。

# 问题解决

让我们以以下图表中显示的用例为例，以了解在编写代码时如何理解事件源和 CQRS：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00086.jpeg)

# 解释问题

在这种情况下，我们提供了**用户详细信息**，如**用户 ID**（应该是唯一的），**用户名**，**密码**，**电子邮件 ID**等等，我们需要创建两个要触发的写**命令**--**UserRegistrationCommand**和**UpdatePasswordCommand**，触发两个**事件**：**UserRegisterEvents**和**UpdatePasswordEvents**。这个想法是，一旦注册用户，就应该能够根据他们的需求重置密码。

# 解决方案

为了解决这个问题，我们需要编写与写命令相关的函数来接收输入并更新事件存储。

现在，让我们将以下代码添加到`commands.py`文件中，其中将包含需要执行的写命令相关的代码：

```py
   class userregister(object): 
     def __init__(self, user_id, user_name, password, emailid): 
       self.user_id = user_id 
       self.user_name = user_name 
       self.password = password 
       self.emailid = emaild 

   class updatepassword(object): 
     def __init__(self, user_id, new_password, original_version): 
       self.item_id = item_id 
       self.new_password = new__password 
       self.original_version = original_version 

```

因此，我们已经添加了与命令相关的函数，但它应该从某个地方调用用户详细信息。

让我们添加一个名为`main.py`的新文件，从这里将调用前面命令的函数。

在下面的代码中，我们通过触发事件来调用前面的代码：

```py
    from aggregate import Aggregate 
    from errors import InvalidOperationError 
    from events import * 

   class userdetails(Aggregate): 
     def __init__(self, id = None, name = '"", password = "", emailid =
     "" ): 
       Aggregate.__init__(self) 
       self._apply_changes(Userdetails(id, name, password, emailid)) 

   def userRegister(self, userdetails): 
       userdetails = {1, "robin99", "xxxxxx", "robinatkevin@gmail.com" 
   } 
       self._apply_changes(UserRegisterevent(userdetails)) 

   def updatePassword(self, count):        
      password = "" 
       self._apply_changes(UserPasswordEvent(password)) 

```

让我们逐个理解前面的代码：

```py
    def __init__(self, id = None, name = '"", password = "", emailid =
     "" ): 
       Aggregate.__init__(self) 
       self._apply_changes(Userdetails(id, name, password, emailid)) 

```

最后的代码初始化了`self`对象的一些默认值；这类似于任何编程语言中的初始化函数。

接下来，我们定义了`userRegister`函数，基本上收集`userdetails`，然后创建事件（`UserRegisterevent(userdetails))`）如下：

```py
    def userRegister(self, userdetails): 
       userdetails = {1, "robin99", "xxxxxx", "robinatkevin@gmail.com"
    } 
       self._apply_changes(UserRegisterevent(userdetails)) 

```

因此，一旦用户注册，他/她就有权更新配置文件详细信息，这可能是电子邮件 ID、密码、用户名等--在我们的情况下，是密码。请参考以下代码：

```py
     def updatePassword(self, count):        
      password = "" 
     self._apply_changes(UserPasswordEvent(password))

```

您可以编写类似的代码来更新电子邮件 ID、用户名或其他信息。

接下来，我们需要添加错误处理，因为在我们的`main.py`文件中，我们调用一个自定义模块`errors`来处理与操作相关的错误。让我们将以下代码添加到`errors.py`中以传递捕获的错误：

```py
    class InvalidOperationError(RuntimeError): 
     pass 

```

正如您在`main.py`中所看到的，我们调用`Aggregate`模块，您一定想知道为什么要使用它。`Aggregate`模块非常重要，因为它跟踪需要应用的更改。换句话说，它强制事件将其所有未注释的更改提交到事件存储。

为了做到这一点，让我们将以下代码添加到一个名为`aggregate.py`的新文件中：

```py
   class Aggregate(object): 
     def __init__(self): 
       self.uncommitted_changes = [] 

     @classmethod 
     def from_events(cls, events): 
       aggregate = cls() 
       for event in events: event.apply_changes(aggregate) 
       aggregate.uncommitted_changes = [] 
       return aggregate 

    def changes_committed(self): 
       self.uncommitted_changes = [] 

    def _apply_changes(self, event): 
       self.uncommitted_changes.append(event) 
       event.apply_changes(self) 

```

在`aggregate.py`中，我们初始化了`self`对象，该对象在`main.py`中被调用，然后跟踪被触发的事件。一段时间后，我们将调用`main.py`中的更改来更新`eventstore`的更新值和事件。

```py
events.py:
```

```py
   class UserRegisterEvent(object): 
    def apply_changes(self, userdetails): 
       id = userdetails.id 
       name = userdetails.name 
       password = userdetails.password 
       emailid = userdetails.emailid 

   class UserPasswordEvent(object): 
    def __init__(self, password): 
       self.password = password 

    def apply_changes(password): 
       user.password = password 

```

现在我们还剩下命令处理程序，这非常重要，因为它决定了需要执行的操作以及需要触发的相应事件。让我们添加名为`command_handler.py`的文件，并添加以下代码：

```py
    from commands import * 

    class UserCommandsHandler(object): 
     def __init__(self, user_repository): 
       self.user_repository = user_repository 

     def handle(self, command): 
       if command.__class__ == UserRegisterEvent: 
           self.user_repository.save(commands.userRegister(command.id, 
     command.name, command.password, command.emailid)) 
       if command.__class__ == UpdatePasswordEvent: 
           with self._user_(command.password, command.original_version)
      as item: 
               user.update(command.password) 
   @contextmanager 
     def _user(self, id, user_version): 
       user = self.user_repository.find_by_id(id) 
       yield user 
       self.user.save(password, user_version) 

```

在`command_handler.py`中，我们编写了一个处理函数，它将决定事件执行流程。

正如您所看到的，我们调用了`@contextmanager`模块，在这里非常重要。

让我们来看一个场景：假设有两个人，Bob 和 Alice，两者都使用相同的用户凭据。假设他们都试图同时更新配置文件详细信息字段，例如密码。现在，我们需要了解这些命令是如何请求的。简而言之，谁的请求会先到达事件存储。此外，如果两个用户都更新密码，那么很可能一个用户的更新密码将被另一个用户覆盖。

解决问题的一种方法是在用户模式中使用版本，就像我们在上下文管理器中使用的那样。我们将`user_version`作为参数，它将确定用户数据的状态，一旦修改，我们可以增加版本以使数据一致。

因此，在我们的情况下，如果 Bob 的修改值首先更新（当然，使用新版本），如果 Alice 的请求版本字段与数据库中的版本不匹配，则 Alice 的更新请求将被拒绝。

一旦更新完成，我们应该能够注册和更新密码。虽然这只是一个示例，展示了如何实现 CQRS，但您可以扩展它以在其上创建微服务。

# Kafka 作为事件存储

尽管我们已经看到了 CQRS 的实现，但我仍然觉得您可能对`eventstore`及其工作方式有一些疑问。这就是为什么我将采用 Kafka 的用例，它可以用作应用程序的`eventstore`。

Kafka 通常是一个消息代理或消息队列（类似于 RabbitMQ、JMS 等）。

根据 Kafka 文档，事件溯源是一种应用设计风格，其中状态更改被记录为时间顺序的记录序列。Kafka 对非常大的存储日志数据的支持使其成为构建此风格的应用程序的优秀后端。

有关实施 Kafka 的更多信息，请阅读此链接上的文档：[`kafka.apache.org/documentation/`](https://kafka.apache.org/documentation/)。

Kafka 具有以下基本组件：

+   **生产者**：将消息发送到 Kafka

+   **消费者**：这些订阅 Kafka 中的消息流

Kafka 的工作方式如下：

+   生产者在 Kafka 主题中写入消息，这些消息可能是用户

+   在 Kafka 主题中的每条消息都会被追加到分区的末尾

Kafka 只支持**写**操作。

+   分区代表事件流，主题可以被分类为多个主题

+   主题中的分区彼此独立。

+   为了避免灾难，Kafka 分区会被复制到多台机器上

+   为了消费 Kafka 消息，客户端按顺序读取消息，从在 Kafka 中由消费者设置的偏移开始

# 使用 Kafka 应用事件溯源

让我们来看一个使用案例，客户端尝试执行某个操作，我们使用 Kafka 作为事件存储来捕获所有传递的消息。在这种情况下，我们有用户管理服务，它可能是负责管理所有用户请求的微服务。我们将从基于用户事件的 Kafka 主题开始识别主题，可能是以下之一：

+   `UserCreatedEvent`

+   `UserUpdatedEvent`

+   `UserDeletionEvent`

+   `UserLoggedinEvent`

+   `UserRoleUpdatedEvent`

这些事件理想情况下将由**用户管理服务**发布，并且所有微服务都将消费这些事件。以下图表显示了用户请求流程：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00087.jpeg)

# 工作原理

用户向 API 网关发出`POST`请求，这是用户管理服务注册用户的入口点。API 网关反过来调用管理服务中的`createUser`方法。`createUser`端点对用户输入进行一系列验证。如果输入无效，它将抛出异常，并将错误返回给 API 网关。一旦用户输入被验证，用户将被注册，并且将触发`UserCreatedEvent`以在 Kafka 中发布。在 Kafka 中，分区捕获事件。在我们的示例中，用户主题有三个分区，因此事件将根据一些定义的逻辑发布到三个分区中的一个；这个逻辑由我们定义，根据用例的不同而变化。

所有读取操作，比如列出用户等，都可以直接从 readStore（如 PostgreSQL 等数据库）中检索出来。

# 总结

这是一个复杂的章节，但如果你完全理解了它，它将使你的应用程序高效且性能卓越。

我们首先了解了经典架构的缺点，然后讨论了 ES 和 CQRS 的概念和实现。我们还看了一个示例问题的实现。我们谈到了为什么这些模式有用，以及它们如何与大规模、云原生应用程序特别协调。

在接下来的章节中，我们将深入探讨应用程序的安全性。敬请关注！
