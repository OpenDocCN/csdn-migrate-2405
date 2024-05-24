# JavaScript 数据结构和算法实用手册（三）

> 原文：[`zh.annas-archive.org/md5/929680AA3DCF1ED8FDD0EBECC6F0F541`](https://zh.annas-archive.org/md5/929680AA3DCF1ED8FDD0EBECC6F0F541)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用图简化复杂应用程序

定义图的最简单方法是任何由边连接的节点集合。图是计算机科学中使用的最流行的数学概念之一。图的常见实现示例是任何社交媒体网站。Facebook 使用*朋友*作为节点，*友谊*作为边；而 Twitter 则将*追随者*定义为节点，*关注*作为边，依此类推。看一下下面的图像：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/d8be5138-4d0c-4624-9c82-e933197e3fd2.png)

在上述图像中，你可以看到一个典型的图，有*节点*和*边*。正如你所注意到的，我们的边没有列出方向，节点也没有详细信息。这是因为有不同类型的图，节点和边在这些不同类型的图之间略有不同，我们将在接下来的部分中看到。

在本章中，我们将首先讨论以下主题：

1.  图的类型

1.  为求职门户网站创建一个参考生成器

1.  创建一个朋友推荐系统

# 图的类型

根据前面的描述，我们可以推测出图的类型。有太多类型要在本章甚至本书中涵盖。然而，让我们来看一些最重要和最流行的图，我们将在本章中通过示例来探索：

+   **简单图**：简单图是一个无向、无权重的图，不包含循环或多边（即两个节点之间的多条边，也称为平行边）节点：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/c6c9cd6b-d1fe-4904-bc9d-15317644dfc0.png)

+   **无向图**：这是一个图，其中边的定义是可互换的。例如，在下面的图像中，节点**1**和**2**之间的边可以表示为(1,2)或(2,1)。因此，节点之间通过一条没有箭头指向任何节点的线连接：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/6f480d4b-8a1a-4a4c-937a-589b08501a32.png)

+   **有向图**：这是一个图，其中边根据功能或逻辑条件给定预定义方向。边用箭头绘制，表示流动的方向，例如 Twitter 上的一个用户关注另一个用户。看一下下面的图像：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/bf89bad9-4cda-460f-a26a-d7fe494e145d.png)

+   **循环图**：这是一个图，其中边形成节点之间的循环连接，即起始和结束节点相同。例如，在下面的图像中，我们可以注意到节点**1** >> **5** >> **6** >> **7** >> **3** >> **1**形成了图中的循环：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/bf89bad9-4cda-460f-a26a-d7fe494e145d.png)

+   **有向无环图**：这是一个没有循环的有向图。这是最常见的图的类型。在下面的例子中，节点是**1**、**2**、**3**、**4**、**5**、**6**、**7**，边是{(1, 2), (1, 3), (1, 5), (2, 4), (4, 3), (4, 6), (5, 4), (5, 6), (6, 7), (7, 3)}：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/46f3b2e7-694f-4ce4-a7b9-f6550d0016d6.png)

+   **加权图**：这是一个图，其中边根据穿越该边的成本或便宜程度被分配数值权重。每条边的权重的使用可以根据用例而变化。在下面的例子中，你可以注意到图之间的边被分配了权重(**0**、**1**、**3**或**5**)：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/c6e00e40-2786-46eb-b85d-43d2ac14d9d7.png)

幸运的是，或不幸的是，我们在日常挑战中面临的问题并没有直接告诉我们是否可以用图解决它们，如果可以，它需要什么样的图或者我们需要使用什么样的解析算法。这是我们会根据具体情况来处理的事情，这也是我们将在下面的用例中所做的。

# 用例

实现图与树的方式类似；没有固定的创建方式。然而，根据您的用例，您可以根据需要将图结构化为有向、循环或其他形式，如前面所述。这样做可以使它们的遍历更容易，从而使数据检索更容易、更快。

让我们先看一些示例，我们首先需要一个基础应用程序。

# 创建一个 Node.js Web 服务器

首先，让我们使用 Node.js 创建一个 Web 服务器，稍后我们将使用它来创建端点以访问我们基于图的应用程序：

1.  第一步是创建应用程序的项目文件夹；要做到这一点，从终端运行以下命令：

```js
 mkdir <project-name>
```

1.  然后，要初始化一个 Node.js 项目，在项目的根目录运行`init`命令。这将提示一系列问题以生成`package.json`文件。您可以填写您想要的答案，或者只需点击`return`接受提示的默认值：

```js
 cd <project-name>
 npm init
```

1.  接下来，因为我们想要创建一个 Web 服务器，我们将使用`express`，这是一个非常强大和流行的 Node.js 框架。我们还将使用另一个名为`body-parser`的库，它可以帮助我们轻松解析传入的 JSON 请求体。最后，我们还将使用`lodash`来帮助处理一些复杂的数据操作。要安装`lodash`，`express`和`body-parser`，运行以下命令：

```js
 npm install express body-parser lodash --save
```

1.  一旦我们完成了应用程序的设置，我们将需要使用 express 启动应用程序服务器，并包含我们的`body-parser`中间件。因此，我们现在可以在根目录下创建一个`server.js`文件，然后添加以下代码：

```js
 var express = require('express');
 var app = express();
 var bodyParser = require('body-parser');

 // middleware to parse the body of input requests app.use(bodyParser.json());

 // test url app.get('/', function (req, res) {
           res.status(200).send('OK!')
        });

 // start server app.listen(3000, function () {
           console.log('Application listening on port 3000!')
        });
```

1.  现在，应用程序已经准备好启动了。在您的`package.json`文件的`scripts`标签下，添加以下内容，然后从终端运行`npm start`来启动服务器：

```js
 {

        ...

        "scripts": {
          "start": "node server.js",
          "test": "echo \"Error: no test specified\" && exit 1"        },

        ...

        }
```

# 为求职门户创建一个参考生成器

在这个例子中，我们将为一个求职门户创建一个参考生成器。例如，我们有一些彼此为朋友的用户，我们将为每个用户创建节点，并将每个节点与数据关联，例如他们的姓名和他们工作的公司。

一旦我们创建了所有这些节点，我们将根据节点之间的一些预定义关系将它们连接起来。然后，我们将使用这些预定义关系来确定一个用户需要与谁交谈，以便获得推荐去他们选择的公司的工作面试。例如，A 在 X 公司工作，B 在 Y 公司工作并且是朋友，B 和 C 在 Z 公司工作并且是朋友。因此，如果 A 想要被推荐到 Z 公司，那么 A 与 B 交谈，B 可以介绍他们给 C，以获得去 Z 公司的推荐。

在大多数生产级应用程序中，您不会以这种方式创建图。您可以简单地使用图数据库，它可以直接执行许多功能。

回到我们的例子，更加技术性地说，我们有一个无向图（将用户视为节点，友谊视为它们之间的边），我们想要确定从一个节点到另一个节点的最短路径。

为了实现我们到目前为止所描述的内容，我们将使用一种称为**广度优先搜索**（**BFS**）的技术。BFS 是一种图遍历机制，首先检查或评估相邻节点，然后再移动到下一级。这有助于确保在结果链中找到的链接数量始终是最小的，因此我们总是得到从节点 A 到节点 B 的最短可能路径。

尽管还有其他算法，比如**Dijkstra**，可以实现类似的结果，但我们将选择 BFS，因为 Dijkstra 是一种更复杂的算法，适用于每个边都有相关成本的情况。例如，在我们的情况下，如果我们的用户友谊有与之相关的权重，比如*熟人*、*朋友*和*密友*，那么我们将选择 Dijkstra，这将帮助我们为每条路径关联权重。

考虑使用 Dijkstra 的一个很好的用例是地图应用程序，它会根据两点之间的交通情况（即每条边的权重或成本）为你提供从 A 点到 B 点的方向。

# 创建一个双向图

我们可以通过在`utils/graph.js`下创建一个新文件来为我们的图形创建逻辑，该文件将保存边缘，然后提供一个简单的`shortestPath`方法来访问图形，并在生成的图形上应用 BFS 算法，如下面的代码所示：

```js
var _ = require('lodash');

class Graph {

   constructor(users) {
      // initialize edges
  this.edges = {};

      // save users for later access
  this.users = users;

      // add users and edges of each
  _.forEach(users, (user) => {
         this.edges[user.id] = user.friends;
      });
   }
}

module.exports = Graph;
```

一旦我们将边添加到我们的图形中，它就有了节点（用户 ID），边被定义为每个用户 ID 和`friends`数组中的朋友之间的关系。由于我们的数据结构的方式，形成图形是一项容易的任务。在我们的示例数据集中，每个用户都有一个朋友列表，如下面的代码所示：

```js
[
   {
      id: 1,
      name: 'Adam',
      company: 'Facebook',
      friends: [2, 3, 4, 5, 7]
   },
   {
      id: 2,
      name: 'John',
      company: 'Google',
      friends: [1, 6, 8]
   },
   {
      id: 3,
      name: 'Bill',
      company: 'Twitter',
      friends: [1, 4, 5, 8]
   },
   {
      id: 4,
      name: 'Jose',
      company: 'Apple',
      friends: [1, 3, 6, 8]
   },
   {
      id: 5,
      name: 'Jack',
      company: 'Samsung',
      friends: [1, 3, 7]
   },
   {
      id: 6,
      name: 'Rita',
      company: 'Toyota',
      friends: [2, 4, 7, 8]
   },
   {
      id: 7,
      name: 'Smith',
      company: 'Matlab',
      friends: [1, 5, 6, 8]
   },
   {
      id: 8,
      name: 'Jane',
      company: 'Ford',
      friends: [2, 3, 4, 6, 7]
   }
]
```

正如你在前面的代码中所看到的，我们在这里并不需要专门建立双向边，因为如果用户`1`是用户`2`的朋友，那么用户`2`也是用户`1`的朋友。

# 生成最短路径的伪代码

在实施之前，让我们快速记录一下我们将要做的事情，这样实际的实施就会变得更容易：

```js
INITIALIZE tail to 0 for subsequent iterations

MARK source node as visited

WHILE result not found

    GET neighbors of latest visited node (extracted using tail)

    FOR each of the node

        IF node already visited

            RETURN

        Mark node as visited

        IF node is our expected result

            INITIALIZE result with current neighbor node

            WHILE not source node

               BACKTRACK steps by popping users 
               from previously visited path until
               the source user

            ADD source user to the result

            CREATE and format result variable

        IF result found return control

        NO result found, add user to previously visited path

        ADD friend to queue for BFS in next iteration

    INCREMENT tail for next loop

RETURN NO_RESULT
```

# 实现最短路径生成

现在让我们创建我们定制的 BFS 算法来解析图并生成用户被推荐到 A 公司的最短路径：

```js
var _ = require('lodash');

class Graph {

   constructor(users) {
      // initialize edges
  this.edges = {};

      // save users for later access
  this.users = users;

      // add users and edges of each
  _.forEach(users, (user) => {
         this.edges[user.id] = user.friends;
      });
   }

   shortestPath(sourceUser, targetCompany) {
      // final shortestPath
  var shortestPath;

      // for iterating along the breadth
  var tail = 0;

      // queue of users being visited
  var queue = [ sourceUser ];

      // mark visited users
  var visitedNodes = [];

      // previous path to backtrack steps when shortestPath is found
  var prevPath = {};

      // request is same as response
  if (_.isEqual(sourceUser.company, targetCompany)) {
         return;
      }

      // mark source user as visited so
 // next time we skip the processing  visitedNodes.push(sourceUser.id);

      // loop queue until match is found
 // OR until the end of queue i.e no match  while (!shortestPath && tail < queue.length) {

         // take user breadth first
  var user = queue[tail];

         // take nodes forming edges with user
  var friendsIds = this.edges[user.id];

         // loop over each node
  _.forEach(friendsIds, (friendId) => {
            // result found in previous iteration, so we can stop
            if (shortestPath) return;

            // get all details of node
  var friend = _.find(this.users, ['id', friendId]);

            // if visited already,
 // nothing to recheck so return  if (_.includes(visitedNodes, friendId)) {
               return;
            }

            // mark as visited
  visitedNodes.push(friendId);

            // if company matched
  if (_.isEqual(friend.company, targetCompany)) {

               // create result path with the matched node
  var path = [ friend ];

               // keep backtracking until source user and add to path
  while (user.id !== sourceUser.id) {

                  // add user to shortest path
  path.unshift(user);

                  // prepare for next iteration
  user = prevPath[user.id];
               }

               // add source user to the path
  path.unshift(user);

               // format and return shortestPath
  shortestPath = _.map(path, 'name').join(' -> ');
            }

            // break loop if shortestPath found
  if (shortestPath) return;

            // no match found at current user,
 // add it to previous path to help backtracking later  prevPath[friend.id] = user;

            // add to queue in the order of visit
 // i.e. breadth wise for next iteration  queue.push(friend);
         });

         // increment counter
  tail++;
      }

      return shortestPath ||
            `No path between ${sourceUser.name} & ${targetCompany}`;
   }

}

module.exports = Graph;
```

代码的最重要部分是当找到匹配时，如前面代码块所示：

```js
// if company matched if (_.isEqual(friend.company, targetCompany)) {

   // create result path with the matched node
  var path = [ friend ];

   // keep backtracking until source user and add to path
  while (user.id !== sourceUser.id) {

      // add user to shortest path
  path.unshift(user);

      // prepare for next iteration
  user = prevPath[user.id];
   }

   // add source user to the path
  path.unshift(user);

   // format and return shortestPath
  shortestPath = _.map(path, 'name').join(' -> ');
}
```

在这里，我们使用了一种称为回溯的技术，当找到结果时，它可以帮助我们重新追溯我们的步骤。这里的想法是，每当找不到结果时，我们将迭代的当前状态添加到一个映射中——键作为当前正在访问的节点，值作为我们正在访问的节点。

因此，例如，如果我们从节点 3 访问节点 1，那么直到我们从其他节点访问节点 1，地图中将包含{1:3}，当发生这种情况时，我们的地图将更新为指向我们从中得到节点 1 的新节点，例如{1:newNode}。一旦我们设置了这些先前的路径，我们可以通过查看这个地图轻松地追溯我们的步骤。通过添加一些日志语句（仅在 GitHub 代码中可用，以避免混淆），我们可以轻松地查看数据的长但简单的流程。让我们以我们之前定义的数据集为例，当 Bill 试图寻找可以推荐他给丰田的朋友时，我们看到以下日志语句：

```js
starting the shortest path determination added 3 to the queue marked 3 as visited
 shortest path not found, moving on to next node in queue: 3 extracting neighbor nodes of node 3 (1,4,5,8) accessing neighbor 1 mark 1 as visited result not found, mark our path from 3 to 1 result not found, add 1 to queue for next iteration current queue content : 3,1 accessing neighbor 4 mark 4 as visited result not found, mark our path from 3 to 4 result not found, add 4 to queue for next iteration current queue content : 3,1,4 accessing neighbor 5 mark 5 as visited result not found, mark our path from 3 to 5 result not found, add 5 to queue for next iteration current queue content : 3,1,4,5 accessing neighbor 8 mark 8 as visited result not found, mark our path from 3 to 8 result not found, add 8 to queue for next iteration current queue content : 3,1,4,5,8 increment tail to 1 shortest path not found, moving on to next node in queue: 1 extracting neighbor nodes of node 1 (2,3,4,5,7) accessing neighbor 2 mark 2 as visited result not found, mark our path from 1 to 2 result not found, add 2 to queue for next iteration current queue content : 3,1,4,5,8,2 accessing neighbor 3 neighbor 3 already visited, return control to top accessing neighbor 4 neighbor 4 already visited, return control to top accessing neighbor 5 neighbor 5 already visited, return control to top accessing neighbor 7 mark 7 as visited result not found, mark our path from 1 to 7 result not found, add 7 to queue for next iteration current queue content : 3,1,4,5,8,2,7 increment tail to 2 shortest path not found, moving on to next node in queue: 4 extracting neighbor nodes of node 4 (1,3,6,8) accessing neighbor 1 neighbor 1 already visited, return control to top accessing neighbor 3 neighbor 3 already visited, return control to top accessing neighbor 6 mark 6 as visited result found at 6, add it to result path ([6]) backtracking steps to 3 we got to 6 from 4 update path accordingly: ([4,6]) add source user 3 to result form result [3,4,6] return result increment tail to 3 return result Bill -> Jose -> Rita
```

我们基本上在这里使用 BFS 进行迭代过程，以遍历树并回溯结果。这构成了我们功能的核心。

# 创建一个 Web 服务器

我们现在可以添加一个路由来访问这个图形及其相应的`shortestPath`方法。让我们首先在`routes/references`下创建路由，并将其添加为 Web 服务器的中间件：

```js
var express = require('express');
var app = express();
var bodyParser = require('body-parser');

// register endpoints var references = require('./routes/references');

// middleware to parse the body of input requests app.use(bodyParser.json());

// route middleware app.use('/references', references);

// start server app.listen(3000, function () {
   console.log('Application listening on port 3000!');
});
```

然后，创建如下代码所示的路由：

```js
var express = require('express');
var router = express.Router();
var Graph = require('../utils/graph');
var _ = require('lodash');
var userGraph;

// sample set of users with friends 
// same as list shown earlier var users = [...];

// middleware to create the users graph router.use(function(req) {
   // form graph
  userGraph = new Graph(users);

   // continue to next step
  req.next();
});

// create the route for generating reference path // this can also be a get request with params based // on developer preference router.route('/')
   .post(function(req, res) {

      // take user Id
  const userId = req.body.userId;

      // target company name
  const companyName = req.body.companyName;

      // extract current user info
  const user = _.find(users, ['id', userId]);

      // get shortest path
  const path = userGraph.shortestPath(user, companyName);

      // return
  res.send(path);
   });

module.exports = router;
```

# 运行参考生成器

要测试这个，只需从项目的根目录运行`npm start`命令启动 Web 服务器，如前面所示。

一旦服务器启动运行，你可以使用任何你希望的工具将请求发送到你的 Web 服务器，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/986cd6f5-bb76-4a38-87cc-86cbe6efd012.png)

正如你在前面的截图中所看到的，我们得到了预期的响应。当然，这可以以一种方式进行更改，以返回所有用户对象而不仅仅是名称。这可能是一个有趣的扩展示例，你可以自己尝试一下。

# 为社交媒体创建一个好友推荐系统

你不能简单地否认社交网络网站都是关于数据的事实。这就是为什么这些网站中构建的大多数功能都依赖于你提供给它们的数据。这些中的一个例子就是*你可能认识的人*或*推荐关注*组件，你可以在许多网站上找到。

从前面的例子中，我们知道数据可以分组为“节点”和“边”，其中节点是人，边是您想要在节点之间建立的关系。

我们可以简单地形成一个双向图，然后应用 BFS 算法来确定第 n 度的连接节点，然后我们可以去重以显示朋友或节点推荐。然而，考虑到我们在前面的例子中已经这样做了，而且在生产应用程序中，每个用户和这些用户的朋友的实际列表都非常庞大，我们将采取不同的方法。我们将假设我们的数据集存储在图数据库中，比如**neo4j**，然后我们将使用一种称为**Personalized PageRank**的算法，这是一种 BFS 和 PageRank 的组合，我们将在下一节中探讨。

# 理解 PageRank 算法

在我们的生活中的某个时刻，我们一定遇到过这个术语，PageRank。PageRank 是 Google 对网页进行搜索和索引排名的众多方式之一。一个简单的谷歌搜索（完全是故意的双关语）将返回结果，告诉您它基本上涉及从中我们可以随机走向的一组节点。然而，这到底意味着什么呢？

假设控制权被放置在图中的任何节点上，我们说控制权可以以`alpha`的概率不偏向地跳转到图上的任何节点，当它确实落在任何节点上时，它会在以`(1-alpha)`的概率随机地沿着这些节点的边之一遍历之前，与所有连接的节点平均分享其排名的一部分。

这有什么意义和原因呢？这只是从一个节点跳到另一个节点，然后随机地遍历到其他连接的节点，对吧？

如果您这样做足够长的时间，您会落在所有节点上，有些节点会比其他节点多次。您明白我要说什么吗？这最终会告诉您哪些节点比其他节点更频繁地访问，这可能是由于以下两个原因：

+   我们碰巧多次跳转到同一个节点

+   该节点连接到多个节点

第一种情况可能发生，但是，由于我们知道我们的跳跃是不偏向的，大数定律规定，这将在足够长的时间内产生归一化的值，我们可以安全地排除它。

另一方面，第二种情况不仅可能，而且对 PageRank 非常重要。一旦您落在其中一个节点上，这时我们根据 alpha 和从前一个节点继承的排名来计算该节点的 PageRank。

我们在抽象的节点和边的术语中进行了讨论；然而，让我们暂时看一下 Sergey Brin 和 Lawrence Page 在 PageRank 的第一篇发表文章中所说的一句话([`infolab.stanford.edu/~backrub/google.html`](http://infolab.stanford.edu/~backrub/google.html))：

我们假设页面 A 有指向它的页面 T1...Tn（即引用）。参数 d 是一个阻尼因子，可以设置在 0 和 1 之间。我们通常将 d 设置为 0.85。关于 d 的更多细节将在下一节中介绍。此外，C(A)被定义为从页面 A 指向外部的链接数。页面 A 的 PageRank 如下所示：

PR(A) = (1-d) + d (PR(T1)/C(T1) + ... + PR(Tn)/C(Tn))

请注意，PageRanks 形成了网页的概率分布，因此所有网页的 PageRanks 之和将为 1。

从前面的陈述中，我们可以看到给定页面/节点的 PageRank *(PR*)是从其引用(*T1...Tn*)的*PR*派生出来的，但是我们如何知道从哪里开始，因为我们需要知道它的引用来计算*T1*的 PR。简单的答案是，实际上我们不需要知道*PR(T1)*的值或者事实上任何其他引用的值。相反，我们可以简单地猜测*PR(T1)*的值，并递归地应用从前一步骤派生出的值。

然而，你为什么会这样问呢？答案很简单，记得大数定律吗？如果你重复一个动作足够长的时间，该动作的结果将收敛到中位数值。然后，还有关于如何在数百万和数十亿的网页上进行有效操作的问题？有方法和手段，这超出了本章和本书的范围；然而，对于那些感兴趣的人，这本解释 Google Page Rank 的书是一本很好的读物，可在[`press.princeton.edu/titles/8216.html`](https://press.princeton.edu/titles/8216.html)上获得。我希望这本书能为基本原则提供一些启发。

# 理解个性化 PageRank（PPR）算法

现在我们对 PageRank 有了简要的了解，那么个性化 PageRank 是什么？实际上很简单，每次不是跳转到随机节点，而是跳转到预定义的节点，然后递归地累积每个节点的命中概率，使用 BFS 进行遍历。

假设我们有一些朋友，他们的结构如下图所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/1ae23c87-a88e-4087-8b5b-0b8f5f37b003.png)

这很简单；节点之间有双向边，表示它们之间有友谊关系。在这个问题中，我们可以假设我们想向用户**A**推荐新的朋友。

最简单的部分也是我们在转到 PPR 的代码之前需要讨论的重要事情。我们将始终从我们的目标节点开始，也就是说，跳转不再是随机开始的。我们从我们的目标节点开始，假设控制以相等的方式遍历所有边，然后回到父节点。然后，我们递归地重复这个过程，同时通过一条边扩展度，直到满足目标度。

此外，每次我们从目标节点增加一度搜索时，我们都会与邻居分享节点的概率，但如果我们全部分享，节点就会变为 0，所以我们要做的是应用一个阻尼因子（alpha）。

例如，假设我们在节点*X*，它的概率为 1（即，它是目标节点），并且这个节点*X*有两个邻居*Y*和*Z*。我们设置的 alpha（例如，0.5）将在这里应用，因此在第一次迭代之后，*X*的概率将为 0.5，然后*Y*和*Z*将有相等的概率 0.25。然后，这个过程将递归地重复到下一个度，使用我们刚刚创建的新概率映射。

# 个性化 PageRank 的伪代码

让我们将之前部分讨论的内容转换为伪代码，以便更容易实现：

```js
START at root node

    assign it a probability of 1 in the probabilityMap

    trigger CALC_PPR with current node, probabilityMap and iterations count

FUNCTION CALC_PPR

    IF number of iteration left is 0

        remove target and its neighbors from probabilityMap

        return rest of probabilityMap

    ELSE

        determine an ALPHA

        extract all nodes at the current degree

        FOR each nodes at current degree

            extract neighbors

            calculate the probability to propagate to neighbor

            IF neighbor already has a probability

                add to existing probability

            ELSE

               assign new probability

        CALC_PPR with decreased iteration count                 
```

现在这并不可怕，是吗？现在实现 PPR 算法将会很容易。

# 创建一个 Web 服务器

在我们为个性化 PageRank 编写任何代码之前，让我们首先创建一个 Node.js 应用程序，就像之前解释的那样。

一旦应用程序准备就绪，让我们创建一个路由，用于为我们提供用户建议。类似于之前的示例，我们可以快速拼凑出以下路由，放在`routes/suggestions.js`下：

```js
const express = require('express');
const router = express.Router();
const _ = require('lodash');

// sample set of users with friends extracted from some grapgh db const users = {
   A: { neighbors: [ 'B', 'D' ] },
   B: { neighbors: [ 'A', 'C', 'E' ] },
   C: { neighbors: [ 'B', 'D', 'E' ] },
   D: { neighbors: [ 'A', 'C' ] },
   E: { neighbors: [ 'B', 'C' ] }
};

// middleware router.use(function(req) {
   // intercept, modify and then continue to next step
  req.next();
});

// route router.route('/:userId')
   .get(function(req, res) {
      var suggestions;

      // take user Id
  const userId = req.params.userId;

      // generate suggestions   // return suggestions  res.send(userId);
   });

module.exports = router;
```

我们还可以快速拼凑出我们的 express 服务器：

```js
var express = require('express');
var app = express();
var bodyParser = require('body-parser');

// suggestion endpoints var suggestions = require('./routes/suggestions');

// middleware to parse the body of input requests app.use(bodyParser.json());

// route middleware app.use('/suggestions', suggestions);

// start server app.listen(3000, function () {
   console.log('Application listening on port 3000!');
});
```

# 实现个性化 PageRank

现在，让我们转到创建我们的**个性化 PageRank**（**PPR**）算法。我们将创建一个`ES6`类，它将处理提供图形和目标节点后生成建议的所有逻辑。请注意，在上面的代码中，我已经向您展示了图形的样子：

```js
const users = {
   A: { neighbors: [ 'B', 'D' ] },
   B: { neighbors: [ 'A', 'C', 'E' ] },
   C: { neighbors: [ 'B', 'D', 'E' ] },
   D: { neighbors: [ 'A', 'C' ] },
   E: { neighbors: [ 'B', 'C' ] }
};
```

我们通过指定两个节点为彼此的邻居建立了双向关系。现在，我们可以开始编写 PPR 的代码：

```js
const _ = require('lodash');

class PPR {

   constructor(data) {
      this.data = data;
   }

   getSuggestions(nodeId) {
      return this.personalizedPageRankGenerator(nodeId);
   };
}

module.exports = PPR;
```

我们首先将图形作为输入接受到我们的`constructor`中。接下来，我们将定义我们的`getSuggestions`方法，它将接受输入的`nodeId`，然后将其传递给计算 PPR。这也是我们之前伪代码的第一步，如下所示：

```js
personalizedPageRankGenerator(nodeId) {
   // Set Probability of the starting node as 1
 // because we will start from that node  var initProbabilityMap = {};

   initProbabilityMap[nodeId] = 1;

   // call helper to iterate thrice
  return this.pprHelper(nodeId, initProbabilityMap, 3);
};
```

由于我们的控制被定义为从一个固定节点开始，我们将其概率设置为`1`。我们将进行三次迭代，只是因为我们只想走出三个级别来获取建议。第 1 级是目标节点，第 2 级是目标节点的邻居（即当前的朋友），然后第 3 级是邻居的邻居（即朋友的朋友）。

现在，我们来到了有趣的部分。我们将递归地计算我们跳到每个相邻节点的概率，从目标节点开始：

```js
pprHelper(nodeId, currentProbabilitiesMap, iterationCount) {
   // iterations done
  if (iterationCount === 0) {

      // get root nodes neighbors
  var currentNeighbors = this.getNeighbors(nodeId);

      // omit neighbors and self node from calculated probabilities
  currentProbabilitiesMap = _.omit(currentProbabilitiesMap,
      currentNeighbors.concat(nodeId));

      // format data and sort by probability of final suggestions
  return _.chain(currentProbabilitiesMap)
         .map((val, key) => ({ name: key, score: val }))
         .orderBy('score', 'desc')
         .valueOf();

   } else {
      // Holds the updated set of probabilities for the next iteration
  var nextIterProbabilityMap = {};

      // set alpha
  var alpha = 0.5;

      // With probability alpha, we teleport to the start node again
  nextIterProbabilityMap[nodeId] = alpha;

      // extract nodes within current loop
  var parsedNodes = _.keys(currentProbabilitiesMap);

      // go to next degree nodes of each of the currently parsed nodes
  _.forEach(parsedNodes, (parsedId) => {

         // get current probability of each node
  var prob = currentProbabilitiesMap[parsedId];

         // get connected nodes
  var neighbors = this.getNeighbors(parsedId);

         // With probability 1 - alpha, we move to a connected node...
 // And at each node we distribute its current probability
         equally to // its neighbors    var probToPropagate = (1 - alpha) * prob / neighbors.length;

         // spreading the probability equally to neighbors   _.forEach(neighbors, (neighborId) => {
            nextIterProbabilityMap[neighborId] =
         (nextIterProbabilityMap[neighborId] || 0) + probToPropagate;
         });
      });

      // next iteration
  return this.pprHelper(nodeId, nextIterProbabilityMap, iterationCount - 1);
   }
}

getNeighbors(nodeId) {
   return _.get(this.data, [nodeId, 'neighbors'], []);
}
```

这并不像你想象的那样糟糕，对吧？一旦我们准备好 PPR 算法，我们现在可以将这个类导入到我们的`suggestions`路由中，并可以用它来为任何输入用户生成推荐，如下面的代码片段所示：

```js
const express = require('express');
const router = express.Router();
const _ = require('lodash');
const PPR = require('../utils/ppr');

// sample set of users with friends extracted from some grapgh db const users = .... // from previous example

....

// route router.route('/:userId')
   .get(function(req, res) {
      var suggestions;

      // take user Id
  const userId = req.params.userId;

----> // generate suggestions ----> suggestions = new PPR(users).getSuggestions(userId);

      // return suggestions
  res.send(suggestions);
   });

module.exports = router;
```

# 结果和分析

现在，为了测试这个，让我们通过从根文件夹运行`npm start`命令来启动我们的 Web 服务器。一旦您的应用程序启动，您将在终端上看到以下消息：

```js
Application listening on port 3000!
```

一旦消息出现，您可以打开 Postman 或您选择的其他任何东西来进行 API 调用以获取建议：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/3a99d1de-2e5a-4c3e-bbfd-86262553501b.png)

我们可以看到用户`C`比用户`E`得分更高。这是因为我们可以从输入数据集中看到用户`A`和`C`比用户`A`和`E`有更多的共同朋友。这就是为什么，根据我们之前的推断，我们的控制落在节点`C`上的机会比节点`E`上的机会更高。

另外，需要注意的有趣的事情是，这里实际分数的值并不重要。您只需要看分数的比较来确定哪一个更有可能发生。您可以根据需要更改 alpha 来决定每个节点之间将分配多少概率，这最终会改变每个结果节点的分数，例如，我们将 alpha 值更改为 0.5 的结果，显示了名称和分数，我们将现在将其更改为`0.33`，即父节点保留三分之一，其余与邻居分配：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/0c1ffd35-abd0-4486-b64c-ca37e5574010.png)

在每个递归调用之前添加了一些日志语句，以便更清晰地理解：

```js
.....

console.log(`End of Iteration ${ 4 - iterationCount} : ${JSON.stringify(nextIterProbabilityMap)}`);
 // next iteration return this.pprHelper(nodeId, nextIterProbabilityMap, iterationCount - 1);
```

前面的日志语句产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/09b6cd98-6333-4725-b931-03af662e5509.png)

从前面的截图中，您可以注意到在第一次迭代结束时，我们分配给目标节点`A`的总概率为 1，在我们的逻辑确定的 BFS 遍历后，被分成了三部分，即节点`A`的邻居`B`和`D`。现在，这成为了第 2 次迭代的输入，我们重复这个过程，直到最后一次迭代结束，在最后一次迭代结束时，我们移除了当前目标节点`A`及其直接邻居节点`B`和`D`（因为它们已经是朋友），并返回剩下的节点`C`和`E`。

# 摘要

在本章中，我们直面了一些现实世界的挑战，并根据手头的问题创建了一些定制解决方案。这是本章最重要的收获之一。很少会有一个理想的解决方案是 readily available。我们采用了图论算法之一，称为 BFS，并利用它来为我们的职位门户和用户建议生成推荐。我们还简要讨论了 PageRank 算法，任何开发人员都应该熟悉。这引出了为什么以及何时使用一种算法而不是另一种算法的问题。选择算法的利弊是什么？这将是我们下一章的主题，我们将分析不同类型的算法以及它们可以应用的地方。


# 第六章：探索算法类型

在计算机科学世界中，算法是一组指令，它需要有限的空间和时间来执行。它从应用程序的初始状态开始，然后逐步执行一系列指令以达到最终结果。

算法有各种各样的形状和大小，当您将其与算法的过于通用的定义进行比较时，所有这些算法都将符合要求。重要的问题是决定在哪种情况下使用哪种算法，并根据应用程序的需求进行修改以增强其功能。

正如我在前几章的用例中所展示的，大多数时候，那些已经存在的算法并不直接适用于手头的问题。这就是在需要对算法进行深入理解时的用武之地。这正是我们将在本章中要做的；我们将看一系列算法，然后尝试通过一些示例更好地理解它们。

在本章中，我们将讨论以下算法，并陦有一些示例：

+   递归

+   迪杰斯特拉

+   广度优先搜索（BFS）

+   动态规划

+   贪婪算法

+   分支和界限

在我们开始查看用例之前，让我们先建立一个简单的 Node.js 项目。

# 创建一个 Node.js 应用程序

在本章中，我们将使用一个非常简单和轻量的 Node.js 应用程序，它将保存我们的示例脚本。这里的主要目标是能够单独运行每个用例，而不是为每个用例都有一个完整的 Web（客户端或服务器）应用程序。这有助于我们拥有一个统一的基础项目。

1.  第一步是创建应用程序的项目文件夹。从终端运行以下命令：

```js
mkdir <project-name>
```

1.  然后，要初始化一个 Node.js 项目，请在项目的`root`文件夹中运行`init`命令。这将提示一系列问题以生成`package.json`文件。您可以填写您希望的答案，或者只需点击`return`接受提示的默认值：

```js
cd <project-name>
npm init
```

1.  让我们也安装我们心爱的`lodash`，以帮助我们处理一些琐碎的数组和对象操作和实用程序：

```js
npm install --save lodash
```

# 用例

一旦您的项目准备就绪，我们现在可以在项目的根目录中添加必要的脚本，然后独立运行它们。

# 使用递归来序列化数据

递归是一种非常流行的**编程范式**，其中问题陈述可以被分解成几个较小的问题，这些问题可以用自身来定义。递归通常与**分而治之**混淆在一起，其中问题陈述被分解成不重叠的子问题，可以同时解决。

在接下来的部分中，我们将采用一个简单的树结构，其中有一个根元素，后面跟着一些子元素。我们将对这棵树的数据进行序列化，然后可以轻松地将其发送到 UI 或持久化在数据库中。

让我们首先在我们基于前一节创建的项目中创建一个名为`recursion`的文件夹。然后，我们可以在这个文件夹中创建我们的`serializer.js`文件，其中将包含用于序列化树数据的类。

# 伪代码

在实现递归序列化器之前，让我们用伪代码来制定我们的算法：

```js
INITIALIZE response

FOR each node

    extract child nodes

    add current node info to serialized string

    IF childNodes exist

        repeat process for child nodes

    ELSE

        add ^ to indicate end of the level 

IF rootnode

    return serialized string

ELSE

   add ^ to indicate child node of root

```

# 序列化数据

现在我们已经有了伪代码，序列化的代码变得非常简单，让我们将以下内容添加到一个名为`recursion.js`的文件中，放在我们的序列化器旁边：

```js
var _ = require('lodash');

class Recursion {
   constructor(tree) {
      this.tree = tree;
   }

   // serialize method which accepts list of nodes
  serialize(nodes) {
      // initialize response
  this.currentState = this.currentState || '';

      // loop over all nodes
  _.forEach(nodes, (node) => {

         // depth first traversal, extracting nodes at each level
 // traverse one level down  var childNodes = this.tree[node];

         // add current node to list of serialized nodes
  this.currentState += ` ${node}`;

         // has child nodes
  if (childNodes) {

            // recursively repeat
  this.serialize(childNodes);
         } else {

            // mark as last node, traverse up
  this.currentState += ` ^`;
         }
      });

      // loop complete, traverse one level up
 // unless already at root otherwise return response  if (!this.isRoot(nodes)) {
         this.currentState += ` ^`;
      } else {
         return this.currentState.trim();
      }
   }

   isRoot(nodes) {
      return _.isEqual(this.tree.root, nodes);
   }
}

module.exports = Recursion;
```

请注意，在前面的代码中，我们按照自身的方式分解了问题，确定了一个级别需要做什么，然后递归地为所有节点重复了这个过程。现在，为了使用这种序列化方法，创建一个`serialization.js`文件，然后将以下代码添加到其中：

```js
var fs = require('fs');
var Recursion = require('./recursion');

// set up data const tree = {
   root: ['A'],
   A: ['B', 'C', 'D'],
   B: ['E', 'F'],
   D: ['G', 'H', 'I', 'J'],
   F: ['K']
};

// initialize var serializer = new Recursion(tree);

// serialize var serializedData = serializer.serialize(tree.root);

console.log(serializedData);
```

当我们从项目的根目录运行上述文件时，使用`node recursion/serializer.js`命令，我们会在控制台上得到序列化的响应日志：

```js
A B E ^ F K ^ ^ ^ C ^ D G ^ H ^ I ^ J ^ ^ ^
```

从前面的响应中，您可以注意到基于我们的输入数据集，深度优先方法可以很清楚地看到。`B`是`A`的子节点，`E`是`B`的叶子节点（在`E`后面的`^`符号表示）。使用递归来反序列化这个序列化的数据也是一个简单的过程，您可以自己尝试一下。

# 使用 Dijkstra 确定最短路径

在前面的章节中，我们只探讨了图遍历的简单方法，**广度优先搜索**（**BFS**）和**深度优先搜索**（**DFS**）。在前一章中，我们简要讨论了 Dijkstra 以及它如何帮助我们确定图中从节点**A**到节点**B**的路径，前提是图是有向的，带有加权边。

在这个例子中，我们就是这样。我们有一个节点（城市）和边（大约的距离）的图，我们需要确定用户从给定的起始节点到达目的节点的最快路径，前提是其他因素，如速度、交通和天气保持不变：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/abe94949-c722-4241-8575-b60cdde8783b.png)

我们的行程从**旧金山**（**SF**）开始，到**凤凰城**（**PX**）结束。我们已经确定了一些中间城市，用户可以在那里停下来休息或加油：**蒙特利**（**MT**）、**圣何塞**（**SJ**）、**圣巴巴拉**（**SB**）、**洛杉矶**（**LA**）、**圣迭戈**（**SD**）、**弗雷斯诺**（**FR**）、**贝克斯菲尔德**（**BK**）和**拉斯维加斯**（**LV**）。到达每个城市的距离由每个城市之间的边关联的权重表示。

# 伪代码

让我们来看一下实现 Dijkstra 算法的伪代码：

```js
INITIALIZE Costs, Previous Paths, Visited Nodes

ADD each neighbor of start node to Previous Paths

GET cheapest node from start node and set as current node

WHILE node exists

    GET cost of current node from costs

    GET neighbors of current node

    FOREACH neighbor

        ADD cost of neighbor to current nodes cost as new cost

        IF cost of neighbor not recorded OR cost of 
            neighbor is the lowest amongst all neighbors

            SET cost of neighbor as new cost

            SET the path of neighbor as current node

    MARK current node as visited

    GET cheapest node from start node and set as current node

INITIALIZE response

BACKTRACK path from end to start

RETURN distance and path    
```

# 实现 Dijkstra 算法

让我们根据前一节描述的伪代码来分解 Dijkstra 算法的实现。第一步是初始化所有变量。我们将使用一个变量来跟踪通过每个节点的成本，一个用于跟踪我们所采取的路径，还有一个用于跟踪已经访问的节点，以避免重新计算：

```js
var _ = require('lodash');

class Dijkstra {
   solve (graph, start, end) {

      // track costs of each node
  const costs = graph[start];

      // set end to infinite on 1st pass
  costs[end] = Infinity;

      // remember path from
 // which each node was visited  const paths = {};

      // add path for the start nodes neighbors
  _.forEach(graph[start], (dist, city) => {
         // e.g. city SJ was visited from city SF
  paths[city] = start;
      });

      // track nodes that have already been visited nodes
  const visitedNodes = [];

      ....
```

我们的`solve()`方法在这里已经用起始节点的`成本`初始化了`costs`，然后将终点节点的`成本`设置为`Infinity`，因为还没有计算。这意味着在开始时，`costs` `set`将包含与从起始节点出发的节点和边完全相同的数据。

我们还相应地计算了路径，例如，由于在我们的示例中从`SF`开始，节点`SJ`、`MT`和`SB`都是从节点`SF`到达的。以下代码解释了如何在每个节点提取最低成本：

```js
...

// track nodes that have already been visited nodes const visitedNodes = [];

// get current nodes cheapest neighbor let currentCheapestNode = this.getNextLowestCostUnvisitedNode(costs, visitedNodes);

// while node exists while (currentCheapestNode) {

   // get cost of reaching current cheapest node
  let costToReachCurrentNode = costs[currentCheapestNode];

   // access neighbors of current cheapest node
  let neighbors = graph[currentCheapestNode];

   // loop over neighbors
  _.forEach(neighbors, (dist, neighbor) => {

      // generate new cost to reach each neighbor
  let newCost = costToReachCurrentNode + dist;

      // if not already added
 // or if it is lowest cost amongst the neighbors  if (!costs[neighbor] || costs[neighbor] > newCost) {

         // add cost to list of costs
  costs[neighbor] = newCost;

         // add to paths
  paths[neighbor] = currentCheapestNode;

      }

   });

   // mark as visited
  visitedNodes.push(currentCheapestNode);

   // get cheapest node for next node
  currentCheapestNode = this.getNextLowestCostUnvisitedNode(costs, visitedNodes);
}

...
```

这可能是代码中最重要的部分；我们根据`costs`和`visitedNodes`数组计算了`currentCheapestNode`，在第一次迭代中，它的值将是`SJ`，正如我们从前面的图中可以看到的。

一旦我们有了第一个节点，我们就可以访问它的邻居，并且只有在到达这些邻居的“成本”小于当前节点的“成本”时，我们才会更新到达这些邻居的“成本”。此外，如果成本更低，那么我们很可能会通过这个节点到达终点节点，因此我们也会更新到这个邻居的路径。然后在标记访问过的节点后，我们递归重复这个过程。在所有迭代结束时，我们将得到所有节点的更新成本，从而得到到达节点的最终成本：

```js
....

        // get cheapest node for next node
  currentCheapestNode = 
 this.getNextLowestCostUnvisitedNode(costs, visitedNodes);
       }

       // generate response
  let finalPath = [];

       // recursively go to the start
  let previousNode = paths[end];

       while (previousNode) {
          finalPath.unshift(previousNode);
          previousNode = paths[previousNode];
       }

       // add end node at the end
  finalPath.push(end);

       // return response
  return {
          distance: costs[end],
          path: finalPath
  };
    }
 getNextLowestCostUnvisitedNode(costs, visitedNodes) {
       //extract the costs of all non visited nodes
  costs = _.omit(costs, visitedNodes);

       // return the node with minimum cost
  return _.minBy(_.keys(costs), (node) => {
          return costs[node];
       });
    }
}

module.exports = Dijkstra;
```

一旦生成了所有节点的“成本”，我们将简单地回溯到达终点节点所采取的步骤，然后我们可以返回终点节点的成本和到达终点节点的路径。在最后添加了一个获取未访问节点最低成本的实用方法。

现在，要使用这个类，我们可以在`dijkstra`文件夹下创建一个名为`shortest-path.js`的文件，以及刚刚创建的`dijkstra.js`类：

```js
var Dijkstra = require('./dijkstra');

const graph = {
   'SF': { 'SB': 326, 'MT': 118, 'SJ': 49 },
   'SJ': { 'MT': 72, 'FR': 151, 'BK': 241 },
   'MT': { 'SB': 235, 'LA': 320 },
   'SB': { 'LA': 95 },
   'LA': { 'SD': 120 },
   'SD': { 'PX': 355 },
   'FR': { 'LV': 391 },
   'BK': { 'LA': 112, 'SD': 232, 'PX': 483, 'LV': 286 },
   'LV': { 'PX': 297 },
   'PX': {}
};

console.log(new Dijkstra().solve(graph, 'SF', 'PX'));
```

现在，要运行这个文件，只需运行以下命令：

```js
node dijkstra/shortest-path.js 
```

上述命令记录了以下代码：

```js
{ distance: 773, path: [ 'SF', 'SJ', 'BK', 'PX' ] } 
```

基于原始插图的可视化如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/123c2c77-d526-47da-afb3-c71e80586f43.png)

# 使用 BFS 确定关系

好吧，这不是听起来的样子。我们不是在走一条浪漫的道路，彼此问难题。然而，我们正在谈论一个简单的图，例如，一个家谱（是的，树是图的形式）。在这个例子中，我们将使用 BFS 来确定两个节点之间的最短路径，然后可以建立这两个节点之间的关系。

让我们首先设置我们的测试数据，以便我们有准备好的输入图：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/1112a6c8-816d-40ac-a461-0a3782262a2d.png)

您可以从前面的图中注意到，我们有一个小家庭，其中节点`A`，`E`和`F`是兄弟姐妹。 `A`与`B`结婚，节点`C`和`D`是他们的孩子。节点`G`是节点`F`的孩子。这里没有复杂或不寻常的地方。我们将使用这些数据来确定节点`C`和`G`之间的关系。您肯定可以看一下图表并自己判断，但现在这样做并不有趣，对吧？

现在让我们将其转换为我们的程序可以理解的格式：

```js
[
  {
    "name": "A",
    "connections": [
      {
        "name": "E",
        "relation": "Brother"
  },
      {
        "name": "F",
        "relation": "Sister"
  },
      {
        "name": "B",
        "relation": "Wife"
  },
      {
        "name": "D",
        "relation": "Son"
  },
      {
        "name": "C",
        "relation": "Daughter"
  }
    ]
  },
  {
    "name": "B",
    "connections": [
      {
        "name": "A",
        "relation": "Husband"
  },
      {
        "name": "D",
        "relation": "Son"
  },
      {
        "name": "C",
        "relation": "Daughter"
  }
    ]
  },
  {
    "name": "C",
    "connections": [
      {
        "name": "A",
        "relation": "Father"
  },
      {
        "name": "B",
        "relation": "Mother"
  },
      {
        "name": "D",
        "relation": "Brother"
  }
    ]
  },
  {
    "name": "D",
    "connections": [
      {
        "name": "A",
        "relation": "Father"
  },
      {
        "name": "B",
        "relation": "Mother"
  },
      {
        "name": "C",
        "relation": "Sister"
  }
    ]
  },
  {
    "name": "E",
    "connections": [
      {
        "name": "A",
        "relation": "Brother"
  },
      {
        "name": "F",
        "relation": "Sister"
  }
    ]
  },
  {
    "name": "F",
    "connections": [
      {
        "name": "E",
        "relation": "Brother"
  },
      {
        "name": "A",
        "relation": "Brother"
  },
      {
        "name": "G",
        "relation": "Son"
  }
    ]
  },
  {
    "name": "G",
    "connections": [
      {
        "name": "F",
        "relation": "Mother"
  }
    ]
  }
]
```

这很快变得复杂了，不是吗？这是节点的一个挑战，您想建立关系（即有标签的边）。让我们将这些数据添加到`family.json`文件中，然后再看一下 BFS 的伪代码，以便在实现之前更好地理解它。

# 伪代码

BFS 的伪代码与 DFS 非常相似，主要区别在于 BFS 在移动到另一个级别寻找目标节点之前，我们首先迭代所有连接的节点：

```js
INITIALIZE paths, nodes to visit (queue), visited nodes

SET start node as visited

WHILE nodes to visit exist

    GET the next node to visit as current node from top of queue

    IF current node is target

        INITIALIZE result with target node

        WHILE path retrieval not at source

            EXTRACT how we got to this node

            PUSH to result

        FORMAT and return relationship

    ELSE

        LOOP over the entire graph

            IF node is connected to current node

                SET its path as current node

                MARK node as visited

                PUSH it to queue for visiting breadth wise

RETURN Null that is no result

```

听起来与我们之前使用 DFS 处理的另一个示例非常相似，不是吗？这是因为 DFS 和 BFS 在解决问题的方式上非常相似。两者之间的微小区别在于，在 BFS 中，我们在扩展到另一个级别之前首先评估所有连接的节点，而在 DFS 的情况下，我们选择一个连接的节点，然后遍历它直到整个深度。

# 实施 BFS

为了实现先前讨论的伪代码，我们将首先简化我们的数据。有两种方法可以做到这一点，如下所示：

1.  创建图数据的邻接矩阵，指示图作为大小为*m x m*的二维数组，其中包含 1 和 0。 *1*表示*mrow*节点与*mcolumn*之间的连接，*0*表示没有连接。

1.  我们简化数据集，只提取节点作为一个映射，其中键是节点，值是它连接到的节点列表。

虽然这两种方法都是解决问题的好方法，但通常更喜欢第一种选项，因为第二种选项由于所有附带的集合和列表的开销而具有更高的代码复杂性。

然而，现在我们不需要担心代码复杂性，因为我们想要得到可能的最简单的解决方案，所以我们将选择第二个选项。

首先，我们将简化输入数据，以便将转换后的输入传递到我们将创建的 BFS 算法中：

```js
var _ = require('lodash');
var BFS = require('./bfs');
var familyNodes = require('./family.json');

// transform familyNodes into shorter format for simplified BFS var transformedFamilyNodes = _.transform(familyNodes, (reduced, currentNode) => {

      reduced[currentNode.name] = _.map(currentNode.relations, 'name');

      return reduced;
}, {});
```

这基本上将`transformedFamilyNodes`设置为前面描述的结构，在我们的情况下，它看起来如下：

```js
{ 
    A: [ 'E', 'F', 'B', 'D', 'C' ],
    B: [ 'A', 'D', 'C' ],
    C: [ 'A', 'B', 'D' ],
    D: [ 'A', 'B', 'C' ],
    E: [ 'A', 'F' ],
    F: [ 'E', 'A', 'G' ],
    G: [ 'F' ] 
}
```

然后，我们创建我们的 BFS 搜索类，然后添加一个方法来实现搜索功能：

```js
var _ = require('lodash');

class BFS {

   constructor(familyNodes) {
      this.familyNodes = familyNodes;
   }

   search (graph, startNode, targetNode) {

   }

}

module.exports = BFS;
```

我们在构造函数中接受原始家庭节点的列表，然后在我们的搜索方法中接受修改后的图，我们将对其进行迭代。那么，为什么我们需要原始家庭节点？因为一旦我们从一个节点提取路径到另一个节点，我们将需要建立它们之间的关系，这是记录在原始未处理的家庭节点上的。

我们将继续实现`search()`方法：

```js
search (graph, startNode, targetNode) {
   // initialize the path to traverse
  var travelledPath = [];

   // mark the nodes that need to be visited breadthwise
  var nodesToVisit = [];

   // mark all visited nodes
  var visitedNodes = {};

   // current node being visited
  var currentNode;

   // add start node to the to be visited path
  nodesToVisit.push(startNode);

   // mark starting node as visited node
  visitedNodes[startNode] = true;

   // while there are more nodes to go
  while (nodesToVisit.length) {

      // get the first one in the list to visit
  currentNode = nodesToVisit.shift();

      // if it is the target
  if (_.isEqual(currentNode, targetNode)) {

         // add to result, backtrack steps based on path taken
  var result = [targetNode];

         // while target is not source
  while (!_.isEqual(targetNode, startNode)) {

            // extract how we got to this node
  targetNode = travelledPath[targetNode];

            // add it to result
  result.push(targetNode);
         }

         // extract the relationships between the edges and return
         // value
  return this.getRelationBetweenNodes(result.reverse());
      }

      // if result not found, set the next node to visit by traversing
 // breadth first  _.forOwn(graph, (connections, name) => {

         // if not current node, is connected to current node 
         // and not already visited
  if (!_.isEqual(name, currentNode)
            && _.includes(graph[name], currentNode)
            && !visitedNodes[name]) {

            // we will be visiting the new node from current node
  travelledPath[name] = currentNode;

            // set the visited flag
  visitedNodes[name] = true;

            // push to nodes to visit
  nodesToVisit.push(name);
         }
      });
   }

   // nothing found
  return null;
}
```

这一切都很快而且没有痛苦。如果您注意到，我们正在调用`getRelationBetweenNodes`，它会根据传入构造函数的`familyNodes`提取节点之间的关系，一旦确定了两个节点之间的路径。这将提取每个节点与其后继节点的关系：

```js
getRelationBetweenNodes(relationship) {
   // extract start and end from result
  var start = relationship.shift();
   var end = relationship.pop();

   // initialize loop variables
  var relation = '';
   var current = start;
   var next;
   var relationWithNext;

   // while end not found
  while (current != end) {
      // extract the current node and its relationships
  current = _.find(this.familyNodes, { name: current });

      // extract the next node, if nothing then set to end node
  next = relationship.shift() || end;

      // extract relationship between the current and the next node
  relationWithNext = _.find(current.relations, {name : next });

      // add it to the relation with proper grammar
  relation += `${relationWithNext.relation}${next === end ? '' : 
 '\'s'} `;

      // set next to current for next iteration
  current = next;
   }

   // return result
  return `${start}'s ${relation}is ${end}`;
}
```

现在我们的类已经准备好了，我们可以通过调用`node bfs/relations.js`来调用它：

```js
var _ = require('lodash');
var BFS = require('./bfs');
var familyNodes = require('./family.json');

// transform familyNodes into shorter format for simplified BFS var transformedFamilyNodes = _.transform(familyNodes, (reduced, currentNode) => {

      reduced[currentNode.name] = _.map(currentNode.relations, 'name');

      return reduced;
}, {});

var relationship = new BFS(familyNodes).search(transformedFamilyNodes, 'C', 'G');

console.log(relationship);
```

前面的代码记录了以下内容：

```js
C's Father's Sister's Son is G 
```

根据初始示例，这可以用以下方式进行可视化表示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/8b31bd8e-9e12-41f3-8f0a-7b702782be69.png)

# 使用动态规划来构建财务规划师

**动态规划**（**DP**）是解决某一类问题的一种非常常见和强大的方法。这些问题以主要问题可以分解为子问题，子问题可以进一步分解为更小的问题，并且它们之间存在一些重叠的方式呈现。

DP 经常因为与递归的相似性而被混淆。DP 问题只是一种问题类型，而递归是解决这类问题的一部分。我们可以通过两种主要方式来解决这类问题：

+   将问题分解为子问题：如果子问题已经解决，则返回保存的解决方案，否则解决并保存解决方案，然后返回。这也被称为**记忆化**。这也被称为自顶向下的方法。

+   将问题分解为子问题：开始解决最小的子问题，然后逐步解决更大的问题。这种方法被称为**自底向上**方法。

在这个例子中，我们有一系列用户的开销；我们需要根据用户设定的总数为用户提供所有可能的结果。我们希望用户能够自由选择他们喜欢的选项，因此我们将采用自底向上的方法。首先，让我们分解输入数据，然后从伪代码中推导出代码：

```js
let expenses = [
   {
      type: 'rent',
      cost: 5
  },
   {
      type: 'food',
      cost: 3
  },
   {
      type: 'entertainment',
      cost: 2
  },
   {
      type: 'car and gas',
      cost: 2
  },
   {
      type: 'ski-trip',
      cost: 5
  }
];
 let total = 10;
```

您可以从前面的代码中注意到，样本输入数据已经被规范化，以便简化和提高代码效率。一旦我们设置好了，我们就可以创建我们的伪代码来理解算法。

# 伪代码

在这个例子中，对于这种类型的问题，我们将创建一个二维数组，其中一个维度（y）表示元素的值（即每个开销的成本：5、3、2、2 和 5），另一个维度（x）表示总成本的增量（即 0 到 10）。这就是为什么我们在第一步中规范化我们的数据——它有助于我们在维度方面保持数组的小型化。

一旦我们有了数组，我们将为数组的每个位置`arr[i][j]`分配一个 true，如果`0 到 i`的任何费用可以在任何时候创建`j`的总和，否则为 false：

```js
CREATE empty 2d array with based on input data

IF expected total 0, any element can achieve this, so set [i][0] to true

IF cost of first row is less than total, set [0][cost] to true

LOOP over each row from the second row

    LOOP over each column

        IF current row cost is less than the current column total

            COPY from the row above, the value of the current column if
            it is true
                or else offset the column by current rows cost

        ELSE

            Copy value from the row above for the same column

IF last element of the array is empty

   No results found

generate_possible_outcomes()

FUNCTION generate_possible_outcomes

    IF reached the end and sum is non 0

       ADD cost as an option and return options

    IF reached the end and sum is 0

        return option

    IF sum can be derived without current row cost

        generate_possible_outcomes() from the previous row

    IF sum cannot be derived without current row

        ADD current row as an option

        generate_possible_outcomes() from the previous row
```

请注意在前面的代码中，算法非常简单；我们只是将问题分解为更小的子问题，并尝试回答每个子问题的问题，同时向更大的问题迈进。一旦我们构建好数组，我们就从数组的最后一个单元格开始，然后向上遍历并根据当前单元格是否为 true，将一个单元格添加到所采取的路径上。一旦我们达到总数为`0`，也就是第一列时，递归过程就停止了。

# 实施动态规划算法

现在我们了解了这种方法，让我们首先为我们的算法创建类，并添加`analyze()`方法，该方法将在生成算法之前首先创建 2D 数组。

当类被初始化时，我们将构建一个 2D 数组，其中所有的值都设置为`false`。然后我们将使用这个 2D 数组，并根据我们的条件更新其中的一些值，我们将很快讨论这些条件：

```js
var _ = require('lodash');

class Planner {

   constructor(rows, cols) {
      // create a 2d array of rows x cols
 // all with value false  this.planner = _.range(rows).map(() => {
         return _.range(cols + 1).map(()=> false);
      });
 // holds the response
      this.outcomes = [];
   }
}

module.exports = Planner;
```

现在，我们可以实现`analyze()`方法，该方法将在 2D 数组的每个单元格中设置适当的值。

首先，我们将设置第一列的值，然后是第一行的值：

```js
analyze(expenses, sum) {
   // get size of expenses
  const size = _.size(expenses);

   // if sum 0, result can be done with 0 elements so
 // set col 0 of all rows as true  _.times(size, (i)=> {
      this.planner[i] = this.planner[i] || [];
      this.planner[i][0] = true;
   });

   // for the first row, if the first cost in the expenses
 // is less than the requested total, set its column value // to true  if(expenses[0].cost <= sum) {
      this.planner[0][expenses[0].cost] = true;
   }

```

虽然第一列都是 true，但是第一行的一个单元格只有在与该行相关的成本小于总和时才为 true，也就是说，我们可以只用一个元素构建所请求的总和。接下来，我们取出已填写的行和列，用它们来构建数组的其余部分：

```js
 // start from row #2 and loop over all other rows  for(let i = 1; i < size; i++) {

      // take each column
  _.times(sum + 1, (j) => {

         // if the expenses cost for the current row
 // is less than or equal to the sum assigned to the // current column  if (expenses[i].cost <= j) {

            // copy value from above row in the same column if true
 // else look at the value offset by the current rows cost  this.planner[i][j] =  this.planner[i - 1][j] 
                                || this.planner[i - 1][j -
                                expenses[i].cost];
         } else {
            // copy value from above row in the same column
  this.planner[i][j] =  this.planner[i - 1][j];
         }
      });
   }

   // no results found
  if (!this.planner[size - 1][sum]) {
      return [];
   }

   // generate the outcomes from the results found
  this.generateOutcomes(expenses, size - 1, sum, []);

   return this.outcomes;
}
```

接下来，我们可以实现`generateOutcomes()`方法，这将允许我们递归地捕获可能的路径。当我们列出我们的二维数组并查看生成的数组的外观时，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/6e297533-3d83-4957-ae0c-38525e7b20c5.png)

您可以在上面的屏幕截图中看到，列`0`（即总和`0`）都是`true`，对于行`0`（成本`5`），唯一的其他所有值都为 true 的列是列 5（即总和`5`）。

现在，继续下一行，让我们逐个分析值，例如，在这个阶段，来自当前行和上面一行的成本`5`和`3`不能相加得到成本`1`或`2`，但可以得到`3`、`5`和`8`，所以只有它们是`true`，其余都是`false`。

现在，继续到下一行的每个值，我们可以尝试从上面的行导入值，如果为 true，则从当前行的成本中减去该列总和，并检查上面一行的该列是否为 true。这样我们就可以确定总和是由先前的子集确定的。

例如，在第`3`行第`1`列，我们只是从父行导入（记住列`0`始终为`true`）。当我们到达第`2`列时，我们看到父行的列`2`为`false`，所以我们用当前行的成本（`2`）抵消这一列的总和（`2`），所以我们最终得到了第`2`行第`0`列为`true`。因此，我们将值为`true`分配给第`2`行第`2`列，然后我们继续这个过程，直到结束。

构建整个数组后，我们需要从最后开始，也就是`array[4][10]`，然后递归向上遍历，直到达到总和`0`或者到达非零总和的顶部：

```js
generateOutcomes(expenses, i, sum, p) {
   // reached the end and the sum is non zero
  if(i === 0 && sum !== 0 && this.planner[0][sum]) {
      p.push(expenses[i]);
      this.outcomes.push(_.cloneDeep(p));
      p = [];
      return;
   }

   // reached the end and the sum is zero
 // i.e. reached the origin  if(i === 0 && sum === 0) {
      this.outcomes.push(_.cloneDeep(p));
      p = [];
      return;
   }

   // if the sum can be generated
 // even without the current value  if(this.planner[i - 1][sum]) {
      this.generateOutcomes(expenses, i - 1, sum, _.cloneDeep(p));
   }

   // if the sum can be derived
 // only by including the the current value  if(sum >= expenses[i].cost && this.planner[i - 1][sum -
   expenses[i].cost]) {
      p.push(expenses[i]);
      this.generateOutcomes(expenses, i - 1, sum - expenses[i].cost,
      p);
   }
}
```

现在，这可以在我们的计划中使用，以生成用户选择的选项列表：

```js
var Planner = require('./dp');

let expenses = [
   {
      type: 'rent',
      cost: 5
  },
   {
      type: 'food',
      cost: 3
  },
   {
      type: 'entertainment',
      cost: 2
  },
   {
      type: 'car and gas',
      cost: 2
  },
   {
      type: 'ski-trip',
      cost: 5
  }
];
let total = 10;

var options = new Planner(expenses.length, total).analyze(expenses, total);

console.log(options);
```

运行上面的代码记录符合我们预算的不同组合，结果是：

```js
[ 
    [ { type: 'entertainment', cost: 2 },
      { type: 'food', cost: 3 },
      { type: 'rent', cost: 5 } 
    ],
    [ { type: 'car and gas', cost: 2 },
      { type: 'food', cost: 3 },
      { type: 'rent', cost: 5 } 
    ],
    [ { type: 'ski-trip', cost: 5 }, 
      { type: 'rent', cost: 5 } 
    ],
    [ { type: 'ski-trip', cost: 5 },
      { type: 'entertainment', cost: 2 },
      { type: 'food', cost: 3 } 
    ],
    [ { type: 'ski-trip', cost: 5 },
      { type: 'car and gas', cost: 2 },
      { type: 'food', cost: 3 } 
    ] 
]
```

# 使用贪婪算法构建旅行行程

贪婪算法是一种将问题分解为较小子问题，并根据每一步的局部优化选择拼凑出每个子问题的解决方案的算法。这意味着，在加权边图的情况下，例如，下一个节点是根据从当前节点出发的最小成本来选择的。这可能不是最佳路径，但是在贪婪算法的情况下，获得解决方案是主要目标，而不是获得完美或理想的解决方案。

在这个用例中，我们有一组城市以及前往每个城市的权重（旅行/停留成本+享受因素等）。目标是找出我们想要旅行和访问这些城市的方式，以便旅行是完整和有趣的。当然，对于给定的一组城市，可以以许多可能的方式前往这些城市，但这并不保证路径将被优化。为了解决这个问题，我们将使用 Kruskal 的最小生成树算法，这是一种贪婪算法，将为我们生成最佳可能的解决方案。图中的生成树是指所有节点都连接在一起，并且节点之间没有循环的图。

假设我们的输入数据格式如下，与我们之前在 Dijkstra 示例中看到的格式相同，只是我们没有定义节点之间的方向，允许我们从任一方向进行旅行：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/da5896ae-c1eb-4e81-9f3a-932850db3b74.png)

这些数据可以以编程方式写成如下形式：

```js
const graph = {
   'SF': { 'SB': 326, 'MT': 118, 'SJ': 49 },
   'SJ': { 'MT': 72, 'FR': 151, 'BK': 241 },
   'MT': { 'SB': 235, 'LA': 320 },
   'SB': { 'LA': 95 },
   'LA': { 'SD': 120 },
   'SD': { 'PX': 355 },
   'FR': { 'LV': 391 },
   'BK': { 'LA': 112, 'SD': 232, 'PX': 483, 'LV': 286 },
   'LV': { 'PX': 297 },
   'PX': {}
};
```

从这些信息中，我们可以提取唯一的边，如下所示：

```js
[ 
  { from: 'SF', to: 'SB', weight: 326 },
  { from: 'SF', to: 'MT', weight: 118 },
  { from: 'SF', to: 'SJ', weight: 49 },
  { from: 'SJ', to: 'MT', weight: 72 },
  { from: 'SJ', to: 'FR', weight: 151 },
  { from: 'SJ', to: 'BK', weight: 241 },
  { from: 'MT', to: 'SB', weight: 235 },
  { from: 'MT', to: 'LA', weight: 320 },
  { from: 'SB', to: 'LA', weight: 95 },
  { from: 'LA', to: 'SD', weight: 120 },
  { from: 'SD', to: 'PX', weight: 355 },
  { from: 'FR', to: 'LV', weight: 391 },
  { from: 'BK', to: 'LA', weight: 112 },
  { from: 'BK', to: 'SD', weight: 232 },
  { from: 'BK', to: 'PX', weight: 483 },
  { from: 'BK', to: 'LV', weight: 286 },
  { from: 'LV', to: 'PX', weight: 297 } 
]
```

# 理解生成树

在继续实现伪代码和代码之前，让我们花一些时间了解生成树是什么，以及我们如何利用它们来简化前面提到的问题。

图中的生成树是一系列边，可以连接所有节点而不形成任何循环。因此，很明显对于任何给定的图，可能会有多个生成树。在我们的例子中，现在更有意义的是我们想要生成**最小生成树**（**MST**），也就是说，边的总权重最小的生成树。

然而，我们如何生成生成树并确保它具有最小值呢？解决方案虽然不太明显，但相当简单。让我们用伪代码来探讨这个方法。

# 伪代码

现在手头的问题已经归结为以下内容——用最小权重的边连接图的所有节点，且没有循环。为了实现这一点，首先，我们需要分离所有的边，并按权重递增的顺序进行排序。然后，我们使用一种称为`按秩合并`的技术来获得最终的边列表，这些边可以用来创建 MST：

```js
SORT all edges by weight in increasing order

DIVIDE all nodes into their own subsets whose parent is the node iteself

WHILE more edges are required

    EXTRACT the first edge from the list of edges

    FIND the parent nodes of the from and to nodes of that edge

    IF start and end nodes do not have same parent

        ADD edge to results

        GET parent of from node and to node

        IF parent nodes of from and to are the same rank

            SET one node as the parent of the other and increment rank 
            of parent

        ELSE

            SET parent of element with lesser rank            

RETURN Results
```

在`find()`方法中，我们将执行一种称为路径压缩的小优化。听起来很花哨，但实际上并不是。假设我们在一个名为`A`的节点，其父节点是节点`B`，而其父节点是节点`C`。当我们试图确定这一点时，我们只需一次解析整个路径，然后下一次，我们就记住了节点`A`的父节点最终是节点`C`。我们做这件事的方式也相对简单——每次我们遍历树的上一个节点时，我们将更新它的`parent`属性：

```js
FIND_PARENT(all_subsets, currentNode)

    IF parent of currentNode is NOT currentNode

        FIND_PARENT(all_subsets, currentNode.parent)

    RETURN currentNode.parent
```

# 使用贪婪算法实现最小生成树

到目前为止，我们已经按照前面描述的方式设置了数据集。现在，我们将从这些数据生成边，然后将其传递给我们的生成树类以生成 MST。因此，让我们将以下代码添加到`greeds/travel.js`中：

```js
const _ = require('lodash');
const MST = require('./mst');

const graph = {
   'SF': { 'SB': 326, 'MT': 118, 'SJ': 49 },
   'SJ': { 'MT': 72, 'FR': 151, 'BK': 241 },
   'MT': { 'SB': 235, 'LA': 320 },
   'SB': { 'LA': 95 },
   'LA': { 'SD': 120 },
   'SD': { 'PX': 355 },
   'FR': { 'LV': 391 },
   'BK': { 'LA': 112, 'SD': 232, 'PX': 483, 'LV': 286 },
   'LV': { 'PX': 297 },
   'PX': {}
};

const edges= [];

_.forEach(graph, (values, node) => {
   _.forEach(values, (weight, city) => {
      edges.push({
         from: node,
         to: city,
         weight: weight
      });
   });
});

var mst = new MST(edges, _.keys(graph)).getNodes();

console.log(mst);
```

我们的 MST 类可以添加到`greedy/mst.js`中，如下所示：

```js
const _ = require('lodash');

class MST {

   constructor(edges, vertices) {
      this.edges = _.sortBy(edges, 'weight');
      this.vertices = vertices;
   }

   getNodes () {
      let result = [];

      // subsets to track the parents and ranks
  var subsets = {};

      // split each vertex into its own subset
 // with each of them initially pointing to themselves  _.each(this.vertices, (val)=> {
         subsets[val] = {
            parent: val,
            rank: 0
  };
      });

      // loop over each until the size of the results
 // is 1 less than the number of vertices  while(!_.isEqual(_.size(result), _.size(this.vertices) - 1)) {

         // get next edge
  var selectedEdge = this.edges.shift();

         // find parent of start and end nodes of selected edge
  var x = this.find(subsets, selectedEdge.from);
         var y = this.find(subsets, selectedEdge.to);

         // if the parents nodes are not the same then
 // the nodes belong to different subsets and can be merged  if (!_.isEqual(x, y)) {

            // add to result
  result.push(selectedEdge);

            // push is resultant tree as new nodes
  this.union(subsets, x, y);
         }
      }

      return result;
   }

   // find parent with path compression
  find(subsets, i) {
      let subset = subsets[i];

      // until the parent is not itself, keep updating the
 // parent of the current node  if (subset.parent != i) {
         subset.parent = this.find(subsets, subset.parent);
      }

      return subset.parent;
   }

   // union by rank
  union(subsets, x, y) {
      // get the root nodes of each of the nodes
  let xRoot = this.find(subsets, x);

      let yRoot = this.find(subsets, y);

      // ranks equal so it doesnt matter which is the parent of which
      node
  if (_.isEqual(subsets[xRoot].rank, subsets[yRoot].rank)) {

         subsets[yRoot].parent = xRoot;

         subsets[xRoot].rank++;

      } else {
         // compare ranks and set parent of the subset
  if(subsets[xRoot].rank < subsets[yRoot].rank) {

            subsets[xRoot].parent = yRoot;
         } else {

            subsets[yRoot].parent = xRoot;
         }
      }
   }

}

module.exports = MST;
```

运行上述代码将记录边缘，如下所示：

```js
[ { from: 'SF', to: 'SJ', weight: 49 },
  { from: 'SJ', to: 'MT', weight: 72 },
  { from: 'SB', to: 'LA', weight: 95 },
  { from: 'BK', to: 'LA', weight: 112 },
  { from: 'LA', to: 'SD', weight: 120 },
  { from: 'SJ', to: 'FR', weight: 151 },
  { from: 'MT', to: 'SB', weight: 235 },
  { from: 'BK', to: 'LV', weight: 286 },
  { from: 'LV', to: 'PX', weight: 297 } ]
```

一旦连接，这些路径将如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/c9a3e0e6-cf76-4109-b6f3-e6c6b355af4c.png)

# 使用分支和界限算法创建自定义购物清单

分支和界限算法适用于一组涉及组合优化的问题。这意味着我们手头可能有一个问题，并不一定有一个正确的解决方案，但根据我们拥有的信息，我们需要从可用解决方案的有限但非常大的数量中生成最佳解决方案。

我们将使用分支和界限算法来优化和解决一类称为 0/1 背包问题的动态规划问题。在这种情况下，考虑我们有一个购物清单，其中列出了物品、它们的成本（以美元计）以及它们对你的重要性（价值）在 0 到 10 的范围内。例如，考虑以下示例清单：

```js
const list = [
   {
      name: 'vegetables',
      value: 12,
      cost: 4   },
   {
      name: 'candy',
      value: 1,
      cost: 1   },
   {
      name: 'magazines',
      value: 4,
      cost: 2   },
   {
      name: 'dvd',
      value: 6,
      cost: 2   },
   {
      name: 'earphones',
      value: 6,
      cost: 3   },
   {
      name: 'shoes',
      value: 4,
      cost: 2   },
   {
      name: 'supplies',
      value: 9,
      cost: 3   }
];
```

给定清单，我们现在需要找到最佳组合以最大化价值，给定一个固定的预算（例如，10 美元）。该算法称为 0/1 背包，因为你可以做出的决定只有二进制，即，要么拿起一个物品，要么放下它。

现在，让我们试着从数学的角度理解问题陈述是什么。我们希望在预算范围内最大化价值，因此如果我们假设我们有`e[1], e[2], e[3]`等元素，我们知道每个元素都可以被选择（这将为其分配一个值 1）或不选择（这将为其分配一个值 0），为了确定总价值，我们可以将其公式化如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/226735ec-f528-40d7-95b2-bb927ad02550.jpg)

虽然我们试图最大化价值，但我们也希望保持总成本低于预算：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/099d05c5-9ea6-4a49-90e7-4324ad5763e1.jpg)

好的，很好，现在我们知道问题在哪里了，但是对于这个问题有什么解决方案呢？由于我们知道值始终只能是 0 或 1，我们可以创建一个二叉树来表示解的状态空间，然后在每个节点上为每种可能性布置一个分支；例如在我们的情况下，我们将有*2*^(*n*)种可能性（n = 7），总共 128 种。现在，遍历这 128 种可能性听起来并不是很理想，我们可以注意到这个数字会呈指数增长。

# 理解分支和界限算法

在编写伪代码之前，让我们分解解决方案以便更好地理解。我们要做的是创建一个二叉树，在树的每个级别上，我们要为到达该节点的成本、节点的价值和到达该节点的成本的上限分配值。

然而，我们如何计算树的上限呢？为了确定这一点，让我们首先将我们的问题分解成更小的部分：

```js
const costs = [4, 1, 2, 2, 3, 2, 3];
const value = [12, 1, 4, 6, 6, 4, 9];
const v2c = [12/4, 1/1, 4/2, 6/2, 6/3, 4/2, 9/3];
const maxCost = 10
```

一旦我们有了这个，我们将按照价值与成本比的递减顺序重新排列我们的元素，因为我们希望以最小的成本选择价值最高的元素：

```js
const costs = [4, 2, 3, 3, 2, 2, 1];
const value = [12, 6, 9, 6, 4, 4, 1];
const v2c = [3, 3, 3, 2, 2, 2, 1];
const maxCost = 10;
```

为了确定上限，我们现在将使用贪婪算法（按递减顺序排列的元素），在其中我们将允许分数值以获得可能的最高上限。

因此，让我们首先选择显而易见的第一个元素，其价值为`12`，成本为`4`，因此此步骤的总上限价值为`12`，总成本为`4`，小于最大值，即`10`。然后，我们继续下一个元素，其中上限现在变为*12+6=18*，成本为*4+2=6*，仍然小于`10`。然后，我们选择下一个元素，将价值的上限提高到*18+9=27*，成本为*6+3=9*。如果我们选择成本为`3`的下一个元素，我们将超过最大成本，因此我们将按比例选择它，即*(剩余成本/项目成本) * 项目价值*，这将等于(1/3)*6*，即`2`。因此，根元素的上限为*27+2=29*。

因此，我们现在可以说在给定的约束条件下，例如成本和价值，我们可以获得的上限值是`29`。现在我们有了价值的上限，我们可以为我们的二叉树创建一个根元素，该根元素的上限值为此，成本和价值分别为 0。

一旦计算出根节点的最大上限，我们可以从第一个节点开始递归地重复这个过程，为后续节点计算。在每个级别上，我们将以反映节点被选择与未被选择时的值的方式更新成本、值和上限：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/hsn-dsal-js/img/d8282701-a7f3-4e8e-bc5c-23064eb18a5d.png)

在上图中，您可以注意到我们已经为几个级别构建了状态空间树，显示了当采取分支和不采取分支时每个节点的状态。正如您所看到的，其中一些分支低于我们之前计算的最大上限**27**，而其中一个分支超过了**27**，因此我们可以将该分支从进一步考虑中移除。现在，在每个步骤中，我们的主要目标是在增加累积值的同时保持在上限以下或等于上限。任何偏离太远或超过上限的分支都可以安全地从考虑中移除。

# 实施分支和界限算法

到目前为止，我们已经讨论了如何逐步为每个可用元素构建状态空间树，但这并不是必要的，我们只需要根据我们的界限和已设置的最大成本有选择地添加节点。

那么，对我们的实施意味着什么？我们将逐个节点地考虑，考虑如果包括它或者不包括它会发生什么，然后根据我们设置的条件（上限）将其添加到队列中以供进一步处理。

由于我们已经有了一系列项目，我们将首先进行一些转换，以使算法的其余部分更简单：

```js
const _ = require('lodash');

class BranchAndBound {

   constructor(list, maxCost) {
      // sort the costs in descending order for greedy calculation of 
      upper bound
  var sortedList = _.orderBy(list, 
                     (option) => option.value/option.cost,
                     'desc');

      // original list
  this.list = list;

      // max allowed cost
  this.maxCost = maxCost;

      // all costs
  this.costs = _.map(sortedList, 'cost');

      // all values
  this.values = _.map(sortedList, 'value');
   }
}

module.exports = BranchAndBound;
```

一旦我们有了成本和值排序并提取出来，我们就可以实现算法来计算每个节点的最大值，以及当前节点的最大上限值，和不包括当前节点的情况：

```js
const _ = require('lodash');

class BranchAndBound {

   constructor(list, maxCost) {
      // sort the costs in descending order for greedy calculation of
      upper bound
  var sortedList = _.orderBy(list,
                     (option) => option.value/option.cost,
                     'desc');

      // original list
  this.list = list;

      // max allowed cost
  this.maxCost = maxCost;

      // all costs
  this.costs = _.map(sortedList, 'cost');

      // all values
  this.values = _.map(sortedList, 'value');
   }

   calculate() {
      // size of the input data set
  var size = _.size(this.values);

      // create a queue for processing nodes
  var queue = [];

      // add dummy root node
  queue.push({
         depth: -1,
         value: 0,
         cost: 0,
         upperBound: 0
  });

      // initialize result
  var maxValue = 0;

      // initialize path to the result
  var finalIncludedItems = [];

      // while queue is not empty
 // i.e leaf node not found  while(!_.isEmpty(queue)) {

         // initialize next node
  var nextNode = {};

         // get selected node from queue
  var currentNode = queue.shift();

         // if leaf node, no need to check for child nodes
  if (currentNode.depth !== size - 1) {

            // increment depth of the node
  nextNode.depth = currentNode.depth + 1;

            /*
 * *  We need to calculate the cost and value when the next
               item *  is included and when it is not * * *  First we check for when it is included */   // increment cost of the next node by adding current nodes
            cost to it // adding current nodes cost is indicator that it is
            included  nextNode.cost =  currentNode.cost +
            this.costs[nextNode.depth];

            // increment value of the next node similar to cost
  nextNode.value =  currentNode.value +
            this.values[nextNode.depth];

            // if cost of next node is below the max and the value
            provided
 // by including it is more than the currently accrued value // i.e. bounds and constrains satisfied  if (nextNode.cost <= this.maxCost && nextNode.value >
            maxValue) {

               // add node to results
  finalIncludedItems.push(nextNode.depth);

               // update maxValue accrued so far
  maxValue = nextNode.value;
            }

            // calculate the upper bound value that can be
 // generated from the new node  nextNode.upperBound = this.upperBound(nextNode, size,
                              this.maxCost, this.costs, this.values);

            // if the node is still below the upper bound
  if (nextNode.upperBound > maxValue) {

               // add to queue for further consideration
  queue.push(_.cloneDeep(nextNode));
            }

            /*
 *  Then we check for when the node is not included */   // copy over cost and value from previous state  nextNode.cost = currentNode.cost;
            nextNode.value = currentNode.value;

            // recalculate upper bound
  nextNode.upperBound = this.upperBound(nextNode, size,
                              this.maxCost, this.costs, this.values);

            // if max value is still not exceeded,
 // add to queue for processing later  if (nextNode.upperBound > maxValue) {

               // add to queue for further consideration
  queue.push(_.cloneDeep(nextNode));
            }
         }
      }

      // return results
  return { val: maxValue, items: _.pullAt(this.list,
      finalIncludedItems) };
   }

   upperBound(node, size, maxCost, costs, values) {
      // if nodes cost is over the max allowed cost
  if (node.cost > maxCost) {
         return 0;
      }

      // value of current node
  var valueBound = node.value;

      // increase depth
  var nextDepth = node.depth + 1;

      // init variable for cost calculation
 // starting from current node  var totCost = node.cost;

      // traverse down the upcoming branch of the tree to see what
 // cost would be at the leaf node  while ((nextDepth < size) && (totCost + costs[nextDepth] <=
      maxCost)) {
         totCost += costs[nextDepth];
         valueBound += values[nextDepth];
         nextDepth++;
      }

      // allow fractional value calculations
 // for the last node  if (nextDepth < size) {
         valueBound += (maxCost - totCost) * values[nextDepth] / 
         costs[nextDepth];
      }

      // return final value at leaf node
  return valueBound;
   }
}

module.exports = BranchAndBound;
```

运行相同的算法，我们得到了返回给我们的最大值的结果：

```js
const _ = require('lodash');
const BnB = require('./bnb');

const list = [
   {
      name: 'vegetables',
      value: 12,
      cost: 4
  },
   {
      name: 'candy',
      value: 1,
      cost: 1
  },
   {
      name: 'magazines',
      value: 4,
      cost: 2
  },
   {
      name: 'dvd',
      value: 6,
      cost: 2
  },
   {
      name: 'earphones',
      value: 6,
      cost: 3
  },
   {
      name: 'shoes',
      value: 4,
      cost: 2
  },
   {
      name: 'supplies',
      value: 9,
      cost: 3
  }
];

const budget = 10;

var result = new BnB(list, budget).calculate();

console.log(result);
```

这记录如下：

```js
{ 
  val: 28,
  items:[ 
     { name: 'vegetables', value: 12, cost: 4 },
     { name: 'candy', value: 1, cost: 1 },
     { name: 'magazines', value: 4, cost: 2 },
     { name: 'supplies', value: 9, cost: 3 } 
  ] 
}
```

# 何时不使用蛮力算法

蛮力算法是一种问题解决技术，它在选择或拒绝问题的最终解决方案之前，探索特定问题的每种可能的解决方案。

面对挑战时，最自然的反应是蛮力解决方案，或者首先尝试蛮力解决方案，然后再进行优化。然而，这真的是解决这类问题的最佳方式吗？有更好的方法吗？

答案绝对是肯定的，因为到目前为止我们在整个章节中已经看到了。蛮力不是解决方案，直到它是唯一的解决方案。有时，我们可能会觉得我们正在创建一个自定义算法来解决我们所面临的问题，但我们需要问自己是否我们真的正在尝试找到问题的所有可能解决方案，如果是的话，那么这又是蛮力。

不幸的是，蛮力不是一个固定的算法供我们检测。方法随着问题陈述而改变，因此需要查看我们是否试图生成所有解决方案并避免这样做。

然而，你可能会问，我如何知道何时蛮力解决一个问题，何时应该尝试找到最优解？我如何知道更优解或算法是否存在？

没有快速简单的方法来判断是否有比蛮力更容易的解决方案来计算任何解决方案。例如，一个问题可以以蛮力方式解决，例如，本章中的任何一个例子。我们可以列出所有可能性（无论生成这个列表有多困难，因为可能存在大量的可能性），然后筛选出我们认为是解决方案的那些。

在我们生成最短路径的示例中，我们使用 Dijkstra 算法来使用与到达每个城市相关的成本。这个问题的蛮力解决方案是计算从起点到终点节点的图中所有可用路径，然后计算每条路径的成本，最终选择成本最低的路径。

了解问题陈述可以极大地帮助减少问题的复杂性，也可以帮助我们避免蛮力解决方案。

# 蛮力斐波那契生成器

例如，让我们以斐波那契生成器为例，蛮力生成一些数字：

```js
var _ = require('lodash');

var count = 10;

bruteForceFibonacci(count);

function bruteForceFibonacci(count) {
   var prev = 0;
   var next = 1;
   var res = '';

   res += prev;
   res += ',' + next;

   _.times(count, ()=> {
      var tmp = next;
      next = prev + next;
      prev = tmp;

      res += ',' + next;
   });

   console.log(res);
}
```

在这里，我们可以看到我们没有应用任何领域知识；我们只是从系列中取出前两个数字并相加。这是一个很好的方法，但我们可以看到这里有一些改进的空间。

# 递归斐波那契生成器

我们可以使用递归生成斐波那契数列如下：

```js
function recursiveFibonacci(num) {
   if (num == 0) {
      return 0;
   } else if (num == 1 || num == 2) {
      return 1;
   } else {
      return recursiveFibonacci(num - 1) + recursiveFibonacci(num - 2);
   }
}
```

你可以看到我们应用了与之前相同的概念，即下一个数字是斐波那契数列数字的前两个数字的总和。然而，我们依赖递归来在需要新值时重新计算所有旧值。

# 记忆化斐波那契生成器

我们可以进一步增强生成器，使用记忆化，这是一种只计算一次值并记住它以备后用的技术：

```js
function memoizedFibonacci(num) {
   if (num == 0) {
      memory[num] = 0;
      return 0;
   } else if (num == 1 || num == 2) {
      memory[num] = 1;
      return 1;
   } else {
      if (!memory[num]) {
         memory[num] = memoizedFibonacci(num - 1) +
         memoizedFibonacci(num - 2);
      }

      return memory[num];
   }
}
```

在这里，我们依赖于一个名为`memory`的内存变量来存储和检索系列中先前计算的斐波那契数的值，从而避免一系列重复计算。

如果记录每种方法所花费的时间，您会发现随着输入数字的大小增加，递归方法的性能确实会显著下降。仅仅因为一个算法是蛮力算法，并不意味着它是最差/最慢/最昂贵的。然而，通过对递归进行简单的改变（记忆化），您会发现它再次比蛮力技术更快。

在尝试为任何问题编写解决方案时，最大的帮助是减少不必要的空间和时间复杂度。

# 总结

在本章中，我们涵盖了一些重要类型的算法，并为一些示例用例实施了它们。我们还讨论了各种算法优化技术，如记忆化和回溯。

在下一章中，我们将讨论一些排序技术，并将它们应用于解决一些示例。
