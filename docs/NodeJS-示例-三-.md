# NodeJS 示例（三）

> 原文：[`zh.annas-archive.org/md5/59094B51B116DA7DDAC7E4359313EBB3`](https://zh.annas-archive.org/md5/59094B51B116DA7DDAC7E4359313EBB3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章，“标记、分享和喜欢”

第八章，“创建页面和事件”，是关于创建页面并将事件附加到它们上面。我们还使得评论的发布成为可能。在本书的这一部分，我们将添加三个新功能。几乎每个社交网络都包含一种喜欢帖子的方式。这是一种很好的方式来对你感兴趣的帖子进行排名。分享是另一个流行的过程，包括发布已经存在的帖子。有时，我们想把帖子转发给我们的一些朋友。在这些情况下，我们会**标记**人。这三个功能将在本章中实现。以下是将指导我们完成开发过程的各个部分：

+   选择朋友并将他们的 ID 发送到后端

+   存储标记的用户并在用户的动态中显示它们

+   分享帖子

+   喜欢帖子并计算喜欢的数量

+   显示喜欢的数量

# 选择朋友并将他们的 ID 发送到后端

我们将从不仅随机用户的标记开始，还包括当前用户的朋友。我们想要构建的功能将放置在主页上。创建新帖子的表单将包含一个复选框列表。非常第一步将是从 API 中获取朋友。在第六章，“添加友谊功能”中，我们已经做到了。我们有一个`models/Friends.js`文件，查询 Node.js 服务器并返回用户列表。所以，让我们使用它。在`controllers/Home.js`的顶部，我们将添加以下内容：

```js
var Friends = require('../models/Friends');
```

稍后，在`onrender`处理程序中，我们将使用所需的模块。API 的结果将以以下方式设置为本地`friends`变量的值：

```js
var friends = new Friends();
friends.fetch(function(err, result) {
  if (err) { throw err; }
  self.set('friends', result.friends);
});
```

控制器在其数据结构中有用户的朋友，我们可以更新模板。我们将通过记录进行循环，并以以下方式为每个用户显示复选框：

```js
// frontend/tpl/home.html
{{#if friends.length > 0}}
<p>Tag friends:
{{#each friends:index}}
  <label>
    <input type="checkbox" name="{{taggedFriends}}"  value="{{friends[index].id}}" />
    {{friends[index].firstName}} 
    {{friends[index].lastName}}
  </label>
{{/each}}
</p>
{{/if}}
```

Ractive.js 框架很好地处理复选框组。在我们的情况下，JavaScript 组件将接收一个名为`taggedFriends`的变量。它将是一个选定用户的数组，或者如果用户没有选择任何内容，则为空数组。预期的输出是用户的朋友列表，以复选框和标签的形式呈现。

一旦 Gulp 编译了模板的新版本并且我们点击浏览器的刷新按钮，我们将在屏幕上看到我们的朋友。我们将选择其中一些，填写帖子的内容，然后按下**发布**按钮。应用程序向 API 发送请求，但没有标记的朋友。需要进行一次更改来修复这个问题。在`controllers/Home.js`文件中，我们必须使用`taggedFriends`变量的值，如下所示：

```js
formData.append('text', this.get('text'));
formData.append('taggedFriends', JSON.stringify(this.get('taggedFriends')));
model.create(formData, function(error, result) {
  ...
});
```

FormData API 只接受 Blob、文件或字符串值。我们不能发送一个字符串数组。因此，我们将使用`JSON.stringify`将`taggedFriends`序列化为字符串。在下一节中，我们将使用`JSON.parse`将字符串转换为对象。`JSON`接口在浏览器和 Node.js 环境中都可用。

# 存储标记的用户并在用户的动态中显示它们

现在，除了文本和文件，我们还发送一个用户 ID 列表——应该在帖子中标记的用户。如前所述，它们以字符串的形式传递到服务器。我们需要使用`JSON.parse`将它们转换为常规数组。以下行是`backend/api/content.js`模块的一部分：

```js
var form = new formidable.IncomingForm();
form.multiples = true;
form.parse(req, function(err, formData, files) {
  var data = {
    text: formData.text
  };
  if(formData.pageId) {
    data.pageId = formData.pageId;
  }
  if(formData.eventDate) {
    data.eventDate = formData.eventDate;
  }
  if(formData.taggedFriends) {
    data.taggedFriends = JSON.parse(formData.taggedFriends);
  }
  ...
```

`content.js`模块是`formidable`提供的前端发送的数据的地方。在此代码片段的末尾，我们从先前序列化的字符串中重构了数组。

我们可以轻松地进行这种改变并存储`data`对象。实际上，在客户端，我们将接收包含`taggedFriends`属性的帖子。然而，我们对显示朋友的名称而不是他们的 ID 感兴趣。如果前端控制器具有 ID 并且需要名称，那么它应该执行另一个 HTTP 请求到 API。这可能会导致大量的 API 查询，特别是如果我们显示了许多消息。为了防止这种情况，我们将在后端获取帖子时获取标记的人的名称。这种方法有自己的缺点，但与前面提到的变体相比仍然更好。

让我们创建一个包装所需逻辑的函数，并在保存信息到数据库之前使用它：

```js
// backend/api/content.js
var getFriendsProfiles = function(db, ids, callback) {
  if(ids && ids.length > 0) {
    var collection = db.collection('users');
    ids.forEach(function(value, index, arr) {
      arr[index] = ObjectId(value);
    });
    collection.find({ 
      _id: { $in: ids }
    }).toArray(function(err, friends) {
      var result = [];
      friends.forEach(function(friend) {
        result.push(friend.firstName + ' ' + friend.lastName);
      });
      callback(result);
    });  
  } else {
    callback([]);
  }
}
```

我们为 MongoDB 查询准备了用户的 ID。在这种情况下，需要`$in`运算符，因为我们希望获取与`ids`数组中的任何项目匹配的 ID 的记录。当 MongoDB 驱动程序返回数据时，我们创建另一个包含朋友名称的数组。`GetFriendsProfiles`将在接下来的几页中使用，我们将更新帖子的动态获取。

实际的数据存储仍然是相同的。唯一的区别是`data`对象现在包含`taggedFriends`属性：

```js
getDatabaseConnection(function(db) {
  getCurrentUser(function(user) {
    var collection = db.collection('content');
    data.userId = user._id.toString();
    data.userName = user.firstName + ' ' + user.lastName;
    data.date = new Date();
    processFiles(user._id, function(file) {
      if(file) {
        data.file = file;
      }
      collection.insert(data, done);
    });
  }, req, res);
});
```

如果我们创建一个新帖子并检查数据库中的记录，我们会看到类似于这样的东西：

```js
{
  "text": "What a nice day. Isn't it?",
  "taggedFriends": [
    "54b235be6fd75df10c278b63",
    "5499ded286c27ff13a36b253"
  ],
  "userId": "5499ded286c27ff13a36b253",
  "userName": "Krasimir Tsonev",
  "date": ISODate("2015-02-08T20:54:18.137Z")
}
```

现在，让我们更新数据库记录的获取。我们有我们朋友的 ID，但我们需要他们的名称。因此，在同一个`content.js`文件中，我们将放置以下代码：

```js
var numberOfPosts = result.length;
var friendsFetched = function() {
  numberOfPosts -= 1;
  if(numberOfPosts === 0) {
    response({
      posts: result
    }, res);
  }
}
result.forEach(function(value, index, arr) {
  arr[index].id = ObjectId(value._id);
  arr[index].ownPost = user._id.toString() ===  ObjectId(arr[index].userId).toString();
  arr[index].numberOfLikes = arr[index].likes ?  arr[index].likes.length : 0;
  delete arr[index].userId;
  delete arr[index]._id;
  getFriendsProfiles(db, arr[index].taggedFriends,  function(friends) {
    arr[index].taggedFriends = friends;
    friendsFetched();
  });
});
```

我们在`results`数组中有来自数据库的项目。遍历帖子仍然是相同的，但在`forEach`调用之后不发送响应。对于列表中的每个帖子，我们需要向 MongoDB 数据库发送请求并获取朋友的名称。因此，我们将初始化`numberOfPosts`变量，并且每次朋友名称的请求完成时，我们将减少该值。一旦它减少到 0，我们就知道最后一个帖子已经处理完毕。之后，我们将向浏览器发送响应。

这是`frontend/tpl/home.html`文件的一个小更新，将使`taggedFriends`数组可见：

```js
{{#each posts:index}}
  <div class="content-item">
    <h2>{{posts[index].userName}}</h2>
    {{posts[index].text}}
    {{#if posts[index].taggedFriends.length > 0}}
      <p>
        <small>
          Tagged: {{posts[index].taggedFriends.join(', ')}}
        </small>
      </p>
    {{/if}}
    {{#if posts[index].file}}
    <img src="img/{{posts[index].file}}" />
    {{/if}}
  </div>
{{/each}}
```

除了所有者、文本和图片（如果有的话），我们还检查是否有任何标记的人。如果有任何标记的人，那么我们将使用给定的分隔符连接`taggedFriends`数组的所有元素。结果看起来像下面的截图：

![存储标记用户并在用户的动态中显示它们](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00182.jpeg)

## 分享帖子

我们应用的分享功能将为当前用户提供重新发布已创建帖子的选项。我们应该确保用户不分享自己的记录。因此，让我们从那里开始。API 返回帖子并知道谁创建了它们。它还知道哪个用户正在发出请求。以下代码创建了一个名为`ownPost`的新属性：

```js
// backend/api/content.js
getCurrentUser(function(user) {
  ...
  getDatabaseConnection(function(db) {
    var collection = db.collection('content');
    collection.find({ 
      ...
    }).toArray(function(err, result) {
      result.forEach(function(value, index, arr) {
        arr[index].id = ObjectId(value._id);
        arr[index].ownPost = user._id.toString() ===  ObjectId(arr[index].userId).toString();
        delete arr[index].userId;
        delete arr[index]._id;
      });
      response({ posts: result }, res);
    });
  });
}, req, res);
```

这是准备帖子并将其发送到浏览器的逻辑。`getCurrentUser`属性返回当前发出请求的用户。`user._id`变量正是我们需要的。这个 ID 实际上分配给了每个帖子的`userId`属性。因此，我们将简单地比较它们，并确定是否允许分享。如果`ownPost`变量等于`true`，那么用户就不应该能够分享帖子。

在上一节中，我们添加了一个新的标记朋友的标记以显示标记的朋友。它们下方的空间似乎是放置**分享**按钮的好地方：

```js
{{#if posts[index].taggedFriends.length > 0}}
  <p>
    <small>
      Tagged: {{posts[index].taggedFriends.join(', ')}}
    </small>
  </p>
{{/if}}
{{#if !posts[index].ownPost}}
<p><input type="button" value="Share"  on-click="share:{{posts[index].id}}" /></p>
{{/if}}
```

在这里，新的`ownPost`属性开始发挥作用。如果帖子不是由当前用户发布的，那么我们将显示一个按钮，用于触发`share`事件。Ractive.js 为我们提供了发送数据的机会。在我们的情况下，这是帖子的 ID。

主页的控制器应该监听这个事件。`controllers/Home.js`的快速更新添加了监听器，如下所示：

```js
this.on('share', function(e, id) {
  var formData = new FormData();
  formData.append('postId', id);
  model.sharePost(formData, getPosts);
});
```

`model`对象是`ContentModel`类的一个实例。分享是一个新功能。因此，我们需要向不同的 API 端点发送查询。新的`sharePost`方法如下所示：

```js
// frontend/js/models/Content.js
sharePost: function(formData, callback) {
  var self = this;
  ajax.request({
    url: this.get('url') + '/share',
    method: 'POST',
    formData: formData,
    json: true
  })
  .done(function(result) {
    callback(null, result);
  })
  .fail(function(xhr) {
    callback(JSON.parse(xhr.responseText));
  });
}
```

我们在上一章中多次使用了与前面相似的代码。它向特定 URL 的后端发送一个`POST`请求。在这里，URL 是`/api/content/share`。还要提到的是，`formData`包含我们想要分享的帖子的 ID。

让我们继续，在 API 中进行必要的更改。我们已经定义了将承载此功能的 URL——`/api/content/share`。需要在`backend/API.js`中添加一个新路由，如下所示：

```js
.add('api/content/share', require('./api/content-share'))
```

下一步涉及创建`content-share`控制器。像每个其他控制器一样，我们将从要求助手开始。我们将跳过这部分，直接转到处理`POST`请求：

```js
// backend/api/content-share.js
case 'POST':
  var formidable = require('formidable');
  var form = new formidable.IncomingForm();
  form.parse(req, function(err, formData, files) {
    if(!formData.postId) {
      error('Please provide ID of a post.', res);
    } else {
      var done = function() {
        response({
          success: 'OK'
        }, res);
      };
      // ...
    }
  });
break;
```

上述方法期望一个`postId`变量。如果没有这样的变量，那么我们将以错误响应。代码的其余部分再次涉及`formidable`模块的使用和定义`done`函数以发送成功操作的响应。以下是更有趣的部分：

```js
getDatabaseConnection(function(db) {
  getCurrentUser(function(user) {
    var collection = db.collection('content');
    collection
    .find({ _id: ObjectId(formData.postId) })
    .toArray(function(err, result) {
      if(result.length === 0) {
        error('There is no post with that ID.', res);
      } else {
        var post = result[0];
        delete post._id;
        post.via = post.userName;
        post.userId = user ._id.toString();
        post.userName = user.firstName + ' ' + user.lastName;
        post.date = new Date();
        post.taggedFriends = [];
        collection.insert(post, done);
      }
    });
  }, req, res);
```

在找到应该分享的帖子后，我们将准备一个将保存为新记录的对象。我们需要对原始帖子执行一些操作：

```js
var post = result[0];
delete post._id;
post.via = post.userName;
post.userId = user ._id.toString();
post.userName = user.firstName + ' ' + user.lastName;
post.date = new Date();
post.taggedFriends = [];
collection.insert(post, done);
```

我们确实不需要`_id`属性。MongoDB 将创建一个新的。第三行定义了一个`via`属性。我们将在一分钟内讨论这个问题，但简而言之，它用于显示帖子的原始作者。`via`后面的行设置了新记录的所有者。日期也被更改了，由于这是一个新帖子，我们清除了`taggedFriends`数组。

共享的帖子现在在数据库中，并显示在用户的动态中。让我们使用`via`属性，并以以下方式显示帖子的原始创建者：

```js
// frontend/tpl/home.html
{{#each posts:index}}
<div class="content-item">
  <h2>{{posts[index].userName}}</h2>
  <p>{{posts[index].text}}</p>
  {{#if posts[index].via}}
  <small>via {{posts[index].via}}</small>
  {{/if}}
  …
```

我们将检查变量是否可用，如果是，那么我们将在帖子文本下面添加一小段文字。结果将如下所示：

![分享帖子](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00183.jpeg)

# 喜欢帖子并计算喜欢的数量

我们的社交网络用户应该能够看到一个**喜欢**按钮。点击它，他们将向 API 发送一个请求，我们的任务是计算这些点击。当然，每个用户只允许点击一次。与上一节一样，我们将从更新用户界面开始。让我们以以下方式在**分享**旁边添加另一个按钮：

```js
// frontend/tpl/home.html
<input type="button" value="Like"  on-click="like:{{posts[index].id}}" />
{{#if !posts[index].ownPost}}
<input type="button" value="Share"  on-click="share:{{posts[index].id}}" />
{{/if}}
```

新按钮分派了一个`like`事件，我们将再次传递帖子的 ID。这实际上类似于`share`事件。此外，喜欢的动作将使用与后端相同类型的通信。因此，重构我们的代码并仅使用一个函数来处理这两个功能是有意义的。在上一节中，我们在`models/Content.js`文件中添加了`sharePost`方法。让我们以以下方式将其更改为`usePost`：

```js
usePost: function(url, formData, callback) {
  var self = this;
  ajax.request({
    url: this.get('url') + '/' + url,
    method: 'POST',
    formData: formData,
    json: true
  })
  .done(function(result) {
    callback(null, result);
  })
  .fail(function(xhr) {
    callback(JSON.parse(xhr.responseText));
  });
}
```

因为唯一不同的是 URL，我们将其定义为参数。`formData`接口仍然包含帖子的 ID。以下是我们控制器的更新代码：

```js
// controllers/Home.js
this.on('share', function(e, id) {
  var formData = new FormData();
  formData.append('postId', id);
  model.usePost('share', formData, getPosts);
});
this.on('like', function(e, id) {
  var formData = new FormData();
  formData.append('postId', id);
  model.usePost('like', formData, getPosts);
});
```

我们跳过了定义另一个方法，并使模型的实现更加灵活。我们可能需要添加一个新操作，最后的微调将派上用场。

根据 API 的更改，我们遵循了相同的工作流程。需要响应`/api/content/like`的新路由，可以创建如下：

```js
// backend/API.js
add('api/content/like', require('./api/content-like'))
```

`content-like` 控制器仍然不存在。我们将创建一个新的 `backend/api/content-like.js` 文件，其中将包含与喜欢相关的逻辑。像保护未经授权用户的方法和使用 `formidable` 获取 `POST` 数据这样的常规操作都存在。这次，我们不会使用集合的 `insert` 方法。相反，我们将使用 `update`。我们将构建一个稍微复杂一些的 MongoDB 查询，并更新一个名为 `likes` 的新属性。

`update` 方法接受四个参数。第一个是条件。符合我们条件的记录将被更新。第二个包含了我们想要更新的指令。第三个参数包含了额外的选项，最后一个是一个回调函数，一旦操作结束就会被调用。这是我们的查询的样子：

```js
getDatabaseConnection(function(db) {
  getCurrentUser(function(user) {
    var collection = db.collection('content');
    var userName = user.firstName + ' ' + user.lastName;
    collection.update(
      {
        $and: [
          { _id: ObjectId(formData.postId) },
          { "likes.user": { $nin: [userName] } }
        ]
      },
      { 
        $push: { 
          likes: { user: userName }
        }
      },
      {w:1}, 
      function(err) {
        done();
      }
    );
  }, req, res);
});
```

代码确实有点长，但它完成了它的工作。让我们逐行来看一下。第一个参数，我们的条件，确保我们将要更新正确的帖子。因为我们使用了 `$and` 运算符，数组中的第二个对象也应该是有效的。你可能注意到在 `$and` 下面几行，`$push` 运算符向一个名为 `likes` 的数组中添加了一个新对象。每个对象都有一个包含点击**喜欢**按钮的用户的名字的 `name` 属性。所以，在我们的 `"likes.user": { $nin: [userName] }` 条件中，这意味着只有当 `userName` 不在 `likes` 数组的一些元素中时，记录才会被更新。这可能看起来有点复杂，但它确实是一种强大的运算符组合。如果没有这个，我们可能最终会对数据库进行多次查询。

`{w: 1}` 选项总是在传递回调时改变其值。

记录更新后，我们将简单地调用 `done` 方法并向用户发送响应。

通过对 API 的更改，我们成功完成了这个功能。现在帖子在浏览器中的样子如下：

![喜欢帖子和计算喜欢次数](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00184.jpeg)

# 显示喜欢的次数

我们将喜欢的内容保存在一个数组中。很容易对其中的元素进行计数，找出一篇帖子被喜欢的次数。我们将进行两个小改动，使这成为可能。第一个是在 API 中，那是我们准备帖子对象的地方：

```js
// backend/api/content.js
result.forEach(function(value, index, arr) {
  arr[index].id = ObjectId(value._id);
  arr[index].ownPost = user._id.toString() ===  ObjectId(arr[index].userId).toString();
  arr[index].numberOfLikes = arr[index].likes ?  arr[index].likes.length : 0;
  delete arr[index].userId;
  delete arr[index]._id;
});
```

一个新的 `numberOfLikes` 属性被附加上。记录一开始没有 `likes` 属性。所以，在使用之前我们必须检查它是否存在。如果我们有 `numberOfLikes` 变量，我们可以将前端**喜欢**按钮的标签更新为以下代码：

```js
<input type="button" value="Like ({{posts[index].numberOfLikes}})" on-click="like:{{posts[index].id}}" />
```

每个帖子创建后都没有喜欢。所以，按钮的标签是**喜欢（0）**，但第一次点击后，它会变成**喜欢（1）**。以下截图展示了这在实践中的样子：

![显示喜欢的次数](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00185.jpeg)

# 总结

本章讨论了当今社交网络中最常用的一些功能——标记、分享和喜欢。我们更新了应用程序的两侧，并验证了我们在之前章节中的知识。

下一章将讨论实时通信。我们将为用户构建一个聊天窗口，他们将能够向其他人发送实时消息。


# 第十章：添加实时聊天

在前两章中，我们通过添加新功能来扩展了我们的社交网络，以创建页面和分享帖子。在本章中，我们将讨论系统中用户之间的实时通信。我们将使用的技术称为 WebSockets。本书的这一部分计划如下：

+   了解 WebSockets

+   将 Socket.IO 引入项目

+   准备聊天区域的用户界面

+   在客户端和服务器之间交换消息

+   仅向用户的朋友发送消息

+   自定义聊天输出

# 了解 WebSockets

WebSockets 是一种在服务器和浏览器之间打开双向交互通道的技术。通过使用这种类型的通信，我们能够在没有初始请求的情况下交换消息。双方只需向对方发送事件。WebSockets 的其他好处包括较低的带宽需求和延迟。

有几种从服务器传输数据到客户端以及反之的方式。让我们检查最流行的几种方式，并看看为什么 WebSockets 被认为是实时 Web 应用的最佳选择：

+   **经典的 HTTP 通信**：客户端请求服务器的资源。服务器确定响应内容并发送。在实时应用的情况下，这并不是很实用，因为我们必须手动请求更多的数据。

+   **Ajax 轮询**：它类似于经典的 HTTP 请求，不同之处在于我们的代码会不断向服务器发送请求，例如，每隔半秒一次。这并不是一个好主意，因为我们的服务器将收到大量的请求。

+   **Ajax 长轮询**：我们再次有一个执行 HTTP 请求的客户端，但这次服务器延迟结果并不立即响应。它会等到有新信息可用时才回应请求。

+   **HTML5 服务器发送事件（EventSource）**：在这种通信类型中，我们有一个从服务器到客户端的通道，服务器会自动向浏览器发送数据。当我们需要单向数据流时，通常会使用这种技术。

+   **WebSockets**：如前所述，如果我们使用 WebSockets，我们将拥有双向数据流。客户端和服务器双方都可以在不询问对方的情况下发送消息。

服务器发送事件在某些情况下可能有效，但对于实时聊天，我们绝对需要 WebSockets，因为我们希望用户能够互相发送消息。我们将实现的解决方案如下截图所示：

![了解 WebSockets](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00186.jpeg)

每个用户都将连接到服务器并开始发送消息。我们的后端将负责将消息分发给其他用户。

使用原始 WebSockets API 可能并不那么容易。在下一节中，我们将介绍一个非常有用的 Node.js 模块来处理 WebSockets。

# 将 Socket.IO 引入项目

Socket.IO（[`socket.io/`](http://socket.io/)）是建立在 WebSockets 技术之上的实时引擎。它是一个使 Web 开发变得简单和直接的层。像现在的每一样新事物一样，WebSockets 也有自己的问题。并非每个浏览器都支持这项技术。我们可能会遇到协议问题和缺少心跳、超时或断开支持等事件。幸运的是，Socket.IO 解决了这些问题。它甚至为不支持 WebSockets 的浏览器提供了备用方案，并采用长轮询等技术。

在后端进行更改之前，我们需要安装该模块。该引擎与每个其他 Node.js 模块一样分发；它可以通过包管理器获得。因此，我们必须以以下方式将 Socket.IO 添加到`package.json`文件中：

```js
{
  "name": "nodejs-by-example",
  "version": "0.0.2",
  "description": "Node.js by example",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "socket.io": "1.3.3"
    ...
    ...
  }
}
```

在进行这些更改之后，我们将运行`npm install`并获取`node_modules/socket.io`文件夹。安装了该模块后，我们可以开始更新我们的社交网络。让我们在后端目录中添加一个`Chat.js`文件，其中包含以下代码：

```js
module.exports = function(app) {
  var io = require('socket.io')(app);
  io.on('connection', function (socket) {
    socket.emit('news', { hello: 'world' });
    socket.on('my other event', function (data) {
      console.log(data);
    });
  });
}
```

新模块导出一个接受 HTTP 服务器的函数。在`server.js`中，我们可以使用`http.createServer`来初始化它，如下所示：

```js
var app = http.createServer(checkSession).listen(port, '127.0.0.1');
console.log("Listening on 127.0.0.1:" + port);

var Chat = require('./backend/Chat');
Chat(app);
```

Socket.IO 完全建立在事件触发和监听的概念上。`io`变量代表我们的通信中心。每当新用户连接到我们的服务器时，我们都会收到一个连接事件，并且被调用的处理程序会接收一个`socket`对象，我们将使用它来处理从浏览器到和从浏览器的消息。

在上面的例子中，我们发送（`emit`）了一个带有`news`名称的事件，其中包含一些简单的数据。之后，我们开始监听来自客户端的其他事件。

现在，即使我们重新启动服务器，我们也不会收到任何 socket 连接。这是因为我们没有更改前端代码。为了使 Socket.IO 在客户端工作，我们需要在页面中包含`/socket.io/socket.io.js`文件。我们应用程序的布局存储在`backend/tpl/page.html`中，在修改后，它看起来像这样：

```js
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Node.js by example</title>
  <meta http-equiv="Content-Type" content="text/html;  charset=utf-8" />
  <meta name="description" content="Node.js by examples">
  <meta name="author" content="Packt">
  <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
  <div class="container"></div>
  <script src="img/socket.io.js"></script>
  <script src="img/ractive.js"></script>
  <script src="img/app.js"></script>
</body>
</html>
```

`socket.io.js`文件在我们的代码库中不存在。它是 Socket.IO 模块的一部分。引擎会自动注册一个路由，并确保它提供文件。

我们 WebSockets 实现测试的最后一步是连接到服务器。为了简单起见，让我们在`frontend/js/app.js`文件中添加几行代码：

```js
window.onload = function() {

  ...

  var socket = io('http://localhost:9000');
  socket.on('news', function (data) {
    console.log(data);
    socket.emit('my other event', { my: 'data' });
  });

};
```

我们将把我们的代码放在`onload`处理程序中，因为我们希望确保所有外部 JavaScript 文件都已完全加载。然后，我们将初始化到`http://localhost:9000`的连接，这是 Node.js 服务器运行的相同主机和端口。代码的其余部分只做一件事——监听`news`事件，并响应其他事件消息。如果我们在浏览器中运行服务器并加载`http://localhost:9000`，我们将在终端中得到以下结果：

![将 Socket.IO 引入项目](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00187.jpeg)

我们得到`{ my: 'data' }`作为输出，因为在`backend/Chat.js`文件中有`console.log(data)`。

# 准备聊天区域的 UI

因为实时聊天是我们社交网络的重要部分，我们将为其创建一个单独的页面。就像我们在之前的章节中所做的那样，我们将在主导航中添加一个新链接，如下所示：

```js
<nav>
  <ul>
    <li><a on-click="goto:home">Home</a></li>
    {{#if !isLogged }}
      <li><a on-click="goto:register">Register</a></li>
      <li><a on-click="goto:login">Login</a></li>
    {{else}}
      <li class="right"><a on-click="goto:logout">Logout</a></li>
      <li class="right"><a  
        on-click="goto:profile">Profile</a></li>
      <li class="right"><a on-click="goto:find-friends">Find  friends</a></li>
      <li class="right"><a on-click="goto:pages">Pages</a></li>
      <li class="right"><a on-click="goto:chat">Chat</a></li>
    {{/if}}
  </ul>
</nav>
```

列表中的最新链接将把用户转到`http://localhost:9000/chat`的 URL，用户将在那里看到聊天的界面。

让我们通过调整`frontend/js/app.js`文件来处理`/chat`路由。让我们对路由进行另一个添加，如下所示：

```js
Router
...
...
.add('chat', function() {
  if(userModel.isLogged()) {
    var p = new Chat();
    showPage(p);
  } else {
    Router.navigate('login');
  }    
})
.add(function() {
  Router.navigate('home');
})
.listen()
.check();
```

在同一个文件中，我们将需要`frontend/js/controllers/Chat.js`模块。它将包含客户端的聊天逻辑。我们将从一些简单的东西开始——一个基本的 Ractive.js 组件，可以实现如下：

```js
// frontend/js/controllers/Chat.js
module.exports = Ractive.extend({
  template: require('../../tpl/chat'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  data: {
    output: ''
  },
  onrender: function() {

  }
});
```

像我们应用程序中的每个其他控制器一样，`Chat.js`有一个关联的模板，其中包含一个空的`<div>`元素来显示聊天消息，一个文本字段和一个发送数据到服务器的按钮：

```js
// front/tpl/chat.html
<header>
  <navigation></navigation>
</header>
<div class="hero">
  <h1>Chat</h1>
</div>
<form>
  <div class="chat-output">{{output}}</div>
  <input type="text" value="{{text}}" />
  <a href="#" on-click="send" class="button">Send</a>
</form>
<appfooter />
```

值得一提的是，如果要更新`chat-output`元素的内容，需要更改`output`变量的值。按钮还会触发一个`send`事件，我们将在下一节中捕获这个事件。在编译资产之后，如果您转到聊天的 URL，您将看到以下屏幕：

![准备聊天区域的 UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00188.jpeg)

# 在客户端和服务器之间交换消息

我们准备编写一些可工作的 Socket.IO 代码。到目前为止，我们放置了一些代码片段，只是证明了套接字连接的工作。例如，添加到`frontend/js/app.js`的代码应该移动到`frontend/js/controllers/Chat.js`，这是负责聊天页面的控制器。因为它充当了这个实时功能的基础，我们将从那里开始。让我们向组件添加一些本地变量，如下所示：

```js
data: {
  messages: ['Loading. Please wait.'],
  output: '',
  socketConnected: false
}
```

这些变量具有默认值，并且可以在组件模板中使用。第一个变量`messages`将保存来自聊天用户的所有消息，包括当前用户。`output`变量用于在屏幕上填充消息容器。最后一个`socketConnected`控制文本字段和按钮的可见性。如果设置为`false`，则控件将被隐藏。在与服务器初始化连接或由于某种原因断开连接之前，最好隐藏聊天输入文本字段，直到与服务器的连接初始化。否则，我们可能会因某种原因断开连接。更新后的模板如下所示：

```js
// frontend/tpl/chat.html
<header>
  <navigation></navigation>
</header>
<div class="hero">
  <h1>Chat</h1>
</div>
<form>
  <div class="chat-output"  data-component="output">{{{output}}}</div>
  {{#if socketConnected}}
    <input type="text" value="{{text}}" />
    <a href="#" on-click="send" class="button">Send</a>
  {{/if}}
</form>
<appfooter />
```

差异在于包裹字段和按钮的`{{if}}`运算符。在本章末尾，我们将对消息进行着色，并需要传递 HTML 标签。我们将使用`{{{output}}}`而不是`{{output}}`，以便框架正确显示它们（通过关闭自动转义）。

让我们回到前端控制器。我们提到的代码放在`app.js`中移动到这里。这是与套接字服务器的实际连接。我们将以以下方式扩展它：

```js
var self = this;
var socket = io('http://localhost:9000');
socket.on('connect', function() {
  self.push('messages', 'Connected!');
  self.set('socketConnected', true);
  self.find('input[type="text"]').focus();
});
socket.on('disconnect', function() {
  self.set('socketConnected', false);
  self.push('messages', 'Disconnected!');
});
socket.on('server-talking', function(data) {
  self.push('messages', data.text);
});
```

收到`connect`事件后，我们将`Connected!`字符串添加到`messages`数组中。因此，在收到**加载中，请稍候。**消息后，用户将看到一条确认消息，告知他/她应用程序已经建立了成功的套接字连接。通过将`socketConnected`设置为`true`，我们显示输入控件，并为用户提供发送聊天消息的选项。此处理程序中的最后一件事是强制浏览器聚焦在输入字段上，这是一个很好的细节，可以节省用户的鼠标点击。

`socket`对象可能会分派另一个事件 - `disconnect`。在这种情况下，我们可以采取两种行动 - 隐藏输入控件，并通过在浏览器中显示`Disconnected!`字符串来通知用户。

我们监听的最后一个事件是`server-talking`。这是我们自己的事件 - 后端代码将分派的消息。一开始，`data`对象将只包含一个`text`属性，这将是聊天消息。我们将简单地将其附加到`messages`数组的其余元素中。

我们之前谈到的行监听来自后端的事件。让我们编写一些代码，将信息从客户端发送到服务器：

```js
var send = function() {
  socket.emit('client-talking', { text: self.get('text')});
  self.set('text', '');
}
this.on('send', send);
```

当用户单击按钮时，将调用`send`函数。我们使用相同的`socket`对象及其`emit`方法将文本传输到服务器。我们还清除输入字段的内容，以便用户可以开始撰写新消息。每次按按钮可能很烦人。以下代码在用户按下*Enter*键时触发`send`函数：

```js
this.find('form').addEventListener('keypress', function(e) {
  if(e.keyCode === 13 && e.target.nodeName === 'INPUT') {
    e.preventDefault();
    send();
  }
});
```

`this.find`方法返回一个有效的 DOM 元素。我们将`keypress`监听器附加到`form`元素，因为`input`变量并不总是可见。由于事件冒泡，我们能够在上层元素中捕获事件。还值得一提的是，在某些浏览器中，需要不同的代码来监听 DOM 事件。

我们必须处理的最后一件事是在屏幕上显示`messages`数组的内容。如果您检查到目前为止我们编写的代码，您会发现我们没有更新`output`变量。以下是一个新的组件方法，将处理这个问题：

```js
updateOutput: function() {
  this.set('output', this.get('messages').join('<br />'));
  var outputEl = this.find('[data-component="output"]');
  outputEl.scrollTop = outputEl.scrollHeight;
}
```

我们使用`join`方法而不是循环遍历数组的所有元素。它将数组的所有元素连接成一个由给定参数分隔的字符串。在我们的情况下，我们需要在每条消息后面换行。一旦我们开始接收更多数据，我们将需要将`<div>`元素滚动到底部，以便用户看到最新的消息。函数的另外两行将容器的滚动条定位在底部。

`updateOutput`函数应该在新消息到达时被调用。Ractive.js 的观察对于这种情况非常完美：

```js
this.observe('messages', this.updateOutput);
```

只需要一行代码将`messages`数组的更新连接到`updateOutput`方法。添加了这个之后，每次对消息数组进行`push`操作都会强制渲染`chat-output`元素。

组件的代码如下：

```js
module.exports = Ractive.extend({
  template: require('../../tpl/chat'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  data: {
    messages: ['Loading. Please wait.'],
    output: '',
    socketConnected: false
  },
  onrender: function() {

    var self = this;
    var socket = io('http://localhost:9000');
    socket.on('connect', function() {
      self.push('messages', 'Connected!');
      self.set('socketConnected', true);
      self.find('input[type="text"]').focus();
    });
    socket.on('disconnect', function() {
      self.set('socketConnected', false);
      self.push('messages', 'Disconnected!');
    });
    socket.on('server-talking', function(data) {
      self.push('messages', data.text);
    });

    var send = function() {
      socket.emit('client-talking', { text: self.get('text')});
      self.set('text', '');
    }

    this.on('send', send);
    this.observe('messages', this.updateOutput);

    this.find('form').addEventListener('keypress', function(e) {
      if(e.keyCode === 13 && e.target.nodeName === 'INPUT') {
        e.preventDefault();
        send();
      }
    });

  },
  updateOutput: function() {
    this.set('output', this.get('messages').join('<br />'));
    var outputEl = this.find('[data-component="output"]');
    outputEl.scrollTop = outputEl.scrollHeight;
  }
});
```

前端已准备好通过套接字发送和接收消息。但是，后端仍然包含我们开始时的初始示例代码。对`Chat`模块进行小小的更新将使其能够向用户发送消息：

```js
// backend/Code.js
module.exports = function(app) {
  var io = require('socket.io')(app);
  io.on('connection', function (socket) {
    socket.on('client-talking', function (data) {
      io.sockets.emit('server-talking', { text: data.text });
    });
  });
}
```

我们仍在监听`connection`事件。在处理程序中收到的`socket`对象代表与用户的连接。之后，我们将开始监听`client-talking`事件，该事件由前端在用户在字段中输入内容或按下按钮或*Enter*键时触发。一旦接收到数据，我们就会将其广播给系统中的所有用户。`io.sockets.emit`变量向当前使用服务器的所有客户端发送消息。

# 仅向用户的朋友发送消息

我们后端的最后一个更改是将接收到的聊天消息分发给我们社交网络中的所有用户。当然，这实际上并不太实用，因为我们可能会与彼此不认识的人交换文本。我们必须相应地更改我们的代码，以便只向我们朋友列表中的用户发送消息。

使用 Socket.IO 时，我们无法像在后端 API 中那样默认访问`request`和`response`对象。这将使得解决问题变得更有趣，因为我们无法识别发送消息的用户。幸运的是，Socket.IO 让我们可以访问活动会话。它是以原始格式存在的。因此，我们需要解析它并提取用户的个人资料数据。为此，我们将使用`cookie` Node.js 模块。让我们以以下方式将其添加到`package.json`文件中：

```js
"dependencies": {
  "cookie": "0.1.2",
  "socket.io": "1.3.3",
  ...
  ...
}
```

在终端中进行另一个`npm install`后，我们将能够`require`该模块。在第八章中，*创建页面和事件*，我们重构了我们的 API 并创建了`backend/api/helpers.js`文件，其中包含实用函数。我们将使用仅使用`session`对象的方式添加另一个类似于`getCurrentUser`的文件，如下所示：

```js
var getCurrentUserBySessionObj = function(callback, obj) {
  getDatabaseConnection(function(db) {
    var collection = db.collection('users');
    collection.find({ 
      email: obj.user.email
    }).toArray(function(err, result) {
      if(result.length === 0) {
        callback({ error: 'No user found.' });
      } else {
        callback(null, result[0]);
      }
    });
  });
};
```

如果我们比较这两种方法，我们会发现有两个不同之处。第一个不同之处是我们没有收到通常的请求和响应对象；我们只收到一个回调和一个`session`对象。第二个变化是即使出现错误，结果也总是发送到回调中。

有了`getCurrentUserBySessionObj`函数，我们可以修改`backend/Chat.js`，使其只向当前用户的朋友发送消息。让我们首先初始化所需的辅助程序。我们将在文件顶部添加以下行：

```js
var helpers = require('./api/helpers');
var getCurrentUserBySessionObj =  helpers.getCurrentUserBySessionObj;
var cookie = require('cookie');
```

我们已经讨论过`cookie`模块。在 Socket.IO 引擎中可用的会话数据可以通过`socket.request.headers.cookie`访问。如果我们在控制台中打印该值，将会得到以下截图中的内容：

![仅向用户的朋友发送消息](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00189.jpeg)

前面的输出是一个 Base64 编码的字符串，我们肯定不能直接使用它。幸运的是，Node.js 有接口可以轻松解码这样的值。以下是一个提取所需 JSON 对象的简短函数：

```js
var decode = function(string) {
  var body = new Buffer(string, 'base64').toString('utf8');
  return JSON.parse(body);
};
```

我们从 cookie 中传递了字符串，并接收了稍后将在`getCurrentUserBySessionObj`中使用的普通`user`对象。

因此，我们有机制来找出当前用户是谁以及他/她的朋友是谁。我们所要做的就是缓存可用的套接字连接和相关用户。我们将引入一个新的全局（对于模块来说）`users`变量。它将作为一个哈希映射，其中键将是用户的 ID，值将包含套接字和朋友。为了向正确的用户广播消息，我们可以总结以下方法的逻辑：

```js
var broadcastMessage = function(userId, message) {
  var user = users[userId];
  if(user && user.friends && user.friends.length > 0) {
    user.socket.emit('server-talking', { text: message });
    for(var i=0; i<user.friends.length; i++) {
      var friend = users[user.friends[i]];
      if(friend && friend.socket) {
        friend.socket.emit('server-talking', { text: message });
      }
    }
  }
};
```

这段代码提供了一个接受用户 ID 和文本消息的函数。我们首先检查是否缓存了套接字引用。如果是，我们将确保用户有朋友。如果这也是有效的，我们将开始分发消息。第一个`emit`项是给用户自己，以便他/她接收自己的消息。其余的代码循环遍历朋友并将文本发送给所有人。

当然，我们必须更新接受套接字连接的代码。以下是相同代码的新版本：

```js
module.exports = function(app) {
  var io = require('socket.io')(app);
  io.on('connection', function (socket) {
    var sessionData = cookie.parse(socket.request.headers.cookie);
    sessionData = decode(sessionData['express:sess']);
    if(sessionData && sessionData.user) {
      getCurrentUserBySessionObj(function(err, user) {
        var userId = user._id.toString();
        users[userId] = {
          socket: socket,
          friends: user.friends
        };
        socket.on('client-talking', function (data) {
          broadcastMessage(userId, data.text);
        });
        socket.on('disconnect', function() {
          users[userId] = null;
        });
      }, sessionData);
    }

  });
}
```

现在我们将获取 cookie 值并确定当前用户。`socket`对象和用户的朋友已被缓存。然后，我们将继续监听`client-talking`事件，但现在，我们将通过`broadcastMessage`函数发送消息。在最后做了一个小但非常重要的添加；我们监听`disconnect`事件并移除缓存的数据。这是为了防止向断开连接的用户发送数据。

# 自定义聊天输出

能够向正确的人发送消息是很好的，但聊天仍然有点混乱，因为屏幕上出现的每条文本消息都是相同的颜色，我们不知道哪个朋友发送的。在本节中，我们将进行两项改进——我们将在消息前附加用户的名称并给文本着色。

让我们从颜色开始，并在`backend/api/helpers.js`文件中添加一个新的辅助方法：

```js
var getRandomColor = function() {
  var letters = '0123456789ABCDEF'.split('');
  var color = '#';
  for(var i = 0; i < 6; i++ ) {
    color += letters[Math.floor(Math.random() * 16)];
  }
  return color;
}
```

以下函数生成一个有效的 RGB 颜色，可以在 CSS 中使用。你选择用户颜色的时机是在缓存`socket`对象时：

```js
...
var getRandomColor = helpers.getRandomColor;

module.exports = function(app) {
  var io = require('socket.io')(app);
  io.on('connection', function (socket) {
    var sessionData = cookie.parse(socket.request.headers.cookie);
    sessionData = decode(sessionData['express:sess']);
    if(sessionData && sessionData.user) {
      getCurrentUserBySessionObj(function(err, user) {
        var userId = user._id.toString();
        users[userId] = {
          socket: socket,
          friends: user.friends,
          color: getRandomColor()
        };
        socket.on('client-talking', function (data) {
          broadcastMessage(user, data.text);
        });
        socket.on('disconnect', function() {
          users[userId] = null;
        });
      }, sessionData);
    }

  });
}
```

因此，除了`socket`对象和`friends`，我们还存储了一个随机选择的颜色。还有一个小的更新。我们不再将用户的 ID 传递给`broadcastMessage`函数。我们发送整个对象，因为我们需要获取用户的名字和姓氏。

以下是更新后的`broadcastMessage`辅助方法：

```js
var broadcastMessage = function(userProfile, message) {
  var user = users[userProfile._id.toString()];
  var userName = userProfile.firstName + ' ' +  userProfile.lastName;
  if(user && user.friends && user.friends.length > 0) {
    user.socket.emit('server-talking', {
      text: message,
      user: userName,
      color: user.color
    });
    for(var i=0; i<user.friends.length; i++) {
      var friend = users[user.friends[i]];
      if(friend && friend.socket) {
        friend.socket.emit('server-talking', { 
          text: message,
          user: userName,
          color: user.color
        });
      }
    }
  }
};
```

现在，发送到客户端的`data`对象包含两个额外的属性——当前用户的名称和他/她随机选择的颜色。

后端已经完成了它的工作。现在我们要做的就是调整前端控制器，以便它使用名称和颜色，如下所示：

```js
// frontend/js/controllers/Chat.js
socket.on('server-talking', function(data) {
  var message = '<span style="color:' + data.color + '">';
  message += data.user + ': ' + data.text;
  message += '</span>';
  self.push('messages', message);
});
```

我们不再只发送文本，而是将消息包装在`<span>`标签中。它应用了文本颜色。此外，消息以用户的名称开头。

我们工作的最终结果如下截图所示：

![自定义聊天输出](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00190.jpeg)

# 总结

Socket.IO 是最流行的用于开发实时应用程序的 Node.js 工具之一。在本章中，我们成功地使用它构建了一个交互式聊天。我们网络中的用户不仅能够发布出现在其动态中的内容，还能够与其他用户实时交换消息。WebSockets 技术使这一切成为可能。

下一章专门讲解测试。我们将了解一些流行的模块，这些模块将帮助我们编写测试。


# 第十一章：测试用户界面

在第十章 *添加实时聊天*中，我们通过添加实时聊天功能扩展了我们的社交网络。我们使用了 WebSockets 和 Socket.IO 来实现系统中用户之间的通信。本书的最后一章专门讨论用户界面测试。我们将探讨两种流行的工具来运行无头浏览器测试。本章涵盖以下主题：

+   介绍基本的测试工具集

+   准备我们的项目来运行测试

+   使用 PhantomJS 运行我们的测试

+   测试用户的注册

+   使用 DalekJS 进行测试

# 介绍基本的测试工具集

在编写测试之前，我们将花一些时间讨论测试工具集。我们需要一些工具来定义和运行我们的测试。

## 测试框架

在 JavaScript 的上下文中，测试框架是一组函数，帮助你将测试组织成逻辑组。有一些框架函数，比如`suite`、`describe`、`test`或`it`，定义了我们的测试套件的结构。以下是一个简短的例子：

```js
describe('Testing database communication', function () {
  it('should connect to the database', function(done) {
    // the actual testing goes here
  });
  it('should execute a query', function(done) {
    // the actual testing goes here
  });
});
```

我们使用`describe`函数将更详细的测试（`it`）包装成一个组。以这种方式组织组有助于我们保持专注，同时也非常信息丰富。

JavaScript 社区中一些流行的测试框架包括**QUnit**、**Jasmine**和**Mocha**。

## 断言库

我们通常在测试时运行一个断言。我们经常比较变量的值，以检查它们是否与我们最初编写程序逻辑时的预期值匹配。一些测试框架带有自己的断言库，一些则没有。

以下一行展示了这样一个库的简单用法：

```js
expect(10).to.be.a('number')
```

重要的是要提到 API 是这样设计的，以便我们通过阅读测试来理解上下文。

Node.js 甚至有自己内置的名为`assert`的库。其他选项包括**Chai**、**Expect**和**Should.js**。

## 运行器

运行器是一个工具，我们用它在特定的上下文中执行测试，这个上下文很常见是特定的浏览器，但也可能是不同的操作系统或定制的环境。我们可能需要也可能不需要运行器。在这一特定章节中，我们将使用 DalekJS 作为测试运行器。

# 准备我们的项目来运行测试

现在我们知道了运行测试所需的工具。下一步是准备我们的项目来放置这样的测试。通常在开发过程中，我们通过访问页面并与其交互来测试我们的应用程序。我们知道这些操作的结果，并验证一切是否正常。我们希望用自动化测试做同样的事情。但是，不是我们一遍又一遍地重复相同的步骤，而是会有一个脚本。

为了使这些脚本起作用，我们必须将它们放在正确的上下文中。换句话说，它们应该在我们的应用程序的上下文中执行。

在前一节中，我们提到了 Chai（一个断言库）和 Mocha（一个测试框架）。它们很好地配合在一起。因此，我们将把它们添加到我们的依赖列表中，如下所示：

```js
// package.json
…
"dependencies": {
    "chai": "2.0.0",
    "mocha": "2.1.0",
    ...
}
…
```

快速运行`npm install`将在`node_modules`目录中设置模块。Chai 和 Mocha 被分发为 Node.js 模块，但我们也可以在浏览器环境中使用它们。`node_modules`中新创建的文件夹包含编译版本。例如，要在浏览器中运行 Mocha，我们必须在我们的页面中包含`node_modules/mocha/mocha.js`。

我们的社交网络是一个单页面应用程序。我们有一个主 HTML 模板，由后端提供，位于`backend/tpl/page.html`中。Node.js 服务器读取此文件并将其发送到浏览器。其余部分由 JavaScript 代码处理。以下是`page.html`的样子：

```js
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Node.js by example</title>
  <meta http-equiv="Content-Type" content="text/html;  charset=utf-8" />
  <meta name="description" content="Node.js by example">
  <meta name="author" content="Packt">
  <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
  <div class="container"></div>
  <script src="img/socket.io.js"></script>
  <script src="img/ractive.js"></script>
  <script src="img/app.js"></script>
</body>
</html>
```

该文件包含运行应用程序所需的所有外部资源。但是，现在我们需要添加一些标签；其中一些如下：

+   `/node_modules/mocha/mocha.css`文件包含了测试结果正确显示的样式。这是 Mocha 报告者的一部分。

+   `/node_modules/mocha/mocha.js`文件是测试框架。

+   `/node_modules/chai/chai.js`文件是断言库。

+   `/tests/spec.js`是一个包含实际测试的文件。它目前还不存在。我们将创建一个`tests`目录，并在其中创建一个`spec.js`文件。

+   一个空的`div`标签充当测试结果的占位符，几行 JavaScript 代码引导 Mocha 框架。

我们不能把所有这些新元素都添加到当前的`page.html`文件中，因为系统的用户会看到它们。我们将把它们放在另一个文件中，并调整后端，以便在特定条件下提供它。让我们创建`backend/tpl/pageTest.html`：

```js
<!doctype html>
<html lang="en">
<head>
  ...
  <link rel="stylesheet" href="/static/css/styles.css">
  <link rel="stylesheet" href="/node_modules/mocha/mocha.css" />
</head>
<body>
  <div class="container"></div>
  <script src="img/socket.io.js"></script>
  <script src="img/ractive.js"></script>
  <script src="img/app.js"></script>

  <div id="mocha"></div>
  <script src="img/mocha.js"></script>
  <script src="img/chai.js"></script>
  <script>
    mocha.ui('bdd');
    mocha.reporter('html');
    expect = chai.expect;
  </script>
  <script src="img/spec.js"></script>
  <script>
    if (window.mochaPhantomJS) { 
      mochaPhantomJS.run();
   }
    else {
     mocha.run();
   }
  </script>

</body>
</html>
```

一旦`mocha.js`和`chai.js`被注入到页面中，我们将配置框架。我们的用户界面将遵循行为驱动开发，报告者将是`html`。Mocha 有几种类型的报告者，由于我们想在浏览器中显示结果，所以我们使用了这个。我们定义了一个`expect`全局对象，起到了断言工具的作用。

在接下来的部分中，这些行将会派上用场，我们将使用 PhantomJS 运行我们的测试。这些行基本上会检查是否有`window.mochaPhantomJS`对象，如果有的话，它将被用来代替默认的`mocha`。

到目前为止，一切都很顺利。我们有工具可以帮助我们运行和编写测试，还有一个包含必要代码的页面。下一步是调整后端，以便使用新的`pageTest.html`文件：

```js
// backend/Default.js
var fs = require('fs');
var url = require('url');

var html = fs.readFileSync(__dirname +  '/tpl/page.html').toString('utf8');
var htmlWithTests = fs.readFileSync(__dirname +  '/tpl/pageTest.html').toString('utf8');

module.exports = function(req, res) {
  res.writeHead(200, {'Content-Type': 'text/html'});
  var urlParts = url.parse(req.url, true);
  var parameters = urlParts.query;
  if(typeof parameters.test !== 'undefined') {
    res.end(htmlWithTests + '\n');
  } else {
    res.end(html + '\n');
  }
}
```

我们需要更改的文件是`Default.js`。这是我们应用程序中`Default.js`文件路由的处理程序。新添加的`htmlWithTests`变量包含了新的 HTML 标记。我们使用`url`模块来查找来自客户端的`GET`变量。如果有`test`参数，那么我们将加载包含布局和测试的页面。否则，就是原始的 HTML。

在最后一次更改之后，我们可以运行服务器并打开`http://localhost:9000/register?test=1`。然而，我们会收到一堆错误消息，抱怨有一些文件丢失。这是因为`server.js`文件不识别以`node_modules`或`tests`开头的 URL。这些目录中存在的文件是静态资源。因此，我们可以使用已经定义的`Assets`模块，如下所示：

```js
// server.js
…
Router
.add('static', Assets)
.add('node_modules', Assets)
.add('tests', Assets)
.add('api', API)
.add(Default);
```

最后，还有一个文件需要创建——`tests/spec.js`：

```js
describe("Testing", function () {
  it("Test case", function (done) {
    expect(1).to.be.equal(1);
    done();
  });
});
```

这段代码是一个测试的最简单结构。我们有一个组和一个测试。关键时刻是在测试结束时运行`done()`。

我们知道这个测试通过了。浏览器中的结果如下截图所示：

![准备项目运行测试](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00191.jpeg)

值得一提的是，加载的页面仍然是相同的，除了右上角和页脚下方的元素。这些新标签是由 Mocha 框架生成的。这就是`html`报告者显示我们测试结果的方式。

# 使用 PhantomJS 运行我们的测试

前面几节的结果是在浏览器中运行的自动化测试。然而，这通常是不够的。我们可能需要将测试集成到部署流程中，而在浏览器中进行测试并不总是一个选择。幸运的是，有一种称为**无头浏览器**的浏览器类型。它是一个没有用户界面的功能性浏览器。我们仍然可以访问页面，点击链接或填写表单，但所有这些操作都是由代码控制的。这对于我们和自动化测试来说是完美的。

有几种流行的无头浏览器。Selenium ([`github.com/seleniumhq/selenium`](https://github.com/seleniumhq/selenium))就是其中之一。它有很好的文档和庞大的社区。另一个是 PhantomJS。它与 Node.js 兼容良好。所以我们将使用它。

我们已经在测试环境中添加了几个组件。要直接使用 PhantomJS，需要一些补充配置。为了避免额外的复杂性，我们将安装`mocha-phantomjs`模块。它的目的是简化无头浏览器的使用，特别是与 Mocha 框架的结合。以下命令将在我们的终端中将`mocha-phantomjs`设置为全局命令：

```js
npm install mocha-phantomjs -g

```

自 3.4 版本以来，`mocha-phantomjs`模块使用 PhantomJS 作为对等依赖，这意味着我们不必手动安装浏览器。

安装成功后，我们准备运行测试。我们在控制台中要输入的命令是`mocha-phantomjs http://localhost:9000\?test=1`。有反斜杠是因为如果不是这样的话，终端可能无法正确解释这行。

结果显示在以下截图中：

![使用 PhantomJS 运行我们的测试](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00192.jpeg)

这基本上与我们在浏览器中得到的结果相同。好处是现在这个过程发生在终端中。

# 测试用户注册

让我们使用前几节中构建的设置并编写一个实际的测试。假设我们要确保我们的注册页面可以正常工作。以下是我们想要用我们的测试捕获的两个过程：

+   填写表单并确保应用程序显示错误消息

+   填写表单并看到成功消息

我们将使用 PhantomJS 作为我们的无头（虚拟）浏览器。因此，我们所要做的就是加载我们的注册页面并模拟用户交互，比如在字段中输入并按下按钮。

## 模拟用户交互

我们将解决几个问题。第一个问题是实际模拟用户操作。从 JavaScript 的角度来看，这些操作被转换为由特定 DOM 元素分派的事件。以下辅助方法将成为`tests/spec.js`文件的一部分：

```js
describe("Testing", function () {

  var trigger = function(element, event, eventGroup, keyCode) {
    var e = window.document.createEvent(eventGroup || 'MouseEvents');
    if(keyCode) {
      e.keyCode = e.which = keyCode;
    }
    e.initEvent(event, true, true);
    return element.dispatchEvent(e);
  }

  it("Registration", function (done) {
    // ... our test here
  });

});
```

`trigger`函数接受一个元素、事件的名称、事件组和一个键码。前两个参数是必需的。第三个参数的默认值为`MouseEvents`，最后一个参数是可选的。我们将使用该方法来触发`change`和`click`事件。

## 填写并提交注册表单

让我们从填写注册表单的输入字段开始。值得一提的是，我们将要编写的代码在浏览器中运行，因此我们可以访问`document.querySelector`，例如。以下行在名字字段中输入一个字符串：

```js
var firstName = document.querySelector('#first-name');
firstName.value = 'First name';
trigger(firstName, 'change');
```

向`firstName`元素发送一个字符串会更新用户界面。然而，我们的客户端框架 Ractive.js 并不知道这个变化。分派`change`事件可以解决这个问题。

我们将使用相同的模式向姓氏、电子邮件和密码字段添加值：

```js
var lastName = document.querySelector('#last-name');
lastName.value = 'Last name';
trigger(lastName, 'change');

var email = document.querySelector('#email');
email.value = 'wrong email';
trigger(email, 'change');

var password = document.querySelector('#password');
password.value = 'password';
trigger(password, 'change');
```

电子邮件输入字段的值是无效的。这是故意的。我们希望捕获后端返回错误的情况。要完成操作，我们必须点击**注册**按钮：

```js
trigger(document.querySelector('input[value="register"]'),  'click');
```

如果我们现在运行测试，将会看到以下截图：

![填写并提交注册表单](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00193.jpeg)

测试基本上因超时而失败。这是因为我们没有调用`done`函数。然而，即使这样，我们也没有任何断言。

现在，事情变得有趣起来。在浏览器中发生的过程是异步的。这意味着我们不能简单地在点击按钮后运行我们的断言。我们应该等一会儿。在这种情况下，使用`setTimeout`是不可接受的。正确的方法是调整应用程序的代码，以便它通知外部世界特定的工作已经完成。在我们的情况下，这是提交注册表单。更准确地说，我们必须更新`s/controllers/Register.js`：

```js
module.exports = Ractive.extend({
  template: require('../../tpl/register'),
  components: {
    navigation: require('../views/Navigation'),
    appfooter: require('../views/Footer')
  },
  onrender: function() {
    ...
    this.on('register', function() {
      userModel.create(function(error, result) {
        ...
        self.fire('form-submitted');
      });
    });
  }
});
```

添加的是`self.fire('form-submitted')`。一旦模型返回响应并且我们处理它，我们就会分派一个事件。对于访问网站的用户，这一行无效。但是对于我们的测试套件来说，这是一种找出后端响应并且用户界面已更新的方法。这时我们需要进行断言。

## 调整代码的执行顺序

事件的分派很好，但并不能完全解决问题。我们需要到达`Register`控制器并订阅`form-submitted`消息。在我们的测试中，我们可以访问全局范围（`window`对象）。让我们将其用作桥梁，并为当前使用的控制器提供一个快捷方式，如下所示：

```js
// frontend/js/app.js
var showPage = function(newPage) {
  if(currentPage) currentPage.teardown();
  currentPage = newPage;
  body.innerHTML = '';
  currentPage.render(body);
  currentPage.on('navigation.goto', function(e, route) {
    Router.navigate(route);
  });
  window.currentPage = currentPage;
  if(typeof window.onAppReady !== 'undefined') {
    window.onAppReady();
  }
}
```

在`app.js`文件中，我们切换了应用程序的页面。这是我们调整的完美位置，因为在这一点上，我们知道哪个控制器被呈现。

在继续实际测试之前，您应该做的最后一件事是确保您的社交网络已完全初始化，并且有一个正在呈现的视图。这再次需要访问全局`window`对象。我们的测试将在`window.onAppReady`属性中存储一个函数，并且当 PhantomJS 打开页面时，应用程序将运行它。请注意，将对象或变量附加到全局范围并不被认为是一种良好的做法。但是，为了使我们的测试工作，我们需要这样的小技巧。在编译文件进行生产发布时，我们可以随时跳过这一点。

在`backend/tpl/pageTest.html`中，我们有以下代码：

```js
<script src="img/socket.io.js"></script>
<script src="img/ractive.js"></script>
<script src="img/app.js"></script>
<div id="mocha"></div>
<script src="img/mocha.js"></script>
<script src="img/chai.js"></script>
<script>
  mocha.ui('bdd');
  mocha.reporter('html');
  expect = chai.expect;
</script>
<script src="img/spec.js"></script>
<script>
  if (window.mochaPhantomJS) { mochaPhantomJS.run(); }
  else { mocha.run(); }
</script>
```

如果我们继续使用这些行，我们的测试将失败，因为在执行断言时没有呈现任何 UI。相反，我们应该使用新的`onAppReady`属性以以下方式延迟调用`run`方法：

```js
<div id="mocha"></div>
<script src="img/mocha.js"></script>
<script src="img/chai.js"></script>
<script>
  mocha.ui('bdd');
  mocha.reporter('html');
  expect = chai.expect;
</script>
<script src="img/spec.js"></script>
<script>
  window.onAppReady = function() {
    if (window.mochaPhantomJS) { mochaPhantomJS.run(); }
    else { mocha.run(); }
  }
</script>
<script src="img/socket.io.js"></script>
<script src="img/ractive.js"></script>
<script src="img/app.js"></script>
```

因此，我们包括了 Mocha 和 Chai。我们配置了测试框架，添加了一个在调用`onAppReady`时执行的函数，然后运行了实际应用程序。

## 监听`form-submitted`事件

我们需要编写的最后一行代码是订阅`form-submitted`事件，当表单提交并且后端处理结果时，控制器会分发此事件。我们的 API 应该首先响应错误，因为我们设置了错误的电子邮件值（`email.value = 'wrong email'`）。以下是我们如何捕获错误消息：

```js
var password = document.querySelector('#password');
password.value = 'password';
trigger(password, 'change');

window.currentPage.on('form-submitted', function() {
  var error = document.querySelector('.error');
  expect(!!error).to.be.equal(true);
  done();
});

trigger(document.querySelector('input[value="register"]'),  'click');
```

`!!error`项目将错误变量转换为布尔值。我们将检查错误元素的存在。如果存在，那么测试通过。控制台中的结果如下：

![监听 form-submitted 事件](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00194.jpeg)

我们验证了错误报告。让我们通过确保当所有字段都正确填写时成功消息出现来结束这个循环：

```js
var submitted = 0;
window.currentPage.on('form-submitted', function() {
  if(submitted === 0) {
    submitted++;
    var error = document.querySelector('.error');
    expect(!!error).to.be.equal(true);
    var email = document.querySelector('#email');
    var validEmail = 'test' + (new Date()).getTime() +  '@test.com';
    email.value = validEmail;
    trigger(email, 'change');
    trigger(document.querySelector('input[value="register"]'),  'click');
  } else {    
    var success = document.querySelector('.success');
    expect(!!success).to.be.equal(true);
    done();
  }
});
```

`form-submitted`事件将被分派两次。因此，我们将使用额外的`submitted`变量来区分这两个调用。在第一种情况下，我们将检查`.error`，而在第二种情况下，我们将检查`.success`。运行`mocha-phantomjs`命令后，我们将得到与之前相同的结果，但这次我们确信整个注册过程都是有效的。请注意，我们附加了一个动态生成的时间戳，以便每次都获得不同的电子邮件。

# 使用 DalekJS 进行测试

DalekJS 是一个完全用 JavaScript 编写的开源 UI 测试工具。它充当测试运行器。它有自己的 API 来执行用户界面交互。DalekJS 的一个非常有趣的特性是它可以与不同的浏览器一起工作。它能够在 PhantomJS 和流行的浏览器（如 Chrome、Safari、Firefox 和 Internet Explorer）中运行测试。它使用**WebDriver JSON-Wire**协议与这些浏览器进行通信，并基本上控制它们的操作。

## 安装 DalekJS

首先，我们需要安装 DalekJS 的命令行工具。它作为一个 Node.js 包进行分发。因此，以下命令将下载必要的文件：

```js
npm install dalek-cli -g

```

当进程完成时，我们可以在终端中运行`dalek`命令。下一步是在我们的依赖项中添加`dalekjs`模块。这是召唤该工具 API 的包。因此，在`package.json`文件中需要两行：

```js
{
  ...
  "dependencies": {
    "dalekjs": "0.0.9",
    "dalek-browser-chrome": "0.0.11"
    ...
  }
}
```

我们提到 DalekJS 可以与 Chrome、Safari 和 Firefox 等真实浏览器一起工作。有专门的包来处理所有这些浏览器。例如，如果我们想在 Chrome 浏览器中进行测试，我们必须安装`dalek-browser-chrome`作为依赖项。

## 使用 DalekJS API

DalekJS 的工作方式类似于`mocha-phantomjs`模块。我们在文件中编写我们的测试，然后简单地将该文件传递给我们的终端中的命令。让我们创建一个名为`tests/dalekjs.spec.js`的新文件，并将以下代码放入其中：

```js
module.exports = {
  'Testing registration': function (test) {
    test
    .open('http://localhost:9000/register')
    .setValue('#first-name', 'First name')
    .setValue('#last-name', 'Last name')
    .setValue('#email', 'wrong email')
    .setValue('#password', 'password')
    .click('input[value="register"]')
    .waitForElement('.error')
    .assert.text('.error').to.contain('Invalid or missing email')
    .setValue('#email', 'test' + (new Date()).getTime() +  '@test.com')
    .click('input[value="register"]')
    .waitForElement('.success')
    .assert.text('.success').to.contain('Registration successful')
    .done();
  }
};
```

该工具要求我们导出一个对象，其键是我们的测试用例。我们只有一个名为`Testing registration`的案例。我们传递一个接收`test`参数的函数，这使我们可以访问 DalekJS API。

该模块的 API 设计得非常易于理解。我们打开一个特定的 URL 并为输入字段设置值。就像在之前的测试中，我们将输入一个错误的电子邮件值，然后点击**提交**按钮。在这里，`.waitForElement`方法非常方便，因为操作是异步的。一旦我们检测到`.error`元素的存在，我们将继续写入正确的电子邮件值并再次提交表单。

要运行测试，我们必须在控制台中键入`dalek ./tests/dalekjs.spec.js -b chrome`。DalekJS 将打开一个真正的 Chrome 窗口，执行测试并在终端中报告以下内容：

![使用 DalekJS API](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-ex/img/image00195.jpeg)

使用 DalekJS，我们不需要调整我们应用的代码。没有额外的断言库或测试框架。所有这些都包含在一个易于使用和安装的单个模块中。

从另一个角度来看，DalekJS 可能对每个项目都不是有用的。例如，当我们需要与应用程序的代码交互或需要一些未在提供的 API 中列出的东西时，它可能就不那么有用了。

# 摘要

在本章中，我们看到了如何测试我们的用户界面。我们成功解决了一些问题，并使用了诸如 Mocha、Chai 和 DalekJS 之类的工具。测试我们的代码很重要，但通常还不够。应该存在模拟用户交互并证明我们的软件正常工作的测试。
