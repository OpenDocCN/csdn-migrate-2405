# React 全栈项目（四）

> 原文：[`zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB`](https://zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：构建媒体流应用程序

上传和流媒体内容，特别是视频内容，已经成为互联网文化的一个日益增长的部分。从个人分享个人视频内容到娱乐行业在在线流媒体服务上发布商业内容，我们都依赖于能够实现平稳上传和流媒体的网络应用程序。MERN 堆栈技术中的功能可以用于构建和集成这些核心流媒体功能到任何基于 MERN 的 Web 应用程序中。

在这一章中，我们将通过扩展 MERN 骨架应用程序来覆盖以下主题，实现基本的媒体上传和流媒体：

+   将视频上传到 MongoDB GridFS

+   存储和检索媒体详情

+   从 GridFS 流式传输到基本媒体播放器

# MERN Mediastream

我们将通过扩展基本应用程序来构建 MERN Mediastream 应用程序。这将是一个简单的视频流应用程序，允许注册用户上传视频，任何浏览应用程序的人都可以观看：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/71c4f48b-a483-4c54-aa63-b515ec8ff080.png)完整的 MERN Mediastream 应用程序的代码可在 GitHub 上找到[github.com/shamahoque/mern-mediastream](https://github.com/shamahoque/mern-mediastream)。本章讨论的实现可以在同一存储库的`simple-mediastream-gridfs`分支中访问。您可以克隆此代码，并在本章的其余部分中阅读代码解释时运行应用程序。

为了实现与媒体上传、编辑和流媒体相关的功能所需的视图，我们将通过扩展和修改 MERN 骨架应用程序中的现有 React 组件来开发。下图显示了构成本章中开发的 MERN Mediastream 前端的所有自定义 React 组件的组件树：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/4ff4252c-f5de-4c9d-a967-550090c679eb.jpg)

# 上传和存储媒体

在 MERN Mediastream 上注册的用户将能够从其本地文件上传视频，直接在 MongoDB 上使用 GridFS 存储视频和相关详情。

# 媒体模型

为了存储媒体详情，我们将在`server/models/media.model.js`中为媒体模型添加一个 Mongoose 模式，其中包含用于记录媒体标题、描述、流派、观看次数、创建时间、更新时间以及发布媒体的用户的引用字段。

`mern-mediastream/server/models/media.model.js`：

```jsx
import mongoose from 'mongoose'
import crypto from 'crypto'
const MediaSchema = new mongoose.Schema({
  title: {
    type: String,
    required: 'title is required'
  },
  description: String,
  genre: String,
  views: {type: Number, default: 0},
  postedBy: {type: mongoose.Schema.ObjectId, ref: 'User'},
  created: {
    type: Date,
    default: Date.now
  },
  updated: {
    type: Date
  }
})

export default mongoose.model('Media', MediaSchema)
```

# MongoDB GridFS 用于存储大文件

在之前的章节中，我们讨论了用户上传的文件可以直接存储在 MongoDB 中作为二进制数据。但这仅适用于小于 16 MB 的文件。为了在 MongoDB 中存储更大的文件，我们需要使用 GridFS。

GridFS 通过将文件分成最大为 255 KB 的几个块，然后将每个块存储为单独的文档来在 MongoDB 中存储大文件。当需要响应 GridFS 查询检索文件时，根据需要重新组装块。这打开了根据需要获取和加载文件的部分而不是检索整个文件的选项。

在 MERN Mediastream 中存储和检索视频文件时，我们将利用 GridFS 存储视频文件，并根据用户跳转到和开始播放的部分来流式传输视频的部分。

我们将使用`gridfs-stream` npm 模块将 GridFS 功能添加到我们的服务器端代码中：

```jsx
npm install gridfs-stream --save
```

为了将`gridfs-stream`与我们的数据库连接配置，我们将使用 Mongoose 将其链接如下。

`mern-mediastream/server/controllers/media.controller.js`：

```jsx
import mongoose from 'mongoose'
import Grid from 'gridfs-stream'
Grid.mongo = mongoose.mongo
let gridfs = null
mongoose.connection.on('connected', () => {
  gridfs = Grid(mongoose.connection.db)
})
```

`gridfs`对象将提供访问 GridFS 所需的功能，以便在创建新媒体时存储文件，并在需要向用户流回媒体时获取文件。

# 创建媒体 API

我们将在 Express 服务器上设置一个创建媒体 API，该 API 将在`'/api/media/new/:userId'`接收包含媒体字段和上传的视频文件的多部分内容的 POST 请求。

# 创建媒体的路由

在`server/routes/media.routes.js`中，我们将添加创建路由，并利用用户控制器中的`userByID`方法。`userByID`方法处理 URL 中传递的`:userId`参数，并从数据库中检索关联的用户。

`mern-mediastream/server/routes/media.routes.js`：

```jsx
router.route('/api/media/new/:userId')
        .post(authCtrl.requireSignin, mediaCtrl.create)
router.param('userId', userCtrl.userByID)
```

对创建路由的 POST 请求将首先确保用户已登录，然后在媒体控制器中启动`create`方法。

类似于用户和认证路由，我们将不得不在`express.js`中将媒体路由挂载到 Express 应用程序上。

`mern-mediastream/server/express.js`：

```jsx
app.use('/', mediaRoutes)
```

# 处理创建请求的控制器方法

媒体控制器中的`create`方法将使用`formidable` npm 模块解析包含媒体详细信息和用户上传的视频文件的多部分请求体：

```jsx
npm install formidable --save
```

以`formidable`解析的表单数据接收的媒体字段将用于生成新的媒体对象并保存到数据库中。

`mern-mediastream/server/controllers/media.controller.js`：

```jsx
const create = (req, res, next) => {
  let form = new formidable.IncomingForm()
    form.keepExtensions = true
    form.parse(req, (err, fields, files) => {
      if (err) {
        return res.status(400).json({
          error: "Video could not be uploaded"
        })
      }
      let media = new Media(fields)
      media.postedBy= req.profile
      if(files.video){
        let writestream = gridfs.createWriteStream({_id: media._id})
        fs.createReadStream(files.video.path).pipe(writestream)
      }
      media.save((err, result) => {
        if (err) {
          return res.status(400).json({
            error: errorHandler.getErrorMessage(err)
          })
        }
        res.json(result)
      })
    })
}
```

如果请求中有文件，`formidable`将在文件系统中临时存储它，我们将使用媒体对象的 ID 创建一个`gridfs.writeStream`来读取临时文件并将其写入 MongoDB。这将在 MongoDB 中生成关联的块和文件信息文档。当需要检索此文件时，我们将使用媒体 ID 来识别它。

# 在视图中创建 API 获取

在`api-media.js`中，我们将添加一个相应的方法，通过传递视图中的多部分表单数据来向创建 API 发出`POST`请求。

`mern-mediastream/client/user/api-user.js`：

```jsx
const create = (params, credentials, media) => {
  return fetch('/api/media/new/'+ params.userId, {
    method: 'POST',
    headers: {
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: media
  }).then((response) => {
    return response.json() 
  }).catch((err) => {
    console.log(err) 
  }) 
}
```

当用户提交新的媒体表单以上传新视频时，将使用此`create`获取方法。

# 新媒体表单视图

注册用户将在菜单中看到一个链接，用于添加新媒体。这个链接将带他们到新的媒体表单视图，并允许他们上传视频文件以及视频的详细信息。

# 添加媒体菜单按钮

在`client/core/Menu.js`中，我们将更新现有的代码，以添加添加媒体按钮链接的 My Profile 和 Signout 链接：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/70473631-4b0c-4671-a6d6-5f5ea13228f7.png)

只有在用户当前已登录时才会在菜单上呈现。

`mern-mediastream/client/core/Menu.js/`：

```jsx
<Link to="/media/new">
     <Button style={isActive(history, "/media/new")}>
        <AddBoxIcon style={{marginRight: '8px'}}/> Add Media
     </Button>
</Link>
```

# NewMedia 视图的 React 路由

当用户点击添加媒体链接时，我们将更新`MainRouter`文件以添加`/media/new` React 路由，这将渲染`NewMedia`组件，将用户带到新的媒体表单视图。

`mern-mediastream/client/MainRouter.js`：

```jsx
<PrivateRoute path="/media/new" component={NewMedia}/>
```

由于这个新的媒体表单只能由已登录用户访问，我们将把它添加为`PrivateRoute`。

# NewMedia 组件

在`NewMedia`组件中，我们将渲染一个表单，允许用户输入标题、描述和流派，并从本地文件系统上传视频文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/88d4481d-4f65-41db-9f97-d32ab8547e5e.png)

我们将使用 Material-UI 的`Button`和 HTML5 的`file input`元素添加文件上传元素。

`mern-mediastream/client/media/NewMedia.js`：

```jsx
<input accept="video/*" 
       onChange={this.handleChange('video')} 
       id="icon-button-file" 
       type="file"
       style={{display: none}}/>
<label htmlFor="icon-button-file">
    <Button color="secondary" variant="raised" component="span">
       Upload <FileUpload/>
    </Button>
</label> 
<span>{this.state.video ? this.state.video.name : ''}</span>

```

`Title`，`Description`和`Genre`表单字段将添加`TextField`组件。

`mern-mediastream/client/media/NewMedia.js`：

```jsx
<TextField id="title" label="Title" value={this.state.title} 
           onChange={this.handleChange('title')} margin="normal"/><br/>
<TextField id="multiline-flexible" label="Description"
           multiline rows="2"
           value={this.state.description}
           onChange={this.handleChange('description')}/><br/>
<TextField id="genre" label="Genre" value={this.state.genre} 
           onChange={this.handleChange('genre')}/><br/>
```

这些表单字段的更改将通过`handleChange`方法进行跟踪。

`mern-mediastream/client/media/NewMedia.js`：

```jsx
handleChange = name => event => {
    const value = name === 'video'
      ? event.target.files[0]
      : event.target.value
    this.mediaData.set(name, value)
    this.setState({ [name]: value })
}
```

`handleChange`方法使用新值更新状态并填充`mediaData`，这是一个`FormData`对象。`FormData` API 确保要发送到服务器的数据以`multipart/form-data`编码类型所需的正确格式存储。这个`mediaData`对象在`componentDidMount`中初始化。

`mern-mediastream/client/media/NewMedia.js`:

```jsx
componentDidMount = () => {
    this.mediaData = new FormData()
}
```

在表单提交时，将使用必要的凭据调用`create` fetch 方法，并将表单数据作为参数传递：

```jsx
 clickSubmit = () => {
    const jwt = auth.isAuthenticated()
    create({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, this.mediaData).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({redirect: true, mediaId: data._id})
      }
    })
 }
```

在成功创建媒体后，用户可以根据需要重定向到不同的视图，例如，到一个带有新媒体详情的媒体视图。

`mern-mediastream/client/media/NewMedia.js`:

```jsx
if (this.state.redirect) {
      return (<Redirect to={'/media/' + this.state.mediaId}/>)
}
```

为了允许用户流媒体和查看存储在 MongoDB 中的视频文件，接下来我们将实现如何在视图中检索和渲染视频。

# 检索和流媒体

在服务器上，我们将设置一个路由来检索单个视频文件，然后将其用作 React 媒体播放器中的源，以渲染流媒体视频。

# 获取视频 API

我们将在媒体路由中添加一个路由，以在`'/api/medias/video/:mediaId'`接收到 GET 请求时获取视频。

`mern-mediastream/server/routes/media.routes.js`:

```jsx
router.route('/api/medias/video/:mediaId')
        .get(mediaCtrl.video)
router.param('mediaId', mediaCtrl.mediaByID)
```

路由 URL 中的`:mediaId`参数将在`mediaByID`控制器中处理，以从媒体集合中获取关联文档并附加到请求对象中，因此可以根据需要在`video`控制器方法中使用。

`mern-mediastream/server/controllers/media.controller.js`:

```jsx
const mediaByID = (req, res, next, id) => {
  Media.findById(id).populate('postedBy', '_id name').exec((err, media) => {
    if (err || !media)
      return res.status('400').json({
        error: "Media not found"
      })
    req.media = media
    next()
  })
}
```

`media.controller.js`中的`video`控制器方法将使用`gridfs`在 MongoDB 中查找与`mediaId`关联的视频。然后，如果找到匹配的视频并且取决于请求是否包含范围标头，响应将发送回正确的视频块，并将相关内容信息设置为响应标头。

`mern-mediastream/server/controllers/media.controller.js`:

```jsx
const video = (req, res) => {
  gridfs.findOne({
        _id: req.media._id
    }, (err, file) => {
        if (err) {
            return res.status(400).send({
                error: errorHandler.getErrorMessage(err)
            })
        }
        if (!file) {
            return res.status(404).send({
                error: 'No video found'
            })
        }

        if (req.headers['range']) {
            ...
            ... consider range headers and send only relevant chunks in 
           response ...
            ...
        } else {
            res.header('Content-Length', file.length)
            res.header('Content-Type', file.contentType)

            gridfs.createReadStream({
                _id: file._id
            }).pipe(res)
        }
    })
}
```

如果请求包含范围标头，例如当用户拖动到视频中间并从那一点开始播放时，我们需要将范围标头转换为与使用 GridFS 存储的正确块对应的起始和结束位置。然后，我们将这些起始和结束值作为范围传递给 gridfs-stream 的`createReadStream`方法，并且还使用附加文件详情设置响应标头，包括内容长度、范围和类型。

`mern-mediastream/server/controllers/media.controller.js`:

```jsx
let parts = req.headers['range'].replace(/bytes=/, "").split("-")
let partialstart = parts[0]
let partialend = parts[1]

let start = parseInt(partialstart, 10)
let end = partialend ? parseInt(partialend, 10) : file.length - 1
let chunksize = (end - start) + 1

res.writeHead(206, {
    'Accept-Ranges': 'bytes',
 'Content-Length': chunksize,
 'Content-Range': 'bytes ' + start + '-' + end + '/' + file.length,
 'Content-Type': file.contentType
})

gridfs.createReadStream({
        _id: file._id,
        range: {
                 startPos: start,
                 endPos: end
                }
}).pipe(res)
```

最终的`readStream`管道传输到响应中可以直接在前端视图中使用基本的 HTML5 媒体播放器或 React 风格的媒体播放器进行渲染。

# 使用 React 媒体播放器来呈现视频

作为 npm 可用的 React 风格媒体播放器的一个很好的选择是`ReactPlayer`组件，可以根据需要进行自定义：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/815895de-c19d-439e-b16b-56eb8b0c12d2.png)

可以通过安装相应的`npm`模块在应用程序中使用它：

```jsx
npm install react-player --save
```

对于使用浏览器提供的默认控件的基本用法，我们可以将其添加到应用程序中任何具有要呈现的媒体 ID 访问权限的 React 视图中：

```jsx
<ReactPlayer url={'/api/media/video/'+media._id} controls/>
```

在下一章中，我们将探讨使用我们自己的控件自定义这个`ReactPlayer`的高级选项。

要了解有关`ReactPlayer`可能性的更多信息，请访问[cookpete.com/react-player](https://cookpete.com/react-player)。

# 媒体列表

在 MERN Mediastream 中，我们将添加相关媒体的列表视图，并为每个视频提供快照，以便访问者更容易地访问应用程序中的视频概述。我们将在后端设置列表 API 来检索不同的列表，例如单个用户上传的视频以及应用程序中观看次数最多的最受欢迎视频。然后，这些检索到的列表可以在`MediaList`组件中呈现，该组件将从父组件接收一个列表作为 prop，该父组件从特定 API 中获取列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/6c2da7fb-dec3-407d-b2e4-3114b4b61e71.png)

在前面的屏幕截图中，`Profile`组件使用用户 API 列表来获取前面配置文件中看到的用户发布的媒体列表，并将接收到的列表传递给`MediaList`组件以呈现每个视频和媒体详细信息。

# 媒体列表组件

`MediaList`组件是一个可重用的组件，它将获取一个媒体列表并在视图中迭代每个项目进行呈现。在 MERN Mediastream 中，我们使用它来在主页视图中呈现最受欢迎的媒体列表，以及在用户配置文件中上传的媒体列表。

`mern-mediastream/client/media/MediaList.js`：

```jsx
<GridList cols={3}>
   {this.props.media.map((tile, i) => (
        <GridListTile key={i}>
          <Link to={"/media/"+tile._id}>
            <ReactPlayer url={'/api/media/video/'+tile._id} 
                         width='100%' height='inherit'/>
          </Link>
          <GridListTileBar 
            title={<Link to={"/media/"+tile._id}>{tile.title}</Link>}
            subtitle={<span>{tile.views} views 
                  <span style={{float: 'right'}}>{tile.genre}</span>}/>
        </GridListTile>
    ))}
</GridList>
```

`MediaList`组件使用 Material-UI 的`GridList`组件，它在 props 中迭代列表，并为列表中的每个项目呈现媒体详细信息，以及一个`ReactPlayer`组件，用于呈现视频 URL 而不显示任何控件。在视图中，这为访问者提供了媒体的简要概述，也可以一瞥视频内容。

# 列出热门媒体

为了从数据库中检索特定的媒体列表，我们需要在服务器上设置相关的 API。对于热门媒体，我们将设置一个路由，接收`/api/media/popular`的 GET 请求。

`mern-mediastream/server/routes/media.routes.js`：

```jsx
 router.route('/api/media/popular')
          .get(mediaCtrl.listPopular)
```

`listPopular`控制器方法将查询媒体集合，以检索具有整个集合中最高`views`的十个媒体文档。

`mern-mediastream/server/controllers/media.controller.js`：

```jsx
const listPopular = (req, res) => {
  Media.find({}).limit(10)
  .populate('postedBy', '_id name')
  .sort('-views')
  .exec((err, posts) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(posts)
  })
}
```

为了在视图中使用此 API，我们将在`api-media.js`中设置相应的 fetch 方法。

`mern-mediastream/client/media/api-media.js`：

```jsx
const listPopular = (params) => {
  return fetch('/api/media/popular', {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  }).then(response => {
    return response.json() 
  }).catch((err) => console.log(err)) 
}
```

当`Home`组件挂载时，将调用此`fetch`方法，以便将列表设置为状态，并传递给视图中的`MediaList`组件。

`mern-mediastream/client/core/Home.js`：

```jsx
componentDidMount = () => {
    listPopular().then((data) => {
      if (data.error) {
        console.log(data.error) 
      } else {
        this.setState({media: data}) 
      }
    })
  }
```

在主页视图中，我们将添加`MediaList`如下，列表作为 prop 提供：

```jsx
<MediaList media={this.state.media}/>
```

# 按用户列出媒体

为了检索特定用户上传的媒体列表，我们将设置一个 API，该 API 在路由上接受`'/api/media/by/:userId'`的 GET 请求。

`mern-mediastream/server/routes/media.routes.js`：

```jsx
router.route('/api/media/by/:userId')
         .get(mediaCtrl.listByUser) 
```

`listByUser`控制器方法将查询媒体集合，以查找`postedBy`值与`userId`匹配的媒体文档。

`mern-mediastream/server/controllers/media.controller.js`：

```jsx
const listByUser = (req, res) => {
  Media.find({postedBy: req.profile._id})
  .populate('postedBy', '_id name')
  .sort('-created')
  .exec((err, posts) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(posts)
  })
}
```

为了在前端视图中使用此用户列表 API，我们将在`api-media.js`中设置相应的`fetch`方法。

`mern-mediastream/client/user/api-user.js`：

```jsx
const listByUser = (params) => {
  return fetch('/api/media/by/'+ params.userId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  }).then(response => {
    return response.json() 
  }).catch((err) => console.log(err)) 
}
```

这个 fetch 方法可以在`Profile`组件中使用，类似于在主页视图中使用的`listPopular`fetch 方法，以检索列表数据，设置状态，然后传递给`MediaList`组件。

# 显示、更新和删除媒体

MERN Mediastream 的任何访问者都可以查看媒体详细信息并流式传输视频，而只有注册用户才能在在应用程序上发布后随时编辑详细信息和删除媒体。

# 显示媒体

MERN Mediastream 的任何访问者都可以浏览到单个媒体视图，播放视频并阅读与媒体相关的详细信息。每次在应用程序上加载特定视频时，我们还将增加与媒体相关的观看次数。

# 阅读媒体 API

为了获取特定媒体记录的媒体信息，我们将设置一个路由，接受`'/api/media/:mediaId'`的 GET 请求。

`mern-mediastream/server/routes/media.routes.js`：

```jsx
router.route('/api/media/:mediaId')
    .get( mediaCtrl.incrementViews, mediaCtrl.read)
```

请求 URL 中的`mediaId`将导致执行`mediaByID`控制器方法，并将检索到的媒体文档附加到请求对象。然后，此媒体数据将由`read`控制器方法返回在响应中。

`mern-mediastream/server/controllers/media.controller.js`:

```jsx
const read = (req, res) => {
  return res.json(req.media)
}
```

对此 API 的 GET 请求还将执行`incrementViews`控制器方法，该方法将找到匹配的媒体记录，并将`views`值增加 1，然后将更新后的记录保存到数据库中。

`mern-mediastream/server/controllers/media.controller.js`:

```jsx
const incrementViews = (req, res, next) => {
  Media.findByIdAndUpdate(req.media._id, {$inc: {"views": 1}}, {new: true})
      .exec((err, result) => {
        if (err) {
          return res.status(400).json({
            error: errorHandler.getErrorMessage(err)
          })
        }
        next()
      })
}
```

为了在前端使用此读取 API，我们将在`api-media.js`中设置相应的 fetch 方法。

`mern-mediastream/client/user/api-user.js`:

```jsx
const read = (params) => {
  return fetch(config.serverUrl+'/api/media/' + params.mediaId, {
    method: 'GET'
  }).then((response) => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

读取 API 可用于在视图中呈现单个媒体详细信息，或者预填充媒体编辑表单。

# 媒体组件

`Media`组件将呈现单个媒体记录的详细信息，并在具有默认浏览器控件的基本`ReactPlayer`中流式传输视频。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/0573b444-addd-489c-99eb-7fb12e3c0a68.png)

`Media`组件可以调用读取 API 来获取媒体数据，也可以从调用读取 API 的父组件作为 prop 接收数据。在后一种情况下，父组件将添加`Media`组件，如下所示。

`mern-mediastream/client/media/PlayMedia.js`:

```jsx
<Media media={this.state.media}/>
```

在 MERN Mediastream 中，我们在`PlayMedia`组件中添加了`Media`组件，该组件使用读取 API 从服务器获取媒体内容，并将其作为 prop 传递给 Media。 `Media`组件将获取这些数据并在视图中呈现它们，以显示详细信息并在`ReactPlayer`组件中加载视频。

标题，流派和观看次数可以在 Material-UI`CardHeader`组件中呈现。

`mern-mediastream/client/media/Media.js`:

```jsx
<CardHeader 
   title={this.props.media.title}
   action={<span>
                {this.props.media.views + ' views'}
           </span>}
   subheader={this.props.media.genre}
/>
```

视频 URL，基本上是我们在后端设置的 GET API 路由，将在`ReactPlayer`中加载，并具有默认的浏览器控件。

`mern-mediastream/client/media/Media.js`:

```jsx
const mediaUrl = this.props.media._id
          ? `/api/media/video/${this.props.media._id}`
          : null
            … 
<ReactPlayer url={mediaUrl} 
             controls
             width={'inherit'}
             height={'inherit'}
             style={{maxHeight: '500px'}}
             config={{ attributes: 
                        { style: { height: '100%', width: '100%'} } 
}}/>
```

`Media`组件会渲染发布视频的用户的其他详细信息，媒体描述以及媒体创建日期。

`mern-mediastream/client/media/Media.js`:

```jsx
<ListItem>
    <ListItemAvatar>
      <Avatar>
        {this.props.media.postedBy.name && 
                        this.props.media.postedBy.name[0]}
      </Avatar>
    </ListItemAvatar>
    <ListItemText primary={this.props.media.postedBy.name} 
              secondary={"Published on " + 
                        (new Date(this.props.media.created))
                        .toDateString()}/>
</ListItem>
<ListItem>
    <ListItemText primary={this.props.media.description}/>
</ListItem>
```

如果当前登录的用户也是发布显示的媒体的用户，则`Media`组件还会有条件地显示编辑和删除选项。

`mern-mediastream/client/media/Media.js`:

```jsx
{(auth.isAuthenticated().user && auth.isAuthenticated().user._id) 
    == this.props.media.postedBy._id && (<ListItemSecondaryAction>
        <Link to={"/media/edit/" + this.props.media._id}>
          <IconButton aria-label="Edit" color="secondary">
            <Edit/>
          </IconButton>
        </Link>
        <DeleteMedia mediaId={this.props.media._id} mediaTitle=
       {this.props.media.title}/>
      </ListItemSecondaryAction>)}
```

编辑选项链接到媒体编辑表单，删除选项打开一个对话框，可以启动从数据库中删除特定媒体文档。

# 更新媒体详细信息

注册用户将可以访问其每个媒体上传的编辑表单，更新并提交此表单将保存更改到媒体集合中的文档中。

# 媒体更新 API

为了允许用户更新媒体详细信息，我们将设置一个媒体更新 API，该 API 将在`'/api/media/:mediaId'`处接受 PUT 请求，并在请求正文中包含更新的详细信息。

`mern-mediastream/server/routes/media.routes.js`：

```jsx
router.route('/api/media/:mediaId')
        .put(authCtrl.requireSignin, 
                mediaCtrl.isPoster, 
                    mediaCtrl.update)
```

当收到此请求时，服务器将首先通过调用`isPoster`控制器方法来确保登录用户是媒体内容的原始发布者。

`mern-mediastream/server/controllers/media.controller.js`：

```jsx
const isPoster = (req, res, next) => {
  let isPoster = req.media && req.auth 
  && req.media.postedBy._id == req.auth._id
  if(!isPoster){
    return res.status('403').json({
      error: "User is not authorized"
    })
  }
  next()
}
```

如果用户被授权，将调用`update`控制器方法`next`，以更新现有的媒体文档并将其保存到数据库中。

`mern-mediastream/server/controllers/media.controller.js`：

```jsx
const update = (req, res, next) => {
  let media = req.media
  media = _.extend(media, req.body)
  media.updated = Date.now()
  media.save((err) => {
    if (err) {
      return res.status(400).send({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(media)
  })
}
```

为了在前端访问更新 API，我们将在`api-media.js`中添加相应的获取方法，该方法将以必要的凭据和媒体详细信息作为参数。

`mern-mediastream/client/user/api-user.js`：

```jsx
const update = (params, credentials, media) => {
  return fetch('/api/media/' + params.mediaId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify(media)
  }).then((response) => {
    return response.json() 
  }).catch((err) => {
    console.log(err) 
  }) 
}
```

当用户更新并提交表单时，此获取方法将用于媒体编辑表单。

# 媒体编辑表单

媒体编辑表单将类似于新媒体表单，但不包括上传选项，并且字段将预填充现有细节：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/dd5cc45f-20f1-422b-b493-2d38f7343bca.png)

包含此表单的`EditMedia`组件只能由登录用户访问，并将呈现在`'/media/edit/:mediaId'`。此私有路由将在`MainRouter`中与其他前端路由一起声明。

`mern-mediastream/client/MainRouter.js`：

```jsx
<PrivateRoute path="/media/edit/:mediaId" component={EditMedia}/>
```

一旦`EditMedia`组件挂载到视图上，将调用获取调用以从读取媒体 API 检索媒体详细信息并设置为状态，以便在文本字段中呈现值。

`mern-mediastream/client/media/EditMedia.js`：

```jsx
  componentDidMount = () => {
    read({mediaId: this.match.params.mediaId}).then((data) => {
      if (data.error) {
        this.setState({error: data.error}) 
      } else {
        this.setState({media: data}) 
      }
    }) 
  }
```

表单字段元素将与`NewMedia`组件中的相同。当用户更新表单中的任何值时，将通过调用`handleChange`方法在状态中注册`media`对象中的更改。

`mediastream/client/media/EditMedia.js`：

```jsx
handleChange = name => event => {
    let updatedMedia = this.state.media
    updatedMedia[name] = event.target.value
    this.setState({media: updatedMedia})
}
```

当用户完成编辑并点击提交时，将调用更新 API，并提供所需的凭据和更改后的媒体值。

`mediastream/client/media/EditMedia.js`:

```jsx
  clickSubmit = () => {
    const jwt = auth.isAuthenticated() 
    update({
      mediaId: this.state.media._id
    }, {
      t: jwt.token
    }, this.state.media).then((data) => {
      if (data.error) {
        this.setState({error: data.error}) 
      } else {
        this.setState({error: '', redirect: true, media: data}) 
      }
    }) 
}
```

这将更新媒体详情，并且与媒体相关的视频文件将保持在数据库中不变。

# 删除媒体

经过身份验证的用户可以完全删除他们上传到应用程序的媒体，包括媒体集合中的媒体文档，以及使用 GridFS 存储在 MongoDB 中的文件块。

# 删除媒体 API

在后端，我们将添加一个 DELETE 路由，允许授权用户删除他们上传的媒体记录。

`mern-mediastream/server/routes/media.routes.js`:

```jsx
router.route('/api/media/:mediaId')
        .delete(authCtrl.requireSignin, 
                    mediaCtrl.isPoster, 
                        mediaCtrl.remove)
```

当服务器在`'/api/media/:mediaId'`接收到 DELETE 请求时，它将首先确保登录用户是需要删除的媒体的原始发布者。然后`remove`控制器方法将从数据库中删除指定的媒体详情。

`mern-mediastream/server/controllers/media.controller.js`:

```jsx
const remove = (req, res, next) => {
  let media = req.media
    media.remove((err, deletedMedia) => {
      if (err) {
        return res.status(400).json({
          error: errorHandler.getErrorMessage(err)
        })
      }
      gridfs.remove({ _id: req.media._id })
      res.json(deletedMedia)
    })
}
```

除了从媒体集合中删除媒体记录外，我们还使用`gridfs`来删除数据库中存储的相关文件详情和块。

我们还将在`api-media.js`中添加一个相应的方法来从视图中获取`delete` API。

`mern-mediastream/client/user/api-user.js`:

```jsx
const remove = (params, credentials) => {
  return fetch('/api/media/' + params.mediaId, {
    method: 'DELETE',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then((response) => {
    return response.json() 
  }).catch((err) => {
    console.log(err) 
  }) 
}
```

# 删除媒体组件

`DeleteMedia`组件被添加到`Media`组件中，只对添加了特定媒体的已登录用户可见。该组件以媒体 ID 和标题作为 props：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/b0470db1-6793-4723-8c9e-b918a4929e74.png)

这个`DeleteMedia`组件基本上是一个图标按钮，点击后会打开一个确认对话框，询问用户是否确定要删除他们的视频。

`mern-mediastream/client/media/DeleteMedia.js`:

```jsx
<IconButton aria-label="Delete" onClick={this.clickButton} color="secondary">
    <DeleteIcon/>
</IconButton>
<Dialog open={this.state.open} onClose={this.handleRequestClose}>
  <DialogTitle>{"Delete "+this.props.mediaTitle}</DialogTitle>
  <DialogContent>
     <DialogContentText>
         Confirm to delete {this.props.mediaTitle} from your account.
     </DialogContentText>
  </DialogContent>
  <DialogActions>
     <Button onClick={this.handleRequestClose} color="primary">
        Cancel
     </Button>
     <Button onClick={this.deleteMedia} 
              color="secondary" 
              autoFocus="autoFocus"
              variant="raised">
        Confirm
     </Button>
  </DialogActions>
</Dialog>
```

当用户确认删除意图时，将调用`delete`获取方法。

`mern-mediastream/client/media/DeleteMedia.js`:

```jsx
deleteMedia = () => {
    const jwt = auth.isAuthenticated() 
    remove({
      mediaId: this.props.mediaId
    }, {t: jwt.token}).then((data) => {
      if (data.error) {
        console.log(data.error) 
      } else {
        this.setState({redirect: true}) 
      }
    }) 
}
```

然后在成功删除后，用户将被重定向到主页。

`mern-mediastream/client/media/DeleteMedia.js`:

```jsx
if (this.state.redirect) {
   return <Redirect to='/'/> 
}
```

本章开发的 MERN Mediastream 应用程序是一个完整的媒体流应用程序，具有将视频文件上传到数据库的功能，将存储的视频流回给观众的功能，支持 CRUD 操作，如媒体创建、更新、读取和删除，以及按上传者或受欢迎程度列出媒体的选项。

# 总结

在本章中，我们通过扩展 MERN 骨架应用程序并利用 MongoDB GridFS 开发了一个媒体流应用程序。

除了为媒体添加基本的添加、更新、删除和列表功能外，我们还研究了基于 MERN 的应用如何允许用户上传视频文件，将这些文件存储到 MongoDB GridFS 中，并根据需要部分或完全地向观看者流式传输视频。我们还介绍了使用默认浏览器控件来流式传输视频文件的`ReactPlayer`的基本用法。

在下一章中，我们将看到如何使用自定义控件和功能定制`ReactPlayer`，以便用户拥有更多选项，比如播放列表中的下一个视频。此外，我们将讨论如何通过实现带有媒体视图数据的服务器端渲染来改善媒体详情的搜索引擎优化。


# 第九章：自定义媒体播放器和改善 SEO

用户主要是为了播放媒体和探索其他相关媒体而访问媒体流应用程序。这使得媒体播放器和呈现相关媒体详情的视图对于流媒体应用程序至关重要。

在本章中，我们将专注于为我们在上一章开始构建的 MERN Mediastream 应用程序开发播放媒体页面。我们将讨论以下主题，以加强媒体播放功能，并帮助增加媒体内容在网络上的存在，以便能够触达更多用户：

+   自定义`ReactPlayer`上的控件

+   从相关视频列表中播放下一个视频

+   自动播放相关媒体列表

+   服务器端渲染媒体视图以改善 SEO

# 使用自定义媒体播放器的 MERN Mediastream

在上一章中开发的 MERN Mediastream 应用程序实现了一个简单的媒体播放器，具有默认的浏览器控件，一次只能播放一个视频。在本章中，我们将使用自定义的`ReactPlayer`和相关媒体列表更新播放媒体的视图，可以在当前视频结束时自动播放。更新后的具有自定义播放器和相关播放列表的视图如下图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/2f2b187f-d816-4640-a728-d3627fbf0a39.png)完整的 MERN Mediastream 应用程序的代码可在 GitHub 上找到，网址为[github.com/shamahoque/mern-mediastream](https://github.com/shamahoque/mern-mediastream)。您可以在阅读本章其余部分的代码解释时，克隆此代码并运行应用程序。

以下组件树图显示了构成 MERN Mediastream 前端的所有自定义组件，突出显示了本章中将改进或添加的组件。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/48f71397-98ac-4e74-92de-dfb7d6758f4c.jpg)

本章中新增的组件包括`MediaPlayer`组件，它添加了带有自定义控件的`ReactPlayer`，以及`RelatedMedia`组件，其中包含相关视频列表。

# 播放媒体页面

当访问者想要在 MERN Mediastream 上观看特定媒体时，他们将被带到播放媒体页面，其中包含媒体详情、用于流媒体视频的媒体播放器，以及可以接下来播放的相关媒体列表。

# 组件结构

我们将以一种允许媒体数据从父组件向内部组件传递的方式构成播放媒体页面的组件结构。在这种情况下，`PlayMedia`组件将是父组件，包含`RelatedMedia`组件和带有嵌套的`MediaPlayer`组件的`Media`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c3e134b6-0f5f-4e9b-93cb-cce0c5a316b5.png)

当访问单个媒体链接时，`PlayMedia`组件将挂载并从服务器检索媒体数据和相关媒体列表。然后，相关数据将作为 props 传递给`Media`和`RelatedMedia`子组件。

`RelatedMedia`组件将链接到其他相关媒体的列表，点击每个将重新渲染`PlayMedia`组件和内部组件以显示新数据。

我们将更新我们在第八章中开发的`Media`组件，*构建媒体流应用程序*，以添加一个定制的媒体播放器作为子组件。这个定制的`MediaPlayer`组件还将利用从`PlayMedia`传递的数据来播放当前视频并链接到相关媒体列表中的下一个视频。

在`PlayMedia`组件中，我们将添加一个自动播放切换按钮，让用户选择自动播放相关媒体列表中的视频，一个接着一个。自动播放状态将从`PlayMedia`组件管理，但此功能将需要在`MediaPlayer`中视频结束时重新渲染状态中的数据，这是一个嵌套的子组件，所以下一个视频可以在保持相关列表跟踪的同时自动开始播放。

为了实现这一点，`PlayMedia`组件将需要提供一个状态更新方法作为 prop，该方法将在`MediaPlayer`组件中使用，以更新这些组件之间共享和相互依赖的状态值。

考虑到这种组件结构，我们将扩展和更新 MERN Mediastream 应用程序，以实现一个功能性的播放媒体页面。

# 相关媒体列表

相关媒体列表将包括属于与给定视频相同流派的其他媒体记录，并按观看次数最多的顺序排序。

# 相关列表 API

为了从数据库中检索相关媒体列表，我们将在服务器上设置一个 API，该 API 将在`'/api/media/related/:mediaId'`接收 GET 请求。

`mern-mediastream/server/routes/media.routes.js`：

```jsx
router.route('/api/media/related/:mediaId')
        .get(mediaCtrl.listRelated)
```

`listRelated`控制器方法将查询媒体集合，以找到与提供的媒体具有相同流派的记录，并从返回的结果中排除此媒体记录。返回的结果将按照最高的观看次数进行排序，并限制为前四个媒体记录。返回的结果中的每个`media`对象还将包含发布媒体的用户的名称和 ID。

`mern-mediastream/server/controllers/media.controller.js`：

```jsx
const listRelated = (req, res) => {
  Media.find({ "_id": { "$ne": req.media },
  "genre": req.media.genre}).limit(4)
  .sort('-views')
  .populate('postedBy', '_id name')
  .exec((err, posts) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(posts)
  })
}
```

在客户端，我们将设置一个相应的`fetch`方法，该方法将在`PlayMedia`组件中用于使用此 API 检索相关媒体列表。

`mern-mediastream/client/media/api-media.js`：

```jsx
const listRelated = (params) => {
  return fetch('/api/media/related/'+ params.mediaId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    }
  }).then(response => {
    return response.json() 
  }).catch((err) => console.log(err)) 
}
```

# 相关媒体组件

`RelatedMedia`组件从`PlayMedia`组件中以 prop 的形式获取相关媒体列表，并呈现每个视频的详细信息以及视频快照。

我们使用`map`函数遍历媒体列表，以呈现每个媒体项。

`mern-mediastream/client/media/RelatedMedia.js`：

```jsx
{this.props.media.map((item, i) => { 
    return 
      <span key={i}>... video snapshot ... | ... media details ...</span> 
  })
}
```

为了显示视频快照，我们将使用一个基本的`ReactPlayer`，没有控件。

`mern-mediastream/client/media/RelatedMedia.js`：

```jsx

<Link to={"/media/"+item._id}>
  <ReactPlayer url={'/api/media/video/'+item._id} width='160px'    
  height='140px'/>
</Link>
```

单击快照将重新呈现 PlayMedia 视图，以加载链接的媒体详细信息。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/087a88c8-0ee4-46c9-a3c7-0e0942fe6fb7.png)

除了快照之外，我们还将显示每个视频的详细信息，包括标题、流派、创建日期和观看次数。

`mern-mediastream/client/media/RelatedMedia.js`：

```jsx
<Typography type="title" color="primary">{item.title}</Typography>
<Typography type="subheading"> {item.genre} </Typography>
<Typography component="p">
        {(new Date(item.created)).toDateString()}
</Typography>
<Typography type="subheading">{item.views} views</Typography>
```

为了在视图中使用`RelatedMedia`组件，我们将在`PlayMedia`组件中添加它。

# 播放媒体组件

`PlayMedia`组件由`Media`和`RelatedMedia`子组件以及自动播放切换按钮组成，并在视图加载时向这些组件提供数据。为了在用户访问单个媒体链接时呈现`PlayMedia`组件，我们将在`MainRouter`中添加一个`Route`来在`'/media/:mediaId'`处挂载`PlayMedia`。

`mern-mediastream/client/MainRouter.js`：

```jsx
<Route path="/media/:mediaId" component={PlayMedia}/>
```

当`PlayMedia`组件挂载时，它将使用`loadMedia`函数基于路由链接中的`媒体 ID`参数从服务器获取媒体数据和相关媒体列表。

`mern-mediastream/client/media/PlayMedia.js`：

```jsx
loadMedia = (mediaId) => {
    read({mediaId: mediaId}).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({media: data})
          listRelated({
            mediaId: data._id}).then((data) => {
            if (data.error) {
              console.log(data.error)
            } else {
              this.setState({relatedMedia: data})
            }
          })
      }
    })
  }
```

`loadMedia`函数使用媒体 ID 和`read`API 的`fetch`方法从服务器检索媒体详细信息。然后，它使用`listRelated`API 的 fetch 方法从服务器检索相关媒体列表，并将值设置为状态。

当组件挂载时，将使用`mediaId`值调用`loadMedia`函数，也会在接收到 props 时调用。

`mern-mediastream/client/media/PlayMedia.js`：

```jsx
componentDidMount = () => {
    this.loadMedia(this.match.params.mediaId)
}
componentWillReceiveProps = (props) => {
    this.loadMedia(props.match.params.mediaId)
}
```

为了在组件挂载时访问路由 URL 中的`mediaId`参数，我们需要在组件的构造函数中访问 react-router 的`match`对象。

`mern-mediastream/client/media/PlayMedia.js`：

```jsx
constructor({match}) {
    super() 
    this.state = {
      media: {postedBy: {}},
      relatedMedia: [],
      autoPlay: false,
    } 
    this.match = match 
}
```

存储在组件状态中的媒体和相关媒体列表值用于将相关的 props 传递给视图中添加的子组件。例如，只有在相关媒体列表包含任何项目时，才会渲染`RelatedMedia`组件，并将其作为 prop 传递给列表。

`mern-mediastream/client/media/PlayMedia.js`：

```jsx
{this.state.relatedMedia.length > 0 && 
      (<RelatedMedia media={this.state.relatedMedia}/>)}
```

在本章的*自动播放相关媒体*部分，如果相关媒体列表的长度大于零，我们将在`RelatedMedia`组件上方添加自动播放切换组件。我们还将讨论`handleAutoPlay`方法的实现，该方法将作为 prop 传递给`Media`组件，以及媒体详情对象和相关媒体列表中第一个媒体的视频 URL 作为下一个要播放的 URL。

`mern-mediastream/client/media/PlayMedia.js`：

```jsx
const nextUrl = this.state.relatedMedia.length > 0
          ? `/media/${this.state.relatedMedia[0]._id}` : ''
<Media media={this.state.media} 
       nextUrl={nextUrl} 
       handleAutoplay={this.handleAutoplay}/>
```

`Media`组件渲染媒体详情，还有一个媒体播放器，允许观众控制视频的流媒体。

# 媒体播放器

我们将自定义`ReactPlayer`上的播放器控件，以替换默认的浏览器控件，具有自定义外观和功能，如屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/2c97a393-aea9-4d2b-ad38-f61da596bf40.png)

控件将添加在视频下方，并包括进度查找栏、播放、暂停、下一个、音量、循环和全屏选项，还会显示已播放的持续时间。

# 更新媒体组件

我们将创建一个新的`MediaPlayer`组件，其中包含自定义的`ReactPlayer`。在`Media`组件中，我们将用新的`MediaPlayer`组件替换先前使用的`ReactPlayer`，并将视频源 URL、下一个视频的 URL 和`handleAutoPlay`方法作为 props 从`PlayMedia`组件接收。

`mern-mediastream/client/media/Media.js`：

```jsx
const mediaUrl = this.props.media._id
          ? `/api/media/video/${this.props.media._id}`
          : null
...
<MediaPlayer srcUrl={mediaUrl} 
             nextUrl={this.props.nextUrl} 
             handleAutoplay={this.props.handleAutoplay}/>
```

# 初始化媒体播放器

`MediaPlayer`组件将包含`ReactPlayer`组件，首先使用初始控制值，然后添加自定义控件和处理代码。

首先，我们将将初始控制值设置为`state`。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
state = {
      playing: true,
      volume: 0.8,
      muted: false,
      played: 0,
      loaded: 0,
      duration: 0,
      ended:false,
      playbackRate: 1.0,
      loop: false,
      fullscreen: false,
      videoError: false
} 
```

在视图中，我们将使用从`Media`组件发送的 prop 来添加带有控制值和源 URL 的`ReactPlayer`。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
const { playing, ended, volume, muted, loop, played, loaded, duration, playbackRate, fullscreen, videoError } = this.state
...
  <ReactPlayer
     ref={this.ref}
     width={fullscreen ? '100%':'inherit'}
     height={fullscreen ? '100%':'inherit'}
     style={fullscreen ? {position:'relative'} : {maxHeight: '500px'}}
     config={{ attributes: { style: { height: '100%', width: '100%'} } }}
     url={this.props.srcUrl}
     playing={playing}
     loop={loop}
     playbackRate={playbackRate}
     volume={volume}
     muted={muted}
     onEnded={this.onEnded}
     onError={this.videoError}
     onProgress={this.onProgress}
     onDuration={this.onDuration}/>
```

我们将获取对此播放器的引用，以便在自定义控件的更改处理代码中使用它。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
ref = player => {
      this.player = player
}
```

如果无法加载源视频，我们将捕获错误。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
videoError = e => {
  this.setState({videoError: true}) 
}
```

然后我们将在视图中有条件地显示错误消息。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
{videoError && <p className={classes.videoError}>Video Error. Try again later.</p>}
```

# 自定义媒体控件

我们将在视频下方添加自定义播放器控件元素，并使用`ReactPlayer` API 提供的选项和事件来操纵它们的功能。

# 播放、暂停和重播

用户将能够播放、暂停和重播当前视频，我们将使用`Material-UI`组件绑定到`ReactPlayer`属性和事件来实现这三个选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/52a12bc4-9e39-4efc-bfba-c5d77ff41219.png)

为了实现播放、暂停和重播功能，我们将有条件地添加一个播放、暂停或重播图标按钮，具体取决于视频是正在播放、暂停还是已结束。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
<IconButton color="primary" onClick={this.playPause}>
    <Icon>{playing ? 'pause': (ended ? 'replay' : 'play_arrow')}</Icon>
</IconButton>
```

当用户点击按钮时，我们将更新状态中的 playing 值，以便更新`ReactPlayer`。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
playPause = () => {
     this.setState({ playing: !this.state.playing })
}
```

# 播放下一个

用户将能够使用下一个按钮播放相关媒体列表中的下一个视频：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/26dd9561-6f17-4f76-b118-a5755e88fef7.png)

如果相关列表不包含任何媒体，下一个按钮将被禁用。播放下一个图标基本上将链接到从`PlayMedia`传递的下一个 URL 值。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
<IconButton disabled={!this.props.nextUrl} color="primary">
    <Link to={this.props.nextUrl}>
       <Icon>skip_next</Icon>
    </Link>
</IconButton>
```

点击此“下一个”按钮将重新加载带有新媒体详情的`PlayMedia`组件并开始播放视频。

# 结束时循环

用户还可以使用循环按钮将当前视频设置为保持循环播放：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/bd40c922-9269-4e12-abb0-13d1cc516a7c.png)

我们将设置一个循环图标按钮，以显示不同的颜色，以指示它是设置还是未设置。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
<IconButton color={loop? 'primary' : 'default'} 
            onClick={this.onLoop}>
    <Icon>loop</Icon>
</IconButton>
```

当循环图标按钮被点击时，它会更新状态中的`loop`值。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
onLoop = () => {
   this.setState({ loop: !this.state.loop })
}
```

我们需要捕获`onEnded`事件，以检查`loop`是否被设置为 true，这样`playing`值可以相应地更新。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
onEnded = () => {
    if(this.state.loop){
      this.setState({ playing: true})
    }else{
      this.setState({ ended: true, playing: false })
    }
}
```

因此，如果`loop`设置为 true，当视频结束时，它将重新开始播放，否则它将停止播放并渲染重播按钮。

# 音量控制

为了控制正在播放的视频的音量，用户可以选择增加或减少音量，以及静音或取消静音。渲染的音量控件将根据用户操作和音量的当前值进行更新：

+   如果音量提高，将呈现一个音量增加图标：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/74ba3641-fea7-48d8-8b15-8a36ad7f0df4.png)

+   如果用户将音量减少到零，将呈现一个音量关闭图标：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/cef09c93-73fe-48bc-a36b-d97965b28e14.png)

+   当用户点击图标静音音量时，将显示一个音量静音图标按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/b34a64a7-d26b-487d-9783-48b66f54b040.png)

为了实现这一点，我们将有条件地在`IconButton`中渲染不同的图标，根据`volume`、`muted`、`volume_up`和`volume_off`的值：

```jsx
<IconButton color="primary" onClick={this.toggleMuted}>
    <Icon> {volume > 0 && !muted && 'volume_up' || 
            muted && 'volume_off' || 
               volume==0 && 'volume_mute'} </Icon>
</IconButton>
```

当点击音量按钮时，它将静音或取消静音。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
toggleMuted = () => {
    this.setState({ muted: !this.state.muted })
}
```

为了允许用户增加或减少音量，我们将添加一个`input range`，允许用户设置音量值在`0`和`1`之间。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
<input type="range" 
       min={0} 
       max={1} 
       step='any' 
       value={muted? 0 : volume} 
       onChange={this.setVolume}/>
```

更改输入范围上的`value`将相应地设置`volume`值。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
  setVolume = e => {
    this.setState({ volume: parseFloat(e.target.value) })
  }
```

# 进度控制

我们将使用 Material-UI 的`LinearProgress`组件来指示视频已缓冲的部分和已播放的部分。然后我们将把这个组件与`range input`结合起来，让用户能够移动时间滑块到视频的不同部分并从那里播放：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/3406e0dd-b022-472d-aec1-16d1f4697a25.png)

`LinearProgress`组件将采用`played`和`loaded`值来显示不同的颜色：

```jsx
<LinearProgress color="primary" variant="buffer" 
                value={played*100} valueBuffer={loaded*100} 
                style={{width: '100%'}} 
                classes={{ colorPrimary: classes.primaryColor,
                           dashedColorPrimary: classes.primaryDashed,
                           dashed: {animation: 'none'} }}
/>
```

为了在视频播放或加载时更新`LinearProgress`组件，我们将使用`onProgress`事件监听器来设置`played`和`loaded`的当前值。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
onProgress = progress => {
    if (!this.state.seeking) {
      this.setState({played: progress.played, loaded: progress.loaded})
    }
}
```

对于时间滑动控制，我们将添加`range input`元素，并使用 CSS 样式将其放置在`LinearProgress`组件上。随着`played`值的变化，范围的当前值将更新，因此范围值似乎随着视频的进展而移动。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
<input type="range" min={0} max={1}
       value={played} step='any'
       onMouseDown={this.onSeekMouseDown}
       onChange={this.onSeekChange}
       onMouseUp={this.onSeekMouseUp}
       style={{ position: 'absolute',
                width: '100%',
                top: '-7px',
                zIndex: '999',
                '-webkit-appearance': 'none',
                backgroundColor: 'rgba(0,0,0,0)' }}
/>
```

在用户自行拖动并设置范围选择器的情况下，我们将添加代码来处理`onMouseDown`、`onMouseUp`和`onChange`事件，以从所需位置开始播放视频。

当用户按住鼠标开始拖动时，我们将把 seeking 设置为 true，以便进度值不设置为`played`和`loaded`。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
onSeekMouseDown = e => {
    this.setState({ seeking: true })
}
```

随着范围值的变化，我们将设置`played`值和`ended`值，并检查用户是否将时间滑块拖到视频的末尾。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
onSeekChange = e => {
  this.setState({ played: parseFloat(e.target.value), 
                    ended: parseFloat(e.target.value) >= 1 })
}
```

当用户完成拖动并松开鼠标点击时，我们将把`seeking`设置为`false`，并将播放器的`seekTo`值设置为`range input`中的当前值。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
onSeekMouseUp = e => {
  this.setState({ seeking: false })
  this.player.seekTo(parseFloat(e.target.value))
}
```

这样，用户将能够选择视频的任何部分，并获得视频流的时间进度的视觉信息。

# 全屏

用户可以通过单击控件中的全屏按钮在全屏模式下观看视频：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/94d9b7b1-191f-48ae-87bf-ad155addb093.png)

为了为视频实现全屏选项，我们将使用`screenfull` npm 模块来跟踪视图是否处于全屏状态，并使用`react-dom`中的`findDOMNode`来指定哪个 DOM 元素将与`screenfull`一起全屏显示。

要设置“全屏”代码，我们首先安装`screenfull`：

```jsx
npm install screenfull --save
```

然后将`screenfull`和`findDOMNode`导入到`MediaPlayer`组件中。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
import screenfull from 'screenfull'
import { findDOMNode } from 'react-dom'
```

当`MediaPlayer`组件挂载时，我们将添加一个`screenfull`更改事件侦听器，以更新状态中的“全屏”值，以指示屏幕是否处于全屏状态。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
componentDidMount = () => {
  if (screenfull.enabled) {
     screenfull.on('change', () => {
         let fullscreen = screenfull.isFullscreen ? true : false 
         this.setState({fullscreen: fullscreen}) 
     }) 
  }
}
```

在视图中，我们将在其他控制按钮中添加一个“全屏”图标按钮。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
<IconButton color="primary" onClick={this.onClickFullscreen}>
  <Icon>fullscreen</Icon>
</IconButton>
```

当用户点击此按钮时，我们将使用`screenfull`和`findDOMNode`使视频播放器全屏。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
onClickFullscreen = () => {
   screenfull.request(findDOMNode(this.player))
}
```

然后用户可以在全屏模式下观看视频，可以随时按*Esc*退出全屏并返回到 PlayMedia 视图。

# 播放持续时间

在媒体播放器的自定义媒体控件部分，我们希望以可读的时间格式显示已经过去的时间和视频的总持续时间：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/bc1f8bcf-a2d9-4303-9243-5ec1f87e922d.png)

为了显示时间，我们可以利用 HTML 的`time`元素。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
<time dateTime={`P${Math.round(duration * played)}S`}>
      {this.format(duration * played)}
</time> / 
<time dateTime={`P${Math.round(duration)}S`}>
    {this.format(duration)}
</time>
```

我们将通过使用`onDuration`事件获取视频的`duration`值，然后将其设置为状态，以便在时间元素中渲染。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
onDuration = (duration) => {
    this.setState({ duration })
}
```

为了使持续时间值可读，我们将使用以下的`format`函数。

`mern-mediastream/client/media/MediaPlayer.js`:

```jsx
format = (seconds) => {
  const date = new Date(seconds * 1000)
  const hh = date.getUTCHours()
  let mm = date.getUTCMinutes()
  const ss = ('0' + date.getUTCSeconds()).slice(-2)
  if (hh) {
    mm = ('0' + date.getUTCMinutes()).slice(-2) 
    return `${hh}:${mm}:${ss}`
  }
  return `${mm}:${ss}`
}
```

`format`函数接受以秒为单位的持续时间值，并将其转换为`hh/mm/ss`格式。

添加到自定义媒体播放器的控件大多基于`ReactPlayer`模块中的一些可用功能，以及其提供的示例作为文档。还有更多选项可用于进一步定制和扩展，具体取决于特定的功能需求。

# 自动播放相关媒体

我们将通过在`PlayMedia`中添加一个切换并实现`handleAutoplay`方法来完成之前讨论的自动播放功能，当相关媒体列表中有媒体时，需要在`MediaPlayer`组件中调用该方法。

# 切换自动播放

除了允许用户设置自动播放外，切换还将指示当前是否已设置自动播放：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/cc0fa409-f523-44c3-9234-d5ebe695c302.png)

对于自动播放切换，我们将使用`Material-UI`的`Switch`组件以及`FormControlLabel`，并将其添加到`PlayMedia`组件中，仅在相关媒体列表中有媒体时进行渲染。

`mern-mediastream/client/media/PlayMedia.js`:

```jsx
<FormControlLabel 
    control={
            <Switch
              checked={this.state.autoPlay}
              onChange={this.handleChange}
              color="primary"
            />
          }
    label={this.state.autoPlay? 'Autoplay ON':'Autoplay OFF'}
/>
```

处理切换并在状态的`autoplay`值中反映这一变化，我们将使用以下的`onChange`处理函数。

`mern-mediastream/client/media/PlayMedia.js`:

```jsx
handleChange = (event) => {
   this.setState({ autoPlay: event.target.checked }) 
} 
```

# 跨组件处理自动播放

`PlayMedia`将`handleAutoPlay`方法作为属性传递给`Media`组件，以便在视频结束时由`MediaPlayer`组件使用。

这里期望的功能是，当视频结束时，如果自动播放设置为 true 并且当前相关媒体列表不为空，则`PlayMedia`应加载相关列表中第一个视频的媒体详情。反过来，`Media`和`MediaPlayer`组件应更新为新的媒体详情，开始播放新视频，并适当地渲染播放器上的控件。`RelatedMedia`组件中的列表也应更新，从列表中移除当前媒体，因此只有剩余的播放列表项可见。

`mern-mediastream/client/media/PlayMedia.js`：

```jsx
handleAutoplay = (updateMediaControls) => {
    let playList = this.state.relatedMedia
    let playMedia = playList[0]

    if(!this.state.autoPlay || playList.length == 0 )
      return updateMediaControls()

    if(playList.length > 1){
      playList.shift()
      this.setState({media: playMedia, relatedMedia:playList})
    }else{
      listRelated({
          mediaId: playMedia._id}).then((data) => {
            if (data.error) {
             console.log(data.error)
            } else {
             this.setState({media: playMedia, relatedMedia: data})
            }
         })
    }
  }
```

`handleAutoplay`方法在`MediaPlayer`组件中视频结束时处理以下内容：

+   它从`MediaPlayer`组件的`onEnded`事件监听器中获取回调函数。如果未设置自动播放或相关媒体列表为空，则将执行此回调，以便在`MediaPlayer`上呈现视频已结束的控件。

+   如果设置了自动播放并且列表中有多个相关媒体，则：

+   将相关媒体列表中的第一项设置为状态中的当前媒体对象，以便进行渲染

+   通过删除将在视图中开始播放的第一个项目来更新相关媒体列表

+   如果设置了自动播放并且相关媒体列表中只有一个项目，则将此最后一个项目设置为媒体，以便开始播放，并调用`listRelated`获取方法来重新填充 RelatedMedia 视图与此最后一个项目的相关媒体。

# 在 MediaPlayer 中视频结束时更新状态

`MediaPlayer`从`PlayMedia`中接收`handleAutoplay`方法作为属性。我们将更新`onEnded`事件的监听器代码，仅当`loop`设置为当前视频的`false`时才执行此方法。

`mern-mediastream/client/media/MediaPlayer.js`：

```jsx
onEnded = () => {
  if(this.state.loop){
    this.setState({ playing: true})
  }else{
    this.props.handleAutoplay(() => {
                              this.setState({ ended: true, 
                                                playing: false })
                            }) 
    }
}
```

回调函数被传递给`handleAutoplay`方法，以便在`PlayMedia`中确定自动播放未设置或相关媒体列表为空后，将播放设置为 false，并渲染重播图标按钮而不是播放或暂停图标按钮。

使用这种实现，自动播放功能将继续播放相关视频。这种实现演示了在值相互依赖时跨组件更新状态的另一种方式。

# 使用数据进行服务器端渲染

搜索引擎优化对于向用户提供内容并希望使内容易于查找的任何 Web 应用程序都很重要。通常，如果网页上的内容对搜索引擎易于阅读，那么该网页上的内容就有更多的机会获得更多的观众。当搜索引擎爬虫访问网址时，它将获取服务器端渲染的输出。因此，为了使内容可发现，内容应该是服务器端渲染输出的一部分。

在 MERN Mediastream 中，我们将使用使媒体详情在搜索引擎结果中受欢迎的案例，以演示如何在 MERN 应用程序中将数据注入到服务器端渲染的视图中。我们将专注于为在`'/media/:mediaId'`路径返回的`PlayMedia`组件实现服务器端渲染并注入数据。这里概述的一般步骤可以用于为其他视图实现带有数据的 SSR。

# 路由配置

为了在服务器上渲染 React 视图时加载数据，我们将使用 React Router Config npm 模块，该模块为 React Router 提供了静态路由配置助手：

```jsx
npm install react-router-config --save
```

我们将创建一个路由配置文件，用于在服务器上匹配路由和传入的请求 URL，以检查在服务器返回渲染标记之前是否必须注入数据。

在 MERN Mediastream 中的路由配置中，我们只会列出渲染`PlayMedia`组件的路由。

`mern-mediastream/client/routeConfig.js`：

```jsx
import PlayMedia from './media/PlayMedia' 
import { read } from './media/api-media.js' 
const routes = [
  {
    path: '/media/:mediaId',
    component: PlayMedia,
    loadData: (params) => read(params)
  }
]
export default routes 
```

对于这个路由和组件，我们将指定来自`api-media.js`的`read`获取方法作为加载数据的方法。然后它将用于在服务器生成标记时检索并注入数据到 PlayMedia 视图中。

# 更新 Express 服务器的 SSR 代码

我们将更新`server/express.js`中现有的基本服务器端渲染代码，以添加用于在服务器端呈现的 React 视图的数据加载功能。

# 使用路由配置加载数据

我们将定义`loadBranchData`来使用`react-router-config`中的`matchRoutes`，以及路由配置文件中定义的路由，以查找与传入请求 URL 匹配的路由。

`mern-mediastream/server/express.js`：

```jsx
import { matchRoutes } from 'react-router-config' 
import routes from './../client/routeConfig' 
const loadBranchData = (location) => {
  const branch = matchRoutes(routes, location) 
  const promises = branch.map(({ route, match }) => {
    return route.loadData
      ? route.loadData(branch[0].match.params)
      : Promise.resolve(null)
  })
  return Promise.all(promises)
}
```

如果找到匹配的路由，则将执行任何相关的`loadData`方法，以返回包含获取的数据的`Promise`，或者如果没有`loadData`方法，则返回`null`。

在这里定义的`loadBranchData`需要在服务器接收到请求时调用，因此如果找到任何匹配的路由，我们可以获取相关数据并在服务器端渲染时将其注入到 React 组件中。

# 同构抓取

我们还将在`express.js`中导入同构抓取，以便可以在服务器上使用`read`抓取方法，或者我们为客户端定义的任何其他抓取。

`mern-mediastream/server/express.js`：

```jsx
import 'isomorphic-fetch'
```

# 绝对 URL

使用`同构抓取`的一个问题是它当前要求抓取 URL 是绝对的。因此，我们需要将在`api-media.js`中定义的`read`抓取方法中使用的 URL 更新为绝对 URL。

我们将在`config.js`中设置一个`config`变量，而不是在代码中硬编码服务器地址。

`mern-mediastream/config/config.js`：

```jsx
serverUrl: process.env.serverUrl || 'http://localhost:3000'
```

然后，我们将更新`api-media.js`中的`read`方法，使其使用绝对 URL 来调用服务器上的读取 API。

`mern-mediastream/client/media/api-media.js`：

```jsx
import config from '../../config/config'
const read = (params) => {
  return fetch(config.serverUrl +'/api/media/' + params.mediaId, {
    method: 'GET'
  }).then((response) => { ... })
```

这将使`read`抓取调用与`同构抓取`兼容，因此在服务器上可以无问题地使用它。

# 将数据注入到 React 应用程序中

在后端现有的服务器端渲染代码中，我们使用`ReactDOMServer`将 React 应用程序转换为标记。我们将在`express.js`中更新此代码，以在使用`loadBranchData`方法获取数据后将数据作为属性注入到`MainRouter`中。

`mern-mediastream/server/express.js`：

```jsx
...
loadBranchData(req.url).then(data => {
    const markup = ReactDOMServer.renderToString(
      <StaticRouter location={req.url} context={context}>
        <JssProvider registry={sheetsRegistry}
      generateClassName={generateClassName}>
      <MuiThemeProvider theme={theme} sheetsManager={new Map()}>
        < MainRouter data={data}/>
      </MuiThemeProvider>
    </JssProvider>
      </StaticRouter>
    ) 
...
}).catch(err => {
 res.status(500).send("Data could not load") 
 }) 
...

```

为了在服务器生成标记时将这些数据添加到渲染的`PlayMedia`组件中，我们需要更新客户端代码以考虑服务器注入的数据。

# 在客户端代码中应用服务器注入的数据

在客户端，我们将访问从服务器传递的数据，并将其添加到 PlayMedia 视图中。

# 从 MainRouter 向 PlayMedia 传递数据属性

在使用`ReactDOMServer.renderToString`生成标记时，我们将预加载的数据传递给`MainRouter`作为属性。我们可以在`MainRouter`的构造函数中访问该数据属性。

`mern-mediastream/client/MainRouter.js`：

```jsx
  constructor({data}) {
    super() 
      this.data = data 
  }
```

为了让`PlayMedia`访问这些数据，我们将更改`PlayMedia`的`Route`组件，以将这些数据作为属性传递。

`mern-mediastream/client/MainRouter.js`：

```jsx
<Route path="/media/:mediaId" 
       render={(props) => (
          <PlayMedia {...props} data={this.data} />
        )} />
```

# 在 PlayMedia 中呈现接收到的数据

在`PlayMedia`组件中，我们将检查从服务器传递的数据并将值设置为状态，以便在视图中呈现媒体详细信息。

`mern-mediastream/client/media/PlayMedia.js`：

```jsx
...
render() {
    if (this.props.data && this.props.data[0] != null) {
      this.state.media = this.props.data[0] 
      this.state.relatedMedia = [] 
    }
...
}
```

这将生成带有媒体数据注入 PlayMedia 视图的服务器生成标记。

# 检查带有数据的 SSR 实现

对于 MERN Mediastream，任何呈现 PlayMedia 的链接现在应该在服务器端生成预加载媒体详情的标记。我们可以通过在关闭 JavaScript 的浏览器中打开应用程序 URL 来验证服务器端渲染数据的实现是否正常工作。我们将研究如何在 Chrome 浏览器中实现这一点，以及结果视图应该向用户和搜索引擎显示什么。

# 在 Chrome 中进行测试

在 Chrome 中测试这个实现只需要更新 Chrome 设置，并在禁用 JS 的标签中加载应用程序。

# 加载启用 JS 的页面

首先，在 Chrome 中打开应用程序，然后浏览到任何媒体链接，并让它以启用 JavaScript 的正常方式呈现。这应该显示已实现的 PlayMedia 视图，其中包括功能齐全的媒体播放器和相关的媒体列表。

# 从设置中禁用 JS

接下来，在 Chrome 上禁用 JavaScript。您可以转到`chrome://settings/content/javascript`的高级设置，并使用切换按钮来阻止 JavaScript：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/7b2d5eb9-1018-48e8-9041-05b34aa960dc.png)

现在，刷新 MERN Mediastream 标签中的媒体链接，地址 URL 旁边将会显示一个图标，表明 JavaScript 确实已禁用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/5d31d57c-a0f6-42de-b110-195cba56852b.png)

# 带有 JS 阻止的 PlayMedia 视图

PlayMedia 视图应该呈现类似于以下图片，只有媒体详情被填充。但是由于 JavaScript 被阻止，用户界面不再具有交互性，只有默认的浏览器控件是可操作的。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/f4559f8f-6d44-4ccd-a87a-6ab9e218e3b1.png)

这是搜索引擎机器人将读取的媒体内容，以及当浏览器未加载 JavaScript 时用户将看到的内容。

MERN Mediastream 现在拥有完全操作的媒体播放工具，这将允许用户轻松浏览和播放视频。此外，显示单个媒体内容的媒体视图现在经过了服务器端渲染预加载数据的优化，以便搜索引擎优化。

# 摘要

在本章中，我们通过使用`ReactPlayer`提供的选项，完全升级了 MERN Mediastream 上的播放媒体页面，实现了自定义媒体播放器控件，使相关媒体从数据库中检索后，能够启用自动播放功能，并且在服务器渲染视图时，通过从服务器注入数据，使媒体详细信息对搜索引擎可读。

既然我们已经探索了 MERN 堆栈技术的高级功能，比如流媒体和 SEO，在接下来的章节中，我们将通过将虚拟现实元素融入到 Web 应用程序中，进一步测试这个堆栈的潜力。
