# React 全栈项目（三）

> 原文：[`zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB`](https://zh.annas-archive.org/md5/05F04F9004AE49378ED0525C32CB85EB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：通过在线市场锻炼新的 MERN 技能

随着越来越多的企业继续转向网络，能够在在线市场环境中进行买卖已经成为许多网络平台的核心要求。在本章和下一章中，我们将利用 MERN 堆栈技术开发一个在线市场应用程序，其中包括使用户能够买卖的功能。

在本章中，我们将通过扩展 MERN 骨架来构建在线市场，添加以下功能：

+   具有卖家账户的用户

+   商店管理

+   产品管理

+   按名称和类别搜索产品

# MERN Marketplace

MERN Marketplace 应用程序将允许用户成为卖家，他们可以管理多个商店，并在每个商店中添加他们想要出售的产品。访问 MERN Marketplace 的用户将能够搜索和浏览他们想要购买的产品，并将产品添加到购物车中以下订单：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/3a5e153a-60bd-4cba-8f79-523426175c96.png)完整的 MERN Marketplace 应用程序的代码可在 GitHub 上找到：[github.com/shamahoque/mern-marketplace](https://github.com/shamahoque/mern-marketplace)。本章讨论的实现可以在存储库的 seller-shops-products 分支中访问。您可以在阅读本章其余部分的代码解释时，克隆此代码并运行应用程序。

与卖家账户、商店和产品相关的功能所需的视图将通过扩展和修改 MERN 骨架应用程序中的现有 React 组件来开发。下图显示的组件树展示了本章中开发的 MERN Marketplace 前端中的所有自定义 React 组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/80051e3f-cad6-4cc1-b7ff-457b701d9998.jpg)

# 用户作为卖家

在 MERN Marketplace 注册的任何用户都可以选择通过更新其个人资料成为卖家：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/59234305-80cf-4846-9bf4-def391fdfd9b.png)

与成为普通用户相比，成为卖家将允许用户创建和管理自己的商店，他们可以在其中管理产品：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/5c7b9488-dd1a-474d-977f-75f6a80fa956.png)

为了添加这个卖家功能，我们需要更新用户模型、编辑个人资料视图，并在菜单中添加一个“我的商店”链接，只有卖家才能看到。

# 更新用户模型

用户模型将需要一个卖家值，默认情况下将其设置为`false`以表示普通用户，并且可以将其设置为`true`以表示也是卖家的用户。

`mern-marketplace/server/models/user.model.js`:

```jsx
seller: {
    type: Boolean,
    default: false
}
```

卖家值必须与成功登录时收到的用户详细信息一起发送到客户端，以便视图可以相应地呈现与卖家相关的信息。

# 更新编辑个人资料视图

已登录用户将在编辑个人资料视图中看到一个切换按钮，用于激活或停用卖家功能。我们将更新`EditProfile`组件，在`FormControlLabel`中添加`Material-UI`的`Switch`组件。

`mern-marketplace/client/user/EditProfile.js`:

```jsx
<Typography type="subheading" component="h4" className={classes.subheading}>
    Seller Account
</Typography>
<FormControlLabel
    control = { <Switch classes={{ checked: classes.checked, bar: classes.bar}}
                  checked={this.state.seller}
                  onChange={this.handleCheck}
                /> }
    label={this.state.seller? 'Active' : 'Inactive'}
/>
```

通过调用`handleCheck`方法，对切换进行的任何更改都将设置为状态中`seller`的值。

`mern-marketplace/client/user/EditProfile.js`:

```jsx
handleCheck = (event, checked) => {
    this.setState({'seller': checked})
} 
```

提交时，`seller`值将被添加到发送到服务器的详细信息中。

`mern-marketplace/client/user/EditProfile.js`:

```jsx
clickSubmit = () => {
    const jwt = auth.isAuthenticated() 
    const user = {
      name: this.state.name || undefined,
      email: this.state.email || undefined,
      password: this.state.password || undefined,
      seller: this.state.seller
    }
    update({
      userId: this.match.params.userId
    }, {
      t: jwt.token
    }, user).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        auth.updateUser(data, ()=> {
 this.setState({'userId':data._id,'redirectToProfile':true})
 })
      }
    })
  }
```

成功更新后，存储在`sessionStorage`中的用户详细信息也应该更新。调用`auth.updateUser`方法来进行`sessionStorage`的更新。它与其他`auth-helper.js`方法一起定义，并传递更新后的用户数据和一个更新视图的回调函数作为参数。

`mern-marketplace/client/auth/auth-helper.js`:

```jsx
updateUser(user, cb) {
  if(typeof window !== "undefined"){
    if(sessionStorage.getItem('jwt')){
       let auth = JSON.parse(sessionStorage.getItem('jwt'))
       auth.user = user
       sessionStorage.setItem('jwt', JSON.stringify(auth))
       cb()
     }
  }
}
```

# 更新菜单

在导航栏中，为了有条件地显示一个链接到*我的商店*，该链接只对已登录的也是卖家的用户可见，我们将更新`Menu`组件，如下所示，在先前的代码中只有在用户登录时才会呈现。

`mern-marketplace/client/core/Menu.js`:

```jsx
{auth.isAuthenticated().user.seller && 
  (<Link to="/seller/shops">
  <Button color = {isPartActive(history, "/seller/")}> My Shops </Button>
   </Link>)
}
```

# 市场中的商店

MERN Marketplace 上的卖家可以创建商店，并向每个商店添加产品。为了存储商店数据并启用商店管理，我们将实现一个用于商店的 Mongoose 模式，用于访问和修改商店数据的后端 API，以及用于商店所有者和买家浏览市场的前端视图。

# 商店模型

在`server/models/shop.model.js`中定义的商店模式将具有简单的字段来存储商店详细信息，以及一个标志图像和拥有该商店的用户的引用。

+   **商店名称和描述**：名称和描述字段将是字符串类型，其中`name`是一个必填字段：

```jsx
name: { 
    type: String, 
    trim: true, 
    required: 'Name is required' 
},
description: { 
    type: String, 
    trim: true 
},
```

+   **商店标志图像**：`image`字段将存储用户上传的标志图像文件，作为 MongoDB 数据库中的数据：

```jsx
image: { 
    data: Buffer, 
    contentType: String 
},
```

+   **商店所有者**：所有者字段将引用创建商店的用户：

```jsx
owner: {
    type: mongoose.Schema.ObjectId, 
    ref: 'User'
}
```

+   **创建和更新时间**：`created`和`updated`字段将是`Date`类型，`created`在添加新商店时生成，`updated`在修改任何商店详情时更改。

```jsx
updated: Date,
created: { 
    type: Date, 
    default: Date.now 
},
```

此模式定义中的字段将使我们能够在 MERN Marketplace 中实现所有与商店相关的功能。

# 创建新商店

在 MERN Marketplace 中，已登录并且也是卖家的用户将能够创建新的商店。

# 创建商店 API

在后端，我们将添加一个 POST 路由，验证当前用户是否为卖家，并使用请求中传递的商店数据创建一个新的商店。

`mern-marketplace/server/routes/shop.routes.js`：

```jsx
router.route('/api/shops/by/:userId')
    .post(authCtrl.requireSignin,authCtrl.hasAuthorization, 
           userCtrl.isSeller, shopCtrl.create)
```

`shop.routes.js`文件将与`user.routes`文件非常相似，为了在 Express 应用程序中加载这些新路由，我们需要在`express.js`中挂载商店路由，就像我们为 auth 和 user 路由所做的那样。

`mern-marketplace/server/express.js`：

```jsx
app.use('/', shopRoutes)
```

我们将更新用户控制器以添加`isSeller`方法，这将确保当前用户实际上是卖家，然后才创建新的商店。

`mern-marketplace/server/controllers/user.controller.js`：

```jsx
const isSeller = (req, res, next) => {
  const isSeller = req.profile && req.profile.seller
  if (!isSeller) {
    return res.status('403').json({
      error: "User is not a seller"
    })
  }
  next()
}
```

商店控制器中的`create`方法使用`formidable` npm 模块来解析可能包含用户上传的商店标志图片文件的多部分请求。如果有文件，`formidable`将在文件系统中临时存储它，然后我们将使用`fs`模块来读取它，以检索文件类型和数据，以将其存储到商店文档中的`image`字段中。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const create = (req, res, next) => {
  let form = new formidable.IncomingForm()
  form.keepExtensions = true
  form.parse(req, (err, fields, files) => {
    if (err) {
      res.status(400).json({
        message: "Image could not be uploaded"
      })
    }
    let shop = new Shop(fields)
    shop.owner= req.profile
    if(files.image){
      shop.image.data = fs.readFileSync(files.image.path)
      shop.image.contentType = files.image.type
    }
    shop.save((err, result) => {
      if (err) {
        return res.status(400).json({
          error: errorHandler.getErrorMessage(err)
        })
      }
      res.status(200).json(result)
    })
  })
}
```

商店的标志图片文件由用户上传，并以数据形式存储在 MongoDB 中。然后，为了在视图中显示，它将作为一个单独的 GET API 从数据库中检索为图像文件。GET API 设置为 Express 路由在`/api/shops/logo/:shopId`，它从 MongoDB 获取图像数据，并将其作为文件发送到响应中。文件上传、存储和检索的实现步骤在第五章的*上传个人资料照片*部分中有详细说明，*从简单的社交媒体应用开始*。

# 在视图中获取创建 API

在前端，为了使用这个创建 API，我们将在`client/shop/api-shop.js`中设置一个`fetch`方法，通过传递多部分表单数据向创建 API 发出 POST 请求：

```jsx
const create = (params, credentials, shop) => {
  return fetch('/api/shops/by/'+ params.userId, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + credentials.t
      },
      body: shop
    })
    .then((response) => {
      return response.json()
    }).catch((err) => console.log(err))
}
```

# NewShop 组件

在`NewShop`组件中，我们将呈现一个表单，允许卖家输入名称和描述，并从其本地文件系统上传商店的标志图像文件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/df926141-6696-4db6-ac6e-40059ccba860.png)

我们将使用 Material-UI 按钮和 HTML5 文件输入元素添加文件上传元素。

`mern-marketplace/client/shop/NewShop.js`：

```jsx
<input accept="image/*" onChange={this.handleChange('image')} 
       style={display:'none'} id="icon-button-file" type="file" />
<label htmlFor="icon-button-file">
   <Button raised color="secondary" component="span">
      Upload Logo <FileUpload/>
   </Button>
</label> 
<span> {this.state.image ? this.state.image.name : ''} </span>
```

名称和描述表单字段将使用`TextField`组件添加。

`mern-marketplace/client/shop/NewShop.js`：

```jsx
<TextField 
    id="name" 
    label="Name" 
    value={this.state.name} 
    onChange={this.handleChange('name')}/> <br/>
<TextField 
    id="multiline-flexible" 
    label="Description"
    multiline rows="2" 
    value={this.state.description}
    onChange={this.handleChange('description')}/>
```

这些表单字段的更改将通过`handleChange`方法进行跟踪。

`mern-marketplace/client/shop/NewShop.js`：

```jsx
handleChange = name => event => {
    const value = name === 'image'
      ? event.target.files[0]
      : event.target.value
    this.shopData.set(name, value)
    this.setState({ [name]: value })
}
```

`handleChange`方法更新状态并填充`shopData`，这是一个`FormData`对象，确保数据以`multipart/form-data`编码类型存储在正确的格式中。`shopData`对象在`componentDidMount`中初始化。

`mern-marketplace/client/shop/NewShop.js`：

```jsx
componentDidMount = () => {
  this.shopData = new FormData()
}
```

在表单提交时，`clickSubmit`函数中将调用`create` fetch 方法。

`mern-marketplace/client/shop/NewShop.js`：

```jsx
  clickSubmit = () => {
    const jwt = auth.isAuthenticated()
    create({
      userId: jwt.user._id
    }, {
      t: jwt.token
    }, this.shopData).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({error: '', redirect: true})
      }
    })
 }
```

在成功创建商店后，用户将被重定向回`MyShops`视图。

`mern-marketplace/client/shop/NewShop.js`：

```jsx
if (this.state.redirect) {
      return (<Redirect to={'/seller/shops'}/>)
}
```

`NewShop`组件只能由已登录的卖家用户查看。因此，我们将在`MainRouter`组件中添加一个`PrivateRoute`，该组件将仅在`/seller/shop/new`路径上为经过授权的用户呈现此表单。

`mern-marketplace/client/MainRouter.js`：

```jsx
<PrivateRoute path="/seller/shop/new" component={NewShop}/>
```

此链接可以添加到卖家可能访问的任何视图组件中。

# 列出商店

在 MERN Marketplace 中，普通用户将能够浏览平台上所有商店的列表，商店所有者将管理他们自己商店的列表。

# 列出所有商店

所有商店的列表将从后端获取并显示给最终用户。

# 商店列表 API

在后端，当服务器在`'/api/shops'`路径接收到 GET 请求时，我们将在`server/routes/shop.routes.js`中添加一个路由来检索数据库中存储的所有商店：

```jsx
router.route('/api/shops')
    .get(shopCtrl.list)
```

`shop.controller.js`中的`list`控制器方法将查询数据库中的商店集合，以返回所有商店。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const list = (req, res) => {
  Shop.find((err, shops) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(shops)
  })
}
```

# 获取视图的所有商店

在前端，为了使用此列表 API 获取商店，我们将在`client/shop/api-shop.js`中设置一个`fetch`方法：

```jsx
const list = () => {
  return fetch('/api/shops', {
    method: 'GET',
  }).then(response => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

# 商店组件

在“商店”组件中，我们将在 Material-UI`List`中呈现商店列表，在组件挂载时获取数据并将数据设置为状态：

！[](assets/c67be761-9fe9-4ad4-bd31-e1f4418fb682.png)

在`componentDidMount`中调用`loadShops`方法以在组件挂载时加载商店。

`mern-marketplace/client/shop/Shops.js`：

```jsx
componentDidMount = () => {
    this.loadShops()
}
```

它使用`list`fetch 方法来检索商店列表并将数据设置为状态。

`mern-marketplace/client/shop/Shops.js`：

```jsx
loadShops = () => {
    list().then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        this.setState({shops: data})
      }
    })
 }
```

在“商店”组件中，使用`map`迭代检索到的商店数组，每个商店的数据在视图中以 Material-UI`ListItem`的形式呈现，每个`ListItem`也链接到单独的商店视图。

`mern-marketplace/client/shop/Shops.js`：

```jsx
{this.state.shops.map((shop, i) => {
  return <Link to={"/shops/"+shop._id} key={i}>
          <Divider/>
          <ListItem button>
            <ListItemAvatar>
            <Avatar src={'/api/shops/logo/'+shop._id+"?" + new 
            Date().getTime()}/>
            </ListItemAvatar>
            <div>
              <Typography type="headline" component="h2" 
             color="primary">
                {shop.name}
              </Typography>
              <Typography type="subheading" component="h4">
                {shop.description}
              </Typography>
            </div>
           </ListItem><Divider/>
         </Link>})}
```

“商店”组件将由最终用户在`/shops/all`访问，使用 React Router 设置并在`MainRouter.js`中声明。

`mern-marketplace/client/MainRouter.js`：

```jsx
 <Route path="/shops/all" component={Shops}/>
```

# 按所有者列出商店

经授权的卖家将看到他们创建的商店列表，他们可以通过编辑或删除列表上的任何商店来管理。

# 按所有者查询商店 API

我们将在后端声明的商店路由中添加一个 GET 路由，以检索特定用户拥有的商店。

`mern-marketplace/server/routes/shop.routes.js`：

```jsx
router.route('/api/shops/by/:userId')
    .get(authCtrl.requireSignin, authCtrl.hasAuthorization, shopCtrl.listByOwner)
```

为了处理`:userId`参数并从数据库中检索关联的用户，我们将在用户控制器中利用`userByID`方法。我们将在`shop.routes.js`的`Shop`路由中添加以下内容，以便用户作为`profile`在`request`对象中可用。

`mern-marketplace/server/routes/shop.routes.js`：

```jsx
router.param('userId', userCtrl.userByID) 
```

`shop.controller.js`中的`listByOwner`控制器方法将查询数据库中的`Shop`集合以获取匹配的商店。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const listByOwner = (req, res) => {
  Shop.find({owner: req.profile._id}, (err, shops) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(shops)
  }).populate('owner', '_id name')
}
```

在对商店集合的查询中，我们找到所有`owner`字段与使用`userId`参数指定的用户匹配的商店。

# 获取用户拥有的所有商店以供查看

在前端，为了使用此按所有者列表 API 获取特定用户的商店，我们将在`client/shop/api-shop.js`中添加一个 fetch 方法：

```jsx
const listByOwner = (params, credentials) => {
  return fetch('/api/shops/by/'+params.userId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# MyShops 组件

`MyShops`组件类似于`Shops`组件，它在`componentDIdMount`中获取当前用户拥有的商店列表，并在`ListItem`中呈现每个商店：

！[](assets/616c4231-1720-4919-beac-fe405b705498.png)

此外，每个商店都有“编辑”和“删除”选项，而不像“商店”中的物品列表。

`mern-marketplace/client/shop/MyShops.js`：

```jsx
<ListItemSecondaryAction>
   <Link to={"/seller/shop/edit/" + shop._id}>
       <IconButton aria-label="Edit" color="primary">
             <Edit/>
       </IconButton>
   </Link>
   <DeleteShop shop={shop} onRemove={this.removeShop}/>
</ListItemSecondaryAction>
```

`编辑`按钮链接到编辑商店视图。`DeleteShop`组件处理删除操作，并通过调用从`MyShops`传递的`removeShop`方法来更新列表，以更新当前用户的修改后的商店列表状态。

`mern-marketplace/client/shop/MyShops.js`：

```jsx
removeShop = (shop) => {
    const updatedShops = this.state.shops
    const index = updatedShops.indexOf(shop)
    updatedShops.splice(index, 1)
    this.setState({shops: updatedShops})
}
```

`MyShops`组件只能被已登录且也是卖家的用户查看。因此，我们将在`MainRouter`组件中添加一个`PrivateRoute`，仅为授权用户在`/seller/shops`处呈现此组件。

`mern-marketplace/client/MainRouter.js`：

```jsx
<PrivateRoute path="/seller/shops" component={MyShops}/>
```

# 展示一个商店

任何浏览 MERN Marketplace 的用户都可以浏览每个单独的商店。

# 读取商店 API

在后端，我们将添加一个`GET`路由，用 ID 查询`Shop`集合并在响应中返回商店。

`mern-marketplace/server/routes/shop.routes.js`：

```jsx
router.route('/api/shop/:shopId')
    .get(shopCtrl.read)
router.param('shopId', shopCtrl.shopByID)
```

路由 URL 中的`:shopId`参数将调用`shopByID`控制器方法，类似于`userByID`控制器方法，从数据库中检索商店，并将其附加到请求对象中，以便在`next`方法中使用。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const shopByID = (req, res, next, id) => {
  Shop.findById(id).populate('owner', '_id name').exec((err, shop) => {
    if (err || !shop)
      return res.status('400').json({
        error: "Shop not found"
      })
    req.shop = shop
    next()
  })
}
```

然后`read`控制器方法将这个`shop`对象返回给客户端的响应中。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const read = (req, res) => {
  return res.json(req.shop)
}
```

# 在视图中获取商店

在`api-shop.js`中，我们将添加一个`fetch`方法来在前端使用这个读取 API。

`mern-marketplace/client/shop/api-shop.js`：

```jsx
const read = (params, credentials) => {
  return fetch('/api/shop/' + params.shopId, {
    method: 'GET'
  }).then((response) => {
    return response.json()
  }).catch((err)  => console.log(err) )
}
```

# 商店组件

`Shop`组件将呈现商店的详细信息，还使用产品列表组件呈现指定商店的产品列表，这将在*产品*部分讨论：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/ea0dcb6f-6c84-49b8-b545-6f7fb64e2d01.png)

`Shop`组件可以在浏览器中通过`/shops/:shopId`路由访问，该路由在`MainRouter`中定义如下。

`mern-marketplace/client/MainRouter.js`：

```jsx
<Route path="/shops/:shopId" component={Shop}/>
```

在`componentDidMount`中，使用`api-shop.js`中的`read`方法获取商店详情。

`mern-marketplace/client/shop/Shop.js`：

```jsx
componentDidMount = () => {
    read({
      shopId: this.match.params.shopId
    }).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({shop: data})
      }
    })
}
```

检索到的商店数据被设置为状态，并在视图中呈现以显示商店的名称、logo 和描述。

`mern-marketplace/client/shop/Shop.js`：

```jsx
<CardContent>
   <Typography type="headline" component="h2">
       {this.state.shop.name}
   </Typography><br/>
   <Avatar src={logoUrl}/><br/>
   <Typography type="subheading" component="h2">
       {this.state.shop.description}
   </Typography><br/>
</CardContent>
```

如果存在，`logoUrl`指向从数据库中检索 logo 图像的路由，并定义如下。

`mern-marketplace/client/shop/Shop.js`：

```jsx
const logoUrl = this.state.shop._id
 ? `/api/shops/logo/${this.state.shop._id}?${new Date().getTime()}`
 : '/api/shops/defaultphoto'
```

# 编辑一个商店

授权卖家也可以编辑他们拥有的商店的详细信息。

# 编辑商店 API

在后端，我们将添加一个`PUT`路由，允许授权的卖家编辑他们的商店之一。

`mern-marketplace/server/routes/shop.routes.js`：

```jsx
router.route('/api/shops/:shopId')
    .put(authCtrl.requireSignin, shopCtrl.isOwner, shopCtrl.update)
```

`isOwner`控制器方法确保已登录的用户实际上是正在编辑的商店的所有者。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const isOwner = (req, res, next) => {
  const isOwner = req.shop && req.auth && req.shop.owner._id == 
   req.auth._id
  if(!isOwner){
    return res.status('403').json({
      error: "User is not authorized"
    })
  }
  next()
}
```

`update`控制器方法将使用`formidable`和`fs`模块，如前面讨论的`create`控制器方法一样，解析表单数据并更新数据库中的现有商店。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const update = (req, res, next) => {
  let form = new formidable.IncomingForm()
  form.keepExtensions = true
  form.parse(req, (err, fields, files) => {
    if (err) {
      res.status(400).json({
        message: "Photo could not be uploaded"
      })
    }
    let shop = req.shop
    shop = _.extend(shop, fields)
    shop.updated = Date.now()
    if(files.image){
      shop.image.data = fs.readFileSync(files.image.path)
      shop.image.contentType = files.image.type
    }
    shop.save((err) => {
      if (err) {
        return res.status(400).send({
          error: errorHandler.getErrorMessage(err)
        })
      }
      res.json(shop)
    })
  })
}
```

# 在视图中获取编辑 API

在视图中使用`fetch`方法调用编辑 API，该方法获取表单数据并将多部分请求发送到后端。

`mern-marketplace/client/shop/api-shop.js`：

```jsx
const update = (params, credentials, shop) => {
  return fetch('/api/shops/' + params.shopId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: shop
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# EditShop 组件

`EditShop`组件将显示一个类似于创建新商店表单的表单，预先填充现有商店的详细信息。该组件还将显示该商店中的产品列表，将在*产品*部分中讨论：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/7d0e26cb-2b0f-4f2f-8ba5-21e567bf8905.png)

表单部分类似于`NewShop`组件中的表单，具有相同的表单字段和一个`formData`对象，该对象保存了与`update` fetch 方法一起发送的多部分表单数据。

`EditShop`组件只能被授权的商店所有者访问。因此，我们将在`MainRouter`组件中添加一个`PrivateRoute`，该组件将仅为`/seller/shop/edit/:shopId`上的授权用户呈现此组件。

`mern-marketplace/client/MainRouter.js`：

```jsx
<PrivateRoute path="/seller/shop/edit/:shopId" component={EditShop}/>
```

这个链接是在`MyShops`组件中为每个商店添加的编辑图标。

# 删除商店

授权的卖家可以从`MyShops`列表中删除他们自己的任何商店。

# 删除商店 API

在后端，我们将添加一个`DELETE`路由，允许授权的卖家删除他们自己的商店之一。

`mern-marketplace/server/routes/shop.routes.js`：

```jsx
router.route('/api/shops/:shopId')
    .delete(authCtrl.requireSignin, shopCtrl.isOwner, shopCtrl.remove)
```

`remove`控制器方法从数据库中删除指定的商店，如果`isOwner`确认已登录的用户是商店的所有者。

`mern-marketplace/server/controllers/shop.controller.js`：

```jsx
const remove = (req, res, next) => {
  let shop = req.shop
  shop.remove((err, deletedShop) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
```

```jsx
      })
    }
    res.json(deletedShop)
  })
}
```

# 在视图中获取删除 API

我们将在前端添加一个相应的方法，向删除 API 发出删除请求。

`mern-marketplace/client/shop/api-shop.js`：

```jsx
const remove = (params, credentials) => {
  return fetch('/api/shops/' + params.shopId, {
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

# DeleteShop 组件

`DeleteShop`组件添加到`MyShops`组件中，用于列表中的每个商店。它从`MyShops`中获取`shop`对象和`onRemove`方法作为 props：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/9dc19d06-d474-4b66-bbaa-070dd8d16b12.png)

该组件基本上是一个图标按钮，点击后会打开一个确认对话框，询问用户是否确定要删除他们的商店。

`mern-marketplace/client/shop/DeleteShop.js`：

```jsx
<IconButton aria-label="Delete" onClick={this.clickButton} color="secondary">
   <DeleteIcon/>
</IconButton>
<Dialog open={this.state.open} onRequestClose={this.handleRequestClose}>
   <DialogTitle>{"Delete "+this.props.shop.name}</DialogTitle>
      <DialogContent>
         <DialogContentText>
            Confirm to delete your shop {this.props.shop.name}.
         </DialogContentText>
      </DialogContent>
      <DialogActions>
         <Button onClick={this.handleRequestClose} color="primary">
            Cancel
         </Button>
         <Button onClick={this.deleteShop} color="secondary" 
          autoFocus="autoFocus">
            Confirm
         </Button>
      </DialogActions>
</Dialog>
```

在对话框中用户确认删除后，将调用`deleteShop`中的`delete`获取方法。

`mern-marketplace/client/shop/DeleteShop.js`：

```jsx
  deleteShop = () => {
    const jwt = auth.isAuthenticated()
    remove({
      shopId: this.props.shop._id
    }, {t: jwt.token}).then((data) => {
      if (data.error) {
        console.log(data.error)
      } else {
        this.setState({open: false}, () => {
          this.props.onRemove(this.props.shop)
        })
      }
    })
 }
```

成功删除后，对话框将关闭，并通过调用`onRemove`属性更新`MyShops`中的商店列表，该属性从`MyShops`中作为属性传递的`removeShop`方法获取。

这些商店视图将允许买家和卖家与商店互动。商店还将拥有产品，接下来将讨论，业主将管理这些产品，买家将通过浏览并选择添加到购物车的选项。

# 产品

产品是市场应用程序中最关键的方面。在 MERN Marketplace 中，卖家可以管理他们商店中的产品，访问者可以搜索和浏览产品。

# 产品模型

产品将存储在数据库中的产品集合中，使用 Mongoose 定义的模式。对于 MERN Marketplace，我们将保持产品模式简单，支持诸如产品名称、描述、图像、类别、数量、价格、创建时间、更新时间以及对商店的引用等字段。

+   **产品名称和描述**：`name`和`description`字段将是`String`类型，`name`为`required`字段：

```jsx
name: { 
    type: String, 
    trim: true, 
    required: 'Name is required' 
},
description: { 
    type: String, 
    trim: true 
},
```

+   **产品图片**：`image`字段将存储用户上传的图像文件作为 MongoDB 数据库中的数据：

```jsx
image: { 
    data: Buffer, 
    contentType: String 
},
```

+   **产品类别**：`category`值将允许将相同类型的产品分组在一起：

```jsx
category: { 
    type: String 
},
```

+   **产品数量**：`quantity`字段将表示商店中可供销售的数量：

```jsx
quantity: { 
    type: Number, 
    required: "Quantity is required" 
},
```

+   **产品价格**：`price`字段将保存该产品的单价：

```jsx
price: { 
    type: Number, 
    required: "Price is required" 
},
```

+   **产品商店**：`shop`字段将引用产品所添加的商店：

```jsx
shop: {
    type: mongoose.Schema.ObjectId, 
    ref: 'Shop'
}
```

+   **创建和更新时间**：`created`和`updated`字段将是`Date`类型，`created`在添加新产品时生成，当修改同一产品的详细信息时，`updated`时间会改变。

```jsx
updated: Date,
created: { 
    type: Date, 
    default: Date.now 
},
```

这个模式定义中的字段将使我们能够在 MERN Marketplace 中实现所有与产品相关的功能。

# 创建新产品

在 MERN Marketplace 中，卖家将能够向他们拥有的商店和平台上创建的商店添加新产品。

# 创建产品 API

在后端，我们将在`/api/products/by/:shopId`添加一个路由，接受包含产品数据的`POST`请求，以创建一个与`:shopId`参数标识的商店相关联的新产品。处理这个请求的代码将首先检查当前用户是否是将要添加新产品的商店的所有者，然后在数据库中创建新产品。

这个创建产品 API 路由在`product.routes.js`文件中声明，并利用了商店控制器中的`shopByID`和`isOwner`方法来处理`:shopId`参数，并验证当前用户是否为商店所有者。

`mern-marketplace/server/routes/product.routes.js`:

```jsx
router.route('/api/products/by/:shopId')
  .post(authCtrl.requireSignin, 
            shopCtrl.isOwner, 
                productCtrl.create)
router.param('shopId', shopCtrl.shopByID)
```

`product.routes.js`文件将与`shop.routes.js`文件非常相似，为了在 Express 应用程序中加载这些新路由，我们需要像为商店路由一样，在`express.js`中挂载产品路由。

在前端，为了使用这个创建 API，我们将在`client/product/api-product.js`中设置一个`fetch`方法，通过传递视图中的多部分表单数据，向创建 API 发起 POST 请求。

```jsx
app.use('/', productRoutes)
```

在产品控制器中，`create`方法使用`formidable` npm 模块来解析可能包含用户上传的图像文件和产品字段的多部分请求。然后将解析的数据保存到`Product`集合中作为新产品。

`mern-marketplace/server/controllers/product.controller.js`:

```jsx
const create = (req, res, next) => {
  let form = new formidable.IncomingForm()
  form.keepExtensions = true
  form.parse(req, (err, fields, files) => {
    if (err) {
      return res.status(400).json({
        message: "Image could not be uploaded"
      })
    }
    let product = new Product(fields)
    product.shop= req.shop
    if(files.image){
      product.image.data = fs.readFileSync(files.image.path)
      product.image.contentType = files.image.type
    }
    product.save((err, result) => {
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

# 在视图中获取创建 API

NewProduct 组件

在 MERN Marketplace 中，产品将以多种方式呈现给用户，两个主要区别在于产品在卖家列表和买家列表中的呈现方式。

```jsx
const create = (params, credentials, product) => {
  return fetch('/api/products/by/'+ params.shopId, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + credentials.t
      },
      body: product
    })
    .then((response) => {
      return response.json()
    }).catch((err) => console.log(err))
}
```

# ![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/651b5ab8-bc62-48ac-8ff4-c5acdfeb28ea.png)

`NewProduct`组件将类似于`NewShop`组件。它将包含一个表单，允许卖家输入名称、描述、类别、数量和价格，并从本地文件系统上传产品图像文件。

列出产品

这个`NewProduct`组件只会在与特定商店相关联的路由上加载，因此只有已登录的卖家用户才能向他们拥有的商店添加产品。为了定义这个路由，我们在`MainRouter`组件中添加了一个`PrivateRoute`，它只会在`/seller/:shopId/products/new`上为经过授权的用户渲染这个表单。

`mern-marketplace/client/MainRouter.js`:

```jsx
<PrivateRoute path="/seller/:shopId/products/new" component={NewProduct}/>
```

# `mern-marketplace/server/express.js`:

`mern-marketplace/client/product/api-product.js`:

# 按商店列出

市场的访问者将浏览每个店铺中的产品，卖家将管理他们各自店铺中的产品列表。

# 按店铺 API

为了从数据库中检索特定店铺的产品，我们将在`/api/products/by/:shopId`设置一个 GET 路由，如下所示。

`mern-marketplace/server/routes/product.routes.js`:

```jsx
router.route('/api/products/by/:shopId')
    .get(productCtrl.listByShop)
```

对这个请求执行的`listByShop`控制器方法将查询产品集合，返回与给定店铺引用匹配的产品。

`mern-marketplace/server/controllers/product.controller.js`:

```jsx
const listByShop = (req, res) => {
  Product.find({shop: req.shop._id}, (err, products) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(products)
  }).populate('shop', '_id name').select('-image')
}
```

在前端，使用此列表按店铺 API 获取特定店铺的产品，我们将在`api-product.js`中添加一个 fetch 方法。

`mern-marketplace/client/product/api-product.js`:

```jsx
const listByShop = (params) => {
  return fetch('/api/products/by/'+params.shopId, {
    method: 'GET'
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  }) 
}
```

# 买家的产品组件

`Products`组件主要用于向访问者展示可能购买的产品。我们将使用此组件来呈现与买家相关的产品列表。它将从显示产品列表的父组件中作为 props 接收产品列表。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/ac725381-88fc-4ed2-8d4e-73c76d340bf1.png)

店铺中的产品列表将显示给用户在单独的`Shop`视图中。因此，将此`Products`组件添加到`Shop`组件中，并将相关产品列表作为 props 传递。`searched` prop 传递了这个列表是否是产品搜索的结果，因此可以呈现适当的消息。

`mern-marketplace/client/shop/Shop.js`:

```jsx
<Products products={this.state.products} searched={false}/></Card>
```

在`Shop`组件中，我们需要在`componentDidMount`中添加对`listByShop` fetch 方法的调用，以检索相关产品并将其设置为状态。

`mern-marketplace/client/shop/Shop.js`:

```jsx
listByShop({
      shopId: this.match.params.shopId
    }).then((data)=>{
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({products: data})
      }
}) 
```

在`Products`组件中，如果 props 中发送的产品列表包含产品，那么将对列表进行迭代，并在 Material-UI 的`GridListTile`中呈现每个产品的相关细节，同时提供到单个产品视图的链接和一个`AddToCart`组件（其实现在第七章中讨论，*扩展订单和支付的市场*）。

`mern-marketplace/client/product/Products.js`:

```jsx
{this.props.products.length > 0 ?
   (<div><GridList cellHeight={200} cols={3}>
       {this.props.products.map((product, i) => (
          <GridListTile key={i}>
            <Link to={"/product/"+product._id}>
              <img src={'/api/product/image/'+product._id}
           alt= {product.name} />
            </Link>
            <GridListTileBar
              title={<Link to={"/product/"+product._id}>{product.name}
           </Link>}
              subtitle={<span>$ {product.price}</span>}
              actionIcon={<AddToCart item={tile}/>}
             />
          </GridListTile>
       ))}
    </GridList></div>) : this.props.searched && 
      (<Typography type="subheading" component="h4">
                         No products found! :(</Typography>)}
```

这个`Products`组件用于呈现商店中的产品，按类别的产品以及搜索结果中的产品。

# 店主的 MyProducts 组件

与`Products`组件相比，`client/product/MyProducts.js`中的`MyProducts`组件仅用于向卖家展示产品，以便他们可以管理每个店铺中的产品。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/1179071d-86e9-4026-8dac-527e64f4fe67.png)

`MyProducts`组件被添加到`EditShop`视图中，这样卖家就可以在一个地方管理商店及其内容。它通过一个 prop 提供了商店的 ID，以便可以获取相关产品。

`mern-marketplace/client/shop/EditShop.js`:

```jsx
<MyProducts shopId={this.match.params.shopId}/>
```

在`MyProducts`中，相关产品首先在`componentDidMount`中加载。

`mern-marketplace/client/product/MyProducts.js`:

```jsx
componentDidMount = () => {
   this.loadProducts()
}
```

`loadProducts`方法使用相同的`listByShop`获取方法来检索商店中的产品，并将其设置为状态。

`mern-marketplace/client/product/MyProducts.js`:

```jsx
loadProducts = () => {
    listByShop({
      shopId: this.props.shopId
    }).then((data)=>{
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({products: data})
      }
    })
}
```

遍历产品列表，并在`ListItem`中呈现每个产品，同时提供编辑和删除选项，类似于`MyShops`列表视图。编辑按钮链接到编辑产品视图。`DeleteProduct`组件处理删除操作，并通过调用从`MyProducts`传递的`onRemove`方法重新加载列表，以更新当前商店的产品列表状态。

`removeProduct`方法在`MyProducts`中定义，并作为`onRemove`prop 提供给`DeleteProduct`组件。

`mern-marketplace/client/product/MyProducts.js`:

```jsx
**removeProduct** = (product) => {
    const updatedProducts = this.state.products
    const index = updatedProducts.indexOf(product)
    updatedProducts.splice(index, 1)
    this.setState({shops: updatedProducts})
}   
...
<DeleteProduct
       product={product}
       shopId={this.props.shopId}
       **onRemove={this.removeProduct}**/> 
```

# 列出产品建议

访问 MERN Marketplace 的访客将看到产品建议，例如最新添加到市场的产品以及与他们当前查看的产品相关的产品。

# 最新产品

在 MERN Marketplace 的主页上，我们将显示最新添加到市场的五个产品。为了获取最新产品，我们将设置一个 API，该 API 将在`/api/products/latest`接收 GET 请求。

`mern-marketplace/server/routes/product.routes.js`:

```jsx
router.route('/api/products/latest')
      .get(productCtrl.listLatest)
```

`listLatest`控制器方法将对数据库中的产品列表按照`created`日期从新到旧进行排序，并在响应中返回排序后的列表中的前五个产品。

`mern-marketplace/server/controllers/product.controller.js`:

```jsx
const listLatest = (req, res) => {
  Product.find({}).sort('-created').limit(5).populate('shop', '_id   
  name').exec((err, products) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(products)
  })
}
```

在前端，我们将为这个最新的`products`API 设置一个对应的 fetch 方法，类似于检索商店列表的`fetch`。然后将检索到的列表呈现在添加到主页的`Suggestions`组件中。

# 相关产品

在每个单独的产品视图中，我们将显示五个相关产品作为建议。为了检索这些相关产品，我们将设置一个 API，该 API 将在`/api/products/related`接收请求。

`mern-marketplace/server/routes/product.routes.js`:

```jsx
router.route('/api/products/related/:productId')
              .get(productCtrl.listRelated)
router.param('productId', productCtrl.productByID)
```

路由 URL 中的`:productId`参数将调用`productByID`控制器方法，类似于`shopByID`控制器方法，从数据库中检索产品并将其附加到请求对象中，以便在`next`方法中使用。

`mern-marketplace/server/controllers/product.controller.js`：

```jsx
const productByID = (req, res, next, id) => {
  Product.findById(id).populate('shop', '_id name').exec((err, product) => {
    if (err || !product)
      return res.status('400').json({
        error: "Product not found"
      })
    req.product = product
    next()
  })
}
```

`listRelated`控制器方法查询`Product`集合，以查找具有与给定产品相同类别的其他产品，排除给定产品，并返回结果列表中的前五个产品。

`mern-marketplace/server/controllers/product.controller.js`：

```jsx
const listRelated = (req, res) => {
  Product.find({ "_id": { "$ne": req.product }, 
                "category": req.product.category}).limit(5)
         .populate('shop', '_id name')
         .exec((err, products) => {
            if (err) {
              return res.status(400).json({
              error: errorHandler.getErrorMessage(err)
            })
         }
    res.json(products)
  })
}
```

为了在前端利用这个相关产品的 API，我们将在`api-product.js`中设置一个对应的 fetch 方法。这个 fetch 方法将在`Product`组件中被调用，用于填充在产品视图中渲染的`Suggestions`组件。

# 建议组件

`Suggestions`组件将在主页和单个产品页面上呈现，分别显示最新产品和相关产品：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/81546059-ce0f-4787-9d3c-a6c9d41cb1de.png)

它将从父组件作为 props 接收相关的产品列表，以及列表的标题：

```jsx
<Suggestions  products={this.state.suggestions} title={this.state.suggestionTitle}/>
```

在`Suggestions`组件中，接收到的列表被迭代，并渲染出具体的产品细节，一个指向单个产品页面的链接，以及一个`AddToCart`组件。

`mern-marketplace/client/product/Suggestions.js`：

```jsx
<Typography type="title"> {this.props.title} </Typography>
{this.props.products.map((item, i) => { 
  return <span key={i}> 
           <Card>
             <CardMedia image={'/api/product/image/'+item._id} 
                        title={item.name}/>
                <CardContent>
                   <Link to={'/product/'+item._id}>
                     <Typography type="title" component="h3">
                    {item.name}</Typography>
                   </Link>
                   <Link to={'/shops/'+item.shop._id}>
                     <Typography type="subheading">
                        <Icon>shopping_basket</Icon> {item.shop.name}
                     </Typography>
                   </Link>
                   <Typography component="p">
                      Added on {(new 
                     Date(item.created)).toDateString()}
                   </Typography>
                </CardContent>
                <Typography type="subheading" component="h3">$ 
                 {item.price}</Typography>
 <Link to={'/product/'+item._id}>
                  <IconButton color="secondary" dense="dense">
                    <ViewIcon className={classes.iconButton}/>
                  </IconButton>
                </Link>
                <AddToCart item={item}/>
           </Card>
         </span>})}
```

# 显示一个产品

MERN Marketplace 的访客将能够浏览每个产品，显示在单独的视图中的更多细节。

# 阅读产品 API

在后端，我们将添加一个 GET 路由，用于查询带有 ID 的`Product`集合，并在响应中返回产品。

`mern-marketplace/server/routes/product.routes.js`：

```jsx
router.route('/api/products/:productId')
      .get(productCtrl.read) 
```

`：productId`参数调用`productByID`控制器方法，从数据库中检索产品并将其附加到请求对象。请求对象中的产品由`read`控制器方法使用，以响应`read`请求。

`mern-marketplace/server/controllers/product.controller.js`：

```jsx
const read = (req, res) => {
  req.product.image = undefined
  return res.json(req.product)
}
```

在`api-product.js`中，我们将添加一个 fetch 方法来在前端使用这个 read API。

`mern-marketplace/client/product/api-product.js`：

```jsx
const read = (params) => {
  return fetch('/api/products/' + params.productId, {
    method: 'GET'
  }).then((response) => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

# 产品组件

`Product`组件将呈现产品细节，包括加入购物车选项，并显示相关产品列表：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/5ade3fb1-cdb7-40a3-8d9c-75a03b55131d.png)

`Product` 组件可以在浏览器中通过 `/product/:productID` 路由访问，该路由在 `MainRouter` 中定义如下。

`mern-marketplace/client/MainRouter.js`:

```jsx
<Route path="/product/:productId" component={Product}/>
```

当组件挂载时，将获取产品详情和相关列表数据，或者在前端路由路径中的 `productId` 更改后，将接收新的 props，用户点击相关列表中的另一个产品时。

`mern-marketplace/client/product/Product.js`:

```jsx
  componentDidMount = () => {
    this.loadProduct(this.match.params.productId)
  }
  componentWillReceiveProps = (props) => {
    this.loadProduct(props.match.params.productId)
  }
```

`loadProduct` 方法调用 `read` 和 `listRelated` 获取产品和相关列表数据，然后将数据设置到状态中。

`mern-marketplace/client/product/Product.js`:

```jsx
loadProduct = (productId) => {
    read({productId: productId}).then((data) => {
      if (data.error) {
        this.setState({error: data.error})
      } else {
        this.setState({product: data})
        listRelated({
          productId: data._id}).then((data) => {
          if (data.error) {
            console.log(data.error)
          } else {
            this.setState({suggestions: data})
          }
        }) 
      }
    }) 
}
```

组件的产品详情部分显示有关产品的相关信息，以及在 Material-UI `Card` 组件中的 `AddToCart` 组件。

`mern-marketplace/client/product/Product.js`:

```jsx
<Card>
  <CardHeader
 action={<AddToCart cartStyle={classes.addCart} 
    item= {this.state.product}/>}
    title={this.state.product.name}
    subheader={this.state.product.quantity > 0? 'In Stock': 'Out of   
   Stock'}
  />
  <CardMedia image={imageUrl} title={this.state.product.name}/>
  <Typography component="p" type="subheading">
    {this.state.product.description}<br/>
 $ {this.state.product.price}
    <Link to={'/shops/'+this.state.product.shop._id}>
      <Icon>shopping_basket</Icon> {this.state.product.shop.name}
    </Link>
  </Typography>
</Card>
...
<Suggestions  products={this.state.suggestions} title='Related Products'/>
```

`Suggestions` 组件添加到产品视图中，相关列表数据作为 prop 传递。

# 编辑和删除产品

在应用程序中编辑和删除产品的实现与编辑和删除商店类似，如前几节所述。这些功能将需要后端中相应的 API、前端中的 fetch 方法，以及带有表单和操作的 React 组件视图。

# 编辑

编辑功能与创建产品非常相似，`EditProduct` 表单组件也只能由经过验证的卖家在 `/seller/:shopId/:productId/edit` 访问。

`mern-marketplace/client/MainRouter.js`:

```jsx
<PrivateRoute path="/seller/:shopId/:productId/edit" component={EditProduct}/>
```

`EditProduct` 组件包含与 `NewProduct` 相同的表单，使用读取产品 API 检索到的产品的填充值，并使用 fetch 方法将多部分表单数据发送到后端的编辑产品 API，位于 `/api/products/by/:shopId`。

`mern-marketplace/server/routes/product.routes.js`:

```jsx
router.route('/api/product/:shopId/:productId')
      .put(authCtrl.requireSignin, shopCtrl.isOwner, productCtrl.update)
```

`update` 控制器类似于产品 `create` 方法和商店 `update` 方法；它使用 `formidable` 处理多部分表单数据，并扩展产品详情以保存更新。

# 删除

`DeleteProduct` 组件添加到 `MyProducts` 组件中，用于列表中的每个产品，如前面讨论的。它从 `MyProducts` 中获取 `product` 对象、`shopID` 和 `loadProducts` 方法作为 prop。该组件类似于 `DeleteShop`，当用户确认删除意图时，它调用删除的 fetch 方法，向服务器发出 DELETE 请求，位于 `/api/product/:shopId/:productId`。

`mern-marketplace/server/routes/product.routes.js`：

```jsx
router.route('/api/product/:shopId/:productId')
      .delete(authCtrl.requireSignin, shopCtrl.isOwner, productCtrl.remove)
```

# 带类别的产品搜索

在 MERN Marketplace 中，访问者将能够按名称和特定类别搜索特定产品。

# 类别 API

为了让用户选择要搜索的特定类别，我们将设置一个 API，该 API 从数据库中的`Product`集合中检索所有不同的类别。对`/api/products/categories`的 GET 请求将返回一个唯一类别的数组。

`mern-marketplace/server/routes/product.routes.js`：

```jsx
router.route('/api/products/categories')
      .get(productCtrl.listCategories)
```

`listCategories`控制器方法通过对`category`字段进行`distinct`调用来查询`Product`集合。

`mern-marketplace/server/controllers/product.controller.js`：

```jsx
const listCategories = (req, res) => {
  Product.distinct('category',{},(err, products) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(products)
  })
}
```

这个类别 API 可以在前端使用相应的 fetch 方法来检索不同类别的数组，并在视图中显示。

# 搜索产品 API

搜索产品 API 将在`/api/products?search=value&category=value`处接收 GET 请求，URL 中带有查询参数，用于查询`Product`集合中提供的搜索文本和类别值。

`mern-marketplace/server/routes/product.routes.js`：

```jsx
router.route('/api/products')
      .get(productCtrl.list)
```

`list`控制器方法将首先处理请求中的查询参数，然后查找给定类别中的产品（如果有的话），这些产品的名称部分匹配提供的搜索文本。

`mern-marketplace/server/controllers/product.controller.js`：

```jsx
const list = (req, res) => {
  const query = {}
  if(req.query.search)
    query.name = {'$regex': req.query.search, '$options': "i"}
  if(req.query.category && req.query.category != 'All')
    query.category = req.query.category
  Product.find(query, (err, products) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(products)
  }).populate('shop', '_id name').select('-image')
}
```

# 获取视图的搜索结果

为了在前端利用这个搜索 API，我们将设置一个方法来构建带有查询参数的 URL，并调用 API 进行 fetch。

`mern-marketplace/client/product/api-product.js`：

```jsx
import queryString from 'query-string'
const list = (params) => {
  const query = queryString.stringify(params)
  return fetch('/api/products?'+query, {
    method: 'GET',
  }).then(response => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

为了以正确的格式构造查询参数，我们将使用`query-string` npm 模块，它将帮助将参数对象字符串化为可以附加到请求路由的查询字符串。

# 搜索组件

应用类别 API 和搜索 API 的第一个用例是`Search`组件：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c2c169cb-0551-44c2-b0ac-862e033f86ac.png)

搜索组件为用户提供了一个简单的表单，其中包含一个搜索输入文本字段和一个下拉菜单，该下拉菜单包含从父组件接收的类别选项，父组件将使用不同类别的 API 检索列表。

`mern-marketplace/client/product/Search.js`：

```jsx
<TextField id="select-category" select label="Select category" value={this.state.category}
     onChange={this.handleChange('category')}
     SelectProps={{ MenuProps: { className: classes.menu, } }}>
  <MenuItem value="All"> All </MenuItem>
  {this.props.categories.map(option => (
    <MenuItem key={option} value={option}> {option} </MenuItem>
        ))}
</TextField>
<TextField id="search" label="Search products" type="search" onKeyDown={this.enterKey}
     onChange={this.handleChange('search')}
/>
<Button raised onClick={this.search}> Search </Button>
<Products products={this.state.results} searched={this.state.searched}/>

```

一旦用户输入搜索文本并点击*Enter*，就会调用搜索 API 来检索结果。

`mern-marketplace/client/product/Search.js`：

```jsx
search = () => {
    if(this.state.search){
      list({
        search: this.state.search || undefined, category: 
      this.state.category
      }).then((data) => {
        if (data.error) {
          console.log(data.error) 
        } else {
          this.setState({results: data, searched:true}) 
        }
      }) 
    }
  }
```

然后将结果数组作为 props 传递给“产品”组件，以在搜索表单下方呈现匹配的产品。

# 类别组件

“类别”组件是不同类别和搜索 API 的第二个用例。对于这个组件，我们首先在父组件中获取类别列表，并将其作为 props 发送以显示给用户：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/6f0f8fd3-ab5c-4441-8e25-b50c38df2bf8.png)

当用户在显示的列表中选择一个类别时，将使用搜索 API 调用一个类别值，并且后端返回所选类别中的所有产品。然后在“产品”组件中呈现返回的产品。

在 MERN Marketplace 的第一个版本中，用户可以成为卖家创建商店和添加产品，访问者可以浏览商店和搜索产品，同时应用程序还会向访问者推荐产品。

# 总结

在这一章中，我们开始使用 MERN 堆栈构建一个在线市场应用程序。MERN 骨架被扩展以向用户添加卖家角色，这样他们就可以创建商店并向每个商店添加产品，以便向其他用户出售。我们还探讨了如何利用堆栈来实现产品浏览、搜索以及对有兴趣购买的普通用户提出建议等功能。但是，一个市场应用程序如果没有购物车用于结账、订单管理和支付处理就是不完整的。

在下一章中，我们将扩展我们的应用程序以添加这些功能，并了解更多关于如何使用 MERN 堆栈来实现电子商务应用程序的核心方面。


# 第七章：扩展市场以支持订单和付款

处理顾客下订单时的付款，并允许卖家管理这些订单是电子商务应用的关键方面。在本章中，我们将通过引入以下功能来扩展上一章中构建的在线市场：

+   购物车

+   使用 Stripe 进行付款处理

+   订单管理

# 具有购物车、付款和订单的 MERN 市场

在第六章中开发的 MERN 市场应用程序，*通过在线市场锻炼新的 MERN 技能* 将扩展到包括购物车功能、Stripe 集成以处理信用卡付款，以及基本的订单管理流程。以下的实现保持简单，以便作为开发这些功能更复杂版本的起点。

以下的组件树图显示了构成 MERN 市场前端的所有自定义组件。本章讨论的功能修改了一些现有的组件，如`Profile`、`MyShops`、`Products`和`Suggestions`，还添加了新的组件，如`AddToCart`、`MyOrders`、`Cart`和`ShopOrders`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/2c82bf96-7c16-481d-8ab8-4b86c7dc266c.jpg)完整的 MERN 市场应用程序的代码可在 GitHub 上找到[github.com/shamahoque/mern-marketplace](https://github.com/shamahoque/mern-marketplace)。您可以在阅读本章其余部分的代码解释时，克隆此代码并运行应用程序。要使 Stripe 付款的代码工作，您需要创建自己的 Stripe 账户，并在`config/config.js`文件中更新您的测试值，包括 Stripe API 密钥、秘密密钥和 Stripe Connect 客户端 ID。

# 购物车

访问 MERN 市场的访客可以通过点击每个产品上的“加入购物车”按钮将他们想要购买的产品添加到购物车中。菜单中的购物车图标将指示已添加到购物车中的产品数量，当用户继续浏览市场时。他们还可以更新购物车内容，并通过打开购物车视图开始结账。但是，要完成结账并下订单，用户将需要登录。

购物车主要是一个前端功能，因此购物车详情将在客户端本地存储，直到用户在结账时下订单。为了实现购物车功能，我们将在`client/cart/cart-helper.js`中设置辅助方法，以帮助使用相关的 React 组件操纵购物车详情。

# 添加到购物车

`client/Cart/AddToCart.js`中的`AddToCart`组件从父组件中获取`product`对象和 CSS 样式对象作为 props。例如，在 MERN Marketplace 中，它被添加到产品视图中，如下所示：

```jsx
<AddToCart cartStyle={classes.addCart} item={this.state.product}/>
```

`AddToCart`组件本身根据传递的项目是否有库存显示购物车图标按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/068f6b31-5b72-4764-b4e7-3ed9e6e2a194.png)

例如，如果项目数量大于`0`，则显示`AddCartIcon`，否则呈现`DisabledCartIcon`。

`mern-marketplace/client/cart/AddToCart.js`：

```jsx
{this.props.item.quantity >= 0 ? 
    <IconButton color="accent" dense="dense" onClick={this.addToCart}>
      <AddCartIcon className={this.props.cartStyle || 
     classes.iconButton}/>
    </IconButton> : 
    <IconButton disabled={true} color="accent" dense="dense"
      <DisabledCartIcon className={this.props.cartStyle || 
     classes.disabledIconButton}/>
    </IconButton>}
```

当点击`AddCartIcon`按钮时，将调用`addToCart`方法。

`mern-marketplace/client/cart/AddToCart.js`：

```jsx
addToCart = () => {
    cart.addItem(this.props.item, () => {
      this.setState({redirect:true})
    })
}
```

在`cart-helper.js`中定义的`addItem`辅助方法，以`product`项目和更新状态的`callback`函数作为参数，然后将更新后的购物车详情存储在`localStorage`中并执行传递的回调。

`mern-marketplace/client/cart/cart-helper.js`：

```jsx
addItem(item, cb) {
    let cart = []
    if (typeof window !== "undefined") {
      if (localStorage.getItem('cart')) {
        cart = JSON.parse(localStorage.getItem('cart'))
      }
      cart.push({
        product: item,
        quantity: 1,
        shop: item.shop._id
      })
      localStorage.setItem('cart', JSON.stringify(cart))
      cb()
    }
}
```

存储在`localStorage`中的购物车数据包含一个购物车项目对象数组，每个对象包含产品详情，添加到购物车的产品数量（默认为`1`），以及产品所属商店的 ID。

# 菜单上的购物车图标

在菜单中，我们将添加一个链接到购物车视图，并添加一个徽章，显示存储在`localStorage`中的购物车数组的长度，以便直观地通知用户当前购物车中有多少商品：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/6785911f-d5df-4b43-b833-8b329fd4f2d8.png)

购物车的链接将类似于菜单中的其他链接，唯一的区别是 Material-UI 的`Badge`组件显示购物车长度。

`mern-marketplace/client/core/Menu.js`：

```jsx
<Link to="/cart">
    <Button color={isActive(history, "/cart")}>
       Cart
       <Badge color="accent" badgeContent={cart.itemTotal()} >
           <CartIcon />
       </Badge>
    </Button>
</Link>
```

`itemTotal`辅助方法在`cart-helper.js`中返回购物车长度，它读取存储在`localStorage`中的购物车数组并返回数组的长度。

`mern-marketplace/client/cart/cart-helper.js`：

```jsx
itemTotal() {
    if (typeof window !== "undefined") {
      if (localStorage.getItem('cart')) {
        return JSON.parse(localStorage.getItem('cart')).length
      }
    }
    return 0
}
```

# 购物车视图

购物车视图将包含购物车项目和结账详情，但最初只会显示购物车详情，直到用户准备结账。

`mern-marketplace/client/cart/Cart.js`：

```jsx
<Grid container spacing={24}>
      <Grid item xs={6} sm={6}>
            <CartItems checkout={this.state.checkout}
 setCheckout={this.setCheckout}/>
      </Grid>
 {this.state.checkout && 
      <Grid item xs={6} sm={6}>
        <Checkout/>
      </Grid>}
</Grid>
```

`CartItems`组件被传递了一个`checkout`布尔值，以及一个用于更新此结账值的状态更新方法，以便基于用户交互来呈现`Checkout`组件和选项。

`mern-marketplace/client/cart/Cart.js`：

```jsx
setCheckout = val =>{
    this.setState({checkout: val})
}
```

`Cart`组件将在`/cart`路由处访问，因此我们需要在`MainRouter`组件中添加一个`Route`，如下所示。

`mern-marketplace/client/MainRouter.js`：

```jsx
<Route path="/cart" component={Cart}/>
```

# CartItems 组件

`CartItems`组件将允许用户查看和更新其购物车中当前的物品。如果用户已登录，还将为他们提供开始结账流程的选项：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/1a9d8699-72ed-420e-9358-b4a009b4d2b2.png)

如果购物车中包含物品，`CartItems`组件将遍历物品并呈现购物车中的产品。如果没有添加物品，则购物车视图只显示一条消息，说明购物车是空的。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
{this.state.cartItems.length > 0 ? <span>
      {this.state.cartItems.map((item, i) => {
          ...          
            … Product details
              … Edit quantity
              … Remove product option
          ...
        })
      }
     … Show total price and Checkout options … 
    </span> : 
    <Typography type="subheading" component="h3" color="primary">
        No items added to your cart.    
    </Typography>
}
```

每个产品项目显示产品的详细信息和可编辑的数量文本字段，以及删除项目选项。最后，它显示购物车中物品的总价和开始结账的选项。

# 检索购物车详细信息

`cart-helper.js`中的`getCart`辅助方法从`localStorage`中检索并返回购物车详细信息。

`mern-marketplace/client/cart/cart-helper.js`：

```jsx
getCart() {
    if (typeof window !== "undefined") {
      if (localStorage.getItem('cart')) {
        return JSON.parse(localStorage.getItem('cart'))
      }
    }
    return []
}
```

在`CartItems`组件中，我们将使用`componentDidMount`中的`getCart`辅助方法检索购物车项目并将其设置为状态。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
componentDidMount = () => {
    this.setState({cartItems: cart.getCart()})
}
```

然后使用`map`函数迭代从`localStorage`中检索的`cartItems`数组，以呈现每个项目的详细信息。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
<span key={i}>
  <Card>
    <CardMedia image={'/api/product/image/'+item.product._id}
         title={item.product.name}/>
         <CardContent>
                <Link to={'/product/'+item.product._id}>
                    <Typography type="title" component="h3" 
                    color="primary">
                      {item.product.name}</Typography>
                </Link>
                <Typography type="subheading" component="h3" 
               color="primary">
                      $ {item.product.price}
                </Typography>
                <span>${item.product.price * item.quantity}</span>
                <span>Shop: {item.product.shop.name}</span>
         </CardContent>
         <div>
          … Editable quantity …
          … Remove item option ...
         </div>
 </Card>
  <Divider/>
</span> 
```

# 修改数量

为每个购物车项目呈现的可编辑数量`TextField`允许用户更新他们购买的每种产品的数量，并设置最小允许值为`1`。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
Quantity: <TextField
          value={item.quantity}
          onChange={this.handleChange(i)}
          type="number"
          inputProps={{ min:1 }}
          InputLabelProps={{
            shrink: true,
          }}
        />
```

当用户更新此值时，将调用`handleChange`方法来强制执行最小值验证，更新状态中的`cartItems`，并使用辅助方法更新`localStorage`中的购物车。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
handleChange = index => event => {
    let cartItems = this.state.cartItems 
    if(event.target.value == 0){
      cartItems[index].quantity = 1 
    }else{
      cartItems[index].quantity = event.target.value 
    }
    this.setState({cartItems: cartItems}) 
    cart.updateCart(index, event.target.value) 
  } 
```

`updateCart`辅助方法接受要在购物车数组中更新的产品的索引和新的数量值作为参数，并更新`localStorage`中存储的详细信息。

`mern-marketplace/client/cart/cart-helper.js`：

```jsx
updateCart(itemIndex, quantity) {
    let cart = []
    if (typeof window !== "undefined") {
      if (localStorage.getItem('cart')) {
        cart = JSON.parse(localStorage.getItem('cart'))
      }
      cart[itemIndex].quantity = quantity
      localStorage.setItem('cart', JSON.stringify(cart))
    }
}
```

# 删除项目

在购物车中为每个物品呈现的删除选项是一个按钮，当点击时，它将物品的数组索引传递给`removeItem`方法，以便从数组中删除它。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
<Button color="primary" onClick={this.removeItem(i)}>x Remove</Button>
```

`removeItem`点击处理程序方法使用`removeItem`辅助方法从`localStorage`中删除购物车中的物品，然后更新状态中的`cartItems`。该方法还检查购物车是否已清空，因此可以使用从`Cart`组件传递的`setCheckout`函数来隐藏结账。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
removeItem = index => event =>{
    let cartItems = cart.removeItem(index)
    if(cartItems.length == 0){
      this.props.setCheckout(false)
    }
    this.setState({cartItems: cartItems})
}
```

`cart-helper.js`中的`removeItem`辅助方法获取要从数组中删除的产品的索引，然后将其切出，并在返回更新后的`cart`数组之前更新`localStorage`。

`mern-marketplace/client/cart/cart-helper.js`：

```jsx
removeItem(itemIndex) {
    let cart = []
    if (typeof window !== "undefined") {
      if (localStorage.getItem('cart')) {
        cart = JSON.parse(localStorage.getItem('cart'))
      }
      cart.splice(itemIndex, 1)
      localStorage.setItem('cart', JSON.stringify(cart))
    }
    return cart
}
```

# 显示总价

在`CartItems`组件的底部，我们将显示购物车中物品的总价。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
<span className={classes.total}>Total: ${this.getTotal()}</span>
```

`getTotal`方法将计算总价，考虑到`cartItems`数组中每个物品的单价和数量。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
getTotal(){
    return this.state.cartItems.reduce( function(a, b){
        return a + (b.quantity*b.product.price)
    }, 0)
}
```

# 结账选项

用户将看到执行结账的选项，这取决于他们是否已登录以及结账是否已经打开。

`mern-marketplace/client/cart/CartItems.js`：

```jsx
{!this.props.checkout && (auth.isAuthenticated() ? 
    <Button onClick={this.openCheckout}>
        Checkout
    </Button> : 
    <Link to="/signin">
        <Button>Sign in to checkout</Button>
    </Link>)
}
```

当单击结账按钮时，`openCheckout`方法将使用作为属性传递的`setCheckout`方法在`Cart`组件中将结账值设置为`true`：

```jsx
openCheckout = () => {
    this.props.setCheckout(true)
}
```

一旦在购物车视图中将结账值设置为`true`，`Checkout`组件将被呈现，允许用户输入结账详情并下订单。

# 使用条纹进行支付

支付处理需要跨结账、订单创建和订单管理流程的实现。它还涉及对买家和卖家用户数据的更新。在我们深入讨论结账和订单功能的实现之前，我们将简要讨论使用条纹的支付处理选项和考虑事项，以及它在 MERN Marketplace 中的集成方式。

# 条纹

条纹提供了一套必要的工具，可以在任何 Web 应用程序中集成支付。这些工具可以根据应用程序的特定类型和正在实施的支付用例以不同的方式选择和使用。

在 MERN Marketplace 设置的情况下，应用程序本身将在 Stripe 上拥有一个平台，并且希望卖家在平台上连接 Stripe 账户，以便应用程序可以代表卖家对在结账时输入其信用卡详细信息的用户进行收费。在 MERN Marketplace 中，用户可以从不同商店添加产品到其购物车，因此他们的卡上的费用只会由应用程序为特定订购的产品创建，当卖家处理时。此外，卖家将完全控制从其 Stripe 仪表板上代表他们创建的费用。我们将演示如何使用 Stripe 提供的工具来使此付款设置工作。

Stripe 为每个工具提供了完整的文档和指南，并公开了在 Stripe 上设置的账户和平台的测试数据。为了在 MERN Marketplace 中实现付款，我们将使用测试密钥，并让您扩展实现以进行实时付款。

# 每个卖家的 Stripe 连接账户

为了代表卖家创建费用，应用程序将允许作为卖家的用户将其 Stripe 账户连接到其 MERN Marketplace 用户账户。

# 更新用户模型

在成功连接用户的 Stripe 账户后，我们将使用以下字段更新用户模型以存储 Stripe OAuth 凭据。

`mern-marketplace/server/models/user.model.js`：

```jsx
stripe_seller: {}
```

`stripe_seller`字段将存储卖家的 Stripe 账户凭据，并且在需要通过 Stripe 处理他们从商店出售的产品的收费时将使用此字段。

# 连接 Stripe 的按钮

在卖家的用户资料页面上，如果用户尚未连接其 Stripe 账户，我们将显示一个按钮，该按钮将带用户前往 Stripe 进行身份验证并连接其 Stripe 账户：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c26a53b2-2032-4685-ad5f-b14fd59ef2ad.png)

如果用户已成功连接其 Stripe 账户，我们将显示一个禁用的 STRIPE CONNECTED 按钮：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/1618ca16-5f33-4815-8829-a2816ba2e80c.png)

在`Profile`组件中添加的代码将首先检查用户是否是卖家，然后再渲染任何`STRIPE CONNECTED`按钮。然后，第二个检查将确认给定用户的`stripe_seller`字段中是否已经存在 Stripe 凭据。如果用户已经存在 Stripe 凭据，则显示禁用的`STRIPE CONNECTED`按钮，否则显示一个连接到 Stripe 的 OAuth 链接的链接。

`mern-marketplace/client/user/Profile.js`：

```jsx
{this.state.user.seller &&
   (this.state.user.stripe_seller ?
       (<Button variant="raised" disabled>
            Stripe connected
        </Button>) :
       (<a href={"https://connect.stripe.com/oauth/authorize?response_type=code&client_id="+config.stripe_connect_test_client_id+"&scope=read_write"}}>
           <img src={stripeButton}/>
        </a>)
)}
```

OAuth 链接获取平台的客户端 ID，我们将在`config`变量中设置，并将其他选项值作为查询参数。此链接将用户带到 Stripe，并允许用户连接现有的 Stripe 账户或创建新账户。然后一旦 Stripe 的认证过程完成，它会使用在 Stripe 仪表板上设置的重定向 URL 返回到我们的应用程序的平台连接设置。Stripe 将认证代码或错误消息作为查询参数附加到重定向 URL 上。

MERN Marketplace 重定向 URI 设置为`/seller/stripe/connect`，将呈现`StripeConnect`组件。

`mern-marketplace/client/MainRouter.js`：

```jsx
<Route path="/seller/stripe/connect" component={StripeConnect}/>
```

# `StripeConnect`组件

`StripeConnect`组件将基本上完成与 Stripe 的剩余认证过程步骤，并根据 Stripe 连接是否成功呈现相关消息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c0f9a30b-0a63-4f36-80f3-6ef632bbf11e.png)

当`StripeConnect`组件加载时，在`componentDidMount`中，我们将首先解析附加到来自 Stripe 重定向的 URL 的查询参数。对于解析，我们使用了之前用于产品搜索的相同`query-string` npm 模块。然后，如果 URL 的`query`参数包含认证代码，我们将在服务器上进行必要的 API 调用，以完成来自 Stripe 的 OAuth。

`mern-marketplace/client/user/StripeConnect.js`：

```jsx
  componentDidMount = () => {
    const parsed = queryString.parse(this.props.location.search)
    if(parsed.error){
      this.setState({error: true})
    }
    if(parsed.code){
      this.setState({connecting: true, error: false})
      const jwt = auth.isAuthenticated()
      stripeUpdate({
        userId: jwt.user._id
      }, {
        t: jwt.token
      }, parsed.code).then((data) => {
        if (data.error) {
          this.setState({error: true, connected: false,
          connecting:false})
        } else {
          this.setState({connected: true, connecting: false, 
          error:false})
        }
      })
    }
 }
```

`stripeUpdate` fetch 方法在`api-user.js`中定义，并将从 Stripe 检索的认证代码传递给我们将在服务器上设置的 API`'/api/stripe_auth/:userId'`。

`mern-marketplace/client/user/api-user.js`：

```jsx
const stripeUpdate = (params, credentials, auth_code) => {
  return fetch('/api/stripe_auth/'+params.userId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify({stripe: auth_code})
  }).then((response)=> {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# Stripe 认证更新 API

一旦 Stripe 账户连接成功，为了完成 OAuth 过程，我们需要使用检索到的授权码从我们的服务器向 Stripe OAuth 发出 POST API 调用，并检索凭据以存储在卖家的用户账户中以处理收费。Stripe 授权更新 API 在`/api/stripe_auth/:userId`接收请求，并启动向 Stripe 发出 POST API 调用以检索凭据。

此 Stripe 授权更新 API 的路由将在用户路由中声明如下。

`mern-marketplace/server/routes/user.routes.js`：

```jsx
router.route('/api/stripe_auth/:userId')
   .put(authCtrl.requireSignin, authCtrl.hasAuthorization,   
    userCtrl.stripe_auth, userCtrl.update)
```

对这个路由的请求使用`stripe_auth`控制器方法从 Stripe 检索凭据，并将其传递给现有的用户更新方法以存储在数据库中。

为了从我们的服务器向 Stripe API 发出 POST 请求，我们将使用`request` npm 模块：

```jsx
npm install request --save
```

用户控制器中的`stripe_auth`控制器方法将如下所示。

`mern-marketplace/server/controllers/user.controller.js`：

```jsx
const stripe_auth = (req, res, next) => {
  request({
    url: "https://connect.stripe.com/oauth/token",
    method: "POST",
    json: true,
    body:  
  {client_secret:config.stripe_test_secret_key,code:req.body.stripe, 
  grant_type:'authorization_code'}
  }, (error, response, body) => {
    if(body.error){
      return res.status('400').json({
        error: body.error_description
      })
    }
    req.body.stripe_seller = body
    next()
  })
}
```

向 Stripe 发出的 POST API 调用需要平台的秘钥和检索到的授权码来完成授权，并返回连接账户的凭据，然后将其附加到请求体中，以便用户可以在`next()`方法中更新。

有了这些凭据，应用程序可以代表卖家在客户信用卡上创建收费。

# 用于结账的 Stripe Card Elements

在结账过程中，为了从用户那里收集信用卡详细信息，我们将使用 Stripe 的`Card` `Elements`来在结账表单中添加信用卡字段。为了将`Card` `Elements`与我们的 React 界面集成，我们将利用`react-stripe-elements` npm 模块：

```jsx
npm install --save react-stripe-elements
```

我们还需要在`template.js`中注入`Stripe.js`代码，以便在前端代码中访问 Stripe：

```jsx
<script id="stripe-js" src="https://js.stripe.com/v3/" async></script>
```

对于 MERN Marketplace，Stripe 仅在购物车视图中需要，在那里`Checkout`组件需要它来渲染`Card` `Elements`并处理卡片详细信息。因此，在`Cart`组件挂载后，我们将使用应用程序的 Stripe API 密钥初始化 Stripe 实例，在其`componentDidMount`中。

`mern-marketplace/client/cart/Cart.js`：

```jsx
componentDidMount = () => {
    if (window.Stripe) {
      this.setState({stripe: 
     window.Stripe(config.stripe_test_api_key)})
    } else {
      document.querySelector('#stripe-js')
     .addEventListener('load', () 
     => {
        this.setState({stripe: 
     window.Stripe(config.stripe_test_api_key)})
      })
    }
 }
```

在`Cart.js`中添加的`Checkout`组件应该使用`react-stripe-elements`中的`StripeProvider`组件进行包装，以便`Checkout`中的`Elements`可以访问 Stripe 实例。

`mern-marketplace/client/cart/Cart.js`：

```jsx
<StripeProvider stripe={this.state.stripe}> 
     <Checkout/>
</StripeProvider>
```

然后，在`Checkout`组件中，我们将使用 Stripe 的`Elements`组件。使用 Stripe 的`Card Elements`将使应用程序能够收集用户的信用卡详细信息，并使用 Stripe 实例对卡片信息进行标记，而不是在我们自己的服务器上处理。关于在结账流程中收集卡片详细信息和生成卡片令牌的实现将在*结账*和*创建新订单*部分讨论。

# Stripe 客户记录卡片详细信息

在结账流程结束时下订单时，生成的卡片令牌将被用来创建或更新代表我们用户的 Stripe 客户（[`stripe.com/docs/api#customers`](https://stripe.com/docs/api#customers)），这是一个存储信用卡信息的好方法（[`stripe.com/docs/saving-cards`](https://stripe.com/docs/saving-cards)），以便进一步使用，比如在卖家从他们的商店处理已订购的产品时，仅为购物车中的特定产品创建收费。这消除了在自己的服务器上安全存储用户信用卡详细信息的复杂性。

# 更新用户模型

为了在我们的数据库中跟踪用户对应的 Stripe`Customer`信息，我们将使用以下字段更新用户模型：

```jsx
stripe_customer: {},
```

# 更新用户控制器

当用户在输入信用卡详细信息后下订单时，我们将创建一个新的或更新现有的 Stripe 客户。为了实现这一点，我们将更新用户控制器，添加一个`stripeCustomer`方法，该方法将在我们的服务器收到请求创建订单 API（在*创建新订单*部分讨论）时，在创建订单之前被调用。

在`stripeCustomer`控制器方法中，我们将需要使用`stripe` npm 模块：

```jsx
npm install stripe --save
```

安装`stripe`模块后，需要将其导入到用户控制器文件中，并使用应用程序的 Stripe 秘钥初始化`stripe`实例。

`mern-marketplace/server/controllers/user.controller.js`：

```jsx
import stripe from 'stripe'
const myStripe = stripe(config.stripe_test_secret_key)
```

`stripeCustomer`控制器方法将首先检查当前用户是否已在数据库中存储了相应的 Stripe 客户，然后使用从前端收到的卡片令牌来创建一个新的 Stripe 客户或更新现有的客户。

# 创建一个新的 Stripe 客户

如果当前用户没有相应的 Stripe`客户`，换句话说，`stripe_customer`字段没有存储值，我们将使用 Stripe 的创建客户 API（[`stripe.com/docs/api#create_customer`](https://stripe.com/docs/api#create_customer)）。

`mern-marketplace/server/controllers/user.controller.js`:

```jsx
myStripe.customers.create({
            email: req.profile.email,
            source: req.body.token
      }).then((customer) => {
          User.update({'_id':req.profile._id},
            {'$set': { 'stripe_customer': customer.id }},
            (err, order) => {
              if (err) {
                return res.status(400).send({
                  error: errorHandler.getErrorMessage(err)
                })
              }
              req.body.order.payment_id = customer.id
              next()
        })
})
```

如果 Stripe 客户成功创建，我们将通过将 Stripe 客户 ID 引用存储在`stripe_customer`字段中来更新当前用户的数据。我们还将将此客户 ID 添加到正在下订单的订单中，以便更简单地创建与订单相关的收费。

# 更新现有的 Stripe 客户

对于现有的 Stripe 客户，换句话说，当前用户在`stripe_customer`字段中存储了一个值，我们将使用 Stripe API 来更新 Stripe 客户。

`mern-marketplace/server/controllers/user.controller.js`:

```jsx
 myStripe.customers.update(req.profile.stripe_customer, {
       source: req.body.token
     }, 
       (err, customer) => {
         if(err){
           return res.status(400).send({
             error: "Could not update charge details"
           })
         }
         req.body.order.payment_id = customer.id
         next()
       })
```

一旦 Stripe 客户成功更新，我们将在`next()`调用中将客户 ID 添加到正在创建的订单中。

虽然这里没有涉及，但 Stripe 客户功能可以进一步用于允许用户从应用程序中存储和更新他们的信用卡信息。

# 为每个处理的产品创建一个收费

当卖家通过处理其商店中订购的产品更新订单时，应用程序将代表卖家在客户的信用卡上为产品的成本创建一个收费。为了实现这一点，我们将更新`user.controller.js`文件，使用`createCharge`控制器方法来使用 Stripe 的创建收费 API，并需要卖家的 Stripe 账户 ID 以及买家的 Stripe 客户 ID。

`mern-marketplace/server/controllers/user.controller.js`:

```jsx
const createCharge = (req, res, next) => {
  if(!req.profile.stripe_seller){
    return res.status('400').json({
      error: "Please connect your Stripe account"
    })
  }
  myStripe.tokens.create({
    customer: req.order.payment_id,
  }, {
    stripe_account: req.profile.stripe_seller.stripe_user_id,
  }).then((token) => {
      myStripe.charges.create({
        amount: req.body.amount * 100, //amount in cents
        currency: "usd",
        source: token.id,
      }, {
        stripe_account: req.profile.stripe_seller.stripe_user_id,
      }).then((charge) => {
        next()
      })
  })
}
```

如果卖家尚未连接他们的 Stripe 账户，`createCharge`方法将返回 400 错误响应，以指示需要连接 Stripe 账户。

为了能够代表卖家的 Stripe 账户向 Stripe 客户收费，我们首先需要使用客户 ID 和卖家的 Stripe 账户 ID 生成一个 Stripe 令牌，然后使用该令牌创建一个收费。

当服务器收到请求将产品状态更改为**处理中**的订单更新请求时，将调用`createCharge`控制器方法（关于此订单更新请求的 API 实现将在*按商店排序的订单*部分讨论）。

这涵盖了与 MERN Marketplace 特定用例的支付处理实现相关的所有 Stripe 相关概念。现在我们将继续允许用户完成结账并下订单。

# 结账

已登录并且已将商品添加到购物车的用户将能够开始结账流程。结账表单将收集客户详细信息、送货地址信息和信用卡信息：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/82230cf9-ee29-41e7-835e-b9c00f4f5a63.png)

# 初始化结账详细信息

在`Checkout`组件中，我们将在收集表单详细信息之前，在状态中初始化`checkoutDetails`对象。

`mern-marketplace/client/cart/Checkout.js`：

```jsx
state = {
    checkoutDetails: {customer_name: '', customer_email:'', 
                      delivery_address: {street: '', city: '', state: 
                        '', zipcode: '', country:''}},
  }
```

组件挂载后，我们将根据当前用户的详细信息预填充客户详细信息，并将当前购物车商品添加到`checkoutDetails`中。

`mern-marketplace/client/cart/Checkout.js`：

```jsx
componentDidMount = () => {
    let user = auth.isAuthenticated().user
    let checkoutDetails = this.state.checkoutDetails
    checkoutDetails.products = cart.getCart()
    checkoutDetails.customer_name = user.name
    checkoutDetails.customer_email = user.email
    this.setState({checkoutDetails: checkoutDetails})
}
```

# 客户信息

在结账表单中，我们将添加文本字段以收集客户姓名和电子邮件。

`mern-marketplace/client/cart/Checkout.js`：

```jsx
<TextField id="name" label="Name" value={this.state.checkoutDetails.customer_name} onChange={this.handleCustomerChange('customer_name')}/>
<TextField id="email" type="email" label="Email" value={this.state.checkoutDetails.customer_email} onChange={this.handleCustomerChange('customer_email')}/><br/>

```

当用户更新值时，`handleCustomerChange`方法将更新状态中的相关详细信息：

```jsx
handleCustomerChange = name => event => {
    let checkoutDetails = this.state.checkoutDetails
    checkoutDetails[name] = event.target.value || undefined
    this.setState({checkoutDetails: checkoutDetails})
}
```

# 送货地址

为了从用户那里收集送货地址，我们将在结账表单中添加以下文本字段以收集街道地址、城市、邮政编码、州和国家。

`mern-marketplace/client/cart/Checkout.js`：

```jsx
<TextField id="street" label="Street Address" value={this.state.checkoutDetails.delivery_address.street} onChange={this.handleAddressChange('street')}/>
<TextField id="city" label="City" value={this.state.checkoutDetails.delivery_address.city} onChange={this.handleAddressChange('city')}/>
<TextField id="state" label="State" value={this.state.checkoutDetails.delivery_address.state} onChange={this.handleAddressChange('state')}/>
<TextField id="zipcode" label="Zip Code" value={this.state.checkoutDetails.delivery_address.zipcode} onChange={this.handleAddressChange('zipcode')}/>
<TextField id="country" label="Country" value={this.state.checkoutDetails.delivery_address.country} onChange={this.handleAddressChange('country')}/>
```

当用户更新这些地址字段时，`handleAddressChange`方法将更新状态中的相关详细信息。

`mern-marketplace/client/cart/Checkout.js`：

```jsx
handleAddressChange = name => event => {
    let checkoutDetails = this.state.checkoutDetails
    checkoutDetails.delivery_address[name] = event.target.value || 
    undefined
    this.setState({checkoutDetails: checkoutDetails})
}
```

# PlaceOrder 组件

将使用来自`react-stripe-elements`的 Stripe 的`CardElement`组件将信用卡字段添加到结账表单中。

`CardElement`组件必须是使用`injectStripe` **higher-order component** (**HOC**)构建的支付表单组件的一部分，并且使用`Elements`组件进行包装。因此，我们将创建一个名为`PlaceOrder`的组件，其中包含`injectStripe`，它将包含 Stripe 的`CardElement`和`PlaceOrder`按钮。

`mern-marketplace/client/cart/PlaceOrder.js`：

```jsx
class **PlaceOrder** extends Component { … } export default **injectStripe**(withStyles(styles)(PlaceOrder))
```

然后我们将在结账表单中添加`PlaceOrder`组件，将`checkoutDetails`对象作为 prop 传递给它，并使用来自`react-stripe-elements`的`Elements`组件进行包装。

`mern-marketplace/client/cart/Checkout.js`：

```jsx
<Elements> <PlaceOrder checkoutDetails={this.state.checkoutDetails} /> </Elements>
```

`injectStripe` HOC 提供了`this.props.stripe`属性，用于管理`Elements`组。这将允许我们在`PlaceOrder`中调用`this.props.stripe.createToken`来提交卡片详情到 Stripe 并获取卡片令牌。

# Stripe CardElement 组件

Stripe 的`CardElement`是自包含的，因此我们只需将其添加到`PlaceOrder`组件中，然后根据需要添加样式，卡片详情输入就会被处理。

`mern-marketplace/client/cart/PlaceOrder.js`：

```jsx
<CardElement className={classes.StripeElement}
      {...{style: {
      base: {
        color: '#424770',
        letterSpacing: '0.025em',
        '::placeholder': {
          color: '#aab7c4',
        },
      },
      invalid: {
        color: '#9e2146',
      },
    }}}/>
```

# 下订单

在`PlaceOrder`组件中的`CardElement`之后，也放置了“下订单”按钮。

`mern-marketplace/client/cart/PlaceOrder.js`：

```jsx
<Button color="secondary" variant="raised" onClick={this.placeOrder}>Place Order</Button>
```

点击“下订单”按钮将调用`placeOrder`方法，该方法将尝试使用`stripe.createToken`对卡片详情进行标记。如果失败，用户将被告知错误，但如果成功，结账详情和生成的卡片令牌将被发送到我们服务器的创建订单 API（在下一节中介绍）。

`mern-marketplace/client/cart/PlaceOrder.js`：

```jsx
placeOrder = ()=>{
  this.props.stripe.createToken().then(payload => {
      if(payload.error){
        this.setState({error: payload.error.message})
      }else{
        const jwt = auth.isAuthenticated()
        create({userId:jwt.user._id}, {
          t: jwt.token
        }, this.props.checkoutDetails, payload.token.id).then((data) => 
        {
          if (data.error) {
            this.setState({error: data.error})
          } else {
            cart.emptyCart(()=> {
              this.setState({'orderId':data._id,'redirect': true})
            })
          }
        })
      }
  })
}
```

在`client/order/api-order.js`中定义了`create` fetch 方法，该方法向后端的创建订单 API 发出 POST 请求。它将结账详情、卡片令牌和用户凭据作为参数，并将其发送到`/api/orders/:userId`的 API。

`mern-marketplace/client/order/api-order.js`：

```jsx
const create = (params, credentials, order, token) => {
  return fetch('/api/orders/'+params.userId, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + credentials.t
      },
      body: JSON.stringify({order: order, token:token})
    })
    .then((response) => {
      return response.json()
    }).catch((err) => console.log(err))
}
```

# 购物车为空

如果创建订单 API 成功，我们将使用`cart-helper.js`中的`emptyCart`辅助方法清空购物车。

`mern-marketplace/client/cart/cart-helper.js`：

```jsx
emptyCart(cb) {
  if(typeof window !== "undefined"){
     localStorage.removeItem('cart')
     cb()
  }
}
```

`emptyCart`方法从`localStorage`中移除购物车对象，并通过执行传递的回调来更新视图的状态。

# 重定向到订单视图

下订单并清空购物车后，用户将被重定向到订单视图，该视图将显示刚刚下的订单的详细信息。

`mern-marketplace/client/cart/PlaceOrder.js`：

```jsx
if (this.state.redirect) {
      return (<Redirect to={'/order/' + this.state.orderId}/>)
}
```

这将表明结账过程已经完成，并成功调用了我们在服务器端设置的创建订单 API，用于在数据库中创建和存储订单。

# 创建新订单

当用户下订单时，将使用在结账时确认的订单详情来在数据库中创建新的订单记录，更新或创建用户的 Stripe 客户端，并减少已订购产品的库存数量。

# 订单模型

为了存储订单，我们将为订单模型定义一个 Mongoose 模式，记录客户详细信息以及用户帐户引用，交货地址信息，付款参考，创建和更新时间戳，以及一个订购产品的数组，其中每个产品的结构将在名为`CartItemSchema`的单独子模式中定义。

# 下订单者和客户

为了记录订单面向的客户的详细信息，我们将在`Order`模式中添加`customer_name`和`customer_email`字段。

`mern-marketplace/server/models/order.model.js`：

```jsx
customer_name: { type: String, trim: true, required: 'Name is required' },
customer_email: { type: String, trim: true,
    match: [/.+\@.+\..+/, 'Please fill a valid email address'],
    required: 'Email is required' }
```

为了引用下订单的已登录用户，我们将添加一个`ordered_by`字段。

`mern-marketplace/server/models/order.model.js`：

```jsx
ordered_by: {type: mongoose.Schema.ObjectId, ref: 'User'}
```

# 交货地址

订单的交货地址信息将存储在交货地址子文档中，其中包括`street`，`city`，`state`，`zipcode`和`country`字段。

`mern-marketplace/server/models/order.model.js`：

```jsx
delivery_address: {
    street: {type: String, required: 'Street is required'},
    city: {type: String, required: 'City is required'},
    state: {type: String},
    zipcode: {type: String, required: 'Zip Code is required'},
    country: {type: String, required: 'Country is required'}
  },
```

# 付款参考

付款信息将在订单更新时相关，卖家处理订购产品后需要创建费用时。我们将在`Order`模式的`payment_id`字段中记录与信用卡详细信息相关的 Stripe 客户 ID。

`mern-marketplace/server/models/order.model.js`：

```jsx
payment_id: {},
```

# 订购的产品

订单的主要内容将是订购产品的列表以及每个产品的数量等详细信息。我们将在`Order`模式的一个名为`products`的字段中记录此列表。每个产品的结构将在`CartItemSchema`中单独定义。

`mern-marketplace/server/models/order.model.js`：

```jsx
products: [CartItemSchema],
```

# 购物车项目模式

`CartItem`模式将代表每个订购的产品。它将包含对产品的引用，用户订购的产品数量，产品所属商店的引用以及状态。

`mern-marketplace/server/models/order.model.js`：

```jsx
const CartItemSchema = new mongoose.Schema({
  product: {type: mongoose.Schema.ObjectId, ref: 'Product'},
  quantity: Number,
  shop: {type: mongoose.Schema.ObjectId, ref: 'Shop'},
  status: {type: String,
    default: 'Not processed',
    enum: ['Not processed' , 'Processing', 'Shipped', 'Delivered', 
   'Cancelled']}
}) 
const CartItem = mongoose.model('CartItem', CartItemSchema)
```

产品的`status`只能具有枚举中定义的值，表示卖家更新的产品订购的当前状态。

在这里定义的`Order`模式将记录客户和卖家完成订购产品的购买步骤所需的详细信息。

# 创建订单 API

创建订单 API 路由在`server/routes/order.routes.js`中声明。订单路由将与用户路由非常相似。要在 Express 应用程序中加载订单路由，我们需要在`express.js`中挂载路由，就像我们为 auth 和 user 路由所做的那样。

`mern-marketplace/server/express.js`：

```jsx
app.use('/', orderRoutes)
```

当创建订单 API 在`/api/orders/:userId`接收到 POST 请求时，将按以下顺序执行一系列操作。

+   确保用户已登录

+   使用之前讨论过的`stripeCustomer`用户控制器方法，创建或更新 Stripe`Customer`

+   使用`decreaseQuanity`产品控制器方法，更新所有订购产品的库存数量

+   使用`create`订单控制器方法在订单集合中创建订单

路由将被定义如下。

`mern-marketplace/server/routes/order.routes.js`：

```jsx
router.route('/api/orders/:userId') 
    .post(authCtrl.requireSignin, userCtrl.stripeCustomer, 
          productCtrl.decreaseQuantity, orderCtrl.create)
```

为了检索与路由中的`:userId`参数相关联的用户，我们将使用`userByID`用户控制器方法，该方法从用户集合中获取用户，并将其附加到请求对象中，以便下一个方法访问。我们将在订单路由中添加它。

`mern-marketplace/server/routes/order.routes.js`：

```jsx
router.param('userId', userCtrl.userByID)
```

# 减少产品库存数量

我们将更新产品控制器文件，添加`decreaseQuantity`控制器方法，该方法将更新新订单中购买的所有产品的库存数量。

`mern-marketplace/server/controllers/product.controller.js`：

```jsx
const decreaseQuantity = (req, res, next) => {
  let bulkOps = req.body.order.products.map((item) => {
    return {
        "updateOne": {
            "filter": { "_id": item.product._id } ,
            "update": { "$inc": {"quantity": -item.quantity} }
        }
    }
   })
   Product.bulkWrite(bulkOps, {}, (err, products) => {
     if(err){
       return res.status(400).json({
         error: "Could not update product"
       })
     }
     next()
   })
}
```

在这种情况下，更新操作涉及在与产品数组匹配后对集合中的多个产品进行批量更新，我们将使用 MongoDB 中的`bulkWrite`方法，以便一次性向 MongoDB 服务器发送多个`updateOne`操作。首先使用`map`函数将需要的多个`updateOne`操作列在`bulkOps`中。这将比发送多个独立的保存或更新操作更快，因为使用`bulkWrite()`只需要一次往返到 MongoDB。

# 创建订单控制器方法

在订单控制器中定义的`create`控制器方法接收订单详情，创建新订单，并将其保存到 MongoDB 的订单集合中。

`mern-marketplace/server/controllers/order.controller.js`：

```jsx
const create = (req, res) => {
  req.body.order.user = req.profile
  const order = new Order(req.body.order)
  order.save((err, result) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.status(200).json(result)
  })
}
```

通过这样的实现，任何在 MERN Marketplace 上登录的用户都可以创建并将订单存储在后端。现在我们可以设置 API 来获取用户的订单列表、商店的订单列表，或者读取单个订单并将获取的数据显示在前端视图中。

# 商店的订单

市场的一个重要特性是允许卖家查看和更新他们在商店中收到的订单的状态。为了实现这一点，我们首先将设置 API 来按商店列出订单，然后在卖家更改已购买产品的状态时更新订单。

# 按商店列出 API

我们将实现一个 API 来获取特定商店的订单，这样经过身份验证的卖家可以查看他们每个商店的订单。对于这个 API 的请求将在`'/api/orders/shop/:shopId`接收，路由在`order.routes.js`中定义如下。

`mern-marketplace/server/routes/order.routes.js`：

```jsx
router.route('/api/orders/shop/:shopId') 
    .get(authCtrl.requireSignin, shopCtrl.isOwner, orderCtrl.listByShop)
router.param('shopId', shopCtrl.shopByID)
```

为了检索与路由中的`:shopId`参数相关联的商店，我们将使用`shopByID`商店控制器方法，该方法从商店集合中获取商店并将其附加到请求对象中，以便下一个方法访问。

`listByShop`控制器方法将检索具有与匹配商店 ID 购买的产品的订单，然后按日期从最近到最旧的顺序填充每个产品的 ID、名称和价格字段。

`mern-marketplace/server/controllers/order.controller.js`：

```jsx
const listByShop = (req, res) => {
  Order.find({"products.shop": req.shop._id})
  .populate({path: 'products.product', select: '_id name price'})
  .sort('-created')
  .exec((err, orders) => {
    if (err) {
      return res.status(400).json({
        error: errorHandler.getErrorMessage(err)
      })
    }
    res.json(orders)
  })
}
```

为了在前端获取这个 API，我们将在`api-order.js`中添加一个相应的`listByShop`方法，用于在`ShopOrders`组件中显示每个商店的订单。

`mern-marketplace/client/order/api-order.js`：

```jsx
const listByShop = (params, credentials) => {
  return fetch('/api/orders/shop/'+params.shopId, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    }
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# ShopOrders 组件

卖家将在`ShopOrders`组件中查看他们的订单列表，每个订单只显示与商店相关的已购买产品，并允许卖家使用可能状态值的下拉菜单更改产品的状态：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/76b773d7-1bb1-429b-b10b-20933f551b19.png)

我们将在`MainRouter`中更新一个`PrivateRoute`，以在`/seller/orders/:shop/:shopId`路由处加载`ShopOrders`组件。

`mern-marketplace/client/MainRouter.js`：

```jsx
<PrivateRoute path="/seller/orders/:shop/:shopId" component={ShopOrders}/>
```

# 列出订单

当`ShopOrders`组件挂载时，我们将使用`listByShop`获取方法加载相关订单，并将检索到的订单设置为状态。

`mern-marketplace/client/order/ShopOrders.js`：

```jsx
 loadOrders = () => {
    const jwt = auth.isAuthenticated()
    listByShop({
      shopId: this.match.params.shopId
    }, {t: jwt.token}).then((data) => {
      if (data.error) {
        console.log(data)
      } else {
        this.setState({orders: data})
      }
    })
 }
```

在视图中，我们将遍历订单列表，并在`Material-UI`的可折叠列表中呈现每个订单，点击时会展开。

`mern-marketplace/client/order/ShopOrders.js`：

```jsx
<Typography type="title"> Orders in {this.match.params.shop} </Typography>
<List dense> {this.state.orders.map((order, index) => { return 
    <span key={index}>
        <ListItem button onClick={this.handleClick(index)}>
           <ListItemText primary={'Order # '+order._id} 
                 secondary={(new Date(order.created)).toDateString()}/>
           {this.state.open == index ? <ExpandLess /> : <ExpandMore />}
        </ListItem>
        <Collapse component="li" in={this.state.open == index} 
       timeout="auto" unmountOnExit>
           <ProductOrderEdit shopId={this.match.params.shopId} 
           order={order} orderIndex={index} 
           updateOrders={this.updateOrders}/>
           <Typography type="subheading"> Deliver to:</Typography>
           <Typography type="subheading" color="primary">
               {order.customer_name} ({order.customer_email})
          </Typography>
           <Typography type="subheading" color="primary">
               {order.delivery_address.street}</Typography>
           <Typography type="subheading" color="primary">
               {order.delivery_address.city}, 
           {order.delivery_address.state}
               {order.delivery_address.zipcode}</Typography>
           <Typography type="subheading" color="primary">
               {order.delivery_address.country}</Typography>
        </Collapse>
    </span>})}
</List>
```

每个展开的订单将显示订单详情和`ProductOrderEdit`组件。`ProductOrderEdit`组件将显示已购买的产品，并允许卖家编辑每个产品的状态。`updateOrders`方法作为属性传递给`ProductOrderEdit`组件，以便在更改产品状态时可以更新状态。

`mern-marketplace/client/order/ShopOrders.js`：

```jsx
updateOrders = (index, updatedOrder) => {
    let orders = this.state.orders 
    orders[index] = updatedOrder 
    this.setState({orders: orders}) 
}
```

# 产品订单编辑组件

`ProductOrderEdit`组件将订单对象作为属性，并遍历订单的产品数组，仅显示从当前商店购买的产品，以及更改每个产品状态值的下拉菜单。

`mern-marketplace/client/order/ProductOrderEdit.js`：

```jsx
{this.props.order.products.map((item, index) => { return <span key={index}> 
     { item.shop == this.props.shopId && 
          <ListItem button>
              <ListItemText primary={ <div>
                     <img src=
                    {'/api/product/image/'+item.product._id}/> 
                     {item.product.name}
                     <p>{"Quantity: "+item.quantity}</p>
              </div>}/>
              <TextField id="select-status" select
                   label="Update Status" value={item.status}
                   onChange={this.handleStatusChange(index)}
                   SelectProps={{
                       MenuProps: { className: classes.menu },
                   }}>
                      {this.state.statusValues.map(option => (
                          <MenuItem key={option} value={option}>
                            {option}
                          </MenuItem>
                      ))}
              </TextField>
          </ListItem>}
```

在加载`ProductOrderEdit`组件时，从服务器获取可能的状态值列表，并设置为`statusValues`状态，以在下拉菜单中呈现为`MenuItem`。

`mern-marketplace/client/order/ProductOrderEdit.js`：

```jsx
loadStatusValues = () => {
    getStatusValues().then((data) => {
      if (data.error) {
        this.setState({error: "Could not get status"})
      } else {
        this.setState({statusValues: data, error: ''})
      }
    })
}
```

当从可能的状态值中选择一个选项时，将调用`handleStatusChange`方法来更新状态中的订单，并根据所选状态的值发送请求到适当的后端 API。

`mern-marketplace/client/order/ProductOrderEdit.js`：

```jsx
handleStatusChange = productIndex => event => {
    let order = this.props.order 
    order.products[productIndex].status = event.target.value 
    let product = order.products[productIndex] 
    const jwt = auth.isAuthenticated() 
    if(event.target.value == "Cancelled"){
       cancelProduct({ shopId: this.props.shopId, 
       productId: product.product._id }, 
       {t: jwt.token}, 
       {cartItemId: product._id, status: 
       event.target.value, 
       quantity: product.quantity
       }).then((data) => { 
       if (data.error) {
       this.setState({error: "Status not updated, 
       try again"})
       } else {
 this.props.updateOrders(this.props.orderIndex, order)      this.setState(error: '') 
       } 
       }) 
       } else if(event.target.value == "Processing"){
       processCharge({ userId: jwt.user._id, shopId: 
       this.props.shopId, orderId: order._id }, 
       { t: jwt.token}, 
       { cartItemId: product._id, 
       amount: (product.quantity *
       product.product.price)
       status: event.target.value }).then((data) => { ... 
       })
       } else {
       update({ shopId: this.props.shopId }, {t: 
       jwt.token}, 
       { cartItemId: product._id, 
       status: event.target.value}).then((data) => { ... })
      }
}
```

在`api-order.js`中定义了`cancelProduct`、`processCharge`和`update`获取方法，以调用后端对应的 API 来更新取消产品的库存数量，在处理产品时在客户的信用卡上创建一个费用，并更新订单以更改产品状态。

# 已订购产品的 API

允许卖家更新产品状态将需要设置四个不同的 API，包括一个用于检索可能状态值的 API。然后实际状态更新将需要处理订单本身的更新 API，因为状态已更改，以启动相关操作，例如增加取消产品的库存数量，并在处理产品时在客户的信用卡上创建一个费用。

# 获取状态值

已订购产品的可能状态值在`CartItem`模式中设置为枚举，并且为了在下拉视图中显示这些值作为选项，我们将在`/api/order/status_values`设置一个 GET API 路由，以检索这些值。

`mern-marketplace/server/routes/order.routes.js`：

```jsx
router.route('/api/order/status_values')
    .get(orderCtrl.getStatusValues)
```

`getStatusValues`控制器方法将从`CartItem`模式的`status`字段返回枚举值。

`mern-marketplace/server/controllers/order.controller.js`：

```jsx
const getStatusValues = (req, res) => {
  res.json(CartItem.schema.path('status').enumValues)
}
```

我们还将在`api-order.js`中设置一个`fetch`方法，这在视图中用于向 API 路由发出请求。

`mern-marketplace/client/order/api-order.js`：

```jsx
const getStatusValues = () => {
  return fetch('/api/order/status_values', {
    method: 'GET'
  }).then((response) => {
    return response.json()
  }).catch((err) => console.log(err))
}
```

# 更新订单状态

当产品的状态更改为除**处理中**和**已取消**之外的任何值时，将直接向`'/api/order/status/:shopId'`发送 PUT 请求，以更新数据库中的订单，假设当前用户是已验证的拥有订购产品的商店的所有者。

`mern-marketplace/server/routes/order.routes.js`：

```jsx
router.route('/api/order/status/:shopId')
    .put(authCtrl.requireSignin, shopCtrl.isOwner, orderCtrl.update)
```

`update`控制器方法将查询订单集合，并找到与更新产品匹配的`CartItem`对象的订单，并设置订单中`products`数组中匹配的`CartItem`的`status`值。

`mern-marketplace/server/controllers/order.controller.js`：

```jsx
const update = (req, res) => {
  Order.update({'products._id':req.body.cartItemId}, {'$set': {
        'products.$.status': req.body.status
    }}, (err, order) => {
      if (err) {
        return res.status(400).send({
          error: errorHandler.getErrorMessage(err)
        })
      }
      res.json(order)
    })
}
```

在`api-order.js`中，我们将添加一个`update` fetch 方法，以使用从视图传递的必需参数调用此更新 API。

`mern-marketplace/client/order/api-order.js`：

```jsx
const update = (params, credentials, product) => {
  return fetch('/api/order/status/' + params.shopId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify(product)
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  }) 
}
```

# 取消产品订单

当卖家决定取消产品的订单时，将发送一个 PUT 请求到`/api/order/:shopId/cancel/:productId`，以便增加产品库存数量，并在数据库中更新订单。

`mern-marketplace/server/routes/order.routes.js`：

```jsx
router.route('/api/order/:shopId/cancel/:productId')
       .put(authCtrl.requireSignin, shopCtrl.isOwner,
       productCtrl.increaseQuantity, orderCtrl.update)
       router.param('productId', productCtrl.productByID)
```

为了检索与路由中的`productId`参数相关联的产品，我们将使用`productByID`产品控制器方法。

增加数量的控制器方法被添加到`product.controller.js`中。它在产品集合中通过匹配的 ID 找到产品，并将数量值增加到客户订购的数量，现在该产品的订单已被取消。

`mern-marketplace/server/controllers/product.controller.js`：

```jsx
const increaseQuantity = (req, res, next) => {
  Product.findByIdAndUpdate(req.product._id, {$inc: 
  {"quantity": req.body.quantity}}, {new: true})
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

从视图中，我们将使用在`api-order.js`中添加的相应 fetch 方法来调用取消产品订单 API。

`mern-marketplace/client/order/api-order.js`：

```jsx
const cancelProduct = (params, credentials, product) => {
  return fetch('/api/order/'+params.shopId+'/cancel/'+params.productId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify(product)
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

# 为产品处理收费

当卖家将产品的状态更改为**处理中**时，我们将建立一个后端 API，不仅更新订单，还会为产品的价格乘以订购数量在客户的信用卡上创建一个收费。

`mern-marketplace/server/routes/order.routes.js`：

```jsx
router.route('/api/order/:orderId/charge/:userId/:shopId')
            .put(authCtrl.requireSignin, shopCtrl.isOwner,     
            userCtrl.createCharge, orderCtrl.update)
router.param('orderId', orderCtrl.orderByID)
```

为了检索与路由中的`orderId`参数相关联的订单，我们将使用`orderByID`订单控制器方法，该方法从订单集合中获取订单并将其附加到请求对象中，以便由`next`方法访问，如下所示。

`mern-marketplace/server/controllers/order.controller.js:`

```jsx
const orderByID = (req, res, next, id) => {
  Order.findById(id).populate('products.product', 'name price')
       .populate('products.shop', 'name')
       .exec((err, order) => {
          if (err || !order)
            return res.status('400').json({
              error: "Order not found"
            })
          req.order = order
          next()
       })
}
```

此过程收费 API 将在`/api/order/:orderId/charge/:userId/:shopId`接收 PUT 请求，并在成功验证用户后，通过调用`createCharge`用户控制器来创建收费，如前面的*使用 Stripe 进行付款*部分所讨论的，最后使用`update`方法更新订单。

从视图中，我们将在`api-order.js`中使用`processCharge` fetch 方法，并提供所需的路由参数值、凭据和产品详情，包括要收费的金额。

`mern-marketplace/client/order/api-order.js`：

```jsx
const processCharge = (params, credentials, product) => {
  return fetch('/api/order/'+params.orderId+'/charge/'+params.userId+'/'
    +params.shopId, {
    method: 'PUT',
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + credentials.t
    },
    body: JSON.stringify(product)
  }).then((response) => {
    return response.json()
  }).catch((err) => {
    console.log(err)
  })
}
```

卖家可以查看其店铺中收到的产品订单，并可以轻松更新每个产品订单的状态，而应用程序会处理其他任务，例如更新库存数量和发起付款。这涵盖了 MERN Marketplace 应用程序的基本订单管理功能，可以根据需要进一步扩展。

# 查看订单详情

随着订单集合和数据库访问的设置完成，向前推进很容易添加每个用户的订单列表功能，并在单独的视图中显示单个订单的详细信息，用户可以在该视图中跟踪每个已订购产品的状态。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/4af78ad1-eb61-4c8b-a32b-a56d7ba0b649.png)

遵循本书中反复出现的步骤，设置后端 API 以检索数据并在前端使用它来构建前端视图，您可以根据需要开发与订单相关的视图，并从 MERN Marketplace 应用程序代码中的这些示例视图的快照中获得灵感：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/flstk-react-pj/img/c1282af6-a2af-41c2-8909-5f176615778d.png)

在本章和第六章中开发的 MERN Marketplace 应用程序，通过在 MERN 骨架应用程序的基础上构建，涵盖了标准在线市场应用程序的关键功能。这反过来展示了 MERN 堆栈如何扩展以包含复杂功能。

# 总结

在本章中，我们扩展了 MERN Marketplace 应用程序，并探讨了如何为买家添加购物车，使用信用卡付款的结账流程，以及在线市场应用程序中卖家的订单管理。

我们发现 MERN 堆栈技术如何与第三方集成良好，因为我们实现了购物车结账流程，并使用 Stripe 提供的工具处理已订购产品的信用卡付款，用于管理在线付款。

我们还解锁了 MERN 的更多可能性，例如在 MongoDB 中进行优化的批量写操作，以响应单个 API 调用更新多个文档。这使我们能够一次性减少多个产品的库存数量，例如当用户从不同商店订购多个产品时。

在 MERN Marketplace 应用程序中开发的市场功能揭示了这种堆栈和结构如何被利用来设计和构建不断增长的应用程序，通过添加可能是简单或更复杂的特性。

在下一章中，我们将借鉴本书迄今为止所学到的经验，通过扩展 MERN 骨架构建媒体流应用程序，探索更高级的可能性。
