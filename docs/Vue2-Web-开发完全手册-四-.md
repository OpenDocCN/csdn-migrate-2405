# Vue2 Web 开发完全手册（四）

> 原文：[`zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070`](https://zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 Vue-Router 动态路由加载数据

在第八章《介绍 Vue-Router 和加载基于 URL 的组件》中，我们探索了 Vue-router 及其功能和功能。有了这些知识，我们现在可以继续使用 Vue 制作我们的商店。在我们进入代码并开始创建之前，我们应该首先计划我们的商店将如何工作，我们需要哪些 URL 以及我们需要制作哪些组件。一旦我们计划好我们的应用程序，我们就可以继续创建一个产品页面。

在本章中，我们将：

+   概述我们的组件和路由，并创建占位符文件

+   加载产品 CSV 文件，处理并缓存在 Vuex 中

+   创建一个带有图像和产品变体的单独产品页面

# 概述和计划您的应用程序

首先，让我们考虑整个应用程序和用户流程。

我们将创建一个没有支付处理网关的商店。商店首页将显示一系列精选产品。用户将能够使用类别浏览产品，并使用我们制作的筛选器缩小选择范围。他们将能够选择一个产品并查看更多详细信息。产品将具有变体（大小、颜色等），并且可能有多个产品图像。用户将能够将变体添加到购物篮中。从那里，他们可以继续浏览产品并添加更多产品到购物篮中，或者进入结账流程，在那里他们将被要求提供姓名和地址，并进行支付。将显示订单确认屏幕。

整个商店应用程序将在 Vue 中创建并在客户端运行。这不涵盖任何用于付款、用户帐户、库存管理或验证的服务器端代码。

该应用程序将使用 Vue-router 处理 URL 和 Vuex 存储产品、购物篮内容和用户详细信息。

# 组件

在确定用户流程后，我们需要计划我们的商店需要制作哪些组件以及它们的名称。这有助于开发应用程序，因为我们清楚地知道需要创建哪些组件。我们还将决定组件的名称。根据 Vue 风格指南（[`vuejs.org/v2/style-guide/index.html`](https://vuejs.org/v2/style-guide/index.html)），我们的所有组件都将由两个名称组成。

# 路由组件

以下组件将与 Vue-router 一起使用，形成我们应用程序的页面：

+   **商店首页**—`HomePage`：商店首页将显示由商店所有者精选的产品列表。这将使用预先选择的产品句柄列表进行显示。

+   **分类页面**—`CategoryPage`：这将列出特定类别的产品。类别列表页面还将具有过滤器。

+   **产品页面**—`ProductPage`：产品页面将显示产品的详细信息、图片和产品的变体。

+   **购物篮**—`OrderBasket`：在购物篮中，用户可以查看已添加的产品，删除不需要的项目，并更改每个项目的数量。它还将显示订单的总成本。

+   **结账**—`OrderCheckout`：结账将锁定购物篮，禁止删除和更新产品，并提供一个表单供用户输入地址。

+   **订单确认**—`OrderConfirmation`：下单后将显示此组件，确认购买的产品、交付地址和总价格。

+   `404` **页面**—`PageNotFound`：当输入错误的 URL 时显示的错误页面。

# HTML 组件

HTML 组件将在页面组件中使用，以帮助减少我们的代码中的重复布局。

+   **产品列表**—`ListProducts`：在列表视图中查看时，将显示产品的分页列表，例如在`HomePage`或`CategoryPage`组件中。

+   **类别列表**—`ListCategories`：这将创建一个用于导航的类别列表。

+   **购买列表**—`ListPurchases`：此组件将出现在购物篮、结账和订单确认页面中；它将以表格形式列出产品的变体、价格和数量。它还将显示购物篮中所有产品的总价格。

+   **过滤**—`ProductFiltering`：在类别页面的侧边使用的组件将提供用户过滤的能力，并且将使用我们在[第八章](https://cdp.packtpub.com/vue_js_by_example/wp-admin/post.php?post=103&action=edit#post_93)中介绍的 GET 参数更新 URL，*介绍 Vue-Router 和加载基于 URL 的组件*。

# 路径

在我们概述了组件之后，我们可以规划商店的路径和 URL，以及它们将采取的组件或操作。我们还需要考虑错误的 URL 以及是否应该将用户重定向到适当的位置或显示错误消息：

+   `/`：`Home`

+   `/category/:slug`：`CategoryPage`，使用`:slug`唯一标识符来确定要显示的产品

+   `/category`：这将重定向到`/`

+   `/product/:slug`：`ProductPage` - 再次使用`:slug`来标识产品

+   `/product`：这将重定向到`/`

+   `/basket`：`OrderBasket`

+   `/checkout`：`OrderCheckout` - 如果没有产品，它将重定向用户到`/basket`

+   `/complete`：`OrderConfirmation` - 如果用户没有从`OrderCheckout`组件进入，则会重定向到`/basket`

+   `*`：`PageNotFound` - 这将捕获任何未指定的路由

随着我们确定了路由和组件，我们可以开始创建我们的应用程序。

# 创建初始文件

在前一节中概述的应用程序中，我们可以为文件结构和组件创建框架。由于这个应用程序是一个大型应用程序，我们将把文件拆分为每个组件的单独文件。这意味着我们的文件更易管理，我们的主应用程序 JavaScript 文件不会变得无法控制。

尽管在开发过程中可以接受，但是部署具有这么多文件的应用程序可能会增加加载时间，这取决于服务器的设置方式。使用传统的 HTTP/1.1，浏览器必须请求和加载每个文件 - 如果有多个文件，这将是一个阻碍。然而，使用 HTTP/2，您可以同时向用户推送多个文件 - 在这种情况下，多个文件可以在一定程度上提高应用程序的性能。

无论您选择使用哪种部署方法，强烈建议在将代码部署到生产环境时对 JavaScript 进行缩小。这样可以确保在为用户提供服务时，代码尽可能小：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/f936b8d6-368f-45a4-92c7-4d7b63d1104d.png)

为每个组件、视图和库（如 Vue、Vuex 和 Vue-router）创建一个文件。然后，为每种类型的文件创建一个文件夹。最后，添加一个`app.js` - 这是初始化库的地方。

您还可以考虑使用 vue-cli [(https://github.com/vuejs/vue-cli)](https://github.com/vuejs/vue-cli)来构建您的应用程序。超出了本书的范围，因为我们只涵盖了使用包含的 JavaScript 文件构建 Vue 应用程序，vue-cli 应用程序允许您以更模块化的方式开发应用程序，并在开发完成后以类似我们一直在开发应用程序的方式部署它。

创建一个`index.html`文件，并包含您的 JavaScript 文件，确保首先加载 Vue，最后加载您的应用程序的 JavaScript。添加一个容器来形成我们商店的视图：

```js
<!DOCTYPE html>
<html>
<head>
  <title>Vue Shop</title>
</head>
<body>
  <div id="app"></div>

  <!-- Libraries -->
  <script type="text/javascript" src="js/libs/vue.js"></script>
  <script type="text/javascript" src="js/libs/vuex.js"></script>
  <script type="text/javascript" src="js/libs/router.js"></script>

  <!-- Components -->
  <script src="js/components/ListCategories.js"></script>
  <script src="js/components/ListProducts.js"></script>
  <script src="js/components/ListPurchases.js"></script>
  <script src="js/components/ProductFiltering.js"></script>

  <!-- Views -->
  <script src="js/views/PageNotFound.js"></script>
  <script src="js/views/CategoryPage.js"></script>
  <script src="js/views/HomePage.js"></script>
  <script src="js/views/OrderBasket.js"></script>
  <script src="js/views/OrderCheckout.js"></script>
  <script src="js/views/OrderConfirmation.js"></script>
  <script src="js/views/ProductPage.js"></script>

  <!-- App -->
  <script type="text/javascript" src="js/app.js"></script>
</body>
</html>
```

确保首先加载`PageNotFound`组件，因为我们将在其他组件中使用它，并将其指定为我们的 404 页面。

在每个文件中，通过声明变量或使用`Vue.component`来初始化组件的类型。对于视图，还要添加一个`name`属性，以便以后调试时使用。

例如，位于`js/components/`文件夹中的所有文件应该像下面这样初始化。确保这些组件是小写的，并且使用连字符分隔：

```js
Vue.component('list-products', {

});
```

而位于`js/views`中的路由和视图组件应该如下所示：

```js
const OrderConfirmation = {
name: 'OrderConfirmation'
};
```

最后一步是初始化我们的 Vuex 存储、Vue-router 和 Vue 应用程序。打开`app.js`并初始化这些库：

```js
const store = new Vuex.Store({});

const router = new VueRouter({});

new Vue({
  el: '#app',

  store,
  router
});
```

准备好 Vue 组件和路由，初始化我们的存储、路由和应用程序后，让我们来看看如何设置服务器（如果需要）并加载数据。

# 服务器设置

在我们的商店中，我们将在页面加载时加载一个产品的 CSV 文件。这将模拟从数据库或 API 中收集库存和产品数据的过程，这是在线商店与实体店可能需要处理的事情。

与本书前面的 Dropbox 应用程序类似，我们将加载外部数据并将其保存到 Vuex 存储中。然而，我们将面临一个问题，即在通过 JavaScript 加载资源时，浏览器要求请求的文件的协议必须是 HTTP、HTTPS 或 CORS 请求。

这意味着我们无法使用我们在 Dropbox API 中使用的`fetch()`技术来加载*本地*文件，因为在浏览器中查看我们的应用程序时，我们是通过`file://`协议加载本地资源的。

我们可以通过几种不同的方式解决这个问题-你选择哪种方式取决于你的情况。我们将加载一个 CSV 文件，并使用两个插件将其转换为可用的 JSON 对象。你有三个选项：

1.  将文件存储在本地

1.  使用远程服务器或

1.  使用本地服务器

让我们逐个讨论每个选项的优缺点。

# 将文件存储在本地

第一种选择是将 CSV 适当地转换为 JSON，然后将输出保存在文件中。您需要将其分配给文件中的变量，并在加载库之前加载 JSON。一个示例可能是创建一个`data.json`并将其更新为分配给变量：

```js
const products = {...}
```

然后可以在您的 HTML 中加载 JSON 文件：

```js
<script type="text/javascript" src="data.json"></script>
```

然后，在您的`app.js`中可以使用`products`变量。

优点：

+   代码负载较少

+   无需加载处理 CSV 所需的额外文件

+   不需要额外的步骤

缺点：

+   无法模拟真实世界

+   如果要更新 CSV 数据，需要进行转换、保存并分配给变量

# 使用远程服务器

另一个选项是将文件上传到远程现有服务器并在那里开发您的应用程序。

优点：

+   模拟真实世界中加载 CSV 的开发

+   可以在任何地方、任何机器上开发

缺点：

+   可能会很慢

+   需要连接到互联网

+   需要设置部署过程或在实时服务器上编辑文件

# 设置本地服务器

最后一种选择是在您的计算机上设置本地服务器。有几个小型、轻量级、零配置模块和应用程序，也有更大、更强大的应用程序。如果您的计算机上安装了 npm，则建议使用 Node HTTP 服务器。如果没有，还有其他选项可用。

另一种选择是使用更重量级的应用程序，它可以为您提供 SQL 数据库和运行 PHP 应用程序的能力。这种情况的一个例子是 MAMP 或 XAMPP。

优点：

+   模拟真实世界中加载 CSV 的开发

+   快速、即时更新

+   可以离线开发

缺点：

+   需要安装软件

+   可能需要一些配置和/或命令行知识

我们将选择的选项是使用 HTTP 服务器。让我们加载和处理 CSV 文件，以便开始创建我们的商店。

# 加载 CSV

为了模拟从商店数据库或销售点收集数据，我们的应用程序将从 CSV 加载产品数据。CSV（逗号分隔值）是一种常用的文件格式，用于以数据库样式的方式共享数据。想象一下如何在 Excel 或 Numbers 中布置产品列表：这就是 CSV 文件的格式。

下一步需要下载并包含几个 JavaScript 文件。如果您在“服务器设置”部分选择了选项 1-将文件存储在本地的 JSON 文件中-则可以跳过此步骤。

我们将使用 Shopify 的示例商店数据。这些 CSV 文件有各种产品类型和不同的数据，这将测试我们的 Vue 技能。Shopify 已经将他们的示例数据放在了一个 GitHub 仓库中（[`github.com/shopifypartners/shopify-product-csvs-and-images`](https://github.com/shopifypartners/shopify-product-csvs-and-images)）。下载任何你感兴趣的 CSV 文件，并将其保存在你的文件系统中的`data/`文件夹中。对于这个应用程序，我将使用`bicycles.csv`文件。

JavaScript 不能本地加载和处理 CSV 文件，除非进行大量的编码和处理逗号分隔和引号封装的值。为了避免本书偏离主题，介绍如何加载、解析和处理 CSV 文件，我们将使用一个库来完成这些繁重的工作。有两个值得注意的库，CSV 解析器（[`github.com/okfn/csv.js`](https://github.com/okfn/csv.js)）和 d3（[`d3js.org/`](https://d3js.org/)）。CSV 解析器只做 CSV 解析，而 d3 有生成图表和数据可视化的能力。

值得考虑哪个适合你；CSV 解析器只会给你的应用程序增加 3KB 多的负担，而 d3 大约是 60KB。除非你预计以后会添加可视化效果，否则建议你选择更小的库-尤其是它们执行相同的功能。然而，我们将为两个库运行示例。

我们希望在应用程序加载时加载我们的产品数据，这样我们的组件在需要数据时就可以加载和解析 CSV。因此，我们将在 Vue 的`created()`方法中加载数据。

# 使用 d3 加载 CSV

这两个插件以非常相似的方式加载数据，但返回的数据有所不同-然而，我们将在加载数据后处理这个问题。

加载 d3 库-如果你想尝试一下，你可以使用托管的版本：

```js
<script src="https://d3js.org/d3.v4.min.js"></script>
```

使用 d3，我们使用`d3`对象上的`csv()`函数，它接受一个参数-CSV 文件的路径。将`created()`函数添加到你的 Vue 实例中，并初始化 CSV 加载器：

```js
new Vue({
  el: '#app',

  store,
  router,

  created() {
    d3.csv('./data/csv-files/bicycles.csv', (error, data) => {
 console.log(data);
 });
  }
});
```

请记住，文件的路径是相对于包含 JavaScript 文件的 HTML 文件的路径-在这种情况下是`index.html`。

在浏览器中打开文件不会显示任何输出。然而，如果你打开 Javascript 控制台并展开输出的对象，你会看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/c4cf6826-0321-44d9-a5f2-d14f3a370b05.png)

这将以`key: value`的格式为每个产品提供所有可用属性的详细信息。这使我们可以使用每个产品上的一致的`key`来访问每个`value`。例如，如果我们想要获取上面产品的`15mm-combo-wrench`，我们可以使用`Handle`键。稍后将详细介绍这个。

# 使用 CSV 解析器加载 CSV 文件

CSV 解析器的工作方式略有不同，它可以接受许多不同的参数，并且库包含几种不同的方法和函数。数据输出也是以不同的格式，以表格/CSV 样式的结构返回，包含`headers`和`fields`对象：

```js
new Vue({
  el: '#app',

  store,
  router,

  created() {
    CSV.fetch({url: './data/csv-files/bicycles.csv'}).then(data => {
 console.log(data);
 });
  }
});
```

这次查看输出将显示一个非常不同的结构，并需要将字段的`key`与`headers`对象的索引进行匹配。

# 统一 Shopify CSV 数据

在保存和使用 Shopify 数据之前，我们需要统一数据并将其转换为更易处理的状态。如果检查任一库输出的数据，您会注意到每个变体或产品的附加图像都有一个条目，而链接因子是 handle。例如，有大约 12 个 handle 为`pure-fix-bar-tape`的条目，每个条目都是不同的颜色。理想情况下，我们希望将每个变体分组到同一项下，并将图像显示为一个产品的列表。

Shopify CSV 数据的另一个问题是字段标题的标点符号和语法不适合作为对象键。理想情况下，对象键应该像 URL 的 slug 一样，小写且不包含空格。例如，`Variant Inventory Qty`理想情况下应该是`variant-inventory-qty`。

为了避免手动处理数据并更新键，我们可以使用一个 Vue 插件来处理加载库的输出，并返回一个格式完全符合我们要求的产品对象。该插件是`vue-shopify-products`，可以从 unpkg 获取：

```js
https://unpkg.com/vue-shopify-products
```

下载并将该库包含到您的`index.html`文件中。下一步是告诉 Vue 使用这个插件 - 在您的`app.js`文件的顶部，包含以下行：

```js
Vue.use(ShopifyProducts);
```

这将在 Vue 实例的`$formatProducts()`上暴露一个新的方法，允许我们传入 CSV 加载库的输出，并获得一个更有用的对象集合：

```js
Vue.use(ShopifyProducts);

const store = new Vuex.Store({});

const router = new VueRouter({});

new Vue({
  el: '#app',

  store,
  router,

  created() {
    CSV.fetch({url: './data/csv-files/bicycles.csv'}).then(data => {
      let products = this.$formatProducts(data);
      console.log(products);
    });
  }
});
```

现在检查输出，可以看到按`handle`分组的集合，其中变体和图像作为对象：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/3796f088-bf51-4dfc-a9cb-d0d895d0e2a0.png)

通过更有效地分组我们的产品，我们可以按需存储和调用。

# 存储产品

一旦我们检索和格式化了 CSV 数据，我们就可以将内容缓存到 Vuex store 中。这将通过一个简单的 mutation 来完成，该 mutation 接受一个 payload 并将其存储在不进行任何修改的情况下。

在你的 store 中创建一个`state`和`mutations`对象。在`state`中添加一个`products`键作为一个对象，并在`mutations`对象中创建一个名为`products`的函数。该 mutation 应该接受两个参数 - state 和 payload：

```js
const store = new Vuex.Store({
  state: {
    products: {}
  },

  mutations: {
    products(state, payload) {

    }
  }
});
```

更新`state.products`对象为`payload`的内容：

```js
const store = new Vuex.Store({
  state: {
    products: {}
  },

  mutations: {
    products(state, payload) {
      state.products = payload;
    }
  }
});
```

用一个 commit 函数替换主 Vue 实例中的`console.log`，调用新的 mutation 并传入格式化的产品数据：

```js
new Vue({
  el: '#app',

  store,
  router,

  created() {
    CSV.fetch({url: './data/csv-files/bicycles.csv'}).then(data => {
      let products = this.$formatProducts(data);
      this.store.commit('products', products);
    });
  }
});
```

可以通过直接将`$formatProducts`函数传递给 store 的`commit()`函数来减少一些代码，而不是将其存储为一个变量：

```js
new Vue({
  el: '#app',

  store,
  router,

  created() {
    CSV.fetch({url: './data/csv-files/bicycles.csv'}).then(data => {
      this.$store.commit('products', this.$formatProducts(data));
    });
  }
});
```

# 显示单个产品

现在我们的数据已经存储好了，我们可以开始制作组件并在前端显示内容了。我们将从制作产品视图开始 - 显示产品详情、变体和图片。接下来我们将在第十章中创建分类列表页面，*构建电子商务商店 - 浏览产品*。

创建产品视图的第一步是创建路由，以允许通过 URL 显示组件。回顾一下本章开头的笔记，产品组件将加载在`/product/:slug`路径上。

在你的 Vue-router 中创建一个`routes`数组，指定路径和组件：

```js
const router = new VueRouter({
  routes: [
 {
      path: '/product/:slug', 
      component: ProductPage
    }
 ]
});
```

通过解释`products`对象的布局，我们可以开始理解路由和产品之间的关联。我们将把产品的句柄传递到 URL 中。这将选择具有该句柄的产品并显示数据。这意味着我们不需要显式地将`slug`与`products`关联起来。

# 页面未找到

创建第一个路由后，我们还应该创建我们的`PageNotFound`路由，以捕获任何不存在的 URL。当没有与之匹配的产品时，我们也可以重定向到此页面。

我们将以稍微不同的方式创建`PageNotFound`组件。我们将创建一个`/404`路径作为一个命名路由，而不是将组件放在`*`上。这样可以根据需要对多个不同的路由进行别名和重定向。

向路由数组添加一个新对象，将`/404`作为路径，将`PageNotFound`组件作为指定的组件。为您的路由添加一个名称，以便在需要时使用，并最后添加一个`alias`属性，其中包含我们的全局捕获所有路由。

不要忘记将此放在路由数组的末尾，以捕获任何先前未指定的路由。添加新路由时，始终记得将它们放在`PageNotFound`路由之前：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/product/:slug', 
      component: ProductPage
    },

    {
 path: '/404', 
 alias: '*',
 component: PageNotFound
 }
  ]
});
```

为您的`PageNotFound`组件添加一个模板。现在，给它一些基本内容 - 一旦我们设置好应用程序的其余部分，我们可以稍后改进它：

```js
const PageNotFound = {
  name: 'PageNotFound',
  template: `<div>
 <h1>404 Page Not Found</h1>
 <p>Head back to the <router-link to="/">home page</router-link> and start again.</p>
 </div>`
};
```

注意内容中使用的路由链接。让我们启动应用程序的最后一件事是在我们的应用程序中添加`<router-view>`元素。转到视图，并将其包含在应用程序空间中：

```js
<div id="app">
  <router-view></router-view>
</div> 
```

在浏览器中加载应用程序，不要忘记在需要时启动 HTTP 服务器。首先，您应该看到`PageNotFound`组件的内容。导航到以下产品 URL 应该导致 JavaScript 错误，而不是`404`页面。这表明路由正确地捕获了 URL，但错误是因为我们的`ProductPage`组件不包含模板：

```js
#/product/15mm-combo-wrench
```

如果您看到`PageNotFound`组件，请检查您的路由代码，因为这意味着`ProductPage`路由没有被捕获。

# 选择正确的产品

设置初始路由后，我们现在可以继续加载所需的产品并显示存储中的信息。打开`views/Product.js`并创建一个模板键。首先，创建一个简单的`<div>`容器，显示产品的标题：

```js
const ProductPage = {
  name: 'ProductPage',
  template: `<div>{{ product.title }}</div>`
};
```

在浏览器中查看此内容将立即引发 JavaScript 错误，因为 Vue 期望`product`变量是一个对象 - 但由于我们尚未声明它，它目前是未定义的。尽管此问题的修复目前似乎非常简单，但我们需要考虑产品尚未定义的情况。

我们的商店应用程序异步加载数据 CSV。这意味着在产品加载时，应用程序的其余部分不会停止执行。总体而言，这增加了我们应用程序的速度，一旦我们有了产品，我们就可以开始操作和显示列表，而不需要等待应用程序的其余部分启动。

因此，有可能用户在没有加载产品列表的情况下访问产品详情页面，无论是通过共享的链接还是搜索结果。为了防止应用程序在没有完全初始化的情况下尝试显示产品数据，可以在模板中添加一个条件属性，检查产品变量是否存在，然后再尝试显示其任何属性。

在加载产品数据时，可以确保产品变量设置为`false`，直到所有内容都加载完成。在模板中的包含元素上添加`v-if`属性：

```js
const ProductPage = {
  name: 'ProductPage',
  template: `<div v-if="product">{{ product.title }}</div>`
};
```

现在我们可以从存储中加载正确的产品并将其赋值给一个变量。

创建一个带有`product()`函数的`computed`对象。在函数内部，创建一个空的变量来存储产品，并在之后返回它。现在默认返回`false`，这意味着我们的模板不会生成`<div>`标签：

```js
const ProductPage = {
  name: 'ProductPage',
  template: `<div v-if="product">{{ product.title }}</div>`,

  computed: {
    product() {
 let product;

 return product;
 }
  }
};
```

由于我们有格式良好的产品存储和可在`Product`组件中使用的`slug`变量的帮助，选择产品现在变得相当简单。存储中的`products`对象以句柄作为键，以`product details`对象作为值进行格式化。有了这个想法，我们可以使用方括号格式来选择所需的产品。例如：

```js
products[handle]
```

使用路由器的`params`对象，从存储中加载所需的产品并将其赋值给`product`变量以返回：

```js
const ProductPage = {
  name: 'ProductPage',
  template: `<div v-if="product">{{ product.title }}</div>`,

  computed: {
    product() {
      let product;

      product = this.$store.state.products[this.$route.params.slug];

      return product;
    }
  }
};
```

我们不直接赋值给`product`的原因是我们可以添加一些条件语句。为了确保只有在存储中有可用数据时才加载产品，我们可以添加一个`if()`语句来确保产品对象有可用的键；换句话说，是否已加载数据？

添加一个`if`语句来检查存储产品键的长度。如果它们存在，则将存储中的数据赋值给`product`变量以返回。

```js
const ProductPage = {
  name: 'ProductPage',
  template: `<div v-if="product">{{ product.title }}</div>`,

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {
        product = this.$store.state.products[this.$route.params.slug];
      }

      return product;
    }
  }
};
```

现在在浏览器中查看应用程序，一旦数据加载完成，您将看到产品的标题。这应该只需要一瞬间就能加载完成，并且应该由我们的`if`语句优雅地处理。

在继续显示所有产品数据之前，我们需要处理 URL 中不存在产品句柄的情况。因为我们的`ProductPage`路由会捕捉 URL 中`/product`之后的任何内容，所以无法使用`PageNotFound`通配符路径 - 因为我们的`ProductPage`组件正在加载数据并确定产品是否存在。

# 捕捉找不到的产品

为了在产品不可用时显示`PageNotFound`页面，我们将使用我们的`ProductPage`组件加载组件并有条件地显示它。

为了做到这一点，我们需要注册组件，以便在模板中使用它。我们需要注册它，因为我们的`PageNotFound`组件当前是一个对象，而不是一个 Vue 组件（例如，当我们使用`Vue.component`时）。

在`ProductPage`组件中添加一个`components`对象，并包含`PageNotFound`：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div v-if="product"><h1>{{ product.title }}</h1></div>`,

 components: {
 PageNotFound
 },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {
        product = this.$store.state.products[this.$route.params.slug];
      }

      return product;
    }
  }
};
```

现在，我们有了一个新的 HTML 元素可以在模板中使用，即`<page-not-found>`。在现有的`<div>`之后，在模板中添加此元素。由于我们的模板需要一个根元素，所以将它们都包装在一个额外的容器中：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product"><h1>{{ product.title }}</h1></div>
    <page-not-found></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },
  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {
        product = this.$store.state.products[this.$route.params.slug];
      }

      return product;
    }
  }
};
```

在浏览器中查看时，将呈现`404`页面模板，一旦数据加载完成，就会显示在其上方的产品标题。现在我们需要更新组件，只有在没有数据可显示时才显示`PageNotFound`组件。我们可以使用现有的产品变量和`v-if`属性，如果为 false，则显示错误消息，如下所示：

```js
<page-not-found v-if="!product"></page-not-found>
```

然而，这意味着如果用户在产品数据加载之前访问产品页面，他们会先看到 404 信息，然后再被替换为产品信息。这不是一个很好的用户体验，所以我们应该只在确定产品数据已加载并且没有匹配项时显示错误。

为了解决这个问题，我们将创建一个新的变量来确定组件是否显示。在`ProductPage`组件中创建一个数据函数，返回一个键为`productNotFound`的对象，将其设置为 false。在`<page-not-found>`元素中添加一个`v-if`条件，检查新的`productNotFound`变量：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product"><h1>{{ product.title }}</h1></div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

 data() {
 return {
 productNotFound: false
 }
 },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {
        product = this.$store.state.products[this.$route.params.slug];
      }

      return product;
    }
  }
};
```

最后一步是将变量设置为`true`，如果产品不存在。由于我们只想在数据加载完成后执行此操作，因此将代码添加到`$store.state.products`检查中。我们已经将数据分配给了`product`变量，因此我们可以添加一个检查以查看此变量是否存在-如果不存在，则更改我们的`productNotFound`变量的极性：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product"><h1>{{ product.title }}</h1></div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

  data() {
    return {
      productNotFound: false
    }
  },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {
        product = this.$store.state.products[this.$route.params.slug];

 if(!product) {
 this.productNotFound = true;
 }
      }

      return product;
    }
  }
};
```

尝试在 URL 末尾输入一个错误的字符串-您应该看到我们现在熟悉的`404`错误页面。

# 显示产品信息

有了我们的产品加载、过滤和错误捕捉，我们可以继续显示我们所需的产品信息。每个产品可能包含一个或多个图像，一个或多个变体以及任何组合之间的任何组合-因此我们需要确保我们为每种情况提供支持。

在`return`之前添加一个`console.log(product)`以查看我们可用的数据：

```js
product() {
  let product;

  if(Object.keys(this.$store.state.products).length) {
    product = this.$store.state.products[this.$route.params.slug];
    if(!product) {
      this.productNotFound = true;
    }
  }

  console.log(product);
  return product;
}
```

打开 JavaScript 控制台并检查应该存在的对象。熟悉可用的键和值。请注意，`images`键是一个数组，而`variations`是一个对象，包含一个字符串和一个进一步的数组。

在处理变体和图像之前-让我们输出简单的内容。我们需要记住的是，我们输出的每个字段可能不会存在于每个产品上-因此最好在必要时将其包装在条件标签中。

从产品详细信息中输出`body`，`type`和`vendor.title`。在供应商标题和类型之前添加它们的描述，但请确保仅在产品详细信息中存在时才呈现该文本：

```js
template: `<div>
  <div v-if="product">
    <h1>{{ product.title }}</h1>
    <div class="meta">
 <span>
 Manufacturer: <strong>{{ product.vendor.title }}</strong>
 </span>
 <span v-if="product.type">
 Category: <strong>{{ product.type }}</strong>
 </span>
 </div>
 {{ product.body }}
  </div>
  <page-not-found v-if="productNotFound"></page-not-found>
</div>`,
```

请注意，我们可以在类型和供应商之前添加更友好的名称。一旦我们设置好了我们的类别和过滤器，我们就可以将供应商和类型链接到适当的产品列表。

在浏览器中查看此内容将显示将所有 HTML 标签输出为文本-这意味着我们可以在页面上看到它们。如果你回想起我们在本书开头讨论输出类型时，我们需要使用`v-html`告诉 Vue 将该块呈现为原始 HTML：

```js
template: `<div>
  <div v-if="product">
    <h1>{{ product.title }}</h1>
    <div class="meta">
      <span>
        Manufacturer: <strong>{{ product.vendor.title }}</strong>
      </span>
      <span v-if="product.type">
        Category: <strong>{{ product.type }}</strong>
      </span>
    </div>
    <div v-html="product.body"></div>
  </div>
  <page-not-found v-if="productNotFound"></page-not-found>
</div>`,
```

# 产品图像

下一步是输出我们产品的图像。如果您使用的是自行车的 CSV 文件，则可以使用`650c-micro-wheelset`进行测试-导航到此产品，因为它有四个图像。不要忘记返回到原始产品以检查它是否适用于一个图像。

无论是一个图像还是 100 个图像，images 的值始终是一个数组，因此要显示它们，我们始终需要使用`v-for`。添加一个新的容器并循环遍历图像。为每个图像添加一个宽度，以免占用整个页面。

images 数组包含每个图像的对象。该对象具有`alt`和`source`键，可以直接输入到 HTML 中。然而，有些情况下`alt`值是缺失的 - 如果缺失，将产品标题插入其中：

```js
template: `<div>
  <div v-if="product">

    <div class="images" v-if="product.images.length">
 <template v-for="img in product.images">
 <img 
 :src="img.source" 
 :alt="img.alt || product.title" 
 width="100">
 </template>
 </div> 

    <h1>{{ product.title }}</h1>

    <div class="meta">
      <span>
        Manufacturer: <strong>{{ product.vendor.title }}</strong>
      </span>
      <span v-if="product.type">
        Category: <strong>{{ product.type }}</strong>
      </span>
    </div>

    <div v-html="product.body"></div>

  </div>
  <page-not-found v-if="productNotFound"></page-not-found>
</div>`,
```

在显示图像的同时，创建一个画廊会是一个不错的补充。商店通常会显示一张大图像，下面是一组缩略图。点击每个缩略图，然后替换主图像，以便用户可以更好地查看更大的图像。让我们重新创建这个功能。我们还需要确保如果只有一个图像，不显示缩略图。

我们通过将图像变量设置为 images 数组中的第一个图像来实现这一点，这是将形成大图像的图像。如果数组中有多个图像，我们将显示缩略图。然后，我们将创建一个点击方法，用选定的图像更新图像变量。

在数据对象中创建一个新变量，并在产品加载完成时使用 images 数组的第一项进行更新。在尝试分配值之前，确保`images`键实际上是一个项目数组是一个好的做法：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product">
      <div class="images" v-if="product.images.length">
        <template v-for="img in product.images">
          <img 
            :src="img.source" 
            :alt="img.alt || product.title" 
            width="100">
        </template>
      </div> 
      <h1>{{ product.title }}</h1>
      <div class="meta">
        <span>
          Manufacturer: <strong>{{ product.vendor.title }}</strong>
        </span>
        <span v-if="product.type">
          Category: <strong>{{ product.type }}</strong>
        </span>
      </div>
      <div v-html="product.body"></div>
    </div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

  data() {
    return {
      productNotFound: false,
      image: false
    }
  },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {

        product = this.$store.state.products[this.$route.params.slug];
        this.image = (product.images.length) ? product.images[0] : false;

        if(!product) {
          this.productNotFound = true;
        }
      }

      console.log(product);
      return product;
    }
  }
};
```

接下来，在模板中更新现有的图像循环，只有在数组中有多个图像时才显示。还要将第一个图像添加为模板中的主图像 - 不要忘记先检查它是否存在：

```js
template: `<div>
  <div v-if="product">

    <div class="images" v-if="image">
      <div class="main">
        <img 
 :src="image.source" 
 :alt="image.alt || product.title">
      </div>

      <div class="thumbnails" v-if="product.images.length > 1">
        <template v-for="img in product.images">
          <img 
            :src="img.source" 
            :alt="img.alt || product.title" 
            width="100">
        </template>
      </div>
    </div> 

    <h1>{{ product.title }}</h1>

    <div class="meta">
      <span>
        Manufacturer: <strong>{{ product.vendor.title }}</strong>
      </span>
      <span v-if="product.type">
        Category: <strong>{{ product.type }}</strong>
      </span>
    </div>

    <div v-html="product.body"></div>

  </div>
  <page-not-found v-if="productNotFound"></page-not-found>
</div>`,
```

最后一步是为每个缩略图像添加一个点击处理程序，以在与之交互时更新图像变量。由于图像本身不会具有`cursor: pointer`的 CSS 属性，因此考虑添加这个属性可能是值得的。

点击处理程序将是一个接受缩略图循环中的每个图像作为参数的方法。点击时，它将简单地使用传递的对象更新图像变量：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product">
      <div class="images" v-if="image">
        <div class="main">
          <img 
            :src="image.source" 
            :alt="image.alt || product.title">
        </div>

        <div class="thumbnails" v-if="product.images.length > 1">
          <template v-for="img in product.images">
            <img 
              :src="img.source" 
              :alt="img.alt || product.title" 
              width="100" 
              @click="updateImage(img)">
          </template>
        </div>
      </div> 

      <h1>{{ product.title }}</h1>

      <div class="meta">
        <span>
          Manufacturer: <strong>{{ product.vendor.title }}</strong>
        </span>
        <span v-if="product.type">
          Category: <strong>{{ product.type }}</strong>
        </span>
      </div>

      <div v-html="product.body"></div>

    </div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

  data() {
    return {
      productNotFound: false,
      image: false
    }
  },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {

        product = this.$store.state.products[this.$route.params.slug];
        this.image = (product.images.length) ? product.images[0] : false;

        if(!product) {
          this.productNotFound = true;
        }
      }

      console.log(product);
      return product;
    }
  },

  methods: {
 updateImage(img) {
 this.image = img;
 }
 }
};
```

在浏览器中加载产品，并尝试点击任何缩略图 - 您应该能够更新主图像。不要忘记在只有一个图像甚至零个图像的产品上验证您的代码，以确保用户不会遇到任何错误。

不要害怕使用空格和添加新行以提高可读性。能够轻松理解您的代码比在文件加载时节省几个字节更重要。在部署到生产环境时，文件应该被压缩，但在开发过程中，空白占据主导地位。

# 产品变体

对于这个特定的数据集，我们的每个产品至少包含一个变体，但可以包含多个变体。这通常与图像数量相对应，但并不总是相关的。变体可以是颜色或尺寸等。

在我们的`Product`对象上，我们有两个键将帮助我们显示变体。它们是`variationTypes`，列出了变体的名称，如尺寸和颜色，以及`variationProducts`，其中包含所有的变体。`variationProducts`对象中的每个产品都有一个更进一步的`variant`对象，列出了所有可变的属性。例如，如果一件夹克有两种颜色，每种颜色有三种尺寸，那么将有六个`variationProducts`，每个产品都有两个`variant`属性。

每个产品都将包含至少一个变体，尽管如果只有一个变体，我们可能需要考虑产品页面的用户体验。我们将在表格和下拉菜单中显示产品的变体，这样您就可以体验创建这两个元素。

# 变体显示表格

在产品模板中创建一个新的容器，用于显示变体。在此容器中，我们可以创建一个表格来显示产品的不同变体。这将通过`v-for`声明来实现。然而，现在您对功能更加熟悉，我们可以引入一个新的属性。

# 使用循环键

在 Vue 中使用循环时，建议您使用额外的属性来标识每个项，即`:key`。这有助于 Vue 在重新排序、排序或过滤时识别数组的元素。使用`:key`的示例如下：

```js
<div v-for="item in items" :key="item.id">
  {{ item.title }}
</div>
```

键属性应该是项本身的唯一属性，而不是数组中的项的索引，以帮助 Vue 识别特定的对象。有关使用循环键的更多信息，请参阅[官方 Vue 文档](https://vuejs.org/v2/guide/list.html#key)。

在显示变体时，我们将使用`key`属性，但使用`barcode`属性。

# 在表格中显示变体

在您的变体容器中添加一个表格元素，并循环遍历`items`数组。现在，显示`title`、`quantity`和`price`。添加一个包含值为“添加到购物篮”的按钮的额外单元格。我们将在第十一章“构建电子商务商店 - 添加结账”中进行配置。不要忘记在价格前面添加`$`货币符号，因为它目前只是一个“原始”数字。

注意 - 当在模板文字中使用`$`符号时，JavaScript 将尝试解释它，以及花括号，作为 JavaScript 变量。为了抵消这一点，用反斜杠在货币前面 - 这告诉 JavaScript 下一个字符是字面的，不应以任何其他方式解释：

```js
template: `<div>
  <div v-if="product">
    <div class="images" v-if="image">
      <div class="main">
        <img 
          :src="image.source" 
          :alt="image.alt || product.title">
      </div>

      <div class="thumbnails" v-if="product.images.length > 1">
        <template v-for="img in product.images">
          <img 
            :src="img.source" 
            :alt="img.alt || product.title" 
            width="100" 
            @click="updateImage(img)">
        </template>
      </div>
    </div> 

    <h1>{{ product.title }}</h1>

    <div class="meta">
      <span>
        Manufacturer: <strong>{{ product.vendor.title }}</strong>
      </span>
      <span v-if="product.type">
        Category: <strong>{{ product.type }}</strong>
      </span>
    </div>

    <div class="variations">
 <table>
 <tr v-for="variation in product.variationProducts" :key="variation.barcode">
 <td>{{ variation.quantity }}</td>
 <td>\${{ variation.price }}</td>
 <td><button>Add to basket</button></td>
 </tr>
 </table>
 </div>

    <div v-html="product.body"></div>

  </div>
  <page-not-found v-if="productNotFound"></page-not-found>
</div>`,
```

尽管我们显示了价格和数量，但我们没有输出变体的实际属性（如颜色）。为了做到这一点，我们需要对变体进行一些处理，使用一个方法。

变体对象包含每个变体类型的子对象，每个类型都有一个名称和一个值。它们还以 slug 转换后的键存储在对象中。有关更多详细信息，请参见以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/28be9090-e8ff-4446-a407-dc2a0dad9ded.png)

在表格开头添加一个新的单元格，将变体传递给名为`variantTitle()`的方法：

```js
<div class="variations">
  <table>
    <tr v-for="variation in product.variationProducts" :key="variation.barcode">
      <td>{{ variantTitle(variation) }}</td>
      <td>{{ variation.quantity }}</td>
      <td>\${{ variation.price }}</td>
      <td><button>Add to basket</button></td>
    </tr>
  </table>
</div>
```

在`methods`对象中创建新的方法：

```js
methods: {
  updateImage(img) {
    this.image = img;
  },

 variantTitle(variation) {

 }
}
```

现在，我们需要构建一个包含变体标题的字符串，显示所有可用选项。为此，我们将构建一个包含每个类型的数组，然后将它们连接成一个字符串。

将`variants`存储为一个变量，并创建一个空数组。现在我们可以循环遍历`variants`对象中可用的键，并创建一个输出字符串。如果您决定在字符串中添加 HTML，如下面的示例所示，我们需要更新模板以输出 HTML 而不是原始字符串：

```js
variantTitle(variation) {
  let variants = variation.variant,
 output = [];

 for(let a in variants) {
 output.push(`<b>${variants[a].name}:</b> ${variants[a].value}`);
 } 
}
```

我们的输出数组将有一个项目，格式如下：

```js
["<b>Color:</b> Alloy", "<b>Size:</b> 49 cm"]
```

现在我们可以将它们连接在一起，将输出从数组转换为字符串。您可以选择使用的字符、字符串或 HTML 取决于您。现在，使用两边带有空格的`/`。或者，您可以使用`</td><td>`标签创建一个新的表格单元格。添加`join()`函数并更新模板以使用`v-html`：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product">
      <div class="images" v-if="image">
        <div class="main">
          <img 
            :src="image.source" 
            :alt="image.alt || product.title">
        </div>

        <div class="thumbnails" v-if="product.images.length > 1">
          <template v-for="img in product.images">
            <img 
              :src="img.source" 
              :alt="img.alt || product.title" 
              width="100" 
              @click="updateImage(img)">
          </template>
        </div>
      </div> 

      <h1>{{ product.title }}</h1>

      <div class="meta">
        <span>
          Manufacturer: <strong>{{ product.vendor.title }}</strong>
        </span>
        <span v-if="product.type">
          Category: <strong>{{ product.type }}</strong>
        </span>
      </div>

      <div class="variations">
        <table>
          <tr v-for="variation in product.variationProducts" :key="variation.barcode">
            <td v-html="variantTitle(variation)"></td>
            <td>{{ variation.quantity }}</td>
            <td>\${{ variation.price }}</td>
            <td><button>Add to basket</button></td>
          </tr>
        </table>
      </div>

      <div v-html="product.body"></div>

    </div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

  data() {
    return {
      productNotFound: false,
      image: false
    }
  },

  computed: {
    ...
  },

  methods: {
    updateImage(img) {
      this.image = img;
    },

    variantTitle(variation) {
      let variants = variation.variant,
        output = [];

      for(let a in variants) {
        output.push(`<b>${variants[a].name}:</b> ${variants[a].value}`);
      }

      return output.join(' / ');
    }

  }
};
```

将点击事件附加到“添加到购物篮”按钮，并在组件上创建一个新的方法。此方法将需要传入`variation`对象，以便将正确的对象添加到购物篮中。现在，添加一个 JavaScript `alert()`来确认您是否选择了正确的对象：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product">
      <div class="images" v-if="image">
        <div class="main">
          <img 
            :src="image.source" 
            :alt="image.alt || product.title">
        </div>

        <div class="thumbnails" v-if="product.images.length > 1">
          <template v-for="img in product.images">
            <img 
              :src="img.source" 
              :alt="img.alt || product.title" 
              width="100" 
              @click="updateImage(img)">
          </template>
        </div>
      </div> 

      <h1>{{ product.title }}</h1>

      <div class="meta">
        <span>
          Manufacturer: <strong>{{ product.vendor.title }}</strong>
        </span>
        <span v-if="product.type">
          Category: <strong>{{ product.type }}</strong>
        </span>
      </div>

      <div class="variations">
        <table>
          <tr v-for="variation in product.variationProducts" :key="variation.barcode">
            <td v-html="variantTitle(variation)"></td>
            <td>{{ variation.quantity }}</td>
            <td>\${{ variation.price }}</td>
            <td><button @click="addToBasket(variation)">Add to basket</button></td>
          </tr>
        </table>
      </div>

      <div v-html="product.body"></div>

    </div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

  data() {
    return {
      productNotFound: false,
      image: false
    }
  },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {

        product = this.$store.state.products[this.$route.params.slug];
        this.image = (product.images.length) ? product.images[0] : false;

        if(!product) {
          this.productNotFound = true;
        }
      }

      console.log(product);
      return product;
    }
  },

  methods: {
    updateImage(img) {
      this.image = img;
    },

    variantTitle(variation) {
      let variants = variation.variant,
        output = [];

      for(let a in variants) {
        output.push(`<b>${variants[a].name}:</b> ${variants[a].value}`);
      }

      return output.join(' / ');
    },

    addToBasket(variation) {
 alert(`Added to basket: ${this.product.title} - ${this.variantTitle(variation)}`);
 }

  }
};
```

注意在警告框中使用的模板字面量-这允许我们使用 JavaScript 变量，而无需使用字符串连接技术。现在，点击“添加到购物篮”按钮将生成一个弹出窗口，列出产品的名称和所点击的变体。

# 在选择框中显示变体

产品页面上更常见的界面模式是在下拉列表或选择框中显示和选择您的变体。

使用选择框时，我们将有一个变体，它要么是默认选择的，要么是用户已经与之交互并专门选择的。因此，当用户更改选择框时，我们可以更改图像，并在产品页面上显示有关变体的其他信息，包括价格和数量。

我们不会依赖于将变体传递给`addToBasket`方法，因为它将作为产品组件上的一个对象存在。

将您的`<table>`元素更新为`<select>`，将`<tr>`更新为`<option>`。将按钮移动到此元素之外，并从`click`事件中删除参数。从`variantTitle()`方法中删除任何 HTML。因为它现在在选择框内，所以不需要它。

```js
<div class="variations">
 <select>
 <option 
 v-for="variation in product.variationProducts" 
 :key="variation.barcode" 
 v-html="variantTitle(variation)"
 ></option>
 </select>

  <button @click="addToBasket()">Add to basket</button>
</div>
```

下一步是创建一个新的变量，可供组件使用。与图片类似，这将在`variationProducts`数组的第一项完成，并在选择框更改时进行更新。

在数据对象中创建一个名为`variation`的新项。在数据加载到`product`计算变量中时填充此变量：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `...`,

  components: {
    PageNotFound
  },

  data() {
    return {
      productNotFound: false,
      image: false,
      variation: false
    }
  },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {

        product = this.$store.state.products[this.$route.params.slug];

        this.image = (product.images.length) ? product.images[0] : false;
        this.variation = product.variationProducts[0];

        if(!product) {
          this.productNotFound = true;
        }
      }

      console.log(product);
      return product;
    }
  },

  methods: {
    ...
  }
};
```

更新`addToBasket`方法，使用`ProductPage`组件的`variation`变量，而不是依赖于参数：

```js
addToBasket() {
  alert(`Added to basket: ${this.product.title} - ${this.variantTitle(this.variation)}`);
}
```

尝试点击“添加到购物篮”按钮-它应该添加第一个变体，而不管在下拉列表中选择了什么。为了在更改时更新变量，我们可以将`variations`变量绑定到选择框上-就像我们在本书开始时对文本框进行过滤一样。

在`select`元素上添加`v-model`属性。当选择时，我们还需要告诉 Vue 要绑定到此变量的内容。默认情况下，它将使用`<option>`的内容，即我们当前的自定义变体标题。但是，我们希望绑定整个`variation`对象。在`<option>`元素上添加一个`:value`属性：

```js
<div class="variations">
  <select v-model="variation">
    <option 
      v-for="variation in product.variationProducts" 
      :key="variation.barcode" 
      :value="variation"
      v-html="variantTitle(variation)"
    ></option>
  </select>

  <button @click="addToBasket()">Add to basket</button>
</div>
```

更改选择框并单击“添加到购物篮”按钮现在将生成正确的变体。这种方法使我们在表格中显示变体更加灵活。

它允许我们在产品的其他位置显示变体数据。尝试在产品标题旁边添加价格，并在`meta`容器中显示数量：

```js
template: `<div>
  <div v-if="product">
    <div class="images" v-if="image">
      <div class="main">
        <img 
          :src="image.source" 
          :alt="image.alt || product.title">
      </div>

      <div class="thumbnails" v-if="product.images.length > 1">
        <template v-for="img in product.images">
          <img 
            :src="img.source" 
            :alt="img.alt || product.title" 
            width="100" 
            @click="updateImage(img)">
        </template>
      </div>
    </div> 

    <h1>{{ product.title }} - \${{ variation.price }}</h1>

    <div class="meta">
      <span>
        Manufacturer: <strong>{{ product.vendor.title }}</strong>
      </span>
      <span v-if="product.type">
        Category: <strong>{{ product.type }}</strong>
      </span>
      <span>
 Quantity: <strong>{{ variation.quantity }}</strong>
 </span>
    </div>

    <div class="variations">
      <select v-model="variation">
        <option 
          v-for="variation in product.variationProducts" 
          :key="variation.barcode" 
          :value="variation"
          v-html="variantTitle(variation)"
        ></option>
      </select>

      <button @click="addToBasket()">Add to basket</button>
    </div>

    <div v-html="product.body"></div>

  </div>
  <page-not-found v-if="productNotFound"></page-not-found>
</div>`,
```

这两个新属性将在更改变体时更新。如果有选择的变体，则还可以更新图像。为此，请在组件中添加一个`watch`对象，该对象监视变体变量。更新后，我们可以检查变体是否有图像，如果有，则使用此属性更新图像变量：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `...`,

  components: {
    ...
  },

  data() {
    ...
  },

  computed: {
    ...
  },

 watch: {
 variation(v) {
 if(v.hasOwnProperty('image')) {
 this.updateImage(v.image);
 }
 }
 },

  methods: {
    ...
  }
};
```

在使用`watch`时，函数将新项作为第一个参数传递。我们可以使用此参数来收集图像信息，而不是引用组件上的参数。

我们可以进行的另一个改进是，如果变体缺货，则禁用“添加到购物篮”按钮并在下拉菜单中添加注释。此信息从变体的`quantity`键中获取。

检查数量，如果小于 1，则在选择框中显示缺货消息，并使用`disabled` HTML 属性禁用“添加到购物篮”按钮。我们还可以更新按钮的值：

```js
template: `<div>
    <div v-if="product">
      <div class="images" v-if="image">
        <div class="main">
          <img 
            :src="image.source" 
            :alt="image.alt || product.title">
        </div>

        <div class="thumbnails" v-if="product.images.length > 1">
          <template v-for="img in product.images">
            <img 
              :src="img.source" 
              :alt="img.alt || product.title" 
              width="100" 
              @click="updateImage(img)">
          </template>
        </div>
      </div> 

      <h1>{{ product.title }} - \${{ variation.price }}</h1>

      <div class="meta">
        <span>
          Manufacturer: <strong>{{ product.vendor.title }}</strong>
        </span>
        <span v-if="product.type">
          Category: <strong>{{ product.type }}</strong>
        </span>
        <span>
          Quantity: <strong>{{ variation.quantity }}</strong>
        </span>
      </div>

      <div class="variations">
        <select v-model="variation">
          <option 
            v-for="variation in product.variationProducts" 
            :key="variation.barcode" 
            :value="variation"
            v-html="variantTitle(variation) + ((!variation.quantity) ? ' - out of stock' : '')"
          ></option>
        </select>

        <button @click="addToBasket()" :disabled="!variation.quantity">
          {{ (variation.quantity) ? 'Add to basket' : 'Out of stock' }}
        </button>
      </div>

      <div v-html="product.body"></div>

    </div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,
```

如果使用`bicycles.csv`数据集，则 Keirin Pro Track Frameset 产品（`/#/product/keirin-pro-track-frame`）包含几种变体，其中一些没有库存。这样可以测试“缺货”功能以及图像更改。

我们可以对产品页面进行的另一项操作是仅在存在多个变体时显示下拉菜单。一个只有一个变体的产品的示例是 15 mm Combo 扳手（`#/product/15mm-combo-wrench`）。在这种情况下，显示`<select>`框没有意义。由于我们在加载时在`Product`组件上设置了`variation`变量，因此我们不依赖于选择来最初设置变量。因此，当只有一个备选产品时，我们可以使用`v-if=""`完全删除选择框。

与图像一样，检查数组的长度是否大于 1，这次是`variationProducts`数组：

```js
<div class="variations">
  <select v-model="variation" v-if="product.variationProducts.length > 1">
    <option 
      v-for="variation in product.variationProducts" 
      :key="variation.barcode" 
      :value="variation"
      v-html="variantTitle(variation) + ((!variation.quantity) ? ' - out of stock' : '')"
    ></option>
  </select>

  <button @click="addToBasket()" :disabled="!variation.quantity">
    {{ (variation.quantity) ? 'Add to basket' : 'Out of stock' }}
  </button>
</div>
```

通过在不需要时删除元素，我们现在有了一个更简洁的界面。

# 在切换 URL 时更新产品详细信息

在浏览不同的产品 URL 以检查变体时，您可能已经注意到点击后退和前进不会更新页面上的产品数据。

这是因为`Vue-router`意识到在页面之间使用相同的组件，所以它不会销毁和创建一个新实例，而是重用组件。这样做的缺点是数据不会更新；我们需要触发一个函数来包含新的产品数据。好处是代码更高效。

为了告诉 Vue 检索新数据，我们需要创建一个`watch`函数；而不是观察一个变量，我们将观察`$route`变量。当它更新时，我们可以加载新数据。

在数据实例的`slug`中创建一个新变量，并将默认值设置为路由参数。更新`product`计算函数以使用此变量而不是路由：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `...`,

  components: {
    PageNotFound
  },

  data() {
    return {
      slug: this.$route.params.slug,
      productNotFound: false,
      image: false,
      variation: false
    }
  },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {

        product = this.$store.state.products[this.slug];

        this.image = (product.images.length) ? product.images[0] : false;
        this.variation = product.variationProducts[0];

        if(!product) {
          this.productNotFound = true;
        }
      }

      console.log(product);
      return product;
    }
  },

  watch: {
    ...
  },

  methods: {
    ...
  }
};
```

现在我们可以创建一个`watch`函数，监视`$route`变量。当它改变时，我们可以更新`slug`变量，从而更新显示的数据。

在观察路由时，函数有两个参数传递给它：`to`和`from`。`to`变量包含有关我们要去的路由的所有内容，包括参数和使用的组件。`from`变量包含有关当前路由的所有内容。

通过在路由更改时将`slug`变量更新为新参数，我们强制组件使用来自存储的新数据重新绘制：

```js
const ProductPage = {
  name: 'ProductPage',

  template: `<div>
    <div v-if="product">
      <div class="images" v-if="image">
        <div class="main">
          <img 
            :src="image.source" 
            :alt="image.alt || product.title">
        </div>

        <div class="thumbnails" v-if="product.images.length > 1">
          <template v-for="img in product.images">
            <img 
              :src="img.source" 
              :alt="img.alt || product.title" 
              width="100" 
              @click="updateImage(img)">
          </template>
        </div>
      </div> 

      <h1>{{ product.title }} - \${{ variation.price }}</h1>

      <div class="meta">
        <span>
          Manufacturer: <strong>{{ product.vendor.title }}</strong>
        </span>
        <span v-if="product.type">
          Category: <strong>{{ product.type }}</strong>
        </span>
        <span>
          Quantity: <strong>{{ variation.quantity }}</strong>
        </span>
      </div>

      <div class="variations">
        <select v-model="variation" v-if="product.variationProducts.length > 1">
          <option 
            v-for="variation in product.variationProducts" 
            :key="variation.barcode" 
            :value="variation"
            v-html="variantTitle(variation) + ((!variation.quantity) ? ' - out of stock' : '')"
          ></option>
        </select>

        <button @click="addToBasket()" :disabled="!variation.quantity">
          {{ (variation.quantity) ? 'Add to basket' : 'Out of stock' }}
        </button>
      </div>

      <div v-html="product.body"></div>

    </div>
    <page-not-found v-if="productNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

  data() {
    return {
      slug: this.$route.params.slug,
      productNotFound: false,
      image: false,
      variation: false
    }
  },

  computed: {
    product() {
      let product;

      if(Object.keys(this.$store.state.products).length) {

        product = this.$store.state.products[this.slug];

        this.image = (product.images.length) ? product.images[0] : false;
        this.variation = product.variationProducts[0];

        if(!product) {
          this.productNotFound = true;
        }
      }

      return product;
    }
  },

  watch: {
    variation(v) {
      if(v.hasOwnProperty('image')) {
        this.updateImage(v.image);
      }
    },

    '$route'(to) {
 this.slug = to.params.slug;
 }
  },

  methods: {
    updateImage(img) {
      this.image = img;
    },

    variantTitle(variation) {
      let variants = variation.variant,
        output = [];

      for(let a in variants) {
        output.push(`${variants[a].name}: ${variants[a].value}`);
      }

      return output.join(' / ');
    },

    addToBasket() {
      alert(`Added to basket: ${this.product.title} - ${this.variantTitle(this.variation)}`);
    }

  }
};
```

完成产品页面后，我们可以继续创建一个类别列表，包括`type`和`vendor`变量。还要删除代码中的任何`console.log()`调用，以保持代码整洁。

# 总结

本章涵盖了很多内容。我们将产品的 CSV 文件加载并存储到 Vuex 存储中。从那里，我们创建了一个产品详细页面，该页面使用 URL 中的动态变量加载特定产品。我们创建了一个产品详细视图，允许用户浏览图库并从下拉列表中选择变体。如果变体有关联的图像，主图像会更新。

在第十章《构建电子商务商店-浏览产品》中，

我们将创建一个分类页面，创建过滤和排序功能，帮助用户找到他们想要的产品。


# 第十章：构建电子商务商店-浏览产品

在第九章中，我们将产品数据加载到 Vuex 存储中，并创建了一个产品详细页面，用户可以在该页面查看产品及其变体。在查看产品详细页面时，用户可以从下拉菜单中更改变体，价格和其他详细信息将更新。

在本章中，我们将：

+   创建一个具有特定产品的主页列表页面

+   创建一个具有可重用组件的类别页面

+   创建一个排序机制

+   动态创建过滤器，并允许用户过滤产品

# 列出产品

在创建任何过滤、精选列表、排序组件和功能之前，我们需要创建一个基本的产品列表-首先显示所有产品，然后我们可以创建一个分页组件，然后在整个应用程序中重复使用它。

# 添加一个新的路由

让我们向我们的`routes`数组添加一个新的路由。现在，我们将在`HomePage`组件上工作，它将有一个`/`路由。确保将其添加到`routes`数组的顶部，这样它就不会被其他组件覆盖：

```js
const router = new VueRouter({
  routes: [
 {
 path: '/',
 name: 'Home',
 component: HomePage
 },
    {
      path: '/product/:slug', 
      component: ProductPage
    },

    {
      path: '/404', 
      alias: '*',
      component: PageNotFound
    }
  ]
});
```

在`HomePage`组件内部，创建一个新的`computed`属性，并从`store`中收集所有产品。在模板中显示任何内容之前，请确保产品已加载。使用以下代码填充`HomePage`组件：

```js
const HomePage = {
  name: 'HomePage',

  template: `<div v-if="products"></div>`,

  computed: {
 products() {
 return this.$store.state.products;
 }
 }
};
```

# 循环遍历产品

在查看任何商店的类别列表时，显示的数据往往具有重复的主题。通常包括图像、标题、价格和制造商。

在模板中添加一个有序列表-由于产品将按顺序排列，将它们放在有序列表中在语义上是有意义的。在`<ol>`中，添加一个`v-for`循环遍历产品，并显示每个产品的标题，如下所示。在继续显示之前，确保`product`变量存在也是一个好习惯：

```js
template: `<div v-if="products">
  <ol>
 <li v-for="product in products" v-if="product">
 <h3>{{ product.title }}</h3>
 </li>
 </ol>
</div>`,
```

在浏览器中查看页面时，您可能会注意到产品列表非常长。为所有这些产品加载图像将对用户的计算机造成巨大负担，并且会用那么多产品来压倒用户。在向我们的模板添加更多信息（如价格和图像）之前，我们将查看对产品进行分页，允许以更可管理的方式访问数据。

# 创建分页

创建分页，最初似乎相当简单——只需要返回一定数量的产品即可。然而，如果我们希望使我们的分页与产品列表交互并对其进行响应，它就需要更加先进一些。我们需要构建我们的分页能够处理不同长度的产品——在产品列表被过滤为较少产品的情况下。

# 计算数值

创建分页组件和显示正确产品的算术依赖于四个主要变量：

+   **每页项目数**：通常由用户设置；然而，我们将首先使用一个固定的数值 12

+   **总项目数**：这是要显示的产品总数

+   **页数**：这可以通过将产品数除以每页项目数来计算得到

+   **当前页码**：这个与其他变量结合起来，将允许我们返回我们需要的确切产品

通过这些数字，我们可以计算出我们分页所需的一切。这包括要显示的产品、是否显示下一页/上一页链接，以及如果需要的话，跳转到不同链接的组件。

在继续之前，我们将把我们的`products`对象转换成一个数组。这样我们就可以在其上使用 split 方法，从而返回一个特定的产品列表。这也意味着我们可以很容易地计算出总项目数。

更新你的`products`计算函数，将其返回一个数组而不是一个对象。这可以通过使用`map()`函数来实现——这是一个 ES2015 中用来替代简单`for`循环的函数。这个函数现在返回一个包含产品对象的数组：

```js
products() {
  let products = this.$store.state.products;
 return Object.keys(products).map(key => products[key]);
},
```

在计算对象中创建一个名为`pagination`的新函数。这个函数将返回一个包含有关我们分页的各种数据的对象，例如总页数。这将允许我们创建一个产品列表并更新导航组件。只有在我们的`products`变量有数据时才需要返回这个对象。下面的代码片段显示了这个函数：

```js
computed: {
  products() {
    let products = this.$store.state.products;
    return Object.keys(products).map(key => products[key]);
  },

  pagination() {
 if(this.products) {

 return {

 }
 }
 }
},
```

现在我们需要跟踪两个变量——每页项目数和当前页码。在你的`HomePage`组件上创建一个`data`函数并存储这两个变量。我们将在稍后给用户更新`perPage`变量的能力。下面的代码部分显示了我们的`data`函数：

```js
const HomePage = {
  name: 'HomePage',

  template: `...`,

 data() {
 return {
 perPage: 12, 
 currentPage: 1
 }
 },

  computed: {
    ...
  }
};
```

你可能想知道何时在组件上使用本地数据，何时将信息存储在 Vuex 存储中。这完全取决于您将在何处使用数据以及将对其进行何种操作。一般规则是，如果只有一个组件使用数据并对其进行操作，则使用本地的`data()`函数。然而，如果有多个组件将与变量进行交互，则将其保存在中央存储中。

回到`pagination()`计算函数，存储一个变量，其值为`products`数组的长度。有了这个变量，我们现在可以计算总页数。为了做到这一点，我们将进行以下方程计算：

*产品总数 / 每页项目数*

一旦我们得到了这个结果，我们需要将其四舍五入到最近的整数。这是因为如果有任何余数，我们需要为其创建一个新页面。

例如，如果您每页显示 12 个项目，并且您有 14 个产品，那么结果将是 1.1666 页-这不是一个有效的页码。将其四舍五入确保我们有两个页面来显示我们的产品。为此，使用`Math.ceil()` JavaScript 函数。我们还可以将产品的总数添加到输出中。请查看以下代码以使用`Math.ceil()`函数：

```js
pagination() {
  if(this.products) {
    let totalProducts = this.products.length;

    return {
 totalProducts: totalProducts,
 totalPages: Math.ceil(totalProducts / this.perPage)
    }
  }
}
```

我们需要做的下一个计算是确定当前页面的产品范围是什么。这有点复杂，因为我们不仅需要确定我们从页码中需要什么，而且数组切片是基于项目索引的-这意味着第一个项目是`0`。

为了确定从哪里获取切片，我们可以使用以下计算：

*(当前页码 * 每页项目数) - 每页项目数*

最后的减法可能看起来很奇怪，但它意味着在第一页上，结果是 0。这使我们能够计算出我们需要从`products`数组中切片的索引位置。

举个例子，如果我们在第三页，结果将是 24，这是第三页的起始位置。切片的结束位置是这个结果加上每页的项目数。这种方法的优点是我们可以更新每页的项目数，所有的计算都会更新。

在`pagination`结果中创建一个对象，其中包含这两个结果-这将使我们以后可以轻松访问它们：

```js
pagination() {
  if(this.products) {
    let totalProducts = this.products.length,
      pageFrom = (this.currentPage * this.perPage) - this.perPage;

    return {
      totalProducts: totalProducts,
      totalPages: Math.ceil(totalProducts / this.perPage),
      range: {
 from: pageFrom,
 to: pageFrom + this.perPage
 }
    }
  }
}
```

# 显示分页列表

计算出我们的分页属性后，我们现在可以使用起始点和结束点来操作我们的`products`数组。我们将使用一个方法来截断产品列表，而不是使用硬编码的值或使用另一个计算函数。这样做的好处是可以传递任何产品列表，并且意味着 Vue 不会缓存结果。

在组件中创建一个新的方法对象，其中包含一个名为`paginate`的新方法。这个方法应该接受一个参数，这个参数将是我们要切片的`products`数组。在函数内部，我们可以使用之前计算的两个变量来返回正确数量的产品：

```js
methods: {
  paginate(list) {
    return list.slice(
      this.pagination.range.from, 
      this.pagination.range.to
    );
  }
}
```

更新模板以在循环遍历产品时使用此方法：

```js
template: `<div v-if="products">
  <ol>
    <li v-for="product in paginate(products)" v-if="product">
      <h3>{{ product.title }}</h3>
    </li>
  </ol>
</div>`,
```

现在我们可以在浏览器中查看它，并注意它返回我们对象中的前 12 个产品。在`data`对象中更新`currentPage`变量为 2 或 3 将显示不同的产品列表，具体取决于数量。

为了继续我们对产品列表的语义化方法，当不在第一页时，我们应该更新有序列表的起始位置。这可以使用`start`的 HTML 属性来完成 - 这允许您指定应该从哪个数字开始有序列表。

使用`pagination.range.from`变量来设置有序列表的起始点 - 记住在第一页上要添加`1`，因为它将是`0`：

```js
template: `<div v-if="products">
  <ol :start="pagination.range.from + 1">
    <li v-for="product in paginate(products)" v-if="product">
      <h3>{{ product.title }}</h3>
    </li>
  </ol>
</div>`
```

现在在代码中递增页面编号时，您会注意到有序列表从每个页面的适当位置开始。

# 创建分页按钮。

通过代码更新页面编号不够用户友好，所以我们应该添加一些页面来增加和减少页面编号变量。为此，我们将创建一个函数，将`currentPage`变量更改为其值。这样我们就可以同时用于“下一页”和“上一页”按钮，以及一个带有编号的页面列表（如果需要）。

首先，在您的`pagination`容器中创建两个按钮。如果我们处于导航的极限位置，我们希望禁用这些按钮 - 例如，当返回时，您不希望能够低于`1`，并且在向前时超过最大页面数。我们可以通过在按钮上设置`disabled`属性来实现这一点 - 就像我们在产品详细信息页面上所做的，并将当前页面与这些限制进行比较。

在上一页按钮上添加`disabled`属性，并检查当前页面是否为第一页。在下一页按钮上，将其与我们的`pagination`方法的`totalPages`值进行比较。实现前面提到的属性的代码如下所示：

```js
<button :disabled="currentPage == 1">Previous page</button>
<button :disabled="currentPage == pagination.totalPages">Next page</button>
```

将`currentPage`变量设置回`1`，并在浏览器中加载主页。您会注意到上一页按钮被禁用了。如果您更改了`currentPage`变量，您会注意到按钮会按预期地变为激活或非激活状态。

现在我们需要为按钮创建一个点击方法来更新`currentPage`。创建一个名为`toPage()`的新函数。它应该接受一个变量 - 这将直接更新`currentPage`变量：

```js
methods: {
 toPage(page) {
 this.currentPage = page;
 },

  paginate(list) {
    return list.slice(this.pagination.range.from, this.pagination.range.to);
  }
}
```

为按钮添加点击处理程序，对于下一页按钮，传递`currentPage + 1`，对于上一页按钮，传递`currentPage - 1`：

```js
template: `<div v-if="products">
  <button @click="toPage(currentPage - 1)" :disabled="currentPage == 1">Previous page</button>
  <button @click="toPage(currentPage + 1)" :disabled="currentPage == pagination.totalPages">Next page</button>

  <ol :start="pagination.range.from + 1">
    <li v-for="product in paginate(products)" v-if="product">
      <h3>{{ product.title }}</h3>
    </li>
  </ol>
</div>`
```

现在我们可以在产品之间来回导航了。作为用户界面的一个很好的补充，我们可以使用代码中提到的可用变量来指示页面编号和剩余页面数量：

```js
template: `<div v-if="products">
  <p>
 Page {{ currentPage }} out of {{ pagination.totalPages }}
 </p>
  <button @click="toPage(currentPage - 1)" :disabled="currentPage == 1">Previous page</button>
  <button @click="toPage(currentPage + 1)" :disabled="currentPage == pagination.totalPages">Next page</button>

  <ol :start="pagination.range.from + 1">
    <li v-for="product in paginate(products)" v-if="product">
      <h3>{{ product.title }}</h3>
    </li>
  </ol>
</div>`
```

# 在导航时更新 URL

改进用户体验的另一个方法是在页面导航时更新 URL - 这将允许用户分享 URL、将其加入书签并稍后返回。在分页时，页面是一个*临时*状态，不应该是 URL 的主要终点。相反，我们可以利用 Vue 路由的查询参数。

更新`toPage`方法，在页面更改时将参数添加到 URL 中。这可以通过使用`$router.push`来实现，但是，我们需要小心，不要删除可能用于将来的过滤的任何现有参数。这可以通过将路由的当前查询对象与包含`page`变量的新对象合并来实现：

```js
toPage(page) {
  this.$router.push({
 query: Object.assign({}, this.$route.query, {
 page
 })
 }); 
  this.currentPage = page;
},
```

在从页面到页面的导航过程中，您会注意到 URL 获取了一个新的参数`?page=`，其值等于当前页面的名称。然而，按下刷新按钮将不会得到正确的页面结果，而是重新回到第一页。这是因为我们需要将当前的`page`查询参数传递给我们的`HomePage`组件中的`currentPage`变量。

这可以通过`created()`函数来完成 - 更新变量 - 确保我们首先检查了它的存在。`created`函数是 Vue 生命周期的一部分，在第四章中有介绍，*使用 Dropbox API 获取文件列表*：

```js
created() {
 if(this.$route.query.page) {
 this.currentPage = parseInt(this.$route.query.page);
 }
}
```

我们需要确保`currentPage`变量是一个整数，以帮助我们进行后续的算术运算，因为`string`不喜欢计算。

# 创建分页链接

在查看分页产品时，通常最好的做法是有一个截断的页面数字列表，允许用户跳转到多个页面。我们已经有了在页面之间导航的机制 - 这可以扩展它。

作为一个简单的入口点，我们可以通过循环直到达到`totalPages`值来为每个页面创建一个链接。Vue 允许我们在没有任何 JavaScript 的情况下做到这一点。在组件底部创建一个带有列表的`nav`元素。使用`v-for`，并为`totalPages`变量中的每个项目创建一个`page`变量：

```js
<nav>
  <ol>
    <li v-for="page in pagination.totalPages">
      <button @click="toPage(page)">{{ page }}</button>
    </li>
  </ol>
</nav>
```

这将为每个页面创建一个按钮 - 例如，如果总共有 24 个页面，这将创建 24 个链接。这不是期望的效果，因为我们希望在当前页面之前和之后显示几个页面。例如，如果当前页面是 15，页面链接应该是 12、13、14、15、16、17 和 18。这意味着链接较少，对用户来说不那么压倒性。

首先，在`data`对象中创建一个新变量，用于记录选定页面两侧要显示的页面数量 - 一个好的起始值是三：

```js
data() {
  return {
    perPage: 12, 
    currentPage: 1,
    pageLinksCount: 3
  }
},
```

接下来，创建一个名为`pageLinks`的新计算函数。这个函数需要获取当前页面，并计算出比它小三个和比它大三个的页面数字。从那里，我们需要检查较低范围是否小于 1，较高范围是否大于总页数。在继续之前，检查产品数组是否有项目：

```js
pageLinks() {
  if(this.products.length) {
    let negativePoint = parseInt(this.currentPage) - this.pageLinksCount,
      positivePoint = parseInt(this.currentPage) + this.pageLinksCount;

    if(negativePoint < 1) {
      negativePoint = 1;
    }

    if(positivePoint > this.pagination.totalPages) {
      positivePoint = this.pagination.totalPages;
    }

    return pages;
  }
}
```

最后一步是创建一个数组和一个`for`循环，从较低范围循环到较高范围。这将创建一个包含最多七个数字的页面范围的数组：

```js
pageLinks() {
  if(this.products.length) {
    let negativePoint = parseInt(this.currentPage) - this.pageLinksCount,
      positivePoint = parseInt(this.currentPage) + this.pageLinksCount,
      pages = [];

    if(negativePoint < 1) {
      negativePoint = 1;
    }

    if(positivePoint > this.pagination.totalPages) {
      positivePoint = this.pagination.totalPages;
    }

    for (var i = negativePoint; i <= positivePoint; i++) {
 pages.push(i)
 }

 return pages;
  }
}
```

现在，我们可以用新的`pageLinks`变量替换导航组件中的`pagination.totalPages`变量，将创建正确数量的链接，如下所示：

```js
<nav>
  <ul>
    <li v-for="page in pageLinks">
      <button @click="toPage(page)">{{ page }}</button>
    </li>
  </ul>
</nav>
```

然而，在浏览器中查看时，会呈现一些奇怪的行为。虽然会生成正确数量的链接，但点击它们或使用下一个/上一个按钮将导致按钮保持不变 - 即使您导航到超出按钮范围的位置。这是因为计算值被缓存了。我们可以通过两种方式解决这个问题 - 要么将函数移动到`method`对象中，要么在路由上添加一个`watch`函数来监听并更新当前页面。

选择第二个选项意味着我们可以确保没有其他结果和输出被缓存并相应地更新。在组件中添加一个`watch`对象，并将`currentPage`变量更新为页面查询变量的值。确保它存在，否则默认为 1。`watch`方法如下所示：

```js
watch: {
  '$route'(to) {
    this.currentPage = parseInt(to.query.page) || 1;
  }
}
```

这样可以确保在导航到不同页面时，所有计算的变量都会更新。打开您的`HomePage`组件，并确保所有分页组件按预期工作并更新列表。

# 更新每页的项目

我们需要创建的最后一个用户界面添加是允许用户更新每页产品数量。为了最初设置这个，我们可以创建一个带有`v-model`属性的`<select>`框，直接更新值。这按预期工作，并相应地更新产品列表，如下所示：

```js
template: `<div v-if="products">
  <p>
    Page {{ currentPage }} out of {{ pagination.totalPages }}
  </p>

 Products per page: 
 <select v-model="perPage">
 <option>12</option>
 <option>24</option>
 <option>48</option>
 <option>60</option>
 </select>

  <button @click="toPage(currentPage - 1)" :disabled="currentPage == 1">Previous page</button>
  <button @click="toPage(currentPage + 1)" :disabled="currentPage == pagination.totalPages">Next page</button>

  <ol :start="pagination.range.from + 1">
    <li v-for="product in paginate(products)" v-if="product">
      <h3>{{ product.title }}</h3>
    </li>
  </ol>

  <nav>
    <ul>
      <li v-for="page in pageLinks">
        <button @click="toPage(page)">{{ page }}</button>
      </li>
    </ul>
  </nav>
</div>
```

这个问题是，如果用户在值改变后处于一个超过可能的页面。例如，如果有 30 个产品，每页 12 个产品，这将创建三个页面。如果用户导航到第三页，然后选择每页 24 个产品，只需要两个页面，第三页将为空。

这可以再次通过一个`watch`函数解决。当`perPage`变量更新时，我们可以检查当前页面是否高于`totalPages`变量。如果是，我们可以将其重定向到最后一页：

```js
watch: {
  '$route'(to) {
    this.currentPage = parseInt(to.query.page);
  },

  perPage() {
 if(this.currentPage > this.pagination.totalPages) {
 this.$router.push({
 query: Object.assign({}, this.$route.query, {
 page: this.pagination.totalPages
 })
 })
 }
 }
}
```

# 创建 ListProducts 组件

在继续创建过滤和排序之前，我们需要提取我们的产品列表逻辑并将其模板化到我们的组件中 - 以便我们可以轻松重用它。这个组件应该接受一个名为`products`的 prop，它应该能够列出和分页。

打开`ListProducts.js`文件，将代码从`HomePage.js`文件复制到组件中。将数据对象和复制`pagination`和`pageLinks`计算函数。将 watch 和 methods 对象以及`created()`函数从`HomePage`移动到`ListProducts`文件中。

更新`HomePage`模板，使用带有`products`属性的`<list-products>`组件，并传入`products`计算值。相比之下，`HomePage`组件现在应该更小：

```js
const HomePage = {
  name: 'HomePage',

  template: `<div>
    <list-products :products="products"></list-products>
  </div>`,

  computed: {
    products() {
      let products = this.$store.state.products;
      return Object.keys(products).map(key => products[key]);
    }
  }
};
```

在`ListProducts`组件中，我们需要添加一个 props 对象，让组件知道要期望什么。这个组件现在很重要。我们还需要添加一些东西到这个组件中，使其更加通用。它们包括：

+   如果有多个页面，则显示下一页/上一页链接

+   如果有超过 12 个产品，则显示“每页产品”组件，并且只在比前一步骤中有更多产品时显示每个步骤

+   只有当`pageLinks`组件超过我们的`pageLinksCount`变量时才显示

所有这些添加都已添加到以下组件代码中。我们还删除了不必要的`products`计算值：

```js
Vue.component('list-products', {
  template: `<div v-if="products">
    <p v-if="pagination.totalPages > 1">
      Page {{ currentPage }} out of {{ pagination.totalPages }}
    </p>

    <div v-if="pagination.totalProducts > 12">
      Products per page: 
      <select v-model="perPage">
        <option>12</option>
        <option>24</option>
        <option v-if="pagination.totalProducts > 24">48</option>
        <option v-if="pagination.totalProducts > 48">60</option>
      </select>
    </div>

    <button 
      @click="toPage(currentPage - 1)" 
      :disabled="currentPage == 1" 
      v-if="pagination.totalPages > 1"
    >
      Previous page
    </button>
    <button 
      @click="toPage(currentPage + 1)" 
      :disabled="currentPage == pagination.totalPages" 
      v-if="pagination.totalPages > 1"
    >
      Next page
    </button>

    <ol :start="pagination.range.from + 1">
      <li v-for="product in paginate(products)" v-if="product">
        <h3>{{ product.title }}</h3>
      </li>
    </ol>

    <nav v-if="pagination.totalPages > pageLinksCount">
      <ul>
        <li v-for="page in pageLinks">
          <button @click="toPage(page)">{{ page }}</button>
        </li>
      </ul>
    </nav>
  </div>`,

 props: {
 products: Array
 },

  data() {
    return {
      perPage: 12, 
      currentPage: 1,
      pageLinksCount: 3
    }
  },

  computed: {
    pagination() {
      if(this.products) {
        let totalProducts = this.products.length,
          pageFrom = (this.currentPage * this.perPage) - this.perPage,
          totalPages = Math.ceil(totalProducts / this.perPage);

        return {
          totalProducts: totalProducts,
          totalPages: Math.ceil(totalProducts / this.perPage),
          range: {
            from: pageFrom,
            to: pageFrom + this.perPage
          }
        }
      }
    },

    pageLinks() {
      if(this.products.length) {
        let negativePoint = this.currentPage - this.pageLinksCount,
          positivePoint = this.currentPage + this.pageLinksCount,
          pages = [];

        if(negativePoint < 1) {
          negativePoint = 1;
        }

        if(positivePoint > this.pagination.totalPages) {
          positivePoint = this.pagination.totalPages;
        }

        for (var i = negativePoint; i <= positivePoint; i++) {
          pages.push(i)
        }

        return pages;
      }
    }
  },

  watch: {
    '$route'(to) {
      this.currentPage = parseInt(to.query.page);
    },
    perPage() {
      if(this.currentPage > this.pagination.totalPages) {
        this.$router.push({
          query: Object.assign({}, this.$route.query, {
            page: this.pagination.totalPages
          })
        })
      }
    }
  },

  created() {
    if(this.$route.query.page) {
      this.currentPage = parseInt(this.$route.query.page);
    }
  },

  methods: {
    toPage(page) {
      this.$router.push({
        query: Object.assign({}, this.$route.query, {
          page
        })
      });

      this.currentPage = page;
    },

    paginate(list) {
      return list.slice(this.pagination.range.from, this.pagination.range.to)
    }
  }
});
```

您可以通过在`HomePage`模板中临时截断产品数组来验证您的条件渲染标签是否正常工作-完成后不要忘记删除它：

```js
products() {
  let products = this.$store.state.products;
  return Object.keys(products).map(key => products[key]).slice(1, 10);
}
```

# 为主页创建一个精选列表

有了我们的产品列表组件，我们可以继续为主页创建一个精选产品列表，并向产品列表添加更多信息。

在这个例子中，我们将在主页组件上硬编码一个产品句柄数组，我们希望显示这些产品。如果这是在开发中，你会期望这个列表通过内容管理系统或类似方式进行控制。

在`HomePage`组件上创建一个`data`函数，其中包含一个名为`selectedProducts`的数组：

```js
data() {
  return {
    selectedProducts: []
  }
},
```

用产品列表中的几个`handles`填充数组。尽量选择六个，但如果超过 12 个，请记住它会与我们的组件分页。将您选择的句柄添加到`selectedProducts`数组中：

```js
data() {
  return {
    selectedProducts: [
      'adjustable-stem',
 'colorful-fixie-lima',
 'fizik-saddle-pak',
 'kenda-tube',
 'oury-grip-set',
 'pure-fix-pedals-with-cages'
    ]
  }
},
```

使用我们选择的句柄，我们现在可以将产品列表过滤为仅包含在我们的`selectedProducts`数组中的产品列表。最初的直觉可能是在产品数组上结合使用 JavaScript 的`filter()`函数和`includes()`函数：

```js
products() {
  let products = this.$store.state.products;

  products = Object.keys(products).map(key => products[key]);
  products = products.filter(product => this.selectedProducts.includes(product.handle));

  return products;
}
```

问题在于，尽管它似乎工作正常，但它不遵守所选产品的顺序。过滤函数只是删除不匹配的项目，并按加载的顺序保留剩余的产品。

幸运的是，我们的产品以键/值对的形式保存，键是句柄。利用这一点，我们可以利用产品对象并使用`for`循环返回一个数组。

在计算函数中创建一个空数组`output`。遍历`selectedProducts`数组，找到每个所需的产品并添加到`output`数组中：

```js
products() {
  let products = this.$store.state.products,
    output = [];

  if(Object.keys(products).length) {
 for(let featured of this.selectedProducts) {
 output.push(products[featured]);
 }
 return output;
 }
}
```

这将创建相同的产品列表，但这次是按正确的顺序。尝试重新排序、添加和删除项目，以确保您的列表能够相应地做出反应。

# 显示更多信息

现在我们可以在`ListProduct`组件中显示更多的产品信息了。正如在本章开头提到的，我们应该显示：

+   图像

+   标题

+   价格

+   制造商

我们已经显示了标题，并且可以轻松地从产品信息中提取出图像和制造商。不要忘记始终从`images`数组中检索第一个图像。打开`ListProducts.js`文件并更新产品以显示这些信息 - 确保在显示之前检查图像是否存在。制造商标题在产品数据的`vendor`对象下列出：

```js
<ol :start="pagination.range.from + 1">
  <li v-for="product in paginate(products)" v-if="product">
    <img v-if="product.images[0]" :src="product.images[0].source" :alt="product.title" width="120">
    <h3>{{ product.title }}</h3>
    <p>Made by: {{ product.vendor.title }}</p>
  </li>
</ol>
```

价格会更复杂一些。这是因为产品的每个变体可能有不同的价格，但通常是相同的。如果有不同的价格，我们应该显示最便宜的价格，并在前面加上*from*。

我们需要创建一个循环遍历变体并计算出最低价格的函数，如果有价格范围，还要添加*from*这个词。为了实现这个目标，我们将遍历变体并建立一个唯一价格的数组 - 如果价格在数组中不存在的话。完成后，我们可以检查数组的长度 - 如果有多个价格，我们可以添加前缀，如果没有，这意味着所有的变体都是相同的价格。

在`ListProducts`组件上创建一个名为`productPrice`的新方法。这个方法接受一个参数，即变体。在方法内部，创建一个空数组`prices`：

```js
productPrice(variations) {
  let prices = [];
}
```

遍历变体，如果价格在`prices`数组中不存在，则将价格添加到`prices`数组中。创建一个使用`includes()`函数检查价格是否存在于数组中的`for`循环：

```js
productPrice(variations) {
  let prices = [];

  for(let variation of variations) {
 if(!prices.includes(variation.price)) {
 prices.push(variation.price);
 }
 }
}
```

有了价格数组，我们现在可以提取最低的数字并检查是否有多个项目。

要从数组中提取最小的数字，我们可以使用 JavaScript 的`Math.min()`函数。使用`.length`属性来检查数组的长度。最后，返回`price`变量：

```js
productPrice(variations) {
  let prices = [];

  for(let variation of variations) {
    if(!prices.includes(variation.price)) {
      prices.push(variation.price);
    }
  }

 let price = '$' + Math.min(...prices);

 if(prices.length > 1) {
 price = 'From: ' + price;
 }

  return price;
}
```

将您的`productPrice`方法添加到模板中，记得将`product.variationProducts`传递给它。我们需要在模板中添加的最后一件事是一个指向产品的链接：

```js
<ol :start="pagination.range.from + 1">
  <li v-for="product in paginate(products)" v-if="product">
    <router-link :to="'/product/' + product.handle">
      <img v-if="product.images[0]" :src="product.images[0].source" :alt="product.title" width="120">
    </router-link> 
    <h3>
      <router-link :to="'/product/' + product.handle">
        {{ product.title }}
      </router-link>
    </h3>

    <p>Made by: {{ product.vendor.title }}</p>
    <p>Price {{ productPrice(product.variationProducts) }}</p>
  </li>
</ol>
```

理想情况下，产品链接应该使用命名路由而不是硬编码的链接，以防路由发生变化。给产品路由添加一个名称，并更新`to`属性以使用该名称。

```js
{
  path: '/product/:slug',
  name: 'Product',
  component: ProductPage
}
```

更新模板，现在使用路由名称和`params`对象：

```js
<ol :start="pagination.range.from + 1">
  <li v-for="product in paginate(products)" v-if="product">
    <router-link :to="{name: 'Product', params: {slug: product.handle}}">
      <img v-if="product.images[0]" :src="product.images[0].source" :alt="product.title" width="120">
    </router-link>
    <h3>
      <router-link :to="{name: 'Product', params: {slug: product.handle}}">
        {{ product.title }}
      </router-link>
    </h3>
    <p>Made by: {{ product.vendor.title }}</p>
    <p>Price {{ productPrice(product.variationProducts) }}</p>
  </li>
</ol>
```

# 创建类别

如果商店没有可导航的类别，那么它实际上不是一个可用的商店。幸运的是，我们的每个产品都有一个`type`键，指示它所属的类别。现在我们可以创建一个类别页面，列出该特定类别的产品。

# 创建类别列表

在我们能够显示特定类别的产品之前，我们首先需要生成一个可用类别的列表。为了提高应用程序的性能，我们还将在每个类别中存储产品的句柄。类别结构将如下所示：

```js
categories = {
  tools: {
    name: 'Tools',
    handle: 'tools',
    products: ['product-handle', 'product-handle'...]
  },
  freewheels: {
    name: 'Freewheels',
    handle: 'freewheels',
    products: ['another-product-handle', 'product'...]
  }
};
```

创建这样的类别列表意味着我们可以轻松地获取类别内的产品列表，同时可以循环遍历类别并输出`title`和`handle`以创建一个链接到类别的列表。由于我们已经有了这些信息，所以我们将在获取产品列表后创建类别列表。

打开`app.js`并导航到`Vue`实例上的`created()`方法。我们将不再在`products`存储方法下面创建第二个`$store.commit`，而是将使用 Vuex 的另一个功能-`actions`。

Actions 允许您在存储库本身中创建函数。Actions 无法直接改变状态-这仍然是 mutations 的工作，但它允许您将多个 mutations 组合在一起，这在这种情况下非常适合我们。如果您想在改变状态之前运行异步操作，例如使用`setTimeout` JavaScript 函数，那么 Actions 也非常适合。

导航到您的`Vuex.Store`实例，并在 mutations 之后添加一个新的`actions`对象。在其中，创建一个名为`initializeShop`的新函数：

```js
const store = new Vuex.Store({
  state: {
    products: {}
  },

  mutations: {
    products(state, payload) {
      state.products = payload;
    }
  },

 actions: {
 initializeShop() {

 }
 }
});
```

在动作参数中，第一个参数是存储本身，我们需要使用它来利用突变。有两种方法可以做到这一点，第一种是使用一个变量并在函数内部访问其属性。例如：

```js
actions: {
  initializeShop(store) {
    store.commit('products');
  }
}
```

然而，使用 ES2015，我们可以使用参数解构并利用我们需要的属性。对于这个动作，我们只需要`commit`函数，就像这样：

```js
actions: {
  initializeShop({commit}) {
    commit('products');
  }
}
```

如果我们还想要存储中的状态，我们可以将其添加到花括号中：

```js
actions: {
  initializeShop({state, commit}) {
    commit('products');
    // state.products
  }
}
```

使用这种“分解”的方法访问属性使我们的代码更清晰，减少了重复。删除`state`属性，并在花括号后面添加一个标记为`products`的第二个参数。这将是我们格式化的产品数据。将该变量直接传递给产品的`commit`函数：

```js
initializeShop({commit}, products) {
  commit('products', products);
}
```

使用动作与使用`mutations`一样简单，只是不使用`$store.commit`，而是使用`$store.dispatch`。更新您的`created`方法-不要忘记更改函数名称，并检查您的应用程序是否仍然正常工作：

```js
created() {
  CSV.fetch({url: './data/csv-files/bicycles.csv'}).then(data => {
    this.$store.dispatch('initializeShop', this.$formatProducts(data));
  });
}
```

下一步是为我们的类别创建一个突变。由于我们可能希望独立于我们的产品更新我们的类别-我们应该在`mutations`中创建第二个函数。它也应该是这个函数遍历产品并创建类别列表。

首先，在状态对象中创建一个名为`categories`的新属性。这应该是一个默认的对象：

```js
state: {
  products: {},
  categories: {}
}
```

接下来，创建一个名为`categories`的新突变。除了状态之外，这应该有一个第二个参数。为了保持一致，将其命名为`payload`-因为这是 Vuex 所指的：

```js
mutations: {
  products(state, payload) {
    state.products = payload;
  },

 categories(state, payload) {

 }
},
```

现在是功能的时间。这个突变需要遍历产品。对于每个产品，它需要隔离`type`。一旦它有了标题和 slug，它就需要检查是否存在具有该 slug 的条目；如果存在，则将产品句柄附加到`products`数组中，如果不存在-它需要创建一个新数组和详细信息。

创建一个空的`categories`对象，并循环遍历`payload`，为产品和类型设置一个变量：

```js
categories(state, payload) {
 let categories = {}; 
 Object.keys(payload).forEach(key => {
 let product = payload[key],
 type = product.type;
 });
}
```

现在，我们需要检查是否存在具有当前`type.handle`键的条目。如果不存在，我们需要创建一个新条目。该条目需要具有标题、句柄和一个空的产品数组：

```js
categories(state, payload) {
  let categories = {};

  Object.keys(payload).forEach(key => {
    let product = payload[key],
      type = product.type;

 if(!categories.hasOwnProperty(type.handle)) {
 categories[type.handle] = {
 title: type.title,
 handle: type.handle,
 products: []
 }
 }
  });
}
```

最后，我们需要将当前产品句柄附加到条目的产品数组中：

```js
categories(state, payload) {
  let categories = {};

  Object.keys(payload).forEach(key => {
    let product = payload[key],
      type = product.type;

    if(!categories.hasOwnProperty(type.handle)) {
      categories[type.handle] = {
        title: type.title,
        handle: type.handle,
        products: []
      }
    }

    categories[type.handle].products.push(product.handle);
  });
}
```

您可以通过在函数末尾添加`console.log`来查看`categories`输出：

```js

categories(state, payload) {
  let categories = {};

  Object.keys(payload).forEach(key => {
    ...
  });

  console.log(categories);
}
```

将突变添加到`initializeShop`动作中：

```js
initializeShop({commit}, products) {
  commit('products', products);
  commit('categories', products);
}
```

在浏览器中查看应用程序时，您将面临一个 JavaScript 错误。这是因为一些产品没有包含我们用来对其进行分类的“类型”。即使解决了 JavaScript 错误，仍然有很多类别被列出。

为了帮助处理类别的数量，并将未分类的产品分组，我们应该创建一个“杂项”类别。这将汇总所有包含两个或更少产品的类别，并将产品分组到它们自己的组中。

# 创建一个“杂项”类别

我们需要解决的第一个问题是无名称的类别。在循环遍历产品时，如果找不到类型，则应插入一个类别，以便对所有内容进行分类。

在`categories`方法中创建一个新对象，其中包含一个新类别的标题和句柄。对于句柄和变量，称其为“other”。通过将标题称为“杂项”来使其更加用户友好。

```js
let categories = {},
  other = {
 title: 'Miscellaneous',
 handle: 'other'
 };
```

在循环遍历产品时，我们可以检查`type`键是否存在，如果不存在，则创建一个`other`类别并将其附加到其中：

```js
Object.keys(payload).forEach(key => {
  let product = payload[key],
    type = product.hasOwnProperty('type') ? product.type : other;

  if(!categories.hasOwnProperty(type.handle)) {
    categories[type.handle] = {
      title: type.title,
      handle: type.handle,
      products: []
    }
  }

  categories[type.handle].products.push(product.handle);
});
```

现在查看应用程序将在 JavaScript 控制台中显示所有类别-让您看到有多少类别。

让我们将任何包含两个或更少产品的类别合并到“other”类别中-不要忘记之后删除该类别。在产品循环之后，循环遍历类别，检查可用产品的数量。如果少于三个，则将它们添加到“other”类别中：

```js
Object.keys(categories).forEach(key => {
  let category = categories[key];

  if(category.products.length < 3) {
    categories.other.products = categories.other.products.concat(category.products);
  }
});
```

然后，我们可以删除刚刚从中窃取产品的类别：

```js
Object.keys(categories).forEach(key => {
  let category = categories[key];

  if(category.products.length < 3) {
    categories.other.products = categories.other.products.concat(category.products);
    delete categories[key];
  }
});
```

有了这个，我们有了一个更易于管理的类别列表。我们可以做的另一个改进是确保类别按字母顺序排列。这有助于用户更快地找到他们想要的类别。在 JavaScript 中，数组比对象更容易排序，因此我们需要再次循环遍历对象键的数组并对其进行排序。创建一个新对象，并将排序后的类别添加到其中。然后，将其存储在`state`对象上，以便我们可以使用这些类别：

```js
categories(state, payload) {
  let categories = {},
    other = {
      title: 'Miscellaneous',
      handle: 'other'
    };

  Object.keys(payload).forEach(key => {
    let product = payload[key],
      type = product.hasOwnProperty('type') ? product.type : other;

    if(!categories.hasOwnProperty(type.handle)) {
      categories[type.handle] = {
        title: type.title,
        handle: type.handle,
        products: []
      }
    }

    categories[type.handle].products.push(product.handle);
  });

  Object.keys(categories).forEach(key => {
    let category = categories[key];

    if(category.products.length < 3) {
      categories.other.products =      categories.other.products.concat(category.products);
      delete categories[key];
    }
  });

  let categoriesSorted = {}
 Object.keys(categories).sort().forEach(key => {
 categoriesSorted[key] = categories[key]
 });
 state.categories = categoriesSorted;
}
```

有了这个，我们现在可以在`HomePage`模板中添加一个类别列表。为此，我们将创建命名的`router-view`组件-允许我们将东西放在选定页面的商店侧边栏中。

# 显示类别

有了我们存储的类别，我们现在可以继续创建我们的`ListCategories`组件。我们希望在主页的侧边栏和商店类别页面中显示我们的类别导航。由于我们希望在多个位置显示它，我们有几个选项可以选择如何显示它。

我们可以像使用`<list-products>`组件一样在模板中使用该组件。但是，问题在于如果我们想在侧边栏中显示我们的列表，并且我们的侧边栏需要在整个站点上保持一致，我们将不得不在视图之间复制和粘贴大量的 HTML。

更好的方法是使用命名路由，并在我们的`index.html`中设置模板。

更新应用程序模板以包含一个`<main>`和一个`<aside>`元素。在其中创建一个`router-view`，将`main`内部的一个未命名，而将`aside`元素内部的一个命名为`sidebar`：

```js
<div id="app">
  <main>
    <router-view></router-view>
  </main>
 <aside>
 <router-view name="sidebar"></router-view>
 </aside>
</div>
```

在我们的路由对象中，我们现在可以为不同的命名视图添加不同的组件。在`Home`路由上，将`component`键更改为`components`，并添加一个对象-指定每个组件及其视图：

```js
{
  path: '/',
  name: 'Home',
  components: {
 default: HomePage,
 sidebar: ListCategories
 }
}
```

默认情况下，组件将进入未命名的`router-view`中。这使我们仍然可以使用单数的`component`键（如果需要的话）。为了正确加载组件到侧边栏视图中，我们需要修改`ListCategories`组件的初始化方式。不要使用`Vue.component`，而是像初始化`view`组件一样进行初始化：

```js
const ListCategories = {
  name: 'ListCategories'

};
```

现在我们可以继续创建类别列表的模板了。由于我们的类别保存在 store 中，加载和显示它们应该是熟悉的。建议您将类别从状态加载到计算函数中-这样可以使模板代码更清晰，并且在需要以任何方式操作它时更容易适应。

在创建模板之前，我们需要为该类别创建一个路由。回顾一下第九章中的计划，*使用 Vue-Router 动态路由加载数据*，我们可以看到路由将是`/category/:slug` - 添加此路由并启用 props，因为我们将在`slug`中使用它们。确保您已经创建了`CategoryPage`文件并初始化了组件。

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      name: 'Home',
      components: {
        default: HomePage,
        sidebar: ListCategories
      }
    },
    {
 path: '/category/:slug',
 name: 'Category',
 component: CategoryPage,
 props: true
 },
    {
      path: '/product/:slug',
      name: 'Product',
      component: ProductPage
    },

    {
      path: '/404', 
      alias: '*',
      component: PageNotFound
    }
  ]
});
```

回到我们的`ListCategories`组件；循环遍历存储的类别，并为每个类别创建一个链接。在每个名称后面用括号显示产品数量：

```js
const ListCategories = {
  name: 'ListCategories',

 template: `<div v-if="categories">
 <ul>
 <li v-for="category in categories">
 <router-link :to="{name: 'Category', params: {slug: category.handle}}">
 {{ category.title }} ({{ category.products.length }})
 </router-link>
 </li>
 </ul>
 </div>`,

 computed: {
 categories() {
 return this.$store.state.categories;
 }
 } 
};
```

现在我们的类别链接已经显示在主页上，我们可以继续创建一个类别页面。

# 显示类别中的产品

点击其中一个类别链接（即`/#/category/grips`）将导航到一个空白页面 - 这要归功于我们的路由。我们需要创建一个模板并设置类别页面以显示产品。作为起点，创建一个类似于产品页面的`CategoryPage`组件。

创建一个带有空容器和`PageNotFound`组件的模板。创建一个名为`categoryNotFound`的数据变量，并确保如果它设置为`true`，则显示`PageNotFound`组件。创建一个`props`对象，允许传递`slug`属性，并最后创建一个`category`计算函数。

`CategoryPage`组件应该如下所示：

```js
const CategoryPage = {
  name: 'CategoryPage',

  template: `<div>
    <div v-if="category"></div>
    <page-not-found v-if="categoryNotFound"></page-not-found>
  </div>`,

  components: {
    PageNotFound
  },

  props: {
    slug: String
  },

  data() {
    return {
      categoryNotFound: false,
    }
  },

  computed: {
    category() {
    }
  }
};
```

在`category`计算函数内，根据 slug 从存储中加载正确的类别。如果它不在列表中，则将`categoryNotFound`变量标记为 true - 类似于我们在`ProductPage`组件中所做的操作：

```js
computed: {
  category() {
    let category;

 if(Object.keys(this.$store.state.categories).length) {

 category = this.$store.state.categories[this.slug];

 if(!category) {
 this.categoryNotFound = true;
 }
 }

 return category;
  }
}
```

在加载了我们的类别后，我们可以在模板中输出标题：

```js
template: `<div>
  <div v-if="category">
    <h1>{{ category.title }}</h1>
  </div>
  <page-not-found v-if="categoryNotFound"></page-not-found>
</div>`,
```

现在，我们可以继续在类别页面上显示产品。为此，我们可以使用`HomePage`组件中的代码，因为我们有完全相同的情况 - 一个产品句柄数组。

创建一个新的`computed`函数，它接受当前类别产品并像在主页上那样对它们进行处理：

```js
computed: {
  category() {
    ...
  },

  products() {
    if(this.category) {
 let products = this.$store.state.products,
 output = [];

 for(let featured of this.category.products) {
 output.push(products[featured]);
 }

 return output; 
 }
  }
}
```

在这个函数中，我们不需要检查产品是否存在，因为我们正在检查类别是否存在，只有在数据加载完成时才会返回 true。将组件添加到 HTML 中并传入`products`变量：

```js
template: `<div>
  <div v-if="category">
    <h1>{{ category.title }}</h1>
    <list-products :products="products"></list-products>
  </div>
  <page-not-found v-if="categoryNotFound"></page-not-found>
</div>`
```

有了这个，我们就可以为每个类别列出我们的类别产品。

# 代码优化

完成`CategoryPage`组件后，我们可以看到它与主页之间有很多相似之处 - 唯一的区别是主页有一个固定的产品数组。为了避免重复，我们可以将这两个组件合并 - 这意味着如果需要，我们只需要更新一个组件。

我们可以通过在识别我们是否在主页时显示它来解决固定数组问题。做法是检查 slug 属性是否有值。如果没有，我们可以假设我们在主页上。

首先，将`Home`路由更新为指向`CategoryPage`组件并启用 props。在使用命名视图时，您必须为每个视图启用 props。更新 props 值为一个对象，其中包含每个命名视图，为每个视图启用 props：

```js
{
  path: '/',
  name: 'Home',
  components: {
    default: CategoryPage,
    sidebar: ListCategories
  },
  props: {
 default: true, 
 sidebar: true
 }
}
```

接下来，在`CategoryPage`的`data`函数中创建一个名为`categoryHome`的新变量。这将是一个对象，其结构与类别对象相同，包含一个`products`数组，标题和句柄。虽然句柄不会被使用，但遵循惯例是一个好习惯：

```js
data() {
  return {
    categoryNotFound: false,
    categoryHome: {
 title: 'Welcome to the Shop',
 handle: 'home',
 products: [
 'adjustable-stem',
 'fizik-saddle-pak',
 'kenda-tube',
 'colorful-fixie-lima',
 'oury-grip-set',
 'pure-fix-pedals-with-cages'
 ]
 }
  }
}
```

我们需要做的最后一件事是检查 slug 是否存在。如果不存在，则将我们的新对象分配给计算函数中的类别变量：

```js
category() {
  let category;

  if(Object.keys(this.$store.state.categories).length) {
    if(this.slug) {
 category = this.$store.state.categories[this.slug];
 } else {
 category = this.categoryHome;
 }

    if(!category) {
      this.categoryNotFound = true;
    }
  }

  return category;
}
```

转到主页并验证您的新组件是否正常工作。如果是，请删除`HomePage.js`并从`index.html`中删除它。更新类别路由以在侧边栏中包含类别列表并使用`props`对象：

```js
{
  path: '/category/:slug',
  name: 'Category',
  components: {
 default: CategoryPage,
 sidebar: ListCategories
 },
  props: {
 default: true, 
 sidebar: true
 }
},
```

# 对类别中的产品进行排序

当我们的类别页面显示正确的产品时，现在是时候在`ListProducts`组件中添加一些排序选项了。在在线商店中查看产品时，通常可以按以下方式对产品进行排序：

+   标题：升序（A - Z）

+   标题：降序（Z - A）

+   价格：升序（$1 - $999）

+   价格：降序（$999 - $1）

然而，一旦我们有了这个机制，您可以添加任何您想要的排序标准。

首先，在`ListProducts`组件中创建一个选择框，其中包含上述每个值。添加一个额外的第一个值为“按产品排序...”：

```js
<div class="ordering">
  <select>
    <option>Order products</option>
    <option>Title - ascending (A - Z)</option>
    <option>Title - descending (Z - A)</option>
    <option>Price - ascending ($1 - $999)</option>
    <option>Price - descending ($999 - $1)</option>
  </select>
</div>
```

现在我们需要在`data`函数中为选择框创建一个变量以便更新。添加一个名为`ordering`的新键，并为每个选项添加一个值，以便更容易解释该值。通过使用字段和顺序，用连字符分隔来构造值。例如，`Title - ascending (`A - Z`)`将变为`title-asc`：

```js
<div class="ordering">
  <select v-model="ordering">
    <option value="">Order products</option>
    <option value="title-asc">Title - ascending (A - Z)</option>
    <option value="title-desc">Title - descending (Z - A)</option>
    <option value="price-asc">Price - ascending ($1 - $999)</option>
    <option value="price-desc">Price - descending ($999 - $1)</option>
  </select>
</div>
```

更新后的`data`函数如下：

```js
data() {
  return {
    perPage: 12, 
    currentPage: 1,
    pageLinksCount: 3,

    ordering: ''
  }
}
```

要更新产品的顺序，我们现在需要操作产品列表。这需要在列表被分割为分页之前完成 - 因为用户期望整个列表被排序，而不仅仅是当前页面。

# 存储产品价格

在继续之前，我们需要解决一个问题。要按价格排序，最好将价格作为产品本身的属性而不是专门为模板计算的属性。为了解决这个问题，我们将在将产品添加到存储之前计算价格。这意味着它将作为产品本身的属性可用，而不是动态创建的属性。

我们需要知道的细节是最便宜的价格以及产品是否有多个价格。后者意味着我们知道在列出产品时是否需要显示`"From:"`。我们将为每个产品创建两个新属性：`price`和`hasManyPrices`。

转到存储中的`products`mutation，并创建一个新对象和产品的循环：

```js
products(state, payload) {
 let products = {};

 Object.keys(payload).forEach(key => {
 let product = payload[key];

 products[key] = product;
 });

  state.products = payload;
}
```

从`ListProducts`组件的`productPrice`方法中复制代码，并将其放置在循环内。更新第二个`for`循环，使其循环遍历`product.variationProducts`。完成此`for`循环后，我们可以向产品添加新属性。最后，使用新的产品对象更新状态：

```js
products(state, payload) {
  let products = {};

  Object.keys(payload).forEach(key => {
    let product = payload[key];

    let prices = [];
 for(let variation of product.variationProducts) {
 if(!prices.includes(variation.price)) {
 prices.push(variation.price);
 }
 }

 product.price = Math.min(...prices);
 product.hasManyPrices = prices.length > 1;

    products[key] = product;
  });

  state.products = products;
}
```

现在我们可以更新`ListProducts`组件上的`productPrice`方法。更新函数，使其接受产品而不是变体。从函数中删除`for`循环，并更新变量，使其使用产品的`price`和`hasManyPrices`属性：

```js
productPrice(product) {
  let price = '$' + product.price;

  if(product.hasManyPrices) {
    price = 'From: ' + price;
  }

  return price;
}
```

更新模板，以便将产品传递给函数：

```js
<p>Price {{ productPrice(product) }}</p>
```

# 连接排序

有了我们需要的价格，我们可以继续连接排序。创建一个名为`orderProducts`的新的`computed`函数，它返回`this.products`。我们希望确保我们始终从源头进行排序，而不是对之前已经排序过的东西进行排序。从`paginate`函数中调用这个新函数，并从该方法和模板中删除参数：

```js
computed: {
 ...

  orderProducts() {
 return this.products;
 }, },

methods: {
  paginate() {
    return this.orderProducts.slice(
      this.pagination.range.from,  
      this.pagination.range.to
    );
  },
}
```

为了确定我们需要如何对产品进行排序，我们可以使用`this.ordering`的值。如果存在，我们可以在连字符上拆分字符串，这意味着我们有一个包含字段和排序类型的数组。如果不存在，我们只需返回现有的产品数组：

```js
orderProducts() {
  let output;

 if(this.ordering.length) {
 let orders = this.ordering.split('-');
 } else {
 output = this.products;
 }
 return output;
}
```

根据排序数组的第一个项目的值对`products`数组进行排序。如果它是一个字符串，我们将使用`localCompare`进行比较，它在比较时忽略大小写。否则，我们将简单地从另一个值中减去一个值 - 这是`sort`函数所期望的：

```js
orderProducts() {
  let output;

  if(this.ordering.length) {
    let orders = this.ordering.split('-');

    output = this.products.sort(function(a, b) {
 if(typeof a[orders[0]] == 'string') {
 return a[orders[0]].localeCompare(b[orders[0]]);
 } else {
 return a[orders[0]] - b[orders[0]];
 }
 });

  } else {
    output = this.products;
  }
  return output;
}
```

最后，我们需要检查`orders`数组中的第二个项目是`asc`还是`desc`。默认情况下，当前排序函数将以“升序”方式返回排序后的项目，因此如果值为`desc`，我们可以反转数组：

```js
orderProducts() {
  let output;

  if(this.ordering.length) {
    let orders = this.ordering.split('-');

    output = this.products.sort(function(a, b) {
      if(typeof a[orders[0]] == 'string') {
        return a[orders[0]].localeCompare(b[orders[0]]);
      } else {
        return a[orders[0]] - b[orders[0]];
      }
    });

 if(orders[1] == 'desc') {
 output.reverse();
 }
  } else {
    output = this.products;
  }
  return output;
}
```

前往浏览器，查看产品的排序！

# 创建 Vuex 的 getter

使我们的类别页面与其他任何商店一样的最后一步是引入过滤。过滤允许您查找具有特定尺寸、颜色、标签或制造商的产品。我们的过滤选项将从页面上的产品构建。例如，如果没有产品具有 XL 尺寸或蓝色，那么将其显示为过滤器就没有意义。

为了实现这一点，我们还需要将当前类别的产品传递给过滤组件。然而，产品在`CategoryPage`组件上进行处理。我们可以将这个功能移动到 Vuex 存储的 getter 中，而不是重复这个处理过程。Getter 允许您从存储中检索数据并像在组件的函数中一样操作它。然而，因为它是一个中心位置，这意味着多个组件可以从处理中受益。

Getter 是 Vuex 中计算函数的等效物。它们被声明为函数，但作为变量调用。然而，它们可以通过返回一个函数来进行参数化处理。

我们将把`CategoryPage`组件中的`category`和`products`函数都移动到 getter 中。然后，`getter`函数将返回一个包含类别和产品的对象。

在您的存储中创建一个名为`getters`的新对象。在其中创建一个名为`categoryProducts`的新函数：

```js
getters: {
  categoryProducts: () => {

  }
}
```

Getter 本身接收两个参数，第一个是状态，第二个是任何其他 getter。要将参数传递给 getter，必须在 getter 内部返回一个接收参数的函数。幸运的是，在 ES2015 中，可以使用双箭头（`=>`）语法实现这一点。由于在此函数中不会使用任何其他 getter，因此我们不需要调用第二个参数。

由于我们正在将所有逻辑抽象出来，所以将`slug`变量作为第二个函数的参数传入：

```js
categoryProducts: (state) => (slug) => {

}
```

由于我们正在将选择和检索类别和产品的逻辑转移到存储中，所以将`HomePage`类别内容存储在`state`本身是有意义的。

```js
state: {
  products: {},
  categories: {},

  categoryHome: {
 title: 'Welcome to the Shop',
 handle: 'home',
 products: [
 'adjustable-stem',
 'fizik-saddle-pak',
 'kenda-tube',
 'colorful-fixie-lima',
 'oury-grip-set',
 'pure-fix-pedals-with-cages'
 ]
 }
}
```

将`CategoryPage`组件中的`category`计算函数中的类别选择逻辑移动到 getter 中。更新`slug`和`categoryHome`变量，使用相关位置的内容：

```js
categoryProducts: (state) => (slug) => {
  if(Object.keys(state.categories).length) {
    let category = false;

    if(slug) {
      category = this.$store.state.categories[this.slug];
    } else {
      category = state.categoryHome;
    }
  }
}
```

现在，我们可以根据类别分配加载基于类别中存储的句柄的产品。将代码从`products`计算函数移动到 getter 中。将变量赋值合并在一起，并删除存储产品检索变量，因为我们已经有了可用的状态。确保检查类别是否存在的代码仍然存在：

```js
categoryProducts: (state) => (slug) => {
  if(Object.keys(state.categories).length) {
    let category = false,
      products = [];

    if(slug) {
      category = this.$store.state.categories[this.slug];
    } else {
      category = state.categoryHome;
    }

    if(category) {
 for(let featured of category.products) {
 products.push(state.products[featured]);
 }
 }
  }
}
```

最后，在`category`上添加一个新的`productDetails`数组，其中包含详细的产品数据。在函数的末尾返回`category`。如果`slug`变量输入存在作为一个类别，我们将得到所有的数据。如果没有，它将返回`false` - 我们可以显示我们的`PageNotFound`组件：

```js
categoryProducts: (state) => (slug) => {
  if(Object.keys(state.categories).length) {
    let category = false,
      products = [];

    if(slug) {
      category = state.categories[slug];
    } else {
      category = state.categoryHome;
    }

    if(category) {
      for(let featured of category.products) {
        products.push(state.products[featured]);
      }

      category.productDetails = products;
    }

    return category;
  }
}
```

在我们的`CategoryPage`组件中，我们可以删除`products()`计算函数并更新`category()`函数。要调用一个`getter`函数，可以引用`this.$store.getters`：

```js
computed: {
  category() {
    if(Object.keys(this.$store.state.categories).length) {
      let category = this.$store.getters.categoryProducts(this.slug);

      if(!category) {
        this.categoryNotFound = true;
      }
      return category;
    }
  }
}
```

不幸的是，我们仍然需要在继续之前检查类别是否存在。这样我们就可以知道是否有一个名为的类别，而不是一个未加载的类别。

为了使这个更整洁，我们可以将这个检查提取到另一个 getter 中，并在我们的其他 getter 和组件中使用它。

创建一个名为`categoriesExist`的新 getter，并返回`if`语句的内容。

```js
categoriesExist: (state) => {
  return Object.keys(state.categories).length;
},
```

更新`categoryProducts`getter 以接受第一个函数的 getter 作为参数，并使用这个新的 getter 来指示其输出：

```js
categoryProducts: (state, getters) => (slug) => {
  if(getters.categoriesExist) {
    ...
  }
}
```

在我们的`CategoryPage`组件中，我们现在可以使用`this.$store.getters.categoriesExist()`调用新的 getter。为了避免在这个函数中重复使用`this.$store.getters`两次，我们可以将 getter 映射为本地访问。这允许我们调用`this.categoriesExist()`作为一个更可读的函数名。

在`computed`对象的开头，添加一个名为`...Vuex.mapGetters()`的新函数。这个函数接受一个数组或一个对象作为参数，而开头的三个点确保内容被展开以与`computed`对象合并。

传入一个包含两个 getter 名称的数组：

```js
computed: {
 ...Vuex.mapGetters([
 'categoryProducts',
 'categoriesExist'
 ]),

  category() {
    ...
  }
}
```

这意味着我们现在可以使用`this.categoriesExist`和`this.categoryProducts`。更新类别函数以使用这些新函数：

```js
computed: {
  ...Vuex.mapGetters([
    'categoriesExist',
    'categoryProducts'
  ]),

  category() {
    if(this.categoriesExist) {
      let category = this.categoryProducts(this.slug);

      if(!category) {
        this.categoryNotFound = true;
      }
      return category;
    }
  }
}
```

更新模板以反映计算数据的更改：

```js
template: `<div>
  <div v-if="category">
    <h1>{{ category.title }}</h1>
    <list-products :products="category.productDetails"></list-products>
  </div>
  <page-not-found v-if="categoryNotFound"></page-not-found>
</div>`,
```

# 基于产品构建过滤组件

如前所述，我们所有的过滤器都将根据当前类别中的产品创建。这意味着如果没有*IceToolz*制造的产品，它将不会显示为可用的过滤器。

首先打开`ProductFiltering.js`组件文件。我们的产品过滤将放在侧边栏中，所以将组件定义从`Vue.component`更改为一个对象。我们仍然希望在过滤之后显示我们的类别，所以将`ListCategories`组件添加为`ProductFiltering`中的一个声明组件。添加一个模板键并包含`<list-categories>`组件：

```js
const ProductFiltering = {
  name: 'ProductFiltering',

  template: `<div>
    <list-categories />
  </div>`,

  components: {
    ListCategories
  }
}
```

更新类别路由，将`ProductFiltering`组件放在侧边栏中，而不是`ListCategories`：

```js
{
  path: '/category/:slug',
  name: 'Category',
  components: {
    default: CategoryPage,
    sidebar: ProductFiltering
  },
  props: {
    default: true, 
    sidebar: true
  }
}
```

现在，您应该有`Home`路由，其中包括`CategoryPage`和`ListCategories`组件，以及`Category`路由，其中包括`ProductFiltering`组件。

从`CategoryPage`组件中复制 props 和 computed 对象-因为我们将使用大量现有代码。将`category`计算函数重命名为`filters`。删除返回语句和`componentNotFound`的 if 语句。您的组件现在应该如下所示：

```js
const ProductFiltering = {
  name: 'ProductFiltering',

  template: `<div>
    <list-categories />
  </div>`,

  components: {
    ListCategories
  },

  props: {
 slug: String
 },

 computed: {
 ...Vuex.mapGetters([
 'categoriesExist',
 'categoryProducts'
 ]),
 filters() {
 if(this.categoriesExist) {
 let category = this.categoryProducts(this.slug);

 }
 }
 }
}
```

现在，我们需要根据类别中的产品构建我们的过滤器。我们将通过循环遍历产品，收集来自预选值的信息并显示它们来完成这个过程。

创建一个包含`topics`键的`data`对象。这将是一个包含子对象的对象，每个子对象都有一个现在熟悉的模式`'handle'：{}`，用于我们要过滤的每个属性。

每个子对象将包含一个`handle`，它是要过滤的产品的值（例如，供应商），一个`title`，它是键的用户友好版本，以及一个将被填充的值数组。

我们将从两个开始，`vendor`和`tags`；然而，随着我们处理产品的过程，会动态添加更多：

```js
data() {
  return {
    topics: {
      vendor: {
        title: 'Manufacturer',
        handle: 'vendor',
        values: {}
      },
      tags: {
        title: 'Tags',
        handle: 'tags',
        values: {}
      }
    }
  }
},
```

现在，我们将开始循环遍历产品。除了值之外，我们还将跟踪具有相同值的产品数量，以便向用户指示将显示多少产品。

在`filters`方法中循环遍历类别中的产品，并首先找到每个产品的`vendor`。对于每个遇到的产品，检查它是否存在于`values`数组中。

如果没有，添加一个新对象，其中包含`name`、`handle`和`count`，`count`是一个产品句柄的数组。我们存储句柄数组是为了验证产品是否已经被查看过。如果我们只是保留一个原始的数字计数，可能会遇到触发过滤器两次的情况，导致计数翻倍。通过检查产品句柄是否已经存在，我们可以确保它只被查看过一次。

如果已存在具有该名称的过滤器，则在检查其不存在后将句柄添加到数组中：

```js
filters() {
  if(this.categoriesExist) {

    let category = this.categoryProducts(this.slug),
      vendors = this.topics.vendor;

 for(let product of category.productDetails) {

        if(product.hasOwnProperty('vendor')) {
 let vendor = product.vendor; 
 if(vendor.handle) { if(!vendor.handle.count.includes(product.handle)) {
              category.values[item.handle].count.push(product.handle);
            }
          } else {
 vendors.values[vendor.handle] = {
 ...vendor,
 count: [product.handle]
 }
 }
 } 
 }

 }
  }
}
```

这里使用了之前使用的对象展开省略号（`...`），这样我们就不必写：

```js
vendors.values[product.vendor.handle] = {
  title: vendor.title,
 handle: vendor.handle,
  count: [product.handle]
}
```

如果您对此更熟悉，可以随意使用它。

复制代码以处理`tags`，但由于`tags`本身是一个数组，我们需要循环遍历每个标签并相应地添加：

```js
for(let product of category.productDetails) {

  if(product.hasOwnProperty('vendor')) {
    let vendor = product.vendor;

    if(vendor.handle) {
      if(!vendor.handle.count.includes(product.handle)) {
        category.values[item.handle].count.push(product.handle);
      }
    } else {
      vendors.values[vendor.handle] = {
        ...vendor,
        count: [product.handle]
      }
    }
  }

 if(product.hasOwnProperty('tags')) {
 for(let tag of product.tags) {
 if(tag.handle) {
 if(topicTags.values[tag.handle]) {
 if(!topicTags.values[tag.handle].count.includes(product.handle)) {
            topicTags.values[tag.handle].count.push(product.handle);
          }
 } else {
 topicTags.values[tag.handle] = {
 ...tag,
 count: [product.handle]
 }
 }
 }
 }
 }

}
```

我们的代码已经变得重复和复杂，让我们通过创建一个处理重复代码的方法来简化它。

创建一个`methods`对象，其中包含一个名为`addTopic`的函数。它将接受两个参数：要附加到的对象和单个项目。例如，使用方式如下：

```js
if(product.hasOwnProperty('vendor')) {
  this.addTopic(this.topics.vendor, product.vendor, product.handle);
}
```

创建函数并将`hasOwnProperty`内部的逻辑抽象出来。将两个参数命名为`category`和`item`，并相应地更新代码：

```js
methods: {
  addTopic(category, item, handle) {
    if(item.handle) {

      if(category.values[item.handle]) {
        if(!category.values[item.handle].count.includes(handle)) {
          category.values[item.handle].count.push(handle);
        }

      } else {

        category.values[item.handle] = {
          ...item,
          count: [handle]
        }
      }
    }
  }
}
```

更新`filters`计算属性函数，使用新的`addTopic`方法。删除函数顶部的变量声明，因为它们直接传递给方法：

```js
filters() {
  if(this.categoriesExist) {

    let category = this.categoryProducts(this.slug);

    for(let product of category.productDetails) {

      if(product.hasOwnProperty('vendor')) {
        this.addTopic(this.topics.vendor, product.vendor, product.handle);
      }

      if(product.hasOwnProperty('tags')) {
        for(let tag of product.tags) {
          this.addTopic(this.topics.tags, tag, product.handle);
        }
      }

    }
  }
}
```

在函数末尾返回`this.topics`。虽然我们可以直接在模板中引用`topics`，但我们需要确保`filters`计算属性被触发：

```js
filters() {
  if(this.categoriesExist) {
    ...
  }

  return this.topics;
}
```

在继续创建基于不同类型的动态过滤器之前，让我们显示当前的过滤器。

由于`topics`对象的设置方式，我们可以循环遍历每个子对象，然后遍历每个对象的`values`。我们将使用复选框来创建过滤器，输入的值将是每个过滤器的句柄：

```js

template: `<div>
 <div class="filters">
 <div class="filterGroup" v-for="filter in filters">
 <h3>{{ filter.title }}</h3>

 <label class="filter" v-for="value in filter.values">
 <input type="checkbox" :value="value.handle">
 {{ value.title }} ({{ value.count }})
 </label>
 </div> 
 </div>

  <list-categories />
</div>`,
```

为了跟踪已检查的内容，我们可以使用`v-model`属性。如果有多个复选框使用相同的`v-model`，Vue 会创建一个包含每个项目的数组。

在数据对象的每个`topic`对象中添加一个`checked`数组：

```js
data() {
  return {
    topics: {
      vendor: {
        title: 'Manufacturer',
        handle: 'vendor',
        checked: [],
        values: {}
      },
      tags: {
        title: 'Tags',
        handle: 'tags',
        checked: [],
        values: {}
      }
    }
  }
}
```

接下来，为每个复选框添加一个`v-model`属性，引用`filter`对象上的该数组，并添加一个点击绑定器，引用一个`updateFilters`方法：

```js
<div class="filters">
  <div class="filterGroup" v-for="filter in filters">
    <h3>{{ filter.title }}</h3>

    <label class="filter" v-for="value in filter.values">
      <input type="checkbox" :value="value.handle" v-model="filter.checked"  @click="updateFilters">
      {{ value.title }} ({{ value.count }})
    </label>
  </div> 
</div>
```

暂时创建一个空方法，稍后我们将配置它：

```js
methods: {
    addTopic(category, item) {
      ...
    },

 updateFilters() {

 }
}
```

# 动态创建过滤器

通过创建和监视固定的过滤器，我们可以利用这个机会创建动态过滤器。这些过滤器将观察产品上的`variationTypes`（例如颜色和尺寸），并列出选项 - 再次包括每个选项的计数。

为了实现这一点，我们首先需要循环遍历产品上的`variationTypes`。在添加任何内容之前，我们需要检查该变体类型是否存在于`topics`对象上，如果不存在 - 我们需要添加一个骨架对象。这会展开变体（其中包含`title`和`handle`），并且还包括空的`checked`和`value`属性：

```js
filters() {
  if(this.categoriesExist) {

    let category = this.categoryProducts(this.slug);

    for(let product of category.productDetails) {

      if(product.hasOwnProperty('vendor')) {
        this.addTopic(this.topics.vendor, product.vendor);
      }

      if(product.hasOwnProperty('tags')) {
        for(let tag of product.tags) {
          this.addTopic(this.topics.tags, tag);
        }
      }

 Object.keys(product.variationTypes).forEach(vkey => {
 let variation = product.variationTypes[vkey];

 if(!this.topics.hasOwnProperty(variation.handle)) {
 this.topics[variation.handle] = {
 ...variation,
 checked: [],
 values: {}
 }
 }
 });

    }
  }

  return this.topics;
}
```

创建了空对象后，我们现在可以循环遍历产品对象上的`variationProducts`。对于每个产品，我们可以通过当前变体的句柄访问变体。从那里，我们可以使用我们的`addTopic`方法在过滤器中包含值（例如，蓝色或 XL）：

```js
Object.keys(product.variationTypes).forEach(vkey => {
  let variation = product.variationTypes[vkey];

  if(!this.topics.hasOwnProperty(variation.handle)) {
    this.topics[variation.handle] = {
      ...variation,
      checked: [],
      values: {}
    }
  }

  Object.keys(product.variationProducts).forEach(pkey => {
 let variationProduct = product.variationProducts[pkey]; 
 this.addTopic(
 this.topics[variation.handle],
 variationProduct.variant[variation.handle],      product.handle
 );
 });

});
```

但是，我们确实需要更新我们的`addTopic`方法。这是因为动态属性具有`value`，而不是标题。

在您的`addTopic`方法中添加一个`if`语句，检查是否存在一个`value`，如果存在 - 将其设置为`title`：

```js
addTopic(category, item, handle) {
  if(item.handle) {

    if(category.values[item.handle]) {
      if(!category.values[item.handle].count.includes(handle)) {
        category.values[item.handle].count.push(handle);
      }

    } else {

 if(item.hasOwnProperty('value')) {
 item.title = item.value;
 }

      category.values[item.handle] = {
        ...item,
        count: [handle]
      }
    }
  }
}
```

在浏览器中查看应用程序应该显示出您动态添加的过滤器，以及我们添加的原始过滤器。

# 重置过滤器

在导航到不同类别之间，您会注意到，当前的过滤器不会重置。这是因为我们在每次导航之间没有清除过滤器，数组仍然存在。这并不理想，因为这意味着随着您的导航，过滤器会变得越来越长，并且不适用于产品列表。

为了解决这个问题，我们可以创建一个返回默认主题对象的方法，并在“slug”更新时调用该方法来重置`topics`对象。将`topics`对象移动到一个名为`defaultTopics`的新方法中：

```js
methods: {
 defaultTopics() {
 return {
 vendor: {
 title: 'Manufacturer',
 handle: 'vendor',
 checked: [],
 values: {}
 },
 tags: {
 title: 'Tags',
 handle: 'tags',
 checked: [],
 values: {}
 }
 }
 },

  addTopic(category, item) {
    ...
  }

  updateFilters() {

  }
}
```

在`data`函数中，将 topics 的值更改为`this.defaultTopics()`来调用该方法：

```js
data() {
  return {
    topics: this.defaultTopics()
  }
},
```

最后，在`slug`更新时，添加一个监视函数来重置主题键：

```js
watch: {
  slug() {
 this.topics = this.defaultTopics();
 }
}
```

# 在复选框过滤器更改时更新 URL

当与过滤器组件交互时，将更新 URL 查询参数。这允许用户看到过滤器的效果，将其加为书签，并在需要时共享 URL。我们已经在分页中使用了查询参数，将用户放回第一页进行过滤是有意义的 - 因为可能只有一页。

为了构建我们的过滤器查询参数，我们需要循环遍历每个过滤器类型，并为每个具有`checked`数组中的项目的过滤器添加一个新参数。然后，我们可以调用`router.push()`来更新 URL，并相应地更改显示的产品。

在`updateFilters`方法中创建一个空对象。循环遍历主题并使用选中的项目填充`filters`对象。将路由器中的`query`参数设置为`filters`对象：

```js
updateFilters() {
  let filters = {};

 Object.keys(this.topics).forEach(key => {
 let topic = this.topics[key];
 if(topic.checked.length) {
 filters[key] = topic.checked;
 }
 });

 this.$router.push({query: filters});
}
```

在右侧勾选和取消勾选过滤器应该更新 URL 中的已选项目。

# 在页面加载时预选过滤器

在加载已经在 URL 中具有过滤器的类别时，我们需要确保右侧的复选框被选中。这可以通过循环遍历现有的查询参数，并将任何匹配的键和数组添加到主题参数中来完成。由于`query`可以是数组或字符串，我们需要确保无论如何，选中的属性都是一个数组。我们还需要确保查询键确实是一个过滤器，而不是一个页面参数。

```js
filters() {
  if(this.categoriesExist) {

    let category = this.categoryProducts(this.slug);

    for(let product of category.productDetails) {
      ...
    }

 Object.keys(this.$route.query).forEach(key => {
      if(Object.keys(this.topics).includes(key)) {
        let query = this.$route.query[key];
        this.topics[key].checked = Array.isArray(query) ? query : [query];
      }
    });
  }

  return this.topics;
}
```

在页面加载时，URL 中的过滤器将被选中。

# 过滤产品

我们现在正在动态创建和附加过滤器，并且激活过滤器会更新 URL 中的查询参数。现在我们可以根据 URL 参数显示和隐藏产品。我们将通过在传递给`ListProducts`组件之前对产品进行过滤来实现这一点。这确保了分页的正确工作。

在过滤产品时，打开`ListProducts.js`并为每个列表项添加一个`：key`属性，其值为`handle`：

```js
<ol :start="pagination.range.from + 1">
  <li v-for="product in paginate(products)" :key="product.handle">
    ...
  </li>
</ol>
```

打开`CategoryPage`视图，并在`methods`对象中创建一个名为`filtering()`的方法，并添加`return true`以开始。该方法应接受两个参数，一个`product`和一个`query`对象：

```js
methods: {
  filtering(product, query) {

 return true;
 }
}
```

接下来，在`category`计算函数内部，如果存在查询参数，我们需要过滤产品。但是，我们需要小心，如果页面号也是一个查询参数，我们不要触发过滤器。

创建一个名为`filters`的新变量，它是来自路由的查询对象的副本。接下来，如果页面参数存在，则从我们的新对象中`删除`它。从那里，我们可以检查查询对象是否有其他内容，如果有，就可以在我们的产品数组上运行原生 JavaScript 的`filter()`函数 - 将产品和新的查询/过滤器对象传递给我们的方法：

```js
category() {
  if(this.categoriesExist) {
    let category = this.categoryProducts(this.slug),
 filters = Object.assign({}, this.$route.query);

 if(Object.keys(filters).length && filters.hasProperty('page')) {
 delete filters.page;
 }

 if(Object.keys(filters).length) {
 category.productDetails = category.productDetails.filter(
 p => this.filtering(p, filters)
 );
 }

    if(!category) {
      this.categoryNotFound = true;
    }
    return category;
  }
}
```

刷新您的应用程序以确保产品仍然显示。

要过滤产品，涉及到一个相当复杂的过程。我们想要检查一个属性是否在查询参数中；如果是，我们将设置一个占位值为`false`。如果产品上的属性与查询参数相匹配，我们将将占位符设置为`true`。然后我们对每个查询参数重复这个过程。完成后，我们只显示符合所有条件的产品。

我们构建的方式允许产品在类别内为“或”，但在不同部分为“与”。例如，如果用户选择了多种颜色（红色和绿色）和一个标签（配件），它将显示所有红色或绿色配件的产品。

我们的过滤器是通过标签、供应商和动态过滤器创建的。由于其中两个属性是固定的，我们将首先检查这些属性。动态过滤器将通过重构它们的构建方式进行验证。

创建一个`hasProperty`对象，它将是我们用来跟踪产品具有的查询参数的占位符对象。我们将从`vendor`开始 - 因为这是最简单的属性。

我们首先通过循环遍历查询属性 - 如果有多个属性（例如红色和绿色），接下来，我们需要确认`query`中是否存在`vendor` - 如果存在，我们将在`hasProperty`对象中将`vendor`属性设置为`false`，然后我们检查`vendor`句柄是否与查询属性相同，如果匹配，我们将更改`hasProperty.vendor`属性为`true`。

```js
filtering(product, query) {
  let display = false,
 hasProperty = {};

 Object.keys(query).forEach(key => {
 let filter = Array.isArray(query[key]) ? query[key] : [query[key]];

 for(attribute of filter) {
 if(key == 'vendor') {

 hasProperty.vendor = false;
 if(product.vendor.handle == attribute) {
 hasProperty.vendor = true;
 }

 }      }
 });

 return display;
}
```

这将根据供应商是否与所选过滤器匹配来更新`hasProperty`对象。我们可以使用`tags`复制该功能 - 记住产品上的标签是我们需要过滤的对象。

还需要检查过滤器构建的动态属性。这是通过检查每个`variationProduct`上的变体对象，并在匹配时更新`hasProperty`对象来完成的。

```js
filtering(product, query) {
  let display = false,
    hasProperty = {};

    Object.keys(query).forEach(key => {
      let filter = Array.isArray(query[key]) ? query[key] : [query[key]];

      for(attribute of filter) {
        if(key == 'vendor') {

          hasProperty.vendor = false;
          if(product.vendor.handle == attribute) {
            hasProperty.vendor = true;
          }

        } else if(key == 'tags') {
 hasProperty.tags = false;

 product[key].map(key => {
 if(key.handle == attribute) {
 hasProperty.tags = true;
 }
 });

 } else {
 hasProperty[key] = false;

 let variant = product.variationProducts.map(v => {
 if(v.variant[key] && v.variant[key].handle == attribute) {
 hasProperty[key] = true;
 }
 });
 }
 }
    });

  return display;
}
```

最后，我们需要检查`hasProperty`对象的每个属性。如果所有值都设置为`true`，我们可以将产品的显示设置为`true` - 表示它将显示。如果其中一个值为`false`，则产品将不会显示，因为它不符合所有条件。

```js
filtering(product, query) {
  let display = false,
    hasProperty = {};

    Object.keys(query).forEach(key => {
      let filter = Array.isArray(query[key]) ? query[key] : [query[key]];

      for(attribute of filter) {
        if(key == 'vendor') {

          hasProperty.vendor = false;
          if(product.vendor.handle == attribute) {
            hasProperty.vendor = true;
          }

        } else if(key == 'tags') {
          hasProperty.tags = false;

          product[key].map(key => {
            if(key.handle == attribute) {
              hasProperty.tags = true;
            }
          });

        } else {
          hasProperty[key] = false;

          let variant = product.variationProducts.map(v => {
            if(v.variant[key] && v.variant[key].handle == attribute) {
              hasProperty[key] = true;
            }
          });
        }
      }

 if(Object.keys(hasProperty).every(key => hasProperty[key])) {
 display = true;
 }

    });

  return display;
}
```

现在我们有了一个成功的过滤产品列表。在浏览器中查看您的应用程序并更新过滤器 - 注意每次单击时产品的显示和隐藏。请注意，即使您按下刷新，只有过滤后的产品会显示。

# 总结

在本章中，我们创建了一个分类列表页面，允许用户查看某一类别中的所有产品。该列表可以进行分页，并且可以改变排序。我们还创建了一个筛选组件，允许用户缩小结果范围。

现在我们的产品可以浏览、筛选和查看，我们可以继续制作购物车和结账页面。
