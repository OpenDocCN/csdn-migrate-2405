# Vue2 和 Laravel5 全栈开发（三）

> 原文：[`zh.annas-archive.org/md5/e47ac4de864f495f2e21aebfb4a63e4f`](https://zh.annas-archive.org/md5/e47ac4de864f495f2e21aebfb4a63e4f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Vue Router 构建多页面应用程序

在上一章中，我们了解了 Vue.js 组件，并将 Vuebnb 转换为基于组件的架构。现在我们已经做到了这一点，我们可以使用 Vue Router 轻松地向我们的应用程序添加新页面。

在本章中，我们将为 Vuebnb 创建一个主页，其中包括一个可点击的缩略图库，展示完整的模拟列表。

本章涉及的主题：

+   解释了路由器库是什么，以及为什么它们是单页面应用的关键部分

+   Vue Router 及其主要功能概述

+   Vue Router 的安装和基本配置

+   使用`RouterLink`和`RouterView`特殊组件来管理页面导航

+   设置 Vue 的 AJAX 以从 Web 服务检索数据而无需刷新页面

+   使用路由导航守卫在加载新页面之前检索数据

# 单页面应用程序

大多数网站都被分成页面，以使它们包含的信息更容易消化。传统上，这是通过服务器/客户端模型完成的，其中每个页面必须使用不同的 URL 从服务器加载。要导航到新页面，浏览器必须发送到该页面的 URL 的请求。服务器将发送数据回来，浏览器可以卸载现有页面并加载新页面。对于普通的互联网连接，这个过程可能需要几秒钟，用户必须等待新页面加载。

通过使用强大的前端框架和 AJAX 实用程序，可以实现不同的模型：浏览器可以加载初始网页，但导航到新页面不需要浏览器卸载页面并加载新页面。相反，新页面所需的任何数据都可以通过 AJAX 异步加载。从用户的角度来看，这样的网站看起来就像任何其他网站一样有页面，但从技术角度来看，这个网站实际上只有一个页面。因此得名，**单页面应用**（**SPA**）。

单页面应用程序架构的优势在于它可以为用户创建更无缝的体验。新页面的数据仍然必须被检索，因此会对用户的流程造成一些小的中断，但由于数据检索可以异步进行并且 JavaScript 可以继续运行，因此这种中断被最小化。此外，由于 SPA 页面通常需要较少的数据，因为一些页面元素可以重复使用，所以页面加载速度更快。

SPA 架构的缺点是，由于增加的功能，客户端应用程序变得更加臃肿，因此通过加快页面切换所获得的收益可能会被用户必须在第一次页面加载时下载一个大型应用程序所抵消。此外，处理路由会给应用程序增加复杂性，因为必须管理多个状态，处理 URL，并且必须在应用程序中重新创建许多默认的浏览器功能。

# 路由器

如果您选择 SPA 架构，并且您的应用设计包括多个页面，您将需要使用*路由器*。在这种情况下，路由器是一个库，它将通过 JavaScript 和各种本机 API 模拟浏览器导航，以便用户获得类似于传统多页面应用的体验。路由器通常包括以下功能：

+   从页面内部处理导航操作

+   将应用程序的部分与路由匹配

+   管理地址栏

+   管理浏览器历史记录

+   管理滚动条行为

# Vue 路由器

一些前端框架，如 Angular 或 Ember，包含一个即插即用的路由器库。这些框架的理念是，开发人员更适合使用完整的、集成的解决方案来构建他们的 SPA。

其他框架/库，如 React 和 Vue.js，不包括路由器。相反，您必须安装一个单独的库。

在 Vue.js 的情况下，有一个名为*Vue Router*的官方路由器库可用。这个库是由 Vue.js 核心团队开发的，因此它针对与 Vue.js 一起使用进行了优化，并充分利用了基本的 Vue 功能，如组件和响应性。

使用 Vue Router，应用程序的不同*页面*由不同的组件表示。当您设置 Vue Router 时，您将传递配置，告诉它哪个 URL 映射到哪个组件。然后，在应用程序中点击链接时，Vue Router 将交换活动组件，以匹配新的 URL，例如：

```php
let routes = [
  { path: '/', component: HomePage },
  { path: '/about', component: AboutPage },
  { path: '/contact', component: ContactPage }
];
```

由于在正常情况下渲染组件是一个几乎瞬间的过程，使用 Vue Router 在页面之间的转换也是如此。但是，有一些异步钩子可以被调用，以便让您有机会从服务器加载新数据，如果您的不同页面需要它。

# 特殊组件

当您安装 Vue Router 时，两个组件将全局注册，供整个应用程序使用：`RouterLink`和`RouterView`。

`RouterLink`通常用于替代`a`标签，并使您的链接可以访问 Vue Router 的特殊功能。

正如所解释的，Vue Router 将交换指定的页面组件，以模拟浏览器导航。`RouterView`是此组件交换发生的出口。就像插槽一样，您可以将其放在主页面模板的某个位置。例如：

```php
<div id="app">
  <header></header>
  <router-view> // This is where different page components display </router-view>
  <footer></footer>
</div>
```

# Vuebnb 路由

Vuebnb 从未被规定为单页面应用程序的目标。事实上，Vuebnb 将偏离纯 SPA 架构，我们将在本书的后面看到。

也就是说，将 Vue Router 纳入 Vuebnb 将对用户在应用程序中的导航体验非常有益，因此我们将在本章中将其添加到 Vuebnb 中。

当然，如果我们要添加一个路由，我们需要一些额外的页面！到目前为止，在项目中，我们一直在 Vuebnb 的*listing*页面上工作，但尚未开始在应用程序的首页上工作。因此，除了安装 Vue Router 之外，我们还将开始在 Vuebnb 主页上工作，该主页显示缩略图和链接到我们所有模拟列表的页面：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/ecdce2d9-a3cb-45ea-81f0-2f653471205e.png)图 7.1。Vuebnb 的首页

# 安装 Vue Router

Vue Router 是一个 NPM 包，可以在命令行上安装：

```php
$  npm i --save-dev vue-router
```

让我们将我们的路由器配置放入一个新文件`router.js`中：

```php
$ touch resources/assets/js/router.js
```

要将 Vue Router 添加到我们的项目中，我们必须导入该库，然后使用`Vue.use`API 方法使 Vue 与 Vue Router 兼容。这将为 Vue 提供一个新的配置属性`router`，我们可以使用它来连接一个新的路由器。

然后，我们使用`new VueRouter()`创建 Vue Router 的实例。

`resources/assets/js/router.js`：

```php
import Vue from 'vue';
import VueRouter from 'vue-router'; Vue.use(VueRouter);

export default new VueRouter();
```

通过从这个新文件中导出我们的路由器实例，我们已经将其转换为一个可以在`app.js`中导入的模块。如果我们将导入的模块命名为`router`，则可以使用对象解构来简洁地将其连接到我们的主配置对象。

`resources/assets/js/app.js`：

```php
import "core-js/fn/object/assign";
import Vue from 'vue';

import ListingPage from '../components/ListingPage.vue';
import router from './router'

var app = new Vue({ el: '#app', render: h => h(ListingPage), router });
```

# 创建路由

Vue Router 的最基本配置是提供一个`routes`数组，它将 URL 映射到相应的页面组件。此数组将包含至少两个属性的对象：`path`和`component`。

请注意，通过*页面组件*，我只是指任何我们指定为在我们的应用程序中表示页面的组件。它们在其他方面都是常规组件。

目前，我们的应用程序中只会有两个路由，一个用于我们的主页，一个用于我们的列表页面。`HomePage`组件尚不存在，因此在创建它之前，我们将保持其路由被注释掉。

`resources/assets/js/router.js`：

```php
import ListingPage from '../components/ListingPage.vue';

export default new VueRouter({ mode: 'history', routes: [
    // { path: '/', component: HomePage }, // doesn't exist yet!
    { path: '/listing/:listing', component: ListingPage }
  ]
});
```

您会注意到我们的`ListingPage`组件的路径包含一个动态段`:listing`，因此此路由将匹配包括`/listing/1、listing/2...listing/whatever`在内的路径。

Vue Router 有两种模式：*hash*模式和*history*模式。哈希模式使用 URL 哈希来模拟完整的 URL，因此当哈希更改时页面不会重新加载。历史模式有*真实*的 URL，并利用`history.pushState`API 来更改 URL 而不引起页面重新加载。历史模式的唯一缺点是 Vue 无法处理应用程序之外的 URL，例如`/some/weird/path`，必须由服务器处理。这对我们来说不是问题，所以我们将使用 Vuebnb 的历史模式。

# 应用程序组件

为了使我们的路由器工作，我们需要在页面模板的某个地方声明一个`RouterView`组件。否则，页面组件将无处可渲染。

我们稍微重构我们的应用程序来做到这一点。目前，`ListingPage`组件是应用程序的`root`组件，因为它位于组件层次结构的顶部，并加载我们使用的所有其他组件。

由于我们希望路由器根据 URL 在`ListingPage`和`HomePage`之间切换，我们需要另一个组件在组件层次结构中位于`ListingPage`之上并处理这项工作。我们将称这个新的根组件为`App`：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/2a411013-4710-4909-ad18-255dd9144d45.png)图 7.2。App、ListingPage 和 HomePage 之间的关系

让我们创建`App`组件文件：

```php
$ touch resources/assets/components/App.vue
```

Vue 的根实例在加载时应该将这个渲染到页面上，而不是`ListingPage`。

`resources/assets/js/app.js`：

```php
import App from '../components/App.vue';

...

var app = new Vue({ el: '#app', render: h => h(App), router });
```

以下是`App`组件的内容。我在模板中添加了特殊的`RouterView`组件，这是`HomePage`或`ListingPage`组件将渲染的出口。

您还会注意到我已经将工具栏从`app.blade.php`移动到了`App`的模板中。这样工具栏就在 Vue 的领域内；之前它在安装点之外，因此无法被 Vue 触及。我这样做是为了以后我们可以使用`RouterLink`将主标志变成一个指向主页的链接，因为这是大多数网站的惯例。我也将任何与工具栏相关的 CSS 移入了`style`元素中。

`resources/assets/components/App.vue`：

```php
<template>
  <div>
    <div id="toolbar">
      <img class="icon" src="/images/logo.png">
      <h1>vuebnb</h1>
    </div>
    <router-view></router-view>
  </div>
</template>
<style> #toolbar {
    display: flex;
    align-items: center;
    border-bottom: 1px solid #e4e4e4;
    box-shadow: 0 1px 5px rgba(0, 0, 0, 0.1);
  }

  #toolbar .icon {
    height: 34px;
    padding: 16px 12px 16px 24px;
    display: inline-block;
  }

  #toolbar h1 {
    color: #4fc08d;
    display: inline-block;
    font-size: 28px;
    margin: 0;
  } </style>
```

完成后，如果您现在将浏览器导航到类似`/listing/1`的 URL，您会发现一切看起来与以前一样。但是，如果您查看 Vue Devtools，您会发现组件层次结构已经改变，反映了`App`组件的添加。

还有一个指示器，告诉我们`ListingPage`组件是 Vue Router 的活动页面组件：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/41b25c67-0eeb-449c-8448-c7703091d149.png)图 7.3。在 Vue Devtools 打开的情况下，显示组件层次结构的/listing/1

# 主页

现在让我们开始在我们的主页上工作。我们首先创建一个新组件`HomePage`：

```php
$ touch resources/assets/components/HomePage.vue
```

现在，让我们在设置之前向组件添加占位符标记。

`resources/assets/components/HomePage.vue`：

```php
<template>
  <div>Vuebnb home page</div>
</template>
```

确保在`router`文件中导入此组件，并取消使用它的路由。

`resources/assets/js/router.js`：

```php
....

import HomePage from '../components/HomePage.vue';
import ListingPage from '../components/ListingPage.vue';

export default new VueRouter({ mode: 'history', routes: [
    { path: '/', component: HomePage },
    { path: '/listing/:listing', component: ListingPage }
  ]
});
```

您可能会尝试通过将 URL`http://vuebnb.test/`放入浏览器地址栏来测试这个新路由。但是，您会发现这导致 404 错误。请记住，我们仍然没有在服务器上为此创建路由。尽管 Vue 从*内部*管理路由，但任何地址栏导航请求必须由 Laravel 提供。

现在，让我们通过使用`RouterLink`组件在工具栏中创建一个指向我们主页的链接。这个组件就像一个增强版的`a`标签。例如，如果给你的路由一个`name`属性，你可以简单地使用`to`属性，而不必提供一个`href`。Vue 会在渲染时解析这个到正确的 URL。

`resources/assets/components/App.vue`：

```php
<div id="toolbar">
  <router-link :to="{ name: 'home' }">
    <img class="icon" src="/images/logo.png">
    <h1>vuebnb</h1>
  </router-link>
</div>
```

让我们也为我们的路由添加`name`属性，以使其工作。

`resources/assets/js/app.js`：

```php
routes: [
  { path: '/', component: HomePage, name: 'home' },
  { path: '/listing/:listing', component: ListingPage, name: 'listing' }
]
```

现在我们必须修改我们的 CSS，因为我们现在的标志周围有另一个标签。修改工具栏 CSS 规则以匹配后面的规则。

`resources/assets/components/App.vue`：

```php
<template>...</template>
<style> #toolbar { border-bottom: 1px solid #e4e4e4; box-shadow: 0 1px 5px rgba(0, 0, 0, 0.1);
  }

 ... #toolbar a { display: flex; align-items: center; text-decoration: none;
  }
</style>
```

现在让我们打开一个列表页面，比如`/listing/1`。如果你检查 DOM，你会看到我们的工具栏现在里面有一个新的`a`标签，其中包含一个正确解析的链接返回到主页：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/f53a1ca6-f0d5-4c08-b75c-c6f794e81b96.png)图 7.4 工具栏是通过`RouterLink`元素返回到主页的链接

如果你点击那个链接，你会被带到主页！记住，*页面*实际上并没有改变；Vue 路由器只是在`RouterView`内将`ListingPage`替换为`HomePage`，并且通过`history.pushState`API 更新了浏览器 URL：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/4a5c5d24-13bb-45ea-8dac-a2272c4f7a4b.png)图 7.5 主页与 Vue Devtools 显示的组件层次结构

# 主页路由

现在让我们为主页添加一个服务器端路由，这样我们就可以从根路径加载我们的应用程序。这个新路由将指向`ListingController`类中的`get_home_web`方法。

`routes/web.php`：

```php
<?php

Route::get('/', 'ListingController@get_home_web'); Route::get('/listing/{listing}', 'ListingController@get_listing_web');
```

现在去控制器，我们将使`get_home_web`方法返回`app`视图，就像它为列表 web 路由所做的那样。`app`视图包括一个模板变量`model`，我们使用它来传递初始应用程序状态，就像在第五章中设置的那样，*使用 Webpack 集成 Laravel 和 Vue.js*。现在，只需将一个空数组分配为占位符。

`app/Http/Controllers/ListingController.php`：

```php
public function get_home_web() 
{
  return view('app', ['model' => []]);
}
```

完成这些后，我们现在可以导航到`http://vuebnb.test/`，它会工作！当 Vue 应用程序启动时，Vue Router 将检查 URL 值，并且看到路径是`*/*`，将在应用程序的第一次渲染中在`RouterView`出口内加载`HomePage`组件。

查看这个页面的源代码，它与我们加载列表路由时得到的页面完全相同，因为它是相同的视图，即`app.blade.php`。唯一的区别是初始状态是一个空数组：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/c29df2f7-0487-481e-8df9-ffaac0b12063.png)图 7.6 vuebnb.test 的页面源代码，初始状态为空

# 初始状态

就像我们的列表页面一样，我们的主页也需要初始状态。从最终产品来看，我们可以看到主页显示了我们所有模拟列表的摘要，包括缩略图、标题和简短描述：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/bdfc15b5-27a5-4468-a68d-bd19e7a2ac25.png)图 7.7 完成的主页，关注列表

# 重构

在我们将初始状态注入到主页之前，让我们对代码进行一些小的重构，包括重命名一些变量和重构一些方法。这将确保代码语义反映出不断变化的需求，并保持我们的代码可读性和易理解性。

首先，让我们将我们的模板变量从`$model`重命名为更一般的`$data`。

`resources/views/app.blade.php`：

```php
<script type="text/javascript"> window.vuebnb_server_data = "{!! addslashes(json_encode($data)) !!}" </script>
```

在我们的列表控制器中，我们现在要将任何通用逻辑从我们的列表路由方法中抽象出来，放到一个名为`get_listing`的新辅助方法中。在这个辅助方法中，我们将`Listing`模型嵌套在 Laravel 的`Collection`中，`Collection`是 Eloquent 模型的类似数组的包装器，提供了一堆方便的方法，我们很快就会用到。`get_listing`将包括来自`add_image_urls`辅助方法的逻辑，现在可以安全地删除它。

当我们调用`view`方法时，我们还需要反映对我们的模板变量的更改。

`app/Http/Controllers/ListingController.php`：

```php
private function get_listing($listing)
{
  $model = $listing->toArray();
  for($i = 1; $i <=4; $i++) {
    $model['image_' . $i] = asset( 'images/' . $listing->id . '/Image_' . $i . '.jpg' );
  }
  return collect(['listing' => $model]);
}

public function get_listing_api(Listing $listing)
{
  $data = $this->get_listing($listing);
  return response()->json($data);
}

public function get_listing_web(Listing $listing)
{
  $data = $this->get_listing($listing);
  return view('app', ['data' => $data]);
}

public function get_home_web() 
```

```php
{
 return view('app', ['data' => []]);
} 
```

最后，我们需要更新我们的`ListingPage`组件，以反映我们正在注入的服务器数据的新名称和结构。

`resources/assets/components/ListingPage.vue`：

```php
<script> let serverData = JSON.parse(window.vuebnb_server_data);
  let model = populateAmenitiesAndPrices(serverData.listing);

  ... </script>
```

# 主页初始状态

使用 Eloquent ORM，使用`Listing::all`方法检索所有我们的列表条目是微不足道的。这个方法在一个`Collection`对象中返回多个`Model`实例。

请注意，我们不需要模型上的所有字段，例如`amenities`，`about`等在填充主页的列表摘要时没有用到。为了确保我们的数据尽可能精简，我们可以将一个字段数组传递给`Listing::all`方法，告诉数据库只包括那些明确提到的字段。

`app/Http/Controllers/ListingController.php`：

```php
public function get_home_web() 
{
  $collection = Listing::all([
    'id', 'address', 'title', 'price_per_night'
  ]);
  $data = collect(['listings' => $collection->toArray()]);
  return view('app', ['data' => $data]);
}

/*
  [
    "listings" => [
      0 => [
        "id" => 1,
        "address" => "...",
        "title" => "...",
        "price_per_night" => "..." ]
      1 => [ ... ]
      ... 29 => [ ... ]
    ]
  ]
*/
```

# 添加缩略图

每个模拟列表都有第一张图片的缩略版本，可以用于列表摘要。缩略图比我们用于列表页面标题的图片要小得多，非常适合在主页上显示列表摘要。缩略图的 URL 是`public/images/{x}/Image_1_thumb.jpg`，其中`{x}`是列表的 ID。

`Collection`对象有一个辅助方法`transform`，我们可以使用它来为每个列表添加缩略图图片 URL。`transform`接受一个回调闭包函数，每个项目调用一次，允许您修改该项目并将其返回到集合中，而不费吹灰之力。

`app/Http/Controllers/ListingController.php`：

```php
public function get_home_web() 
{
  $collection = Listing::all([
    'id', 'address', 'title', 'price_per_night'
  ]);
  $collection->transform(function($listing) {
    $listing->thumb = asset(
      'images/' . $listing->id . '/Image_1_thumb.jpg'
    );
    return $listing;
  });
  $data = collect(['listings' => $collection->toArray()]);
  return view('app', ['data' => $data]);
}

/*
  [
    "listings" => [
      0 => [
        "id" => 1,
        "address" => "...",
        "title" => "...",
        "price_per_night" => "...",
        "thumb" => "..." ]
      1 => [ ... ]
      ... 29 => [ ... ]
    ]
  ]
*/
```

# 在客户端接收

现在初始状态已经准备好了，让我们将其添加到我们的`HomePage`组件中。但在我们使用它之前，还有一个额外的方面需要考虑：列表摘要是按*国家*分组的。再次看一下*图 7.7*，看看这些组是如何显示的。

在我们解析了注入的数据之后，让我们修改对象，使得列表按国家分组。我们可以很容易地创建一个函数来做到这一点，因为每个列表对象都有一个`address`属性，其中国家总是明确命名的，例如，*台湾台北市万华区汉中街 51 号 108*。

为了节省您编写这个函数的时间，我在`helpers`模块中提供了一个名为`groupByCountry`的函数，可以在组件配置的顶部导入。

`resources/assets/components/HomePage.vue`：

```php
...

<script>
  import { groupByCountry } from '../js/helpers';

  let serverData = JSON.parse(window.vuebnb_server_data);
  let listing_groups = groupByCountry(serverData.listings);

  export default {
    data() {
      return { listing_groups }
    }
  }
</script>
```

我们现在将通过 Vue Devtools 看到`HomePage`已经成功加载了按国家分组的列表摘要，准备显示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/3936ccf7-bf87-4f1f-81b6-ba32cefb8c2c.png)图 7.8. Vue Devtools 显示了 HomePage 组件的状态

# ListingSummary 组件

现在`HomePage`组件有了可用的数据，我们可以开始显示它。

首先，清空组件的现有内容，并将其替换为一个`div`。这个`div`将使用`v-for`指令来遍历我们的每一个列表组。由于`listing_groups`是一个具有键/值对的对象，我们将给我们的`v-for`两个别名：`group`和`country`，分别是每个对象项的值和键。

我们将在一个标题中插入`country`。`group`将在下一节中使用。

`resources/assets/components/HomePage.vue`：

```php
<template>
  <div>
    <div v-for="(group, country) in listing_groups">
      <h1>Places in {{ country }}</h1>
      <div> Each listing will go here </div>
    </div>
  </div>
</template>
<script>...</script> 
```

现在主页将会是这个样子：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/858d9f59-82a4-4b37-9f17-d66fb6b3d5ee.png)图 7.9. 在 HomePage 组件中迭代列表摘要组

由于每个列表摘要都会有一定的复杂性，我们将创建一个单独的组件`ListingSummary`来显示它们：

```php
$ touch resources/assets/components/ListingSummary.vue
```

让我们在`HomePage`模板中声明`ListingSummary`。我们将再次使用`v-for`指令来遍历`group`，一个数组，为每个成员创建一个`ListingSummary`的新实例。每个成员的数据将绑定到一个单独的 prop`listing`。

`resources/assets/components/HomePage.vue`：

```php
<template>
  <div>
    <div v-for="(group, country) in listing_groups">
      <h1>Places in {{ country }}</h1>
      <div class="listing-summaries">
        <listing-summary v-for="listing in group" 
          :key="listing.id" 
          :listing="listing"
        ></listing-summary>
      </div>
    </div>
  </div>
</template>
<script> import { groupByCountry } from '../js/helpers';
 import ListingSummary from './ListingSummary.vue'; let serverData = JSON.parse(window.vuebnb_server_data);
  let listing_groups = groupByCountry(serverData.listings);

  export default {
    data() {
      return { listing_groups }
    }, components: { ListingSummary }
  } </script>
```

让我们为`ListingSummary`组件创建一些简单的内容，只是为了测试我们的方法。

`resources/assets/components/ListingSummary.vue`：

```php
<template>
  <div class="listing-summary"> {{ listing.address }} </div>
</template>
<script> export default { props: [ 'listing' ],
  } </script>
```

刷新我们的页面，现在我们将看到我们的列表摘要的原型：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/914379fb-83ff-4ee2-9f2f-bf458f5c6cce.png)图 7.10. ListingSummary 组件的原型

由于这种方法有效，现在让我们完成`ListingSummary`组件的结构。为了显示缩略图，我们将其绑定为固定宽度/高度的背景图片`div`。我们还需要一些 CSS 规则来使其显示得很好。

`resources/assets/components/ListingSummary.vue`：

```php
<template>
  <div class="listing-summary">
    <div class="wrapper">
      <div class="thumbnail" :style="backgroundImageStyle"></div>
      <div class="info title">
        <span>{{ listing.price_per_night }}</span>
        <span>{{ listing.title }}</span>
      </div>
      <div class="info address">{{ listing.address }}</div>
    </div>
  </div>
</template>
<script> export default { props: [ 'listing' ], computed: {
      backgroundImageStyle() {
        return {
          'background-image': `url("${this.listing.thumb}")` }
      }
    }
  } </script>
<style> .listing-summary {
    flex: 0 0 auto;
  }

  .listing-summary a {
    text-decoration: none;
  }

  .listing-summary .wrapper {
    max-width: 350px;
    display: block;
  }

  .listing-summary .thumbnail {
    width: 350px;
    height: 250px;
    background-size: cover;
    background-position: center;
  }

  .listing-summary .info {
    color: #484848;
    word-wrap: break-word;
    letter-spacing: 0.2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .listing-summary .info.title {
    padding-top: 5px;
    font-weight: 700;
    font-size: 16px;
    line-height: 24px;
  }

  .listing-summary .info.address {
    font-size: 14px;
    line-height: 18px;
  } </style>
```

添加了该代码后，您的列表摘要将如下所示：

图 7.11。显示完整的列表摘要

我们给每个列表摘要一个固定的宽度/高度，以便我们可以以整齐的网格显示它们。目前，它们显示在一个高列中，所以让我们向`HomePage`组件添加一些 CSS flex 规则，将摘要放入行中。

我们将在包装摘要的元素中添加一个名为`listing-summary-group`的类。我们还将在根`div`中添加一个名为`home-container`的类，以限制页面的宽度并使内容居中。

`resources/assets/components/HomePage.vue`：

```php
<template>
  <div class="home-container">
    <div v-for="(group, country) in listing_groups" 
      class="listing-summary-group"
    > ... </div>
  </div>
</template>
<script>...</script>
<style> .home-container {
    margin: 0 auto;
    padding: 0 25px;
  }

  @media (min-width: 1131px) {
    .home-container {
      width: 1080px;
    }
  }

  .listing-summary-group {
    padding-bottom: 20px;
  }

  .listing-summaries {
    display: flex;
    flex-direction: row;
    justify-content: space-between;
    overflow: hidden;
  }
  .listing-summaries > .listing-summary {
    margin-right: 15px;
  } .listing-summaries > .listing-summary:last-child {
```

```php
 margin-right: 0;
  } </style>
```

最后，我们需要添加一个规则，防止列表强制文档边缘超出视口。将这个规则添加到主 CSS 文件中。

`resources/assets/css/style.css`：

```php
html, body {
  overflow-x: hidden;
}
```

有了这个，我们得到了一个漂亮的主页：

图 7.12。列表摘要按行显示

您会注意到在整个页面宽度上，我们只能看到每个国家组的三个列表。其他七个被 CSS 的`overflow: hidden`规则隐藏了。很快，我们将为每个组添加图像滑块功能，以允许用户浏览所有列表。

# 应用内导航

如果我们使用浏览器的地址栏导航到主页，`http://vuebnb.test/`，它可以工作，因为 Laravel 现在在这个路由上提供页面。但是，如果我们从列表页导航到主页，就不再有页面内容了：

图 7.13。从列表页导航到空的主页

我们目前没有从主页到列表页的任何链接，但如果有的话，我们会遇到类似的问题。

原因是我们的页面组件目前从我们注入到文档头部的数据中获取它们的初始状态。如果我们使用 Vue Router 导航到不会引发页面刷新的不同页面，下一个页面组件将合并错误的初始状态。

我们需要改进我们的架构，以便在导航到页面时检查注入到头部的模型是否与当前页面匹配。为了实现这一点，我们将在模型中添加一个`path`属性，并检查它是否与活动 URL 匹配。如果不匹配，我们将使用 AJAX 从网络服务获取正确的数据：

图 7.14。页面如何决定需要什么数据如果您对阅读更多关于这种设计模式感兴趣，请查看文章*Avoid This Common Anti-Pattern In Full-Stack Vue/Laravel Apps*，网址为[`vuejsdevelopers.com/2017/08/06/vue-js-laravel-full-stack-ajax/`](https://vuejsdevelopers.com/2017/08/06/vue-js-laravel-full-stack-ajax/)。

# 向模型添加路径

让我们转到列表控制器，并向注入到我们视图头部的数据添加一个`path`属性。为此，我们将添加一个名为`add_meta_data`的辅助函数，它将在后面的章节中添加路径，以及一些其他元属性。

请注意，当前路由的路径可以通过`Request`对象确定。这个对象可以被声明为任何`route-handling`函数的最后一个参数，并且由服务容器在每个请求中提供。

`app/Http/Controllers/ListingController.php`：

```php
...

private function add_meta_data($collection, $request)
{
  return $collection->merge([
    'path' => $request->getPathInfo()
  ]);
}

public function get_listing_web(Listing $listing, Request $request)
{
  $data = $this->get_listing($listing);
  $data = $this->add_meta_data($data, $request);
  return view('app', ['data' => $data]);
}

public function get_home_web(Request $request)
{
  $collection = Listing::all([
    'id', 'address', 'title', 'price_per_night'
  ]);
  $collection->transform(function($listing) {
    $listing->thumb = asset(
      'images/' . $listing->id . '/Image_1_thumb.jpg'
    );
    return $listing;
  });
  $data = collect(['listings' => $collection->toArray()]);
  $data = $this->add_meta_data($data, $request);
  return view('app', ['data' => $data]);
}

/*
  [
    "listings" => [ ... ],
    "path" => "/"
  ]
*/
```

# 路由导航守卫

类似于生命周期钩子，*导航守卫*允许您在其生命周期的特定时刻拦截 Vue Router 导航。这些守卫可以应用于特定组件、特定路由或所有路由。

例如，`afterEach`是在任何路由被导航离开后调用的导航守卫。您可以使用此钩子来存储分析信息，例如：

```php
router.afterEach((to, from) => {
  storeAnalytics(userId, from.path);
})
```

我们可以使用`beforeRouteEnter`导航守卫从我们的网络服务中获取数据，如果头部的数据不合适。考虑以下伪代码，说明我们可能如何实现这一点：

```php
beforeRouteEnter(to, from, next) {
  if (to !== injectedData.path) { getDataWithAjax.then(data => {
      applyData(data)
    })
  } else {
    applyData(injectedData)
  }
  next()
}
```

# 下一个

导航守卫的一个重要特性是它们会阻止导航，直到调用`next`函数。这允许在解析导航之前执行异步代码。

```php
beforeRouteEnter(to, from, next) {
  new Promise(...).then(() => {
    next();  
  });
}
```

你可以向`next`函数传递`false`来阻止导航，或者你可以传递一个不同的路由来重定向它。如果你什么都不传，导航被认为是确认的。

`beforeRouteEnter`守卫是一个特殊情况。首先，在它内部，`this`是未定义的，因为它是在下一个页面组件被创建之前调用的。

```php
beforeRouteEnter(to, from, next) { console.log(this); // undefined
}
```

然而，在`beforeRouteEnter`中的`next`函数可以接受一个回调函数作为参数，例如，`next(component => { ... });`其中`component`是页面组件实例。

这个回调函数直到路由确认并且组件实例被创建后才会被触发。由于 JavaScript 闭包的工作原理，回调函数将可以访问它被调用的周围代码的作用域。

```php
beforeRouteEnter(to, from, next) {
  var data = { ... }
  next(component => { component.$data = data;
  });
}
```

# HomePage 组件

让我们把`beforeRouteEnter`添加到`HomePage`组件中。首先，将从文档头部检索数据的任何逻辑移到这个钩子中。然后我们检查数据的`path`属性，看它是否与当前路由匹配。如果是，我们调用`next`并传递一个将数据应用到组件实例的回调函数。如果不是，我们需要使用 AJAX 来获取正确的数据。

`resources/assets/components/HomePage.vue`：

```php
export default {
  data() {
    return { listing_groups: []
    };
  }, components: { ListingSummary }, beforeRouteEnter(to, from, next) {
    let serverData = JSON.parse(window.vuebnb_server_data);
    if (to.path === serverData.path) {
      let listing_groups = groupByCountry(serverData.listings);
      next(component => component.listing_groups = listing_groups);
    } else { console.log('Need to get data with AJAX!')
      next(false);
    }
  }
}
```

我已经添加了`listing_groups`作为数据属性。之前，我们在组件实例创建时应用我们的数据。现在，我们在组件创建后应用数据。为了设置响应式数据，Vue 必须知道数据属性的名称，所以我们用空值初始化，当需要的数据可用时再更新它。

# 主页 API 端点

现在我们将实现 AJAX 功能。不过，在我们这样做之前，我们需要在我们的 Web 服务中添加一个主页端点。

首先添加主页 API 路由。

`routes/api.php`：

```php
...

Route::get('/', 'ListingController@get_home_api');
```

现在看看`ListingController`类，我们将把`get_home_web`中的大部分逻辑抽象成一个新函数`get_listing_summaries`。然后我们将在`get_home_api`方法中使用这个函数并返回一个 JSON 响应。

`app/Http/Controllers/ListingController.php`：

```php
private function get_listing_summaries()
{
  $collection = Listing::all([
    'id', 'address', 'title', 'price_per_night'
  ]);
  $collection->transform(function($listing) {
    $listing->thumb = asset(
      'images/' . $listing->id . '/Image_1_thumb.jpg'
    );
    return $listing;
  });
  return collect(['listings' => $collection->toArray()]);
}

public function get_home_web(Request $request)
{
  $data = $this->get_listing_summaries();
  $data = $this->add_meta_data($data, $request);
  return view('app', ['data' => $data]);
}

public function get_home_api()
{
  $data = $this->get_listing_summaries();
  return response()->json($data);
}
```

# Axios

为了执行对 Web 服务的 AJAX 请求，我们将使用包含在 Laravel 默认前端代码中的 Axios HTTP 客户端。Axios 有一个非常简单的 API，允许我们向 GET URL 发出请求，如下所示：

```php
axios.get('/my-url');
```

Axios 是一个基于 Promise 的库，所以为了获取响应，你可以简单地链接一个`then`回调：

```php
axios.get('/my-url').then(response => { console.log(response.data); // Hello from my-url
});
```

由于 Axios NPM 包已经安装，我们可以导入`HomePage`组件。然后我们可以使用它来执行对主页 API 端点`/api/`的请求。在`then`回调中，我们将返回的数据应用到组件实例，就像我们在内联模型中所做的那样。

`resources/assets/components/HomePage.vue`：

```php
...
import axios from 'axios';

export default {
  data() { ... },
  components: { ... },
  beforeRouteEnter (to, from, next) {
    let serverData = JSON.parse(window.vuebnb_server_data);
    if (to.path === serverData.path) {
      let listing_groups = groupByCountry(serverData.listings);
      next(component => component.listing_groups = listing_groups);
    } else {
      axios.get(`/api/`).then(({ data }) => {
        let listing_groups = groupByCountry(data.listings);
        next(component => component.listing_groups = listing_groups);
      });
    }
  }
}
```

有了这个，我们现在可以以两种方式导航到主页，一种是通过地址栏，另一种是从列表页面的链接导航。无论哪种方式，我们都能得到正确的数据！

# 混合

如果你有任何在组件之间共同的功能，你可以把它放在一个`mixin`中，以避免重写相同的功能。

Vue `mixin`是一个与组件配置对象形式相同的对象。要在组件中使用它，声明为一个数组，并将其分配给配置属性`mixin`。当这个组件被实例化时，`mixin`的任何配置选项将与你在组件上声明的选项合并：

```php
var mixin = { methods: {
    commonMethod() { console.log('common method');
    }
  }
}; Vue.component('a', { mixins: [ mixin ]
}); Vue.component('b', { mixins: [ mixin ] methods: {
    otherMethod() { ... }
  }
});
```

你可能想知道，如果组件配置中有一个与`mixin`冲突的方法或其他属性会发生什么。答案是`mixins`有一个*合并策略*来确定任何冲突的优先级。通常，组件指定的配置将优先。合并策略的详细信息在 Vue.js 文档中解释[`vuejs.org`](http://vuejs.org)。

# 将解决方案移动到 mixin

让我们将解决方案概括为获取首页正确数据的解决方案，以便我们也可以在列表页面上使用它。为此，我们将 Axios 和`beforeRouteEnter`钩子从`HomePage`组件移动到一个 mixin 中，然后可以将其添加到两个页面组件中：

```php
$ touch resources/assets/js/route-mixin.js
```

同时，让我们通过删除`next`函数调用的重复来改进代码。为此，我们将创建一个新方法`getData`，它将负责找出页面的正确数据来源，并获取它。请注意，这个方法将是异步的，因为它可能需要等待 AJAX 解析，所以它将返回一个 Promise 而不是实际值。这个 Promise 然后在导航守卫中解析。

`resources/assets/js/route-mixin.js`：

```php
import axios from 'axios';

function getData(to) {
  return new Promise((resolve) => {
    let serverData = JSON.parse(window.vuebnb_server_data);
    if (!serverData.path || to.path !== serverData.path) { axios.get(`/api${to.path}`).then(({ data }) => {
        resolve(data);
      });
    } else {
      resolve(serverData);
    }
  });
}

export default { beforeRouteEnter: (to, from, next) => {
    getData(to).then((data) => {
      next(component => component.assignData(data));
    });
  }
};
```

我们不需要为 Promise 添加 polyfill，因为`Axios`库中已经提供了。

# assignData

您会注意到在`next`回调中，我们调用了主题组件上的一个方法`assignData`，并将数据对象作为参数传递。我们需要在使用这个`mixin`的任何组件中实现`assignData`方法。我们这样做是为了让组件在应用到组件实例之前，如果需要的话，可以处理数据。例如，`ListingPage`组件必须通过`populateAmenitiesAndPrices`辅助函数处理数据。

`resources/assets/components/ListingPage.vue`：

```php
...

import routeMixin from '../js/route-mixin';

export default { mixins: [ routeMixin ],
  data() {
    return { title: null, about: null, address: null, amenities: [], prices: [], images: []
    }
  }, components: { ... }, methods: {
    assignData({ listing }) { Object.assign(this.$data, populateAmenitiesAndPrices(listing));
    },
    openModal() {
      this.$refs.imagemodal.modalOpen = true;
    }
  }
}
```

我们还需要将`assignData`添加到`HomePage`组件中。

`resources/assets/components/HomePage.vue`：

```php
<script>
  import { groupByCountry } from '../js/helpers';
  import ListingSummary from './ListingSummary.vue';

  import axios from 'axios';
  import routeMixin from '../js/route-mixin';

  export default { mixins: [ routeMixin ],
    data() { ... }, methods: {
      assignData({ listings }) {
        this.listing_groups = groupByCountry(listings);
      },
    }, components: { ... }
  }
</script>
```

# 链接到列表页面

上面的方法应该有效，但我们无法测试，因为尚未有任何应用内链接到列表页面！

我们的每个`ListingSummary`实例代表一个单独的列表，并且应该是指向该列表页面的可点击链接。让我们使用`RouterLink`组件来实现这一点。请注意，我们绑定到`to`属性的对象包括路由的名称以及一个`params`对象，其中包括路由的动态段的值，即列表 ID。

`resources/assets/components/ListingSummary.vue`：

```php
<div class="listing-summary">
  <router-link :to="{ name: 'listing', params: { listing: listing.id } }">
    <div class="wrapper">
      <div class="thumbnail" :style="backgroundImageStyle"></div>
      <div class="info title">
        <span>{{ listing.price_per_night }}</span>
        <span>{{ listing.title }}</span>
      </div>
      <div class="info address">{{ listing.address }}</div>
    </div>
  </router-link>
</div>
```

完成后，列表摘要现在将是链接。从一个链接到列表页面，我们看到这个：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/47a777b4-a997-42b3-bf6b-5e8d34379b22.png)图 7.15\. 导航到列表页面后成功的 AJAX 调用

我们可以在*图 7.15*中看到，对列表 API 的 AJAX 调用成功返回了我们想要的数据。如果我们还查看 Vue Devtools 选项卡，以及 Dev Tools 控制台，我们可以看到组件实例中的正确数据。问题是，现在我们对头部图片有一个未处理的 404 错误：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/99a48262-9bff-432f-8679-3a846aca5295.png)图 7.16\. Dev Tools 控制台显示错误

原因是组件的第一次渲染发生在`next`钩子中的回调之前。这意味着组件数据的初始化值在第一次渲染中被使用。

`resources/assets/components/ListingPage.vue`：

```php
data() {
  return { title: null, about: null, address: null, amenities: [], prices: [], images: []
  }
},
```

在`HeaderImage`声明中，我们像这样绑定第一个图像：`:image-url="images[0]"`。由于数组最初是空的，这将是一个未定义的值，并导致未处理的错误。

解释很复杂，但修复很简单：只需在`header-image`中添加`v-if`，确保在有效数据可用之前不会渲染。

`resources/assets/components/ListingPage.vue`：

```php
<header-image v-if="images[0]" 
  :image-url="images[0]" 
  @header-clicked="openModal"
></header-image>
```

# 滚动行为

网站导航的另一个方面是浏览器自动管理的*滚动行为*。例如，如果您滚动到页面底部，然后导航到新页面，滚动位置将被重置。但是，如果您返回到上一个页面，浏览器会记住滚动位置，并将您带回底部。

当我们使用 Vue Router 劫持导航时，浏览器无法做到这一点。因此，当您滚动到 Vuebnb 主页的底部并点击古巴的某个列表时，当加载列表页面组件时，滚动位置不会改变。这对用户来说感觉非常不自然，用户期望被带到新页面的顶部：

图 7.17。使用 Vue Router 导航后的滚动位置问题

Vue Router 有一个`scrollbehavior`方法，允许您通过简单地定义水平和垂直滚动条的`x`和`y`位置来调整页面在更改路由时滚动到的位置。为了保持简单，但仍然保持用户体验自然，让我们使得在加载新页面时总是在页面顶部。

`resources/assets/js/router.js`：

```php
export default new VueRouter({ mode: 'history', routes: [ ... ], scrollBehavior (to, from, savedPosition) {
    return { x: 0, y: 0 }
  }
});
```

# 添加页脚

为了改进 Vuebnb 的设计，让我们在每个页面的底部添加一个页脚。我们将把它做成一个可重用的组件，所以让我们从创建它开始：

```php
$ touch resources/assets/components/CustomFooter.vue
```

这是标记。目前，它只是一个无状态的组件。

`resources/assets/js/CustomFooter.vue`：

```php
<template>
  <div id="footer">
    <div class="hr"></div>
    <div class="container">
      <p>
        <img class="icon" src="/images/logo_grey.png"> <span>
          <strong>Vuebnb</strong>. A full-stack Vue.js and Laravel demo app
 </span> </p>
    </div>
  </div>
</template>
<style> #footer {
    margin-bottom: 3em;
  }

  #footer .icon {
    height: 23px;
    display: inline-block;
    margin-bottom: -6px;
  }

  .hr {
    border-bottom: 1px solid #dbdbdb;
    margin: 3em 0;
  }

  #footer p {
    font-size</span>: 15px;
    color: #767676 !important;
 display: flex; }
 #footer p img {
 padding-right: 6px;
 } </style>
```

让我们将页脚添加到`App`组件中，在输出页面的`RouterView`下方。

`resources/assets/js/App.vue`：

```php
<template>
  <div>
    <div id="toolbar">...</div>
    <router-view></router-view>
    <custom-footer></custom-footer>
  </div>
</template>
<script> import CustomFooter from './CustomFooter.vue';

  export default { components: { CustomFooter }
  } </script>
<style>...</style>
```

这是它在列表页面上的样子：

图 7.18。列表页面上的自定义页脚

现在它在主页上的样子。它看起来不太好，因为文本没有左对齐，这不是您期望的。这是因为在这个页面上使用的容器约束与我们添加到页脚的`.container`类不同：

图 7.19。主页上的自定义页脚

事实上，`.container`是专门为列表页面设计的，而`.home-container`是为主页设计的。为了解决这个问题，让事情变得不那么混乱，让我们首先将`.container`类重命名为`.listing-container`。您还需要更新`ListingPage`组件，以确保它使用这个新的类名。

其次，让我们也将`.home-container`移到主 CSS 文件中，因为我们将全局使用它。

`resources/assets/css/style.css`：

```php
.listing-container {
  margin: 0 auto;
  padding: 0 12px;
}

@media (min-width: 744px) {
  .listing-container {
    width: 696px;
  }
}

.home-container {
  margin: 0 auto;
  padding: 0 25px;
}

@media (min-width: 1131px) {
  .home-container {
    width: 1080px;
  }
}
```

现在我们有`.home-container`和`.listing-container`作为我们`custom-footer`组件的两个可能的容器。让我们根据路由动态选择类，以便页脚始终正确对齐。

# 路由对象

*路由对象*代表当前活动路由的状态，并可以在根实例或组件实例中访问，如`this.$route`。该对象包含当前 URL 的解析信息以及 URL 匹配的路由记录：

```php
created() { console.log(this.$route.fullPath); // /listing/1 console.log(this.$route.params); // { listing: "1" }
}
```

# 动态选择容器类

为了在`custom-footer`中选择正确的容器类，我们可以从路由对象中获取当前路由的名称，并在模板文字中使用它。

`resources/assets/components/CustomFooter.vue`：

```php
<template>
  <div id="footer">
    <div class="hr"></div>
    <div :class="containerClass">
      <p>...</p>
    </div>
  </div>
</template>
<script>
  export default { computed: {
      containerClass() {
        // this.$route.name is either 'home' or 'listing'
        return `${this.$route.name}-container`;
      }
    }
  }
</script>
<style>...</style>  
```

现在，当在主页上显示时，页脚将使用`.home-container`：

图 7.20。主页上的自定义页脚与正确的容器类

# 列表摘要图像滑块

在我们的主页上，我们需要让用户能够看到每个国家的可能 10 个列表中不止三个。为此，我们将每个列表摘要组转换为图像滑块。

让我们创建一个新的组件来容纳每个列表摘要组。然后我们将箭头添加到该组件的两侧，让用户可以轻松地浏览其列表：

```php
$ touch resources/assets/components/ListingSummaryGroup.vue
```

现在，我们将从`HomePage`中将显示列表摘要的标记和逻辑抽象到这个新组件中。每个组需要知道国家的名称和包含的列表，因此我们将这些数据添加为 props。

`resources/assets/components/ListingSummaryGroup.vue`：

```php
<template>
  <div class="listing-summary-group">
    <h1>Places in {{ country }}</h1>
    <div class="listing-summaries">
      <listing-summary v-for="listing in listings"
        :key="listing.id"
        :listing="listing"
      ></listing-summary>
    </div>
  </div>
</template>
<script> import ListingSummary from './ListingSummary.vue';

  export default { props: [ 'country', 'listings' ], components: { ListingSummary }
  } </script>
<style> .listing-summary-group {
    padding-bottom: 20px;
  }

  .listing-summaries {
    display: flex;
    flex-direction: row;
    justify-content: space-between;
    overflow: hidden;
  }
  .listing-summaries > .listing-summary {
    margin-right: 15px;
  }

  .listing-summaries > .listing-summary:last-child {
    margin-right: 0;
  } </style>
```

回到`HomePage`，我们将使用`v-for`声明`ListingSummaryGroup`，对每个国家组进行迭代。

`resources/assets/components/HomePage.vue`:

```php
<template>
  <div class="home-container">
    <listing-summary-group v-for="(group, country) in listing_groups"
      :key="country"
      :listings="group"
      :country="country"
      class="listing-summary-group"
    ></listing-summary-group>
  </div>
</template>
<script> import routeMixin from '../js/route-mixin';
  import ListingSummaryGroup from './ListingSummaryGroup.vue';
  import { groupByCountry } from '../js/helpers';

  export default { mixins: [ routeMixin ],
    data() {
      return { listing_groups: []
      };
    }, methods: {
      assignData({ listings }) {
        this.listing_groups = groupByCountry(listings);
      }
    }, components: { ListingSummaryGroup }
  } </script>
```

大多数开发人员会将术语*图像轮播*和*图像滑块*互换使用。在本书中，我做了一个细微的区分，*轮播*包含一个完全被另一个替换的单个图像，而*滑块*则是移动图像的位置，同时可见几个图像。

# 添加滑块

现在我们将为`ListingSummaryGroup`添加滑块功能。为此，我们将重用我们在第六章中制作的`CarouselControl`组件，*使用 Vue.js 组件组合小部件*。我们希望在组的两侧显示一个，所以让我们将它们放入模板中，记得声明`dir`属性。我们还将添加一些结构标记和 CSS 来显示控件。

`resources/assets/components/ListingSummaryGroup.vue`:

```php
<template>
  <div class="listing-summary-group">
    <h1>Places in {{ country }}</h1>
    <div class="listing-carousel">
      <div class="controls">
        <carousel-control dir="left"></carousel-control>
        <carousel-control dir="right"></carousel-control>
      </div>
      <div class="listing-summaries-wrapper">
        <div class="listing-summaries">
          <listing-summary v-for="listing in listings"
            :listing="listing"
            :key="listing.id"
          ></listing-summary>
        </div>
      </div>
    </div>
  </div>
</template>
<script> import ListingSummary from './ListingSummary.vue';
  import CarouselControl from './CarouselControl.vue';

  export default { props: [ 'country', 'listings' ], components: { ListingSummary, CarouselControl }
  } </script>
<style> ... .listing-carousel {
  position: relative;
}

.listing-carousel .controls {
  display: flex;
  justify-content: space-between;
  position: absolute;
  top: calc(50% - 45px);
  left: -45px;
  width: calc(100% + 90px);
}

.listing-carousel .controls .carousel-control{
  color: #c5c5c5;
  font-size: 1.5rem;
  cursor: pointer;
}

.listing-summaries-wrapper {
  overflow: hidden;
} </style>
```

添加了这段代码后，您的主页将如下所示：

图 7.21\. 列表摘要组的轮播控件

# 平移

为了在点击轮播控件时*移动*我们的列表摘要，我们将使用一个名为`translate`的 CSS 变换。这将使受影响的元素从当前位置移动指定像素的距离。

每个列表摘要的总宽度为 365px（350px 固定宽度加上 15px 边距）。这意味着如果我们将我们的组向左移动 365px，它将产生将所有图像位置向左移动一个的效果。您可以在这里看到我已经添加了平移作为内联样式以测试它是否有效。请注意，我们以*负*方向进行平移以使组向左移动：

图 7.22\. 使用平移向左移动的列表组

通过将内联样式绑定到具有`listing-summary`类的元素，我们可以通过 JavaScript 控制平移。让我们通过一个计算属性来做到这一点，这样我们就可以动态计算平移量。

`resources/assets/components/ListingSummaryGroup.vue`:

```php
<template>
  <div class="listing-summary-group">
    <h1>Places in {{ country }}</h1>
    <div class="listing-carousel">
      <div class="controls">...</div>
      <div class="listing-summaries" :style="style">
        <listing-summary...>...</listing-summary>
      </div>
    </div>
  </div>
</template>
<script>
  export default { props: [ 'country', 'listings' ], computed: {
      style() {
        return { transform: `translateX(-365px)` }
      }
    }, components: { ... }
  }
</script>
```

现在所有的摘要组都将被移动：

图 7.23\. 通过 JavaScript 控制的平移后的列表组

*图 7.23*中显而易见的问题是，我们一次只能看到三张图像，并且它们溢出到容器的其他部分。

为了解决这个问题，我们将把 CSS 规则`overflow: hidden`从`listing-summaries`移到`listing-summaries-wrapper`。

`resources/assets/components/ListingSummaryGroup.vue`:

```php
... .listing-summaries-wrapper {
  overflow: hidden;
}

.listing-summaries {
  display: flex;
  flex-direction: row;
  justify-content: space-between;  
} ...
```

# 轮播控件

现在我们需要轮播控件来改变平移的值。为此，让我们在`ListingSummaryGroup`中添加一个数据属性`offset`。这将跟踪我们移动了多少图像，即它将从零开始，最多到七（不是 10，因为我们不希望移动得太远，以至于所有图像都超出屏幕）。

我们还将添加一个名为`change`的方法，它将作为自定义事件的事件处理函数，该事件由轮播控件组件发出。该方法接受一个参数`val`，根据触发了左侧还是右侧轮播控件，它将是`-1`或`1`。

`change`将步进`offset`的值，然后乘以每个列表的宽度（365px）来计算平移。

`resources/assets/components/ListingSummaryGroup.vue`:

```php
...

const rowSize = 3;
const listingSummaryWidth = 365;

export default { props: [ 'country', 'listings' ],
  data() {
    return { offset: 0   
    }
  }, methods: {
    change(val) {
      let newVal = this.offset + parseInt(val);
      if (newVal >= 0 && newVal <= this.listings.length - rowSize) {
        this.offset = newVal;
      }
    }
  }, computed: {
    style() {
      return { transform: `translateX(${this.offset * -listingSummaryWidth}px)` 
      }
    }
  }, components: { ... }
}
```

最后，我们必须在模板中使用`v-on`指令来注册对`CarouselControl`组件的`change-image`事件的监听器。

`resources/assets/components/ListingSummaryGroup.vue`:

```php
<div class="controls">
  <carousel-control dir="left" @change-image="change"></carousel-control>
```

```php
  <carousel-control dir="right" @change-image="change"></carousel-control>
</div>
```

完成后，每个列表组都有一个工作中的图像滑块！

# 最后的修饰

还有两个小功能要添加到这些图像滑块中，以给 Vuebnb 用户最佳体验。首先，让我们添加 CSS 过渡，以在半秒钟的时间内动画平移变化，并产生一个漂亮的*滑动*效果。

`resources/assets/components/ListingSummaryGroup.vue`:

```php
.listing-summaries {
  display: flex;
  flex-direction: row;
  justify-content: space-between;
  transition: transform 0.5s;
}
```

遗憾的是你无法在书中看到这些效果，所以你得自己尝试一下！

最后，与我们的图像轮播不同，这些滑块不是连续的；它们有一个最小值和最大值。如果达到了最小值或最大值，让我们隐藏相应的箭头。例如，当滑块加载时，左箭头应该被隐藏，因为用户不能再减小偏移量到零以下。

为了做到这一点，我们将使用样式绑定动态添加`visibility: hidden`的 CSS 规则。

`resources/assets/components/ListingSummaryGroup.vue`：

```php
<div class="controls">
  <carousel-control dir="left" 
    @change-image="change" 
    :style="leftArrowStyle"
  ></carousel-control>
  <carousel-control dir="right" 
    @change-image="change" 
    :style="rightArrowStyle"
  ></carousel-control>
</div>
```

以及计算属性。

`resources/assets/components/ListingSummaryGroup.vue`：

```php
computed: {
  ...
  leftArrowStyle() {
    return { visibility: (this.offset > 0 ? 'visible' : 'hidden') }
  },
  rightArrowStyle() {
    return { visibility: (
        this.offset < (this.listings.length - rowSize) 
        ? 'visible' : 'hidden'
      ) 
    }
  }
}
```

完成这些后，我们可以看到左箭头在页面加载时隐藏，正如预期的那样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/6797f901-bc01-4b74-bf89-cc6e085eaa9a.png)图 7.24。页面加载时隐藏的左箭头

# 摘要

在本章中，我们学习了路由库的工作原理以及它们为单页应用程序的重要性。然后我们熟悉了 Vue Router 的关键特性，包括路由对象、导航守卫以及`RouterLink`和`RouterView`特殊组件。

将这些知识付诸实践，我们安装了 Vue Router 并配置了它以在我们的应用程序中使用。然后我们为 Vuebnb 建立了一个主页，其中包括一个在图像滑块内组织的列表摘要画廊。

最后，我们实现了一个架构，正确匹配页面与可用的本地数据或通过 AJAX 从 Web 服务检索到的新数据。

现在我们的应用程序中有大量的组件，其中许多组件之间进行数据通信，是时候调查另一个关键的 Vue.js 工具了：Vuex。Vuex 是一个基于 Flux 的库，提供了一种更优越的管理应用程序状态的方式。


# 第八章：使用 Vuex 管理应用程序状态

在上一章中，您学习了如何使用 Vue Router 将虚拟页面添加到 Vue.js 单页面应用程序中。现在，我们将在 Vuebnb 中添加跨页面共享数据的组件，因此不能依赖于瞬态本地状态。为此，我们将利用 Vuex，这是一个受 Flux 启发的 Vue.js 库，提供了一种强大的管理全局应用程序状态的方法。

本章涵盖的主题：

+   Flux 应用程序架构简介以及它在构建用户界面时的用处

+   Vuex 的概述及其关键特性，包括状态和突变

+   如何安装 Vuex 并设置可以被 Vue.js 组件访问的全局存储

+   Vuex 如何通过突变日志和时间旅行调试实现更好的调试

+   为 Vuebnb 列表创建保存功能和保存列表页面

+   将页面状态移入 Vuex 以减少从服务器检索不必要数据

# Flux 应用程序架构

想象一下，您开发了一个多用户聊天应用程序。界面上有用户列表、私人聊天窗口、带有聊天记录的收件箱和通知栏，用于通知用户有未读消息。

数百万用户每天通过您的应用程序进行聊天。但是，有关一个令人讨厌的问题的投诉：应用程序的通知栏偶尔会发出虚假通知；也就是说，用户将收到新的未读消息的通知，但当他们检查时，发现只是他们已经看过的消息。

我描述的是 Facebook 开发人员几年前在他们的聊天系统中遇到的一个真实场景。解决这个问题的过程激发了他们的开发人员创建了一个他们称之为*Flux*的应用程序架构。Flux 是 Vuex、Redux 和其他类似库的基础。

Facebook 的开发人员为这个*僵尸通知*问题苦苦挣扎了一段时间。他们最终意识到，它的持久性不仅仅是一个简单的错误；它指向了应用程序架构中的一个根本缺陷。

这个缺陷在抽象中最容易理解：当应用程序中有多个共享数据的组件时，它们之间的相互连接的复杂性将增加到一个程度，使得数据的状态不再可预测或可理解。当像上面描述的错误不可避免地出现时，应用程序数据的复杂性使得它们几乎不可能解决：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/d3af18a5-6ef2-4e3d-bbc3-421235671ed0.png)图 8.1。组件之间通信的复杂性随着每个额外组件的增加而增加

Flux 不是一个库。你不能去 GitHub 上下载它。Flux 是一组指导原则，描述了一种可扩展的前端架构，足以减轻这个缺陷。它不仅适用于聊天应用程序，还适用于任何具有共享状态的复杂 UI 组件，比如 Vuebnb。

现在让我们探索 Flux 的指导原则。

# 原则＃1-真相的唯一来源

组件可能有它们自己需要知道的*本地数据*。例如，用户列表组件中滚动条的位置可能对其他组件没有兴趣：

```php
Vue.component('user-list', {
  data() { scrollPos: ...
  }
});
```

但是，任何要在组件之间共享的数据，例如*应用程序数据*，都需要保存在一个单独的位置，与使用它的组件分开。这个位置被称为*存储*。组件必须从这个位置读取应用程序数据，而不是保留自己的副本，以防冲突或分歧：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/3929a216-de2f-4ce7-b175-6399ecd98b4d.png)图 8.2。集中式数据简化了应用程序状态

# 原则＃2-数据是只读的

组件可以自由地从存储中读取数据。但是它们不能直接改变存储中的数据，至少不能直接改变。

相反，它们必须通知存储它们改变数据的意图，存储将负责通过一组定义的函数（称为*mutator 方法*）进行这些更改。

为什么要这样做？如果我们集中数据修改逻辑，那么如果状态存在不一致，我们就不必远程查找。我们正在最小化某些随机组件（可能在第三方模块中）以意想不到的方式改变数据的可能性：

图 8.3。状态是只读的。使用改变器方法来写入存储

# 原则＃3 - 变异是同步的

在实现上述两个原则的应用程序中，调试状态不一致要容易得多。您可以记录提交并观察状态如何响应更改（这在 Vue Devtools 中自动发生，我们将看到）。

但是，如果我们的变异被异步应用，这种能力将受到破坏。我们会知道我们提交的顺序，但我们不会知道我们的组件提交它们的顺序和时间。同步变异确保状态不依赖于不可预测事件的顺序和时间。

# Vuex

*Vuex*（通常发音为*veweks*）是 Flux 架构的官方 Vue.js 实现。通过强制执行先前描述的原则，即使在数据被共享到许多组件时，Vuex 也可以保持应用程序数据处于透明和可预测的状态。

Vuex 包括具有状态和变异方法的存储，并且将对从存储中读取数据的任何组件进行反应性更新。它还允许方便的开发功能，如热模块重新加载（更新运行中应用程序中的模块）和时间旅行调试（通过回溯变异来跟踪错误）。

在本章中，我们将为 Vuebnb 列表添加一个*保存*功能，以便用户可以跟踪他们最喜欢的列表。与迄今为止我们应用程序中的其他数据不同，保存的状态必须在页面之间持久存在；例如，当用户从一个页面切换到另一个页面时，应用程序必须记住用户已经保存了哪些项目。我们将使用 Vuex 来实现这一点：

图 8.4。保存状态对所有页面组件可用

# 安装 Vuex

Vuex 是一个可以从命令行安装的 NPM 包：

```php
$ npm i --save-dev vuex
```

我们将把我们的 Vuex 配置放入一个新的模块文件`store.js`：

```php
$ touch resources/assets/js/store.js
```

我们需要在此文件中导入 Vuex，并像 Vue Router 一样使用`Vue.use`进行安装。这使 Vue 具有特殊属性，使其与 Vuex 兼容，例如允许组件通过`this.$store`访问存储。

`resources/assets/js/store.js`：

```php
import Vue from 'vue';
import Vuex from 'vuex'; Vue.use(Vuex);

export default new Vuex.Store();
```

然后我们将在我们的主应用程序文件中导入存储模块，并将其添加到我们的 Vue 实例中。

`resources/assets/js/app.js`：

```php
... import router from './router';
import store from './store';

var app = new Vue({ el: '#app', render: h => h(App), router, store });
```

# 保存功能

如前所述，我们将为 Vuebnb 列表添加一个*保存*功能。该功能的 UI 是一个小的可点击图标，叠加在列表摘要的缩略图像的右上角。它类似于复选框，允许用户切换特定列表的保存状态：

图 8.5。在列表摘要上显示的保存功能

保存功能还将添加为列表页面上的标题图像中的按钮：

图 8.6。在列表页面上显示的保存功能

# ListingSave 组件

让我们开始创建新组件：

```php
$ touch resources/assets/components/ListingSave.vue
```

此组件的模板将包括一个 Font Awesome *heart*图标。它还将包括一个点击处理程序，用于切换保存状态。由于此组件始终是列表或列表摘要的子级，因此它将很快使用列表 ID 作为 prop 来保存状态。不久将使用此 prop。

`resources/assets/components/ListingSave.vue`：

```php
<template>
  <div class="listing-save" @click.stop="toggleSaved()">
    <i class="fa fa-lg fa-heart-o"></i>
  </div>
</template>
<script> export default { props: [ 'id' ], methods: {
      toggleSaved() {
        // Implement this
      }
    }
  } </script>
<style> .listing-save {
    position: absolute;
    top: 20px;
    right: 20px;
    cursor: pointer;
  }

  .listing-save .fa-heart-o {
    color: #ffffff;
  } </style>
```

请注意，点击处理程序具有`stop`修饰符。此修饰符可防止点击事件冒泡到祖先元素，特别是可能触发页面更改的任何锚标签！

现在我们将`ListingSave`添加到`ListingSummary`组件中。记得将列表的 ID 作为 prop 传递。顺便说一句，让我们在`.listing-summary`类规则中添加`position: relative`，这样`ListingSave`可以绝对定位。

`resources/assets/components/ListingSummary.vue`:

```php
<template>
  <div class="listing-summary">
    <router-link :to="{ name: 'listing', params: {listing: listing.id}}"> ... </router-link>
    <listing-save :id="listing.id"></listing-save>
  </div>
</template>
<script> import ListingSave from './ListingSave.vue';

  export default {
    ... components: { ListingSave }
  } </script>
<style> .listing-summary { ... position: relative;
  } ... @media (max-width: 400px) {
    .listing-summary .listing-save {
      left: 15px;
      right: auto;
    }
  } </style>
```

完成后，我们现在将在每个摘要中看到`ListingSave`心形图标的呈现：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/5b38719f-3f5c-4447-bc74-2cfc395ce643.png)图 8.7。`ListingSummary`组件中的`ListingSave`组件

# 已保存状态

`ListingSave`组件没有任何本地数据；相反，我们将保存任何已保存的列表在我们的 Vuex 存储中。为此，我们将在存储中创建一个名为`saved`的数组。每当用户切换列表的保存状态时，其 ID 将被添加或从此数组中移除。

首先，让我们在 Vuex 存储中添加一个`state`属性。这个对象将保存我们想要在应用程序组件中全局可用的任何数据。我们将在这个对象中添加`saved`属性，并将其分配为空数组。

`resources/assets/js/store.js`:

```php
...

export default new Vuex.Store({ state: { saved: []
  }
});
```

# 变更方法

我们在`ListingSave`组件中创建了`toggleSaved`方法的存根。此方法应该在存储中的`saved`状态中添加或删除列表的 ID。组件可以通过`this.$store`访问存储。更具体地说，`saved`数组可以在`this.$store.state.saved`中访问。

`resources/assets/components/ListingSave.vue`:

```php
methods: {
  toggleSaved() { console.log(this.$store.state.saved);
    /* Currently an empty array. []
    */
  }
}
```

请记住，在 Flux 架构中，状态是只读的。这意味着我们不能直接从组件中修改`saved`。相反，我们必须在存储中创建一个变更方法来为我们进行修改。

让我们在存储配置中创建一个`mutations`属性，并添加一个函数属性`toggleSaved`。Vuex 变更方法接收两个参数：存储状态和有效负载。此有效负载可以是您想要从组件传递给变更方法的任何内容。对于当前情况，我们将发送列表 ID。

`toggleSaved`的逻辑是检查列表 ID 是否已经在`saved`数组中，如果是，则将其移除，如果不是，则添加。

`resources/assets/js/store.js`:

```php
export default new Vuex.Store({ state: { saved: []
  }, mutations: {
    toggleSaved(state, id) {
      let index = state.saved.findIndex(saved => saved === id);
      if (index === -1) { state.saved.push(id);
      } else { state.saved.splice(index, 1);
      }
    }
  }
});
```

现在我们需要从`ListingSave`提交这个变更。*提交*是 Flux 术语，与*调用*或*触发*是同义词。提交看起来像一个自定义事件，第一个参数是变更方法的名称，第二个是有效负载。

`resources/assets/components/ListingSave.vue`:

```php
export default { props: [ 'id' ], methods: {
    toggleSaved() {
      this.$store.commit('toggleSaved', this.id);
    }
  }
}
```

在存储架构中使用变更方法的主要目的是保持状态的一致性。但还有一个额外的好处：我们可以轻松地记录这些更改以进行调试。如果您在单击保存按钮后检查 Vue Devtools 中的 Vuex 选项卡，您将看到该变更的条目：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/4f23bdf4-ebe3-4723-8e3f-3a3dfbf6160d.png)图 8.8：变更日志

日志中的每个条目都可以告诉您在提交更改后的状态，以及变化的具体情况。

如果您双击已记录的变更，Vue Devtools 将将应用程序的状态恢复到该更改后的状态。这被称为*时间旅行调试*，对于精细调试非常有用。

# 将图标更改以反映状态

我们的`ListingSave`组件的图标将以不同的方式显示，取决于列表是否已保存；如果列表已保存，它将是不透明的，如果没有保存，则是透明的。由于组件不会在本地存储其状态，因此我们需要从存储中检索状态以实现此功能。

Vuex 存储状态通常应通过计算属性检索。这确保了组件没有自己的副本，这违反了*单一数据源*原则，并且当状态被这个组件或其他组件改变时，组件会重新渲染。响应性也适用于 Vuex 状态！

让我们创建一个计算属性`isListingSaved`，它将返回一个布尔值，反映这个特定列表是否已保存。

`resources/assets/components/ListingSave.vue`:

```php
export default { props: [ 'id' ], methods: {
    toggleSaved() {
      this.$store.commit('toggleSaved', this.id);
    }
  }, computed: {
    isListingSaved() {
      return this.$store.state.saved.find(saved => saved === this.id);
    }
  }
}
```

我们现在可以使用这个计算属性来改变图标。目前我们使用的是 Font Awesome 图标 fa-heart-o。这应该代表“未保存”状态。当列表被保存时，我们应该使用图标 fa-heart。我们可以通过动态类绑定来实现这一点。

`resources/assets/components/ListingSave.vue`:

```php
<template>
  <div class="listing-save" @click.stop="toggleSaved()">
    <i :class="classes"></i>
  </div>
</template>
<script> export default { props: [ 'id' ], methods: { ... }, computed: {
      isListingSaved() { ...},
      classes() {
        let saved = this.isListingSaved;
        return {
          'fa': true,
          'fa-lg': true,
          'fa-heart': saved,
          'fa-heart-o': !saved }
      }
    }
  } </script>
<style> ... .listing-save .fa-heart {
    color: #ff5a5f;
  } </style>
```

现在用户可以直观地识别哪些列表已经被保存，哪些没有。由于响应式的 Vuex 数据，当从应用程序的任何地方对 saved 状态进行更改时，图标将立即更新：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/7d161bd9-3d66-4d56-9fe3-101a47565018.png)图 8.9。ListingSave 图标将根据状态改变

# 添加到 ListingPage

我们还希望保存功能出现在列表页面上。它将放在 HeaderImage 组件中，与查看照片按钮一起，这样，就像列表摘要一样，按钮将覆盖在列表的主图像上。

`resources/assets/components/HeaderImage.vue`:

```php
<template>
  <div class="header">
    <div 
      class="header-img" 
      :style="headerImageStyle" 
      @click="$emit('header-clicked')" >
      <listing-save :id="id"></listing-save>
      <button class="view-photos">View Photos</button>
    </div>
  </div>
</template>
<script> import ListingSave from './ListingSave.vue';

  export default {
    computed: { ... }, props: ['image-url', 'id'], components: { ListingSave }
  } </script>
<style>...</style>
```

请注意，HeaderImage 的范围中没有列表 ID，因此我们将不得不从 ListingPage 将其作为属性传递下来。id 当前也不是 ListingPage 的数据属性，但是，如果我们声明它，它将简单地工作。

这是因为 ID 已经是组件接收到的初始状态/AJAX 数据的属性，因此当组件被路由加载时，id 将自动由 Object.assign 填充。

`resources/assets/components/ListingPage.vue`:

```php
<template>
  <div>
    <header-image v-if="images[0]"
      :image-url="images[0]"
      @header-clicked="openModal"
      :id="id"
    ></header-image> ... </div>
</template>
<script> ...
   export default {
    data() {
      ... id: null
    }, methods: {
      assignData({ listing }) { Object.assign(this.$data, populateAmenitiesAndPrices(listing));
      },
      ...
    },
    ...
   } </script>
<style>...</style>
```

完成后，保存功能现在将出现在列表页面上：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/26551ab4-8d6c-4bc1-97a5-c618aa9afd2f.png)图 8.10。列表页面上的列表保存功能如果您通过列表页面保存一个列表，然后返回主页，相应的列表摘要将被保存。这是因为我们的 Vuex 状态是全局的，并且将在页面更改时持续存在（尽管不是页面刷新...但）。

# 将 ListingSave 设置为按钮

目前，ListingSave 功能在列表页面标题中显得太小，用户很容易忽略它。让我们把它做成一个合适的按钮，类似于标题左下角的查看照片按钮。

为此，我们将修改 ListingSave 以允许父组件发送一个名为 button 的 prop。这个布尔 prop 将指示组件是否应该包含一个包裹在图标周围的按钮元素。

这个按钮的文本将是一个计算属性 message，它将根据 isListingSaved 的值从 Save 变为 Saved。

`resources/assets/components/ListingSave.vue`:

```php
<template>
  <div class="listing-save" @click.stop="toggleSaved()">
    <button v-if="button">
      <i :class="classes"></i> {{ message }} </button>
    <i v-else :class="classes"></i>
  </div>
</template>
<script> export default { props: [ 'id', 'button' ], methods: { ... }, computed: {
      isListingSaved() { ... },
      classes() { ... },
      message() {
        return this.isListingSaved ? 'Saved' : 'Save';
      }
    }
  } </script>
<style> ... .listing-save i {
    padding-right: 4px;
  }

  .listing-save button .fa-heart-o {
    color: #808080;
  } </style>
```

现在我们将在 HeaderImage 中将 button prop 设置为 true。即使值不是动态的，我们也使用 v-bind 来确保该值被解释为 JavaScript 值，而不是字符串。

`resources/assets/components/HeaderImage.vue`:

```php
<listing-save :id="id" :button="true"></listing-save>
```

有了这个，ListingSave 将出现在我们的列表页面上：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/2f04270b-3b6f-4b66-988d-c523580b11d1.png)图 8.11。列表保存功能显示为列表页面上的按钮

# 将页面状态移入存储

现在用户可以保存他们喜欢的任何列表，我们将需要一个“保存”页面，他们可以在那里查看这些保存的列表。我们将很快构建这个新页面，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/6e48bd76-0d44-4746-8cb8-26041676e739.png)图 8.12：已保存页面

实现保存页面将需要对我们的应用架构进行增强。让我们快速回顾一下从服务器检索数据的方式，以了解为什么。

我们应用中的所有页面都需要服务器上的路由返回一个视图。这个视图包括相关页面组件的数据内联在文档头部。或者，如果我们通过应用内链接导航到该页面，一个 API 端点将提供相同的数据。我们在第七章中设置了这个机制，*使用 Vue Router 构建多页面应用*。

保存的页面将需要与主页相同的数据（列表摘要数据），因为保存的页面实际上只是主页的轻微变体。因此，在主页和保存的页面之间共享数据是有意义的。换句话说，如果用户从主页加载 Vuebnb，然后导航到保存的页面，或者反之亦然，多次加载列表摘要数据将是一种浪费。

让我们将页面状态与页面组件解耦，并将其移入 Vuex。这样，它可以被任何需要它的页面使用，并避免不必要的重新加载：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/cac3b0f4-d27d-47d1-aedc-bba44181e368.png)图 8.13。存储中的页面状态

# 状态和变更方法

让我们向 Vuex 存储添加两个新的状态属性：`listings`和`listing_summaries`。这些将是分别存储我们的列表和列表摘要的数组。当页面首次加载时，或者当路由更改并调用 API 时，加载的数据将被放入这些数组中，而不是直接分配给页面组件。页面组件将从存储中检索这些数据。

我们还将添加一个变更方法`addData`，用于填充这些数组。它将接受一个带有两个属性`route`和`data`的有效负载对象。`route`是路由的名称，例如*listing*，*home*等。`data`是从文档头或 API 检索到的列表或列表摘要数据。

`resources/assets/js/store.js`：

```php
import Vue from 'vue';
import Vuex from 'vuex'; Vue.use(Vuex);

export default new Vuex.Store({ state: { saved: [], listing_summaries: [], listings: []
  }, mutations: {
    toggleSaved(state, id) { ... },
    addData(state, { route, data }) {
      if (route === 'listing') { state.listings.push(data.listing);
      } else { state.listing_summaries = data.listings;
      }
    }
  }
});
```

# 路由器

检索页面状态的逻辑在 mixin 文件`route-mixin.js`中。这个 mixin 为页面组件添加了一个`beforeRouteEnter`钩子，当组件实例可用时，将页面状态应用于组件实例。

现在我们将页面状态存储在 Vuex 中，我们将利用不同的方法。首先，我们不再需要 mixin；我们现在将这个逻辑放入`router.js`中。其次，我们将使用不同的导航守卫`beforeEach`。这不是一个组件钩子，而是一个可以应用于路由器本身的钩子，并且在每次导航之前触发。

您可以在以下代码块中看到我如何在`router.js`中实现这一点。请注意，在调用`next()`之前，我们将页面状态提交到存储中。

`resources/assets/js/router.js`：

```php
... 
import axios from 'axios';
import store from './store';

let router = new VueRouter({
  ...
}); router.beforeEach((to, from, next) => {
  let serverData = JSON.parse(window.vuebnb_server_data);
  if (!serverData.path || to.path !== serverData.path) { axios.get(`/api${to.path}`).then(({data}) => { store.commit('addData', {route: to.name, data});
      next();
    });
  }
  else { store.commit('addData', {route: to.name, data: serverData});
    next();
  }
});

export default router;
```

完成后，我们现在可以删除路由 mixin：

```php
$ rm resources/assets/js/route-mixin.js
```

# 从 Vuex 中检索页面状态

现在我们已经将页面状态移入 Vuex，我们需要修改我们的页面组件来检索它。从`ListingPage`开始，我们必须进行的更改是：

+   删除本地数据属性。

+   添加一个计算属性`listing`。这将根据路由从存储中找到正确的列表数据。

+   删除 mixin。

+   更改模板变量，使它们成为`listing`的属性：例如`{{ title }}`，将变成`{{ listing.title }}`。不幸的是，现在所有变量都是`listing`的属性，这使得我们的模板稍微冗长。

`resources/assets/components/ListingPage.vue`：

```php
<template>
  <div>
    <header-image v-if="listing.images[0]" 
      :image-url="listing.images[0]" 
      @header-clicked="openModal" 
      :id="listing.id"
    ></header-image>
    <div class="listing-container">
      <div class="heading">
        <h1>{{ listing.title }}</h1>
        <p>{{ listing.address }}</p>
      </div>
      <hr>
      <div class="about">
        <h3>About this listing</h3>
        <expandable-text>{{ listing.about }}</expandable-text>
      </div>
      <div class="lists">
        <feature-list title="Amenities" :items="listing.amenities"> ... </feature-list>
        <feature-list title="Prices" :items="listing.prices"> ... </feature-list>
      </div>
    </div>
    <modal-window ref="imagemodal">
      <image-carousel :images="listing.images"></image-carousel>
    </modal-window>
  </div>
</template>
<script> ...

  export default { components: { ... }, computed: {
      listing() {
        let listing = this.$store.state.listings.find( listing => listing.id == this.$route.params.listing );
        return populateAmenitiesAndPrices(listing);
      }
    }, methods: { ... }
  } </script>
```

对`HomePage`的更改要简单得多；只需删除 mixin 和本地状态，并用计算属性`listing_groups`替换它，该属性将从存储中检索所有列表摘要。

`resources/assets/components/HomePage.vue`：

```php
export default { computed: {
    listing_groups() {
      return groupByCountry(this.$store.state.listing_summaries);
    }
  }, components: { ... }
}
```

进行这些更改后，重新加载应用程序，您应该看不到行为上的明显变化。但是，检查 Vue Devtools 的 Vuex 选项卡，您将看到页面数据现在在存储中：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/dc5a618d-c18a-4ec3-8b43-229e5021393f.png)图 8.14。页面状态现在在 Vuex 存储中

# Getters

有时我们想要从商店得到的不是直接的价值，而是一个派生的价值。例如，假设我们只想获取用户保存的那些列表摘要。为此，我们可以定义一个*getter*，它类似于存储的计算属性：

```php
state: { saved: [5, 10], listing_summaries: [ ... ]  
}, getters: {
  savedSummaries(state) {
    return state.listing_summaries.filter( item => state.saved.indexOf(item.id) > -1
    );
  }
}
```

现在，任何需要 getter 数据的组件都可以从存储中检索它：

```php
console.log(this.$store.state.getters.savedSummaries);

/*
[
  5 => [ ... ],
  10 => [ ... ]
]
*/
```

通常，当几个组件需要相同的派生值时，您会定义一个 getter 来避免重复编写代码。让我们创建一个 getter 来检索特定的列表。我们已经在`ListingPage`中创建了这个功能，但由于我们在路由器中也需要它，我们将将其重构为 getter。

关于 getter 的一件事是，它们不像 mutations 那样接受有效负载参数。如果要将值传递给 getter，您需要返回一个函数，其中有效负载是该函数的参数。

`resources/assets/js/router.js`:

```php
getters: {
  getListing(state) {
    return id => state.listings.find(listing => id == listing.id);
  }
}
```

现在让我们在`ListingPage`中使用这个 getter 来替换以前的逻辑。

`resources/assets/components/ListingPage.vue`:

```php
computed: {
 listing() {
    return populateAmenitiesAndPrices(
      this.$store.getters.getListing(this.$route.params.listing)
    );
  }
} 
```

# 检查页面状态是否在存储中

我们已成功将页面状态移入存储。现在在导航守卫中，我们将检查页面需要的数据是否已经存储，以避免两次检索相同的数据：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/f45f9b1b-793f-4022-8f0f-25675a8d8b5c.png)图 8.15。获取页面数据的决策逻辑

让我们在`router.js`的`beforeEach`钩子中实现这个逻辑。我们将在开头添加一个`if`块，如果数据已经存在，它将立即解析钩子。`if`使用一个带有以下逻辑的三元函数：

+   如果路由名称是*listing*，则使用`getListing` getter 来查看特定列表是否可用（如果不可用，则此 getter 返回`undefined`）

+   如果路由名称*不是* *listing*，请检查存储是否有列表摘要可用。列表摘要总是一次性检索的，因此如果至少有一个，您可以假定它们都在那里。

`resources/assets/js/router.js`:

```php
router.beforeEach((to, from, next) => {
  let serverData = JSON.parse(window.vuebnb_server_data);
  if ( to.name === 'listing'
      ? store.getters.getListing(to.params.listing)
      : store.state.listing_summaries.length > 0
  ) {
    next();
  }
  else if (!serverData.path || to.path !== serverData.path) { axios.get(`/api${to.path}`).then(({data}) => { store.commit('addData', {route: to.name, data});
      next();
    });

  }
  else { store.commit('addData', {route: to.name, data: serverData});
    next();
  }
});
```

完成后，如果在应用内导航中从主页导航到列表 1，然后返回主页，然后返回列表 1，应用程序将只从 API 中检索列表 1 一次。在以前的架构下，它会做两次！

# 保存的页面

现在我们将保存的页面添加到 Vuebnb。让我们首先创建组件文件：

```php
$ touch resources/assets/components/SavedPage.vue
```

接下来，我们将在路径`/saved`上创建一个新的路由，并使用这个组件。

`resources/assets/js/router.js`:

```php
...

import SavedPage from '../components/SavedPage.vue';

let router = new VueRouter({
  ... routes: [
    ...
    { path: '/saved', component: SavedPage, name: 'saved' }
  ]
});
```

让我们还在 Laravel 项目中添加一些服务器端路由。如上所述，保存的页面使用与主页完全相同的数据。这意味着我们可以调用用于主页的相同控制器方法。

`routes/web.php`:

```php
Route::get('/saved', 'ListingController@get_home_web');
```

`routes/api.php`:

```php
Route::get('/saved', 'ListingController@get_home_api');
```

现在我们将定义`SavedPage`组件。从`script`标签开始，我们将导入我们在第六章中创建的`ListingSummary`组件，*使用 Vue.js 组件组合小部件*。我们还将创建一个计算属性`listings`，它将从存储中返回列表摘要，并根据是否保存进行过滤。

`resources/assets/components/SavedPage.vue`:

```php
<template></template>
<script> import ListingSummary from './ListingSummary.vue';

  export default { computed: {
      listings() {
        return this.$store.state.listing_summaries.filter( item => this.$store.state.saved.indexOf(item.id) > -1
        );
      }
    }, components: { ListingSummary }
  } </script>
<style></style>
```

接下来，我们将添加到`SavedPage`的`template`标签。主要内容包括检查`listings`计算属性返回的数组长度。如果为 0，则尚未保存任何项目。在这种情况下，我们会显示一条消息通知用户。然而，如果有保存的列表，我们将遍历它们并使用`ListingSummary`组件显示它们。

`resources/assets/components/SavedPage.vue`:

```php
<template>
  <div id="saved" class="home-container">
    <h2>Saved listings</h2>
    <div v-if="listings.length" class="listing-summaries">
      <listing-summary v-for="listing in listings"
        :listing="listing"
        :key="listing.id"
      ></listing-summary>
    </div>
    <div v-else>No saved listings.</div>
  </div>
</template>
<script>...</script>
<style>...</style>
```

最后，我们将添加到`style`标签。这里需要注意的主要是我们正在利用`flex-wrap: wrap`规则并向左对齐。这确保我们的列表摘要将自行组织成没有间隙的行。

`resources/assets/components/SavedPage.vue`:

```php
<template>...</template>
<script>...</script>
<style> #saved .listing-summaries {
    display: flex;
    flex-wrap: wrap;
    justify-content: left;
    overflow: hidden;
  }

  #saved .listing-summaries .listing-summary {
    padding-bottom: 30px;
  }

  .listing-summaries > .listing-summary {
    margin-right: 15px;
  } </style>
```

让我们还在全局 CSS 文件中添加`.saved-container` CSS 规则。这确保我们的自定义页脚也可以访问这些规则。

`resources/assets/css/style.css`:

```php
.saved-container {
  margin: 0 auto;
  padding: 0 25px;
}

@media (min-width: 1131px) {
  .saved-container {
    width: 1095px;
    padding-left: 40px;
    margin-bottom: -10px;
  }
}
```

最后的任务是向存储中添加一些默认的保存列表。我随机选择了 1 和 15，但您可以添加任何您想要的。在下一章中，当我们使用 Laravel 将保存的列表持久化到数据库时，我们将再次删除这些。

`resources/assets/js/store.js`:

```php
state: { saved: [1, 15],
  ...
},
```

完成后，我们的保存页面如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/dd5572ee-80c1-420e-b176-df3860c92fe3.png)图 8.16。保存页面

如果我们删除所有保存的列表，我们会看到：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/023a07de-c00d-4eb1-8f8c-26588e1c171e.png)图 8.17。没有列表的保存页面

# 工具栏链接

本章的最后一件事是在工具栏中添加一个链接到保存页面，以便从任何其他页面访问保存页面。为此，我们将添加一个内联`ul`，其中链接被包含在一个子`li`中（我们将在第九章中在工具栏中添加更多链接，*添加用户登录和使用 Passport 进行 API 身份验证*）。

`resources/assets/components/App.vue`:

```php
<div id="toolbar">
  <router-link :to="{ name: 'home' }">
    <img class="icon" src="/images/logo.png">
    <h1>vuebnb</h1>
  </router-link>
  <ul class="links">
    <li>
      <router-link :to="{ name: 'saved' }">Saved</router-link>
    </li>
  </ul>
</div>
```

为了正确显示这一点，我们需要添加一些额外的 CSS。首先，我们将修改`#toolbar`声明，使工具栏使用 flex 进行显示。我们还将在下面添加一些新规则来显示链接。

`resources/assets/components/App.vue`:

```php
<style> #toolbar {
    display: flex;
    justify-content: space-between;
    border-bottom: 1px solid #e4e4e4;
    box-shadow: 0 1px 5px rgba(0, 0, 0, 0.1);
  }

  ... #toolbar ul {
    display: flex;
    align-items: center;
    list-style: none;
    padding: 0 24px 0 0;
    margin: 0;
  }

  @media (max-width: 373px) {
    #toolbar ul  {
      padding-right: 12px;
    }
  }

  #toolbar ul li {
    padding: 10px 10px 0 10px;
  }

  #toolbar ul li a {
    text-decoration: none;
    line-height: 1;
    color: inherit;
    font-size: 13px;
    padding-bottom: 8px;
    letter-spacing: 0.5px;
 cursor: pointer; }

  #toolbar ul li a:hover {
    border-bottom: 2px solid #484848;
    padding-bottom: 6px;
  } </style>
```

现在我们在工具栏中有一个指向保存页面的链接：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/flstk-vue2-lrv5/img/861e4bd0-2979-4ae1-8831-7b51702ed106.png)图 8.18：工具栏中的保存链接

# 摘要

在本章中，我们学习了 Vuex，Vue 的官方状态管理库，它基于 Flux 架构。我们在 Vuebnb 中安装了 Vuex，并设置了一个存储库，可以在其中编写和检索全局状态。

然后，我们学习了 Vuex 的主要特性，包括状态、变化方法和获取器，以及我们如何使用 Vue Devtools 调试 Vuex。我们利用这些知识实现了一个列表保存组件，然后将其添加到我们的主页面。

最后，我们将 Vuex 和 Vue Router 结合起来，以便在路由更改时更有效地存储和检索页面状态。

在下一章中，我们将涵盖全栈应用程序中最棘手的主题之一 - 认证。我们将在 Vuebnb 中添加用户配置文件，以便用户可以将其保存的项目持久保存到数据库中。我们还将继续增加对 Vuex 的了解，利用一些更高级的功能。
