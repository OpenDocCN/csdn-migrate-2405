# jQuery2 开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/44BEA83CD04274AA076F60D831F59B04`](https://zh.annas-archive.org/md5/44BEA83CD04274AA076F60D831F59B04)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：用户界面动画

在本章中，我们将介绍以下主题：

+   创建一个动态登录表单

+   添加照片放大功能

+   创建一个动态内容滑块

+   背景图像动画

+   创建一个动态导航菜单

# 介绍

使用 jQuery，可以通过引人注目的动画增强常见的用户界面元素。这些动画可以为任何网站或 Web 应用程序提供交互式操作，从而提升用户体验。本章将向您展示如何使用现代动画创建一些流行的用户界面，您可以在新项目或当前网站中使用这些动画。

# 创建一个动画登录表单

登录表单是许多网站和 Web 应用程序的主要入口点——第一印象至关重要。使用 jQuery 动画，我们可以创建一个在打开、关闭和出现错误时都会进行动画处理的登录表单，从而创造出通过动画加强的高品质用户体验。

此示例需要支持 PHP 的 Web 服务器。这个服务器可以托管在云中或一个简单的本地开发服务器上。在开始本示例之前，请确保您已经完成了这个设置。

## 准备工作

在与最新版本的 jQuery 库相同的目录中创建 `recipe-1.html`、`recipe-1.js` 和 `recipe.css`。因为我们正在创建一个登录表单，所以我们还需要一个 PHP 脚本来发布我们的登录数据。在 Web 服务器的 Web 根目录内创建一个名为 `index.php` 的 PHP 文件，并添加以下代码：

```js
$response = new stdClass;
$response->success = false;
$response->error = "Username and password must be provided";
if (isset($_POST['username']) && isset($_POST['password'])) {
   $username = $_POST['username'];
   $password = $_POST['password'];
   if ($username == "MyUsername" && $password == "MyPassword") {
      $response->success = true;
   } else {
      $response->error = "Incorrect login credentials";
   }
}
header("Content-type: application/json; charset=UTF-8");
echo json_encode($response);
```

在实际实现中，PHP 脚本将对用户的凭据进行验证，并与数据库记录进行比对。为了保持这个示例简单，并专注于 jQuery 代码，我们的 PHP 代码仅对用户提交的用户名和密码进行字符串比较，分别为 `MyUsername` 和 `MyPassword`。

## 操作步骤…

要创建使用上述 PHP 脚本的动画登录表单，请按照以下逐步说明操作：

1.  将以下 HTML 代码添加到 `recipe-1.html` 中，创建登录表单和打开它的按钮：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
       <title>Chapter 7 :: Recipe 1</title>
       <link href="recipe-1.css" rel="stylesheet" type="text/css" />
       <script src="img/jquery.min.js"></script>
       <script src="img/recipe-1.js"></script>
    </head>
    <body>
       <button class="open-login">Open Login Box</button>
       <div class="login-frame">
          <div class="login-box">
             <div class="login-msg">Please login below</div>
             <div class="form-group">
                <label class="form-label">Username:</label>
                <input type="text" class="form-control" id="username" />
             </div>
             <div class="form-group">
                <label class="form-label">Password:</label>
                <input type="text" class="form-control" id="password" />
             </div>
             <div class="login-actions">
                <button class="btn login-btn">Login</button>
                <button class="btn close-login">Cancel</button>
             </div>
          </div>
       </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到 `recipe-1.css` 中，为网页添加基本样式：

    ```js
    .login-frame {
       position: absolute;
       top: 0;
       bottom: 0;
       left: 0;
       right: 0;
       display: none;
    }
    .login-box {
       width: 400px;
       height: 165px;
       padding: 20px;
       margin: auto;
       top: -165px;
       box-shadow: 0 0 10px #CCC;
       border-radius: 5px;
       position: relative;
    }
    .form-group {
       margin-bottom: 10px;
    }
    .form-group .form-control {
       margin-left: 55px;
       width: 275px;
       height: 30px;
       padding: 0 5px 0 5px;
       font-size: 16px;
       border-radius: 5px;
       border: solid 1px #CCCCCC;
       color: #999;
    }
    .form-group .form-label {
       width: 50px;
       font-size: 18px;
       display: block;
       float: left;
       line-height: 30px;
       padding-left: 5px;
       color: #333;
    }
    .login-msg {
       border: solid 1px #bce8f1;
       text-align: center;
       line-height: 30px;
       margin-bottom: 10px;
       border-radius: 5px;
       color: rgba(58, 135, 173, 0.90);
       background-color: rgba(217, 237, 247, 0.99);
    }
    .login-msg.success {
       color: rgba(70, 136, 71, 0.96);
       background-color: rgba(223, 240, 216, 0.97);
       border-color: rgba(214, 233, 198, 0.98);
    }
    .login-msg.error {
       color: rgba(185, 74, 72, 0.98);
       background-color: rgba(242, 222, 222, 0.98);
       border-color: rgba(238, 211, 215, 0.98);
    }
    .login-actions {
       text-align: right;
    }
    .btn {
       height: 40px;
       width: 100px;
       display: inline-block;
       padding: 6px 12px;
       margin-bottom: 0;
       font-size: 14px;
       text-align: center;
       white-space: nowrap;
       vertical-align: middle;
       cursor: pointer;
       border: 1px solid transparent;
       border-radius: 4px;
    }

    .login-btn {
       color: #ffffff;
       background-color: #5cb85c;
       border-color: #4cae4c;
    }
    .login-btn:hover {
       background-color: #458a45;
    }
    .close-login {
       color: #ffffff;
       background-color: #d2322d;
       border-color: #ac2925;
    }
    .close-login:hover {
       background-color: #ac2c2c;
    }
    ```

1.  将以下 jQuery 代码添加到 `recipe-1.js` 中，以允许用户打开和使用登录表单：

    ```js
    $(function(){
       $(document).on('click', '.open-login', function(){
          $('.login-frame').fadeIn(500);
          $('.login-box').animate({'top' : '50px'}, 500);
       });
       $(document).on('click', '.close-login', function(){
          $('.login-box').animate({'top' : '-165px'}, 500);
          $('.login-frame').fadeOut(500);
       });
       $(document).on('click', '.login-btn', function(){
          var username = $('#username').val();
          var password = $('#password').val();
          $.ajax({
             url: '/index.php',
             type: 'POST',
             data: {
                'username': username,
                'password': password
             },
             success: function(response) {
                var _loginMsg = $('.login-msg');
                if (response.success) {
                   _loginMsg.addClass("success").removeClass("error");
                   _loginMsg.html("Login was successful!");
                } else {
                   _loginMsg.addClass("error").removeClass("success");
                   _loginMsg.html(response.error);
                   $('.login-box')
                   .animate({ left: -25 }, 20)
                   .animate({ left: 0 }, 60)
                   .animate({ left: 25 }, 20)
                   .animate({ left: 0 }, 60);
                }
             }
          });
       });
    });
    ```

1.  在 Web 浏览器中打开 `recipe-1.html`，单击 **打开登录框** 按钮，您将看到以下截图中显示的界面：![操作步骤](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_07_01.jpg)

## 工作原理…

允许用户拥有帐户并登录到这些帐户的网站通常会在主导航的某个地方提供一个登录按钮。本教程中的 HTML 代码创建了一个非常基本的网页，只有一个按钮来表示用户可以访问登录表单的位置。HTML 代码还提供了基本的登录表单，默认情况下使用 CSS 隐藏。CSS 代码提供了登录表单的定位以及登录错误和表单按钮的样式。除了最初隐藏登录表单的 CSS 之外，它还将登录表单的顶部位置的值设置为负数，将登录表单强制移出页面。这样我们就可以创建滑入动画，将登录框带入用户的视野。

jQuery 代码的第一部分创建了一个点击事件处理程序，用于监听登录按钮的点击，如下所示：

```js
$(document).on('click', '.open-login', function(){
   $('.login-frame').fadeIn(500);
   $('.login-box').animate({'top' : '50px'}, 500);
});
```

当用户点击具有`open-login`类的按钮时，使用 jQuery 的`fadeIn()`函数来淡入隐藏的登录表单，使用`animate()`函数将登录表单移动到屏幕上，创建滑入效果。

创建了一个点击事件处理程序，用于监听点击`close-login`按钮的事件，然后触发反向动画，淡出登录框并将其移出屏幕，如下所示：

```js
$(document).on('click', '.close-login', function(){
   $('.login-box').animate({'top' : '-165px'}, 500);
   $('.login-frame').fadeOut(500);
});
```

### 注意

两个动画函数的持续时间都设置为 500 毫秒，允许淡入和位置动画同时开始和结束。

本教程的主要功能放在登录按钮的点击事件处理程序的回调函数中；如下所示：

```js
$(document).on('click', '.login-btn', function(){
   // -- HIDDEN CODE --
});
```

这个点击事件处理程序监听登录按钮的点击，获取输入数据并将其提交给我们在本教程开始时创建的 PHP 脚本。首先，从表单中收集用户名和密码，并存储在`username`和`password`变量中，如下所示：

```js
var username = $('#username').val();
var password = $('#password').val();
```

这些数据然后通过 jQuery 的内置 AJAX 功能发送到 PHP 脚本：

```js
$.ajax({
   url: 'http://localhost:8003/index.php',
   type: 'POST',
   data: {
      'username': username,
      'password': password
   },
   success: function(response) {
   // --- HIDDEN CODE
   }
});
```

上面的代码通过指定 PHP 文件的 URL 并将`type`参数设置为`POST`来创建一个 AJAX `POST`请求。还提供了一个数据对象，其中包含来自表单的信息。

为`success`参数指定了一个回调函数；这个函数在 PHP 脚本成功响应时被调用，如下所示：

```js
success: function(response) {
   var _loginMsg = $('.login-msg');
   if (response.success) {
      // -- HIDDEN CODE
   } else {                         
      // -- HIDDEN CODE
   }
```

通过创建我们的 PHP 代码，我们知道响应将包含一个成功值，要么是`true`要么是`false`。如果成功值是`false`，则会有一个错误消息与之相配。还有一种 AJAX 请求可能会失败；这是由服务器错误引起的，例如`500 文件未找到`。为了处理这些错误，应该使用 jQuery AJAX `.fail()`函数。更多信息请参阅[`api.jquery.com/jquery.ajax/`](http://api.jquery.com/jquery.ajax/)。

在成功的回调函数中，我们选择`login-msg`元素，该元素将用于在屏幕上打印任何消息。评估由 PHP 脚本提供的成功值以确定登录是否成功。

如果登录成功，`login-msg`元素将被更新，其中包含通知用户登录成功的消息，并添加`success`类以使消息元素呈绿色，如下所示：

```js
_loginMsg.addClass("success").removeClass("error");
_loginMsg.html("Login was successful!");
```

`removeClass()`函数用于确保`error`类不作为任何先前登录尝试的遗留物存在。在实际情况下，您可能希望将用户重定向到网站的会员区域。这段代码可以被替换为执行此操作；请参阅本配方的*还有更多...*部分。

如果登录尝试失败，则向`login-msg`元素添加了`error`类，并附有 PHP 脚本的消息。我们使用`response.error`来检索此数据。还使用一系列动画函数将登录框从左到右移动，以创建摇晃效果，强调错误给用户的重要性；如下所示：

```js
_loginMsg.addClass("error").removeClass("success");
_loginMsg.html(response.error);
$('.login-box')
   .animate({ left: -25 }, 20)
   .animate({ left: 0 }, 60)
   .animate({ left: 25 }, 20)
   .animate({ left: 0 }, 60);
}
```

## 还有更多...

如果需要，jQuery 回调的成功登录部分可以轻松替换为重定向用户的操作。可以使用以下代码的原生 JavaScript 代码将用户发送到所需页面，将`/memebers.php`替换为适当的 URL，如下所示：

```js
window.location.href = "/members.php";
```

## 请参阅

+   第五章，*表单处理*

# 添加照片缩放

照片缩放是一个很棒的效果，可以在许多界面中使用，以增加对照片库或产品页面的额外用户交互，使用户可以清晰地看到较小的图像。这个配方将向您展示如何将照片缩放效果添加到列表中的四张图片中。

## 准备工作

在这个配方中，你需要四张图片。确保它们的宽度不超过`800 px`，高度不超过`600 px`。一旦收集到将在这个配方中使用的四张图片，请在与这些图片和 jQuery 库相同的目录中创建`recipe-2.html`、`recipe-2.css`和`recipe-2.js`。

## 如何做...

执行以下说明以将缩放效果添加到您选择的图像中：

1.  将以下 HTML 代码添加到`recipe-2.html`中；确保更新与您选择的图像对应的图像引用：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
       <title>Chapter 7 :: Recipe 2</title>
       <link href="recipe-2.css" rel="stylesheet" type="text/css" />
       <script src="img/jquery.min.js"></script>
       <script src="img/recipe-2.js"></script>
    </head>
    <body>
       <div class="container">
          <ul class="photos">
             <li><img src="img/recipe-2-1.jpg" alt="Countryside 1" /></li>
             <li><img src="img/recipe-2-2.jpg" alt="Countryside 2" /></li>
             <li><img src="img/recipe-2-3.jpg" alt="Countryside 3" /></li>
             <li><img src="img/recipe-2-4.jpg" alt="Countryside 4" /></li>
          </ul>
       </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到`recipe-2.css`中以样式化和定位图像：

    ```js
    body {
       background-color: #333;
    }
    .container {
       width: 600px;
       height: 600px;
       margin: 50px auto auto auto;
    }
    .photos {
       list-style: none;
       margin: 0;
       padding: 0;
    }
    .photos li {
       display: inline-block;
       width: 290px;
       height: 250px;
       background-color: #E1E1E1;
       margin: 0 5px 5px 0;
       overflow: hidden;
       position: relative;
          cursor: pointer;
    }
    .photos li img {
       top: -50%;
       left: -50%;
       position: absolute;
       opacity: 0.5;
    }
    ```

1.  将以下 jQuery 代码添加到`recipe-2.js`中，以在用户将鼠标悬停在图像上时为图像添加照片缩放动画：

    ```js
    var images = [];
    $(function(){
       $(document).on("mouseover", ".photos li", function(){
          var _image = $(this).find('img');
          _image.finish();
          images[$(this).index()] = {
             width: _image.width(),
             height: _image.height()
          };
          _image.animate({
             width: '290px',
             height: '250px',
             top: 0,
             left: 0,
             opacity: 1.0
          });
       }).on("mouseout", ".photos li", function(){
          var _image = $(this).find('img');
          _image.finish();
          _image.animate({
             width: images[$(this).index()].width + "px",
             height: images[$(this).index()].height + "px",
             top: '-50%',
             left: '-50%',
             opacity: 0.5
          });
       });
    });
    ```

1.  在网页浏览器中打开`recipe-2.html`，将鼠标悬停在四张图像之一上，即可看到缩放动画，如下所示：![执行方法...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_07_02.jpg)

## 它是如何工作的...

本配方中的 HTML 代码非常基本，只是创建一个带有类名`container`的 division 元素，该元素在页面上使用 CSS 居中。在 frame division 内部，有一个无序列表元素，它有四个子元素，每个子元素都包含一个图像。

CSS 代码从无序列表中删除任何边距和填充，将其子项设置为内联显示，并将每个子元素的溢出属性设置为`hidden`。这样做是为了让我们最初加载比列表元素大的图像而不显示任何溢出，以提供放大的效果。

CSS 代码还将图像的顶部和左侧位置设置为`-50%`，以使它们居中在列表元素内。图像的不透明度也设置为`0.5`，以防止图像最初显眼。

在 jQuery 代码的开头，声明了一个`images`变量，用于存储稍后可以在代码中重复使用的图像数据。在 jQuery 的加载块内，将两个事件处理程序附加到文档上，以监听照片列表元素上的`mouseover`和`mouseout`事件，如下所示：

```js
$(document).on("mouseover", ".photos li", function(){
   // --  HIDDEN CODE
}).on("mouseout", ".photos li", function(){
   // -- HIDDEN CODE
});
```

在`mouseover`事件处理程序内，使用`$(this).find('img')`来查找鼠标悬停的列表元素内的图像。选定了此图像后，使用`$(this).index()`将其大小存储在`images`变量中，如下所示：

```js
images[$(this).index()] = {
   width: _image.width(),
   height: _image.height()
};
```

然后，使用 jQuery 的`animate()`函数，将图像的宽度和高度设置为与列表元素的大小相匹配，以创建缩小效果。其顶部和左侧位置也设置为`0`，覆盖了 CSS 中设置的`-50%`位置，以确保图像填满列表元素的 100%。图像的不透明度设置为`1`（即 100%），以便悬停和放大的图像在其他图像中突出显示。此代码如下所示：

```js
_image.animate({
   width: '290px',
   height: '250px',
   top: 0,
   left: 0,
   opacity: 1.0
});
```

在`mouseout`事件处理程序内，先前讨论的动画使用存储的图像信息有效地被反转，并将图像重置回鼠标悬停前的位置，执行如下：

```js
var _image = $(this).find('img');
_image.finish();
_image.animate({
   width: images[$(this).index()].width + "px",
   height: images[$(this).index()].height + "px",
   top: '-50%',
   left: '-50%',
   opacity: 0.5
});
```

在上述代码中，可以看到使用`$(this).index()`引用了`images`数组，以获取图像的原始高度和宽度。再次将其顶部和左侧位置设置为`-50%`，使其在列表元素内居中。

### 注意

在事件处理程序回调中都使用`_image.finish();`来完成任何当前动画。这可以防止用户快速切换图像时出现奇怪的结果。

## 另请参阅

+   *创建一个动画导航菜单*

# 创建一个动画内容滑块

您可能已经意识到，在线有一整片 jQuery 内容滑块插件、教程和可下载脚本的森林，其中大部分内容都可以免费使用。内容滑块非常受欢迎，因为它们是向用户展示重要内容（如图像、新闻和促销活动）的一种非常吸引人和引人注目的方式。本篇文章将向您展示如何使用 jQuery 轻松创建内容滑块。本篇食谱中使用的滑块将允许您使用 CSS 轻松自定义其外观和感觉，以使其符合您自己的需求。

## 准备工作

在与您的 jQuery 库相同的目录中创建通常的配方文件：`recipe-3.html`、`recipe-3.css` 和 `recipe-3.js`。

## 如何操作...

执行以下逐步说明以创建引人入胜的内容滑块：

1.  将以下 HTML 代码添加到 `recipe-3.html`，其中包括基本网页和内容滑块的结构：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
       <title>Chapter 7 :: Recipe 3</title>
       <link href="recipe-3.css" rel="stylesheet" type="text/css" />
       <script src="img/jquery.min.js"></script>
       <script src="img/recipe-3.js"></script>
    </head>
    <body>
       <div class="slider-frame">
          <ul class="slider-content">
             <li>
                <h1>Section 1</h1>
                <p>Some content for section one.</p>
             </li>
             <li>
                <h1>Section 2</h1>
                <p>Some content for section two.</p>
             </li>
             <li>
                <h1>Section 3</h1>
                <p>Some content for section three.</p>
             </li>
             <li>
                <h1>Section 4</h1>
                <p>Some content for section four.</p>
             </li>
          </ul>
          <ul class="slider-nav"></ul>
       </div>
    </body>
    </html>
    ```

1.  在 `recipe-3.css` 中添加以下 CSS 代码以添加基本样式并定位内容滑块：

    ```js
    .slider-frame {
       width: 600px;
       height: 250px;
       margin: 50px auto auto auto;
       overflow: hidden;
       position: relative;
    }
    .slider-content {
       margin: 0;
       padding: 0;
       list-style: none;
       position: relative;
    }
    .slider-content li {
       float: left;
       width: 600px;
       height: 250px;
       background-color: #E1E1E1;
    }
    .slider-content li h1 {
       margin: 10px;
    }
    .slider-content li p {
       margin: 10px;
    }
    .slider-nav {
       list-style: none;
       padding: 0;
       margin: 0;
       height: 35px;
       position: absolute;
       bottom: 0;
       left: 0;
       right: 0;
       text-align: center;
    }
    .slider-nav li {
       display: inline-block;
       margin-right: 5px;
    }
    .slider-nav li a {
       display: block;
       color: #FFF;
       text-decoration: none;
       border-radius: 30px;
       background-color: #333;
       width: 25px;
       height: 25px;
       text-align: center;
       line-height: 25px;
    }
    .slider-nav li a:hover {
       background-color: #000;
    }
    .slider-nav li a.active {
       background-color: #FFF;
       color: #333;
    }
    ```

1.  在 `recipe-3.js` 中添加以下 jQuery 代码，以允许用户在内容幻灯片之间切换：

    ```js
    $(function(){
       var _sliderContent = $('.slider-content li');
       for (var i = 0; i < _sliderContent.length; i++) {
          $('.slider-nav').append("<li><a href='#" + i + "' " + ((i == 0) ? "class='active'" : "") + ">" + (i + 1) + "</a></li>");    
       }
       $('.slider-content').width((600 * _sliderContent.length) + "px");
       $(document).on("click", ".slider-nav li a", function(){
          var index = this.hash.replace("#", "");
          $(".slider-nav li a").removeClass("active");
          $(this).addClass("active");
          $('.slider-content').animate({
             left: -(index * 600) + "px"
          });
       });
    });
    ```

## 工作原理...

滑块内容是一个无序列表，其子元素包含要在每个幻灯片中显示的内容。在内容列表下面是另一个无序列表元素，jQuery 将动态填充该元素，以创建每个幻灯片之间的导航。

此配方中的 CSS 代码用于定位滑块框架并设置其静态宽度和高度。将滑块框架的溢出值设置为 `hidden`，以便一次只能看到一个幻灯片。将滑块内容列表项元素设置为 `float left`，以便以行内方式显示它们，从而可以使用 jQuery 动画将它们移入视图中。

jQuery 代码的第一部分选择所有滑块内容子元素并将它们存储在一个局部变量中。对于每个滑块内容列表元素，都会创建一个导航列表项并将其附加到 `slider-nav` 无序列表中，该列表项链接到滑块内容的索引，如下代码所示；还将 `active` 类添加到第一个导航锚点：

```js
var _sliderContent = $('.slider-content li');
for (var i = 0; i < _sliderContent.length; i++) {
   $('.slider-nav').append("<li><a href='#" + i + "' " + ((i == 0) ? "class='active'" : "") + ">" + (i + 1) + "</a></li>");
}
```

为了使滑块内容项能够与彼此一起浮动，需要使 `slider-content` 无序列表元素足够宽。由于 CSS 代码无法知道滑块有多少个幻灯片，因此使用 jQuery 计算内容项的数量，然后将此值乘以滑块的宽度，使用 jQuery `width()` 函数将此结果应用于 `slider-content` 元素，如下所示：

```js
$('.slider-content').width((600 * _sliderContent.length) + "px");
```

执行上述代码将确保 `slider-content` 无序列表元素的宽度足够，以允许每个列表元素的行内定位。

jQuery 代码的最后部分将点击事件处理程序附加到文档，以便监听滑块导航上的点击。当用户点击导航元素之一时，将调用此处理程序的回调函数如下所示：

```js
$(document).on("click", ".slider-nav li a", function(){
   var index = this.hash.replace("#", "");
   $(".slider-nav li a").removeClass("active");
   $(this).addClass("active");
   $('.slider-content').animate({
      left: -(index * 600) + "px"
   });
});
```

在回调函数中，使用 `var index = this.hash.replace("#", "");` 检索点击链接的哈希值，这将导致幻灯片的索引整数。利用这个值，可以使用 jQuery 的 `animate()` 函数在 `slider-content` 无序列表元素上设置负左位置；这将使幻灯片内容动画显示所选幻灯片。`removeClass()` 函数用于从导航列表中的所有锚元素中移除 `active` 类。然后，使用 `addClass` 将 `active` 类添加到点击的元素上。这将向用户指示已选择导航中的哪个幻灯片，因为它会比其他导航项的颜色浅。

## 还有更多…

许多流行的 jQuery 内容滑块都有一个 `auto` 模式，其中每个内容幻灯片都会自动循环，无需任何用户交互。可以通过在示例中添加更多的 jQuery 代码轻松实现这一点。如果想要此功能，请将以下 jQuery 代码添加到 `recipe-3.js` 的 `$(function(){});` 块的底部：

```js
var count = 0;
setInterval(function(){
   if (count >= _sliderContent.length) count = 0;
   $('.slider-content').animate({
      left: -(count * 600) + "px"
   });
   $(".slider-nav li a").removeClass("active");
   $(".slider-nav li").find("a[href='#" + count + "']").addClass("active");
   count++;
}, 3000);
```

使用原生 JavaScript 函数 `setInterval()`，可以连续执行指定间隔的函数。在上述示例中，指定的函数将在每 3000 毫秒后执行。

在上述代码中，声明了一个 `count` 变量来跟踪当前幻灯片。在提供给 `setInterval` 的函数内部，如果已达到可用幻灯片的最大数量，则将 `count` 值设置为 `0`。然后，jQuery 动画函数与单击事件处理程序的方式相同，用于将下一个内容幻灯片动画显示出来。再次使用 `$(".slider-nav li a").removeClass("active");` 从所有导航锚点中移除 `active` 类，然后使用 `$(".slider-nav li").find("a[href='#" + count + "']").addClass("active");` 仅将类添加到链接到下一个内容幻灯片的元素上。最后，增加计数，以便下一次迭代将下一个内容幻灯片动画显示出来。

还值得一提的是，每次调用 jQuery 的 `append()` 函数时，DOM 都会重新绘制。如果使用 `append()` 函数添加了许多项目，例如在这个示例中，这可能会导致应用程序变慢。避免这种情况的一种简单方法是通过创建要添加的所有列表元素的字符串，并在循环后包含单个 `append()` 函数。

## 另见

+   *动画背景图*

# 动画背景图

全屏图像背景可以为任何网站提供非常吸引人的闪屏。本示例将向您展示如何使用 jQuery 动态更改网站的背景图像。

## 准备工作

在与 jQuery 库相同的目录中创建 `recipe-4.html`、`recipe-4.css` 和 `recipe-4.js`。对于此示例，您还需要一组将用作背景图像的图像。找到三到四个大图像（最大尺寸为 1280 x 1024 像素），并将它们保存在您刚刚创建的三个文件相同的目录中。

## 实施方法如下：

打开并准备编辑刚刚创建的三个文件。

1.  将以下 HTML 代码添加到 `recipe-4.html` 中，以创建基本的网页和用于容纳背景图像和文本的元素：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
       <title>Chapter 7 :: Recipe 4</title>
       <link href="recipe-4.css" rel="stylesheet" type="text/css" />
       <script src="img/jquery.min.js"></script>
       <script src="img/recipe-4.js"></script>
    </head>
    <body>
       <div class="background"></div>
       <div class="text-frame">
          <div class="text-inner">
             <h1>BACKGROUND IMAGE ANIMATION</h1>
             <p>This recipe shows you how to alternate the background image of an element using jQuery animations.</p>
          </div>
       </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到 `recipe-4.css` 中，将基本样式应用于新创建的网页；确保更新图像引用以与您选择的图像之一相对应：

    ```js
    body {
       background-color: #333;
    }
    .background {
       background: url(recipe-4-1.jpg)  no-repeat center center fixed;
       -webkit-background-size: cover;
       -moz-background-size: cover;
       -o-background-size: cover;
       background-size: cover;
       position: absolute;
       top: 0;
       bottom: 0;
       left: 0;
       right: 0;
    }
    .text-frame {
       position: absolute;
       top: 0;
       bottom: 0;
       left: 0;
       right: 0;
    }
    .text-inner {
       width: 600px;
       margin: 15% auto auto auto;
       background-color: rgba(0, 0, 0, 0.78);
       padding: 20px;
       color: #E1E1E1;
       border-radius: 5px;
    }
    .text-inner h1 {
       margin: 0;
       padding: 0;
    }
    .text-inner p {
       font-size: 22px;
       line-height: 30px;
       margin: 5px 0 5px 0;
       color: #CCC;
    }
    ```

1.  将以下 jQuery 代码添加到 `recipe-4.js` 中，以激活刚刚添加到 `recipe-4.html` 的 `background` 分割元素中的背景动画：

    ```js
    var _images = ['recipe-4-1.jpg', 'recipe-4-2.jpg', 'recipe-4-3.jpg'];
    var index = 1;
    $(function(){
       setInterval(function(){
          if (index >= _images.length) index = 0;
          $('.background').animate({
             opacity: 0
          }, 1500, function(){
             $(this).css({
                'background-image': "url('" + _images[index] + "')"
             }).animate({
                opacity: 1
             }, 1500);
             index++;
          });
       }, 6000);
    });
    ```

1.  在 `recipe-4.js` 开头的 _`images` 数组中更新文件名，使其与您为此示例选择的图像文件名匹配。

## 工作原理如下：

这个示例创建的基本网页主要分为两个部分。首先是一个具有 `background` 类的分割元素，它被制作成填满整个屏幕，并使用所选的图像作为背景。其次，有一个 `text-frame` 分割元素，简单地将一些文本浮动在屏幕中央。

`recipe-4.css` 中的 CSS 代码将背景元素的位置设置为 `absolute`，并将其左、右、底部和顶部位置设置为 `0`，强制其填满整个屏幕。然后使用以下代码设置其背景属性：

```js
background: url(recipe-4-1.jpg)  no-repeat center center fixed;
-webkit-background-size: cover;
-moz-background-size: cover;
-o-background-size: cover;
background-size: cover;
```

背景选项将其中一个所选图像设置为其初始背景，并确保其居中和固定。使用 `background-size` 属性确保背景图像始终填满 `background` 分割元素的 100%。

使用类似的 CSS 确保 `text-frame` 元素填满屏幕，并使用百分比和自动边距，使包含文本的 `text-inner` 元素在垂直和水平方向上居中。

`recipe-4.js` 开头的 `_images` 数组保存了对所选背景图像的引用。`index` 变量用于跟踪当前显示的背景图像。在 jQuery 加载函数内部，声明 `setInterval` 来执行一组动画，以在六秒钟内更改背景图像。这类似于上一个示例的 *There's more...* 部分。

因为 jQuery 的`animate()`函数不支持直接对背景图像进行动画处理，所以我们必须提供一个变通方法。在`setInterval()`函数中，将`animate()`函数用于背景元素的不透明度，以将元素淡出。然后，通过为 jQuery 的`animate()`函数指定回调，一旦动画完成，就使用 jQuery 的`css()`函数修改背景元素的`background-image`属性。使用`css()`，更改背景图像，然后再次使用`animate()`函数将不透明度更改回`1`，以淡入元素。通过引用`_images`数组的索引值，可以在`setInterval()`函数的每次迭代中选择不同的背景图像，如下所示：

```js
$(this).css({
   'background-image': "url('" + _images[index] + "')"
}).animate({
   opacity: 1
}, 1500);
index++;
```

一旦最后一个动画完成，索引值将增加一，以确保下一次迭代显示不同的图像。

## 另请参阅

+   *创建一个动画内容滑块*

# 创建动画导航菜单

您的网站导航允许访问者轻松找到托管在您网站上的内容。为用户提供一个既有趣又交互式的导航菜单，并且易于使用，可以给他们留下深刻的印象。本秘诀向您展示了如何创建一个现代动画导航菜单。

## 准备工作

在与最新版本的 jQuery 库相同的目录中创建`recipe-5.html`、`recipe-5.css`和`recipe-5.js`。

## 操作方法…

执行以下所有步骤，为任何站点创建一个独特和现代的动画导航菜单：

1.  在`recipe-5.html`中添加以下 HTML，以创建基本网页，并包括新创建的文件以及 jQuery 库：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
       <title>Chapter 7 :: Recipe 5</title>
       <link href="recipe-5.css" rel="stylesheet" type="text/css" />
       <script src="img/jquery.min.js"></script>
       <script src="img/recipe-5.js"></script>
    </head>
    <body>
    </body>
    </html>
    ```

1.  在`recipe-5.html`中身体标签的 HTML 代码中，添加以下代码来创建导航菜单的结构：

    ```js
    <div class="container">
       <ul class="navigation">
          <li>
             <a href="#" class="link-base">
                <div class="link-content">
                   <div class="nav-item">HOME</div>
                   <div class="nav-item hover">HOME</div>
                </div>
             </a>
          </li>
          <li>
             <a href="#" class="link-base">
                <div class="link-content">
                   <div class="nav-item">ABOUT <div class="down-arrow"></div></div>
                   <div class="nav-item hover">ABOUT <div class="down-arrow"></div></div>
                </div>
             </a>
             <ul class="sub-nav">
                <li>
                   <a href="#">
                      <div class="sub-link-content">
                         <div class="sub-nav-item">SECTION 1</div>
                         <div class="sub-nav-item hover">SECTION 1</div>
                        </div>
                     </a>
                  </li>
               <li>
                   <a href="#">
                      <div class="sub-link-content">
                         <div class="sub-nav-item">SECTION 2</div>
                         <div class="sub-nav-item hover">SECTION 2</div>
                      </div>
                   </a>
                </li>
                <li>
                   <a href="#">
                      <div class="sub-link-content">
                         <div class="sub-nav-item">SECTION 3</div>
                         <div class="sub-nav-item hover">SECTION 3</div>
                      </div>
                   </a>
                </li>
             </ul></li>
          <li>
             <a href="#" class="link-base">
                <div class="link-content">
                   <div class="nav-item">CONTACT</div>
                   <div class="nav-item hover">CONTACT</div>
                </div>
             </a>
          </li>
       </ul>
    </div>
    ```

1.  添加以下 CSS 代码到`recipe-5.css`，为导航菜单和网页提供基本样式：

    ```js
    .container {
       width: 800px;
       margin: 100px auto auto auto;
    }
    .navigation {
       margin: 0;
       padding: 0;
       list-style: none;
       background-color: #333;
       height: 50px;
    }
    .navigation li {
       float: left;
       position: relative;
    }
    .navigation li a {
       display: block;
       text-align: center;
       color: #FFF;
       text-decoration: none;
       overflow: hidden;
       height: 50px;
    }
    .navigation li a .nav-item {
       line-height: 50px;
       padding: 0 15px 0 15px;
       height: 50px;
    }
    .navigation li a .nav-item.hover {
       background-color: #ff3600;
    }
    .sub-nav {
       list-style: none;
       margin: 0;
       padding: 50px 0 0 0;
       opacity: 0;
       position: absolute;
       top: 0;
       left: -10000px;
       opacity: 0;
    }
    .sub-nav li {
       display: block;
       height: 40px;
    }
    .sub-nav li a {
       display: block;
       width: 120px;
       height: 40px;
       line-height: 40px;
       text-align: center;
       color: #FFF;
       background-color: #333333;
    }
    .sub-nav li a .sub-link-content {
       width: 240px;
    }
    .sub-nav li a .sub-nav-item {
       float: left;
       width: 120px;
    }
    .sub-nav li a .sub-nav-item.hover {
       background-color: #ff3600;
    }
    .down-arrow {
       width: 0;
       border-left: 7px solid transparent;
       border-right: 7px solid transparent;
       border-top: 7px solid white;
       display: inline-block;
       vertical-align: middle;
       margin: -5px 0 0 5px;
    }
    ```

1.  要根据用户交互将动画添加到导航菜单，将以下 jQuery 代码添加到`recipe-5.js`中：

    ```js
    $(function(){
       //Base navigation
       $(document).on("mouseenter", "ul.navigation li a.link-base", function(){
          $(this).find(".link-content").stop().animate({
             marginTop: -50
          }, 200, function(){
             $(this).parent().parent().find('.sub-nav').css({
               left: 0
            }).animate({
               opacity: 1
            });
          });
       }).on("mouseleave", "ul.navigation li a", function(){
          //Only reverse the animation if this link doesn't have a sub menu
          if ($(this).parent().find('.sub-nav').length == 0) {
             $(this).find(".link-content").stop().animate({
                marginTop: 0
            }, 200);
          }
       }).on("mouseleave", "ul.navigation li .sub-nav", function(){
          $(this).animate({
             opacity: 0
          }, 200, function(){
             $(this).css({
                left: -10000
           });
             //When the mouse leaves the sub menu, also reverse the base link animation
             $(this).parent().find('.link-content').stop().animate({
                marginTop: 0
             }, 200);
          });
       }).on("mouseenter", "ul.sub-nav li a", function(){
          $(this).find(".sub-link-content").stop().animate({
             marginLeft: -120
          }, 200);
       }).on("mouseleave", "ul.navigation li a", function(){
          $(this).find(".sub-link-content").stop().animate({
             marginLeft: 0
          }, 200);
       });
    });
    ```

1.  在 Web 浏览器中打开`recipe-5.html`，您将看到一个简单的导航菜单。在**关于**项目上悬停将会启动动画，并向您呈现相关的子菜单，如下面的屏幕截图所示：![操作方法…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_07_03.jpg)

## 运行原理…

当我们逐步分解时，本秘诀的代码将很容易理解。用于创建导航菜单的 HTML 代码具有一个带有 class `frame`的分区元素，它作为菜单容器来控制宽度和位置。

菜单本身由带有导航类的无序列表元素组成。在这个列表中，有多个作为菜单页面链接的锚的一级列表元素。

每个这些一级链接都有一个包含两个`nav-item`分区元素的`link-content`容器元素。使用 CSS 将其中两个`nav-item`元素进行不同的样式设置，可以使我们创建下拉动画，因为我们一次只显示其中一个。

`about`一级导航项也有一个子菜单。为了实现这一点，列表项包含另一个具有`sub-nav`类的无序列表。使用 CSS，当子菜单可见时，将此子导航元素放置在原始的一级页面链接上，以便鼠标指针不会离开该区域。这样，我们可以保持原始链接处于悬停状态，并且子菜单保持打开状态，直到用户的鼠标完全离开子菜单。

子菜单页面链接的结构与它们包含两个相同文本的一级链接相同。这样做是为了让我们能够创建类似的悬停动画。

在`recipe-5.js`中，第一部分将`mouseenter`事件处理程序附加到文档上，以查找鼠标指针是否进入导航的一级链接之一，如下所示：

```js
$(document).on("mouseenter", "ul.navigation li a.link-base", function(){
   $(this).find(".link-content").stop().animate({
      marginTop: -50
   }, 200, function(){
      $(this).parent().parent().find('.sub-nav').css({
      left: 0
   }).animate({
      opacity: 1
      });
   });
})
```

当发生这种情况时，将在链接的`link-content`子元素上使用`animate()`函数，将其顶部边距设置为`-50`。这将使第二个`nav-item`类移入具有 CSS 橙色背景的视图中。在 200 毫秒后，动画完成时，将调用额外的回调函数。

这将执行代码以打开当前悬停项目包含的任何子菜单。首先使用`css()`函数将子菜单的左侧位置设置为`0`，将其带到屏幕上，然后使用`animate()`函数将元素的不透明度设置为`1`，将图像淡入视图中。子菜单元素最初使用左侧位置`-10000`放置在屏幕外，以便它们不会妨碍用户可能在页面上执行的任何点击操作。

第二个事件处理程序是针对`mouseleave`事件的。此事件处理程序检查最近设置为`left`的顶级链接是否具有子菜单，使用`if($(this).parent().find('.sub-nav').length == 0)`。如果没有，悬停动画将被恢复，将`link-content`元素的顶部边距设为`0`。这样，我们可以在用户浏览子菜单时保持悬停状态处于活动状态。

下一个事件处理程序是另一个`mouseleave`事件处理程序，它处理用户离开子菜单，如下所示：

```js
.on("mouseleave", "ul.navigation li .sub-nav", function(){
   $(this).animate({
      opacity: 0
   }, 200, function(){
      $(this).css({
      left: -10000
   });
   //When the mouse leaves the sub menu, also reverse the base link animation
   $(this).parent().find('.link-content').stop().animate({
      marginTop: 0
      }, 200);
   });
})
```

一旦用户的鼠标离开了子菜单，就会使用`animate()`函数将子菜单的不透明度设为`0`，使其淡出。然后，在完成了 200 毫秒的动画后，使用`css()`函数将子菜单移到屏幕外-10000 像素的位置。最后，使用`find()`来选择第一级`link-content`元素，将原始的悬停动画恢复，将菜单放回休眠状态。

文档附加了两个额外的事件处理程序。额外的`mouseenter`和`mouseleave`事件用于为子菜单项创建悬停动画。与一级导航菜单相同的代码和技术被使用，只是改变了左边距而不是顶边距，以使`sub-link-content`元素从左到右进行动画，而不是从上到下。

## 亦参见

+   *创建一个动态内容滑块*

+   *动画背景图片*


# 第八章：理解插件开发

在本章中，我们将涵盖以下主题：

+   创建一个插件模板

+   创建一个工具提示插件

+   构建内容和图像滑块插件

+   创建一个 RSS 订阅阅读器插件

+   从头开始编写一个图像裁剪插件

# 介绍

jQuery 插件允许开发人员编写可在任何 jQuery 项目中快速重用的可移植代码。作为本书的一部分，我们已经创建了许多功能，您可能希望在多个项目中使用。通过创建具有所需功能的 jQuery 插件，您可以抽象出这些功能的复杂性，并使其简单地包含在您需要的任何地方。

在开始本章之前，请创建一个名为`chapter8`的易于访问的目录。在此文件夹中，添加最新版本的 jQuery 库，该库将在本章中使用。

# 创建一个插件模板

多年来，创建 jQuery 插件已经变得非常流行，有许多关于插件创建最佳实践的文章和在线讨论。这些文章中的许多都深入讨论了如何创建一个插件模板，该模板可用作任何 jQuery 插件的起点。本配方将向您展示如何创建自己的 jQuery 插件模板，该模板将在本章中使用。

## 准备就绪

在前面创建的`chapter8`文件夹内，创建一个名为`jquery.plugin-template.js`的 JavaScript 文件。

## 如何做…

要创建一个基本的插件模板，该模板将成为本章中使用的所有插件的基础，请将以下代码添加到`jquery.plugin-template.js`中：

```js
;(function ($) {

    var name = 'pluginName';
    Plugin.prototype = {
        defaults: {

        }
    };

    // The actual plugin constructor
    function Plugin(element, options) {
        var $scope = this;
        $scope.$element = $(element);
        $scope.element = element;
        $scope.options = $.extend({}, this.defaults, options);
        $scope.init = function () {

        }
    }

    $.fn[name] = function (options) {
        return this.each(function () {
            new Plugin(this, options).init();
        });
    }
})(jQuery);
```

## 它是如何工作的…

在 jQuery 网站上阅读插件文档([`learn.jquery.com/plugins/basic-plugin-creation/`](http://learn.jquery.com/plugins/basic-plugin-creation/)) ，以查看一组指南和最佳实践。

在本配方中创建的插件使用简单的概念和最佳实践来创建一个轻量级的插件模板。 Addy Osmani 撰写了一篇很受欢迎的文章([`coding.smashingmagazine.com/2011/10/11/essential-jquery-plugin-patterns/`](http://coding.smashingmagazine.com/2011/10/11/essential-jquery-plugin-patterns/)) ，其中提供了关于插件编写的深入见解，同时遵循这些推荐的最佳实践。

看看我们的插件模板，首先要注意的是文档开头的分号。这是为了确保任何之前包含的插件或脚本都已正确关闭。

为了符合 jQuery 的作者建议，整个插件被包裹在一个**立即调用的函数表达式**（**IIFE**）中，以为插件提供范围。jQuery 作为本地变量`$`提供给 IIFE，以允许开发人员以通常的方式引用 jQuery 库而不会发生冲突。

在插件构造函数中，声明了一个`$scope`变量，以便清楚地表示插件的范围。然后将插件正在初始化的元素分配给插件的范围，以及任何提供的插件选项。使用 jQuery 的`extend()`函数将`defaults`对象与`options`对象合并，覆盖可能在`options`中提供的任何默认值。最后，将`init()`函数添加到插件的范围，这是您将放置插件初始化代码的地方，如下所示：

```js
$.fn[name] = function (options) {
   return this.each(function () {
      new Plugin(this, options).init();
   });
}
```

上述代码使得插件可用，就像任何其他使用指定插件名称（`($('.element').pluginName();`）的 jQuery 对象方法一样。使用`this.each()`，它将为插件初始化的每个元素创建一个新的插件实例，并调用插件的`init()`函数。

# 创建一个提示框插件

提示框是向用户展示关于他们正在使用的 UI 的其他信息的一种流行方式。本步骤将向您展示如何创建自己的基本提示框插件，您可以在所有项目中轻松使用。

## 准备工作

复制`jquery.plugin-template.js`文件，并创建`jquery.tooltip.js`，它将成为此步骤的插件文件。在与插件文件和 jQuery 库相同的目录中创建`recipe-2.html`和`recipe-2.js`。

## 如何做…

要创建一个简单的提示框插件和示例网页，请执行以下步骤：

1.  在`recipe-2.html`中添加以下 HTML 代码，创建一个非常简单的网页，网页中的元素可以有一个提示框。

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 8 :: Recipe 2</title>
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.tooltip.js"></script>
        <script src="img/recipe-2.js"></script>
    </head>
    <body>
    <p><input type="text" class="hasTooltip" data-title="This is a tooltip on an input box" /></p>
    <p><a href="http://www.google.com/" target="_blank" class="hasTooltip" title="External link to http://www.google.com/">Google.com</a></p>
    <button class="hasTooltip" data-title="A button with a tooltip">Button</button>
    </body>
    </html>
    ```

1.  在`jquery.tooltip.js`的顶部，更新`name`变量，并将插件默认设置更改如下：

    ```js
    var name = 'tooltip';
    Plugin.prototype = {
    defaults: {
                'height': 30,
                'fadeInDelay': 200
    }
    };
    ```

1.  使用以下代码更新`$scope.init()`函数：

    ```js
    $scope.init = function() {
    $scope._text = (typeof $scope.$element.data('title') != "undefined") ? $scope.$element.data('title') : $scope.$element.prop("title");
                //Only display the tooltip if a title has been specified
                if (typeof $scope._text != "undefined") {
                    var $html = $("<div class='tooltip-frame'>"
                        +   "<div class='tooltip-arrow'></div>"
                        +   "<div class='tooltip-text'>" + $scope._text + "</div>"
                        + "</div>");

                    $html.css({
                        'position': 'absolute',
                        'text-align': 'center',
                        'height': $scope.options.height,
                        'line-height': $scope.options.height + "px",
                        'left': $scope.$element.offset().left + $scope.$element.outerWidth() + 15,
                        'top': $scope.$element.offset().top + ($scope.$element.outerHeight() / 2) - ($scope.options.height / 2),
                        'background-color': 'rgba(0, 0, 0, 0.81)',
                        'color': '#FFF',
                        'padding': '0 10px 0 10px',
                        'border-radius': '5px',
                        'opact': 'none'
                    }).find('.tooltip-arrow').css({
                            'width': 0,
                            'height': 0,
                            'border-top': '10px solid transparent',
                            'border-bottom': '10px solid transparent',
                            'border-right': '10px solid rgba(0, 0, 0, 0.81)',
                            'position': 'absolute',
                            'left': '-10px',
                            'top': (($scope.options.height / 2) - 10)
                        });

                    $scope.$element.on("mouseover", function(){
                        $html.fadeIn($scope.options.fadeInDelay);
                        $scope.$element.after($html);
                    }).on("mouseout", function(){
                        $html.remove();
                    });
                }
            }
    ```

1.  将以下 jQuery 代码添加到`recipe-2.js`中，为所有具有`hasTooltip`类的 HTML 元素初始化提示框插件：

    ```js
    $(function(){
        $('.hasTooltip').tooltip();
    });
    ```

1.  在 Web 浏览器中打开`recipe-2.html`，将鼠标悬停在屏幕上的一个元素上，以查看提示框出现。

## 它是如何工作的…

作为此步骤的一部分创建的 HTML 页面仅用于提供可以附加提示框的一些元素。

对插件模板的第一个更改是设置默认设置。在这种情况下，我们设置了提示框的高度和淡入动画持续时间。您可以通过将这些功能添加到此处的默认设置中，引入自己的其他功能。

当为每个选定的元素初始化插件时，将调用`init()`函数，该函数包含此插件的大部分逻辑。

插件模板使得元素的“jQueryfied”版本通过`$scope.$element`可用。我们可以使用`prop()`和`data()`函数来检查元素上是否指定了标题，并将其存储在`$scope._text`中，这将被用作提示框的文本。

然后将检查此变量，以确保有可用的文本来显示。如果没有文本，我们将不显示提示框。

如果 `$scope._text` 被定义，我们使用以下代码创建工具提示 HTML：

```js
var $html = $("<div class='tooltip-frame'>"
       +   "<div class='tooltip-arrow'></div>"
       +   "<div class='tooltip-text'>" + $scope._text + "</div>"
       + "</div>");
```

`var` 语句很重要，以确保为每个选定的元素创建一个新的工具提示元素。通过将 HTML 代码包装在 `$()` 内，我们可以在将其插入到 DOM 中之前在此元素上使用 jQuery 函数。工具提示的 HTML 代码添加了标题文本并创建了一个将显示左箭头的元素。

使用 jQuery 的 `css()` 函数，一系列 CSS 样式被应用于新创建的 HTML 代码，以定位和样式化工具提示。工具提示的左侧和顶部位置是使用将显示工具提示的选定元素的偏移量、宽度和高度来计算的。请注意，使用 `outerWidth()` 和 `outerHeight()` 函数而不是 `width()`/`height()` 函数，以包含填充和边框并返回尺寸。

jQuery 的 `find()` 函数也与 `css()` 函数一起使用，用于向左箭头添加样式。

最后，两个事件侦听器被附加到选定的元素上，以便当用户的鼠标移动到元素上时显示工具提示，并在用户的鼠标移出时移除工具提示。`fadeIn()` 函数从 `defaults` 对象中取得 `duration` 参数，当初始化工具提示插件时可以被覆盖。

要为所有具有 `hasTooltip` 类的元素初始化工具提示插件，将以下 jQuery 代码添加到 `recipe-2.js`：

```js
$(function(){
    $('.hasTooltip').tooltip();
});
```

在这里，你可以覆盖默认设置，例如，使用以下代码：

```js
$(function(){
    $('.hasTooltip').tooltip({
       'height': 50,
          'fadeInDelay': 500              
    });
});
```

## 这还不是全部...

这个配方提供了一个非常基本的工具提示插件。你可以在此基础上扩展很多额外的功能，比如定位，并允许插件用户指定工具提示在哪个事件上打开。

# 构建内容和图片滑块插件

在第七章中，*用户界面动画*，你看到了如何使用 jQuery 创建一个简单的内容滑块。本配方将向你展示如何将该配方转换为一个可重用的 jQuery 插件，还可以向滑块添加图片。你不需要阅读前一个配方来完成这个，但建议你这样做，以便更好地理解代码的工作原理。

## 准备工作

复制 `jquery.plugin-template.js` 文件并将其重命名为 `jquery.slider.js`，它将成为此配方的插件。你还需要找到一张宽度为 600 像素、高度为 250 像素的图片，将其用于滑块。最后，在 `jquery.slider.js` 文件和 jQuery 库相同目录下创建 `recipe-3.html`、`slider.css` 和 `recipe-3.js`。

## 如何做...

执行以下步骤来创建您的图片和内容滑块插件：

1.  将以下 HTML 添加到 `recipe-3.html`：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 8 :: Recipe 3</title>
        <link href="slider.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.slider.js"></script>
        <script src="img/recipe-3.js"></script>
    </head>
    <body>
    <div class="mySlider">
        <div>Slider Content 1</div>
        <img src="img/british-countryside.jpg" />
        <div>Slider Content 3</div>
        <div>Slider Content 4</div>
    </div>
    </body>
    </html>
    ```

1.  在 `jquery.slider.js` 的顶部，将插件名称更新为 `slider`，并将默认设置如下：

    ```js
    var name = 'slider';
    Plugin.prototype = {
       defaults: {
          width: 600,
          height: 250
    }
    };
    ```

1.  更新插件的 `$scope.init()` 函数如下所示：

    ```js
    $scope.init = function () {
    $scope.$element.addClass("slider-frame").css({
       width: $scope.options.width,
       height: $scope.options.height
    });
    $scope.$element.append('<ul class="slider-nav"></ul>');
    var _sliderItems = $scope.$element.find('div, img');
    _sliderItems.wrapAll("<div class='slider-content'></div>");
    $scope.$element.find('.slider-content').css({
       width: $scope.options.width * _sliderItems.length,
       position: 'relative'
    });
    _sliderItems.css({
       float: 'left',
       width: $scope.options.width,
       height: $scope.options.height
    });
    var _sliderNav = $scope.$element.find('.slider-nav');
    for (var i = 0; i < _sliderItems.length; i++) {
       _sliderNav.append("<li><a href='#" + i + "' " + ((i == 0) ? "class='active'" : "") + ">" + (i + 1) + "</a></li>");
    }
    _sliderNav.on("click", "li a", function(){
       var index = this.hash.replace("#", "");
       _sliderNav.find('li a').removeClass("active");
       $(this).addClass("active");
       $scope.$element.find('.slider-content').animate({
          left: -(index * $scope.options.width) + "px"
       });
    });
    }
    ```

1.  将以下 jQuery 代码添加到 `recipe-3.js` 中以初始化滑块插件：

    ```js
    $(function(){
        $('.mySlider').slider();
    });
    ```

1.  将以下 CSS 代码添加到 `slider.css` 中：

    ```js
    .slider-frame {
        overflow: hidden;
        position: relative;
        margin: auto;
        border: solid 1px #CCC;
    }
    .slider-nav {
        list-style: none;
        padding: 0;
        margin: 0;
        height: 35px;
        position: absolute;
        bottom: 0;
        left: 0;
        right: 0;
        text-align: center;
    }
    .slider-nav li {
        display: inline-block;
        margin-right: 5px;
    }
    .slider-nav li a {
        display: block;
        color: #FFF;
        text-decoration: none;
        border-radius: 30px;
        background-color: #333;
        width: 25px;
        height: 25px;
        text-align: center;
        line-height: 25px;
    }
    .slider-nav li a:hover {
        background-color: #000;
    }
    .slider-nav li a.active {
        background-color: #FFF;
        color: #333;
    }
    ```

1.  在 Web 浏览器中打开 `recipe-3.html`，您将看到一个动态创建的图像和内容滑块。

## 工作原理…

HTML 页面设置了滑块插件所需的 HTML。有一个包含子项的容器分区，滑块插件将使用这些子项作为幻灯片。子项可以是分区元素或图像。

`recipe-3.js` 中的 jQuery 代码选择 `mySlider` 分区元素并初始化滑块插件。

我们之前创建的插件模板负责 jQuery 插件的设置。我们的滑块插件的功能放在 `init()` 函数中。在此函数的开头，将 `slider-frame` 类添加到选定的元素（`.mySlider`）中，以便它从 `slider.css` 样式表中继承一些基本样式。使用来自 `options` 对象的值，使用 jQuery `css()` 函数设置元素的宽度和高度，如下所示：

```js
$scope.$element.addClass("slider-frame").css({
width: this.options.width,
height: this.options.height
});
```

之后，使用 `$scope.$element.append('<ul class="slider-nav"></ul>');` 将空的无序列表插入到滑块中，该列表已准备好创建幻灯片导航。

代码的下一部分设置了动画的滑块。如在 第七章 *用户界面动画* 的 *创建动画内容滑块* 配方中所解释的，滑块需要其容器的宽度为其幻灯片的组合宽度，以便幻灯片可以浮动在一起，并使用动画移动到视图中，如下面的代码所示：

```js
var _sliderItems = $scope.$element.find('div, img');
_sliderItems.wrapAll("<div class='slider-content'></div>");
$scope.$element.find('.slider-content').css({
width: $scope.options.width * _sliderItems.length,
position: 'relative'
});
```

为此，选择滑块的子项（幻灯片），然后使用 jQuery `wrapAll()` 函数将其包装在一个分区元素中。该元素的宽度设置为幻灯片的个数乘以单个幻灯片的宽度。为了浮动每个幻灯片，使用 `css()` 函数设置 `float` 属性，如下面的代码所示：

```js
_sliderItems.css({
   float: 'left',
   width: $scope.options.width,
   height: $scope.options.height
});
```

配置了每个幻灯片后，代码的下一步是为 `slider-nav` 无序列表元素添加每个幻灯片的列表项，以形成导航：

```js
var _sliderNav = $scope.$element.find('.slider-nav');
for (var i = 0; i < _sliderItems.length; i++) {
   _sliderNav.append("<li><a href='#" + i + "' " + ((i == 0) ? "class='active'" : "") + ">" + (i + 1) + "</a></li>");
 }
```

插件的最后阶段是监听导航列表中锚元素的点击，代码如下，以允许用户使用此导航更改可见幻灯片：

```js
_sliderNav.on("click", "li a", function(){
   var index = this.hash.replace("#", "");
   _sliderNav.find('li a').removeClass("active");
   $(this).addClass("active");
   $scope.$element.find('.slider-content').animate({
      left: -(index * $scope.options.width) + "px"
});
});
```

当用户点击链接时，使用 `animate()` 函数根据所选链接更改 `slider-content` 分区元素的左侧位置。在 第七章 *用户界面动画* 的 *创建动画内容滑块* 配方中可以阅读更多相关信息。

## 还有更多…

要将流行的自动滑块效果添加到此插件，回顾一下 第七章 中的 *创建一个带动画内容滑块* 配方，*用户界面动画*。

## 另请参阅

+   *创建一个带动画内容滑块的* 配方在 第七章，*用户界面动画*

# 创建一个 RSS 阅读器插件

RSS 阅读器是许多网站非常受欢迎的附加组件。此配方将向您展示如何使用 Google Feed API 创建可配置的 feed 阅读器插件，从而使您可以轻松地在任何网站上重用该插件。

## 准备工作

再次复制 `jquery.plugin-template.js` 文件并将其重命名为 `jquery.rssreader.js`，以提供此配方插件的基础。在同一目录中，创建 `recipe-4.js`、`rssreader.css` 和 `recipe-4.html`。

## 如何实现…

要创建 RSS 阅读器插件，请执行以下步骤：

1.  将以下 HTML 代码添加到 `recipe-4.html` 中，以创建一个基本的网页，并使 Google Feed API 可供页面内使用：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 8 :: Recipe 4</title>
        <link href="rssreader.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/jsapi"></script>
        <script type="text/javascript">
            google.load("feeds", "1");
        </script>
        <script src="img/jquery.rssreader.js"></script>
        <script src="img/recipe-4.js"></script>
    </head>
    <body>
    <div class="myRSSContent"></div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码添加到 `rssreader.css` 中，以创建 RSS 阅读器的样式：

    ```js
    @import url(http://fonts.googleapis.com/css?family=Source+Sans+Pro:200,300,400);
    .rssreader-frame {
        background-color: #333;
        border-radius: 5px;
        border: solid 1px #1f1f1f;
        padding: 0 10px 10px 10px;
        font-family: 'Source Sans Pro', sans-serif !important;
    }
    .rssreader-frame h1 {
        margin: 5px 0 5px 0;
        padding: 0;
        font-size: 22px;
        color: #FFF;
        line-height: 30px;
        font-weight: 200;
    }
    .rssreader-frame ul {
        margin: 0;
        padding: 0;
        list-style: none;
    }
    .rssreader-frame ul h4 {
        margin: 0;
        position: relative;
        font-weight: 200;
        color: #E1E1E1;
    }
    .rssreader-frame p.description {
        margin: 0 -10px 10px -10px;
        padding: 0 10px 10px 10px;
        color: #CCC;
        font-size: 12px;
        border-bottom: solid 1px #494949;
    }
    .rssreader-frame ul h4 a {
        line-height: 25px;
        margin-right: 110px;
        display: block;
        text-decoration: none;
        color: #8bd;
    }
    .rssreader-frame ul h4 .entry-date {
        width: 100px;
        position: absolute;
        right: 0;
        top: 0;
        height: 25px;
        line-height: 25px;
        text-align: right;
    }
    .rssreader-frame ul li p {
        color: #666;
        margin: 0 0 10px 0;
        padding: 0 0 10px 0;
        border-bottom: dotted 1px #494949;
    }
    ```

1.  在 `jquery.rssreader.js` 的顶部，更新 `defaults` 对象和 `name` 变量如下所示：

    ```js
    var name = 'rssreader';
    Plugin.prototype = {
    defaults: {
        url: 'http://feeds.bbci.co.uk/news/technology/rss.xml',
        amount: 5,
        width: null,
        height: null
       }
    };
    ```

1.  更新插件 `init()` 函数以包含以下代码：

    ```js
            $scope.init = function () {
                $scope.$element.addClass("rssreader-frame");
                if ($scope.options.width != null) {
                   $scope.$element.width($scope.options.width);
                }
                var feed = new google.feeds.Feed($scope.options.url);
                feed.setNumEntries($scope.options.amount);
                feed.load(function(result) {
                    if (!result.error) {
                        var _title = $("<h1>" + result.feed.title + "</h1>");
                        var _description = $("<p class='description'>" + result.feed.description + "</p>");
                        var _feedList = $("<ul class='feed-list'></ul>");
                        for (var i = 0; i < result.feed.entries.length; i++) {
                            var entry = result.feed.entries[i];
                            var date = new Date(entry.publishedDate);
                            var dateString = date.getDate() + "/" + (date.getMonth() + 1) + "/" + date.getFullYear();
                            var _listElement = $("<li></li>");
                            _listElement.append("<h4><a href='" + entry.link + "'>" + entry.title + "</a><div class='entry-date'>" + dateString + "</div></h4>");
                            _listElement.append("<p>" + entry.content + "</p>");
                            _feedList.append(_listElement);
                        }
                        $scope.$element.append(_title);
                        $scope.$element.append(_description);
                        $scope.$element.append(_feedList);
                        if ($scope.options.height != null && (_feedList.outerHeight() + _title.outerHeight()) > $scope.options.height) {
                            _feedList.css({
                                'height': ($scope.options.height - _title.outerHeight()),
                                'overflow-y': 'scroll',
                                'padding-right': 10
                            });
                        }
                    }
                });
            }
    ```

1.  将以下几行 jQuery 添加到 `recipe-4.js` 中，以为 `myRSSContent` 元素初始化插件：

    ```js
    $(function(){
        $('.myRSSContent').rssreader({
            width: 400,
            height: 300
        });
    });
    ```

1.  在 Web 浏览器中打开 `recipe-4.html`，您将看到以下 RSS 阅读器：![如何实现…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_08_01.jpg)

## 它是如何工作的…

创建此配方的网页的 HTML 代码有一个用于初始化 RSS 阅读器插件的单个 `division` 元素，并作为 RSS 内容的容器。此外，Google Feed API 也被用于此页面，位于 `jquery.rssreader.js` 文件之前。使用 Google Feed API 意味着我们可以轻松创建一个插件，而不需要任何服务器端工作。这也使得插件很容易移植到任何网站上。在 [`developers.google.com/feed/v1/devguide#hiworld`](https://developers.google.com/feed/v1/devguide#hiworld) 上阅读更多关于此 API 的信息。

CSS 代码为插件内部创建的 RSS 阅读器元素设置样式。不需要进一步解释此代码。

与本章中的其他插件一样，模板负责插件设置，我们的插件功能位于 `init()` 函数内，该函数在插件初始化后执行一次。

此函数的第一部分将 `rssreader-frame` 类添加到所选元素中，CSS 代码使用该类应用各种样式。然后，查看 `options` 变量，如果已提供，则在所选元素上设置宽度。

使用 Google Feed API，使用`options`对象的`URL`和`amount`值配置了反馈请求，如下所示。这将告诉 API 在哪里收集 RSS 内容以及要返回多少个项目。

```js
var feed = new google.feeds.Feed($scope.options.url);
feed.setNumEntries($scope.options.amount);
```

之后，使用`load()`函数进行请求，并指定回调函数，如下所示：

```js
feed.load(function(result) {
if (!result.error) {
// -- HIDDEN CODE
}
}
```

如果没有发生错误，则创建标题、描述和无序列表元素，并将它们存储在本地变量中，如以下代码所示：

```js
var _title = $("<h1>" + result.feed.title + "</h1>");
var _description = $("<p class='description'>" + result.feed.description + "</p>");
var _feedList = $("<ul class='feed-list'></ul>");
```

使用`result.feed`对象，可以提取用于放置在这些元素中的反馈标题和描述。这些元素被创建并包裹在 jQuery 选择器（`$()`）内，以便 jQuery 的函数可以在稍后对这些元素进行操作。

然后我们循环遍历每个条目，并为每个条目创建一个列表项。在每个列表项内，我们添加了反馈内容、日期、标题和链接。使用 JavaScript 的`Date()`函数，创建一个更易读的日期以插入到 DOM 中。要将每个元素添加到先前创建的无序列表元素中，使用了`_feedList.append(_listElement);`。

标题、描述和现在已完全填充了 RSS 内容的列表可以使用以下代码插入到 DOM 中：

```js
$scope.$element.append(_title);
$scope.$element.append(_description);
$scope.$element.append(_feedList);
```

最后，使用以下代码来为 RSS 订阅阅读器应用任何指定的高度，并在内容过大无法适应指定高度时添加滚动条：

```js
if ($scope.options.height != null && (_feedList.outerHeight() + _title.outerHeight()) > $scope.options.height) {
   _feedList.css({
   'height': ($scope.options.height - _title.outerHeight()),
   'overflow-y': 'scroll',
   'padding-right': 10
});
}
```

## 另请参阅

+   第六章中的*创建新闻滚动条*示例，*用户界面*

# 从头开始编写图像裁剪插件

当允许用户上传自己的图像时，无论是用于个人资料图片还是其他用途，让他们能够在浏览器中裁剪图像为用户提供了巨大的好处。这是因为大多数用户不会知道如何使用诸如 Photoshop 之类的第三方应用程序来更改图像。Internet 上有许多免费的图像裁剪插件和许多教程可以帮助您使用它们，但几乎没有提供完整解决方案的示例。本篇将向您展示如何从零开始创建自己的图像裁剪插件，如何将图像上传到 Web 服务器，并如何从图像裁剪器获取数据以按照用户的规范调整并保存图像。

## 准备就绪

由于此示例包含客户端和服务器端代码，因此请确保您仔细遵循每个步骤。在开始此示例之前，请在 Web 服务器的 Web 根目录中设置以下目录结构：

![准备就绪](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_08_02.jpg)

根据上述结构，您需要在您的 Web 根目录（前图中的**www**）下创建`includes`和`uploads`文件夹。在`includes`文件夹中，保存 jQuery 库并创建以下四个文件：

+   `imagecrop.css`

+   `jquery.imagecrop.js`（像以前一样复制`jquery.plugin-template.js`文件以创建此插件的基础）

+   `recipe-5.css`

+   `recipe-5.js`

在 Web 根目录中，您需要创建 `index.html` 和 `upload.php` 文件。

### 注意

本示例将 *不会* 在 IE9 或更低版本中工作，因为较旧的浏览器不支持 `XMLHttpRequest`、`FormData` 和 `FileReader` API。

## 如何做…

仔细按照以下每个步骤，然后阅读 *工作原理…* 部分，以充分理解插件及其相关代码：

1.  将以下 HTML 代码添加到 `index.html` 中，以创建一个带有图像上传表单的 Web 页面：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
        <title>Chapter 8 :: Recipe 5 - Image Crop Plugin</title>
        <link href="includes/imagecrop.css" rel="stylesheet" type="text/css" />
        <link href="includes/recipe-5.css" rel="stylesheet" type="text/css" />
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.imagecrop.js"></script>
        <script src="img/recipe-5.js"></script>
    </head>
    <body>
        <div class="container">
            <h3>#1: Select Image</h3>
            <input type="file" id="selectedImage" />
            <h3>#2: Crop Image</h3>
            <div class="image-preview">
                <div class="preview-msg">Select and image to upload</div>
                <img id="croppable-image" style="display: none;" />
            </div>
            <h3>#3: Upload</h3>
            <div class="progress-bar"><div class="inner"></div></div>
            <div class="actions">
                <button class="upload-button">Upload</button>
            </div>
        </div>
    </body>
    </html>
    ```

1.  将以下 CSS 代码放入 `recipe-5.css` 中，为您刚刚创建的 HTML 页面和表单添加样式：

    ```js
    @import url(http://fonts.googleapis.com/css?family=Source+Sans+Pro:200,300,400);
    body {
        background-color: #F1F1F1;
        font-family: 'Source Sans Pro', sans-serif !important;
    }
    h1, h2, h3 {
        font-weight: 300;
        margin: 0;
    }
    .container {
        width: 800px;
        margin: 50px auto auto auto;
        background-color: #FFFFFF;
        padding: 20px;
        border: solid 1px #E1E1E1;
    }
    .container h3 {
        line-height: 40px;
    }
    .container .image-preview {
        border: solid 1px #E1E1E1;
        width: 800px;
        height: 600px;
        overflow: hidden;
        margin: auto;
        position: relative;
    }
    .container .image-preview .preview-msg {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #F1F1F1;
        text-align: center;
        font-size: 22px;
        line-height: 600px;
        font-weight: 300;
        z-index: 1;
    }
    #croppable-image {
        position: relative;
        z-index: 2;
    }
    .container .progress-bar {
        height: 30px;
        border: solid 1px #E1E1E1;
    }
    .container .progress-bar .inner {
        height: 30px;
        width: 0;
        background-color: #54ee86;
    }
    .container .actions {
        text-align: right;
        margin-top: 10px;
    }
    .container .actions .upload-button {
        height: 30px;
        width: 60px;
    }
    ```

1.  将以下 jQuery 代码添加到 `recipe-5.js` 中，该代码将允许用户从其本地文件系统中选择并预览图像，然后启动图像裁剪插件：

    ```js
    $(function(){
        var _selectedFile;
        $(document).on("change", "#selectedImage", function(){
            var reader = new FileReader();
            var files = $(this).prop("files");
            if (files.length > 0) {
                _selectedFile = files[0];
                reader.onload = function() {
                    var image = new Image;
                    image.src = this.result;
                    if (image.width > 800 || image.height > 600) {
                        alert("Image cannot be larger that 800x600");
                    } else {
                        $('.preview-msg').hide();
                        $('#croppable-image').prop("src", this.result).fadeIn().imagecrop();
                    }
                };
                reader.readAsDataURL(_selectedFile);
            }
        });
        $(document).on("click", ".upload-button", function(){
            var _selectedImage = $('#croppable-image');
            if (_selectedImage.data("selection-width") > 0 && _selectedImage.data("selection-height") > 0) {
                var data = new FormData();
                data.append("image", _selectedFile);
                data.append("selection-width", _selectedImage.data("selection-width"));
                data.append("selection-height", _selectedImage.data("selection-height"));
                data.append("selection-left", _selectedImage.data("selection-x"));
                data.append("selection-top", _selectedImage.data("selection-y"));
                var xhr = new XMLHttpRequest();
                xhr.open("POST", "/upload.php");
                xhr.onprogress = function(event) {
                    var percent = (event.loaded / event.total * 100);
                    $('.progress-bar .inner').width(percent + "%");
                }
                xhr.onload = function() {
                    var response = JSON.parse(this.response);
                    if (response.success == false) {
                        alert(response.error);
                    }
                }
                xhr.send(data);
            } else {
                alert("Please crop the image before upload");
            }
        });
    });
    ```

1.  在 `jquery.imagecrop.js` 中，按照以下代码片段的示例，更新插件名称和默认值：

    ```js
    var name = 'imagecrop';
        Plugin.prototype = {
            defaults: {
                minWidth: 100,
                minHeight: 100
       }
    };
    ```

1.  在由插件模板文件创建的插件构造函数中，在声明 `$scope.options` 之后直接添加以下声明，如下面的代码片段所示：

    ```js
    $scope.options = $.extend({}, this.defaults, options);
    $scope.imageSelection = {
       start: {
          x: 0,
          y: 0
       },
       end: {
          x: 0,
          y: 0
       },
       top: 0,
       left: 0
    };
    var _frame;
    var _overlayLayer;
    var _selectionLayer;
    var _selectionOutline;
    ```

1.  更新插件 `$scope.init()` 函数，包括以下代码：

    ```js
    //Has this element already been initialised?
    if (typeof $scope.$element.data("selection-x") != "undefined") {
       //Yes, so reuse the DOM elements...
       _frame = $(document).find('.crop-frame').css({
          width: $scope.$element.width(),
          height: $scope.$element.height()
       });
          _overlayLayer = $(document).find('.overlay-layer');
          _selectionLayer = $(document).find('.selection-layer');
          _selectionOutline = $(document).find('.selection-outline');
    } else {
       //No, let's initialise then...
       _frame = $("<div class='crop-frame'></div>").css({
          width: $scope.$element.width(),
          height: $scope.$element.height()
       });
       _overlayLayer = $("<div class='overlay-layer'></div>");
       _selectionLayer = $("<div class='selection-layer'></div>");
       _selectionOutline = $("<div class='selection-outline'></div>");
       //Wrap the image with the frame
       $scope.$element.wrap(_frame);
       _overlayLayer.insertAfter($scope.$element);
       _selectionLayer.insertAfter($scope.$element);
       _selectionOutline.insertAfter($scope.$element);
       /** EVENTS **/
       _selectionLayer.on("mousedown", $scope.onSelectionStart);
       _selectionLayer.on("mouseup", $scope.onSelectionEnd);
       _selectionOutline.on("mouseup", $scope.onSelectionEnd); 
       _selectionOutline.on("mousedown", $scope.onSelectionMove);
    }
    $scope.updateElementData();
    /** UPDATE THE OUTLINE BACKGROUND **/
    _selectionOutline.css({
       'background': 'url(' + $scope.$element.prop("src") + ')',
       'display': 'none'
    });
    ```

1.  在 `$scope.init()` 函数之后，添加以下额外的函数：

    ```js
    /**
    * MAKING THE SELECTION
    */
    $scope.onSelectionStart = function(event) {
       $scope.imageSelection.start = $scope.getMousePosition(event);
       _selectionLayer.bind({
         mousemove: function(event) {
       $scope.imageSelection.end = $scope.getMousePosition(event);
       $scope.drawSelection();
        }
      });
    };
    $scope.onSelectionEnd = function() {
       _selectionLayer.unbind("mousemove");
       //Hide the element if it doesn't not meet the minimum specified dimensions
       if (
          $scope.getSelectionDimentions().width < $scope.options.minWidth || $scope.getSelectionDimentions().height < $scope.options.minHeight
    ) {
          _selectionOutline.hide();
       }
       _selectionOutline.css({
          'z-index': 1001
       });
    };
    $scope.drawSelection = function() {
       _selectionOutline.show();
       //The smallest top value and the smallest left value are used to set the position of the element
       $scope.imageSelection.top = ($scope.imageSelection.end.y < $scope.imageSelection.start.y) ? $scope.imageSelection.end.y : $scope.imageSelection.start.y;
    $scope.imageSelection.left = ($scope.imageSelection.end.x < $scope.imageSelection.start.x) ? $scope.imageSelection.end.x : $scope.imageSelection.start.x;
    _selectionOutline.css({
       position: 'absolute',
       top: $scope.imageSelection.top,
       left: $scope.imageSelection.left,
       width: $scope.getSelectionDimentions().width,
       height: $scope.getSelectionDimentions().height,
       'background-position': '-' + $scope.imageSelection.left + 'px -' + $scope.imageSelection.top + 'px'
    });
    $scope.updateElementData();
    };
       /**
    * MOVING THE SELECTION
    */
    $scope.onSelectionMove = function() {
       //Prevent trigger the selection events
       _selectionOutline.addClass('dragging');
       _selectionOutline.on("mousemove mouseout", function(event){
          if ($(this).hasClass("dragging")) {
             var left = ($scope.getMousePosition(event).x - ($(this).width() / 2));
            //Don't allow the draggable element to over the parent's left and right
            if (left < 0) left = 0;
            if ((left + $(this).width()) > _selectionLayer.width()) left = (_selectionLayer.width() - $(this).outerWidth());
            var top = ($scope.getMousePosition(event).y - ($(this).height() / 2));
            //Don't allow the draggable element to go over the parent's top and bottom
            if (top < 0) top = 0;
            if ((top + $(this).height()) > _selectionLayer.height()) top = (_selectionLayer.height() - $(this).outerHeight());
            $scope.imageSelection.left = left;
            $scope.imageSelection.top = top;
            //Set new position
            $(this).css({
               top: $scope.imageSelection.top,
               left: $scope.imageSelection.left,
               'background-position': '-' + $scope.imageSelection.left + 'px -' + $scope.imageSelection.top + 'px'
            });
       }
       }).on("mouseup", function(){
       $(this).removeClass('dragging');                $scope.updateElementData();
       });
    }
    ```

1.  在您添加的函数下方插入以下辅助函数：

    ```js
    /**
    * HELPER FUNCTIONS
    */
    $scope.getMousePosition = function(event) {
       return {
          y: (event.pageY - _selectionLayer.offset().top),
          x: (event.pageX - _selectionLayer.offset().left)
       };
    };
    $scope.getSelectionDimentions = function() {
       //Work out the width and height based on the start and end positions
       var width = ($scope.imageSelection.end.x - $scope.imageSelection.start.x);
       var height = ($scope.imageSelection.end.y - $scope.imageSelection.start.y);
       //If any negatives turn them into positives
       if (height < 0) height = (height * -1);
       if (width < 0) width = (width * -1);
       return {
          width: width,
          height: height,
          x: $scope.imageSelection.start.x,
          y: $scope.imageSelection.start.y
       };
    }
    $scope.updateElementData = function() {
        $scope.$element.data({
          "selection-x": $scope.imageSelection.left,
          "selection-y": $scope.imageSelection.top,
          "selection-width": $scope.getSelectionDimentions().width,
          "selection-height": $scope.getSelectionDimentions().height
       });
    }
    ```

1.  将以下 CSS 代码添加到 `imagecrop.css` 中，为图像裁剪插件创建的元素添加样式：

    ```js
    .crop-frame {
        position: relative;
        margin: auto;
    }
    .selection-layer {
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 1000;
    }
    .selection-outline {
        border: dotted 1px #000000;
        z-index: 999;
    }
    .selection-outline:hover, .selection-outline:active {
        cursor: move;
    }
    .overlay-layer {
        background-color: rgba(255, 255, 255, 0.60);
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        z-index: 998;
    }
    ```

1.  最后，将以下 PHP 代码添加到 `upload.php` 中，该代码将从您刚刚创建的 Web 表单中获取数据，然后裁剪图像并将其保存到 `uploads` 目录中：

    ```js
    <?php
    if (isset($_FILES['image'])) {
        $response = array(
            "success" => false,
            "error" => ""
        );
        //GET SELECTION DATA
        $selectionWidth = (isset($_POST['selection-width'])) ? $_POST['selection-width'] : 0;
        $selectionHeight = (isset($_POST['selection-height'])) ? $_POST['selection-height'] : 0;
        $selectionTop = (isset($_POST['selection-top'])) ? $_POST['selection-top'] : 0;
        $selectionLeft = (isset($_POST['selection-left'])) ? $_POST['selection-left'] : 0;
        //GET IMAGE DATA
        $fileName = $_FILES['image']['name'];
        $ext = pathinfo($fileName, PATHINFO_EXTENSION);
        if ($selectionWidth > 800 || $selectionHeight > 600) {
            $response["error"] = "Image cannot be larger than 800 x 600";
        } else if (!in_array($ext, array("png", "jpg"))) {
            $response["error"] = "Invalid file type";
        } else {
    if ($ext == "png") {
    $source = imagecreatefrompng($_FILES['image']['tmp_name']);
            } else {
    $source = imagecreatefromjpeg($_FILES['image']['tmp_name']);
            }        $dest = imagecreatetruecolor($selectionWidth, $selectionHeight);
    imagecopyresampled($dest, $source, 0, 0, $selectionLeft, $selectionTop, $selectionWidth, $selectionHeight, $selectionWidth, $selectionHeight);
            $path = "/uploads/";
            if (!imagejpeg($dest, getcwd() . $path . $fileName, 100)) {
                $response["error"] = "Could not save uploaded file";
            } else {
                $response["success"] = true;
            }
        }
        header("Content-Type: application/json; charset=UTF-8");
        echo json_encode($response);
    }
    ```

1.  在您的 Web 浏览器中导航到 `index.html` 文件，您将看到一个包含三个步骤的简单 Web 表单。通过选择 **选择文件** 按钮并从计算机中选择图像，您将看到图像显示在预览框内。在预览框中，您可以点击并拖动一个选择区域到图像上。完成后，点击 **上传** 将图像上传到 Web 服务器（通过进度条指示），并且图像将被裁剪并保存到您之前创建的 `uploads` 文件夹中。

## 工作原理…

了解本示例的不同部分非常重要。本示例的第一个元素是上传表单本身，在上传之前，它提供了在浏览器中查看用户选择的图像的功能。本示例的第二个元素是图像裁剪插件本身，这是我们将重点关注的内容。最后，为了提供完整的解决方案，本示例的上传元素接收图像裁剪插件提供的数据，并将其发布到 PHP 脚本。然后，该 PHP 脚本将获取这些数据进行裁剪，并将图像保存到用户指定的位置。

### 图像选择和预览

`index.html` 中的 HTML 代码创建了一个带有文件输入元素的基本界面。当用户点击 **选择文件** 按钮时，将会打开浏览窗口，允许他们从计算机中选择文件。使用 JavaScript 的 `FileReader` 类，我们可以读取此文件并在浏览器中显示它。查看 `recipe-5.js`，您将看到一个包含执行此操作的代码的 `change` 事件处理程序。

在代码中的这一点上，有一个基本的验证检查，以确保所选图片不大于 800 x 600 像素。如果是，则向用户显示警报，并且图片不会加载。

图片加载完成后，`#cropableImage` 元素的 `source` 属性被更新为所选图片，将其显示在屏幕上。最后，在图片元素上初始化了图片裁剪插件，如下所示：

```js
$('#croppable-image').prop("src", this.result).fadeIn().imagecrop();
```

### 图片裁剪插件

图片裁剪插件动态创建了一系列元素，充当图层和容器，允许我们让用户进行选择。为了更容易理解每个图层的作用，它们在下图中进行了说明：

![图片裁剪插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-dev-cb/img/0896OS_08_03.jpg)

**遮罩** 层用白色背景和 0.6 的不透明度淡化了大部分图片。**选择** 层是监听鼠标事件的层，指示用户正在进行选择。这样做的主要原因是，如果将鼠标事件附加到图片本身，我们将在某些允许您将图片拖动到一个带有图片的可视化表示的浏览器中遇到困难，这会妨碍我们的功能。**选择轮廓** 层是插件在用户进行选择时绘制的内容。其背景是所选图片，除了位置被调整以仅显示已选择的图片部分，提供对遮罩遮挡的原始图片的聚焦。

插件初始化时，有一组局部变量和默认值声明，插件将在其运行过程中使用；这些显示在以下代码片段中：

```js
$scope.imageSelection = {
start: {
   x: 0,
   y: 0
},
end: {
   x: 0,
   y: 0
},
top: 0,
left: 0
};
var _frame;
var _overlayLayer;
var _selectionLayer;
var _selectionOutline;
```

以 `var` 开头的变量将存储代表图层的不同 DOM 元素。`imageSelection` 对象存储用户的初始点击坐标，然后是用户完成选择时的坐标。然后，我们可以使用这些坐标来计算选择的宽度和位置。`top` 和 `left` 参数存储了选择的最终坐标，一旦宽度和高度已经计算出来。

在插件的 `init()` 函数内部，有一个初始检查以确定图片是否已初始化。如果是，则图层 DOM 元素已经被创建并插入，如下所示：

```js
if (typeof $scope.$element.data("selection-x") != "undefined") {
   // -- HIDDEN CODE
} else {
   // -- HIDDEN CODE
}
```

如果 DOM 元素可用，则使用 jQuery 的`find()`函数选择元素并将它们存储在关联变量中。如果没有，则创建并存储。可能已为图像初始化插件的一种场景是用户决定更改所选图像。图像源发生变化，但 DOM 元素可以保持原位并以不同的尺寸重用。

当图层元素首次创建时，会创建一个容器分隔元素，其类名为`crop-frame`，尺寸与所选图像相同，如下面的代码片段所示：

```js
_frame = $("<div class='crop-frame'></div>").css({
    width: $scope.$element.width(),
    height: $scope.$element.height()
});
```

用户选择必须精确匹配实际图像像素尺寸，否则裁剪计算将不正确。然后，选定的图像元素将使用 jQuery 的`wrap()`函数包装在此框架内，如下所示：

```js
$scope.$element.wrap(_frame);
_overlayLayer.insertAfter($scope.$element);
_selectionLayer.insertAfter($scope.$element);
_selectionOutline.insertAfter($scope.$element); 
```

其他创建的图层插入到所选图像元素之后，位于`crop-frame`分隔元素内，如上面的代码所示。

图层创建的最后一部分附加了各种处理选择过程不同部分的事件处理程序函数：

```js
_selectionLayer.on("mousedown", $scope.onSelectionStart);
_selectionLayer.on("mouseup", $scope.onSelectionEnd);
_selectionOutline.on("mouseup", $scope.onSelectionEnd);
_selectionOutline.on("mousedown", $scope.onSelectionMove);
```

这里指定的每个函数稍后在`plugin`类中声明。在`init()`函数的末尾，调用`updateElementData()`函数，该函数设置所选图像元素上的初始选择尺寸（例如，`selection-x`）并在选择轮廓图层上设置背景图像。

当用户首次单击选择图层时，鼠标位置将被存储为起始坐标。然后，当用户拖动鼠标进行选择时，新的鼠标坐标被存储为结束坐标，并调用`drawSelection()`函数。`drawSelection()`函数使用起始和结束坐标来计算选择的宽度和高度，并更新选择轮廓图层的 CSS 以显示此内容，如下所示：

```js
$scope.drawSelection = function() {
   _selectionOutline.show();
   //The smallest top value and the smallest left value are used to set the position of the element
$scope.imageSelection.top = ($scope.imageSelection.end.y < $scope.imageSelection.start.y) ? $scope.imageSelection.end.y : $scope.imageSelection.start.y;
$scope.imageSelection.left = ($scope.imageSelection.end.x < $scope.imageSelection.start.x) ? $scope.imageSelection.end.x : $scope.imageSelection.start.x;
_selectionOutline.css({
   position: 'absolute',
   top: $scope.imageSelection.top,
   left: $scope.imageSelection.left,
   width: $scope.getSelectionDimentions().width,
   height: $scope.getSelectionDimentions().height,
   'background-position': '-' + $scope.imageSelection.left + 'px -' + $scope.imageSelection.top + 'px'
});
$scope.updateElementData();
};
```

作为此函数的一部分，选择轮廓图层的背景位置将被更新以显示实际选择，并调用`updateElementData()`函数以将新的选择数据应用于所选图像。

当用户完成选择并释放鼠标按钮时，将调用`onSelectionEnd()`函数。此函数确定选择是否小于允许的最小值；如果是，则隐藏选择。将鼠标移动事件从选择图层解绑，以避免与后续功能发生冲突，并更新选择轮廓图层的`z-index`属性，以便选择轮廓图层移动到选择图层上方，从而实现拖动功能。拖动功能在第六章*用户界面*中的*创建基本拖放功能*配方中进行了详细介绍。有关详细说明，请参阅该配方。

### 图像上传

在 `recipe-5.js` 中，为 **上传** 按钮的点击事件附加了事件处理程序。在此事件的回调函数内，首先确定用户是否已经进行了选择。如果没有，则显示警告，要求用户进行裁剪选择。

如果已经进行了有效的选择，将创建一个新的 `FormData` 对象来存储要上传到 PHP 脚本的数据，如下所示：

```js
var data = new FormData();
data.append("image", _selectedFile);
data.append("selection-width", _selectedImage.data("selection-width"));
data.append("selection-height", _selectedImage.data("selection-height"));
data.append("selection-left", _selectedImage.data("selection-x"));
data.append("selection-top", _selectedImage.data("selection-y"));
```

`_selectedFile` 变量包含对所选文件的引用，在文件输入的更改事件中可用。

将所需数据存储在 `FormData` 对象中后，创建一个新的 `XMLHttpRequest` 对象来将数据发送到 PHP 上传脚本，如下代码片段所示：

```js
var xhr = new XMLHttpRequest();
xhr.open("POST", "/upload.php");
xhr.onprogress = function(event) {
   var percent = (event.loaded / event.total * 100);
   $('.progress-bar .inner').width(percent + "%");
}
xhr.onload = function() {
   var response = JSON.parse(this.response);
   if (response.success == false) {
      alert(response.error);
}
}
xhr.send(data);
```

此代码不言自明，简单地允许我们直接从 JavaScript 中进行 POST，无需 HTML 表单。 `onprogress()` 函数由 XHR 请求调用，当图像正在上传时允许我们更新 HTML 页面上的进度条以反映上传进度。 `onload()` 函数在操作完成时调用，允许我们显示任何发生的错误。

### 使用 PHP 进行裁剪和保存图像

PHP 脚本相对简单。它接受并存储通过 JavaScript 提供的 POST 请求中的信息，并对图像宽度和扩展名进行基本验证，仅允许 JPG 和 PNG 图像。

如果图像通过了验证，则根据提供的图像使用 `imagecreatefrompng()` 或 `imagecreatefromjpeg()` 在 PHP 中创建图像资源。然后，如下所示的代码行创建了一个具有指定裁剪尺寸的空白图像：

```js
$dest = imagecreatetruecolor($selectionWidth, $selectionHeight);
```

你可以将这个空白图像看作是 PHP 将用来在上面绘制修改后图像的画布。然后，提供的图像被裁剪，并且使用 `imagecopyresampled()` 将新图像存储在空白画布上，如下所示：

```js
imagecopyresampled($dest, $source, 0, 0, $selectionLeft, $selectionTop, $selectionWidth, $selectionHeight, $selectionWidth, $selectionHeight);
```

最后，新图像将保存到在此配方开始时创建的 `uploads` 目录中，如下所示：

```js
imagejpeg($dest, getcwd() . $path . $fileName, 100)
```

当你打开 `uploads` 目录时，你应该能看到新图像。

## 还有更多...

本配方提供了一个基本的完整解决方案，用于预览、裁剪、上传和保存图像，但还有许多可以改进的地方。客户端和服务器端的验证都可以进行大幅改进，以允许其他图像类型，并检查文件大小以及尺寸。

当 `FileReader` 正在将本地文件读入浏览器时，可以像为上传部分实现进度条一样添加加载器或进度条。

最后，可以改进拖放功能，使选择区域的中心不会“捕捉”到鼠标指针，因为这可能会对用户造成困惑。

## 另请参阅

+   在 第六章 *用户界面* 的 *创建基本的拖放功能* 配方中
