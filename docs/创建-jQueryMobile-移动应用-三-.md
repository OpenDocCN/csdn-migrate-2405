# 创建 jQueryMobile 移动应用（三）

> 原文：[`zh.annas-archive.org/md5/E63D782D5AA7D46340B47E4B3AD55DAA`](https://zh.annas-archive.org/md5/E63D782D5AA7D46340B47E4B3AD55DAA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：把 jQuery Mobile 整合到现有网站中

我们并非都有幸只为新网站工作。也许客户不愿意为移动优先的站点付费，或者他们喜欢他们的桌面站点，只想要一个移动站点。你的移动实施可能是未来与客户业务的入口。我们需要准备一些技术手段将 jQuery Mobile 嵌入到他们现有的站点。

我们将涵盖的内容如下：

+   服务器端、客户端的移动检测，以及两者的结合

+   移动化全站页面 - 比较困难的方式

+   移动化全站页面 - 比较简单的方式

# 服务器端、客户端的移动检测，以及两者的结合

并非每个人都在做响应式设计，所以你很有可能需要知道如何检测移动设备。我们之前只是轻描淡写地谈到过这个话题，现在让我们认真对待它。

## 浏览器嗅探与特性检测

这个话题有潜力引发一场极客之战。一方面，有人赞美由社区维护的数据库在服务器端执行移动设备检测的优点。WURFL 就是一个典型的例子。使用它，我们可以获取访问我们网站的设备的大量信息。在这里列出所有内容只是浪费空间。可以去查看[`www.tera-wurfl.com/explore/index.php`](http://www.tera-wurfl.com/explore/index.php)来看它的运行情况，或者查看所有功能的完整列表在[`www.scientiamobile.com/wurflCapability/`](http://www.scientiamobile.com/wurflCapability/)。

在辩论的另一面，有人指出服务器端的检测（即使是数据库驱动的）可能导致全新的设备在数据库中没有被识别，直到它们进入数据库，站点管理员更新他们的本地副本。这并非完全正确。所有的安卓都是这样。同样的情况也发生在 iPhone、iPad、BlackBerry 和 Microsoft 上。但是，一个更具有未来前景的([`futurefriend.ly/`](http://futurefriend.ly/))方法是使用特性检测。例如，设备是否支持画布或触摸事件？几乎可以肯定，如果你支持这些技术和事件，你就有了使用 jQuery Mobile 的移动体验的条件。

无论如何，在这一点上，我们要假设我们正在为一家已经拥有网站且现在也想要一个移动站点的公司工作。因此，我们需要能够检测移动设备并将它们路由到正确的站点。

## WURFL – 服务器端数据库驱动的浏览器嗅探

WURFL 拥有 Java、PHP 和.NET 的 API。在[`wurfl.sourceforge.net/apis.php`](http://wurfl.sourceforge.net/apis.php)可以下载适合你的版本。由于几乎每个主机提供商都默认支持 PHP，我们将以 PHP 示例为例：

![WURFL – 服务器端数据库驱动的浏览器嗅探](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_08_00.jpg)

我只是使用了 Mac OS X 自带的服务器，但你也可以使用 MAMP ([`www.mamp.info/en/index.html`](http://www.mamp.info/en/index.html))。你可以轻松地在任何托管平台上运行示例，比如 1&1、GoDaddy、Host Gator，你随便选。如果你想在自己的 Windows 计算机上尝试这些示例，你可以使用 XAMPP ([`www.apachefriends.org/en/xampp.html`](http://www.apachefriends.org/en/xampp.html)) 或 WAMP ([`www.wampserver.com/en/`](http://www.wampserver.com/en/)) 作为快捷方式。我不打算在这本书中详细介绍服务器设置和环境配置。这可能需要一本专门的书来解释。

因此，PHP… 这就是我们要做的。从 [`wurfl.sourceforge.net/php_index.php`](http://wurfl.sourceforge.net/php_index.php) 开始。从那里，你可以下载最新版本的 **WURFL API package** 并解压缩它。把整个解压后的文件夹放在你的网站的任何位置。如果一切正常，你应该能够访问演示页面并查看有关你的浏览器和设备的详细信息。在我的 Mac 上，是 [`127.0.0.1/~sgliser/wurfl-php/examples/demo/index.php`](http://127.0.0.1/~sgliser/wurfl-php/examples/demo/index.php)，但你的路径可能会有所不同。

当你运行默认示例时，你可以立即看到它有多有用，但让我们让它变得更好一些。我创建的这个版本将最有用的功能放在顶部，并在下面列出所有其他选项：

```js
<?php 
  // Move the configuration and initialization to 
  // the tip so you can use it in the head.  

  // Include the configuration file 
  include_once './inc/wurfl_config_standard.php';  

  $wurflInfo = $wurflManager->getWURFLInfo();  

  if (isset($_GET['ua']) && trim($_GET['ua'])) { 
    $ua = $_GET['ua']; 
    $requestingDevice = $wurflManager->getDeviceForUserAgent($_GET['ua']); 
  } else { 
    $ua = $_SERVER['HTTP_USER_AGENT']; 

    //This line detects the visiting device by looking 
    //at its HTTP Request ($_SERVER) 

    $requestingDevice = $wurflManager->getDeviceForHttpRequest($_SERVER); } ?> 

<html> 
  <head> 
    <title>WURFL PHP API Example</title>     
    <?php if($requestingDevice->getCapability('mobile_browser') !== ""){ ?>     
      <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">         
      <link rel="stylesheet" href="http://code.jquery.com/mobile/1.2.0/jquery.mobile-1.2.0.min.css" />         
      <script src="img/jquery-1.8.2.min.js"></script>         
      <script src="img/jquery.mobile-1.2.0.min.js"></script> 
    <?php } ?> 
  </head> 
  <body> 
```

在这里，我们按照 jQuery Mobile 的方式创建了唯一的真实页面：

```js
  <div data-role="page">     
    <div data-role="header">     	
      <h1>WURFL XML INFO</h1>     
    </div> 
  <div data-role="content" id="content"> 

  <h4>VERSION: <?php echo $wurflInfo->version; ?> </h4> 
  <p>User Agent: <b> <?php echo htmlspecialchars($ua); ?> </b></p> 
  <ul data-role="listview">        
    <li data-role="list-divider">
      <h2>Very Useful</h2>
    </li> 
    <li>Brand Name: <?php echo $requestingDevice->getCapability('brand_name'); ?> </li> 
    <li>Model Name: <?php echo $requestingDevice->getCapability('model_name'); ?> </li> 
    <li>Is Wireless Device: <?php echo $requestingDevice->getCapability('is_wireless_device'); ?></li>             
    <li>Mobile: 
    <?php if($requestingDevice->getCapability('mobile_browser') !== ""){ 
       echo "true"; 
     }else{ 
       echo "false"; 
     }; ?>
    </li>             
    <li>Tablet: <?php echo $requestingDevice->getCapability('is_tablet'); ?> </li>             
    <li>Pointing Method: <?php echo $requestingDevice->getCapability('pointing_method'); ?> </li> 	
    <li>Resolution Width: <?php echo $requestingDevice->getCapability('resolution_width'); ?> </li> 
    <li>Resolution Height: <?php echo $requestingDevice->getCapability('resolution_height'); ?> </li> 
    <li>Marketing Name: <?php echo $requestingDevice->getCapability('marketing_name'); ?> </li> 
    <li>Preferred Markup: <?php echo $requestingDevice->getCapability('preferred_markup'); ?> </li> 
```

在这里，我们通过循环遍历属性数组来列出 WURFL 中已知数据的整个集合：

```js
    <li data-role="list-divider">
      <h2>All Capabilities</h2>
    </li>         

    <?php foreach(array_keys($requestingDevice->getAllCapabilities()) as $capabilityName){ ?> 
      <li><?php echo "<h3>" .$capabilityName."</h3><p>" .$requestingDevice->getCapability($capabilityName)."</p>"; ?>
      </li>         
    <?php } ?>         
    </ul> 

    <p><b>Query WURFL by providing the user agent:</b></p> 
    <form method="get" action="index.php"> 
      <div>User Agent: <input type="text" name="ua" size="100" value="<?php echo isset($_GET['ua'])? htmlspecialchars($_GET['ua']): ''; ?>" /> 
        <input type="submit" value="submit" />
      </div> 
    </form> 
  </div> 
</div> 
</body> 
</html>
```

### 注意

注意，我们通过使用服务器端检测来查看用户是否是移动用户，*有条件地*将其制作成了 jQuery Mobile 页面。只有在用户是移动用户时，我们才注入 jQM 库。

在 *非常有用* 部分下的属性可能是你在日常工作中真正需要的所有内容，但请务必至少浏览一下其他选项。最有用的功能如下：

+   `is_wireless_device`

+   `mobile_browser`

+   `is_tablet`

+   `pointing_method`

+   `resolution_width`

+   `resolution_height`

现在，需要说明的是，这并不能告诉我们有关浏览器/设备的所有信息。例如，iPhone 4S 或 5 将被识别为原始 iPhone。WURFL 也无法区分使用 WURFL 的 iPad mini。这是因为随着 Apple 设备的发展，用户代理从未更新。WURFL 无法知道设备具有高像素密度，因此应该发送更高分辨率的图像。因此，我们仍然需要使用媒体查询来确定像素比率，并相应地调整我们的图形。这里是一个简短的示例：

```js
.logo-large{
  background-image:url(../images/logo.png);
  background-repeat:no-repeat;
  background-position:0 0;
  position:relative;
  top:0;
  left:0;
  width:290px;
  height:65px; 
  margin:0 auto; 
  border:none;
}  

/* HD / Retina ---------------------------------------------*/ @media only screen and (-webkit-min-device-pixel-ratio: 1.5),
       only screen and (min--moz-device-pixel-ratio: 1.5),
       only screen and (min-resolution: 240dpi) 
{ 
  .logo-large{
    background-image:url(../images/logoHD.png);
    background-size:290px 65px;
  }  
}
```

### 注意

使用媒体查询几乎是检测 iPad mini 的唯一方法。它具有与 iPad 2 相同的分辨率，只是格式较小。但是，正如我们从前面的代码中可以看到的那样，我们可以使用 DPI 对媒体查询进行限定。iPad 2 的 DPI 为 132。iPad mini 的 DPI 为 163。更多信息，请访问 [`www.mobilexweb.com/blog/ipad-mini-detection-for-html5-user-agent`](http://www.mobilexweb.com/blog/ipad-mini-detection-for-html5-user-agent)。

到目前为止，我们几乎假定了智能手机，但请记住，jQuery Mobile 是一个同样适用于……不那么智能的手机的框架。您可能有客户在一个不那么发达并且几乎使用手机连接的市场。在那里可能没有那么多启用 JavaScript 的触摸屏手机。在这种情况下，您将无法使用基于 JavaScript 的功能检测。非常快地，WURFL 或其他服务器端检测将成为检测无线设备并为其提供有用内容的唯一合理选项。

## 基于 JavaScript 的浏览器嗅探

可以说，这可能是（学术上）检测移动设备的最糟糕的方法，但它确实有其优点。这个实用的例子非常有用，因为它给了您很多选择。也许我们的预算有限，因此我们只测试了某些设备。我们想确保我们只让我们知道会有良好体验的人进来。有一个例子：不会允许使用 BlackBerry 版本低于版本 6 的设备，因为我们选择使用了一些版本低于版本 5 的精美 JavaScript 模板。也许我们还没有花时间为平板电脑进行优化，但同时我们可以开始为任何智能手机提供更好的体验。无论如何，这可能会非常有用：

```js
<script type="text/javascript">     
  var agent = navigator.userAgent;      
  var isWebkit = (agent.indexOf("AppleWebKit") > 0);      
  var isIPad = (agent.indexOf("iPad") > 0);      
  var isIOS = (agent.indexOf("iPhone") > 0 || agent.indexOf("iPod") > 0);     
  var isAndroid = (agent.indexOf("Android")  > 0);     
  var isNewBlackBerry = (agent.indexOf("AppleWebKit") > 0 && agent.indexOf("BlackBerry") > 0);     
  var isWebOS = (agent.indexOf("webOS") > 0);      
  var isWindowsMobile = (agent.indexOf("IEMobile") > 0);     
  var isSmallScreen = (screen.width < 767 || (isAndroid && screen.width < 1000));     
  var isUnknownMobile = (isWebkit && isSmallScreen);     
  var isMobile = (isIOS || isAndroid || isNewBlackBerry || isWebOS || isWindowsMobile || isUnknownMobile);     
  var isTablet = (isIPad || (isMobile && !isSmallScreen));     
if ( isMobile && isSmallScreen && document.cookie.indexOf( "mobileFullSiteClicked=") < 0 ) mobileRedirect(); 
</script>
```

我们在这里做了一些工作，通过创建一个未知移动设备的分类，将其视为运行 WebKit 并具有小屏幕的任何设备，来未来证明检测的有效性。有可能，任何新推出的平台都将使用 WebKit 作为其浏览器。微软是唯一一个似乎仍然认为自己有更多东西可以提供的例外，他们的平台足够容易被嗅探到。尽管这种方法灵活，但如果没有一个 WebKit 浏览器启动一个新平台，就需要直接干预。但是，这种情况并不经常发生。即使发生了，该平台也需要一段时间才能获得值得考虑的关键性质量。如果您按照 80/20 法则（成功达到 80% 并在能够时达到剩下的 20%），那么这将使您的成功率远远超过 90%。

## 使用 Modernizr 进行基于 JavaScript 的功能检测

有几种方法可以进行功能检测。可能最简单的方法是使用像 Modernizr（[`modernizr.com/`](http://modernizr.com/)）这样的工具。您可以定制下载以仅检测您关心的功能。如果您想使用 HTML5 音频/视频，知道您是否可以可能很好：

![使用 Modernizr 进行基于 JavaScript 的特性检测](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_08_01.jpg)

这个平台并不是特别轻便。仅在前面的屏幕截图中显示的选项就导致了 12 K 压缩后的 JS。但是嘿，我们可以轻易地处理那样大小的图像。至少 JavaScript 库是有用的。这仍然不会告诉你访问你的用户是否是移动设备，但这是否是正确的问题？

或许，我们只需要知道我们正在查看的设备是否支持触摸事件。其他选项对于知道您可以和不能做什么是很好的，但是如果用户界面是触摸的，即使是平板电脑或全尺寸的触摸型显示器，也应该给用户他们应得的界面。给他们 jQuery Mobile。

## 基于 JavaScript 的精简特征检测

这个有用的小代码片段是为检测移动设备而凑合在一起的。它是特性检测和浏览器嗅探的混合体。大多数现代智能手机都将支持我们在这里寻找的所有事件和 API。微软，总是显得有些特殊，必须进行浏览器嗅探。根据他们的 Windows Phone 开发者博客，你可以简单地检查用户代理是否为 IEMobile。好吧，这是结果：

```js
if( 
  ('querySelector' in document 
  && 'localStorage' in window      
  && 'addEventListener' in window      
  && ('ontouchstart' in window || 
  window.DocumentTouch && document instanceof DocumentTouch)
  )      

  || navigator.userAgent.indexOf('IEMobile') > 0)
{                  
  location.replace('YOUR MOBILE SITE'); 
}
```

如果出于某种原因，我们决定不将平板发送到我们的 jQM 杰作，我们总是可以从上一节中加入一些其他测试。

## 服务器端加客户端检测

这是一个主意，当用户首次访问您的服务器时，发送一个页面，其唯一任务是运行 Modernizer，然后将结果能力返回给服务器，以便所有收集的知识都在一个地方。

这个文件在章节的代码文件包中名为 `test.html`：

```js
<!doctype html> 
<html> 
<head> 
  <style type="text/css"> 

    #sd{display:block;} /*standard def*/ 
    #hd{display:none;} /*high dev*/ 

    @media only screen and 
      (-webkit-min-device-pixel-ratio: 1.5),        
      only screen and (min--moz-device-pixel-ratio: 1.5),        
      only screen and (min-resolution: 240dpi) { 
        #sd{display:none;} /*standard def*/ 	
        #hd{display:block;} /*high dev*/    
      } 
  </style> 
  <script type="text/javascript" src="img/modernizr.custom.94279.js"></script> 
  <script type="text/javascript" src="img/jquery.min.js"></script> 
  <meta charset="UTF-8"> 
  <title>Loading</title> 
</head>  
<body> 
  <div id="hd"></div> 
  <div id="sd"></div> 
</body> 
<script type="text/javascript"> 
  if($("#hd").is(":visible")){ 
    $("html").addClass("hdpi"); 
  }else{ 
    $("html").addClass("sdpi"); 
  } 

  $.post("/~sgliser/wurfl-php/examples/demo/session_set.php", 
    { 
      modernizrData: $("html").attr("class") 
    } 
  ) 
  .success(function(data, textStatus, jqXHR) {  
    console.log(data); 
    location.replace("YOUR MOBILE SITE");  }) 
  .error(function(jqXHR, textStatus, errorThrown) {  
    console.log(errorThrown); 
    location.replace("SOMEWHERE ELSE");  
  }); 
</script> 
</html> 
```

为了使圆圈完整。这里是一些 WURFL 检测脚本的版本，它将返回 JSON 格式的值，以便我们可以将其存储到 HTML5 的 `sessionStorage` 中。此文件位于 `/wurfl-php/examples/demo/session_set.php`：

```js
<?php session_start();  

// Move the configuration and initialization 
// to the tip so you can use it in the head.  

// Include the configuration file 

include_once './inc/wurfl_config_standard.php';  

$wurflInfo = $wurflManager->getWURFLInfo();  

if (isset($_GET['ua']) && trim($_GET['ua'])) { 
  $ua = $_GET['ua']; 
  $requestingDevice = $wurflManager->getDeviceForUserAgent($_GET['ua']); 
} else { 
  $ua = $_SERVER['HTTP_USER_AGENT']; 

  // This line detects the visiting device by looking 
  // at its HTTP Request ($_SERVER) 

  $requestingDevice = $wurflManager->getDeviceForHttpRequest($_SERVER); 
}  

// store session data $_SESSION['wurflData']=$requestingDevice; 

$_SESSION['modernizrData']=$_POST['modernizrData'];  

$i = 0; 

$capabilities = $requestingDevice->getAllCapabilities(); 
$countCapabilities = count($capabilities); 
?> 
{ 
  "wurflData": <?php  

  //echo json_encode($capabilities); 
  foreach(array_keys($capabilities) as $capabilityName){  
    $capability = $requestingDevice->getCapability($capabilityName); 
    $isString = true; 	
    if($capability == "true" || 
       $capability == "false" || 
       is_numeric($capability))
    { 
      $isString = false; 
    } 

    echo "\"".$capabilityName
      ."\":".(($isString)?"\"":"")l
      .$requestingDevice->getCapability($capabilityName)
      .(($isString)?"\"":"");  

    if(($i + 1) < $countCapabilities){ 
      echo ",\n";  
    } 

    $i++; 
  }   
?> 
}
```

### 注

这个示例已经注释掉了 JSON 编码关联数组的简单方式。用一些 PHP 代码替换，将发送回使用真实布尔值和数值的 JSON 编码，而不是将所有内容都存储为字符串。

有了这些文件，你现在可以了解关于你的访问者在服务器端和客户端的一切都是可知的。

# 移动化全站页面 - 走弯路

为什么要走弯路？为什么？实际上只有一个很好的理由：为了将内容保持在同一页上，这样用户就不会有一个用于移动设备的页面和一个用于桌面的页面。当电子邮件和推特等信息飞来飞去时，用户通常不在乎他们是发送移动视图还是桌面视图，而且他们也不应该在乎。就他们而言，他们正在向某人发送内容。这是响应式设计的主要论点之一。但别担心，当我们也以简单的方式处理事情时，我们将在稍后考虑到这一点。

一般来说，很容易看出站点的哪些部分会转换为移动站点。几乎不管站点布局如何，您都会在现有标签上添加`data`属性来使其移动化。当页面上没有 jQuery Mobile 的库时，这些属性将保持原样，不会造成任何伤害。然后您可以使用我们的许多检测技术之一来决定何时添加 jQM 库。

## 了解您的角色

让我们考虑一些移动页面所需的关键`data-role`属性：

+   `data-role="page"`：这包含了移动视图中将显示的所有内容。

+   `data-role="header"`：这会将`h1`、`h2`、`h(x)`和多达两个链接包装成条形外观，并将链接转换为按钮。您可以将更多内容放入页眉中，但这是不建议的。如果您有很多内容尝试挤入页眉中，您可能最好只留一个“菜单”按钮。页眉可以固定其位置。页眉内的任何内容都将固定在顶部。

+   `data-role="content"`：这为你的内容提供了边距。

+   `data-role="button"`：这将链接转换为按钮。

+   `data-role="navbar"`：这在链接列表周围包装时创建一个导航栏。

+   `data-role="footer"`：这会在底部包装任何您想要的内容。这是次要链接、下一步导航、联系我们以及所有标志着所有有用性结束的法律内容的绝佳位置。这也可以设为固定位置。

+   `data-role="none"`：这将防止 jQuery Mobile 对内容进行样式处理。

从理想的用户体验角度来看，页面上的内容不应该超出用户完成他们访问该页面的任务所需的内容。*让我们为失去的梦想默哀一会…* 在此之前，请记住，任何`data-role="page"`中的内容都将显示在移动视图中。因此，在大多数全站页面上，您可以做的最好的事情就是确定用户实际上想要来到该页面的页面部分，然后使用`content`角色标记该部分，并立即用`page`角色包装起来。这样做，您将自动剔除大多数网页其余部分的琐事。

## 第 1 步中的第 1 步 – 关注内容，市场抗议！

此时，拥有市场营销背景的任何人可能会因为这种方法削减了他们的宣传和定向广告等而哭泣。然而，值得注意的是，人们已经有能力很长时间以来能够自己做这件事。诸如 Pocket（前身为 Read it Later）、Instapaper，甚至 iOS Safari 上的简单阅读工具等具有争议的服务都能向用户提供他们想要的内容。下面是一个普通桌面站点的例子，左边是 iOS Reader 如何去除除内容本身以外的一切。

![第 2 步中的第 1 步 – 关注内容，市场抗议！](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_08_02.jpg)

我们有一个选择；提供用户想要的格式和内容，或者可能会失去与他们联系的机会，因为他们会转向这些工具。这将需要在移动端进行更有创意的市场营销活动。但不要误解，除了页面核心以外的所有内容都应该是你的第一步。

在清除了页面的除主要内容以外的所有内容之后，我们还需要清除当前位于头部的样式和脚本。如果我们可以修改页面本身，我们可以轻松地在服务器端使用 WURFL 来实现这一点。否则，我们可以始终使用 JavaScript 来删除我们不想要的样式表和脚本，然后注入我们自己的样式表和脚本。我们还可以简单地劫持第一个样式表，然后删除其余的样式表，并以同样的方式处理脚本，首先引入 jQuery，然后是 jQuery Mobile。有一千种方式可以解决这个情况，但如果您打算以这种方式移动现有页面，我真的建议使用 WURFL。否则，事情会变得一团糟。

## 第 2 步/2 - 选择全局导航样式并插入

所以，在这一点上，我们已经有了页面的开头，但可能仍然有一些需要移除的小东西。拥有一个移动端样式表来处理那些少数需要覆盖的样式会非常有帮助，而且比使用 JavaScript DOM 操作更快。这很简单，下一个重要的问题是，我们应该如何处理全局导航，因为我们刚刚明确地排除了它。

### 全局导航作为单独的页面

这可能是最简单的方法，并尽可能保持界面的清洁（在以下步骤中提到）：

1.  将全局导航包装在自己独立的`page`和`content`角色中，并确保它们易于选择。

1.  在页面底部（或者在全局导航和内容完成后的任何位置）放置一个脚本，将全局导航所在的页面移动到内容下方。这一点特别重要，因为我们现在处于多页面视图中，而 DOM 中的第一个“页面”将在 jQuery Mobile 启动时显示给用户。我们希望在 jQuery Mobile 甚至知道自己应该做些什么之前就完成这个操作。如果我们不这样做，那么来到网站上期望阅读某些内容的用户首先会被全局导航所迎接。以下是基于我们之前看到的页面的一个非常简单的示例：

    ```js
    $("#NavMainC").insertAfter("#ContentW");
    ```

1.  在这些内部页面中添加标题，以便它们可以相互链接：

    ```js
    $("#ContentW").prepend("<div data-role='header'><h3>"+$("title").text()+"</h3><a href='#NavMainC' data-icon='grid' class='ui-btn-right'>Menu</a></div>") 

    $("#NavMainC").prepend("<div data-role='header'><a data-rel='back' data-icon='back' href='javascript://'>Back</a><h3>Menu</h3></a>");
    ```

    ![全局导航作为单独的页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_08_03.jpg)

### 底部的全局导航

在诸如文章之类的页面中，用户可能会一直阅读到底部，将菜单放在页面底部并不罕见。这是一种促进持续参与的方法。他们已经在那里了，对吧？也许你可以加上一两篇相关文章的链接，然后将全局菜单附加到页面底部。这样，用户就有了更多内容可供阅读，而不必滚动回页面顶部：

![底部的全局导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_08_04.jpg)

就我个人而言，我认为采取这种两方面的方法是最好的。顶部菜单链接到底部，底部菜单包括返回顶部的链接。这是通过`$.mobile.silentScroll`函数实现的。

### 全局导航作为面板

从 jQuery 1.3 开始，现在有一个`Panel`组件，可以直接嵌入到页面中，然后通过按钮单击来显示。它就像 Facebook 应用程序一样：

![全局导航作为面板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_08_06.jpg)

这可能是全局导航的最简单方法。它还有一个好处，即不会更改页面或使界面混乱。有关新面板小部件的完整 API 和选项，请查看 [`view.jquerymobile.com/1.3.0/docs/widgets/panels/`](http://view.jquerymobile.com/1.3.0/docs/widgets/panels/)。

## 困难的方式 - 最终想法

总的来说，将属性注入到完整网站页面中并调用 jQuery Mobile 的方法可能效果不错。你将遇到的最大问题是大多数页面上堆积的垃圾太多了。需要大量的清理和/或 CSS 处理。这也有一个不幸的副作用，那就是它相当脆弱。如果有人稍微修改了页面，可能会破坏你的实现。我只能在页面使用模板或**内容管理系统（CMS）**创建，以便网站结构的更改不会经常发生，并且发生更改时是统一的情况下，才会推荐这种方法。

# 移动化完整网站页面 - 简单方式

没有比创建一个独立的 jQuery Mobile 页面更容易和更清晰的了。让我们就这样做，简单地使用 AJAX 导入我们想要的页面。然后我们可以取出我们想要的部分，其余的部分就留下来。

这种方法的最大缺点主要是学术上的。渐进增强被抛弃了。对于设备上没有 JavaScript 的任何人来说，网站完全崩溃。我的观点是这可能并不重要。我不能代表每个地方，但在美国，如果你没有智能手机，你就不能用你的设备上网。就这么简单。当然也有例外只能证明规则。但是，如果你的市场不同，你可能要考虑这个选项是否适合你。因此，让我们继续。

在任何给定的页面上，我们实际上只需要一个简单的重定向，以便使用我们列出的众多方法之一的移动设备上的任何人。然后，只需使用一个简单的`location.replace`。这个代码示例比这个更多。它检查用户是否在移动设备上并单击了完整网站链接。如果是这样，我们将插入一个`iframe`标签，以允许用户手动切换回移动视图。否则，我们将只是将他们弹回到移动视图。

```js
if (isMobile && isSmallScreen){  
  if(document.cookie.indexOf("mobileFullSiteClicked=")<0){ 
    location.replace("mobileadapter.php?p="
      +escape(location.pathname));
  }else{ 
    document.addEventListener("DOMContentLoaded", function(){ 
      try{ 
        var iframe = document.createElement("iframe");
        iframe.setAttribute("src","gomo.html"); 
        iframe.setAttribute("width","100%"); 
        iframe.setAttribute("height","80");  
        document.body.insertBefore(
          iframe,
          document.body.firstChild); 
      }catch(e){alert(e);} 
    }, false); 
  } 
}
```

这是一个允许完整网站链接到移动端的页面的代码。此文件是章节代码文件中的`gomo.html`：

```js
<!doctype html> 
<html> 
<head> 
  <meta charset="UTF-8"> 
  <style type="text/css"> 
    body{ background-color:#000;} 
    p{
      font-size:60px; 
      font-family:Arial, Helvetica, sans-serif; 
      text-align:center;
    } 	
    a{color:white;}  
  </style> 
</head>  
<body> 
<script type="text/javascript"> 
  document.write("<p><a href='mobileadapter.php?p="
    +escape(window.parent.location.pathname)
    +"' target='_top'>Switch to mobile view</a>"
    +"<img src='32-iphone@2x.png'/></p>");     
</script> 
</body> 
</html> 
```

这两个页面都使用了不需要 jQuery 的脚本。如果每个页面都有 jQuery 就好了，但是市场上有其他竞争平台，我们不能指望我们要移动的基本页面已经为我们准备好了。原生 JavaScript 更快。我们可以直接将其放在页面顶部，而无需先引入库。

![移动全站页面-简便方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_08_05.jpg)

这是包含移动内容的 jQuery Mobile 页面。它也链接回全站视图并设置一个 cookie，这样用户点击全站链接时就不会直接被弹回移动页面。

如前所述，我们正在拉取下一个前 3 篇文章，并将它们放在菜单底部之前，以保持用户的参与度。在这个视图中做起来要容易得多。

该示例还利用了`replaceState`。对于所有支持它的浏览器，当用户来到移动页面时，地址栏和历史记录中的 URL 都将被更新，以显示原始文章的 URL。

现在，不再拖延，我们将看到如何轻松地移动全站页面的最佳示例。它足够通用，你可能只需将其应用到你正在工作的任何项目中，并只需调整做拉取和注入的代码即可：

```js
<!DOCTYPE html>  
<html>  
<head> 
  <meta charset="utf-8"> 	
  <meta name="viewport" content="width=device-width, initial-scale=1">  
  <title class="pageTitle">Loading...</title>  
  <link rel="stylesheet" href="http://code.jquery.com/mobile/1.3.0/jquery.mobile-1.3.0.min.css" /> 
  <script src="img/jquery-1.8.2.min.js"></script> 
  <script src="img/jquery.mobile-1.3.0.min.js"></script>     
  <!-- cookie code from https://github.com/carhartl/jquery-cookie -->
  <script src="img/jquery.cookie.js"></script>
  <style type="text/css"> 
    #iscfz,.comment-bubble{display:none;} 
    #bottomMenu .byline
    {
      padding:0 0 8px 12px; 
      font-weight:normal;
    } 	
  </style> 
</head>   
<body>   
<div id="mainPage" data-role="page">
```

这一部分是 jQuery Mobile 1.3 中可用的新面板。它将接收全局菜单：

```js
      <div data-role="panel" id="globalmenu" data-position="left" data-display="reveal" data-theme="a">     
      <ul data-role="listview"></ul>         
      <!-- panel content goes here -->     
   </div><!-- /panel --> 

  <div data-role="header"> 		
    <a href="#globalmenu" data-icon="bars">Menu</a>
    <h1 class="pageTitle">Loading...</h1>         

  </div><!-- /header -->  
  <div id="mainContent" data-role="content">	          
  </div><!-- /content -->     
  <div>     
    <ul id="bottomMenu" data-role="listview"></ul>     
  </div> 	
  <div data-role="footer"> 
    <h4>
      <a class="fullSiteLink" data-role="button" data-inline="true" href="<?php echo htmlspecialchars(strip_tags($_REQUEST["p"])) ?>" target="fullsite">Full Site View</a>
    </h4> 
  </div><!-- /footer --> 	 
</div><!-- /page -->  

<script type="text/javascript"> 	

  $.cookie("mobileFullSiteClicked","true", {
    path:"/",expires:0}
  );  //0 minutes - erase cookie 
```

我们在这里为了替换用户历史记录中的状态而采取的措施，并不是所有移动浏览器都完全支持。为了安全起见，我已经将那行代码放在了 try/catch 块中。对于那些在你的客户群体中部分支持的东西，这是一个不错的技巧。

```js
  try{ 
    //make the URL the original URL so if the user shares 
    //it with others, they'll be sent to the appropriate URL 
    //and that will govern if they should be shown 
    //mobile view. 
    history.replaceState({},"","<?php echo htmlspecialchars(strip_tags($_REQUEST["p"])) ?>"); 
  }catch(e){ 
    //history state manipulation is not supported 
  }  

  //Global variable for the storage of the imported 
  //page content. Never know when we might need it 
  var $pageContent = null; 

  //Go get the content we're supposed to show here 
  function loadPageContent(){ 

    $.ajax({ 
       //strip_tags and htmlspecialchars are to to help 
       //prevent cross-site scripting attacks 
       url:"<?php echo htmlspecialchars(strip_tags($_REQUEST["p"])) ?>",
       beforeSend: function() { 
         //show the page loading spinner 
         $.mobile.loading( 'show' );
       }
     }) 
    .done(function(data, textStatus, jqXHR){ 

        //jQuery the returned page and thrown it into 
        //the global variable 
        $pageContent = $(data); 

        //take the pieces we want and construct the view  
        renderPage(); 	
     }) 
    .fail(function(jqXHR, textStatus, errorThrown){ 

        //let the user know that something went wrong 
        $("mainContent").html("<p class='ui-bar-e'>Aw snap! Something went wrong:<br/><pre>"+errorThrown+"</pre></p>"); 
      })
     .always(function(){ 
        //Set a timeout to hide the image, in production 
        //it was being told to hide before it had even been shown 	
        //resulting a loading gif never hiding   
        setTimeout(function(){$.mobile.loading( "hide" )}, 300); 
     });; 
  } 
```

这一部分负责拆分导入的页面并将其注入到正确的位置。请注意，我在开始处选择对象并在名称前加上美元符号。我们为了性能而预先选择它们。任何你要引用超过一次的东西都应该存储到一个变量中，以减少 DOM 遍历来重新选择它。美元符号的原因是它提示编码人员，他们看到的变量已经被 jQuery 处理过了：

```js
  function renderPage(){ 
    var $importedPageMainContent = $pageContent.find("#main"); 
    var $thisPageMainContent = $("#mainContent"); 

    //pull the title and inject it. 
    var title = $importedPageMainContent.find("h1.title").text(); 	

    $(".pageTitle").text(title); 

    //set the content for the main page starting 
    //with the logo then appending the headline, 
    //byline, and main content 
    var $logo = $pageContent.find("#logo-headerC img"); 

    $thisPageMainContent.html($logo);  
    $thisPageMainContent.append(
      $importedPageMainContent.find("h1.title")
    ); 
    $thisPageMainContent.append(
      $importedPageMainContent.find("div.byline")
    ); 
    $thisPageMainContent.append(
      $importedPageMainContent.find("div.the-content")
    ); 

    var $bottomMenu = $("#bottomMenu"); 

    //Take the next 3 top stories and place them in the 
    //bottom menu to give the user something to move on to.   
$bottomMenu.html("<li data-role='list-divider'>Read On...</li>"); 	
    $bottomMenu.append(
       $pageContent.find("#alldiaries li:lt(3)")
    );  

    //Inject the main menu items into the bottom menu 

    $bottomMenu.append("<li data-role='list-divider'>Menu</li>"); 	

    var $mainMenuContent = $pageContent.find("#NavMain");  
    $bottomMenu.append($mainMenuContent.html()); 

    //After doing all this injection, refresh the listview 
    $bottomMenu.listview("refresh"); 

    //inject the main menu content into main menu page 
    var $mainMenContent = $("#mainMenuContent"); 
    $mainMenContent.find("ul").append(
      $mainMenuContent.html()
    ); 
  } 

  //once the page is initialized, go get the content. 
  $("[data-role='page']").live("pageinit", loadPageContent); 
  //if the user clicks the full site link, coolie them 
  //so they don't just bounce back.
  $("a.fullSiteLink").live("click", function(){ 
    $.cookie("mobileFullSiteClicked","true", 
      {path:"/",expires:30});  //30 minutes 
  }); 

</script> 
</body> 
</html>
```

### 注意

此处使用的 cookie 管理来自于 jQuery cookie 插件，网址为[`github.com/carhartl/jquery-cookie`](https://github.com/carhartl/jquery-cookie)。

# 摘要

本书前面我们深入探讨了移动检测。现在你知道了所有需要知道的内容。之前，我们从零开始创建移动站点，很少关心它们的桌面体验。现在你知道如何统一它们了。困难的部分是要知道何时从零开始设计移动体验，何时简单地将整个站点体验移动化。可惜这并没有简单的答案。但是，无论是通过在页面上使用 JavaScript 将其转换为移动端（较为困难的方式），还是通过 AJAX 加载内容并选择所需的部分（较为简单的方式），或者是通过响应式设计 + 服务器端组件（RESS），正如我们在前一章中提到的那样，现在你已经准备好处理几乎每种可能的情况了。我们还没有真正解决的唯一问题是与 CMS 集成，这将在下一章中完成。


# 第九章：内容管理系统和 jQM

> “我是一个网页开发者。每次客户想要更改时，将微软 Word 文档剪切粘贴到网页上是对我的时间和才能的浪费” —— 到处都能听到，无数次。

如果这个说法在你心中有共鸣，那么你需要熟悉内容管理系统（CMS）。它们是将发布权交到用户手中的一种简单而强大的方式，这样你就可以专注于不那么繁琐、报酬更高的工作。你需要做的就是帮助客户设置他们的 CMS，选择并定制他们的模板，然后把内容创建和维护交给他们。CMS 通常是小型企业网站和企业网站的核心。

对于流行的平台，有*许多*插件和主题可供选择。宣传册网站从未如此简单。事实上，像 WordPress 和 Squarespace 这样的平台正在使这个过程变得如此简单，以至于通常一个网页开发者只需要定制外观和感觉，其他什么都不需要做。

那么，为什么还要包括这一章？因为 CMS 的普及几乎总是意味着，如果你要制作移动 Web 应用，迟早会遇到一个已经在 CMS 中拥有网站的客户，你需要知道如何集成。

在本章中，我们将涵盖：

+   当前的 CMS 格局

+   WordPress 和 jQuery Mobile

+   Drupal 和 jQuery Mobile

+   更新你的 WordPress 和 Drupal 主题

+   Adobe Experience Manager (AEM)

# 当前的 CMS 格局

WordPress 是世界上最受欢迎的 CMS，按数量计算。对于前 10,000 个网站，有 8.3％是建立在 WordPress 上的。下一个最高的是 Drupal，占 2.95％。尽管听起来似乎不多，但看看这个图表：[`trends.builtwith.com/cms`](http://trends.builtwith.com/cms)。在所有使用 CMS 的网站中，WordPress 和 Drupal 占了近 75％。

![当前的 CMS 格局](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_00.jpg)

# WordPress 和 jQuery Mobile

WordPress 之所以受欢迎，是因为它简单易用。你可以通过在[WordPress.com](http://WordPress.com)上创建托管站点开始使用 WordPress，或者你可以通过访问[WordPress.org](http://WordPress.org)下载源代码，并在任何你喜欢的机器上安装。在你进行实验时，我强烈建议采用后一种方法。本章使用的版本是 3.5。

要快速上手任何 CMS 的关键是，认识到要使用哪些插件和主题。对于 WordPress，我不建议使用 jQuery Mobile 插件。当我为本章做实验时，它破坏了管理界面，并且总体上是一次痛苦的经历。然而，有几个 jQuery Mobile 主题可以很好地为你服务。有些是免费的，有些是付费的。无论哪种方式，尽量不要重复造轮子。选择一个最接近你想要的主题，然后进行微调。到目前为止，很可能你已经足够好，可以修改现有的主题文件。以下是我找到并喜欢的一些主题链接。选择一个，解压缩它，并将其放入你的 WordPress 安装目录下的 `wp-content/themes/` 中：

+   [`www.mobilizetoday.com/freebies/jqmobile`](http://www.mobilizetoday.com/freebies/jqmobile)

+   [`themeforest.net/item/mobilize-jquery-mobile-wordpress-theme/3303257`](http://themeforest.net/item/mobilize-jquery-mobile-wordpress-theme/3303257)

+   [`goldenapplesdesign.com/projects/jquery-mobile-boilerplate-for-wordpress-themes/`](http://goldenapplesdesign.com/projects/jquery-mobile-boilerplate-for-wordpress-themes/)(我的个人最爱)

    ### 注意

    **Mac 提示**

    打开控制台，导航到包含已解压目录的文件夹，并运行以下命令。如果不这样做，你的东西可能不会显示或按预期工作。

    ```js
    xattr -dr com.apple.quarantine *
    ```

    ![WordPress 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_06.jpg)

如果你成功安装了主题，你应该能在管理界面的 **外观** | **主题** 下看到它，如下一张图左侧所示。它应该在 **可用主题** 下列出：

![WordPress 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_07.jpg)

接下来，我们需要一种方式来在移动设备上访问主题。这就是移动主题切换器发挥作用的地方。我们将在这里使用的切换器简单而有效，适用于大多数可能访问你的站点的人。

## 手动安装移动主题切换器

要手动安装移动主题，请从 [`wordpress.org/extend/plugins/mobile-theme-switcher/`](http://wordpress.org/extend/plugins/mobile-theme-switcher/) 下载它。解压文件夹并将其放入你的 WordPress 安装目录下的 `wp-content/plugins/` 中：

![手动安装移动主题切换器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_08.jpg)

接下来，通过管理界面，激活名为 **Mobile theme switch** 的插件：

![手动安装移动主题切换器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_09.jpg)

## 自动安装移动主题切换器

如果你喜欢的话，你可以让 WordPress 为你完成大部分工作。就我个人而言，我喜欢掌控一切。以下是通过管理界面安装的方法：

1.  转到 **插件** 页面，然后在标题旁边找到 **添加新** 按钮，如下一张截图所示：![自动安装移动主题切换器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_10.jpg)

1.  在下一个屏幕上，搜索**移动主题切换器**：![自动安装移动主题切换器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_11.jpg)

1.  有很多选择可供选择，我们使用的是第一个：![自动安装移动主题切换器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_12.jpg)

1.  在下一页上输入你的 FTP 凭据。

1.  激活你新安装的插件。

## 配置移动主题切换器

如果你已经成功安装并激活了插件，它现在将显示在**外观**菜单下，如下面的屏幕截图所示。然后，选择你安装的移动主题，点击**更新选项**按钮：

![配置移动主题切换器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_14.jpg)

插件和主题的组合是强大、简单且有效的。以下是新主题运行的屏幕截图：

![配置移动主题切换器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_03.jpg)

相当简单，对吧？现在，我们只需要调整它直到客户满意。让我们继续下一个 CMS 系统。

### Drupal 和 jQuery Mobile

Drupal 是一个功能更强大的 CMS。使用其中一些标准插件，你可以轻松创建完整的网络应用程序，而不仅仅是宣传册网站。想要在发布评论前让人们证明他们是人类吗？有一个插件可以做到。想要创建联系表单吗？它是内置的。想要创建一个自定义数据库表和表单来保存输入吗？从 Drupal 7 开始，这也是内置的。

Drupal 最大的缺点是，如果你想要发挥它真正的威力，它有点学习曲线。此外，在没有进行一些调整的情况下，它可能会有点慢，并且可能会让你的页面代码变得臃肿。像缓存这样的技术可以提高性能，但也可能会对动态创建的页面产生负面影响。

为 jQuery Mobile 配置 Drupal 的过程与 WordPress 的几乎相同。同样，我们将从已经存在的主题开始。制作这些主题的人知道他们正在编码的系统。不要试图重新发明轮子。我们所要做的就是使用这个主题并进行微调。我最喜欢的 Drupal jQM 主题可以在[`drupal.org/project/mobile_jquery`](http://drupal.org/project/mobile_jquery)找到。在该页面的底部，你将找到主题的可下载分发：

![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_15.jpg)

1.  复制适合你的分发的链接。

1.  登录到你的 Drupal 网站的管理控制台，并转到**外观**部分：![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_16.jpg)

1.  点击**安装新主题**链接，并将你复制的链接粘贴到**从 URL 安装**字段中。点击**安装**按钮，让安装完成所有步骤。![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_17.jpg)

1.  在这一点上，您可能无法看到已安装的主题。制作者鼓励您创建子主题，而不是使用他们的基础安装主题。这是我们将要忽略的一个建议。所以，为了使主题显示出来，您需要编辑位于 Drupal 安装目录中`sites/all/themes/jquery_mobile/`中的文件`mobile_jquery.info`，并将`hidden`的值从`1`更改为`0`。一旦你这样做了，你应该会在**外观**菜单的禁用主题部分看到主题列表，如下一个屏幕截图所示。单击**启用**链接，您的主题将准备好配置和使用。![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_18.jpg)

1.  接下来，我们需要安装主题切换插件。让我们使用位于[`drupal.org/project/mobile_theme`](http://drupal.org/project/mobile_theme)的插件。同样，选择正确的版本并复制其网址。![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_19.jpg)

1.  打开管理员界面到**模块**部分，然后单击**安装新模块**链接：![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_20.jpg)

1.  将网址粘贴到标记为**从 URL 安装**的字段中，然后单击**安装**按钮。让安装过程自动进行。![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_21.jpg)

1.  在**模块**部分的底部，您将找到新安装的插件：![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_22.jpg)

1.  单击复选框以启用模块，然后您将能够配置它：![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_23.jpg)

1.  点击**配置**链接将带您到一个用于配置**全局设置**的屏幕。在该屏幕的右侧，您会找到一个用于配置移动主题选项的部分。**移动主题**部分在下面的屏幕截图中已经用红色箭头标记出来了：![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_24.jpg)

结果不言而喻。该主题肯定需要定制，但对于初学者来说，它完全可以使用。我们知道如何做其余的事情了。

![Drupal 和 jQuery Mobile](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_05.jpg)

# 更新您的 WordPress 和 Drupal 模板

在某些时候（可能是安装后的右后），您会想要更新这些主题以使用最新版本的 jQuery Mobile 库。一些仍在使用 beta 版本。实际上，这个过程非常简单。你只需找到相关模板的头部部分，并更新对 jQuery Mobile CSS、JS 和可能的核心 jQuery 库的引用。

## WordPress – Golden Apples jQM 主题

对于 Golden Apples 的 WordPress 主题（参见 [`github.com/goldenapples/jqm-boilerplate`](https://github.com/goldenapples/jqm-boilerplate)），您需要更改多个文件。在`header.php`文件中，找到并更新以下行：

```js
<link rel="stylesheet" href="http://code.jquery.com/mobile/1.0b1/jquery.mobile-1.0b1.min.css" />
```

在`functions.php`文件中，你需要找到并更新以下行：

```js
wp_enqueue_script( 'jquery',"http://code.jquery.com/jquery-1.6.4.min.js" );

wp_enqueue_script( 'jquery-mobile',"http://code.jquery.com/mobile/1.0.1/jquery.mobile-1.0.1.min.js",array( 'jquery' ) );

wp_enqueue_script( 'mobile-scripts',get_stylesheet_directory_uri().'/lib/mobile-scripts.js', array( 'jquery', 'jquery-mobile' ) );

wp_localize_script( 'mobile-scripts', 'siteData', array( 'siteUrl', home_url() ) );

wp_enqueue_style( 'jquery-mobile', "http://code.jquery.com/mobile/1.0.1/jquery.mobile-1.0.1.min.css" );
```

## Drupal – jQuery Mobile 主题

对于[Drupal jQuery Mobile 主题](http://drupal.org/project/mobile_jquery)，你最快更新主题的方法是编辑`theme`文件夹根目录下的`template.php`文件。在文件中找到以下行并更新对 jQuery Mobile 的引用：

```js
drupal_add_css('http://code.jquery.com/mobile/1.0.1/jquery.mobile.structure-1.0.1.min.css', array_merge($css_options,array('weight' => 100)));
drupal_add_css('http://code.jquery.com/mobile/1.0.1/jquery.mobile-1.0.1.min.css', array_merge($css_options, array('weight' => 100)));

drupal_add_js('http://code.jquery.com/jquery-1.6.4.min.js', array_merge($js_options, array('weight' => 100)));

drupal_add_js(drupal_get_path('theme', 'mobile_jquery') . '/scripts/mobile_jquery.js', array_merge($js_options, array('weight' => 101)));

drupal_add_js('http://code.jquery.com/mobile/1.0.1/jquery.mobile-1.0.1.min.js', array_merge($js_options, array('weight' => 101)));
```

# Adobe Experience Manager

Adobe 一直是网络领域的领导者。他们的首席企业 CMS 名为 Adobe Experience Manager (AEM)（参见[`www.adobe.com/solutions/web-experience-management.html`](http://www.adobe.com/solutions/web-experience-management.html)）。我不会介绍如何安装、配置或为 AEM 编写代码。这是几本本书那么大的培训手册的主题。相信我。我只是提到这一点，以便你知道至少有一个主要的 CMS 玩家提供了完整的 jQuery Mobile 示例。

培训材料以名为 Geometrixx 的虚构站点为中心。

![Adobe Experience Manager](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_25.jpg)

AEM 系统的美妙之处在于它使用 Java JCR 容器（参见[`en.wikipedia.org/wiki/Content_repository_API_for_Java`](http://en.wikipedia.org/wiki/Content_repository_API_for_Java)）来存储内容。这意味着你可以创建自动从桌面页面中提取内容的移动站点，只需引用桌面页面的 JCR 内容节点或允许用户直接在看起来像移动屏幕的界面中输入。

Geometrixx 的移动示例使用了 jQuery Mobile 编写；尽管 jQM 的版本有些过时，但更改模板很容易。移动内容作者界面带有模拟手机界面，以便对内容进行框架化，使其看起来大致像在真实手机或平板电脑上。你可以在作者界面中直接切换设备配置文件。虽然这并不是对这些设备的真正模拟，因为一切都发生在你正在使用的浏览器中，但它仍然非常非常方便。

![Adobe Experience Manager](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_09_26.jpg)

如果你为一家能负担得起 AEM 的公司工作，你已经非常熟悉移动实现。这个平台给内容作者带来的力量是惊人的。

# 概要

自从两年前我开始涉足移动开发以来，移动主题的世界已经爆炸式增长。今天，有很多 jQuery Mobile 的选择；还有一些其他响应式主题。我没费力去列出 Google 能给我们的所有东西。当这本书出版时，即使在一个月的时间里，这些也会发生变化。要记住的重要一点是，我们不必重新发明轮子，也不必让自己背负内容更新。让你的客户有能力自行进行小型更新，而你回到你的事务中去。CMS 虽然有用，但我们不会再次涉及它。下一章将回到定制开发，我们将结合到目前为止学到的一切。


# 第十章：将一切汇聚在一起 - Flood.FM

Flood.FM 是一个独特的想法。这是一个网站，听众将受到来自几个流派和地理区域的本地独立乐队的音乐的欢迎。构建这个网站将需要我们迄今为止开发的许多技能，并且我们将在这项新服务中使用一些新的技术。我们已经在便签上绘制了界面，并使用了 GPS 和客户端模板。我们已经处理了常规的 HTML5 音频和视频。我们甚至已经开始处理多个移动尺寸，并使用媒体查询将我们的布局重新设计为响应式设计。

所有这些都是为了完成任务并尽可能优雅地失败而简化的实现。让我们看看我们可以在这个项目上使用什么技术和技巧。

在本章中，我们将涵盖：

+   一份 Balsamiq 的味道

+   组织你的代码

+   Web Audio API 简介

+   引导用户安装你的应用程序

+   新的设备级硬件访问

+   要做应用还是不要做应用，这是个问题

+   PhoneGap 与 Apache Cordova

# 一份 Balsamiq 的味道

我们通过学习一种称为纸质原型的技术来开始这本书。对于与客户一起工作，这是一个很好的工具。然而，如果你正在处理更大或分布式的团队，你可能需要更多。Balsamiq ([`www.balsamiq.com/`](http://www.balsamiq.com/)) 是一个非常流行的用于快速原型设计的 UX 工具。它非常适合创建和共享交互式的模型。

![一份 Balsamiq 的味道](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_01.jpg)

当我说非常流行时，我是指你习惯看到的许多大公司。超过 80,000 家公司都在使用 Balsamiq Mockups 来创建他们的软件。

![一份 Balsamiq 的味道](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_02.jpg)

所以，让我们看看 Flood.FM 的创建者们打算做什么。这是他们绘制的第一个屏幕；到目前为止，它看起来像是一个非常标准的实现。它在底部有一个图标工具栏，在内容中有一个列表视图。实际上，将其翻译成中文非常简单。我们以前使用 Glyphish 图标和标准工具栏做过这样的事情。

![一份 Balsamiq 的味道](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_04.jpg)

理想情况下，我们希望保持这个特定实现纯粹的 HTML/JS/CSS。这样，我们可以在某个时候使用 PhoneGap 将其编译为本机应用程序。但是，我们希望忠于 DRY（不要重复自己）原则。这意味着我们想要在每个页面上注入这个页脚，而不使用服务器端过程。为此，让我们设置一个应用程序的隐藏部分，其中包含我们可能想要的所有全局元素：

```js
<div id="globalComponents">
  <div data-role="navbar" class="bottomNavBar">
    <ul>
      <li><a class="glyphishIcon" data-icon="notes" href="#stations_by_region" data-transition="slideup">stations</a></li>
      <li><a class="glyphishIcon" data-icon="magnify" href="#search_by_artist" data-transition="slideup">discover</a></li>
      <li><a class="glyphishIcon" data-icon="calendar" href="#events_by_location" data-transition="slideup">events</a></li>
      <li><a class="glyphishIcon" data-icon="gears" href="#settings" data-transition="slideup">settings</a></li>
    </ul>
  </div>
</div>
```

我们将把这段代码放在页面底部，并在样式表中使用一个简单的 CSS 规则来隐藏它，`#globalComponents{display:none;}`。

现在让我们来设置我们的应用程序，在创建每个页面之前将全局页脚插入其中。使用`clone()`方法（下一行的代码段中显示）可以确保我们不仅复制了页脚，还带上了附加的任何数据。这样，每个页面都带有完全相同的页脚，就像它在服务器端一样。当页面经过正常的初始化过程时，页脚将接收与页面其余部分相同的标记处理。

```js
/************************
*  The App
************************/
var floodApp = {
  universalPageBeforeCreate:function(){
    var $page = $(this);
    if($page.find(".bottomNavBar").length == 0){
      $page.append($("#globalComponents .bottomNavBar").clone());
    }

  }
}

/************************
*  The Events
************************/
//Interface Events
$(document).on("pagebeforecreate", "[data-role="page"]",floodApp.universalPageBeforeCreate);
```

看看我们在这段 JavaScript 代码中所做的。这跟我们之前做的有点不同。我们实际上更有效地组织了我们的代码。

# 组织你的代码

在之前的章节中，我们的代码结构非常松散。事实上，我确信学术界的人一定会嘲笑我们敢称之为结构化的胆量。我相信编码非常务实的方法，这导致我使用更简单的结构和最少的库。不过，其中也有一些价值和经验可以借鉴。

## MVC、MVVM、MV*

过去几年里，一些认真对待 JavaScript 开发的人都将后端开发结构引入到网页开发中，因为项目的规模和范围需要更加有条理的方法。对于雄心勃勃、持续时间长、纯网页端的应用来说，这种结构化方法可以提供帮助。特别是如果你在一个较大的团队中。

**MVC**代表"Model-View-Controller"（参见[`en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller`](http://en.wikipedia.org/wiki/Model%E2%80%93view%E2%80%93controller)），**MVVM**代表"Model View ViewModel"（参见[`en.wikipedia.org/wiki/Model_View_ViewModel`](http://en.wikipedia.org/wiki/Model_View_ViewModel)），而**MV***是缩写，代表"Model View Whatever"，是总称，用来概括将这些结构带到前端的整个运动。

一些更流行的库包括：

+   Backbone.JS（[`backbonejs.org/`](http://backbonejs.org/)）

+   脊骨（[`spinejs.com/`](http://spinejs.com/)）

+   腰椎（[`walmartlabs.github.com/lumbar/`](http://walmartlabs.github.com/lumbar/)）

+   琥珀（[`emberjs.com/`](http://emberjs.com/)）

+   Knockout（[`knockoutjs.com/`](http://knockoutjs.com/)）

+   AngularJS（[`angularjs.org/`](http://angularjs.org/)）

+   Batman.js（[`batmanjs.org/`](http://batmanjs.org/)）

更全面的比较可以在[`codebrief.com/2012/01/the-top-10-javascript-mvc-frameworks-reviewed/`](http://codebrief.com/2012/01/the-top-10-javascript-mvc-frameworks-reviewed/)上找到，还有其他的。

如何使 Backbone 与 jQuery Mobile 良好协作的适配器和示例可以在[`view.jquerymobile.com/1.3.0/docs/examples/backbone-require/index.php`](http://view.jquerymobile.com/1.3.0/docs/examples/backbone-require/index.php)找到。

琥珀的示例可以在[`github.com/LuisSala/emberjs-jqm`](https://github.com/LuisSala/ emberjs-jqm)找到。

Angular 还在进行 jQM 的适配器。[`github.com/tigbro/jquery-mobile-angular-adapter`](https://github.com/tigbro/jquery-mobile-angular-adapter) 上有几个示例。

## MV* 和 jQuery Mobile

是的，你可以做到。你可以将任何一个 MV* 框架添加到 jQuery Mobile 中，并制作出你喜欢的复杂应用程序。在其中，我倾向于在桌面上使用 Ember 平台，在 jQuery Mobile 中使用 Angular。但是，我想提出另一种选择。

我不打算深入探讨 MVC 框架背后的概念。基本上，这一切都是关于将应用程序的关注点分离成更可管理的部分，每个部分都有特定的目的。我们不需要再添加另一个库/框架来做到这一点。以更有组织的方式编写代码就足够了。让我们创建一个类似我之前开始的结构：

```js
//JavaScript Document

/*******************
 * The Application
 *******************/

/*******************
 * The Events
 *******************/

/*******************
 * The Model
 *******************/
```

## 应用程序

在应用程序部分下，让我们填写一些我们的应用程序代码，并给它一个*命名空间*。本质上，命名空间是将你的应用程序特定代码放入自己命名的对象中，这样函数和变量就不会与其他潜在的全局变量和函数冲突。它可以防止你污染全局空间，并帮助保护你的代码免受那些对你的工作无知的人的破坏。当然，这是 JavaScript，人们可以重写任何他们想要的东西。但是，这也使得像`floodApp.getStarted`这样的重写比简单地创建自己的名为`getStarted`的函数要更有意义。没有人会意外地重写一个命名空间函数。

```js
/*******************
 * The application
 *******************/
var floodApp = {
  settings:{
    initialized:false,
    geolocation:{
      latitude:null,
      longitude:null,
    },
    regionalChoice:null,
    lastStation:null
  },
  getStarted:function(){
    location.replace("#initialize");
  },
  fireCustomEvent:function(){
    var $clicked = $(this);
    var eventValue = $clicked.attr("data-appEventValue");
    var event = new jQuery.Event($(this).attr("data-appEvent"));
    if(eventValue){ event.val = eventValue; }
    $(window).trigger(event);
  },
  otherMethodsBlahBlahBlah:function(){}
}
```

特别要注意`fireCustomEvent`函数。有了它，我们现在可以设置一个事件管理系统。其核心思想非常简单。我们希望能够简单地在可点击的对象上放置标签属性，并使其触发事件，就像所有的 MV* 系统一样。这完全符合要求。在链接或其他东西上设置一个点击事件处理程序是相当常见的。这更简单。只需在这里或那里添加一个属性，就可以连接上。HTML 代码也变得更加可读。很容易看出这使你的代码声明性的：

```js
<a href="javascript://" data-appEvent="playStation" data-appEventValue="country">Country</a>
```

## 事件

现在，我们不再监听点击，而是监听事件。你可以有尽可能多的应用程序部分注册自己来监听事件，然后适当地执行。

随着我们的应用程序越来越完善，我们会开始收集大量事件；而不是让它们散布在多个嵌套的回调函数中，我们会将它们全部放在一个方便的地方。在大多数 JavaScript MV* 框架中，代码的这部分被称为路由器。连接到每个事件的只会是命名空间应用程序调用：

```js
/*******************
 * The events
 *******************/

//Interface events
$(document).on("click", "[data-appEvent]",
  floodApp.fireCustomEvent);$(document).on("pagebeforeshow",
  "[data-role="page"]",floodApp.universalPageBeforeShow);
$(document).on("pagebeforecreate",
  "[data-role="page"]",floodApp.universalPageBeforeCreate);
$(document).on("pageshow", "#initialize",
  floodApp.getLocation);
$(document).on("pagebeforeshow", "#welcome",
  floodApp.initialize);

//Application events
$(window).on("getStarted",
  floodApp.getStarted);
$(window).on("setHomeLocation",
  floodApp.setHomeLocation);
$(window).on("setNotHomeLocation",
  floodApp.setNotHomeLocation);
$(window).on("playStation",
  floodApp.playStation);
```

注意将关注点分为界面事件和应用程序事件。我们将其用作对 jQuery Mobile 事件（界面事件）和我们抛出的事件（应用程序事件）之间的区别点。这可能是一个任意的区别，但对于后来维护你的代码的人来说，这可能会派上用场。

## 模型

模型部分包含了你的应用程序的数据。这通常是从后端 API 中拉取的数据类型。这里可能不是很重要，但给自己的东西加上命名空间从来都不会有坏处。在这里，我们将我们的数据标记为 `modelData`。我们从 API 中拉取的任何信息都可以直接放入这个对象中，就像我们在这里使用站点数据一样：

```js
/*******************
 * The Model
 *******************/
var modelData = {
  station:{
    genres:[
       {
        display:"Seattle Grunge",
        genreId:12,
        genreParentId:1
       }
    ],
    metroIds[14,33,22,31],
    audioIds[55,43,26,23,11]
  }
}
```

将这种编程风格与客户端模板配对，你将看到一些高度可维护、结构良好的代码。然而，仍然有一些功能是缺失的。通常，这些框架还会为你的模板提供绑定。这意味着你只需要渲染模板一次。之后，只需更新你的模型对象，就足以导致 UI 自动更新。

这些绑定模板的问题在于它们以一种对桌面应用程序非常完美的方式更新 HTML。但请记住，jQuery Mobile 通过大量的 DOM 操作来实现这些功能。

在 jQuery Mobile 中，一个列表视图是这样开始的：

```js
<ul data-role="listview" data-inset="true">
  <li><a href="#stations">Local Stations</a></li>
</ul>
```

在正常的 DOM 操作之后，你会得到这样的结果：

```js
<ul data-role="listview" data-inset="true" data-theme="c" style="margin-top:0" class="ui-listview ui-listview-inset ui-corner-all ui-shadow">
<li data-corners="false" data-shadow="false" data-iconshadow="true" 
data-wrapperels="div" data-icon="arrow-r" data-iconpos="right" data-theme="c" class="ui-btn ui-btn-icon-right ui-li-has-arrow ui-li ui-corner-top ui-btn-up-c">
<div class="ui-btn-inner ui-li ui-corner-top">
<div class="ui-btn-text">
<a href="#stations" class="ui-link-inherit">Local Stations
</a>
</div>
<span class="ui-icon ui-icon-arrow-r ui-icon-shadow">&nbsp;</span>
</div>
</li>
</ul>
```

这仅仅是一个列表项。你真的不想在你的模板中包含所有这些垃圾；所以你需要做的就是，只需将你通常的项目添加到列表视图中，然后调用 `.listview("refresh")`。即使你使用的是 MV* 系统之一，当添加或删除某些内容时，你仍然必须找到或编写一个适配器来刷新列表视图。希望这些问题很快就会在平台级别得到解决。在那之前，使用真正的 MV* 系统与 jQM 会很痛苦。

# 介绍 Web Audio API

当我们在第六章中谈到 HTML 音频时，*HTML5 音频*，我们是从渐进增强和最大设备支持的角度来看待它的。我们拿原生音频控件的常规页面，并使用 JavaScript 构建一个新的界面来控制音频。然后我们看了一些组合它们的方法，并追求更好的体验。现在我们将再进一步。

Web Audio API 是一个相当新的开发，截至本文写作时，它只存在于 iOS 6 的移动空间中。Web Audio API 在最新版本的桌面 Chrome 上可用，因此你仍然可以在那里进行初始测试编码。

目前，这意味着没有 Android、没有 Windows Phone，也没有 Blackberry。至少，还没有。然而，只是时间问题，这将被构建到其他主要平台中。

项目的大部分代码以及 API 的完整说明都可以在[`developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/PlayingandSynthesizingSounds/PlayingandSynthesizingSounds.html`](http://developer.apple.com/library/safari/#documentation/AudioVideo/Conceptual/Using_HTML5_Audio_Video/PlayingandSynthesizingSounds/PlayingandSynthesizingSounds.html)找到。

让我们使用特性检测来分支我们的功能：

```js
function init() {
if("webkitAudioContext" in window) {
    myAudioContext = new webkitAudioContext();
    // ananalyser is used for the spectrum
    myAudioAnalyser = myAudioContext.createAnalyser();
    myAudioAnalyser.smoothingTimeConstant = 0.85;
    myAudioAnalyser.connect(myAudioContext.destination);

    fetchNextSong();
  } else {
    //do the old stuff
  }
}
```

这个页面的原始代码旨在同时下载队列中的每首歌曲。对于高速连接，这可能还可以。但在移动设备上则不太适用。由于连接性和带宽有限，最好只是链接下载以确保更好的体验和更加尊重带宽的使用：

```js
function fetchNextSong() {
var request = new XMLHttpRequest();
  var nextSong = songs.pop();
  if(nextSong){
    request = new XMLHttpRequest();
    // the underscore prefix is a common naming convention
    // to remind us that the variable is developer-supplied
    request._soundName = nextSong;
    request.open("GET", PATH + request._soundName + ".mp3", true);
    request.responseType = "arraybuffer";
    request.addEventListener("load", bufferSound, false);
    request.send();
  }
}
```

现在`bufferSound`函数只需在缓冲后调用`fetchNextSong`，如下面的代码片段所示：

```js
function bufferSound(event) {
  var request = event.target;
  var buffer = myAudioContext.createBuffer(
  request.response, false);
  myBuffers.push(buffer);
  fetchNextSong();
}
```

我们需要从原始版本中更改的最后一件事是，告诉缓冲器按插入顺序拉取歌曲：

```js
function playSound() {
  // create a new AudioBufferSourceNode
  var source = myAudioContext.createBufferSource();
  source.buffer = myBuffers.shift();
  source.loop = false;
  source = routeSound(source);
  // play right now (0 seconds from now)
  // can also pass myAudioContext.currentTime
  source.noteOn(0);
  mySpectrum = setInterval(drawSpectrum, 30);
  mySource = source;
}
```

对于 iOS 上的任何人来说，这个解决方案相当不错。对于那些想要深入了解的人来说，这个 API 还有更多内容。通过这个开箱即用的示例，你可以得到一个很好的基于画布的音频分析器，它使音频水平跟随音乐弹跳的外观非常专业。滑块控件用于更改音量、左右平衡和高通滤波器。如果你不知道什么是高通滤波器，不要担心，我认为那个滤波器的实用性已经过时了。不管怎样，玩起来很有趣。

![Web Audio API 简介](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_05.jpg)

Web Audio API 是一项非常严肃的业务。这个例子是从苹果网站上的例子改编的。它只播放一个声音。然而，Web Audio API 的设计理念是使其能够播放多个声音，以多种方式改变它们，甚至使用 JavaScript 动态生成声音。深入研究可能值得一本书。它还需要比我可能会拥有的更深入的音频处理知识。同时，如果您想在 jQuery Mobile 中查看这个概念验证，您可以在`webaudioapi.html`的示例源代码中找到它。要更深入地了解即将到来的内容，您可以查看[`dvcs.w3.org/hg/audio/raw-file/tip/webaudio/specification.html`](https://dvcs.w3.org/hg/audio/raw-file/tip/webaudio/specification.html)的文档。

# 提示用户安装您的应用

记得在第六章中，*HTML5 音频*，我们添加了苹果触摸图标，使林赛·斯特林网站在添加到主屏幕书签时看起来像一个应用程序？ 我们甚至进一步使用清单文件来本地缓存资产，以实现更快的访问和离线使用。

![提示用户安装您的应用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_06.jpg)

现在让我们看一下如何提示我们的用户将 Flood.FM app 下载到他们的主屏幕。很可能你以前见过它；它是那个小气泡，弹出来指导用户安装应用程序的步骤。

有许多不同的项目，但我见过的最好的一个是 Google 创始的一个分支。非常感谢和尊重 GitHub 上的 Mr. Okamototk（[`github.com/okamototk`](https://github.com/okamototk)）对它的采取和改进。Okamototk 将气泡发展成包括几个 Android 版本、传统 iOS 版本，甚至还支持 BlackBerry。你可以在[`github.com/okamototk/jqm-mobile-bookmark-bubble`](https://github.com/okamototk/jqm-mobile-bookmark-bubble)找到他的原作品。但是，除非你能读日文或乐于翻译，我建议你只是从本章的示例中获取代码。

不用太担心过于打扰你的客户。使用这个版本，如果他们三次关闭了书签气泡，他们就不会再看到它。 这个计数存储在 HTML5 本地存储中；所以如果他们清除了存储，他们会再次看到气泡。幸运的是，大多数人根本不知道这是可以做到的，所以这种情况不会发生很频繁。通常只有像我们这样的极客会清理类似 LocalStorage 和 cookies 的东西，而当我们这样做时，我们知道我们在做什么。

在我的代码版本中，我已将所有 JavaScript 合并为一个单个文件，放置在你的 jQuery 和 jQuery Mobile 导入之间。顶部的第一行非注释行是：

```js
page_popup_bubble="#welcome";
```

这是你将要改变成自己的第一页或你想要气泡弹出的地方。

在我的版本中，我已经将字体颜色和文本阴影属性硬编码到了气泡中。这是因为在 jQM 中，字体颜色和文本阴影颜色根据你使用的主题而变化。因此，在 jQuery Mobile 的默认“ A”主题（黑色背景上的白色文本），字体会显示为白色，阴影为黑色，出现在白色气泡上。现在，在我修改过的 jQM 版本中，它看起来总是对的。

我们只需要确保我们在头部设置了正确的链接，以及我们的图片放在了正确的位置：

```js
<link rel="apple-touch-icon-precomposed" sizes="144x144" href="images/album144.png">
<link rel="apple-touch-icon-precomposed" sizes="114x114" href="images/album114.png">
<link rel="apple-touch-icon-precomposed" sizes="72x72" href="images/album72.png">
<link rel="apple-touch-icon-precomposed" href="images/album57.png">
<link rel="shortcut icon" href="img/images/album144.png">
```

![提示用户安装您的应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_07.jpg)

注意这里的 Flood.FM 标志。标志是从我们标记有 `rel="apple-touch-icon-precomposed"` 的链接标签中提取并注入到气泡中的。所以，实际上，你需要改变的 `jqm_bookmark_bubble.js` 中的唯一东西是 `page_popup_bubble`。

# 新的设备级硬件访问

每年我们的移动浏览器都会有新的硬件级访问方式。下面是一些你现在可以开始做的事情以及未来的展望。并不是所有这些都适用于每个项目，但如果你有创意，你可能会找到创新的方式来使用它们。

## 加速计

加速计是你手机里的小装置，用来测量手机在空间中的方向。想要深入了解，请阅读 [`en.wikipedia.org/wiki/Accelerometer`](http://en.wikipedia.org/wiki/Accelerometer)。

这超出了我们之前简单的定位。这是对加速计的真正访问，而且是详细的。想象一下用户能够摇动他们的设备或者倾斜它作为与你的应用交互的一种方法。也许 Flood.FM 正在播放一些他们不喜欢的东西，我们可以给他们一个有趣的方式来对抗这首歌。比如，“摇一首歌以永远不再听到它”。这里是某人制作的一个简单的弹珠滚动游戏，作为概念验证。参见 [`menscher.com/teaching/woaa/examples/html5_accelerometer.html`](http://menscher.com/teaching/woaa/examples/html5_accelerometer.html)。

## 相机

苹果的 iOS 6 和安卓的 JellyBean 都可以访问它们的文件系统中的照片以及相机。当然，这些是这两个平台的最新版本。如果你打算支持许多仍然在货架上销售的过时的 Android 设备（2.3 2.4），好像它们是全新的一样，那么你需要选择本地编译，比如 PhoneGap 或 Apache Cordova 来获取这个功能。

```js
<input type="file" accept="image/*">
<input type="file" accept="video/*">
```

以下截图显示 iOS 在左边，Android 在右边：

![相机](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_08.jpg)

## 即将推出的 API

Mozilla 正在大力推动移动网络 API 的发展。以下是即将到来并且可能在不到两年内就可以使用的内容：

+   电池电量

+   充电状态

+   环境光传感器

+   接近传感器

+   振动

+   联系人

+   网络信息

+   移动连接（运营商、信号强度等）

+   Web 短信

+   Web 蓝牙

+   Web FM

+   存档 API（打开和读取来自压缩文件的内容）

如果你想阅读更多，请查看 [`wiki.mozilla.org/WebAPI`](https://wiki.mozilla.org/WebAPI)。

# 选择开发应用还是不开发应用，这是个问题

是否应该将你的项目编译成原生应用？以下是一些需要考虑的事项。

## 下雨了（认真对待这个问题）

当你把你的第一个项目编译成一个应用时，你会感到一种特殊的激动。你做到了！你做了一个真正的应用程序！在这一点上，我们需要记住《侏罗纪公园》电影中伊恩·马尔科博士的话（去重新看一遍吧。我等你）：

![下雨了（认真对待这个问题）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_09.jpg)

> “你站在巨人的肩膀上，尽可能地做了一些事情，甚至在你知道你拥有什么之前，你就已经对它进行了专利申请，打包了它，把它塞进了一个塑料午餐盒里，现在 [敲打桌子] 你在卖它，你想卖它。好吧……你的科学家们是如此专注于他们是否能够做到，以至于他们没有停下来思考他们是否应该。”

这些话对我们来说很接近预言性质。最后，他们自己的创造吞食了大部分客人。

根据 2012 年 8 月的这份报告[`www.webpronews.com/over-two-thirds-of-the-app-store-has-never-been-downloaded-2012-08`](http://www.webpronews.com/over-two-thirds-of-the-app-store-has-never-been-downloaded-2012-08)（以及我以前看过的几篇类似的报告），*超过三分之二的应用商店中的所有应用从未被下载过*。甚至没有一次！所以，现实情况是，大多数项目在应用商店中被抛弃。

即使你的应用被发现，任何人会长时间使用它的可能性令人惊讶地小。根据《福布斯》（[`tech.fortune.cnn.com/2009/02/20/the-half-life-of-an-iphone-app/`](http://tech.fortune.cnn.com/2009/02/20/the-half-life-of-an-iphone-app/)）中的一篇文章，大多数应用在几分钟内被放弃，再也不会被打开。付费应用的持续时间大约是之前的两倍，然后要么被遗忘，要么被删除。游戏有一些持久力，但坦率地说，jQuery Mobile 并不是一个引人入胜的游戏平台，对吧？

安卓世界的情况糟糕透顶。仍然可以购买到运行古老版本操作系统的设备，而运营商和硬件合作伙伴在提供更新方面甚至没有及时性可言。如果你想了解采用本地策略可能带来的沉重压力，可以看看这里：

[`developer.android.com/about/dashboards/index.html`](http://developer.android.com/about/dashboards/index.html)

![破坏幻想（认真对待）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_10.jpg)

你可以看到安卓生态系统有多么分裂，以及你可能需要支持多少旧版本。在安卓及其商业伙伴摆脱束缚之前，安卓将继续成为本地移动世界的 IE 6。你*不*想支持那个。

另一方面，如果你严格发布到网络，那么每当用户访问你的网站时，他们都将使用最新版本和最新 API，你永远不必担心有人使用过时的版本。你需要应用安全补丁吗？你可以在几秒钟内完成。如果你在苹果应用商店，这个补丁可能需要数天甚至数周。

## 编译应用的三个好理由

是的，我知道我刚刚告诉过你成功的机会渺茫，以及你将面临支持应用的火海和硫磺。然而，以下是制作真正应用的几个好理由。实际上，在我看来，它们是唯一可接受的理由。

### 项目本身就是产品

这是你需要将项目打包成应用的第一个也是唯一确定的迹象。我不是在说通过你的项目销售东西。我说的是项目本身。它应该制作成一个应用。愿原力与你同在。

### 访问本地独有的硬件功能

GPS 和摄像头在它们的最新版本中，都可靠地为两个主要平台提供支持。iOS 甚至支持加速计。不过，如果你希望得到更多，你将需要编译成应用程序以获得这些 API 的访问权限。

### 推送通知

你喜欢它们吗？我不知道你，但我得到的推送通知太多了；任何一个过于张扬的应用要么被删除，要么完全关闭通知。我在这方面并不孤单。然而，如果你一定要有推送通知，而且不能等待基于网页的实现，你就必须编译一个应用程序。

### 支持当前客户

好吧，这有一定的牵强之处，但如果你在美国企业工作，你就会听到这个。这意味着你是一家成熟的企业，你希望为客户提供移动支持。你或者你的上级已经读过一些白皮书和/或案例研究，表明有将近`50%`的人首先在应用商店搜索。

即使这是真的（我对此仍然没有把握），你要对一个商人说这些。他们懂得金钱、开销和增加的维护成本。一旦向他们解释了在各种平台和它们的操作系统版本中进行建设和测试的成本、复杂性和潜在的持续头疼之后，对于公司向现有客户推广支持移动端，让他们只需要在其移动设备上访问你的网站，这成为一个非常吸引人的替代方案。营销人员总是在寻找可以向客户吹嘘的理由。营销部门可能仍然倾向于在客户设备上显示公司的图标，以增强品牌忠诚度，但这只是需要教育他们，这可以在没有应用程序的情况下完成。

即使你可能无法说服所有正确的人认为应用程序对于客户支持是错误的选择。如果你自己做不到，就用一点 Jakob Nielson 的见解敲打他们的头颅。如果他们不听你的，也许他们会听他的。我敢说任何人反驳尼尔森·诺曼集团不知道他们在说什么的说法。参见 [`www.nngroup.com/articles/mobile-sites-vs-apps-strategy-shift/`](http://www.nngroup.com/articles/mobile-sites-vs-apps-strategy-shift/)。

> "总结：当前移动应用程序的可用性比移动网站更好，但即将发生的变化最终会使移动网站成为更加优越的策略。"

因此，一个价值`64,000`美元的问题就是：我们是为现在还是为未来而生产的？如果我们是为现在而做，那么应该标志着本地策略退休的标准是什么？或者我们打算永远固守它吗？不要在没有退出战略的情况下参与那场战争。

# PhoneGap 与 Apache Cordova

好吧，在所有这些之后，如果你仍然想制作一个本地应用程序，我向你致敬。我钦佩你的精神，并祝你好运。

### 注意

如果你搜索 "jquery mobile phonegap performance"，你会找到 *很多* 负面文章。问题似乎是无穷无尽的。性能低下，屏幕在转换之间闪烁，等等。并不是说 Sencha Touch 或任何其他移动 Web 框架似乎做得更好。只是要意识到它可能不像在 Web 上运行时表现那样好。

PhoneGap 最初是一个将常规的 HTML、JS 和 CSS 打包成一个可在任何应用商店分发的应用程序的项目。最终，它成为了 Apache 软件基金会的一部分。在其核心，PhoneGap *是* Apache Cordova。事实上，如果你去 Cordova 的文档站点，它实际上仍然托管在 [`docs.phonegap.com/`](http://docs.phonegap.com/)。

除了简单地编译你的应用程序之外，你还可以访问以下设备级别的 API：

+   加速度计：利用设备的运动传感器。

+   相机：使用设备的相机拍摄照片。

+   捕获：使用设备的媒体捕获应用程序捕获媒体文件。

+   指南针：获取设备指向的方向。

+   连接：快速检查网络状态和蜂窝网络信息。

+   联系人：使用设备的联系人数据库。

+   设备：收集设备特定信息。

+   事件：通过 JavaScript 连接到本地事件。

+   文件：通过 JavaScript 连接到本地文件系统。

+   地理位置：使你的应用程序具有位置感知能力。

+   全球化：启用特定于区域设置的对象表示。

+   InAppBrowser：在另一个应用程序浏览器实例中启动 URL。

+   媒体：记录并回放音频文件。

+   通知：设备的视觉、听觉和触觉通知。

+   启动画面：显示和隐藏应用程序的启动画面。

+   存储：连接到设备的原生存储选项。

到目前为止，一切都很顺利。我们有更多的东西可以做，而且我们可以全部在 JavaScript 中完成。

接下来，我们需要真正构建我们的应用程序。你需要在你的计算机上下载 PhoneGap 或 Cordova。不要忘记下载你打算支持的每个平台的 SDK。不，等等，划掉！

![PhoneGap 与 Apache Cordova 对比](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_11.jpg)

现在有了 PhoneGap Build。这是一个面向 PhoneGap 的基于云的构建服务。你根本不需要安装任何 SDK。PhoneGap Build 只是把所有工作都做了。如果你想要编译 iOS 应用程序，你仍然需要提供开发者证书，但除了这一点小问题，一切都很顺利。

要开始使用，你只需用你的 Adobe ID 或 GitHub ID 登录。然后，要么粘贴 GitHub 存储库的 URL，要么上传一个小于 9.5 MB 的 zip 文件：

![PhoneGap 与 Apache Cordova 对比](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_12.jpg)

接下来，你需要填写关于应用程序本身的一些信息：

![PhoneGap 与 Apache Cordova 对比](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_13.jpg)

点击**准备构建**按钮。现在只需坐下来，看着漂亮的进度指示器做它们的工作。

![PhoneGap 与 Apache Cordova 对比](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_10_14.jpg)

看，他们甚至给了你一个可爱的小二维码，用于下载这个应用。在 iOS 上显示红色标志的唯一原因是，这一点上，我还没有提供给他们我的开发者证书。

# 总结

我不知道你怎么想，但我真的筋疲力尽了。我真的觉得在这个时候关于 jQuery Mobile 或其支持技术已经没有更多可说的了。你已经有了如何为许多行业构建东西的例子，以及通过 Web 或 PhoneGap Build 部署它的方法。在这一点上，你应该引用建筑工人鲍勃的话。“我们能建造它吗？是的，我们能！”

我希望这本书对你有所帮助和/或启发，让你去做一些了不起的事情。我希望你改变世界，并且通过这样做获得巨额财富。在你前进的过程中，我很乐意听到你的成功故事。想要告诉我你的近况，或者指出任何勘误，甚至是有一些问题要问，欢迎直接给我发邮件到`<shane@roughlybrilliant.com>`。现在，去做一些精彩的事吧！
