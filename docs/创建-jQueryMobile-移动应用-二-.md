# 创建 jQueryMobile 移动应用（二）

> 原文：[`zh.annas-archive.org/md5/E63D782D5AA7D46340B47E4B3AD55DAA`](https://zh.annas-archive.org/md5/E63D782D5AA7D46340B47E4B3AD55DAA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：客户端模板化、JSON API 和 HTML5 Web 存储

我们已经走了很长一段路，为业务准备了一些相当庞大的默认模板和样板。在这一章中，我们将简化并专注于其他事项。我们将创建一个基于社交媒体的新闻聚合网站。到目前为止，我们一直非常重视渐进式增强。在本章中，我们将放弃这一点。这将需要 JavaScript。

在这一章中，您将学到以下内容：

+   客户端模板化选项

+   JsRender

+   联接到 JSON API（Twitter）

+   以编程方式更改页面

+   生成的页面和 DOM 权重管理

+   利用 RSS 订阅（本地化）

+   HTML5 Web 存储

+   利用 Google Feeds API

# 客户端模板化

（以一个脾气暴躁的老人的声音）在我那个年代，我们在服务器上渲染所有页面，我们喜欢这样！哈哈！时代正在变化，我们看到客户端模板化框架的巨大潮流。它们的核心都差不多，即它们接收 JSON 数据并应用在一个包含在 script 标签中的基于 HTML 的模板上。

如果你知道**JSON**是什么，跳过这一段。上一章我花了一点时间讨论了这个问题，但是万一你跳过了并且不知道，JSON 是用 JavaScript 编写的，以便可以用作数据交换格式。它比 XML 更高效，并且以面向对象的方式立即被浏览器解释。JSON 甚至可以使用 JSONP 跨域请求数据。有关 JSON 的更多信息，请阅读[`en.wikipedia.org/wiki/JSON`](http://en.wikipedia.org/wiki/JSON)。有关 JSONP 的更多信息，请阅读[`en.wikipedia.org/wiki/JSONP`](http://en.wikipedia.org/wiki/JSONP)。

所有这些客户端库都有一些标记，显示数据的去向，并提供实现循环和条件语句的方法。有些是“无逻辑”的，并且根据尽可能少的逻辑的理念运行。如果你赞同这种美妙的学术方法，那太棒了。

老实说，从纯粹实用的角度来看，我认为模板是代码的完美容器。越灵活越好。JSON 保存数据，而模板用于转换数据。打个比方，XML 是数据格式，XSL 模板用于转换数据。没有人在 XSL 中抱怨逻辑；所以，我不明白为什么在 JS 模板中会成为问题。但是，所有这些讨论都是纯学术性的。最终，它们几乎都能做你想做的事情。如果你更多的是设计师而不是编码者，你可能会更多地关注无逻辑的模板。

以下是一个相当详尽的客户端模板化框架列表。我可能会漏掉一些，而且到这本书出版时可能会有更多，但这是一个开始。

+   doT

+   dust.js

+   Eco

+   EJS

+   Google Closure Templates

+   handlebars

+   haml-js

+   kite

+   Jade

+   jQote2

+   jQuery 模板（已停止）

+   jsRender / jsView

+   Parrot

+   node-asyncEJS

+   Nun

+   Mu

+   mustache

+   montage

+   Stencil

+   underscore.js

现在，虽然我是一个粉丝，但是，如果它是官方的 jQuery，我喜欢它。因此，我尝试的第一件事是 **jQuery Templates**。遗憾的是，在我刚学会喜欢它不久之后，jQuery 团队放弃了这个项目，并指向 **JsRender** 作为项目的延续。未来是否会持续沿着这个方向是另一个问题，但是，目前，JsRender 的功能和强大性使其成为一个引人注目的选择，并且是本章其余部分模板工作的基础。更不用说，它只有经过精简的 14k 并且速度快如闪电。您可以从 [`github.com/BorisMoore/jsrender`](https://github.com/BorisMoore/jsrender) 下载最新版本。

如果您正在寻找帮助以决定适合您的正确模板框架，那么在本章节审阅过程中，Andy Matthews 很友好地提供了以下链接：[`garann.github.com/template-chooser/`](http://garann.github.com/template-chooser/)。它讨论了几个框架的优点，帮助您做出明智的选择。谢谢，Andy！

# 连接至 JSON API（Twitter）

观看 Twitter 上的热门话题总是很有趣。就像许多其他受欢迎的在线目的地一样，它具有 JSON API。让我们来玩一下。这是我们要构建的内容。您可以在左侧看到列表视图，在右侧看到搜索视图。

![连接到 JSON API（Twitter）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_05_00.jpg)

在这一点上，我将放弃从 HTML 中分离出 CSS 和 JS 的学术正确做法。除了库之外，所有特定于页面的代码（HTML、CSS 和 JS）将位于单个页面内。以下代码是我们起始的基本页面。在本章的代码包中，它是`twitter.html`：

```js
<!DOCTYPE html>  
<html>  
  <head>   
    <meta charset="utf-8">   
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">   
    <title>Chapter 5 - News</title>       
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.3.0/jquery.mobile-1.3.0.min.css" />   
    <script src="img/jquery-1.8.2.min.js"></script>  
    <script src="img/jsrender.min.js" type="text/javascript"></script>
  <script src="img/jquery.mobile-1.3.0.min.js"></script>
```

下面的样式将帮助我们的 Twitter 结果看起来更像 Twitter：

```js
    <style type="text/css">     
      .twitterItem .ui-li-has-thumb .ui-btn-inner a.ui-link-inherit, #results .ui-li-static.ui-li-has-thumb{       
         min-height: 50px;       
         padding-left: 70px;     
      } 
      .twitterItem .ui-li-thumb, #results .ui-listview .ui-li-icon, #results .ui-li-content{       
         margin-top: 10px;
         margin-left: 10px;     
      }     
      .twitterItem .ui-li-desc{       
         white-space:normal;       
         margin-left:-25px;       
      }     
      .twitterItem .handle{       
        font-size:80%;       
        font-weight:normal;         
        color:#aaa;     
      }     
      .twitterItem .ui-li-heading{       
        margin: 0 0 .6em -25px;     
      }   
    </style> 
  </head>   
  <body>  
```

这个页面基本上只是一个占位符，一旦从 Twitter API 获取到结果，它将被填充：

```js
  <div id="home_page" data-role="page"> 	
    <div data-role="header"><h1>Now Trending</h1></div>   
    <div data-role="content">
      <ul id="results" data-role="listview" data-dividertheme="b">
      </ul>
    </div>
  </div>  
```

下面的脚本是页面的处理核心。

```js
  <script type="text/javascript"> 
    $(document).on("pagebeforeshow", "#home_page",  function(){ 	

     //before we show the page, go get the trending topics
     //from twitter
    $.ajax({       
      url:"https://api.twitter.com/1/trends/daily.json",
        dataType:"jsonp",       
        success: function(data) {       
          var keys = Object.keys(data.trends);       

          //Invoke jsRender on the template and pass in
          //the data to be used in the rendering.
          var content = $("#twitterTendingTemplate")
           .render(data.trends[keys[0]]);

          //Inject the rendered content into the results area 
          //and refresh the listview
          $("#results").html( content ).listview("refresh"); 
        }	
      })
      .error(function(jqXHR, textStatus, errorThrown){                  
        alert(textStatus+" - "+errorThrown);     
      });
    });    

    $(document).on('click', 'a.twitterSearch', function(){     
      var searchTerm = $(this).attr("data-search");     

      //take the search term from the clicked element and 
      //do a search with the Twitter API
      $.ajax({        
        url:"http://search.twitter.com/search.json?q="+escape(searchTerm),        
        dataType:"jsonp",       
        success: function(data){

          //create a unique page ID based on the search term
          data.pageId = searchTerm.replace(/[# ]*/g,"");             
          //add the search term to the data object
          data.searchTerm = searchTerm; 

          //render the template with JsRender and the data    
          var content = $("#twitterSearchPageTemplate").render(data);  

          //The rendered content is a full jQuery Mobile 
          //page with a unique ID.  Append it directly to the 
          //body element
          $(document.body).append(content); 	

          //switch to the newly injected page
          $.mobile.changePage("#"+data.pageId);       
        }     
      })
      .error(function(jqXHR, textStatus, errorThrown){                  
        alert(textStatus+" - "+errorThrown);     
      });   
    });     
  </script>  
```

以下是两个 JsRender 模板：

```js
  <script id="twitterTendingTemplate" type="text/x-jsrender"> 
    <li class="trendingItem">     
      <a href="javascript://" class="twitterSearch" data-search="{{>name}}">       
        <h3>{{>name}}</h3>     
      </a>   
    </li> 
  </script>  

  <script id="twitterSearchPageTemplate" type="text/x-jsrender">   
    <div id="{{>pageId}}" data-role="page" data-add-back-btn="true">     
      <div data-role="header">
        <h1>{{>searchTerm}}</h1>
      </div>     
      <div data-role="content">
        <ul id="results" data-role="listview" data-dividertheme="b">
          {{for results}}           
            <li class="twitterItem">             
            <a href="http://twitter.com/{{>from_user}}">   
              <img src="img/{{>profile_image_url}}" alt="{{>from_user_name}}" class="ui-shadow ui-corner-all" /> 
              <h3>{{>from_user_name}} 
                <span class="handle">
                  (@{{>from_user}})<br/>
                  {{>location}} 
                  {{if geo}}
                    {{>geo}}
                  {{/if}}
                </span>
              </h3>               
              <p>{{>text}}</p>             
            </a>           
          </li>         
        {{/for}} 	      
      </ul>     
    </div>   
  </div> 
</script>  
</body> 
</html>
```

好吧，一次把那么多代码给你可能有点多，但大部分代码在这一点上看起来应该相当熟悉。让我们开始解释一些最新的东西。

通常，要将数据加载到网页中，即使您正在获取 JSON 格式的数据，也会受到同源策略的限制。然而，如果数据来自另一个域，您将需要绕过同源策略。为了绕过同源策略，您可以使用某种服务器端代理，例如 PHP 的 **cURL**（[`php.net/manual/en/book.curl.php`](http://php.net/manual/en/book.curl.php)）或 Java 世界中的 Apache **HTTP Core** **Components**（[`hc.apache.org/`](http://hc.apache.org/)）。

让我们保持简单，使用**JSONP**（也称为**JSON with Padding**）。JSONP 不使用常规的 Ajax 请求来获取信息。尽管配置选项是为`$.ajax`命令，但在幕后，它将以独立的脚本标签执行数据调用，如下所示：

```js
 <script type="text/javascript" src="img/daily.json?callback=jQuery172003156238095834851_1345608708562&_=1345608708657"></script>
```

值得注意的是，通过 JSONP 使用 GET 请求。这意味着你不能用它传递敏感数据，因为它会通过网络流量扫描或简单查看浏览器的请求历史立即可见。所以，请不要通过 JSONP 登录或传递任何敏感信息。明白了吗？

在实际请求发出之前，jQuery 会创建一个半随机的函数名称，一旦从服务器收到响应，该函数将被执行。通过在 URL 中附加该函数名称作为回调，我们告诉 Twitter 用这个函数调用包裹他们发给我们的响应。因此，我们不会收到类似 `{"trends": …},` 这样的 JSON 脚本，而是在我们页面上编写的脚本如下所示：

```js
jQuery172003156238095834851_1345608708562({"trends": …}). 
```

这能够运行的原因是同域策略对于脚本并不存在。方便，对吧？在脚本加载完并且回调处理完成之后，我们将以 JSON 格式获得数据。最终，在底层执行上有着截然不同，但结果与你通过自己域上的常规`getJSON`请求获得的结果是一样的。

以下是从 Twitter 返回的响应片段：

```js
jQuery1720026425381423905492_1345774796764({
  "as_of": 1345774741,
  "trends": {
    "2012-08-23 05:20": [
       {
         "events": null,
         "name": "#ThingsISayTooMuch",
         "query": "#ThingsISayTooMuch",
         "promoted_content": null
       },
       {
         "events": null,
         "name": "#QuieroUnBesoDe",
         "query": "#QuieroUnBesoDe",
         "promoted_content": null
       },
       {
          "events": null,
          "name": "#ASongIKnowAllTheLyricsTo",
          "query": "#ASongIKnowAllTheLyricsTo",
          "promoted_content": null
       },
```

接下来，我们将响应精简到我们想要的部分（最新一组热门话题），并将该数组传递给 JsRender 进行渲染。也许直接循环遍历 JSON 并使用字符串连接来构建输出可能更简单，但看看下面的模板，告诉我这不会更清晰易维护：

```js
<script id="twitterTendingTemplate" type="text/x-jsrender"> 
  <li class="trendingItem">     
    <a href="javascript://" class="twitterSearch" data-search="{{>name}}">       
      <h3>{{>name}}</h3>     
    </a>   
  </li> 
</script>  
```

脚本上的`text/x-jsrender`类型将确保页面不会尝试解析内部内容为 JavaScript。由于我们向 JsRender 传入了一个数组，模板将为数组中的每个对象编写。这样就简单了！尽管我们只从数据对象中提取了名称，但你明白这是如何工作的。

让我们来看看下一个重要的 JavaScript 代码块：

```js
$(document).on('click', "a.twitterSearch", function(){     
  //grab the search term off the link     
  var searchTerm = $(this).attr("data-search");          

  //do a Twitter search based on that term     
  $.ajax({       url:"http://search.twitter.com/search.json?q="+escape(searchTerm),        
   dataType:"jsonp",       
   success: function(data){         
     //create the pageID by stripping 
     //all non-alphanumeric data         
     var pageId = searchTerm.replace(/[^a-zA-Z0-9]+/g,"");                  
     //throw the pageId and original search term 
     //into the data that we'll be sending to JSRenderdata.pageId = pageId;
     data.searchTerm = searchTerm;          	      

     //render the page and append it to the document body         $(document.body).append($("#twitterSearchPageTemplate")
       .render(data));                  

     //set the page to remove itself once left          
     $("#"+pageId).attr( "data-" + $.mobile.ns 
       + "external-page", true )
       .one( 'pagecreate', $.mobile._bindPageRemove );                  
     //switch to the new page          
     $.mobile.changePage("#"+data.pageId);   
    }
  })
  .error(function(jqXHR, textStatus, errorThrown){
    //If anything goes wrong, at least we'll know.           
    alert(textStatus+" - "+errorThrown);     
  });    
});
```

首先，我们从链接本身的属性中提取搜索词。搜索词本身作为用于动态渲染页面的`id`属性有些不合适，因此，我们将去除任何空格和非字母数字内容。然后，我们将`pageId`和`searchTerm`属性附加到我们从 Twitter 那里收到的 JSON 对象上。以下是从这个调用返回的数据样本：

```js
jQuery1720026425381423905492_1345774796765({
    "completed_in": 0.02,
    "max_id": 238829616129777665,
    "max_id_str": "238829616129777665",
    "next_page": "?page=2&max_id=238829616129777665&q=%23ThingsISayTooMuch",
    "page": 1,
    "query": "%23ThingsISayToMuch",
    "refresh_url": "?since_id=238829616129777665&q=%23ThingsISay
TooMuch",
    "results": [
        {
            "created_at": "Fri, 24 Aug 2012 02:46:24 +0000",
            "from_user": "MichelleEspra",
            "from_user_id": 183194730,
            "from_user_id_str": "183194730",
            "from_user_name": "Michelle Espranita",
            "geo": null,
            "id": 238829583808483328,
            "id_str": "238829583808483328",
            "iso_language_code": "en",
            "metadata": {
                "result_type": "recent"
            },
            "profile_image_url": "http:\/\/a0.twimg.com\/profile_images\/2315127236\/Photo_20on_202012-03-03_20at_2001.39_20_232_normal.jpg",
            "profile_image_url_https": "https:\/\/si0.twimg.com\/profile_images\/2315127236\/Photo_20on_202012-03-03_20at_2001.39_20_232_normal.jpg",
            "source": "&lt;a href=&quot;http:\/\/twitter.com\/&quot;&gt;web&lt;\/a&gt;",
            "text": "RT @MuchOfficial: @MichelleEspra I'd be the aforementioned Much! #ThingsISayTooMuch",
            "to_user": null,
            "to_user_id": 0,
            "to_user_id_str": "0",
            "to_user_name": null,
            "in_reply_to_status_id": 238518389595840512,
            "in_reply_to_status_id_str": "238518389595840512"
        }

}
```

因此，我们将获取到的响应传递给渲染器，以便根据`twitterSearchPageTemplate`进行转换：

```js
<script id="twitterSearchPageTemplate" type="text/x-jsrender"> 
    <div id="{{>pageId}}" data-role="page" data-add-back-btn="true">     
      <div data-role="header">
        <h1>{{>searchTerm}}</h1>
      </div>     
      <div data-role="content">
        <ul id="results" data-role="listview" data-dividertheme="b">
          {{for results}}           
            <li class="twitterItem">             
            <a href="http://twitter.com/{{>from_user}}">   
              <img src="img/{{>profile_image_url}}" alt="{{>from_user_name}}" class="ui-shadow ui-corner-all" /> 
              <h3>{{>from_user_name}} 
                <span class="handle">
                  (@{{>from_user}})<br/>
                  {{>location}} 
                    {{if geo}}
                      {{>geo}}
                    {{/if}}
                </span>
              </h3>               
              <p>{{>text}}</p>             
            </a>           
          </li>         
        {{/for}}       
      </ul>     
    </div>   
  </div> 
</script> 
```

这些是简单的实现。 GitHub 上的示例展示了许多值得探索的选项。查看[`borismoore.github.com/jsrender/demos/`](http://borismoore.github.com/jsrender/demos/)以获取有关创建更复杂模板的详细信息。这是一个变化迅速的库（大多数客户端模板库都是如此）。因此，如果你在阅读本文时，发现有更多选项和略有变化的语法，不要感到惊讶。

一旦我们获得了转换的结果，我们就可以将新页面的源附加到文档的主体，然后以编程方式切换到这个新页面。

# 以编程方式更改页面

有两种方法可以在 jQuery Mobile 中以编程方式更改页面，它们之间的区别很微妙：

+   调用`$.mobile.changePage`并传递一个选择器到你想要跳转到的页面的 ID。这与 URL 的工作方式相同。无论哪种方式都会产生与用户点击链接相同的结果。该页面将被插入浏览器的历史记录中，正如人们所期望的那样。以下是示例代码：

    ```js
    $.mobile.changePage("#"+data.pageId);
    ```

+   首先通过选择要更改的页面来创建一个 jQuery 对象。然后，将该 jQuery 对象传递到`$.mobile.changePage`函数中。结果是页面被显示，但 URL 永远不会更新，因此它不会存在于浏览器的历史记录中。这在用户刷新页面时重新开始第一个屏幕的过程时可能会有用。它防止了通过书签进行深度链接到多页布局中的其他页面。以下是一个示例：

    ```js
    var $newPage = $("#"+data.pageId);     
    $.mobile.changePage($newPage);
    ```

# 生成的页面和 DOM 负载管理

在正常情况下，当在传统移动站点上浏览时，jQuery Mobile 将每个页面标记为`external-page`，这将导致用户导航离开该页面后从 DOM 中移除该页面。这样做的理念是，它将管理 DOM 的负载，因为“预算”（糟糕的）设备可能没有足够的内存来专用于其浏览器。外部页面很可能仍然在设备缓存中以便快速召回。因此，重新加载它们应该是极快的。如果你想了解 jQuery Mobile 如何处理此行为，请查看[`jquerymobile.com/demos/1.3.0/docs/pages/page-cache.html`](http://jquerymobile.com/demos/1.3.0/docs/pages/page-cache.html)。

jQuery Mobile 通过正常手段很好地管理 DOM 的负载。然而，当我们动态创建页面时，它们不会在退出时自动从 DOM 中删除。如果有很多这样的页面，这可能会变得非常压倒性。我们很容易就会压垮愚蠢手机上的可怜浏览器，甚至一些早期型号或预算智能手机也是如此。如果动态创建的页面可能在会话中再次查看，则将其留在 DOM 中可能是值得的。然而，由于我们开始时是在浏览器中生成它，所以将页面重新呈现可能更安全更快速。

在页面呈现完成但在页面初始化之前，你可以使用这行代码标记一页删除：

```js
$("#"+pageId).attr( "data-" + $.mobile.ns + "external-page", true ).one( 'pagecreate', $.mobile._bindPageRemove );
```

### 注意

**警告**：这行代码基本上是直接从库代码中来的。这就是它们在幕后是如何做的。请注意，`$.mobile._bindPageRemove`以一个下划线开头。这里我们没有处理一个公共方法。

这段代码是 API 的一个未记录和非官方部分，这意味着它可能在任何发布的版本中被更改。这对于框架的核心部分来说，我怀疑它们会更改；但是，任何时候当你开始引入依赖于非公开 API 的代码时，你都面临着升级可能在发布说明中没有任何警告的情况下破坏你的代码的风险。可以自由使用，但是务必对每个库的升级进行彻底测试。

# 利用 RSS 源

我能说什么呢？正是我的编辑让我这么做的。最初我并没有计划围绕 RSS 构建任何东西。我很高兴他们这样做，因为经过调查，发现被 RSS 提供的信息要比 JSON 信息源要多得多。我觉得数字世界比它实际上发展得更多。所以，Usha，谢谢你让我包括这个。

首先，如果我们不使用服务器端代理，我们将立即遇到同一源策略的严苛限制。示例包括 PHP 系统中的 cURL，Java 中的 Apache HTTP Core 组件，或者是.NET 平台上的 HttpWebRequest 等。

以下是我在 PHP 中创建的页面，利用 cURL 抓取 Ars Technica 的信息流。这个文件的源代码在本章的代码包中的`ars.php`中。

```js
<?PHP 

//based on original example from…
//http://www.jonasjohn.de/snippets/php/curl-example.htm

//is cURL installed yet? 
if (!function_exists('curl_init')){     
  die('Sorry cURL is not installed!'); 
}  

// OK cool. Then, let's create a new cURL resource handle 
$ch = curl_init();  

// Now set some options (most are optional)  
// Set URL to download 
curl_setopt($ch, CURLOPT_URL, "http://feeds.arstechnica.com/arstechnica/index?format=xml");  

// Set a referer 
curl_setopt($ch, CURLOPT_REFERER, "http://bookexample/chapter5");  

// User agent 
curl_setopt($ch, CURLOPT_USERAGENT, "BookExampleCurl/1.0");  

// Include header in result? (0 = yes, 1 = no) 
curl_setopt($ch, CURLOPT_HEADER, 0);  

// Should cURL return or print out the data? 
// (true = return, false = print) 
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);  

// Timeout in seconds 
curl_setopt($ch, CURLOPT_TIMEOUT, 10);  

// Download the given URL, and return output 
$output = curl_exec($ch);  

// Close the cURL resource, and free system resources curl_close($ch);  

echo $output; 
?>
```

### 注意

**警告**：cURL 和其他服务器端代理库非常强大，因此也非常危险。*不要*把你想要访问本页的 URL 参数化。硬编码 URL。如果你必须从调用 URL 获取参数来构建你的目标地址，那么*你必须转义所有的参数*。如果不这样做，可以肯定的是总有一天，黑客会利用你的网站进行跨站脚本(XSS)攻击([`www.owasp.org/index.php/Cross-site_Scripting_(XSS)`](https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)))。

接下来，让我们在顶部添加一些按钮。一个是我们的 Twitter 源，一个是 Ars Technica 的。下一部分的最终来源将在本章的代码包中的`index.html`文件中：

```js
<div data-role="header">
  <h1>News</h1>
</div>     
<div data-role="footer"> 
 <div data-role="navbar"> 
 <ul> 
 <li><a id="twitter" href="#" class="ui-btn-active">Twitter</a></li> 
 <li><a id="ars" href="#">Feed</a></li> 
 </ul> 
 </div> 
</div>
<div data-role="content">	         
  <ul id="results" data-role="listview" data-dividertheme="b"></ul>   
</div> 
```

接下来，让我们添加脚本来加载信息流：

```js
function loadArs(){
  //scroll back up to the top     
  $.mobile.silentScroll(0);          

  //Go get the Ars Technica feed content     
  $.ajax({       
    url:"ars.php",        
    dataType:"xml",       
    success: function(data, textStatus, jqXHR) {         

      //Store the response for later use           
      localStorage.setItem("ars", jqXHR.responseText);            
      //prepare the content for use         
      var $feed = $(data);                  

      //prepare a list divider with the title of the feed.	var listView = "<li data-role='list-divider'>"+$feed.find("channel>title").text()+"</li>";                  
     //loop through every feed item and 
     //create a listview element.          
      $feed.find("channel>item").each(function(index){             var $item = $(this);           
        listView += "<li><a href='javascript://' "
          +"data-storyIndex='"+index
          +"' class='arsFeed'><h3>"
          +$item.find("title").text()
          +"</h3><p>"+$item.find("pubDate").text()
          +"</p></a></li>";         
      });                  

      //put the new listview in the main display          
      $("#results").html(listView); 

      //refresh the listview so it looks right         
      $("#results").listview("refresh");   

     //place hooks on the newly created links         
      //so they trigger the display of the         
      //story when clicked         
      $("#results a.arsFeed").click(function(){         

        //get the feed content back out of storage                var arsData = localStorage.getItem("ars");                 
        //figure out which story was clicked and       
        //pull that story's content from the item             var storyIndex = $(this).attr("data-storyIndex");
        var $item =   
          $(arsData).find("channel>item:eq("+storyIndex+")");                     
        //create a new page with the story content                var storyPage = "<div id='ars"+storyIndex+"' "
          +"data-role='page' data-add-back-btn='true'>"
          +"<div data-role='header'><h1>Ars Technica</h1>"
          +"</div><div data-role='content'><h2>"
          +$item.find('title').text()+"</h2>"
          +$item.find('content\\:encoded').html()
          +"</div></div>";                      

        //append the story page to the body 	        
        $("body").append(storyPage);                   
        //find all the images in the newly  	        
        //created page.          
        $("#ars"+storyIndex+" img").each(function(index, element) {                         
          var $img = $(element);                         
          //figure out its currentWidth             
          var currentWidth = Number($img.attr("width"));                          
          //if it has a width and it's large             
          if(!isNaN(currentWidth) && currentWidth > 300){              
            //remove the explicit width and height                  $img.removeAttr("width").removeAttr("height");               
            //make the image scale to the width                     //of it's container but never to be                      //larger than its original size                          
            $img.css({"max-width":currentWidth
              +"px","width":"100%"});             
          }
        });

        //switch to the new page             
        $.mobile.changePage("#ars"+storyIndex);        
      });
    }
  });   
}

$("#ars").click(loadArs); 
```

这是我们的新的 RSS 阅读器的样子！

![利用 RSS 源](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_05_01.jpg)

## 强制响应式图片

当你从一个页面导入内容，而你无法控制内容中嵌入的图片时，你可能需要调整它们以在移动设备上显示正确。就像上一个例子一样，我发现最好是移除图片本身的显式宽度和高度，并使用 CSS 使其填充当前容器的 100%。然后，使用 CSS 的`max-width`属性来确保图像不会被放大超出其原始意图的尺寸。

虽然在加载适合分辨率的不同尺寸的图像方面并没有真正性能响应，但我们已经使用我们有限的资源达到了相同的可见效果，对于这样的情况。

# HTML5 Web 存储

如果你还没有尝试过 HTML5 Web 存储，它其实可以相当简单。如果已经尝试过了，可以跳到下一段。实际上只有两种 web 存储形式：`localStorage`，和 `sessionStorage`。`localStorage` 将永久地保存信息。`sessionStorage` 只在单个会话的周期内保存。这是一个简单的键值配对系统。所有东西都是基于字符串的。因此，一旦你从存储中提取出来，你需要根据需要将这些值转换为其他格式。查看 [`www.w3schools.com/html5/html5_webstorage.asp`](http://www.w3schools.com/html5/html5_webstorage.asp) 获取更多详细信息。

现在，关于会话的定义就变得有趣了。*不要混淆*你服务器上的会话和浏览器会话。你服务器上的用户会话可能在大概 20 分钟内就会过期。然而，只是因为你服务器上的会话已经过期，并不意味着你的浏览器知道这一点。*HTML5 会话存储会一直持续到浏览器实际关闭。* 

这在移动浏览器上就特别棘手了。在安卓和 iOS 系统中，当你切换任务或按下主屏幕按钮时，浏览器并不会真正关闭。在这两种情况下，你必须使用任务关闭功能来完全关闭浏览器。这是最终用户可能并不会自己去做的事情。

但是，关于 web 存储有何不同之处呢？为什么不只是用 cookie 在客户端上存储信息呢？毕竟，这会适用于每个人，对吧？是的，cookie 会适用于每个人。然而，它们从来就不是用来存储大量数据的，就像我们在这个例子中使用的那样，并且每个域名可以存储的 cookie 数量也有软上限（根据浏览器的不同，从 20 到 50 不等）。试图使用 cookie 在客户端存储的最糟糕的一面是，它们随着每个资源的请求一起发送回服务器。这意味着每个 CSS、JS、图像以及页面/Ajax 请求都会携带着所有 cookie 以其有效荷载。你可以看到这样会很快降低你的性能。添加一个 cookie 可能导致数据被传输多次，仅用来渲染一个页面。

## 基于浏览器的数据库（进展中）

基于浏览器的数据库目前处于极端波动状态。实际上，目前有两种不同的标准。第一种是 **Web SQL Database** ([`www.w3.org/TR/webdatabase/`](http://www.w3.org/TR/webdatabase/))。你可以使用它，但根据 W3C 的说法，这个规范已经不再活跃。许多浏览器已经实现了 Web SQL Database，但它能够存活多久呢？

W3C 已经声明，浏览器上数据库的方向将是**Indexed Database**（[`www.w3.org/TR/IndexedDB/`](http://www.w3.org/TR/IndexedDB/)）。工作草案的编辑来自微软、谷歌和 Mozilla；因此，我们可以期待未来有广泛的支持。问题是，工作草案于 2012 年 5 月 24 日发布。截至我写这一章时，只有 Firefox、Chrome 和 Internet Explorer 10 支持 IndexedDB（[`en.wikipedia.org/wiki/Indexed_Database_API`](http://en.wikipedia.org/wiki/Indexed_Database_API)）。

## JSON 拯救了我们

目前，我们发现自己处于一个极其糟糕的境地，要么使用一个丑恶的数据库，要么等待所有人都跟上新规范。在不久的将来，Web 存储看起来是唯一的安全选择。那么，我们如何最好地利用它呢？当然是用 JSON！所有主要浏览器都原生支持 JSON。

想想我们过去一直处理关系数据库的方式。作为面向对象的程序员，我们总是进行查询，然后将结果数据转换成内存中的对象。我们几乎可以通过使用`JSON.stringify`方法将 JSON 直接存储到 Web 存储中，以几乎相同的方式来做完全相同的事情。

这里有一个例子，用来测试你的系统是否原生支持 JSON。源文件在本章的代码包中的`jsonTest.html`。

```js
<!DOCTYPE html>  
<html>  
<head>   
  <title>JSON Test</title>  
</head>    
<body>    
<script type="text/javascript">   

  var myFeedList = {     
    "lastUpdated":"whenever",     
    "feeds":[        
    {         
       "name":"ars",         
    "url":"http://feeds.arstechnica.com/arstechnica/index?format=xml" 	    
    },       
    {       
      "name":"rbds",            
      "url":"http://roughlybrilliant.com/rss.xml"       
    }     
    ]   
  }     

myFeedList.lastUpdated = new Date(); 

localStorage.feedList = JSON.stringify(myFeedList);      

var myFeedListRetrieved = JSON.parse(localStorage.feedList);      
alert(myFeedListRetrieved.lastUpdated); 
</script>  
</body> 
</html>
```

如果一切正常，你将看到一个包含时间戳的警报。

如果出于某种原因，你发现自己不幸地必须支持一些过时的系统（Windows Phone 7 和 BlackBerry 5 或 6，我正在看着你），请从[`github.com/douglascrockford/JSON-js`](https://github.com/douglascrockford/JSON-js)获取`json2.js`并将其包含在其他脚本中。然后，你将能够 stringify 和 parse JSON。

# 利用 Google Feeds API

所以，我们已经看到了如何原生地拉取一个普通的 RSS 订阅，解析，并使用正常而乏味的字符串拼接构建页面。现在，让我们考虑一种替代方案，我在开始写这一章时甚至不知道它的存在。感谢雷蒙德·卡姆登和安迪·马修斯在他们的书《jQuery 移动 Web 开发要点》中指出这一点。你需要在 Twitter 上关注他们两个，`@cfjedimaster`和`@commadelimited`。

Google Feeds API 可以提供多种选择，但它的核心是指定 RSS 或 ATOM 订阅并返回 JSON 表示。当然，这在这一章节中开启了更多有趣的可能性。如果我们现在可以获取不同类型的多个订阅，而无需任何服务器端代理，我们可以极大地简化我们的生活。客户端模板再次出现！不再需要字符串拼接！因为它们都是统一格式（包括发布日期），我们可以把它们全部整合到一个主视图中，所有订阅故事按日期排序。

按其属性对对象进行排序实际上相当简单。你只需要传递一个比较函数。以下代码是我们将用于日期的：

```js
function compareDates(a,b) {     
  var aPubDate = Date.parse(a.publishedDate);     
  var bPubDate = Date.parse(b.publishedDate);     
  if ( aPubDate < bPubDate) return 1;     
  if (aPubDate > bPubDate)  return -1;     
  return 0;   
}
```

现在，让我们指定一个 JSON 对象来存储我们想要使用的 feeds：

```js
var allFeeds = {   

  //all the feeds we want to pull in 	
  "sources":[       
"http://feeds.arstechnica.com/arstechnica/index?format=xml", 
"http://rss.slashdot.org/Slashdot/slashdot",       
"http://www.theregister.co.uk/headlines.atom"     
],   

  //How many of the feeds have responded?  Once all have 
  //responded, we'll finish our processing.  
  "sourcesReporting":0,   

  //This is where we will store the returned stories.	
  "entries":[]   
}; 
```

接下来，我们将使用我们的处理函数来处理传入的故事：

```js
function assimilateFeed(data){   

  //Mark another feed as having reported back  
  allFeeds.sourcesReporting++; 

  //Grab the title of this feed    
  var feedTitle = data.responseData.feed.title; 

  //Loop through every entry returned and add the feed title
  //as the source for the story		
  for(x = 0; x < data.responseData.feed.entries.length; 
    data.responseData.feed.entries[x++].source=feedTitle); 

  //Join this field's entries with whatever entries might have 
  //already been loaded
  allFeeds.entries = allFeeds.entries.concat(data.responseData.feed.entries); 

  //If all the feeds have reported back, it's time to process
  if(allFeeds.sourcesReporting == allFeeds.sources.length){ 

    //Sort all the stories by date
    allFeeds.entries.sort(compareDates);   

   //Take the results that have now all been combined and
    //sorted by date and use jsRender 
    $("#results").html($("#googleFeedTemplate")
      .render(allFeeds)).listview("refresh");         
  }   
} 
```

这是我们的 JsRender 模板：

```js
<script type="text/x-jsrender" id="googleFeedTemplate">   
  {{for entries}}     
    <li>       
      <a href="{{:link}}" target="_blank">         
        <h3>{{:title}}</h3>          
        <p><strong>{{:source}}</strong> - {{:publishedDate}}
          <br/>{{:contentSnippet}}
        </p>
      </a>
    </li>   
  {{/for}} 
</script>
```

最后，这是将启动整个过程的函数：

```js
$("#feeds").click( function() {  

  //Reset the number of received feeds
  allFeeds.sourcesReporting = 0;     

  //Get back to the top of the page
  $.mobile.silentScroll(0);     

  //Loop through all the feeds
  for(var x = 0; x < allFeeds.sources.length; x++){       
    $.ajax({   

//Call to Google's Feed API with the URL encoded      
url:"https://ajax.googleapis.com/ajax/services/feed/load?v=1.0&output=json&q="+escape(allFeeds.sources[x]),          
      dataType:"jsonp",         
      success:assimilateFeed       
    });
  }   
});
```

我已将此包含在我的 `challenge.html` 文件的功能示例中，但源代码要比这深得多。`challenge.html` 的源代码还有几个隐藏的宝藏供你发现。我还添加了 Reddit、Flickr 和本地搜索 Twitter。

# 总结

你已经被呈现了一个非常广泛的客户端模板选择。在这一点上，你现在知道如何利用 JSON 和 JSONP 并有效地将它们结合起来动态创建页面。RSS 对你来说也不会是真正的挑战，因为你可以本地或使用 Google Feeds 来处理。

在下一章中，我们将结合一些这些技术，继续构建我们的技术工具箱，并将目光转向 HTML5 音频。


# 第六章：HTML5 音频

让我们把迄今为止学到的东西转向音乐领域。我们将把 jQuery Mobile 界面转化为一个媒体播放器、艺术家展示和信息中心，并可以保存到人们的主屏幕上。

在这一章中，我们将涵盖：

+   HTML5 音频（渐进增强方式）

+   固定位置，持久工具栏（真的！？）

+   HTML5 音频的自定义 JavaScript 控件

+   iOS 中的 HTML5 音频及其区别

+   全能解决方案（多页面实用）

+   使用 HTML5 清单将内容保存到主屏幕

# HTML5 音频

与琳赛·施特林问好。琳赛在美国达人秀第五季上首次登场。你看过小提琴手*摇滚表演*吗？自她在全国舞台上的表现以来，她在 YouTube 上的视频每个都有数百万次观看。2012 年 9 月 18 日，她发布了她的首张同名专辑。这一章将是对她的音乐和数字存在的粉丝致敬。如果你想要完整的体验，就去她的 YouTube 频道[`youtube.com/lindseystomp`](http://youtube.com/lindseystomp)。她的 200 万订阅者不会错！

![HTML5 音频](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_06_00.jpg)

现在，回到正题。正如我们迄今所见，jQuery Mobile 使一切变得容易。你几乎必须要尝试才能把事情搞复杂。HTML5 音频可以像你希望它那样复杂，我们会到那一步的。现在，让我们看看把音频带入你的 jQuery Mobile 页面有多么简单。考虑下面的代码片段：

```js
<audio id="audio" controls>                     
  <source src="img/electricdaisy.mp3" type="audio/mpeg" />
  <source src="img/electricdaisy.ogg" type="audio/ogg" />
   Your browser is so old that you can't hear the music.
</audio>
```

就是这样。这就是在上一张图片中得到音乐控制条所需的全部内容。我们来稍微分解一下。

就像在第四章的视频中一样，*二维码，地理定位，谷歌地图 API 和 HTML5 视频*，`音频`标签可以支持多个来源，浏览器将简单地选择它知道如何处理的第一个。老旧的浏览器将毫无头绪，只会简单地解析这个像 XML，这意味着唯一显示的是文本，“你的浏览器太老了，无法播放音乐。”

每个浏览器都提供自己的本机界面来控制音频。有些像 iOS 版本那样又小又亮，而有些则完全丑陋但更可用，比如 Android。无论如何，它们都有所不足，所以让我们把 jQuery Mobile 变成一个媒体播放器。

这是我们的基本起始页面。你可以在代码文件中的`electricdaisy_basic.html`中找到其源代码：

```js
<!DOCTYPE html>  
<html>  
  <head> 
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">     
    <link href='chapter6.css' rel='stylesheet' type='text/css'> 
    <title>Lindsey Sterling</title>
    <link rel="stylesheet" href="http://code.jquery.com/mobile/1.3.0/jquery.mobile-1.3.0.min.css" />
    <script src="img/jquery-1.8.2.min.js"></script>
    <script type="text/javascript" src="img/global.js"></script> 
    <script src="img/jquery.mobile-1.3.0.min.js"></script> 
    <link rel="stylesheet" href="chapter6.css" /> 
  </head>    
<body>      
<div id="electricdaisy" class="songPage" data-role="page" >
  <div data-role="header">
    <a href="basic.html" data-transition="slidedown" data-theme="c" data-icon="home" data-iconpos="notext">Home</a> 
    <h2>Lindsey Sterling</h2>             
    <a class="ui-btn-right" data-transition="slidedown" data-theme="c" href="tracklist.html" data-icon="note" data-iconpos="notext" >Music</a>         
  </div>         
  <div data-role="content">
    <img alt="cover art" src="img/electricdaisy.jpg" width="100%" />             
    <p>                 
      <audio id="audio" controls>
        <source src="img/electricdaisy.mp3" type="audio/mpeg" />
        <source src="img/electricdaisy.ogg" type="audio/ogg" />
        Your browser is very old so that you can't hear the music.
      </audio>             
    </p>         
  </div>     
</div> 
</body> 
</html>
```

这个构建良好的 jQuery Mobile 页面除了美化之外无需任何 JavaScript。你可以关闭 JS，整个页面仍能正常工作，还能播放音乐。对于所有的渐进增强粉丝来说，我们正从正确的角度开始。毕竟，每个人都是音乐的粉丝，不仅仅是智能手机用户。

现在让我们看看如何使用 JavaScript 和固定位置工具栏来创建更好的控制界面。

# 固定位置的持续工具栏（真的！？）

我要诚实地说；我对移动空间中的固定位置工具栏的看法普遍很低。从可用性的角度来看，它们是一场灾难。移动屏幕本来可用空间就很少。在没有为用户提供*强大*的好处的情况下浪费更多的屏幕空间是不可想象的。此外，由于涉及到的 CSS，古老版本的 Android（低于版本 2.3）将不支持固定位置工具栏。

<rant>然而，我们经常看到这种情况，不是吗？公司把他们的标志贴在永远不会消失的顶部工具栏上。他们加上一点全局导航，并称之为对用户的一个好处，而实际上这完全是为了加强他们的品牌形象。你可以从工具栏上唯一的可交互部分——一个菜单按钮和可能的一个搜索按钮上看出来（好像我们不能再次在顶部找到它们一样）。有许多更好的技术来提供全局导航。</rant>

![固定位置的持续工具栏（真的！？）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_06_01.jpg)

今天，我们有一个合理的用途来使用这些工具栏。我们将在其中放置音乐控制，这些音乐控制将随着我们切换曲目而持续存在。如果我们做得对，这个音乐网站将更像一个应用程序，并让用户始终控制设备发出的声音。

如果你已经玩过 jQM UI 的这一部分，请立即跳到下一段。

使工具栏固定（滚动时不移动）和持续（在更改页面时不移动）其实很简单。你所要做的就是添加 `data-position="fixed"` 来使其固定，然后在你想要页脚在页面转换时保持不动的页面上添加 `data-id="whatever"` 给页脚。这个功能也适用于头部。

这是我们持续页脚的基础：

```js
<div class="jsShow playcontrols" data-role="footer" data-id="playcontrols" data-position="fixed">         
  <div class="progressContainer">
    <input  data-theme="b" data-track-theme="c" class="progressBar" type="range" name="slider-1"  value="0" min="0" max="227" data-mini="true"/></div>         
  <div data-role="navbar" class="playcontrols">             
    <ul>                 
      <li><a data-theme="c" title="skip back" class="skipback" href="#crystallize" data-direction="reverse"><img src="img/sg_skipback2x.png" alt="Skip Back" height="14"/></a></li>                     
      <li><a data-theme="c" title="seek back" class="seekback" href="javascript://"><img src="img/sg_rw@2x.png" alt="Seek Back" height="14"/></a></li>                     
      <li><a data-theme="c" title="play/pause" class="play" href="javascript://"><img src="img/49-play@2x.png" alt="Play/Pause" height="14"/></a></li>                     
      <li><a data-theme="c" title="seek forward" class="seek" href="javascript://"><img src="img/sg_ff@2x.png" alt="Seek Forward" height="14"/></a></li>                     
      <li><a data-theme="c" title="skip forward" class="skip" href="#shadows"><img src="img/sg_skip@2x.png" alt="Skip Forward" height="14"/></a></li>
      </li>             
    </ul>         
  </div>     
</div> 
```

见到页脚顶部的那个类（`jsShow`）了吗？让我们在围绕`audio`标签的段落中添加另一个类（`jsHide`）：

```js
<p class="jsHide">                 
  <audio id="audio" controls>                     
…            
</p>
```

在 CSS 中，让我们添加以下规则：

```js
.js .jsHide{display:none} 
.no-js .jsShow{display:none;}
```

然后我们将在我们的 `global.js` 文件中添加一行代码来将整个内容组合在一起：

```js
$("html").removeClass("no-js").addClass("js");
```

这是 HTML5 模板 ([`html5boilerplate.com/`](http://html5boilerplate.com/)) 和 Modernizer ([`modernizr.com/`](http://modernizr.com/)) 使用的一种技术。如果你还没有看过这两个奇迹，那值得你的时间。简单来说，我们现在有了一种方便、轻量级的处理渐进增强的方法。对于那些需要帮助的人，语音辅助也非常完美。

现在，我们离一个好用的通用媒体播放器 UI 很近了，但是如果你一直在输入代码，你可能已经注意到输入`type="range"`正在显示一个文本框。单独看这可能不算太糟糕，但 HTML5 音频以秒为单位跟踪其当前位置，这使得它作为显示元素相当无用。所以，让我们隐藏它，并通过一些简单的 CSS 扩展一下进度条：

```js
input.progressBar{display:none} 
div.ui-slider{width:90%;}  
```

现在，我们看起来不错了，让我们将它们连接起来使其工作。

# 用 JavaScript 控制 HTML5 音频

好了，现在我们开始用 JavaScript 变得有点复杂了。

首先，让我们设置一个间隔来更新进度条。它将有两个功能，显示当前时间和更改时间。我们将首先添加对这些对象的引用，并为我们可能想要附加到的每一个音频事件放置事件挂钩。注释描述了何时触发哪些事件：

```js
//for every song page 
$(document).on("pagecreate", ".songPage", function(){ 
  var $page = $(this);	
  var $currentAudio = $page.find("audio");

  //set references to the playing status, progress bar, and 
  //progress interval on the audio object itself 
  $currentAudio.data("playing",false) 
    .data("progressBar", $page.find("input.progressBar")).data("progressThread",null); 

  //loadstart and progress occur with autoload
  $currentAudio[0].addEventListener('loadstart', function(){ 
    //Fires when the browser starts looking 
    //for the audio/video
  }, false);

  $currentAudio[0].addEventListener('progress', function(){ 
    //Fires when the browser is downloading the audio/video
    //This will fire multiple times until the source 
    //is fully loaded.
  }, false); 

  //durationchange, loadedmetadata, loadeddata, canplay, 
  //canplaythrough are kicked off upon pressing play 
  $currentAudio[0].addEventListener('durationchange', 
  function(){ 
    //Fires when the duration of the audio/video is changed 

  }, false); 

  $currentAudio[0].addEventListener('loadedmetadata', 
  function(){
    //Fires when the browser has loaded meta data 
    //for the audio/video 

  }, false); 

  $currentAudio[0].addEventListener('loadeddata', function(){ 
    //Fires when the browser has loaded the current 
    //frame of the audio/video 

  }, false);

  $currentAudio[0].addEventListener('canplay', function(){  
    //Fires when the browser can start playing 
    //the audio/video 	

  }, false); 

  $currentAudio[0].addEventListener('canplaythrough', 
  function(){ 
    //Fires when the browser can play through the audio/video 
    //without stopping for buffering 

  }, false); 

  $currentAudio[0].addEventListener('ended', function(){ 
    //Fires when the current playlist is ended 

  }, false); 

  $currentAudio[0].addEventListener('error', function(){ 
    //Fires when an error occurred during the loading 
    //of an audio/video 

  }, true);  

}); 
```

现在，让我们创建运行间隔的函数：

```js
function scrubberUpdateInterval(){ 

  //Grab the current page 
  var $page = $.mobile.activePage; 

  //Grab the audio element 
  var $audio = $page.find("audio"); 
  var currentAudio = $audio[0]; 

  //Grab the progress monitor and the handle 
  currentAudioProgress = $page.find("input.progressBar"); 
  scrubberHandle = currentAudioProgress
    .closest(".progressContainer")
    .find("a.ui-slider-handle"); 

  //Is the user currently touching the bar? 	
  if(scrubberHandle.hasClass("ui-focus")){ 
    //Pause it if it's not paused already 
    if(!currentAudio.paused){  
      currentAudio.pause(); 
    } 

    //Find the last scrubber's last position 
    var lastScrubPosition = currentAudioProgress
      .data("lastScrubPosition"); 
    if(lastScrubPosition == null) lastScrubPosition = 0; 
    //Are we in the same place as we were last? 
    if(Math.floor(lastScrubPosition) == 
    Math.floor(currentAudio.currentTime)){ 
      var lastScrubUnchangedCount = currentAudioProgress
       .data("lastScrubUnchangedCount");
      //If the user held still for 3 or more cycles of the 
      //interval, resume playing  
      if(++lastScrubUnchangedCount >= 2){ 
        scrubberHandle.removeClass("ui-focus"); 
        currentAudioProgress 
          .data("lastScrubUnchangedCount", 0); 
        currentAudio.play(); 
      }else{ 
        //increment the unchanged counter 
        currentAudioProgress.data("lastScrubUnchangedCount", 
        lastScrubUnchangedCount); 
      } 
    }else{ 
      //set the unchanged counter to 0 since we're not in the 
      //same place 
      currentAudioProgress
        .data("lastScrubUnchangedCount", 0); 
    } 

    //set the last scrubbed position on the scrubber 
    currentAudioProgress.data("lastScrubPosition", 
      Number(currentAudioProgress.val())); 
    //set the current time of the audio 
    currentAudio.currentTime = currentAudioProgress.val(); 
  }else{ 
    //The user is not touching the scrubber, just update the 
    //position of the handle 
    currentAudioProgress
      .val(currentAudio.currentTime)
      .slider('refresh');  
  } 
}  
```

当点击播放按钮时，我们将启动间隔并执行其他必要的操作。和往常一样，所有内容都有很好的注释：

```js
$(document).on('vclick', "a.play", function(){ 
  try{ 
    var $page = $.mobile.activePage; 
    var $audio = $page.find("audio"); 

    //toggle playing 
    $audio.data("playing",!$audio.data("playing")); 
    //if we should now be playing 
    if($audio.data("playing")) { 

      //play the audio 
      $audio[0].play(); 

      //switch the playing image for pause 
      $page.find("img.playPauseImage")
        .attr("src","images/xtras-gray/48-pause@2x.png"); 
      //kick off the progress interval 
      $audio.data("progressThread",  
        setInterval(scrubberUpdateInterval, 750)); 
    }else{
      //pause the audio 
      $audio[0].pause(); 

      //switch the pause image for the playing audio 
$page.find("img.playPauseImage")
        .attr("src","images/xtras-gray/49-play@2x.png");
      //stop the progress interval
      clearInterval($audio.data("progressThread")); 				
    } 
  }catch(e){alert(e)}; 
});
```

设置搜索控件：

```js
$(document).on('click', "a.seekback", function(){
  $.mobile.activePage.find("audio")[0].currentTime -= 5.0; 
}); 

$(document).on('vclick', "a.seek", function(){
  $.mobile.activePage.find("audio")[0].currentTime += 5.0; 
}); 
```

现在，让我们创建一个 JSON 对象来跟踪我们的当前状态和跟踪列表：

```js
var media = { 
  "currentTrack":0, 
  "random":false, 
  "tracklist":[ 
    "electricdaisy.html", 
    "comewithus.html", 
    "crystallize.html",
    "shadows.html", 
    "skyrim.html" 
  ] 
}
```

接下来，是跳过后退和前进按钮。我们可以设置随机按钮，但现在我们会跳过：

```js
$(document).on('vclick', "a.skipback", function(event){ 
  //grab the current audio 
  var currentAudio = $.mobile.activePage.find("audio")[0]; 
  //if we're more than 5 seconds into the song, skip back to 
  //the beginning 
  if(currentAudio.currentTime > 5){ 
    currentAudio.currentTime = 0; 
  }else{ 
    //otherwise, change to the previous track 
    media.currentTrack--; 
    if(media.currentTrack < 0) media.currentTrack = 
      (media.tracklist.length - 1); 
    $.mobile.changePage("#"+media.tracklist[currentTrack]);
  } 
}); 

$(document).on("vclick", "a.skip", function(event){ 
  //grab the current audio and switch to the next track 
  var currentAudio = $.mobile.activePage.find("audio")[0]; 
  media.currentTrack++; 
  if(media.currentTrack >= media.tracklist.length) 
  media.currentTrack = 0; 
  $.mobile.changePage("#"+media.tracklist[currentTrack]); 
}); 
```

### 提示

**性能注解**

注意我已经不再使用`click`事件，而是现在使用`vclick`事件。`vclick`事件是 jQuery Mobile 中的自定义事件，旨在弥合 click（桌面事件）和 tap/touchstart（触摸事件）之间的性能差距。两者之间通常存在约 300 毫秒的差距，而支持什么样的浏览器是一件难以确定的事情。通过使用`vclick`，您仍然可以支持桌面和触摸设备，但您可以希望获得轻微的性能提升。有关更多信息，请参阅 jQuery Mobile 贡献者之一 John Bender 在 [`coderwall.com/p/bdxjzg`](https://coderwall.com/p/bdxjzg) 的博客文章。

# iOS 中的 HTML5 音频不同

理解 HTML5 音频的事件循环对于使其正常工作至关重要。当您开始混合 jQuery Mobile 的奇怪事件循环时，情况可能会变得特别混乱。再加上一系列因设备而异的资源限制，您就真的会变得很困惑。

作为测试移动站点的快速简便方法，你通常只需打开 Google Chrome（因为它是 WebKit）或 IE9（用于 Windows Phone）并将其缩小到移动尺寸。当然，这不能替代真正的测试。始终要在真实设备上检查你的作品。话虽如此，缩小的浏览器方法通常可以让你达到 97.5% 的目标。好吧... HTML5 音频彻底改变了这种操作模式。

在 iOS 上，即使你已经标记了`audio`标签以预加载和自动播放，它也不会。不会抛出错误；也没有任何迹象表明你的编码请求被完全忽视了。如果你查看本章中包含的代码，你会看到在`basicPlayer.js`脚本中我放了多少 try/catch 和 debug 语句来尝试让它起作用，并找出出了什么问题。

从技术上讲，`pageinit`是文档中说等同于`document.ready`的事件，但这并不意味着页面实际上已经可见。导致页面显示的事件链的最后是`pageshow`事件。所以，不管怎样，那应该是结束，并且应该为你可能想做的任何事情做好准备。在这个时候，你应该（理论上）能够使用 JavaScript 告诉歌曲播放（`.play()`）。然而，事实并非如此。你可以使用完全相同的函数来触发音频播放，甚至延迟一段时间再启动它，但仍然没有任何效果。这不是一个时间问题。iOS 需要直接用户交互才能首次启动音频。*直接将其绑定到点击事件，否则不起作用。*

# 全能解决方案（多页面实用化）

现在我们有了一个完整的播放器，具有统一的界面，可以用来管理播放列表。我们目前唯一真正的问题是网络延迟。即使在这个新的 4G 和 LTE 时代，蜂窝网络的延迟也可能变得荒谬。如果你像我一样在一个像斯巴达的方阵一样阻挡信号的建筑物工作，这一点尤为真实。所以，为了给用户带来更好的体验，我们将放弃这种逐页的方式。

顺便说一句，让我们把我们在之前章节中所做的一些工作也整合进来，比如引入林赛最新的推文和她博客的内容。我们将使用之前的 CSS，但其他方面会有所改变。

![全能解决方案（多页面实用化）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_06_02.jpg)

对于那些对服务器端和面向对象类型的人来说，最令人烦恼的事情之一就是你经常不得不重复一段代码。如果有一个全局头部或页脚，这就成为了一个真正的问题。所以，让我们创建一个`div`标签来容纳通用页脚内容，并创建一个脚本在适当的时候将其引入：

```js
<div id="universalPlayerControls" style="display:none">     
  <div class="progressContainer">
    <input  data-theme="b" data-track-theme="c" class="progressBar" type="range" name="slider-1"  value="0" min="0" max="227" data-mini="true"/>
  </div>     
  <div data-role="navbar" class="playcontrols">         
    <ul>             
      <li><a data-theme="c" title="skip back" class="skipback" href="javascript://" data-direction="reverse"><img src="img/sg_skipback2x.png" alt="Skip Back" height="14"/></a></li>             
      <li><a data-theme="c" title="seek back" class="seekback" href="javascript://"><img src="img/sg_rw@2x.png" alt="Seek Back" height="14"/></a></li>             
      <li><a data-theme="c" title="play/pause" class="play" href="javascript://"><img class="playPauseImage" src="img/49-play@2x.png" alt="Play/Pause" height="14"/></a></li>             
      <li><a data-theme="c" title="seek forward" class="seek" href="javascript://"><img src="img/sg_ff@2x.png" alt="Seek Forward" height="14"/></a></li>             
      <li><a data-theme="c" title="skip forward" class="skip" href="javascript://"><img src="img/sg_skip@2x.png" alt="Skip Forward" height="14"/></a></li>         
    </ul>     
  </div> 
</div>
```

现在，对于任何想要在页脚中具有这些控件的页面加载，我们将在 jQM 标记页面之前将这些内容直接复制到页脚中：

```js
$(document).on("pagebeforecreate", function(){ 
  $(this).find("div[data-id='playcontrols']")
    .html($("#universalPlayerControls").html());
});
```

最后，是时候使每个歌曲页面都变得动态了。我们移除了单独的音频元素，简单地在“页面”的数据属性中链接到它们。页脚消失了，取而代之的是一个空的页脚，准备好注入控件：

```js
<div id="electricdaisy" class="songPage" data-role="page" data-mp3="audio/electricdaisy.mp3" data-ogg="audio/electricdaisy.ogg"> 
  <div data-role="header">
    <a href="#home" data-theme="c" data-icon="home" data-iconpos="notext">Home</a>
    <h2>Electric Daisy</h2>
    <a class="ui-btn-right" data-theme="c" href="#tracklist" data-icon="note" data-iconpos="notext" >Music</a>
  </div>         
  <div data-role="content">         
    <img src="img/electricdaisy.jpg" width="100%" />
  </div>          
  <div data-role="footer" data-id="playcontrols" data-position="fixed"></div> 
</div>
```

所有这些都将要求我们重新调整我们的 JavaScript。一些部分将保持不变，但由于我们只剩下一个音频元素，代码可以简化。以下是在 Packt Publishing 网站提供的代码捆绑包的 `index.html` 文件中的所有合并版本的最终源代码：

```js
<!DOCTYPE html>  
<html>  
<head> 
  <meta charset="utf-8"> 
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1.0, user-scalable=no">     
  <link href='http://fonts.googleapis.com/css?family=Playball' rel='stylesheet' type='text/css'> 
  <title>Lindsey Stirling</title>  
  <link rel="stylesheet" href="jquery.mobile-1.2.0-rc.1.min.css" /> 	
  <script src="img/jquery-1.7.2.min.js"></script>     
  <script type="text/javascript"> 
    $(document).bind("mobileinit", function(){ 
      $.mobile.defaultPageTransition = "slide"; 
    }); 
  </script> 
  <script src="img/jquery.mobile-1.2.0-rc.1.min.js"></script>     
  <script type="text/javascript"
src="img/jsrender.min.js"></script>     
  <link rel="stylesheet" href="chapter6.css" /> 
</head>    
<body id="body">
```

在完成所有常规工作之后，这是体验的第一个“页面”：

```js
  <div id="home" data-role="page" 
    data-mp3="audio/electricdaisy.mp3" 
    data-ogg="audio/electricdaisy.ogg"> 	

    <div data-role="header">
      <h1>Lindsey Stirling</h1>
      <a class="ui-btn-right" data-theme="c" href="#tracklist" data-icon="note" data-iconpos="notext" >Music</a>
    </div>     

    <div data-role="content"> 
      <ul id="homemenu" data-role="listview" data-inset="true"> 
        <li><a href="#news">News</a></li>
        <li><a href="#tour">Tour</a></li>
        <li><a href="#comewithus">Music</a></li>  
      </ul>
      <div id="twitterFeed">
        <ul class="curl"></ul>
      </div>     
    </div>     

    <div data-role="footer" data-id="playcontrols" data-position="fixed">
    </div> 

  </div>  

  <div data-role="page" id="news"> 
    <div data-role="header">
      <a href="#home" data-theme="c" data-icon="home" data-iconpos="notext">Home</a>
      <h2>News/Blog</h2>
    </div>      

    <div data-role="content"></div> 
  </div>  
```

以下页面列出了所有可预览的曲目：

```js
  <div id="tracklist" data-role="page">  
    <div data-role="header">
      <a href="#home" data-theme="c" data-icon="home" data-iconpos="notext">Home</a>
      <h2>Track List</h2>
    </div>        

    <img src="img/lindsey-header-new1.jpeg"  width="100%" alt="signature banner" /> 

    <div data-role="content"> 
       <ul data-role="listview"> 
         <li><a class="trackListLink" href="#electricdaisy">Electric Daisy</a></li> 
         <li><a class="trackListLink" href="#shadows">Shadows</a></li>
         <li><a class="trackListLink" href="#comewithus">Come With Us feat. CSWS</a></li>
         <li><a class="trackListLink" href="#skyrim">Skyrim</a></li>
         <li><a class="trackListLink" href="#crystallize">Crystallize</a></li>
      </ul>     
    </div> 
  </div>  
```

以下是各个歌曲页面。我没有包含每个歌曲页面，因为那只是页面的浪费。你会明白这是如何工作的。请注意，每个页面都有相同的 `data-id` 属性的页脚。以下允许在歌曲之间转换时保持页脚不变：

```js
  <div id="shadows" class="songPage" data-role="page" 
    data-mp3="audio/shadows.mp3" 
    data-ogg="audio/shadows.ogg" >  
    <div data-role="header">
      <a href="#home" data-theme="c" data-icon="home" data-iconpos="notext">Home</a>
      <h2>Shadows</h2>
      <a class="ui-btn-right" data-theme="c" href="#tracklist" data-icon="note" data-iconpos="notext" >Music</a>
    </div>         

    <div data-role="content">         
      <img src="img/shadows.jpg" width="100%" alt="cover art" />     
    </div>          

    <div data-role="footer" data-id="playcontrols" data-position="fixed"></div> 
  </div>  

  <div id="crystallize" class="songPage" data-role="page" 
    data-mp3="audio/crystallize.mp3" 
    data-ogg="audio/crystallize.ogg">  
    <div data-role="header">
      <a href="#home" data-theme="c" data-icon="home" data-iconpos="notext">Home</a>
      <h2>Crystallize</h2>
      <a class="ui-btn-right" data-theme="c" href="#tracklist" data-icon="note" data-iconpos="notext" >Music</a>
    </div>         

    <div data-role="content">         
      <img src="img/crystallize.jpg" width="100%" alt="cover art" /> 
    </div>          

    <div data-role="footer" data-id="playcontrols" data-position="fixed"></div> 
  </div>  

  <div id="electricdaisy" class="songPage" data-role="page" 
    data-mp3="audio/electricdaisy.mp3" 
    data-ogg="audio/electricdaisy.ogg">  
    <div data-role="header">
      <a href="#home" data-theme="c" data-icon="home" data-iconpos="notext">Home</a>
      <h2>Electric Daisy</h2>
      <a class="ui-btn-right" data-theme="c" href="#tracklist" data-icon="note" data-iconpos="notext" >Music</a>
    </div>

    <div data-role="content">
      <img src="img/electricdaisy.jpg" width="100%" alt="cover art" /> 
    </div>          

    <div data-role="footer" data-id="playcontrols" data-position="fixed"></div> 
  </div>  
```

这部分不是页面。这是将被导入到播放歌曲的每个页面中的隐藏式主控制器：

```js
  <div id="universalPlayerControls" style="display:none">     
    <div class="progressContainer">
      <input  data-theme="b" data-track-theme="c" class="progressBar" type="range" name="slider-1"  value="0" min="0" max="227" data-mini="true"/>
    </div>     
    <div data-role="navbar" class="playcontrols">         
      <ul>             
        <li><a data-theme="c" title="skip back" class="skipback" href="javascript://" data-direction="reverse"><img src="img/sg_skipback2x.png" alt="Skip Back" height="14"/></a></li>             
        <li><a data-theme="c" title="seek back" class="seekback" href="javascript://"><img src="img/sg_rw@2x.png" alt="Seek Back" height="14"/></a></li>
        <li><a data-theme="c" title="play/pause" class="play" href="javascript://"><img class="playPauseImage" src="img/49-play@2x.png" alt="Play/Pause" height="14"/></a></li>
        <li><a data-theme="c" title="seek forward" class="seek" href="javascript://"><img src="img/sg_ff@2x.png" alt="Seek Forward" height="14"/></a></li>
        <li><a data-theme="c" title="skip forward" class="skip" href="javascript://"><img src="img/sg_skip@2x.png" alt="Skip Forward" height="14"/></a></li>
      </ul>     
    </div> 
  </div>  

  <div style="display:none;">     
    <audio id="audio" controls></audio>     
  </div>  
```

以下代码是呈现导入的博客内容的模板：

```js
  <script type="text/x-jsrender" id="googleFeedTemplate"> 
    <ul class="curl"> 
      {{for entries}} 	
        <li> 
          <h3 class="ul-li-heading">{{:title}}</h3> 
          <p>{{:publishedDate}}<br>{{:content}}</p> 
        </li> 
      {{/for}} 
    </ul> 
  </script> 
```

以下代码是呈现 Twitter 动态的模板：

```js
  <script type="text/x-jsrender" id="twitterTemplate"> 
    <li class="twitterItem"> 
      <img src="img/{{:user.profile_image_url}}" alt="profile image" class="ui-shadow ui-corner-all" />
      <p>{{:text}}</p> 
    </li> 
  </script> 

  <script type="text/javascript"> 
    var media = { 
      "playing":false, 
      "debug":true,
      "currentTrack":0, 
      "random":false,
      "tracklist":[
        "#electricdaisy",
        "#comewithus",
        "#crystallize",
        "#shadows",
        "#skyrim"
      ] 
    } 

    //a handy little debug function
    var lastDebugTS = (new Date).getTime(); 	
    function debug(str){  
    try{ 
        if(media.debug){ 
          $.mobile.activePage.find("div[data-role='content']")
            .append(""+((new Date()).getTime()-lastDebugTS)+": "+str+"<br/>"); 
          lastDebugTS = (new Date).getTime();} 
      }catch(e){} 
    }   

    //grab the audio and control elements with global 
    //variables since everything is going to use them 
    var currentAudio = $("#audio")[0]; 
    var currentAudioProgress = null; 
    var scrubberHandle = null; 
    var scrubberUpdateSpeed = 750; 
    var progressThread = null; 

    //The ended and durationchange are the only events we 
    //really care about  
    currentAudio.addEventListener('ended', 
      function(){
        $.mobile.activePage.find(".skip").click()
      }, false); currentAudio.addEventListener('durationchange', 
     function(){   
       currentAudioProgress.attr('max',currentAudio.duration)
        .slider("refresh"); 
     }); 

   //On the home page 	
   $("#home").live('pagebeforeshow', function(){ 
     var $page = $(this); 

     //bring in the latest tweet 
$.ajax({url:"http://api.twitter.com/1/statuses/user_timeline.json?screen_name="+escape("LindseyStirling"),  
       dataType:"jsonp", 
       success: function(data) { 
         try{ 
           //parse out any hyperlinks and twitter IDs and turn 
           //them into links 
           var words = data[0].text.split(" "); 
           var newMessage = ""; 
           for(var x = 0; x < words.length; x++){
           var word = words[x]; 
             if(word.indexOf("http") == 0){ 	
               newMessage += "<a href='"+word+"' target='_blank'>"+word+"</a>"; 
             }else if(word.match(/@[a-zA-Z0-9_]*/)){ 
       newMessage += "<a href='http://twitter.com/"+word.substring(1)+"' target='_blank'>"+word+"</a> "; 
             }else{
               newMessage += word+" "; 
             } 
           } 
           data[0].text = newMessage;  
         }catch(e){} 

         //use jsRender to display the message 
        $("#twitterFeed ul")
          .html($("#twitterTemplate")
          .render(data[0])); 
      } 
    }); 

    //if we're not currently playing anything, preload audio 
    //as specified by the page's data- attributes 
    if(!media.playing) { 

      //load MP3 by default   
      if(currentAudio.canPlayType("audio/mpeg")){
         currentAudio.src = $page.attr("data-mp3");
      } 

      //load Ogg for all those purists out there 
      else{ currentAudio.src = $page.attr("data-ogg");} 
      //make it load 
      currentAudio.load();

      //set the progres bar
      currentAudioProgress = $page.find("input.progressBar"); 
      //set the scrubber handle 
      scrubberHandle = currentAudioProgress
        .closest(".progressContainer")
        .find("a.ui-slider-handle"); 
    } 
  });  

  //on the news page 
  $("#news").live('pageshow', function(){ 
    //This import can take a while, show the loading message 
  $.mobile.loading( 'show', {           
      text: "Loading Blog Content",           
      textVisible: true         
    });

    //load the actual content 
    $.ajax({ 
  url:"https://ajax.googleapis.com/ajax/services/feed/load?v=1.0&output=json&q="+escape("http://lindseystirlingviolin.com/feed"),  
      dataType:"jsonp", 
      success: function(data) { 
        //use a jsRender template to format the blog 
        $("#news .ui-content")
          .html($("#googleFeedTemplate")
          .render(data.responseData.feed)); 	   
        //for every image in the news feed, make its width 
        //dynamic with a max width or its original size
        $("#news img").each(function(index, element) { 
         var $img = $(element); 

          //figure out its currentWidth 
          var currentWidth = Number($img.attr("width")); 
          //if it has a width and it's large 
          if(!isNaN(currentWidth) && currentWidth > 300){ 
            //remove the explicit width and height 
     $img.removeAttr("width").removeAttr("height"); 
            //make the image scale to the width 
         //of its container but never to be  
         //larger than its original size 
            $img.css({"max-width":currentWidth+"px","width":"100%"}); 
          } 
        });

        //hide the loading   
        $.mobile.loading("hide");
      }
    });
  }); 

  function setCurrentMediaSources(){ 
    var $page = $.mobile.activePage; 

    //set the audio to whatever is playable 	
    var playableSource = $page.attr("data-mp3"); 
    if(!currentAudio.canPlayType("audio/mpeg")){
      playableSource = $page.attr("data-ogg");
    }
    //set the progress bar and scrubber handles 
    currentAudioProgress = $page.find("input.progressBar"); 
  scrubberHandle = currentAudioProgress
      .closest(".progressContainer")
      .find("a.ui-slider-handle"); 

    //change the source and load it.  
    currentAudio.src = playableSource; 
    currentAudio.load(); 

    //if we're currently play, continue playing 
    if(media.playing){ 
      currentAudio.play(); 
      progressThread = setInterval(scrubberUpdateThread, scrubberUpdateSpeed); 	
    } 
  } 

  $(".songPage").live("pageshow", setCurrentMediaSources); 

  $("[data-role='page']").live("pagebeforecreate", 
  function(){ 
    $(this).find("div[data-id='playcontrols']")
      .html($("#universalPlayerControls").html());
  }); 

  function scrubberUpdateThread(){ 
    //if the scrubber has focus, the scrubber becomes 
    //input instead of status display 
    if(scrubberHandle.hasClass("ui-focus")){ 

    //pause the music for now 
    if(!currentAudio.paused){  
      currentAudio.pause(); 
    } 

    //grab the last position to see if we've moved 
    var lastScrubPosition = 
      currentAudioProgress.data("lastScrubPosition"); 
    if(lastScrubPosition == null) lastScrubPosition = 0; 
    //if the user hasn't scrubbed  
    if(Math.floor(lastScrubPosition) == Math.floor(currentAudio.currentTime)){ 
      var lastScrubUnchangedCount = 
      currentAudioProgress.data("lastScrubUnchangedCount"); 
      if(++lastScrubUnchangedCount >= 2){ 
  //since it's been 3 cycles that we haven't moved, 
        //remove the focus and play
        scrubberHandle.removeClass("ui-focus"); 
        currentAudioProgress.data("lastScrubUnchangedCount", 0); 
        currentAudio.play(); 
      }else{ 

        //store the the current position counter 
        currentAudioProgress.data("lastScrubUnchangedCount", lastScrubUnchangedCount); 
      } 
    }else{ 
      //reset the current position counter 
      currentAudioProgress.data("lastScrubUnchangedCount", 0); 
    } 

    //set the position of the scrubber and the currentTime 
    //position of the song itself  
    currentAudioProgress.data("lastScrubPosition", 
      Number(currentAudioProgress.val())); 
    currentAudio.currentTime = currentAudioProgress.val(); 
  }else{ 
    //update the progress scrubber  
    currentAudioProgress.val(currentAudio.currentTime)
     .slider('refresh');  
  } 
} 

//play button controls
$("a.play").live('click',function(){ 
  try{ 
    //toggle the playing status 
    media.playing = !media.playing; 

    //if we're supposed to playing.. 
    if(media.playing) { 

      //do it and set the interval to watch 	
      currentAudio.play(); 
      progressThread = setInterval(scrubberUpdateThread, scrubberUpdateSpeed); 	

      //switch the playing image for pause 
      $("img.playPauseImage").attr("src","images/xtras-gray/48-pause@2x.png"); 
    }else{ 

      //pause the audio and clear the interval 
      currentAudio.pause(); 

      //switch the pause image for the playing audio 
     $("img.playPauseImage").attr("src","images/xtras-gray/49-play@2x.png"); 

      //kill the progress interval  
      clearInterval(progressThread); 
    } 
  }catch(e){alert(e)}; 
}); 

$("a.seekback").live('click',function(){ 
  //back 5 seconds 
  currentAudio.currentTime -= 5.0; 
}); 

$("a.seek").live('click',function(){ 
  //forward 5 seconds 	
  currentAudio.currentTime += 5.0; 
}); 

$("a.skipback").live('click',function(event){
  //if we're more than 5 seconds into the song, skip 
  //back to the beginning 
  if(currentAudio.currentTime > 5){ 
    currentAudio.currentTime = 0; 
  }else{ 
    //othewise, change to the previous track 
    media.currentTrack--; 
    if(media.currentTrack < 0) media.currentTrack = (media.tracklist.length - 1); 

    $.mobile.changePage(media.tracklist[media.currentTrack],
    {
       transition: "slide", 
       reverse: true 
    }); 
  } 
}); 

$("a.skip").live('click',function(event){ 
  //pause the audio and reset the time to 0 	
  currentAudio.currentTime = 0; 

  //change to the next track 
  media.currentTrack++; 
  if(media.currentTrack >= media.tracklist.length) media.currentTrack = 0; 

  $.mobile.changePage(media.tracklist[media.currentTrack]); 
}); 
</script> 
</body> 
</html>
```

将所有内容构建到一个像这样的巨大的多页应用程序中，你将感受到界面的丝般顺滑。我们在这个文件中使用的 CSS 与独立歌曲文件中使用的完全相同。

# 使用 HTML5 清单保存到主屏幕

伴随着巨大的力量而来的是巨大的责任。这是一个强大的功能。如果你充分利用 HTML5 清单和其他一些元标签，你的应用程序将成为一个全屏、无浏览器边框的应用程序。

![使用 HTML5 清单保存到主屏幕](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_06_04.jpg)

要使你的应用程序在保存并启动时作为全屏应用程序，你需要为你的主屏幕准备图标。它们将是大小为 144、114、72 和 57 像素的正方形。像这样链接到它们：

```js
<link rel="apple-touch-icon-precomposed" sizes="144x144" href="images/album144.png">     
<link rel="apple-touch-icon-precomposed" sizes="114x114" href="images/album114.png">     
<link rel="apple-touch-icon-precomposed" sizes="72x72" href="images/album72.png">     
<link rel="apple-touch-icon-precomposed" href="images/album57.png">     
<link rel="shortcut icon" href="img/images/album144.png">  
```

用户的导航按钮可以在 iOS 上隐藏。请注意，如果你选择这样做，你需要在你的应用程序中提供完整的导航。这意味着你可能想要添加返回按钮。如果你想让应用程序全屏，使用以下标签：

```js
<meta name="apple-mobile-web-app-capable" content="yes">     
<meta name="apple-mobile-web-app-status-bar-style" content="black"> 
```

要使该内容在离线模式下可用，我们将使用清单。清单使用应用程序缓存来存储资产。你可以存储的内容有限。这因设备而异，但可能少于 25 MB。列出你想要按优先级保存的所有内容。要了解清单的所有功能，可以查看 [`www.html5rocks.com/en/tutorials/appcache/beginner/`](http://www.html5rocks.com/en/tutorials/appcache/beginner/)。

这是我们清单的内容。它保存在 `app.manifest` 下：

```js
CACHE MANIFEST
# 2012-09-21:v1
js/jquery-1.7.2.min.js
js/jquery.mobile-1.2.0-rc.1.min.js
js/global.js
js/jsrender.min.js

audio/shadows.mp3
audio/comewithus.mp3
audio/skyrim.mp3
audio/electricdaisy.mp3
audio/crystallize.mp3

jquery.mobile-1.2.0-rc.1.min.css
chapter6.css

images/xtras-gray/sg_skip.png
images/xtras-gray/sg_skip@2x.png
images/xtras-gray/sg_skipback.png
images/xtras-gray/sg_skipback@2x.png
images/xtras-gray/sg_ff.png
images/xtras-gray/sg_ff@2x.png
images/xtras-gray/sg_rw.png
images/xtras-gray/sg_rw@2x.png
images/xtras-gray/48-pause.png
images/xtras-gray/48-pause@2x.png
images/xtras-gray/49-play.png
images/xtras-gray/49-play@2x.png
images/ajax-loader.gif
images/comewithus.jpg
images/crystallize.jpg
images/electricdaisy.jpg
images/shadows.jpg
images/skyrim.jpg
images/wallpaper.jpg
images/cork.jpeg
images/icons-18-black.png
images/icons-18-white.png
images/icons-36-black.png
images/icons-36-white.png
images/note18.png
images/note36.png
```

要使用清单文件，你的网络服务器或 `.htaccess` 将需要配置为返回 `text/cache-manifest` 类型。在 HTML 文件中，你只需将它作为 `html` 标签本身的属性添加即可，像这样：

```js
<html manifest="app.manifest">
```

如果你想清除缓存，你可以随时通过浏览器设置来执行。你也可以通过 JavaScript 控制缓存。我之前提供的链接提供了丰富的细节，如果你真的想深入了解的话。

# 摘要

这是一个内容丰富的章节，尽管开始很简单。但是，你现在基本上已经了解了如何将 HTML5 音频与 jQuery Mobile 结合使用的所有知识。你可以创建出精彩的学术页面，并且甚至可以制作复杂的应用程序以保存到设备中。如果这一章没有吓到你，你确实可以开始为媒体机构和场馆制作一些强大的移动站点。这一章唯一真正缺少的是为艺术家和场馆提供的图片画廊。但是，别担心；在下一章中，我们将创建一个为摄影师展示作品的平台。


# 第七章：完全响应式摄影

我们的手机迅速成为我们的照片相册。摄影师代表着移动网页开发中一种尚未充分开发的市场。但如果你仔细想想，这个市场应该是第一个适应移动世界的。随着发达国家智能手机的普及，智能手机上的电子邮件打开率正在迅速接近 40%，当你阅读这篇文章时，可能已经达到了这个水平 ([`www.emailmonday.com/mobile-email-usage-statistics`](http://www.emailmonday.com/mobile-email-usage-statistics))。

当你收到摄影师的电子邮件，告诉你你的照片已经准备好查看时，你是不是很兴奋，立即尝试查看？然而，有很多精通自己行业的摄影师没有准备好满足新的移动需求的网站：

![完全响应式摄影](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_07_03.jpg)

因此，这一章我们将涵盖以下内容：

+   使用 PhotoSwipe 创建基本画廊

+   支持完整的设备尺寸范围 - 响应式网页设计

+   响应式设计中的文本可读性

+   仅发送所需内容 - RESS

# 使用 PhotoSwipe 创建基本画廊

如果你正在寻找创建照片画廊的最快方法，那么你不会找到比 PhotoSwipe ([`www.photoswipe.com/`](http://www.photoswipe.com/)) 更快的解决方案。它的大小为 82 K，并不算轻，但它几乎可以在 jQuery Mobile 支持的任何 A 或 B 级别上使用。他们的网站称它可以在任何基于 WebKit 的浏览器上使用。这基本上意味着 iOS、Android 和 BlackBerry。这三个大平台都被覆盖了。但是 Windows Phone 呢？好消息！它在那里也表现得非常好。即使 JavaScript 被关闭，PhotoSwipe 也会优雅地退化为合理的按页浏览体验。我们可以从头开始制作一个纯粹的 jQuery Mobile 体验，但实际上... 为什么呢？

再次我将放弃严格地将 JavaScript 和 CSS 完全分离到它们自己的文件中的学术上正确的行为，而是简单地将所有定制的 JavaScript 构建到页面本身。对于本书的目的来说，这样做更容易。我假设如果你在阅读这本书，你已经知道如何正确地分离事物以及原因。

让我们从基础知识开始。大部分来自于他们网站的样板，但我们将从摄影师的角度开始：

![使用 PhotoSwipe 创建基本画廊](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_07_09.jpg)

让我们从 `<head>` 标签的关键部分开始：

```js
<link rel="stylesheet" href="http://code.jquery.com/mobile/1.3.0/jquery.mobile-1.3.0.min.css" />
<link rel="stylesheet" href="mullinax.min.css" />
<link rel="stylesheet" href="photoswipe.css" />
<link rel="stylesheet" href="jquery-mobile.css" />

<script src="img/klass.min.js"></script>
<script src="img/jquery-1.8.2.min.js"></script>	
<script src="img/jquery.mobile-1.3.0.min.js"></script>
<script src="img/code.photoswipe.jquery-3.0.5.min.js"></script>
<script src="img/code.photoswipe.galleryinit.js"></script>
```

### 注意

请注意，我们现在正在使用一个用 **ThemeRoller** 构建的自定义主题 ([`jquerymobile.com/themeroller/`](http://jquerymobile.com/themeroller/))。因此，我们只使用 `jquery.mobile.structure-1.2.0.min.css` 而不是完整的 jQM CSS。`mullinax.min.css` 文件是由 ThemeRoller 生成的，除了结构 CSS 外还包含其他所有必需的内容。

文件`photoswipe.css`、`jquery-mobile.css`、`klass.min.js`和`code.photoswipe.jquery-3.0.5.min.js`都是 PhotoSwipe 样板的一部分。文件名`jquery-mobile.css`有点误导。它实际上更像是一个适配器样式表，使 PhotoSwipe 在 jQuery Mobile 中工作和显示正确。没有它，您的画廊的无序列表看起来就不对了。最初，里面没有太多内容：

```js
.gallery { 
list-style: none; 
padding: 0; 
margin: 0; 
} 
.gallery:after { 
clear: both; 
content: "."; 
display: block; 
height: 0; 
visibility: hidden; 
} 
.gallery li { 
float: left; 
width: 33.33333333%;
} 
.gallery li a { 
display: block; 
margin: 5px; 
border: 1px solid #3c3c3c; 
} 
.gallery li img { 
display: block; 
width: 100%; 
height: auto; 
} 
#Gallery1 .ui-content, #Gallery2 .ui-content { 
overflow: hidden; 
}
```

这个设置在 iPhone 或 Android 手机上是可以的，但是如果您在任何类型的平板电脑或桌面大小的浏览器上查看它，画廊的缩略图可能会变得令人讨厌地太大。让我们看看我们能用媒体查询做些什么来使其具有更具响应性的设计。

# 支持全范围设备尺寸 - 响应式网页设计

**响应式网页设计**（**RWD**）是指使单个页面适应每个设备大小的概念。这意味着，我们不仅仅是在谈论具有 3.5 英寸屏幕的手机。那只是个开始。我们将支持各种尺寸的平板电脑，甚至是桌面分辨率。有关 RWD 概念的更多信息，请参阅[`zh.wikipedia.org/wiki/响应式网页设计`](https://zh.wikipedia.org/wiki/响应式网页设计)。

为了使 RWD 起作用，让我们根据常见设备和分辨率断点设置一些断点。我将从重新定义默认画廊项大小为 50％开始。为什么？在我使用智能手机以纵向模式浏览时，它只是让我感觉更舒适。所以，以下是断点。让我们将它们放入`chapter7.css`中：

```js
.gallery li { 
float: left; width: 50%; }

/* iPhone Horizontal -------------------*/ 
@media all and (min-width: 480px){ 
.gallery li { width: 33.33333333%; } 
} 

/* iPad Vertical -----------------------*/ 
@media only screen and (min-width: 768px) {
.gallery li { width: 20%; } 
}  

/* iPad Horizontal ---------------------*/ 
@media only screen and (min-width: 1024px) {     
.gallery li { width: 16.66666666%; } 
}  

/* Nexus 7 Horizontal ------------------*/ 
@media only screen and (min-width: 1280px) {     
.gallery li { width: 14.285714%; } 
}  

/* Laptop 1440 -------------------------*/ 
@media only screen and (min-width: 1440px) {     
.gallery li { width: 12.5%; } 
}  

/* Monitor 1600 ------------------------*/ 
@media only screen and (min-width: 1600px) {
.gallery li { width: 11.111111%; } 
}  

/* Monitor 1920 ------------------------*/ 
@media only screen and (min-width: 1920px) {     
.gallery li { width: 10%; } 
}  
```

在测试这个设置时，我仔细考虑了我与所观看屏幕之间的平均观看距离。这些分解导致了缩略图在视野中看起来理想的大致相同的百分比。显然，我的一个人的焦点小组在科学角度上毫无意义，所以可以随心所欲地进行调整。

可能会问，为什么不只是使每个图像具有固定大小？为什么不同的分辨率断点？真的很简单，它保持了事物的均匀间距，而不是因为某些显示器或浏览器的调整大小刚好有足够的空间强制换行，而不占用空白。它还有一个额外的好处，对于这本书来说，它展示了将通用样式表分解为使用媒体查询将 jQuery Mobile 站点转换为通用站点的好方法。我们想要进行的任何其他基于分辨率的调整都可以直接放入`chapter7.css`中的适当位置。

脚本`code.photoswipe.galleryinit.js`存在于可下载示例内部的 PhotoSwipe 画廊页面上。我认为它永远不需要根据每个页面进行编辑或自定义，所以我将该脚本块提取到了`code.photoswipe.galleryinit.js`中。以下是代码。不要再想它，因为它现在已经成为自己的小文件，再也不会被看到或听到了：

```js
(function(window, $, PhotoSwipe){ 
$(document).ready(function(){ 
  $(document) 
    .on('pageshow', 'div.gallery-page', function(e){ 
       var  currentPage = $(e.target), 
       options = {}, 
       photoSwipeInstance = $("ul.gallery a", e.target)
      .photoSwipe(options,  currentPage.attr('id')); 
       return true; 
    })  
   .on('pagehide', 'div.gallery-page', function(e){ 
      var currentPage = $(e.target), 
      photoSwipeInstance = 
      PhotoSwipe.getInstance(currentPage.attr('id'));
      if (typeof photoSwipeInstance != "undefined" 
      && photoSwipeInstance != null) { 
        PhotoSwipe.detatch(photoSwipeInstance); 
      } 
     return true; 
   }); 
}); 
}(window, window.jQuery, window.Code.PhotoSwipe));
```

现在，让我们考虑一下这些“页面”本身。我们将把这段代码放在`index.html`文件中，并随着进展逐步完善它：

```js
<div id="gallery" data-role="page">
  <div class="logoContainer">
    <img class="logo" src="img/logo.png" alt="Mullinax Photography" />
  </div>
  <div data-role="content">
    <div class="artisticNav">
      <ul data-role="listview" data-inset="true">
        <li><a href="#babies">Babies</a></li>
        <li><a href="#babies">Bellies</a></li>
        <li><a href="#babies">Kiddos</a></li>
        <li><a href="#babies">Families</a></li>
        <li><a href="#babies">Senior</a></li>
        <li><a href="#babies">Other</a></li>
      </ul>
    </div>
  </div><!-- /content -->
</div><!-- /page -->
```

图库屏幕的设计概念如下：

+   全屏照片背景

+   在小屏幕上居中的标志，占屏幕宽度不超过 90%，并且不会超过其原始大小

+   导航仍然应该明显，但不会妨碍艺术本身

以下是我们还将放入`chapter7.css`中的相关 CSS：

```js
.logoContainer{text-align:center;} 
.logoContainer img{width:90%; max-width:438px;} 

#gallery{
background-image:url(backgroundSmall.jpg); 
background-repeat:no-repeat; 
background-position: top center;
} 

.portrait #gallery{ 
background-size:auto 100% !important;
}

.landscape #gallery{
background-size:100% auto !important;
} 

#gallery .ui-btn-up-c { 
background: rgba(255,255,255,.1); 
text-shadow: 1px 1px 0 white; 
background-image: -webkit-gradient(linear,left top,left bottom,from( rgba(255,255,255,.5) ),to( rgba(255,255,255,.7) )); 
background-image: -webkit-linear-gradient( rgba(255,255,255,.5),rgba(255,255,255,.7) ); 
background-image: -moz-linear-gradient( rgba(255,255,255,.5),rgba(255,255,255,.7) ); 
background-image: -ms-linear-gradient( rgba(255,255,255,.5),rgba(255,255,255,.7) ); 
background-image: -o-linear-gradient( rgba(255,255,255,.5),rgba(255,255,255,.7) ); 
background-image: linear-gradient( rgba(255,255,255,.5),rgba(255,255,255,.7) ); 
} 

#galleryNav{ position:absolute; bottom:10px; right:10px; }
```

现在我们只需要一点 JavaScript 来将所有这些联系在一起。当方向改变时，我们希望改变哪个方向占据 100%的背景宽度：

```js
/*Whenever the orientation changes*/
$(window).on("orientationchange", function(event){
  $("body").removeClass("portrait")
    .removeClass("landscape")
    .addClass(event.orientation); 
}); 

/*Prime the body with the orientation on document.ready*/
$(document).ready(function(e) { 
  if($(window).width() > $(window).height()) 
    $("body").addClass("landscape") 
  else 
    $("body").addClass("portrait") 
});
```

这对我们的图库入口页面已经足够了，现在让我们为婴儿照片准备一个示例图库。本章的代码中有许多图库条目。但为了简洁起见，我在这里缩短了代码。同样，这将在代码文件的最终版本`index.html`中。

```js
<div data-role="page" data-add-back-btn="true" id="babies" class="gallery-page">
  <div data-role="header">
    <h1>Babies</h1>
  </div>
  <div data-role="content">
    <ul class="gallery">
      <li><a href="images/full/babies1.jpg" rel="external"><img src="img/babies1.jpg" alt="001" /></a></li>
      <li><a href="images/full/babies2.jpg" rel="external"><img src="img/babies2.jpg" alt="002" /></a></li>
      <li><a href="images/full/babies3.jpg" rel="external"><img src="img/babies3.jpg" alt="003" /></a></li>
      <li><a href="images/full/babies26.jpg" rel="external"><img src="img/babies26.jpg" alt="026" /></a></li>
    </ul>
  </div>
</div>
```

### 注意

如果您没有在每个指向图像的链接上放置`rel="external"`，它将无法正常工作。PhotoSwipe 文档已经很清楚地说明了这一点。如果您还不熟悉`rel="external"`，它是告诉 jQuery Mobile *不要*使用其通常的基于 AJAX 的导航跟随链接的一种方法。因此，它将强制全页加载到您要链接到的任何内容。

现在，只是为了好玩，将其在桌面浏览器中以全宽打开，然后将其缩小到移动设备尺寸，并观察其自适应。尝试使用图库首页、婴儿缩略图库和 PhotoSwipe 提供的幻灯片功能。

PhotoSwipe 的一个很酷的部分是，即使您在移动站点上使用 meta-viewport 标签禁用了缩放，用户仍然可以在全尺寸照片周围捏放和缩放。在平板电脑上非常方便。他们只需双击图像即可返回导航，图像将缩放到原始大小并显示导航。虽然这不是最明显的功能，但返回按钮也可以使用。

自然地，正如名称所暗示的，您可以简单地从一张照片滑动到另一张，并在到达集合末尾时循环回到集合开头。还有一个幻灯片功能，可以无限循环播放。在这两种情况下，如果用户按下返回按钮，他们将被带回缩略图页面。

我们目前唯一真正的问题是我们有一个可以很好缩放的站点，但是背景图像和全尺寸照片可能比严格必要的要大。背景图片实际上不是问题，因为我们可以根据媒体查询来确定发送哪种尺寸的图像。我们只需要创建两到三个背景图像尺寸，并覆盖`jquery-` `le.css`文件中使用的图像。在本章的最终版本代码中，我已将`jquery-mobile.css`重命名为`chapter7.css`，以避免与实际的 jQuery Mobile 库 CSS 文件混淆。

# 文本可读性和响应式设计

研究表明，每行理想的字符限制是有的。理想情况下，您应该选择 35、55、75 或 95 CPL（每行字符数）。人们倾向于更短或更长的行。由于我们真的想在这里展示摄影作品，所以让我们选择较短的 CPL。如果您想阅读完整的报告，可以在 [`psychology.wichita.edu/surl/usabilitynews/72/LineLength.asp`](http://psychology.wichita.edu/surl/usabilitynews/72/LineLength.asp) 找到它。

在很大程度上，我们的文本列宽将受到设备本身的限制。在较小的设备上，我们确实别无选择，只能使用`100%`的宽度。一旦我们到了横向模式的平板电脑，我们就有了创造性地处理文本的空间。对于较大的宽度，我们可以将我们的每行字符数（CPL）增加到 55，效果会很好。我们也可以考虑使用更大的图片。无论我们做什么，都要确保设定了一组强有力的媒体查询断点是关键。

让我们使用这项研究作为指导，将一些有关会话的段落文字更具响应性：

```js
<div id="sessions" data-role="page">
  <div class="logoContainer">
    <a href="#home"><img class="logo" src="img/logo.png" alt="Mullinax Photography" border="0" /></a>
  </div>
<div data-role="content">
  <div class="textContainer ui-shadow">
    <h3>For Your Session</h3>

    <p>Portrait sessions may be held at our Western Shawnee Studio, in the comfort of your home, or a location of your choice. I love capturing little ones in their natural environment. At home, children often feel more comfortable and are more likely to play and have fun. It's the perfect environment for capturing those sweet little smiles and laughs that you as a parent adore!!</p>

     <p>I strive to make each portrait session relaxed, fun, and beautiful. Like each child, each session will be unique to fit your family's needs. As a mother, I understand firsthand the challenges that come with photographing little ones. The perfect portrait can take time. Being the perfect model is hard work and often breaks are needed.  That is why each of my sessions is held without time constraints. A one-of-a-kind portrait cannot be rushed!! While I don't want to overstay my welcome, I do want to stay long enough that you and I are both satisfied with the portraits that were captured.</p>

    <h3>After Your Session</h3>

    <p>Approximately two weeks after your session, I will post an online gallery for you to view your proofs as well as share with friends and family. Your proof gallery will stay online for 10 days. At this time you have the option of placing your order through the website using our shopping cart or you can schedule an in-person appointment.</p>

  </div>
</div><!-- /content -->
<div data-role="footer">
  <div data-role="navbar" data-position="fixed">
    <ul>
      <li><a href="#home">Home</a></li>
      <li><a href="#about">About</a></li>
      <li><a href="#contact">Contact</a></li>
    </ul>
  </div><!-- /navbar -->
</div>
</div><!-- /page -->
```

接下来，让我们制定一些关于其在页面上放置的规则：

```js
#sessions{ 
  background-color:#888; 
  background-repeat:no-repeat; 
  background-position: 
  center center; 
}  

#sessions h3{
  font-family: 'Euphoria Script', Helvetica, sans-serif; 
  font-size:200%; 
  font-weight:bold; 
  margin:0;
}

.textContainer{ 
  background-color:#EEE;
  margin:-5px;
} 

/* iPhone Portrait --*/ 
@media all and (min-width: 320px){ 
  .textContainer{ 
    padding:120px 10px 10px 10px;
  } 
  #sessions{ 
    background-image:none; 
  }
} 

/* iPad Verticle --*/ 
@media only screen and (min-width: 768px) {     
.textContainer{ padding:160px 10px 10px 10px;} 
}

/* iPad Horizontal --*/ 
@media only screen and (min-width: 1024px) {     
  .textContainer{
    float:right; 
    width:35em; 
    padding:2em 2em 2em 2em; 
    height:550px; 
    overflow:scroll;
  } 
  #sessions{ 
    background-image:url(images/Colleen.jpeg)
  }
}

/* Laptop 1440 --*/ 
@media only screen and (min-width: 1440px) { 
  #sessions{ 
    background-image:url(images/Gliser.jpg) 
  }   
}
```

与以前一样，在较小的宽度上设置的规则将延伸到更宽的宽度，除非指定了一个值来覆盖。您可以看到我是如何在 iPad 横向视图和 1440 分辨率上切换用于会话的图像的。在那之前，每个分辨率都继承了 `background-image:none` 形式和 320px 的规则。

现在让我们来看看我们的结果。

## 智能手机尺寸设备

在这里，我们看到了小屏幕上的会话内容，无论是纵向还是横向，都非常易读，但是都不是真正适合显示除文本以外的任何内容的理想方式。如果我们试图塞入任何形式的艺术作品，它都不会显示得好。我们会违反刚刚谈到的良好文本可读性。你或者摄影师可能会认为，将其中一张图片淡入背景看起来不错，但不要这样做！将大部分阅读文本保持为黑底白字、标准字体大小和标准字体。

![智能手机尺寸设备](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_07_10.jpg)

## 平板设备尺寸

这里我们看到相同的内容在平板上渲染。在纵向方向上，如果我们将文本保持在`100%`的宽度，仍然非常适合阅读。我们完全符合良好可读性的指南。然而，当用户切换到横向时，情况就不同了。在横向模式下，平板终于有足够的空间来展示一些摄影作品和文本：

![平板设备](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_07_07.jpg)

## 桌面尺寸设备

这仍然是一个 jQuery Mobile 页面，但我们看起来更像是一个桌面站点。现在我们可以展示不止一个面孔，所以我们不妨换一些不同的照片来展示艺术家的能力：

![桌面尺寸设备](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/crt-mobi-app-jqmobi/img/0069_07_08.jpg)

是的，这是我和我的家人。是的，*我*为他们感到非常自豪。而且我对于每一个分辨率断点上的文本处理方式都非常满意，并且它是在一个页面上完成的。

# 循环背景图像

那么，当我们使用的图像依赖于我们当前的分辨率和方向时，我们如何循环背景图像呢？这几乎排除了循环一个单一图像的可能性。相反，我们将不得不交换整个样式表。下面是代码：

```js
<link rel="stylesheet" href="rotating0.css" id="rotatingBackgrounds" />
```

它开始时是一个非常简单的样式表，但你可以将它制作得像你想要的那样复杂。我们暂不考虑高清显示和标清显示。iPhone 4 具有视网膜显示屏（326 ppi）在 2010 年 6 月发布。自那以后，趋势已经转向高清屏幕，所以我只是假设大多数人在过去两年内已经更新了他们的智能手机，或者他们很快就会更新。同样要记住，我们正处于 LTE（第四代移动宽带）普及的边缘。这意味着很快，移动速度将比大多数家庭宽带速度更快。

现在，这真的是懒惰的借口，不去制作更小的版本以充分利用性能吗？不，很可能，一些讨厌者和学者甚至会对上一段提出异议。我会说，性能确实很重要。这是一个可计费的功能。但想想你想循环播放多少图像，然后乘以你想要花时间准备和测试多少分辨率和尺寸变体。再次强调，这都是可计费的，除非你是免费做的。

一直进行这样细微的优化，到底还需要多长时间才能让其真正没有明显的差别？如果你是在 2014 年或之后阅读此内容，你可能对必须在任何实际意义上担心带宽的想法感到嗤之以鼻（取决于你所在的市场）。这只是一些思考。

下面是用于旋转的一个 CSS 文件：

```js
@charset "UTF-8"; 
/* CSS Document */ 

#gallery{background-image:url(images/homebg.jpg);}   

/* iPhone Portrait --*/ 
@media all and (min-width: 320px){ 
#home{
background-image:url(images/backgroundSmartphone.jpg);
} 
#sessions{ background-image:none; }  
}  

/* iPhone Horizontal / Some Droids --*/ 
@media all and (min-width: 480px){  } 

/* iPad Verticle --*/ 
@media only screen and (min-width: 768px) { 	
#home{background-image:url(images/backgroundSmall.jpg);} 
}  

/* iPad Horizontal --*/ 
@media only screen and (min-width: 1024px) { 
#sessions{ background-image:url(images/Colleen.jpeg) }  
}  

/* Nexus 7 Horizontal --*/ 
@media only screen and (min-width: 1280px) {  }  

/* Laptop 1440 --*/ 
@media only screen and (min-width: 1440px) { 
#sessions{ background-image:url(images/Gliser.jpg) }   
}  

/* Monitor 1600 --*/ 
@media only screen and (min-width: 1600px) {  }  

/* Monitor 1920 --*/ 
@media only screen and (min-width: 1920px) {  } 
```

现在我们需要决定如何循环它们。我们可以使用`setInterval` JavaScript 来定时交换样式表。说实话，即使对于一个摄影网站，我认为这有点乐观。我们可能不希望每五秒钟就交换一次。想想：移动设备的使用模式涉及快速、短暂的工作或游戏。大多数人不会在任何给定的移动屏幕上停留超过 5 秒，除非它要么是文字密集的，比如一篇文章，要么制作得如此糟糕以至于用户无法导航。所以可以很肯定地说，`setInterval`选项不可行。

好吧，也许最好在`pagebeforeshow`事件上随机选择一个样式表？考虑以下代码：

```js
$(document).on("pagebeforeshow", "[data-role='page']", function(){ 
  $("#rotatingBackgrounds").attr("href", "rotating" + 
Math.floor(Math.random()*4) + ".css");
});
```

但是当我们尝试这样做时会发生什么？我们会得到奇怪、丑陋的图像闪烁。使用淡入淡出转换或幻灯片，真的无关紧要。使用`pageshow`事件也没有任何区别。看起来很糟糕。不要这样做。我知道很诱人，但这样做一点也不好看。*因此，经过这一切，我建议保留单一、每次会话随机分配的样式表*。考虑下面的代码片段：

```js
<link rel="stylesheet" href="" id="rotatingBackgrounds" />
<script type="text/javascript">
$("#rotatingBackgrounds")
  .attr("href","rotating"+Math.floor(Math.random()*4)+".css")
</script>
```

请注意，我并没有简单地使用`document.write()`。

### 注意

**专业提示**

永远不要在 jQuery Mobile 环境中使用`document.write()`。它会对你的 DOM 造成严重影响，你会摸不着头脑想知道出了什么问题。我以前看到过它折磨过人们。我的朋友的头发已经很少了，这个问题使他抓狂。相信我，要避免使用`document.write()`。

# 另一种响应式方法 - RESS

**响应式设计 + 服务器端组件**（**RESS**）是一个非常合理的想法。其概念是使用服务器端的移动设备检测方法，比如**WURFL**（[`wurfl.sourceforge.net/`](http://wurfl.sourceforge.net/)）。然后，你会发送不同版本的页面组件、不同大小的图片等等。然后我们可以像任何自制的标记一样轻松地改变页面内容和导航的包装以使用 jQuery Mobile。这种方法的美妙之处在于每个人都能得到适合他们的内容，而不会像典型的响应式设计那样臃肿，而且始终在相同的 URL 上。

我第一次看到这个想法被提出是在 2011 年 9 月的一篇文章中，作者是 Luke Wroblewski（[`twitter.com/lukew`](https://twitter.com/lukew)），文章链接为[`www.lukew.com/ff/entry.asp?1392`](http://www.lukew.com/ff/entry.asp?1392)。在文章中，他概述了我们现在面临的与图像相关的性能问题。Luke 认为这是一种在没有任何移动框架的情况下进行纯粹响应式网页设计的方法。

WURFL 可以告诉你所服务的设备的屏幕尺寸，你可以（实时）调整你的摄影师原始的 3 MB 图像大小，缩小到 150 KB、70 KB 等，具体取决于设备分辨率。你仍然希望确保它比你所服务的屏幕尺寸大约两倍，否则用户在 PhotoSwipe 视图中尝试放大照片时将只会看到模糊的混乱。

虽然在某些方面很方便，但 RESS 永远不会是一个完美的解决方案，因为它依赖于浏览器嗅探来完成其工作。那么，这是不好的吗？不，不是真的。没有一个解决方案是完美的，但设备数据库是由社区驱动的，并且快速更新，所以这有所帮助。这将是一个非常可行的解决方案，我们将在下一章更深入地讨论它。

# 最终代码

本次体验的完整代码有点冗长，不太适合放入一本书中，而且我们已经探讨过相关概念了。我强烈建议你查看代码。到此时，对你来说应该没有什么令人惊讶的了。与之互动。调整它。通过交换服务来建立你的作品集，免费获取一些摄影作品。

# 摘要

处理响应式设计时，采用移动优先的方法，就像我们这里所做的一样，可以将一个很棒的移动站点变成一个性能非常高的桌面站点，但通常反之则不行。其中的关键在于媒体查询和先从小尺寸开始。如果它在移动设备上运行得如此出色，那么想象一下在没有任何限制的机器上会有多么惊人。在下一章中，我们将探讨 WURFL 和其他移动检测方法，尝试调整现有的网站并使其适应移动设备。
