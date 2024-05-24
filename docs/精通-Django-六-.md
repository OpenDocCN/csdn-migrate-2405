# 精通 Django（六）

> 原文：[`zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6`](https://zh.annas-archive.org/md5/0D7AA9BDBF4A402F69CD832FB5D17FA6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十七章：Django 中间件

中间件是 Django 请求/响应处理的钩子框架。它是一个轻量级的、低级别的插件系统，用于全局修改 Django 的输入或输出。

每个中间件组件负责执行一些特定的功能。例如，Django 包括一个中间件组件`AuthenticationMiddleware`，它使用会话将用户与请求关联起来。

本文档解释了中间件的工作原理，如何激活中间件以及如何编写自己的中间件。Django 附带了一些内置的中间件，您可以直接使用。请参见本章后面的*可用中间件*。

# 激活中间件

要激活中间件组件，请将其添加到 Django 设置中的`MIDDLEWARE_CLASSES`列表中。

在`MIDDLEWARE_CLASSES`中，每个中间件组件都由一个字符串表示：中间件类名的完整 Python 路径。例如，这是由`django-admin startproject`创建的默认值：

```py
MIDDLEWARE_CLASSES = [ 
    'django.contrib.sessions.middleware.SessionMiddleware', 
    'django.middleware.common.CommonMiddleware', 
    'django.middleware.csrf.CsrfViewMiddleware', 
    'django.contrib.auth.middleware.AuthenticationMiddleware', 
    'django.contrib.messages.middleware.MessageMiddleware', 
    'django.middleware.clickjacking.XFrameOptionsMiddleware', 
] 

```

Django 安装不需要任何中间件-如果你愿意的话，`MIDDLEWARE_CLASSES`可以为空，但强烈建议至少使用`CommonMiddleware`。

`MIDDLEWARE_CLASSES`中的顺序很重要，因为一个中间件可能依赖于其他中间件。例如，`AuthenticationMiddleware`将认证用户存储在会话中；因此，它必须在`SessionMiddleware`之后运行。有关 Django 中间件类的常见提示的*中间件排序*，请参见本章后面。

# 钩子和应用顺序

在请求阶段，在调用视图之前，Django 按照在`MIDDLEWARE_CLASSES`中定义的顺序应用中间件，从上到下。有两个钩子可用：

+   `process_request()`

+   `process_view()`

在响应阶段，在调用视图之后，中间件按照从下到上的顺序应用。有三个钩子可用：

+   `process_exception()`

+   `process_template_response()`

+   `process_response()`

如果您愿意，您也可以将其视为洋葱：每个中间件类都是包装视图的一层。

下面描述了每个钩子的行为。

# 编写自己的中间件

编写自己的中间件很容易。每个中间件组件都是一个单独的 Python 类，定义了以下一个或多个方法：

## process_request

方法：`process_request(request)`

+   `request`是一个`HttpRequest`对象。

+   `process_request()`在 Django 决定执行哪个视图之前，对每个请求都会调用。

它应该返回`None`或者一个`HttpResponse`对象。如果返回`None`，Django 将继续处理此请求，执行任何其他`process_request()`中间件，然后执行`process_view()`中间件，最后执行适当的视图。

如果返回一个`HttpResponse`对象，Django 将不再调用任何其他请求、视图或异常中间件，或者适当的视图；它将对该`HttpResponse`应用响应中间件，并返回结果。

## process_view

方法：`process_view(request, view_func, view_args, view_kwargs)`

+   `request`是一个`HttpRequest`对象。

+   `view_func`是 Django 即将使用的 Python 函数。（它是实际的函数对象，而不是函数名作为字符串。）

+   `view_args`是将传递给视图的位置参数列表。

+   `view_kwargs`是将传递给视图的关键字参数字典。

+   `view_args`和`view_kwargs`都不包括第一个视图参数（`request`）。

`process_view()`在 Django 调用视图之前调用。它应该返回`None`或者一个`HttpResponse`对象。如果返回`None`，Django 将继续处理此请求，执行任何其他`process_view()`中间件，然后执行适当的视图。

如果返回一个`HttpResponse`对象，Django 将不再调用任何其他视图或异常中间件，或者适当的视图；它将对该`HttpResponse`应用响应中间件，并返回结果。

### 注意

在 `process_request` 或 `process_view` 中从中间件访问 `request.POST` 将阻止任何在中间件之后运行的视图能够修改请求的上传处理程序，并且通常应该避免这样做。

`CsrfViewMiddleware` 类可以被视为一个例外，因为它提供了 `csrf_exempt()` 和 `csrf_protect()` 装饰器，允许视图明确控制 CSRF 验证应该在何时发生。

## process_template_response

方法：`process_template_response(request, response)`

+   `request` 是一个 `HttpRequest` 对象。

+   `response` 是由 Django 视图或中间件返回的 `TemplateResponse` 对象（或等效对象）。

如果响应实例具有 `render()` 方法，表示它是 `TemplateResponse` 或等效对象，则会在视图执行完成后立即调用 `process_template_response()`。

它必须返回一个实现 `render` 方法的响应对象。它可以通过更改 `response.template_name` 和 `response.context_data` 来修改给定的 `response`，也可以创建并返回全新的 `TemplateResponse` 或等效对象。

您不需要显式渲染响应-一旦调用了所有模板响应中间件，响应将自动渲染。

在响应阶段中，中间件按照相反的顺序运行，其中包括 `process_template_response()`。

## process_response

方法：`process_response(request, response)`

+   `request` 是一个 `HttpRequest` 对象。

+   `response` 是由 Django 视图或中间件返回的 `HttpResponse` 或 `StreamingHttpResponse` 对象。

在将响应返回给浏览器之前，将调用 `process_response()`。它必须返回一个 `HttpResponse` 或 `StreamingHttpResponse` 对象。它可以修改给定的 `response`，也可以创建并返回全新的 `HttpResponse` 或 `StreamingHttpResponse`。

与 `process_request()` 和 `process_view()` 方法不同，`process_response()` 方法始终会被调用，即使同一中间件类的 `process_request()` 和 `process_view()` 方法被跳过（因为之前的中间件方法返回了一个 `HttpResponse`）。特别是，这意味着您的 `process_response()` 方法不能依赖于在 `process_request()` 中进行的设置。

最后，在响应阶段，中间件按照从下到上的顺序应用。这意味着在 `MIDDLEWARE_CLASSES` 的末尾定义的类将首先运行。

### 处理流式响应

与 `HttpResponse` 不同，`StreamingHttpResponse` 没有 `content` 属性。因此，中间件不能再假定所有响应都有 `content` 属性。如果它们需要访问内容，它们必须测试流式响应并相应地调整其行为：

```py
if response.streaming: 
    response.streaming_content =  wrap_streaming_content(response.streaming_content) 
else: 
    response.content = alter_content(response.content) 

```

`streaming_content` 应被假定为太大而无法在内存中保存。响应中间件可以将其包装在一个新的生成器中，但不得消耗它。包装通常实现如下：

```py
def wrap_streaming_content(content): 
    for chunk in content: 
        yield alter_content(chunk) 

```

## process_exception

方法：`process_exception(request, exception)`

+   `request` 是一个 `HttpRequest` 对象。

+   `exception` 是由视图函数引发的 `Exception` 对象。

当视图引发异常时，Django 调用 `process_exception()`。`process_exception()` 应该返回 `None` 或一个 `HttpResponse` 对象。如果它返回一个 `HttpResponse` 对象，模板响应和响应中间件将被应用，并将生成的响应返回给浏览器。否则，将启用默认的异常处理。

同样，在响应阶段中，中间件按照相反的顺序运行，其中包括 `process_exception`。如果异常中间件返回一个响应，那么该中间件上面的中间件类将根本不会被调用。

## __init__

大多数中间件类不需要初始化器，因为中间件类本质上是 `process_*` 方法的占位符。如果您需要一些全局状态，可以使用 `__init__` 进行设置。但是，请记住一些注意事项：

1.  Django 在不带任何参数的情况下初始化您的中间件，因此您不能将 `__init__` 定义为需要任何参数。

1.  与每个请求调用一次的 `process_*` 方法不同，`__init__` 仅在 Web 服务器响应第一个请求时调用一次。

### 将中间件标记为未使用

有时在运行时确定是否应使用某个中间件是有用的。在这些情况下，您的中间件的 `__init__` 方法可能会引发 `django.core.exceptions.MiddlewareNotUsed`。Django 将从中间件流程中删除该中间件，并在 `DEBUG` 设置为 `True` 时，将在 `django.request` 记录器中记录调试消息。

## 其他指南

+   中间件类不必是任何东西的子类。

+   中间件类可以存在于 Python 路径的任何位置。Django 关心的是 `MIDDLEWARE_CLASSES` 设置包含其路径。

+   随时查看 Django 提供的中间件示例。

+   如果您编写了一个您认为对其他人有用的中间件组件，请为社区做出贡献！让我们知道，我们将考虑将其添加到 Django 中。

# 可用的中间件

## 缓存中间件

`django.middleware.cache.UpdateCacheMiddleware`; 和 `django.middleware.cache.FetchFromCacheMiddleware`

启用站点范围的缓存。如果启用了这些选项，则每个由 Django 提供动力的页面将根据 `CACHE_MIDDLEWARE_SECONDS` 设置的定义缓存。请参阅缓存文档。

## 常见中间件

`django.middleware.common.CommonMiddleware`

为完美主义者添加了一些便利：

+   禁止访问 `DISALLOWED_USER_AGENTS` 设置中的用户代理，该设置应该是编译的正则表达式对象的列表。

+   基于 `APPEND_SLASH` 和 `PREPEND_WWW` 设置执行 URL 重写。

+   如果 `APPEND_SLASH` 为 `True`，并且初始 URL 不以斜杠结尾，并且在 URLconf 中找不到，则将通过在末尾添加斜杠来形成新的 URL。如果在 URLconf 中找到此新 URL，则 Django 将重定向请求到此新 URL。否则，将像往常一样处理初始 URL。

+   例如，如果您没有 `foo.com/bar` 的有效 URL 模式，但是有 `foo.com/bar/` 的有效模式，则将重定向到 `foo.com/bar/`。

+   如果 `PREPEND_WWW` 为 `True`，则缺少前导 `www.` 的 URL 将重定向到具有前导 `www.` 的相同 URL。

+   这两个选项都旨在规范化 URL。哲学是每个 URL 应该存在于一个且仅一个位置。从技术上讲，URL `foo.com/bar` 与 `foo.com/bar/` 是不同的-搜索引擎索引器将其视为单独的 URL-因此最佳做法是规范化 URL。

+   根据 `USE_ETAGS` 设置处理 ETags。如果 `USE_ETAGS` 设置为 `True`，Django 将通过对页面内容进行 MD5 哈希来计算每个请求的 ETag，并在适当时负责发送 `Not Modified` 响应。

+   `CommonMiddleware.response_redirect_class.` 默认为 `HttpResponsePermanentRedirect`。子类 `CommonMiddleware` 并覆盖属性以自定义中间件发出的重定向。

+   `django.middleware.common.BrokenLinkEmailsMiddleware.` 将损坏的链接通知邮件发送给 `MANAGERS.`

## GZip 中间件

`django.middleware.gzip.GZipMiddleware`

### 注意

安全研究人员最近披露，当网站使用压缩技术（包括 `GZipMiddleware`）时，该网站会暴露于许多可能的攻击。这些方法可以用来破坏 Django 的 CSRF 保护，等等。在您的网站上使用 `GZipMiddleware` 之前，您应该非常仔细地考虑您是否受到这些攻击的影响。如果您对自己是否受影响有任何疑问，您应该避免使用 `GZipMiddleware`。有关更多详细信息，请参阅 `breachattack.com`。

为了理解 GZip 压缩的浏览器压缩内容（所有现代浏览器）。

此中间件应放置在需要读取或写入响应正文的任何其他中间件之前，以便在之后进行压缩。

如果以下任何条件为真，则不会压缩内容：

+   内容主体长度小于 200 字节。

+   响应已设置了`Content-Encoding`头。

+   请求（浏览器）未发送包含`gzip`的`Accept-Encoding`头。

您可以使用`gzip_page()`装饰器将 GZip 压缩应用于单个视图。

## 有条件的 GET 中间件

`django.middleware.http.ConditionalGetMiddleware`

处理有条件的 GET 操作。如果响应具有`ETag`或`Last-Modified`头，并且请求具有`If-None-Match`或`If-Modified-Since`，则响应将被`HttpResponseNotModified`替换。

还设置了`Date`和`Content-Length`响应头。

## 区域中间件

`django.middleware.locale.LocaleMiddleware`

基于请求数据启用语言选择。它为每个用户定制内容。请参阅国际化文档。

`LocaleMiddleware.response_redirect_class`

默认为`HttpResponseRedirect`。子类化`LocaleMiddleware`并覆盖属性以自定义中间件发出的重定向。

## 消息中间件

`django.contrib.messages.middleware.MessageMiddleware`

启用基于 cookie 和会话的消息支持。请参阅消息文档。

## 安全中间件

### 注意

如果您的部署情况允许，通常最好让您的前端 Web 服务器执行`SecurityMiddleware`提供的功能。这样，如果有一些不是由 Django 提供服务的请求（如静态媒体或用户上传的文件），它们将具有与请求到您的 Django 应用程序相同的保护。

`django.middleware.security.SecurityMiddleware`为请求/响应周期提供了几个安全增强功能。`SecurityMiddleware`通过向浏览器传递特殊头来实现这一点。每个头都可以通过设置独立启用或禁用。

### HTTP 严格传输安全

设置：

+   `SECURE_HSTS_INCLUDE_SUBDOMAINS`

+   `SECURE_HSTS_SECONDS`

对于应该只能通过 HTTPS 访问的网站，您可以通过设置`Strict-Transport-Security`头，指示现代浏览器拒绝通过不安全的连接连接到您的域名（在一定时间内）。这减少了您对一些 SSL 剥离中间人（MITM）攻击的风险。

如果将`SECURE_HSTS_SECONDS`设置为非零整数值，则`SecurityMiddleware`将在所有 HTTPS 响应上为您设置此头。

启用 HSTS 时，最好首先使用一个小值进行测试，例如，`SECURE_HSTS_SECONDS = 3600`表示一小时。每次 Web 浏览器从您的站点看到 HSTS 头时，它将拒绝在给定时间内与您的域进行非安全（使用 HTTP）通信。

一旦确认您的站点上的所有资产都安全提供服务（即，HSTS 没有破坏任何内容），最好增加此值，以便偶尔访问者受到保护（31536000 秒，即 1 年，是常见的）。

此外，如果将`SECURE_HSTS_INCLUDE_SUBDOMAINS`设置为`True`，`SecurityMiddleware`将在`Strict-Transport-Security`头中添加`includeSubDomains`标记。这是建议的（假设所有子域都仅使用 HTTPS 提供服务），否则您的站点可能仍然会通过不安全的连接对子域进行攻击。

### 注意

HSTS 策略适用于整个域，而不仅仅是您设置头的响应的 URL。因此，只有在整个域通过 HTTPS 提供服务时才应该使用它。

正确尊重 HSTS 头的浏览器将拒绝允许用户绕过警告并连接到具有过期、自签名或其他无效 SSL 证书的站点。如果使用 HSTS，请确保您的证书状况良好并保持良好！

### X-content-type-options: nosniff

设置：

+   `SECURE_CONTENT_TYPE_NOSNIFF`

一些浏览器会尝试猜测它们获取的资产的内容类型，覆盖`Content-Type`头。虽然这可以帮助显示配置不正确的服务器的站点，但也可能带来安全风险。

如果您的网站提供用户上传的文件，恶意用户可能会上传一个特制的文件，当您期望它是无害的时，浏览器会将其解释为 HTML 或 Javascript。

为了防止浏览器猜测内容类型并强制它始终使用`Content-Type`头中提供的类型，您可以传递`X-Content-Type-Options: nosniff`头。如果`SECURE_CONTENT_TYPE_NOSNIFF`设置为`True`，`SecurityMiddleware`将对所有响应执行此操作。

请注意，在大多数部署情况下，Django 不涉及提供用户上传的文件，这个设置对您没有帮助。例如，如果您的`MEDIA_URL`是由您的前端 Web 服务器（nginx，Apache 等）直接提供的，那么您需要在那里设置这个头部。

另一方面，如果您正在使用 Django 执行诸如要求授权才能下载文件之类的操作，并且无法使用您的 Web 服务器设置头部，那么这个设置将很有用。

### X-XSS 保护

设置：

+   `SECURE_BROWSER_XSS_FILTER`

一些浏览器有能力阻止看起来像 XSS 攻击的内容。它们通过查找页面的 GET 或 POST 参数中的 Javascript 内容来工作。如果服务器的响应中重放了 Javascript，则页面将被阻止渲染，并显示错误页面。

`X-XSS-Protection header`用于控制 XSS 过滤器的操作。

为了在浏览器中启用 XSS 过滤器，并强制它始终阻止疑似的 XSS 攻击，您可以传递`X-XSS-Protection: 1; mode=block`头。如果`SECURE_BROWSER_XSS_FILTER`设置为`True`，`SecurityMiddleware`将对所有响应执行此操作。

### 注意

浏览器 XSS 过滤器是一种有用的防御措施，但不能完全依赖它。它无法检测所有的 XSS 攻击，也不是所有的浏览器都支持该头部。确保您仍在验证和所有输入，以防止 XSS 攻击。

### SSL 重定向

设置：

+   `SECURE_REDIRECT_EXEMPT`

+   `SECURE_SSL_HOST`

+   `SECURE_SSL_REDIRECT`

如果您的网站同时提供 HTTP 和 HTTPS 连接，大多数用户最终将默认使用不安全的连接。为了最佳安全性，您应该将所有 HTTP 连接重定向到 HTTPS。

如果将`SECURE_SSL_REDIRECT`设置为 True，`SecurityMiddleware`将永久（HTTP 301）将所有 HTTP 连接重定向到 HTTPS。

出于性能原因，最好在 Django 之外进行这些重定向，在前端负载均衡器或反向代理服务器（如 nginx）中。`SECURE_SSL_REDIRECT`适用于这种情况下无法选择的部署情况。

如果`SECURE_SSL_HOST`设置有值，所有重定向将发送到该主机，而不是最初请求的主机。

如果您的网站上有一些页面应该通过 HTTP 可用，并且不重定向到 HTTPS，您可以在`SECURE_REDIRECT_EXEMPT`设置中列出正则表达式来匹配这些 URL。

如果您部署在负载均衡器或反向代理服务器后，并且 Django 似乎无法确定请求实际上已经安全，您可能需要设置`SECURE_PROXY_SSL_HEADER`设置。

## 会话中间件

`django.contrib.sessions.middleware.SessionMiddleware`

启用会话支持。有关更多信息，请参见第十五章，“Django 会话”。

## 站点中间件

`django.contrib.sites.middleware.CurrentSiteMiddleware`

为每个传入的`HttpRequest`对象添加代表当前站点的`site`属性。有关更多信息，请参见站点文档（[`docs.djangoproject.com/en/1.8/ref/contrib/sites/`](https://docs.djangoproject.com/en/1.8/ref/contrib/sites/)）。

## 身份验证中间件

`django.contrib.auth.middleware`提供了三个用于身份验证的中间件：

+   `*.AuthenticationMiddleware.` 向每个传入的`HttpRequest`对象添加代表当前登录用户的`user`属性。

+   `*.RemoteUserMiddleware.` 用于利用 Web 服务器提供的身份验证。

+   `*.SessionAuthenticationMiddleware.` 允许在用户密码更改时使用户会话失效。此中间件必须出现在`MIDDLEWARE_CLASSES`中`*.AuthenticationMiddleware`之后。

有关 Django 中用户身份验证的更多信息，请参见第十一章，“Django 中的用户身份验证”。

## CSRF 保护中间件

`django.middleware.csrf.CsrfViewMiddleware`

通过向 POST 表单添加隐藏的表单字段并检查请求的正确值来防止跨站点请求伪造（CSRF）。有关 CSRF 保护的更多信息，请参见第十九章，“Django 中的安全性”。

## X-Frame-options 中间件

`django.middleware.clickjacking.XFrameOptionsMiddleware`

通过 X-Frame-Options 标头进行简单的点击劫持保护。

# 中间件排序

*表 17.1*提供了有关各种 Django 中间件类的排序的一些提示：

| **类** | **注释** |
| --- | --- |
| UpdateCacheMiddleware | 在修改`Vary`标头的中间件之前（`SessionMiddleware`，`GZipMiddleware`，`LocaleMiddleware`）。 |
| GZipMiddleware | 在可能更改或使用响应正文的任何中间件之前。在`UpdateCacheMiddleware`之后：修改`Vary`标头。 |
| ConditionalGetMiddleware | 在`CommonMiddleware`之前：当`USE_ETAGS`=`True`时使用其`Etag`标头。 |
| SessionMiddleware | 在`UpdateCacheMiddleware`之后：修改`Vary`标头。 |
| LocaleMiddleware | 在顶部之一，之后是`SessionMiddleware`（使用会话数据）和`CacheMiddleware`（修改`Vary`标头）。 |
| CommonMiddleware | 在可能更改响应的任何中间件之前（它计算`ETags`）。在`GZipMiddleware`之后，因此它不会在经过 gzip 处理的内容上计算`ETag`标头。靠近顶部：当`APPEND_SLASH`或`PREPEND_WWW`设置为`True`时进行重定向。 |
| CsrfViewMiddleware | 在假定已处理 CSRF 攻击的任何视图中间件之前。 |
| AuthenticationMiddleware | 在`SessionMiddleware`之后：使用会话存储。 |
| MessageMiddleware | 在`SessionMiddleware`之后：可以使用基于会话的存储。 |
| FetchFromCacheMiddleware | 在修改`Vary`标头的任何中间件之后：该标头用于选择缓存哈希键的值。 |
| FlatpageFallbackMiddleware | 应该靠近底部，因为它是一种最后一招的中间件。 |
| RedirectFallbackMiddleware | 应该靠近底部，因为它是一种最后一招的中间件。 |

表 17.1：中间件类的排序

# 接下来是什么？

在下一章中，我们将研究 Django 中的国际化。


# 第十八章：国际化

当从 JavaScript 源代码创建消息文件时，Django 最初是在美国中部开发的，字面上说，劳伦斯市距离美国大陆的地理中心不到 40 英里。然而，像大多数开源项目一样，Django 的社区逐渐包括来自全球各地的人。随着 Django 社区变得越来越多样化，*国际化*和*本地化*变得越来越重要。

Django 本身是完全国际化的；所有字符串都标记为可翻译，并且设置控制着像日期和时间这样的与区域相关的值的显示。Django 还附带了 50 多种不同的本地化文件。如果您不是以英语为母语，那么 Django 已经被翻译成您的主要语言的可能性很大。

用于这些本地化的相同国际化框架可供您在自己的代码和模板中使用。

因为许多开发人员对国际化和本地化的实际含义理解模糊，所以我们将从一些定义开始。

# 定义

## 国际化

指的是为任何区域的潜在使用设计程序的过程。这个过程通常由软件开发人员完成。国际化包括标记文本（如 UI 元素和错误消息）以供将来翻译，抽象显示日期和时间，以便可以遵守不同的本地标准，提供对不同时区的支持，并确保代码不包含对其用户位置的任何假设。您经常会看到国际化缩写为*I18N*。（18 指的是 I 和 N 之间省略的字母数）。

## 本地化

指的是实际将国际化程序翻译为特定区域的过程。这项工作通常由翻译人员完成。有时您会看到本地化缩写为*L10N*。

以下是一些其他术语，将帮助我们处理常见的语言：

### 区域名称

区域名称，可以是`ll`形式的语言规范，也可以是`ll_CC`形式的组合语言和国家规范。例如：`it`，`de_AT`，`es`，`pt_BR`。语言部分始终为小写，国家部分为大写。分隔符是下划线。

### 语言代码

表示语言的名称。浏览器使用这种格式在`Accept-Language` HTTP 标头中发送它们接受的语言名称。例如：`it`，`de-at`，`es`，`pt-br`。语言代码通常以小写表示，但 HTTP `Accept-Language`标头不区分大小写。分隔符是破折号。

### 消息文件

消息文件是一个纯文本文件，代表单一语言，包含所有可用的翻译字符串以及它们在给定语言中的表示方式。消息文件的文件扩展名为`.po`。

### 翻译字符串

可翻译的文字。

### 格式文件

格式文件是定义给定区域的数据格式的 Python 模块。

# 翻译

为了使 Django 项目可翻译，您必须在 Python 代码和模板中添加最少量的钩子。这些钩子称为翻译字符串。它们告诉 Django：如果该文本在该语言中有翻译，则应将此文本翻译成最终用户的语言。标记可翻译字符串是您的责任；系统只能翻译它知道的字符串。

然后 Django 提供了工具来提取翻译字符串到消息文件中。这个文件是翻译人员以目标语言提供翻译字符串的方便方式。一旦翻译人员填写了消息文件，就必须对其进行编译。这个过程依赖 GNU `gettext`工具集。

完成后，Django 会根据用户的语言偏好即时翻译 Web 应用程序。

基本上，Django 做了两件事：

+   它允许开发人员和模板作者指定其应用程序的哪些部分应该是可翻译的。

+   它使用这些信息根据用户的语言偏好来翻译 Web 应用程序。

Django 的国际化钩子默认打开，这意味着在框架的某些地方有一些与 i18n 相关的开销。如果您不使用国际化，您应该花两秒钟在设置文件中设置`USE_I18N = False`。然后 Django 将进行一些优化，以便不加载国际化机制，这将节省一些开销。还有一个独立但相关的`USE_L10N`设置，用于控制 Django 是否应该实现格式本地化。

# 国际化：在 Python 代码中

## 标准翻译

使用函数`ugettext（）`指定翻译字符串。按照惯例，将其导入为更短的别名`_`，以节省输入。

Python 的标准库`gettext`模块将`_（）`安装到全局命名空间中，作为`gettext（）`的别名。在 Django 中，出于几个原因，我们选择不遵循这种做法：

+   对于国际字符集（Unicode）支持，`ugettext（）`比`gettext（）`更有用。有时，您应该使用`ugettext_lazy（）`作为特定文件的默认翻译方法。在全局命名空间中没有`_（）`时，开发人员必须考虑哪个是最合适的翻译函数。

+   下划线字符（`_`）用于表示 Python 交互式 shell 和 doctest 测试中的先前结果。安装全局`_（）`函数会导致干扰。显式导入`ugettext（）`作为`_（）`可以避免这个问题。

在这个例子中，文本“欢迎来到我的网站。”被标记为翻译字符串：

```py
from django.utils.translation import ugettext as _ 
from django.http import HttpResponse 

def my_view(request): 
    output = _("Welcome to my site.") 
    return HttpResponse(output) 

```

显然，您可以在不使用别名的情况下编写此代码。这个例子与前一个例子相同：

```py
from django.utils.translation import ugettext 
from django.http import HttpResponse 

def my_view(request): 
    output = ugettext("Welcome to my site.") 
    return HttpResponse(output) 

```

翻译也适用于计算值。这个例子与前两个相同：

```py
def my_view(request): 
    words = ['Welcome', 'to', 'my', 'site.'] 
    output = _(' '.join(words)) 
    return HttpResponse(output) 

```

...和变量。再次，这是一个相同的例子：

```py
def my_view(request): 
    sentence = 'Welcome to my site.' 
    output = _(sentence) 
    return HttpResponse(output) 

```

（与前两个示例中使用变量或计算值的警告是，Django 的翻译字符串检测实用程序`django-admin makemessages`将无法找到这些字符串。稍后再讨论`makemessages`。）

您传递给`_（）`或`ugettext（）`的字符串可以使用 Python 的标准命名字符串插值语法指定占位符。示例：

```py
def my_view(request, m, d): 
    output = _('Today is %(month)s %(day)s.') % {'month': m, 'day': d} 
    return HttpResponse(output) 

```

这种技术允许特定语言的翻译重新排列占位符文本。例如，英语翻译可能是“今天是 11 月 26 日。”，而西班牙语翻译可能是“Hoy es 26 de Noviembre。”-月份和日期占位符交换了位置。

因此，当您有多个参数时，应使用命名字符串插值（例如`%(day)s`）而不是位置插值（例如`%s`或`%d`）。如果使用位置插值，翻译将无法重新排列占位符文本。

## 翻译者注释

如果您想给翻译者有关可翻译字符串的提示，可以在前一行添加一个以`Translators`关键字为前缀的注释，例如：

```py
def my_view(request): 
    # Translators: This message appears on the home page only 
    output = ugettext("Welcome to my site.") 

```

该注释将出现在与其下方的可翻译结构相关联的生成的`.po`文件中，并且大多数翻译工具也应该显示该注释。

只是为了完整起见，这是生成的`.po`文件的相应片段：

```py
#. Translators: This message appears on the home page only 
# path/to/python/file.py:123 
msgid "Welcome to my site." 
msgstr "" 

```

这也适用于模板。有关更多详细信息，请参见模板中的翻译注释。

## 标记字符串为 No-Op

使用函数`django.utils.translation.ugettext_noop（）`将字符串标记为翻译字符串而不进行翻译。稍后从变量中翻译字符串。

如果您有应存储在源语言中的常量字符串，因为它们在系统或用户之间交换-例如数据库中的字符串-但应在最后可能的时间点进行翻译，例如在向用户呈现字符串时，请使用此功能。

## 复数形式

使用函数`django.utils.translation.ungettext()`来指定复数形式的消息。

`ungettext`需要三个参数：单数翻译字符串、复数翻译字符串和对象的数量。

当您的 Django 应用程序需要本地化到复数形式比英语中使用的两种形式更多的语言时，此功能非常有用（'object'表示单数，'objects'表示`count`与 1 不同的所有情况，而不考虑其值。）

例如：

```py
from django.utils.translation import ungettext 
from django.http import HttpResponse 

def hello_world(request, count): 
    page = ungettext( 
        'there is %(count)d object', 
        'there are %(count)d objects', 
    count) % { 
        'count': count, 
    } 
    return HttpResponse(page) 

```

在此示例中，对象的数量作为`count`变量传递给翻译语言。

请注意，复数形式很复杂，并且在每种语言中的工作方式都不同。将`count`与 1 进行比较并不总是正确的规则。这段代码看起来很复杂，但对于某些语言来说会产生错误的结果：

```py
from django.utils.translation import ungettext 
from myapp.models import Report 

count = Report.objects.count() 
if count == 1: 
    name = Report._meta.verbose_name 
else: 
    name = Report._meta.verbose_name_plural 

text = ungettext( 
    'There is %(count)d %(name)s available.', 
    'There are %(count)d %(name)s available.', 
    count 
    ) % { 
      'count': count, 
      'name': name 
    } 

```

不要尝试实现自己的单数或复数逻辑，这是不正确的。在这种情况下，考虑以下内容：

```py
text = ungettext( 
    'There is %(count)d %(name)s object available.', 
    'There are %(count)d %(name)s objects available.', 
    count 
    ) % { 
      'count': count, 
      'name': Report._meta.verbose_name, 
    } 

```

使用`ungettext()`时，请确保在文字中包含的每个外推变量使用单个名称。在上面的示例中，请注意我们如何在两个翻译字符串中都使用了`name` Python 变量。这个示例，除了如上所述在某些语言中是不正确的，还会失败：

```py
text = ungettext( 
    'There is %(count)d %(name)s available.', 
    'There are %(count)d %(plural_name)s available.', 
    count 
    ) % { 
      'count': Report.objects.count(), 
      'name': Report._meta.verbose_name, 
      'plural_name': Report._meta.verbose_name_plural 
    } 

```

运行`django-admin compilemessages`时会出现错误：

```py
a format specification for argument 'name', as in 'msgstr[0]', doesn't exist in 'msgid' 

```

## 上下文标记

有时单词有几个含义，例如英语中的*May*，它既指月份名称又指动词。为了使翻译人员能够在不同的上下文中正确翻译这些单词，您可以使用`django.utils.translation.pgettext()`函数，或者如果字符串需要复数形式，则使用`django.utils.translation.npgettext()`函数。两者都将上下文字符串作为第一个变量。

在生成的`.po`文件中，该字符串将出现的次数与相同字符串的不同上下文标记一样多（上下文将出现在`msgctxt`行上），允许翻译人员为每个上下文标记提供不同的翻译。

例如：

```py
from django.utils.translation import pgettext 

month = pgettext("month name", "May") 

```

或：

```py
from django.db import models 
from django.utils.translation import pgettext_lazy 

class MyThing(models.Model): 
    name = models.CharField(help_text=pgettext_lazy( 
        'help text for MyThing model', 'This is the help text')) 

```

将出现在`.po`文件中：

```py
msgctxt "month name" 
msgid "May" 
msgstr "" 

```

上下文标记也受`trans`和`blocktrans`模板标记的支持。

## 延迟翻译

在`django.utils.translation`中使用翻译函数的延迟版本（通过它们的名称中的`lazy`后缀很容易识别）来延迟翻译字符串-当访问值而不是在调用它们时。

这些函数存储字符串的延迟引用-而不是实际的翻译。当字符串在字符串上下文中使用时（例如在模板渲染中），翻译本身将在最后可能的时间点进行。

当这些函数的调用位于模块加载时执行的代码路径中时，这是必不可少的。

这很容易发生在定义模型、表单和模型表单时，因为 Django 实现了这些，使得它们的字段实际上是类级属性。因此，在以下情况下，请确保使用延迟翻译。

### 模型字段和关系

例如，要翻译以下模型中*name*字段的帮助文本，请执行以下操作：

```py
from django.db import models 
from django.utils.translation import ugettext_lazy as _ 

class MyThing(models.Model): 
    name = models.CharField(help_text=_('This is the help text')) 

```

您可以通过使用它们的`verbose_name`选项将`ForeignKey`，`ManyToManyField`或`OneToOneField`关系的名称标记为可翻译：

```py
class MyThing(models.Model): 
    kind = models.ForeignKey(ThingKind, related_name='kinds',  verbose_name=_('kind')) 

```

就像您在`verbose_name`中所做的那样，当需要时，应为关系提供一个小写的详细名称文本，Django 将在需要时自动将其转换为标题大小写。

### 模型详细名称值

建议始终提供明确的`verbose_name`和`verbose_name_plural`选项，而不是依赖于 Django 通过查看模型类名执行的后备英语中心且有些天真的决定详细名称：

```py
from django.db import models 
from django.utils.translation import ugettext_lazy as _ 

class MyThing(models.Model): 
    name = models.CharField(_('name'), help_text=_('This is the help  text')) 

    class Meta: 
        verbose_name = _('my thing') 
        verbose_name_plural = _('my things') 

```

### 模型方法的`short_description`属性值

对于模型方法，你可以使用`short_description`属性为 Django 和管理站点提供翻译：

```py
from django.db import models 
from django.utils.translation import ugettext_lazy as _ 

class MyThing(models.Model): 
    kind = models.ForeignKey(ThingKind, related_name='kinds', 
                             verbose_name=_('kind')) 

    def is_mouse(self): 
        return self.kind.type == MOUSE_TYPE 
        is_mouse.short_description = _('Is it a mouse?') 

```

## 使用延迟翻译对象

`ugettext_lazy()`调用的结果可以在 Python 中任何需要使用 Unicode 字符串（类型为`unicode`的对象）的地方使用。如果你试图在需要字节字符串（`str`对象）的地方使用它，事情将不会按预期工作，因为`ugettext_lazy()`对象不知道如何将自己转换为字节字符串。你也不能在字节字符串中使用 Unicode 字符串，因此这与正常的 Python 行为一致。例如：

```py
# This is fine: putting a unicode proxy into a unicode string. 
"Hello %s" % ugettext_lazy("people") 

# This will not work, since you cannot insert a unicode object 
# into a bytestring (nor can you insert our unicode proxy there) 
b"Hello %s" % ugettext_lazy("people") 

```

如果你看到类似`"hello <django.utils.functional...>"`的输出，你尝试将`ugettext_lazy()`的结果插入到字节字符串中。这是你代码中的一个错误。

如果你不喜欢长长的`ugettext_lazy`名称，你可以将其别名为`_`（下划线），就像这样：

```py
from django.db import models 
from django.utils.translation import ugettext_lazy as _ 

class MyThing(models.Model): 
    name = models.CharField(help_text=_('This is the help text')) 

```

在模型和实用函数中使用`ugettext_lazy()`和`ungettext_lazy()`标记字符串是一个常见的操作。当你在代码的其他地方使用这些对象时，你应该确保不要意外地将它们转换为字符串，因为它们应该尽可能晚地转换（以便正确的区域设置生效）。这就需要使用下面描述的辅助函数。

### 延迟翻译和复数

当使用延迟翻译来处理复数字符串（`[u]n[p]gettext_lazy`）时，通常在字符串定义时不知道`number`参数。因此，你可以授权将一个键名而不是整数作为`number`参数传递。然后在字符串插值期间，`number`将在字典中查找该键下的值。这里有一个例子：

```py
from django import forms 
from django.utils.translation import ugettext_lazy 

class MyForm(forms.Form): 
    error_message = ungettext_lazy("You only provided %(num)d    
      argument", "You only provided %(num)d arguments", 'num') 

    def clean(self): 
        # ... 
        if error: 
            raise forms.ValidationError(self.error_message %  
              {'num': number}) 

```

如果字符串只包含一个未命名的占位符，你可以直接使用`number`参数进行插值：

```py
class MyForm(forms.Form): 
    error_message = ungettext_lazy("You provided %d argument", 
        "You provided %d arguments") 

    def clean(self): 
        # ... 
        if error: 
            raise forms.ValidationError(self.error_message % number) 

```

### 连接字符串：string_concat()

标准的 Python 字符串连接（`''.join([...])`）在包含延迟翻译对象的列表上不起作用。相反，你可以使用`django.utils.translation.string_concat()`，它创建一个延迟对象，只有在结果包含在字符串中时才将其内容连接并转换为字符串。例如：

```py
from django.utils.translation import string_concat 
from django.utils.translation import ugettext_lazy 
# ... 
name = ugettext_lazy('John Lennon') 
instrument = ugettext_lazy('guitar') 
result = string_concat(name, ': ', instrument) 

```

在这种情况下，`result`中的延迟翻译只有在`result`本身在字符串中使用时才会转换为字符串（通常在模板渲染时）。

### 延迟翻译的其他用途

对于任何其他需要延迟翻译的情况，但必须将可翻译的字符串作为参数传递给另一个函数，你可以自己在延迟调用内部包装这个函数。例如：

```py
from django.utils import six  # Python 3 compatibility 
from django.utils.functional import lazy 
from django.utils.safestring import mark_safe 
from django.utils.translation import ugettext_lazy as _ 

mark_safe_lazy = lazy(mark_safe, six.text_type) 

```

然后稍后：

```py
lazy_string = mark_safe_lazy(_("<p>My <strong>string!</strong></p>")) 

```

## 语言的本地化名称

`get_language_info()`函数提供了关于语言的详细信息：

```py
>>> from django.utils.translation import get_language_info 
>>> li = get_language_info('de') 
>>> print(li['name'], li['name_local'], li['bidi']) 
German Deutsch False 

```

字典的`name`和`name_local`属性包含了语言的英文名称和该语言本身的名称。`bidi`属性仅对双向语言为 True。

语言信息的来源是`django.conf.locale`模块。类似的访问这些信息的方式也适用于模板代码。见下文。

# 国际化：在模板代码中

Django 模板中的翻译使用了两个模板标签和与 Python 代码略有不同的语法。为了让你的模板可以访问这些标签，将

在你的模板顶部使用`{% load i18n %}`。与所有模板标签一样，这个标签需要在使用翻译的所有模板中加载，即使是那些从已经加载了`i18n`标签的其他模板继承的模板也是如此。

## trans 模板标签

`{% trans %}`模板标签可以翻译常量字符串（用单引号或双引号括起来）或变量内容：

```py
<title>{% trans "This is the title." %}</title> 
<title>{% trans myvar %}</title> 

```

如果存在`noop`选项，变量查找仍然会发生，但翻译会被跳过。这在需要将来进行翻译的内容中是有用的：

```py
<title>{% trans "myvar" noop %}</title> 

```

在内部，内联翻译使用了`ugettext()`调用。

如果将模板变量（如上面的 `myvar`）传递给标签，则标签将首先在运行时将该变量解析为字符串，然后在消息目录中查找该字符串。

不可能在 `{% trans %}` 内部的字符串中混合模板变量。如果您的翻译需要带有变量（占位符）的字符串，请改用 `{% blocktrans %}`。如果您想要检索翻译后的字符串而不显示它，可以使用以下语法：

```py
{% trans "This is the title" as the_title %} 

```

在实践中，您将使用此功能来获取在多个地方使用的字符串，或者应该用作其他模板标签或过滤器的参数：

```py
{% trans "starting point" as start %} 
{% trans "end point" as end %} 
{% trans "La Grande Boucle" as race %} 

<h1> 
  <a href="/" >{{ race }}</a> 
</h1> 
<p> 
{% for stage in tour_stages %} 
    {% cycle start end %}: {{ stage }}{% if forloop.counter|divisibleby:2 %}<br />{% else %}, {% endif %} 
{% endfor %} 
</p> 

```

`{% trans %}` 也支持使用 `context` 关键字进行上下文标记：

```py
{% trans "May" context "month name" %} 

```

## blocktrans 模板标签

`blocktrans` 标签允许您通过使用占位符标记由文字和变量内容组成的复杂句子进行翻译。

```py
{% blocktrans %}This string will have {{ value }} inside.{% endblocktrans %} 

```

要翻译模板表达式，比如访问对象属性或使用模板过滤器，您需要将表达式绑定到本地变量，以便在翻译块内使用。例如：

```py
{% blocktrans with amount=article.price %} 
That will cost $ {{ amount }}. 
{% endblocktrans %} 

{% blocktrans with myvar=value|filter %} 
This will have {{ myvar }} inside. 
{% endblocktrans %} 

```

您可以在单个 `blocktrans` 标签内使用多个表达式：

```py
{% blocktrans with book_t=book|title author_t=author|title %} 
This is {{ book_t }} by {{ author_t }} 
{% endblocktrans %} 

```

仍然支持以前更冗长的格式：`{% blocktrans with book|title as book_t and author|title as author_t %}`

不允许在 `blocktrans` 标签内部使用其他块标签（例如 `{% for %}` 或 `{% if %}`）。

如果解析其中一个块参数失败，`blocktrans` 将通过使用 `deactivate_all()` 函数临时停用当前活动的语言来回退到默认语言。

此标签还提供了复数形式。使用方法如下：

+   指定并绑定名为 `count` 的计数器值。此值将用于选择正确的复数形式。

+   使用两种形式分隔单数和复数形式

+   `{% plural %}` 标签在 `{% blocktrans %}` 和 `{% endblocktrans %}` 标签内。

一个例子：

```py
{% blocktrans count counter=list|length %} 
There is only one {{ name }} object. 
{% plural %} 
There are {{ counter }} {{ name }} objects. 
{% endblocktrans %} 

```

一个更复杂的例子：

```py
{% blocktrans with amount=article.price count years=i.length %} 
That will cost $ {{ amount }} per year. 
{% plural %} 
That will cost $ {{ amount }} per {{ years }} years. 
{% endblocktrans %} 

```

当您同时使用复数形式功能并将值绑定到本地变量以及计数器值时，请记住 `blocktrans` 结构在内部转换为 `ungettext` 调用。这意味着与 `ungettext` 变量相关的相同注释也适用。

不能在 `blocktrans` 内部进行反向 URL 查找，应该事先检索（和存储）：

```py
{% url 'path.to.view' arg arg2 as the_url %} 
{% blocktrans %} 
This is a URL: {{ the_url }} 
{% endblocktrans %} 

```

`{% blocktrans %}` 还支持使用 `context` 关键字进行上下文标记：

```py
{% blocktrans with name=user.username context "greeting" %} 
Hi {{ name }}{% endblocktrans %} 

```

`{% blocktrans %}` 支持的另一个功能是 `trimmed` 选项。此选项将从 `{% blocktrans %}` 标签的内容开头和结尾删除换行符，替换行开头和结尾的任何空格，并使用空格字符将所有行合并成一行。

这对于缩进 `{% blocktrans %}` 标签的内容而不使缩进字符出现在 PO 文件中的相应条目中非常有用，这样可以使翻译过程更加简单。

例如，以下 `{% blocktrans %}` 标签：

```py
{% blocktrans trimmed %} 
  First sentence. 
  Second paragraph. 
{% endblocktrans %} 

```

如果未指定 `trimmed` 选项，将在 PO 文件中生成条目 `"First sentence. Second paragraph."`，而不是 `"\n First sentence.\n Second sentence.\n"`。

## 传递给标签和过滤器的字符串文字

您可以使用熟悉的 `_()` 语法将作为参数传递给标签和过滤器的字符串文字进行翻译：

```py
{% some_tag _("Page not found") value|yesno:_("yes,no") %} 

```

在这种情况下，标签和过滤器都将看到翻译后的字符串，因此它们不需要知道翻译。

在此示例中，翻译基础设施将传递字符串 "`yes,no`"，而不是单独的字符串 "`yes`" 和 "`no`"。翻译后的字符串需要包含逗号，以便过滤器解析代码知道如何分割参数。例如，德语翻译者可能将字符串 "`yes,no`" 翻译为 "`ja,nein`"（保持逗号不变）。

## 模板中的翻译者注释

与 Python 代码一样，这些翻译者注释可以使用注释指定，可以使用 `comment` 标签：

```py
{% comment %}Translators: View verb{% endcomment %} 
{% trans "View" %} 

{% comment %}Translators: Short intro blurb{% endcomment %} 
<p>{% blocktrans %} 
    A multiline translatable literal. 
   {% endblocktrans %} 
</p> 

```

或者使用 `{#` ... `#}` 单行注释结构：

```py
{# Translators: Label of a button that triggers search #} 
<button type="submit">{% trans "Go" %}</button> 

{# Translators: This is a text of the base template #} 
{% blocktrans %}Ambiguous translatable block of text{% endblocktrans %} 

```

仅供完整性，这些是生成的`.po`文件的相应片段：

```py
#. Translators: View verb 
# path/to/template/file.html:10 
msgid "View" 
msgstr "" 

#. Translators: Short intro blurb 
# path/to/template/file.html:13 
msgid "" 
"A multiline translatable" 
"literal." 
msgstr "" 

# ... 

#. Translators: Label of a button that triggers search 
# path/to/template/file.html:100 
msgid "Go" 
msgstr "" 

#. Translators: This is a text of the base template 
# path/to/template/file.html:103 
msgid "Ambiguous translatable block of text" 
msgstr "" 

```

## 在模板中切换语言

如果要在模板中选择语言，则可以使用`language`模板标签：

```py
{% load i18n %} 

{% get_current_language as LANGUAGE_CODE %} 
<!-- Current language: {{ LANGUAGE_CODE }} --> 
<p>{% trans "Welcome to our page" %}</p> 

{% language 'en' %} 

    {% get_current_language as LANGUAGE_CODE %} 
    <!-- Current language: {{ LANGUAGE_CODE }} --> 
    <p>{% trans "Welcome to our page" %}</p> 

{% endlanguage %} 

```

虽然欢迎来到我们的页面的第一次出现使用当前语言，但第二次将始终是英语。

## 其他标签

这些标签还需要`{% load i18n %}`。

+   `{% get_available_languages as LANGUAGES %}`返回一个元组列表，其中第一个元素是语言代码，第二个是语言名称（翻译为当前活动的区域设置）。

+   `{% get_current_language as LANGUAGE_CODE %}`返回当前用户的首选语言，作为字符串。例如：`en-us`。（请参见本章后面的*django 如何发现语言偏好*。）

+   `{% get_current_language_bidi as LANGUAGE_BIDI %}`返回当前区域设置的方向。如果为 True，则是从右到左的语言，例如希伯来语，阿拉伯语。如果为 False，则是从左到右的语言，例如英语，法语，德语等。

如果启用了`django.template.context_processors.i18n`上下文处理器，则每个`RequestContext`将可以访问`LANGUAGES`，`LANGUAGE_CODE`和`LANGUAGE_BIDI`，如上所定义。

对于新项目，默认情况下不会为`i18n`上下文处理器启用。

您还可以使用提供的模板标签和过滤器检索有关任何可用语言的信息。要获取有关单个语言的信息，请使用`{% get_language_info %}`标签：

```py
{% get_language_info for LANGUAGE_CODE as lang %} 
{% get_language_info for "pl" as lang %} 

```

然后您可以访问这些信息：

```py
Language code: {{ lang.code }}<br /> 
Name of language: {{ lang.name_local }}<br /> 
Name in English: {{ lang.name }}<br /> 
Bi-directional: {{ lang.bidi }} 

```

您还可以使用`{% get_language_info_list %}`模板标签来检索语言列表的信息（例如在`LANGUAGES`中指定的活动语言）。请参阅关于`set_language`重定向视图的部分，了解如何使用`{% get_language_info_list %}`显示语言选择器的示例。

除了`LANGUAGES`风格的元组列表外，`{% get_language_info_list %}`还支持简单的语言代码列表。如果在视图中这样做：

```py
context = {'available_languages': ['en', 'es', 'fr']} 
return render(request, 'mytemplate.html', context) 

```

您可以在模板中迭代这些语言：

```py
{% get_language_info_list for available_languages as langs %} 
{% for lang in langs %} ... {% endfor %} 

```

还有一些简单的过滤器可供使用：

+   `{{ LANGUAGE_CODE|language_name }}`（德语）

+   `{{ LANGUAGE_CODE|language_name_local }}`（德语）

+   `{{ LANGUAGE_CODE|language_bidi }}` (False)

# 国际化：在 JavaScript 代码中

向 JavaScript 添加翻译会带来一些问题：

+   JavaScript 代码无法访问`gettext`实现。

+   JavaScript 代码无法访问`.po`或`.mo`文件；它们需要由服务器传送。

+   JavaScript 的翻译目录应尽可能保持小。

Django 为这些问题提供了一个集成的解决方案：它将翻译传递到 JavaScript 中，因此您可以在 JavaScript 中调用`gettext`等。

## javascript_catalog 视图

这些问题的主要解决方案是`django.views.i18n.javascript_catalog()`视图，它发送一个 JavaScript 代码库，其中包含模仿`gettext`接口的函数，以及一个翻译字符串数组。

这些翻译字符串是根据您在`info_dict`或 URL 中指定的内容来自应用程序或 Django 核心。`LOCALE_PATHS`中列出的路径也包括在内。

您可以这样连接它：

```py
from django.views.i18n import javascript_catalog 

js_info_dict = { 
    'packages': ('your.app.package',), 
} 

urlpatterns = [ 
    url(r'^jsi18n/$', javascript_catalog, js_info_dict), 
] 

```

`packages`中的每个字符串都应该是 Python 点分包语法（与`INSTALLED_APPS`中的字符串格式相同），并且应该引用包含`locale`目录的包。如果指定多个包，所有这些目录都将合并为一个目录。如果您的 JavaScript 使用来自不同应用程序的字符串，则这很有用。

翻译的优先级是这样的，`packages`参数中后面出现的包比出现在开头的包具有更高的优先级，这在相同文字的冲突翻译的情况下很重要。

默认情况下，视图使用`djangojs` `gettext`域。这可以通过修改`domain`参数来更改。

您可以通过将包放入 URL 模式中使视图动态化：

```py
urlpatterns = [ 
    url(r'^jsi18n/(?P<packages>\S+?)/$', javascript_catalog), 
] 

```

通过这种方式，您可以将包作为 URL 中由`+`符号分隔的包名称列表指定。如果您的页面使用来自不同应用的代码，并且这些代码经常更改，您不希望拉入一个大的目录文件，这将特别有用。作为安全措施，这些值只能是`django.conf`或`INSTALLED_APPS`设置中的任何包。

`LOCALE_PATHS`设置中列出的路径中找到的 JavaScript 翻译也总是包含在内。为了保持与用于 Python 和模板的翻译查找顺序算法的一致性，`LOCALE_PATHS`中列出的目录具有最高的优先级，先出现的目录比后出现的目录具有更高的优先级。

## 使用 JavaScript 翻译目录

要使用目录，只需像这样拉入动态生成的脚本：

```py
<script type="text/javascript" src="img/{% url  'django.views.i18n.javascript_catalog' %}"></script> 

```

这使用了反向 URL 查找来查找 JavaScript 目录视图的 URL。加载目录时，您的 JavaScript 代码可以使用标准的`gettext`接口来访问它：

```py
document.write(gettext('this is to be translated')); 

```

还有一个`ngettext`接口：

```py
var object_cnt = 1 // or 0, or 2, or 3, ... 
s = ngettext('literal for the singular case', 
      'literal for the plural case', object_cnt); 

```

甚至还有一个字符串插值函数：

```py
function interpolate(fmt, obj, named); 

```

插值语法是从 Python 借来的，因此`interpolate`函数支持位置和命名插值：

+   位置插值：`obj`包含一个 JavaScript 数组对象，其元素值然后按照它们出现的顺序依次插值到相应的`fmt`占位符中。例如：

```py
        fmts = ngettext('There is %s object. Remaining: %s', 
                 'There are %s objects. Remaining: %s', 11); 
        s = interpolate(fmts, [11, 20]); 
        // s is 'There are 11 objects. Remaining: 20' 

```

+   命名插值：通过将可选的布尔命名参数设置为 true 来选择此模式。`obj`包含一个 JavaScript 对象或关联数组。例如：

```py
        d = { 
            count: 10, 
            total: 50 
        }; 

        fmts = ngettext('Total: %(total)s, there is %(count)s  
          object', 
          'there are %(count)s of a total of %(total)s objects', 
            d.count); 
        s = interpolate(fmts, d, true); 

```

不过，您不应该过度使用字符串插值：这仍然是 JavaScript，因此代码必须进行重复的正则表达式替换。这不像 Python 中的字符串插值那样快，因此只在您真正需要它的情况下使用它（例如，与`ngettext`一起产生正确的复数形式）。

## 性能说明

`javascript_catalog()`视图会在每次请求时从`.mo`文件生成目录。由于它的输出是恒定的-至少对于站点的特定版本来说-它是一个很好的缓存候选者。

服务器端缓存将减少 CPU 负载。可以使用`cache_page()`装饰器轻松实现。要在翻译更改时触发缓存失效，请提供一个版本相关的键前缀，如下例所示，或者将视图映射到一个版本相关的 URL。

```py
from django.views.decorators.cache import cache_page 
from django.views.i18n import javascript_catalog 

# The value returned by get_version() must change when translations change. 
@cache_page(86400, key_prefix='js18n-%s' % get_version()) 
def cached_javascript_catalog(request, domain='djangojs', packages=None): 
    return javascript_catalog(request, domain, packages) 

```

客户端缓存将节省带宽并使您的站点加载更快。如果您使用 ETags（`USE_ETAGS = True`），则已经覆盖了。否则，您可以应用条件装饰器。在下面的示例中，每当重新启动应用程序服务器时，缓存就会失效。

```py
from django.utils import timezone 
from django.views.decorators.http import last_modified 
from django.views.i18n import javascript_catalog 

last_modified_date = timezone.now() 

@last_modified(lambda req, **kw: last_modified_date) 
def cached_javascript_catalog(request, domain='djangojs', packages=None): 
    return javascript_catalog(request, domain, packages) 

```

您甚至可以在部署过程的一部分预先生成 JavaScript 目录，并将其作为静态文件提供。[`django-statici18n.readthedocs.org/en/latest/`](http://django-statici18n.readthedocs.org/en/latest/)。

# 国际化：在 URL 模式中

Django 提供了两种国际化 URL 模式的机制：

+   将语言前缀添加到 URL 模式的根部，以便`LocaleMiddleware`可以从请求的 URL 中检测要激活的语言。

+   通过`django.utils.translation.ugettext_lazy()`函数使 URL 模式本身可翻译。

使用这些功能中的任何一个都需要为每个请求设置一个活动语言；换句话说，您需要在`MIDDLEWARE_CLASSES`设置中拥有`django.middleware.locale.LocaleMiddleware`。

## URL 模式中的语言前缀

这个函数可以在您的根 URLconf 中使用，Django 将自动将当前活动语言代码添加到`i18n_patterns()`中定义的所有 URL 模式之前。示例 URL 模式：

```py
from django.conf.urls import include, url 
from django.conf.urls.i18n import i18n_patterns 
from about import views as about_views 
from news import views as news_views 
from sitemap.views import sitemap 

urlpatterns = [ 
    url(r'^sitemap\.xml$', sitemap, name='sitemap_xml'), 
] 

news_patterns = [ 
    url(r'^$', news_views.index, name='index'), 
    url(r'^category/(?P<slug>[\w-]+)/$',  
        news_views.category, 
        name='category'), 
    url(r'^(?P<slug>[\w-]+)/$', news_views.details, name='detail'), 
] 

urlpatterns += i18n_patterns( 
    url(r'^about/$', about_views.main, name='about'), 
    url(r'^news/', include(news_patterns, namespace='news')), 
) 

```

定义这些 URL 模式后，Django 将自动将语言前缀添加到由`i18n_patterns`函数添加的 URL 模式。例如：

```py
from django.core.urlresolvers import reverse 
from django.utils.translation import activate 

>>> activate('en') 
>>> reverse('sitemap_xml') 
'/sitemap.xml' 
>>> reverse('news:index') 
'/en/news/' 

>>> activate('nl') 
>>> reverse('news:detail', kwargs={'slug': 'news-slug'}) 
'/nl/news/news-slug/' 

```

`i18n_patterns()`只允许在根 URLconf 中使用。在包含的 URLconf 中使用它将引发`ImproperlyConfigured`异常。

## 翻译 URL 模式

URL 模式也可以使用`ugettext_lazy()`函数进行标记翻译。例如：

```py
from django.conf.urls import include, url 
from django.conf.urls.i18n import i18n_patterns 
from django.utils.translation import ugettext_lazy as _ 

from about import views as about_views 
from news import views as news_views 
from sitemaps.views import sitemap 

urlpatterns = [ 
    url(r'^sitemap\.xml$', sitemap, name='sitemap_xml'), 
] 

news_patterns = [ 
    url(r'^$', news_views.index, name='index'), 
    url(_(r'^category/(?P<slug>[\w-]+)/$'),  
        news_views.category, 
        name='category'), 
    url(r'^(?P<slug>[\w-]+)/$', news_views.details, name='detail'), 
] 

urlpatterns += i18n_patterns( 
    url(_(r'^about/$'), about_views.main, name='about'), 
    url(_(r'^news/'), include(news_patterns, namespace='news')), 
) 

```

创建了翻译后，`reverse()`函数将返回活动语言的 URL。例如：

```py
>>> from django.core.urlresolvers import reverse 
>>> from django.utils.translation import activate 

>>> activate('en') 
>>> reverse('news:category', kwargs={'slug': 'recent'}) 
'/en/news/category/recent/' 

>>> activate('nl') 
>>> reverse('news:category', kwargs={'slug': 'recent'}) 
'/nl/nieuws/categorie/recent/' 

```

在大多数情况下，最好只在语言代码前缀的模式块中使用翻译后的 URL（使用`i18n_patterns()`），以避免疏忽翻译的 URL 导致与未翻译的 URL 模式发生冲突的可能性。

## 在模板中进行反向操作

如果在模板中反转了本地化的 URL，它们将始终使用当前语言。要链接到另一种语言的 URL，请使用`language`模板标签。它在封闭的模板部分中启用给定的语言：

```py
{% load i18n %} 

{% get_available_languages as languages %} 

{% trans "View this category in:" %} 
{% for lang_code, lang_name in languages %} 
    {% language lang_code %} 
    <a href="{% url 'category' slug=category.slug %}">{{ lang_name }}</a> 
    {% endlanguage %} 
{% endfor %} 

```

`language`标签期望语言代码作为唯一参数。

# 本地化：如何创建语言文件

一旦应用程序的字符串文字被标记为以后进行翻译，翻译本身需要被编写（或获取）。下面是它的工作原理。

## 消息文件

第一步是为新语言创建一个消息文件。消息文件是一个纯文本文件，代表单一语言，包含所有可用的翻译字符串以及它们在给定语言中的表示方式。消息文件具有`.po`文件扩展名。

Django 附带了一个工具`django-admin makemessages`，它可以自动创建和维护这些文件。

`makemessages`命令（以及稍后讨论的`compilemessages`）使用 GNU `gettext`工具集中的命令：`xgettext`、`msgfmt`、`msgmerge`和`msguniq`。

支持的`gettext`实用程序的最低版本为 0.15。

要创建或更新消息文件，请运行此命令：

```py
django-admin makemessages -l de 

```

...其中`de`是要创建的消息文件的区域名称。例如，`pt_BR`表示巴西葡萄牙语，`de_AT`表示奥地利德语，`id`表示印尼语。

该脚本应该从以下两个地方之一运行：

+   您的 Django 项目的根目录（包含`manage.py`的目录）。

+   您的 Django 应用程序之一的根目录。

该脚本在项目源树或应用程序源树上运行，并提取所有标记为翻译的字符串（请参阅 how-django-discovers-translations 并确保`LOCALE_PATHS`已正确配置）。它在目录`locale/LANG/LC_MESSAGES`中创建（或更新）一个消息文件。在`de`的示例中，文件将是`locale/de/LC_MESSAGES/django.po`。

当您从项目的根目录运行`makemessages`时，提取的字符串将自动分发到适当的消息文件中。也就是说，从包含`locale`目录的应用程序文件中提取的字符串将放在该目录下的消息文件中。从不包含任何`locale`目录的应用程序文件中提取的字符串将放在`LOCALE_PATHS`中列出的第一个目录下的消息文件中，如果`LOCALE_PATHS`为空，则会生成错误。

默认情况下，`django-admin makemessages`检查具有`.html`或`.txt`文件扩展名的每个文件。如果要覆盖默认设置，请使用`-extension`或`-e`选项指定要检查的文件扩展名：

```py
django-admin makemessages -l de -e txt 

```

用逗号分隔多个扩展名和/或多次使用`-e`或`-extension`：

```py
django-admin makemessages -l de -e html,txt -e xml 

```

### 注意

从 JavaScript 源代码创建消息文件时，需要使用特殊的'djangojs'域，而不是`e js`。

如果您没有安装`gettext`实用程序，`makemessages`将创建空文件。如果是这种情况，要么安装`gettext`实用程序，要么只需复制英文消息文件（`locale/en/LC_MESSAGES/django.po`）（如果有的话）并将其用作起点；它只是一个空的翻译文件。

如果您使用 Windows 并且需要安装 GNU `gettext`实用程序以便`makemessages`正常工作，请参阅本章稍后的*在 Windows 上使用 gettext*以获取更多信息。

`.po`文件的格式很简单。每个`.po`文件包含一小部分元数据，例如翻译维护者的联系信息，但文件的大部分是*消息*的列表-翻译字符串和特定语言的实际翻译文本之间的简单映射。

例如，如果您的 Django 应用程序包含了文本`"欢迎来到我的网站。"`的翻译字符串，如下所示：

```py
_("Welcome to my site.") 

```

然后`django-admin makemessages`将创建一个包含以下片段消息的`.po`文件：

```py
#: path/to/python/module.py:23 
msgid "Welcome to my site." 
msgstr "" 

```

一个简单的解释：

+   `msgid`是出现在源中的翻译字符串。不要更改它。

+   `msgstr`是您放置特定于语言的翻译的地方。它起初是空的，所以您有责任更改它。确保您在翻译周围保留引号。

+   为了方便起见，每条消息都包括一个以`#`为前缀的注释行，位于`msgid`行上方，其中包含了翻译字符串所在的文件名和行号。

长消息是一个特殊情况。在那里，`msgstr`（或`msgid`）之后的第一个字符串是一个空字符串。然后内容本身将作为下面几行的一个字符串写入。这些字符串直接连接在一起。不要忘记字符串内的尾随空格；否则，它们将被连接在一起而没有空格！

由于`gettext`工具的内部工作方式，以及我们希望允许 Django 核心和您的应用程序中的非 ASCII 源字符串，您必须将 UTF-8 用作 PO 文件的编码（创建 PO 文件时的默认值）。这意味着每个人都将使用相同的编码，在 Django 处理 PO 文件时这一点很重要。

要重新检查所有源代码和模板以获取新的翻译字符串，并为所有语言更新所有消息文件，请运行以下命令：

```py
django-admin makemessages -a 

```

## 编译消息文件

创建消息文件后，每次对其进行更改时，您都需要将其编译为`gettext`可以使用的更高效的形式。使用`django-admin compilemessages`实用程序进行此操作。

此工具将遍历所有可用的`.po`文件，并创建`.mo`文件，这些文件是为`gettext`使用而优化的二进制文件。在您运行`django-admin makemessages`的同一目录中运行：

```py
django-admin compilemessages 

```

就是这样。您的翻译已经准备好了。

如果您使用 Windows 并且需要安装 GNU `gettext`实用程序以使`django-admin compilemessages`正常工作，请参阅下面有关 Windows 上的`gettext`的更多信息。

Django 仅支持以 UTF-8 编码且没有任何 BOM（字节顺序标记）的`.po`文件，因此如果您的文本编辑器默认在文件开头添加这些标记，那么您需要重新配置它。

## 从 JavaScript 源代码创建消息文件

您可以像其他 Django 消息文件一样使用`django-admin makemessages`工具创建和更新消息文件。唯一的区别是，您需要显式指定在这种情况下称为`djangojs`域的`gettext`术语中的域，通过提供一个`-d djangojs`参数，就像这样：

```py
django-admin makemessages -d djangojs -l de 

```

这将为德语创建或更新 JavaScript 的消息文件。更新消息文件后，只需像处理普通 Django 消息文件一样运行`django-admin compilemessages`。

## Windows 上的 gettext

这仅适用于那些想要提取消息 ID 或编译消息文件（`.po`）的人。翻译工作本身只涉及编辑这种类型的现有文件，但如果您想创建自己的消息文件，或者想测试或编译已更改的消息文件，您将需要`gettext`实用程序：

+   从 GNOME 服务器（[`download.gnome.org/binaries/win32/dependencies/`](https://download.gnome.org/binaries/win32/dependencies/)）下载以下 zip 文件

+   `gettext-runtime-X.zip`

+   `gettext-tools-X.zip`

`X`是版本号；需要版本`0.15`或更高版本。

+   将这两个文件夹中`bin\`目录的内容提取到系统上的同一个文件夹中（即`C:\Program Files\gettext-utils`）

+   更新系统 PATH：

+   `控制面板 > 系统 > 高级 > 环境变量`。

+   在`系统变量`列表中，点击`Path`，点击`Edit`。

+   在`Variable value`字段的末尾添加`;C:\Program Files\gettext-utils\bin`。

您也可以使用其他地方获取的`gettext`二进制文件，只要`xgettext -version`命令正常工作。如果在 Windows 命令提示符中输入`xgettext -version`命令会弹出一个窗口说 xgettext.exe 已经生成错误并将被 Windows 关闭，请不要尝试使用 Django 翻译工具与`gettext`包。

## 自定义 makemessages 命令

如果您想向`xgettext`传递额外的参数，您需要创建一个自定义的`makemessages`命令并覆盖其`xgettext_options`属性：

```py
from django.core.management.commands import makemessages 

class Command(makemessages.Command): 
    xgettext_options = makemessages.Command.xgettext_options +  
      ['-keyword=mytrans'] 

```

如果您需要更灵活性，您还可以向自定义的`makemessages`命令添加一个新参数：

```py
from django.core.management.commands import makemessages 

class Command(makemessages.Command): 

    def add_arguments(self, parser): 
        super(Command, self).add_arguments(parser) 
        parser.add_argument('-extra-keyword', 
                            dest='xgettext_keywords',  
                            action='append') 

    def handle(self, *args, **options): 
        xgettext_keywords = options.pop('xgettext_keywords') 
        if xgettext_keywords: 
            self.xgettext_options = ( 
                makemessages.Command.xgettext_options[:] + 
                ['-keyword=%s' % kwd for kwd in xgettext_keywords] 
            ) 
        super(Command, self).handle(*args, **options) 

```

# 显式设置活动语言

您可能希望明确为当前会话设置活动语言。也许用户的语言偏好是从另一个系统中检索的。例如，您已经介绍了`django.utils.translation.activate()`。这仅适用于当前线程。要使语言在整个会话中持续存在，还要修改会话中的`LANGUAGE_SESSION_KEY`：

```py
from django.utils import translation 
user_language = 'fr' 
translation.activate(user_language) 
request.session[translation.LANGUAGE_SESSION_KEY] = user_language 

```

通常您希望同时使用：`django.utils.translation.activate()`将更改此线程的语言，并修改会话使此偏好在将来的请求中持续存在。

如果您不使用会话，语言将保留在一个 cookie 中，其名称在`LANGUAGE_COOKIE_NAME`中配置。例如：

```py
from django.utils import translation 
from django import http 
from django.conf import settings 
user_language = 'fr' 
translation.activate(user_language) 
response = http.HttpResponse(...) 
response.set_cookie(settings.LANGUAGE_COOKIE_NAME, user_language) 

```

# 在视图和模板之外使用翻译

虽然 Django 提供了丰富的国际化工具供视图和模板使用，但它并不限制使用于 Django 特定的代码。Django 的翻译机制可以用于将任意文本翻译成 Django 支持的任何语言（当然，前提是存在适当的翻译目录）。

您可以加载一个翻译目录，激活它并将文本翻译成您选择的语言，但请记住切换回原始语言，因为激活翻译目录是基于每个线程的，这样的更改将影响在同一线程中运行的代码。

例如：

```py
from django.utils import translation 
def welcome_translated(language): 
    cur_language = translation.get_language() 
    try: 
        translation.activate(language) 
        text = translation.ugettext('welcome') 
    finally: 
        translation.activate(cur_language) 
    return text 

```

使用值'de'调用此函数将给您"`Willkommen`"，而不管`LANGUAGE_CODE`和中间件设置的语言如何。

特别感兴趣的功能是`django.utils.translation.get_language()`，它返回当前线程中使用的语言，`django.utils.translation.activate()`，它激活当前线程的翻译目录，以及`django.utils.translation.check_for_language()`，它检查给定的语言是否受 Django 支持。

# 实现说明

## Django 翻译的特点

Django 的翻译机制使用了 Python 自带的标准`gettext`模块。如果您了解`gettext`，您可能会注意到 Django 在翻译方面的一些特点：

+   字符串域是`django`或`djangojs`。这个字符串域用于区分存储其数据在一个共同的消息文件库中的不同程序（通常是`/usr/share/locale/`）。`django`域用于 Python 和模板翻译字符串，并加载到全局翻译目录中。`djangojs`域仅用于 JavaScript 翻译目录，以确保其尽可能小。

+   Django 不仅仅使用`xgettext`。它使用围绕`xgettext`和`msgfmt`的 Python 包装器。这主要是为了方便。

## Django 如何发现语言偏好

一旦您准备好您的翻译，或者如果您只想使用 Django 提供的翻译，您需要为您的应用程序激活翻译。

在幕后，Django 有一个非常灵活的模型来决定应该使用哪种语言-全局安装、特定用户或两者。

要设置全局安装的语言偏好，请设置`LANGUAGE_CODE`。Django 将使用此语言作为默认翻译-如果通过区域设置中间件采用的方法找不到更好的匹配翻译，则作为最后一次尝试。

如果您只想使用本地语言运行 Django，您只需要设置`LANGUAGE_CODE`并确保相应的消息文件及其编译版本（`.mo`）存在。

如果要让每个用户指定他们喜欢的语言，那么您还需要使用`LocaleMiddleware`。`LocaleMiddleware`基于请求中的数据启用语言选择。它为每个用户定制内容。

要使用`LocaleMiddleware`，请将`'django.middleware.locale.LocaleMiddleware'`添加到您的`MIDDLEWARE_CLASSES`设置中。因为中间件顺序很重要，所以您应该遵循以下准则：

+   确保它是最先安装的中间件之一。

+   它应该放在`SessionMiddleware`之后，因为`LocaleMiddleware`使用会话数据。它应该放在`CommonMiddleware`之前，因为`CommonMiddleware`需要激活的语言来解析请求的 URL。

+   如果使用`CacheMiddleware`，请在其后放置`LocaleMiddleware`。

例如，您的`MIDDLEWARE_CLASSES`可能如下所示：

```py
MIDDLEWARE_CLASSES = [ 
   'django.contrib.sessions.middleware.SessionMiddleware', 
   'django.middleware.locale.LocaleMiddleware', 
   'django.middleware.common.CommonMiddleware', 
] 

```

有关中间件的更多信息，请参见第十七章，*Django 中间件*。

`LocaleMiddleware`尝试通过以下算法确定用户的语言偏好：

+   首先，它会在请求的 URL 中查找语言前缀。只有在您的根 URLconf 中使用`i18n_patterns`函数时才会执行此操作。有关语言前缀以及如何国际化 URL 模式的更多信息，请参见*国际化*。

+   如果失败，它会查找当前用户会话中的`LANGUAGE_SESSION_KEY`键。

+   如果失败，它会查找一个 cookie。使用的 cookie 的名称由`LANGUAGE_COOKIE_NAME`设置。 （默认名称是`django_language`。）

+   如果失败，它会查看`Accept-Language` HTTP 标头。此标头由您的浏览器发送，并告诉服务器您首选的语言（按优先级顺序）。Django 尝试标头中的每种语言，直到找到具有可用翻译的语言。

+   ***** 如果失败，它会使用全局`LANGUAGE_CODE`设置。

**注意：**

+   在这些地方中，语言偏好应该是标准语言格式的字符串。例如，巴西葡萄牙语是`pt-br`。

+   如果基本语言可用但未指定子语言，则 Django 将使用基本语言。例如，如果用户指定`de-at`（奥地利德语），但 Django 只有`de`可用，Django 将使用`de`。

+   只有在`LANGUAGES`设置中列出的语言才能被选择。如果要将语言选择限制为提供的语言的子集（因为您的应用程序没有提供所有这些语言），请将`LANGUAGES`设置为语言列表。例如：

```py

        LANGUAGES = [ 
          ('de', _('German')), 
          ('en', _('English')), 
        ] 

```

此示例将可用于自动选择的语言限制为德语和英语（以及任何子语言，如`de-ch`或`en-us`）。

+   如果您定义了自定义的`LANGUAGES`设置，如前面的项目所述，您可以将语言名称标记为翻译字符串-但使用`ugettext_lazy()`而不是`ugettext()`以避免循环导入。

这里有一个示例设置文件：

```py
from django.utils.translation import ugettext_lazy as _ 

LANGUAGES = [ 
    ('de', _('German')), 
    ('en', _('English')), 
] 

```

一旦`LocaleMiddleware`确定了用户的偏好，它会将这个偏好作为`request.LANGUAGE_CODE`对每个`HttpRequest`可用。请随意在您的视图代码中读取这个值。这里有一个简单的例子：

```py
from django.http import HttpResponse 

def hello_world(request, count): 
    if request.LANGUAGE_CODE == 'de-at': 
        return HttpResponse("You prefer to read Austrian German.") 
    else: 
        return HttpResponse("You prefer to read another language.") 

```

请注意，对于静态（无中间件）翻译，语言在`settings.LANGUAGE_CODE`中，而对于动态（中间件）翻译，它在`request.LANGUAGE_CODE`中。

## Django 如何发现翻译

在运行时，Django 会构建一个内存中的统一的文字翻译目录。为了实现这一点，它会按照一定的顺序查找不同文件路径来加载编译好的消息文件（`.mo`），并确定同一文字的多个翻译的优先级。

+   在`LOCALE_PATHS`中列出的目录具有最高的优先级，出现在前面的优先级高于后面的。

+   然后，它会查找并使用（如果存在）每个已安装应用程序中的`INSTALLED_APPS`列表中的`locale`目录。出现在前面的优先级高于后面的。

+   最后，Django 提供的基础翻译在`django/conf/locale`中被用作后备。

在所有情况下，包含翻译的目录的名称应该使用语言环境的命名规范。例如，`de`，`pt_BR`，`es_AR`等。

通过这种方式，您可以编写包含自己翻译的应用程序，并且可以覆盖项目中的基础翻译。或者，您可以构建一个由多个应用程序组成的大型项目，并将所有翻译放入一个特定于您正在组合的项目的大型共同消息文件中。选择权在您手中。

所有消息文件存储库的结构都是相同的。它们是：

+   在您的设置文件中列出的`LOCALE_PATHS`中搜索`<language>/LC_MESSAGES/django.(po|mo)`

+   `$APPPATH/locale/<language>/LC_MESSAGES/django.(po|mo)`

+   `$PYTHONPATH/django/conf/locale/<language>/LC_MESSAGES/django.(po|mo).`

要创建消息文件，您可以使用`django-admin makemessages`工具。您可以使用`django-admin compilemessages`来生成二进制的`.mo`文件，这些文件将被`gettext`使用。

您还可以运行`django-admin compilemessages`来使编译器处理`LOCALE_PATHS`设置中的所有目录。

# 接下来是什么？

在下一章中，我们将讨论 Django 中的安全性。


# 第十九章：Django 中的安全性

确保您构建的网站是安全的对于专业的 Web 应用程序开发人员至关重要。

Django 框架现在非常成熟，大多数常见的安全问题都以某种方式得到了解决，但是没有安全措施是 100%保证的，而且新的威胁不断出现，因此作为 Web 开发人员，您需要确保您的网站和应用程序是安全的。

Web 安全是一个庞大的主题，无法在一本书的章节中深入讨论。本章概述了 Django 的安全功能，并提供了有关保护 Django 网站的建议，这将在 99%的时间内保护您的网站，但您需要随时了解 Web 安全的变化。

有关 Web 安全的更详细信息，请参阅 Django 的安全问题存档（有关更多信息，请访问[`docs.djangoproject.com/en/1.8/releases/security/`](https://docs.djangoproject.com/en/1.8/releases/security/)），以及维基百科的 Web 应用程序安全页面（[`en.wikipedia.org/wiki/web_application_security`](https://en.wikipedia.org/wiki/web_application_security)）。

# Django 内置的安全功能

## 跨站点脚本攻击（XSS）保护

**跨站点脚本**（**XSS**）攻击允许用户向其他用户的浏览器注入客户端脚本。

这通常是通过将恶意脚本存储在数据库中，然后检索并显示给其他用户，或者让用户点击一个链接，从而导致攻击者的 JavaScript 在用户的浏览器中执行。但是，XSS 攻击可能源自任何不受信任的数据源，例如 cookie 或 Web 服务，只要在包含在页面中之前未经充分净化。

使用 Django 模板可以保护您免受大多数 XSS 攻击。但是，重要的是要了解它提供的保护措施及其局限性。

Django 模板会转义对 HTML 特别危险的特定字符。虽然这可以保护用户免受大多数恶意输入，但并非绝对安全。例如，它无法保护以下内容：

```py
<style class={{ var }}>...</style> 

```

如果`var`设置为`'class1 onmouseover=javascript:func()'`，这可能导致未经授权的 JavaScript 执行，具体取决于浏览器如何呈现不完美的 HTML。（引用属性值将修复此情况）。

在使用自定义模板标记时，使用`is_safe`、`safe`模板标记、`mark_safe`以及关闭`autoescape`时要特别小心。

此外，如果您使用模板系统输出除 HTML 之外的内容，可能需要转义完全不同的字符和单词。

在存储 HTML 在数据库时，特别需要非常小心，特别是当检索和显示该 HTML 时。

## 跨站点请求伪造（CSRF）保护

**跨站点请求伪造**（**CSRF**）攻击允许恶意用户在不知情或未经同意的情况下使用另一个用户的凭据执行操作。

Django 内置了对大多数 CSRF 攻击的保护，只要您已启用并在适当的地方使用它。但是，与任何缓解技术一样，存在局限性。

例如，可以全局禁用 CSRF 模块或特定视图。只有在知道自己在做什么时才应该这样做。如果您的网站具有超出您控制范围的子域，还存在其他限制。

CSRF 保护通过检查每个`POST`请求中的一次性令牌来实现。这确保了恶意用户无法简单地重放表单`POST`到您的网站，并使另一个已登录的用户无意中提交该表单。恶意用户必须知道一次性令牌，这是用户特定的（使用 cookie）。

在使用 HTTPS 部署时，`CsrfViewMiddleware`将检查 HTTP 引用头是否设置为同一来源的 URL（包括子域和端口）。因为 HTTPS 提供了额外的安全性，所以必须确保连接在可用时使用 HTTPS，通过转发不安全的连接请求并为受支持的浏览器使用 HSTS。

非常小心地标记视图为`csrf_exempt`装饰器，除非绝对必要。

Django 的 CSRF 中间件和模板标签提供了易于使用的跨站请求伪造保护。

对抗 CSRF 攻击的第一道防线是确保`GET`请求（以及其他“安全”方法，如 9.1.1 安全方法，HTTP 1.1，RFC 2616 中定义的方法（有关更多信息，请访问[`tools.ietf.org/html/rfc2616.html#section-9.1.1`](https://tools.ietf.org/html/rfc2616.html#section-9.1.1)）是无副作用的。然后，通过以下步骤保护通过“不安全”方法（如`POST`，`PUT`和`DELETE`）的请求。

### 如何使用它

要在视图中利用 CSRF 保护，请按照以下步骤进行操作：

1.  CSRF 中间件在`MIDDLEWARE_CLASSES`设置中默认激活。如果您覆盖该设置，请记住`'django.middleware.csrf.CsrfViewMiddleware'`应该在任何假设已处理 CSRF 攻击的视图中间件之前。

1.  如果您禁用了它，这是不推荐的，您可以在要保护的特定视图上使用`csrf_protect()`（见下文）。

1.  在任何使用`POST`表单的模板中，如果表单用于内部 URL，请在`<form>`元素内使用`csrf_token`标签，例如：

```py
        <form action="." method="post">{% csrf_token %} 

```

1.  不应该对目标外部 URL 的`POST`表单执行此操作，因为这会导致 CSRF 令牌泄漏，从而导致漏洞。

1.  在相应的视图函数中，确保使用了`'django.template.context_processors.csrf'`上下文处理器。通常，可以通过以下两种方式之一完成：

1.  使用`RequestContext`，它始终使用`'django.template.context_processors.csrf'`（无论在`TEMPLATES`设置中配置了哪些模板上下文处理器）。如果您使用通用视图或贡献应用程序，则已经涵盖了，因为这些应用程序始终在整个`RequestContext`中使用。

1.  手动导入并使用处理器生成 CSRF 令牌，并将其添加到模板上下文中。例如：

```py
        from django.shortcuts import render_to_response 
        from django.template.context_processors import csrf 

        def my_view(request): 
            c = {} 
            c.update(csrf(request)) 
            # ... view code here 
            return render_to_response("a_template.html", c) 

```

1.  您可能希望编写自己的`render_to_response()`包装器，以便为您处理此步骤。

### AJAX

虽然上述方法可以用于 AJAX POST 请求，但它有一些不便之处：您必须记住在每个 POST 请求中将 CSRF 令牌作为 POST 数据传递。因此，有一种替代方法：在每个`XMLHttpRequest`上，将自定义的`X-CSRFToken`标头设置为 CSRF 令牌的值。这通常更容易，因为许多 JavaScript 框架提供了允许在每个请求上设置标头的钩子。

首先，您必须获取 CSRF 令牌本身。令牌的推荐来源是`csrftoken` cookie，如果您已经按上述方式为视图启用了 CSRF 保护，它将被设置。

CSRF 令牌 cookie 默认名为`csrftoken`，但您可以通过`CSRF_COOKIE_NAME`设置控制 cookie 名称。

获取令牌很简单：

```py
// using jQuery 
function getCookie(name) { 
    var cookieValue = null; 
    if (document.cookie && document.cookie != '') { 
        var cookies = document.cookie.split(';'); 
        for (var i = 0; i < cookies.length; i++) { 
            var cookie = jQuery.trim(cookies[i]); 
            // Does this cookie string begin with the name we want? 
            if (cookie.substring(0, name.length + 1) == (name + '=')) { 
                cookieValue =  decodeURIComponent(cookie.substring(name.length + 1)); 
                break; 
            } 
        } 
    } 
    return cookieValue; 
} 
var csrftoken = getCookie('csrftoken'); 

```

通过使用 jQuery cookie 插件（[`plugins.jquery.com/cookie/`](http://plugins.jquery.com/cookie/)）来替换`getCookie`，可以简化上述代码：

```py
var csrftoken = $.cookie('csrftoken'); 

```

### 注意

CSRF 令牌也存在于 DOM 中，但仅当在模板中明确包含`csrf_token`时才会存在。cookie 包含规范令牌；`CsrfViewMiddleware`将优先使用 cookie 而不是 DOM 中的令牌。无论如何，如果 DOM 中存在令牌，则保证会有 cookie，因此应该使用 cookie！

### 注意

如果您的视图没有呈现包含`csrf_token`模板标签的模板，则 Django 可能不会设置 CSRF 令牌 cookie。这在动态添加表单到页面的情况下很常见。为了解决这种情况，Django 提供了一个视图装饰器，强制设置 cookie：`ensure_csrf_cookie()`。

最后，您将需要在 AJAX 请求中实际设置标头，同时使用 jQuery 1.5.1 及更高版本中的`settings.crossDomain`保护 CSRF 令牌，以防止发送到其他域：

```py
function csrfSafeMethod(method) { 
    // these HTTP methods do not require CSRF protection 
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method)); 
} 
$.ajaxSetup({ 
    beforeSend: function(xhr, settings) { 
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) { 
            xhr.setRequestHeader("X-CSRFToken", csrftoken); 
        } 
    } 
}); 

```

### 其他模板引擎

当使用与 Django 内置引擎不同的模板引擎时，您可以在确保它在模板上下文中可用后，在表单中手动设置令牌。

例如，在 Jinja2 模板语言中，您的表单可以包含以下内容：

```py
<div style="display:none"> 
    <input type="hidden" name="csrfmiddlewaretoken" value="{{ csrf_token }}"> 
</div> 

```

您可以使用类似于上面的 AJAX 代码的 JavaScript 来获取 CSRF 令牌的值。

### 装饰器方法

您可以使用`csrf_protect`装饰器，而不是将`CsrfViewMiddleware`作为一种全面的保护措施，该装饰器具有完全相同的功能，用于需要保护的特定视图。它必须同时用于在输出中插入 CSRF 令牌的视图和接受`POST`表单数据的视图。（这些通常是相同的视图函数，但并非总是如此）。

不建议单独使用装饰器，因为如果您忘记使用它，将会有安全漏洞。同时使用两者的“双重保险”策略是可以的，并且会产生最小的开销。

`django.views.decorators.csrf.csrf_protect(view)`

提供对视图的`CsrfViewMiddleware`保护的装饰器。

用法：

```py
from django.views.decorators.csrf import csrf_protect 
from django.shortcuts import render 

@csrf_protect 
def my_view(request): 
    c = {} 
    # ... 
    return render(request, "a_template.html", c) 

```

如果您正在使用基于类的视图，可以参考装饰基于类的视图。

### 被拒绝的请求

默认情况下，如果传入请求未通过`CsrfViewMiddleware`执行的检查，则向用户发送*403 Forbidden*响应。通常只有在存在真正的跨站请求伪造或由于编程错误，CSRF 令牌未包含在`POST`表单中时才会看到这种情况。

然而，错误页面并不是很友好，因此您可能希望为处理此条件提供自己的视图。要做到这一点，只需设置`CSRF_FAILURE_VIEW`设置。

#### 工作原理

CSRF 保护基于以下几点：

+   设置为随机值的 CSRF cookie（称为会话独立 nonce），其他站点将无法访问。

+   这个 cookie 是由`CsrfViewMiddleware`设置的。它是永久性的，但由于没有办法设置永不过期的 cookie，因此它会随着每次调用`django.middleware.csrf.get_token()`（内部用于检索 CSRF 令牌的函数）的响应一起发送。

+   所有传出的 POST 表单中都有一个名为*csrfmiddlewaretoken*的隐藏表单字段。该字段的值是 CSRF cookie 的值。

+   这部分是由模板标签完成的。

+   对于所有不使用 HTTP `GET`，`HEAD`，`OPTIONS`或`TRACE`的传入请求，必须存在 CSRF cookie，并且必须存在并正确的*csrfmiddlewaretoken*字段。如果没有，用户将收到 403 错误。

+   这个检查是由`CsrfViewMiddleware`完成的。

+   此外，对于 HTTPS 请求，`CsrfViewMiddleware`会进行严格的引用检查。这是必要的，以解决在 HTTPS 下使用会话独立 nonce 时可能发生的中间人攻击，因为（不幸的是）客户端接受了对 HTTPS 站点进行通信的“Set-Cookie”标头。 （在 HTTP 请求下不进行引用检查，因为在 HTTP 下，引用标头的存在不够可靠。）

这确保只有来自您网站的表单才能用于将数据`POST`回来。

它故意忽略`GET`请求（以及 RFC 2616 定义为“安全”的其他请求）。这些请求不应该具有任何潜在的危险副作用，因此使用`GET`请求的 CSRF 攻击应该是无害的。RFC 2616 将`POST`、`PUT`和`DELETE`定义为“不安全”，并假定所有其他方法都是不安全的，以获得最大的保护。

### 缓存

如果模板使用`csrf_token`模板标签（或以其他方式调用`get_token`函数），`CsrfViewMiddleware`将向响应添加一个 cookie 和一个`Vary: Cookie`标头。这意味着如果按照指示使用缓存中间件（`UpdateCacheMiddleware`在所有其他中间件之前），中间件将与缓存中间件协同工作。

然而，如果您在单个视图上使用缓存装饰器，CSRF 中间件还没有能够设置`Vary`标头或 CSRF cookie，响应将被缓存而没有任何一个。

在这种情况下，对于任何需要插入 CSRF 令牌的视图，您应该首先使用`django.views.decorators.csrf.csrf_protect()`装饰器：

```py
from django.views.decorators.cache import cache_page 
from django.views.decorators.csrf import csrf_protect 

@cache_page(60 * 15) 
@csrf_protect 
def my_view(request): 
    ... 

```

如果您正在使用基于类的视图，可以参考 Django 文档中的装饰基于类的视图（[`docs.djangoproject.com/en/1.8/topics/class-based-views/intro/#decorating-class-based-views`](https://docs.djangoproject.com/en/1.8/topics/class-based-views/intro/#decorating-class-based-views)）。

### 测试

由于需要在每个`POST`请求中发送 CSRF 令牌，`CsrfViewMiddleware`通常会对测试视图函数造成很大的阻碍。因此，Django 的测试 HTTP 客户端已经修改，以在请求上设置一个标志，从而放宽中间件和`csrf_protect`装饰器，使其不再拒绝请求。在其他方面（例如发送 cookie 等），它们的行为是相同的。

如果出于某种原因，您希望测试客户端执行 CSRF 检查，您可以创建一个强制执行 CSRF 检查的测试客户端实例：

```py
>>> from django.test import Client 
>>> csrf_client = Client(enforce_csrf_checks=True) 

```

### 限制

站点内的子域将能够在整个域上为客户端设置 cookie。通过设置 cookie 并使用相应的令牌，子域将能够规避 CSRF 保护。避免这种情况的唯一方法是确保子域由受信任的用户控制（或者至少无法设置 cookie）。

请注意，即使没有 CSRF，也存在其他漏洞，例如会话固定，这使得将子域分配给不受信任的方可能不是一个好主意，而且这些漏洞在当前浏览器中不能轻易修复。

### 边缘情况

某些视图可能具有不符合此处正常模式的特殊要求。在这些情况下，一些实用程序可能会有用。它们可能需要的场景在下一节中描述。

### 实用程序

下面的示例假定您正在使用基于函数的视图。如果您正在使用基于类的视图，可以参考 Django 文档中的装饰基于类的视图。

#### django.views.decorators.csrf.csrf_exempt(view)

大多数视图需要 CSRF 保护，但有一些不需要。与其禁用中间件并将`csrf_protect`应用于所有需要它的视图，不如启用中间件并使用`csrf_exempt()`。

这个装饰器标记一个视图被中间件保护豁免。示例：

```py
from django.views.decorators.csrf import csrf_exempt 
from django.http import HttpResponse 

@csrf_exempt 
def my_view(request): 
    return HttpResponse('Hello world') 

```

#### django.views.decorators.csrf.requires_csrf_token(view)

有些情况下，`CsrfViewMiddleware.process_view`可能在您的视图运行之前没有运行-例如 404 和 500 处理程序-但您仍然需要表单中的 CSRF 令牌。

通常，如果`CsrfViewMiddleware.process_view`或类似`csrf_protect`没有运行，`csrf_token`模板标签将无法工作。视图装饰器`requires_csrf_token`可用于确保模板标签正常工作。这个装饰器的工作方式类似于`csrf_protect`，但从不拒绝传入的请求。

示例：

```py
from django.views.decorators.csrf import requires_csrf_token 
from django.shortcuts import render 

@requires_csrf_token 
def my_view(request): 
    c = {} 
    # ... 
    return render(request, "a_template.html", c) 

```

还可能有一些未受保护的视图已经被`csrf_exempt`豁免，但仍需要包含 CSRF 令牌。在这些情况下，使用`csrf_exempt()`后跟`requires_csrf_token()`。（即`requires_csrf_token`应该是最内层的装饰器）。

最后一个例子是，当视图仅在一组条件下需要 CSRF 保护，并且在其余时间不得具有保护时。解决方案是对整个视图函数使用`csrf_exempt()`，并对其中需要保护的路径使用`csrf_protect()`。

例如：

```py
from django.views.decorators.csrf import csrf_exempt, csrf_protect 

@csrf_exempt 
def my_view(request): 

    @csrf_protect 
    def protected_path(request): 
        do_something() 

    if some_condition(): 
       return protected_path(request) 
    else: 
       do_something_else() 

```

#### django.views.decorators.csrf.ensure_csrf_cookie(view)

这个装饰器强制视图发送 CSRF cookie。如果页面通过 AJAX 进行 POST 请求，并且页面没有带有`csrf_token`的 HTML 表单，这将导致所需的 CSRF cookie 被发送。解决方案是在发送页面的视图上使用`ensure_csrf_cookie()`。

### 贡献和可重用应用程序

由于开发人员可以关闭`CsrfViewMiddleware`，因此贡献应用程序中的所有相关视图都使用`csrf_protect`装饰器来确保这些应用程序对 CSRF 的安全性。建议其他希望获得相同保障的可重用应用程序的开发人员也在其视图上使用`csrf_protect`装饰器。

### CSRF 设置

可以用一些设置来控制 Django 的 CSRF 行为：

+   `CSRF_COOKIE_AGE`

+   `CSRF_COOKIE_DOMAIN`

+   `CSRF_COOKIE_HTTPONLY`

+   `CSRF_COOKIE_NAME`

+   `CSRF_COOKIE_PATH`

+   `CSRF_COOKIE_SECURE`

+   `CSRF_FAILURE_VIEW`

有关这些设置的更多信息，请参见附录 D，*设置*。

## SOL 注入保护

SQL 注入是一种攻击类型，恶意用户能够在数据库上执行任意的 SQL 代码。这可能导致记录被删除或数据泄露。

通过使用 Django 的查询集，生成的 SQL 将由底层数据库驱动程序正确转义。但是，Django 还赋予开发人员编写原始查询或执行自定义 SQL 的权力。这些功能应该谨慎使用，并且您应该始终小心地正确转义用户可以控制的任何参数。此外，在使用`extra()`时应谨慎。

## 点击劫持保护

点击劫持是一种攻击类型，恶意站点在框架中包裹另一个站点。当恶意站点欺骗用户点击他们在隐藏框架或 iframe 中加载的另一个站点的隐藏元素时，就会发生这种类型的攻击。

Django 包含防止点击劫持的保护，即`X-Frame-Options 中间件`，在支持的浏览器中可以防止网站在框架内呈现。可以在每个视图的基础上禁用保护，或配置发送的确切标头值。

强烈建议对于任何不需要其页面被第三方站点包裹在框架中的站点，或者只需要允许站点的一小部分进行包裹的站点使用中间件。

### 点击劫持的一个例子

假设一个在线商店有一个页面，用户可以在其中点击“立即购买”来购买商品。用户选择一直保持登录以方便使用。攻击者站点可能在其自己的页面上创建一个“我喜欢小马”按钮，并以透明的`iframe`加载商店的页面，使得“立即购买”按钮被隐形地覆盖在“我喜欢小马”按钮上。如果用户访问攻击者的站点，点击“我喜欢小马”将导致无意中点击“立即购买”按钮，并无意中购买商品。

### 防止点击劫持

现代浏览器遵守 X-Frame-Options（有关更多信息，请访问 [`developer.mozilla.org/en/The_X-FRAME-OPTIONS_response_header`](https://developer.mozilla.org/en/The_X-FRAME-OPTIONS_response_header)）HTTP 头部，该头部指示资源是否允许在框架或 iframe 中加载。如果响应包含带有 `SAMEORIGIN` 值的头部，则浏览器只会在请求源自同一站点时才在框架中加载资源。如果头部设置为 `DENY`，则浏览器将阻止资源在框架中加载，无论哪个站点发出了请求。

Django 提供了一些简单的方法来在您的站点的响应中包含这个头部：

+   一个简单的中间件，可以在所有响应中设置头部。

+   一组视图装饰器，可用于覆盖中间件或仅为特定视图设置头部。

### 如何使用它

#### 为所有响应设置 X-Frame-Options

要为站点中的所有响应设置相同的 `X-Frame-Options` 值，请将 `'django.middleware.clickjacking.XFrameOptionsMiddleware'` 放到 `MIDDLEWARE_CLASSES` 中：

```py
MIDDLEWARE_CLASSES = [ 
    # ... 
    'django.middleware.clickjacking.XFrameOptionsMiddleware', 
    # ... 
] 

```

此中间件在由 `startproject` 生成的设置文件中启用。

默认情况下，中间件将为每个传出的 `HttpResponse` 设置 `X-Frame-Options` 头部为 `SAMEORIGIN`。如果要改为 `DENY`，请设置 `X_FRAME_OPTIONS` 设置：

```py
X_FRAME_OPTIONS = 'DENY' 

```

在使用中间件时，可能存在一些视图，您不希望设置 `X-Frame-Options` 头部。对于这些情况，您可以使用视图装饰器告诉中间件不要设置头部：

```py
from django.http import HttpResponse 
from django.views.decorators.clickjacking import xframe_options_exempt 

@xframe_options_exempt 
def ok_to_load_in_a_frame(request): 
    return HttpResponse("This page is safe to load in a frame on any site.") 

```

#### 为每个视图设置 X-Frame-Options

要在每个视图基础上设置 `X-Frame-Options` 头部，Django 提供了这些装饰器：

```py
from django.http import HttpResponse 
from django.views.decorators.clickjacking import xframe_options_deny 
from django.views.decorators.clickjacking import  xframe_options_sameorigin 

@xframe_options_deny 
def view_one(request): 
    return HttpResponse("I won't display in any frame!") 

@xframe_options_sameorigin 
def view_two(request): 
    return HttpResponse("Display in a frame if it's from the same    
      origin as me.") 

```

请注意，您可以将装饰器与中间件一起使用。使用装饰器会覆盖中间件。

### 限制

`X-Frame-Options` 头部只会在现代浏览器中保护免受点击劫持攻击。旧版浏览器会悄悄地忽略这个头部，并需要其他点击劫持防护技术。

### 支持 X-Frame-Options 的浏览器

+   Internet Explorer 8+

+   Firefox 3.6.9+

+   Opera 10.5+

+   Safari 4+

+   Chrome 4.1+

## SSL/HTTPS

尽管在所有情况下部署站点在 HTTPS 后面对于安全性来说总是更好的，但并非在所有情况下都是实际可行的。如果没有这样做，恶意网络用户可能会窃取身份验证凭据或客户端和服务器之间传输的任何其他信息，并且在某些情况下，主动的网络攻击者可能会更改在任一方向上发送的数据。

如果您希望获得 HTTPS 提供的保护，并已在服务器上启用了它，则可能需要一些额外的步骤：

+   如有必要，请设置 `SECURE_PROXY_SSL_HEADER`，确保您已充分理解其中的警告。不这样做可能会导致 CSRF 漏洞，并且不正确地执行也可能很危险！

+   设置重定向，以便通过 HTTP 的请求被重定向到 HTTPS。

+   这可以通过使用自定义中间件来实现。请注意 `SECURE_PROXY_SSL_HEADER` 下的注意事项。对于反向代理的情况，配置主要的 Web 服务器来执行重定向到 HTTPS 可能更容易或更安全。

+   使用 *secure* cookies。如果浏览器最初通过 HTTP 连接，这是大多数浏览器的默认设置，现有的 cookies 可能会泄漏。因此，您应该将 `SESSION_COOKIE_SECURE` 和 `CSRF_COOKIE_SECURE` 设置为 `True`。这指示浏览器仅在 HTTPS 连接上发送这些 cookies。请注意，这意味着会话将无法在 HTTP 上工作，并且 CSRF 保护将阻止任何通过 HTTP 接受的 `POST` 数据（如果您将所有 HTTP 流量重定向到 HTTPS，则这将是可以接受的）。

+   使用 HTTP 严格传输安全（HSTS）。HSTS 是一个 HTTP 标头，通知浏览器所有未来连接到特定站点应始终使用 HTTPS（见下文）。结合将请求重定向到 HTTPS，这将确保连接始终享有 SSL 提供的额外安全性，只要成功连接一次。HSTS 通常在 Web 服务器上配置。

### HTTP 严格传输安全

对于应仅通过 HTTPS 访问的站点，您可以指示现代浏览器拒绝通过不安全连接（在一定时间内）连接到您的域名，方法是设置 Strict-Transport-Security 标头。这将减少您对某些 SSL 剥离中间人（MITM）攻击的风险。

如果将`SECURE_HSTS_SECONDS`设置为非零整数值，`SecurityMiddleware`将在所有 HTTPS 响应上为您设置此标头。

在启用 HSTS 时，最好首先使用一个小值进行测试，例如`SECURE_HSTS_SECONDS = 3600`表示一小时。每次 Web 浏览器从您的站点看到 HSTS 标头时，它将拒绝在给定时间内与您的域进行非安全通信（使用 HTTP）。

一旦确认您的站点上的所有资产都安全提供（即 HSTS 没有破坏任何内容），最好增加此值，以便偶尔访问者受到保护（31536000 秒，即 1 年，是常见的）。

此外，如果将`SECURE_HSTS_INCLUDE_SUBDOMAINS`设置为`True`，`SecurityMiddleware`将向`Strict-Transport-Security`标头添加`includeSubDomains`标记。这是推荐的（假设所有子域都仅使用 HTTPS 提供服务），否则您的站点仍可能通过不安全的连接对子域进行攻击。

### 注意

HSTS 策略适用于整个域，而不仅仅是您在响应上设置标头的 URL。因此，只有在整个域仅通过 HTTPS 提供服务时才应使用它。

浏览器正确尊重 HSTS 标头将拒绝允许用户绕过警告并连接到具有过期、自签名或其他无效 SSL 证书的站点。如果您使用 HSTS，请确保您的证书状况良好并保持良好！

如果您部署在负载均衡器或反向代理服务器后，并且未将`Strict-Transport-Security`标头添加到您的响应中，可能是因为 Django 没有意识到它处于安全连接中；您可能需要设置`SECURE_PROXY_SSL_HEADER`设置。

## 主机标头验证

Django 使用客户端提供的`Host`标头在某些情况下构建 URL。虽然这些值经过清理以防止跨站点脚本攻击，但可以使用虚假的`Host`值进行跨站点请求伪造、缓存污染攻击和电子邮件中的链接污染。因为即使看似安全的 Web 服务器配置也容易受到虚假的`Host`标头的影响，Django 会在`django.http.HttpRequest.get_host()`方法中针对`ALLOWED_HOSTS`设置验证`Host`标头。此验证仅适用于`get_host()`；如果您的代码直接从`request.META`访问`Host`标头，则会绕过此安全保护。

## 会话安全

与 CSRF 限制类似，要求站点部署在不受信任用户无法访问任何子域的情况下，`django.contrib.sessions`也有限制。有关详细信息，请参阅安全主题指南部分的会话主题。

### 用户上传的内容

### 注意

考虑从云服务或 CDN 提供静态文件以避免其中一些问题。

+   如果您的站点接受文件上传，强烈建议您在 Web 服务器配置中限制这些上传的大小，以防止拒绝服务（DOS）攻击。在 Apache 中，可以使用`LimitRequestBody`指令轻松设置这一点。

+   如果您正在提供自己的静态文件，请确保像 Apache 的`mod_php`这样的处理程序已被禁用，因为它会将静态文件作为代码执行。您不希望用户能够通过上传和请求特制文件来执行任意代码。

+   当媒体以不遵循安全最佳实践的方式提供时，Django 的媒体上传处理会存在一些漏洞。具体来说，如果 HTML 文件包含有效的 PNG 标头，后跟恶意 HTML，则可以将 HTML 文件上传为图像。这个文件将通过 Django 用于`ImageField`图像处理的库（Pillow）的验证。当此文件随后显示给用户时，根据您的 Web 服务器的类型和配置，它可能会显示为 HTML。

在框架级别没有防弹的技术解决方案可以安全地验证所有用户上传的文件内容，但是，您可以采取一些其他步骤来减轻这些攻击：

1.  一类攻击可以通过始终从不同的顶级或二级域名提供用户上传的内容来防止。这可以防止任何被同源策略（有关更多信息，请访问[`en.wikipedia.org/wiki/Same-origin_policy`](http://en.wikipedia.org/wiki/Same-origin_policy)）阻止的利用，例如跨站脚本。例如，如果您的站点运行在`example.com`上，您希望从类似`usercontent-example.com`的地方提供上传的内容（`MEDIA_URL`设置）。仅仅从子域名（如`usercontent.example.com`）提供内容是不够的。

1.  此外，应用程序可以选择为用户上传的文件定义一个允许的文件扩展名白名单，并配置 Web 服务器仅提供这些文件。

# 其他安全提示

+   尽管 Django 在开箱即用时提供了良好的安全保护，但仍然很重要正确部署应用程序并利用 Web 服务器、操作系统和其他组件的安全保护。

+   确保您的 Python 代码位于 Web 服务器的根目录之外。这将确保您的 Python 代码不会被意外地作为纯文本（或意外执行）提供。

+   小心处理任何用户上传的文件。

+   Django 不会限制对用户进行身份验证的请求。为了防止针对身份验证系统的暴力攻击，您可以考虑部署 Django 插件或 Web 服务器模块来限制这些请求。

+   保持您的`SECRET_KEY`是秘密的。

+   限制缓存系统和数据库的可访问性是一个好主意。

## 安全问题档案

Django 的开发团队坚决致力于负责任地报告和披露安全相关问题，如 Django 的安全政策所述。作为承诺的一部分，他们维护了一个已修复和披露的问题的历史列表。有关最新列表，请参阅安全问题档案（[`docs.djangoproject.com/en/1.8/releases/security/`](https://docs.djangoproject.com/en/1.8/releases/security/)）。

## 加密签名

Web 应用程序安全的黄金法则是永远不要相信来自不受信任来源的数据。有时通过不受信任的媒介传递数据可能是有用的。通过加密签名的值可以通过不受信任的渠道传递，以确保任何篡改都将被检测到。Django 提供了用于签名值的低级 API 和用于设置和读取签名 cookie 的高级 API，签名在 Web 应用程序中是最常见的用途之一。您可能还会发现签名对以下内容有用：

+   为失去密码的用户生成*找回我的账户*URL。

+   确保存储在隐藏表单字段中的数据没有被篡改。

+   为允许临时访问受保护资源（例如，用户已支付的可下载文件）生成一次性秘密 URL。

### 保护 SECRET_KEY

当您使用`startproject`创建一个新的 Django 项目时，`settings.py`文件会自动生成并获得一个随机的`SECRET_KEY`值。这个值是保护签名数据的关键-您必须保持它安全，否则攻击者可能会使用它来生成自己的签名值。

### 使用低级 API

Django 的签名方法位于`django.core.signing`模块中。要签名一个值，首先实例化一个`Signer`实例：

```py
>>> from django.core.signing import Signer
>>> signer = Signer()
>>> value = signer.sign('My string')
>>> value
'My string:GdMGD6HNQ_qdgxYP8yBZAdAIV1w'
```

签名附加到字符串的末尾，跟在冒号后面。您可以使用`unsign`方法检索原始值：

```py
>>> original = signer.unsign(value)
>>> original
'My string'
```

如果签名或值以任何方式被更改，将引发`django.core.signing.BadSignature`异常：

```py
>>> from django.core import signing
>>> value += 'm'
>>> try:
   ... original = signer.unsign(value)
   ... except signing.BadSignature:
   ... print("Tampering detected!")
```

默认情况下，`Signer`类使用`SECRET_KEY`设置生成签名。您可以通过将其传递给`Signer`构造函数来使用不同的密钥：

```py
>>> signer = Signer('my-other-secret')
>>> value = signer.sign('My string')
>>> value
'My string:EkfQJafvGyiofrdGnuthdxImIJw'
```

`django.core.signing.Signer`返回一个签名者，该签名者使用`key`生成签名，`sep`用于分隔值。`sep`不能在 URL 安全的 base64 字母表中。这个字母表包含字母数字字符、连字符和下划线。

### 使用盐参数

如果您不希望特定字符串的每次出现都具有相同的签名哈希，可以使用`Signer`类的可选`salt`参数。使用盐将使用盐和您的`SECRET_KEY`对签名哈希函数进行种子处理：

```py
>>> signer = Signer()
>>> signer.sign('My string')
'My string:GdMGD6HNQ_qdgxYP8yBZAdAIV1w'
>>> signer = Signer(salt='extra')
>>> signer.sign('My string')
'My string:Ee7vGi-ING6n02gkcJ-QLHg6vFw'
>>> signer.unsign('My string:Ee7vGi-ING6n02gkcJ-QLHg6vFw')
'My string'
```

以这种方式使用盐将不同的签名放入不同的命名空间。来自一个命名空间（特定盐值）的签名不能用于验证使用不同盐设置的不同命名空间中的相同纯文本字符串。结果是防止攻击者使用在代码中的一个地方生成的签名字符串作为输入到另一段使用不同盐生成（和验证）签名的代码。

与您的`SECRET_KEY`不同，您的盐参数不需要保密。

### 验证时间戳值

`TimestampSigner`是`Signer`的子类，它附加了一个签名的时间戳到值。这允许您确认签名值是在指定的时间段内创建的：

```py
>>> from datetime import timedelta
>>> from django.core.signing import TimestampSigner
>>> signer = TimestampSigner()
>>> value = signer.sign('hello')
>>> value 'hello:1NMg5H:oPVuCqlJWmChm1rA2lyTUtelC-c'
>>> signer.unsign(value)
'hello'
>>> signer.unsign(value, max_age=10)
...
SignatureExpired: Signature age 15.5289158821 > 10 seconds
>>> signer.unsign(value, max_age=20)
'hello'
>>> signer.unsign(value, max_age=timedelta(seconds=20))
'hello'
```

`sign(value)`签名`value`并附加当前时间戳。

`unsign(value, max_age=None)`检查`value`是否在`max_age`秒之内签名，否则会引发`SignatureExpired`。`max_age`参数可以接受整数或`datetime.timedelta`对象。

### 保护复杂的数据结构

如果您希望保护列表、元组或字典，可以使用签名模块的`dumps`和`loads`函数。这些函数模仿了 Python 的 pickle 模块，但在底层使用 JSON 序列化。JSON 确保即使您的`SECRET_KEY`被盗，攻击者也无法利用 pickle 格式执行任意命令：

```py
>>> from django.core import signing
>>> value = signing.dumps({"foo": "bar"})
>>> value 'eyJmb28iOiJiYXIifQ:1NMg1b:zGcDE4-TCkaeGzLeW9UQwZesciI'
>>> signing.loads(value) {'foo': 'bar'}
```

由于 JSON 的性质（没有本地区分列表和元组的区别），如果传入元组，您将从`signing.loads(object)`得到一个列表：

```py
>>> from django.core import signing
>>> value = signing.dumps(('a','b','c'))
>>> signing.loads(value)
['a', 'b', 'c']
```

`django.core.signing.dumps(obj, key=None, salt='django.core.signing', compress=False)`

返回 URL 安全的，经过 sha1 签名的 base64 压缩的 JSON 字符串。序列化对象使用`TimestampSigner`进行签名。

`django.core.signing.loads(string, key=None, salt='django.core.signing', max_age=None)`

`dumps()`的反向操作，如果签名失败则引发`BadSignature`。如果给定，检查`max_age`（以秒为单位）。

### 安全中间件

### 注意

如果您的部署情况允许，通常最好让前端 Web 服务器执行`SecurityMiddleware`提供的功能。这样，如果有一些请求不是由 Django 提供的（例如静态媒体或用户上传的文件），它们将具有与请求到您的 Django 应用程序相同的保护。

`django.middleware.security.SecurityMiddleware`为请求/响应周期提供了几个安全增强功能。每个功能都可以通过设置独立启用或禁用。

+   `SECURE_BROWSER_XSS_FILTER`

+   `SECURE_CONTENT_TYPE_NOSNIFF`

+   `SECURE_HSTS_INCLUDE_SUBDOMAINS`

+   `SECURE_HSTS_SECONDS`

+   `SECURE_REDIRECT_EXEMPT`

+   `SECURE_SSL_HOST`

+   `SECURE_SSL_REDIRECT`

有关安全标头和这些设置的更多信息，请参阅第十七章*Django 中间件*。

### 接下来是什么？

在下一章中，我们将扩展来自第一章的快速安装指南，*Django 简介和入门*，并查看 Django 的一些额外安装和配置选项。
