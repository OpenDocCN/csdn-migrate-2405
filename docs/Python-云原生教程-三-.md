# Python 云原生教程（三）

> 原文：[`zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D`](https://zh.annas-archive.org/md5/7CEC2A066F3DD2FF52013764748D267D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：保护网络应用程序

在本章中，我们将主要讨论如何保护您的应用程序免受可能导致数据丢失的外部威胁，从而影响整体业务。

网络应用程序安全始终是任何业务单位关注的问题。因此，我们不仅关注传统的应用程序逻辑和与数据相关的安全问题，还关注协议和平台方面的问题。开发人员变得更加负责，确保遵守有关网络应用程序安全的最佳实践。

记住这一点，本书旨在面向应用程序开发人员、系统管理员以及希望保持其应用程序安全的 DevOps 专业人员，无论是在应用程序级别还是平台上。

本章将涵盖以下主题：

+   网络安全与应用程序安全

+   使用不同方法实施应用程序授权，如 OAuth、客户端认证等

+   开发安全启用的网络应用程序的要点

# 网络安全与应用程序安全

在当今的情况下，网络应用程序安全取决于两个主要方面--网络应用程序本身和其部署的平台。您可以将这两个方面分开，因为任何网络应用程序都无法在没有平台的情况下部署。

# 网络应用程序堆栈

理解平台和应用程序之间的区别非常重要，因为它对安全性有影响。典型的网络应用程序的架构类似于以下图表所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00088.jpeg)

大多数网络应用程序依赖于诸如 Apache/HTTP 服务器、Rails、nginx 等的网络服务器，这些服务器实际上根据应用程序的类型处理传入的请求。这些网络服务器跟踪传入的流量；它们还验证请求并相应地做出响应，考虑到所有用户认证都经过验证。在我们的情况下，Flask 充当我们应用程序的网络服务器。

# 应用程序 - 平台中的安全替代方案

如前所述，每个网络应用程序在暴露给外部世界之前都需要部署在某种平台上。应用程序平台提供了应用程序所需的协议支持，用于在网络上进行通信。TCP 和在很大程度上 HTTP 都是在应用程序级别处理的。

在软件架构的网络堆栈中，有两个不同的层，包括容易受到网络应用程序攻击的协议，即应用程序平台。这些层如下：

+   传输

+   应用程序

让我们详细了解这些层。

# 传输协议

在**开放系统互连**模型（**OSI**模型）中，传输层通常被称为第 4 层。网络应用程序使用 TCP 协议作为其传输协议，因为它们具有可靠性。

在**TCP**（传输控制协议）中，每个数据包都受到严密监控，并且具有内置的错误恢复机制，这在通信失败的情况下非常有用。这些机制被利用来攻击网络应用程序。

最常见的攻击是**SYN 洪水**攻击，这是一种 TCP 请求确认攻击。SYN 洪水攻击通过使用空闲会话与应用程序服务器建立连接，并不断请求直到服务器耗尽资源，无法再处理更多请求。

为了避免此类攻击，系统管理员（开发人员在这里没有控制权）应设置与超时和空闲行为相关的配置，考虑对客户的影响。这类攻击的另一个例子是**Smurf 攻击**（请参考此链接了解更多详情：[`en.wikipedia.org/wiki/Smurf_attack`](https://en.wikipedia.org/wiki/Smurf_attack)）。

**安全传输协议**

在 OSI 网络模型中，我们还有一些第 5 层的协议，可以使您的网络更安全可靠--SSL/TLS。然而，这一层也存在一些漏洞（例如，SSL 中的 Heartbleed，2014 年，以及 TLS 中的中间人重协议攻击，2009 年）。

# 应用程序协议

在 OSI 网络模型的第 7 层（最顶层），实际的应用程序驻留并使用 HTTP 协议进行通信，这也是大多数应用程序攻击发生的地方。

**HTTP**（超文本传输协议）主要有这两个组件：

+   **元数据**：HTTP 头包含元数据，对于应用程序和平台都很重要。一些头的例子包括 cookies、content-type、status、connection 等。

+   **行为**：这定义了客户端和服务器之间的行为。有一个明确定义的消息如何在 HTTP 客户端（如浏览器）和服务器之间交换的流程。

这里的主要问题是，一个应用程序通常没有内置的能力来识别可疑行为。

例如，客户端通过网络访问 Web 应用程序，可能会受到基于消耗的拒绝服务（DoS）攻击。在这种攻击中，客户端故意以比正常速度慢的速率接收数据，以尝试保持连接时间更长。由于这个原因，Web 服务器的队列开始填充，并消耗更多资源。如果所有资源都用于足够的开放连接，服务器可能会变得无响应。

# 应用程序-应用程序逻辑中的安全威胁

在本节中，我们将研究不同的方法来验证用户，并确保我们的应用程序只能被真实实体访问。

# Web 应用程序安全替代方案

为了保护我们的应用程序免受外部威胁，这里描述了一些替代方法。通常，我们的应用程序没有任何智能来识别可疑活动。因此，以下是一些重要的安全措施描述：

+   基于 HTTP 的身份验证

+   OAuth/OpenID

+   Windows 身份验证

**基于 HTTP 的身份验证**

客户端对用户名和密码进行哈希处理，并发送到 Web 服务器，就像我们为我们的 Web 应用程序设置的那样，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00089.jpeg)

上述的屏幕截图是我们在第六章中创建的 UI，*使用 Flux 创建可扩展的 UI*。它由后端服务（微服务）和用户数据库进行身份验证，用户数据库存储在 MongoDB 数据库服务器中。此外，在验证用户登录到主页时，用户数据从 MongoDB 集合中读取，然后对用户进行身份验证以进一步进入应用程序。以下是调用的 API 的代码片段：

```py
    @app.route('/login', methods=['POST']) 
    def do_admin_login(): 
     users = mongo.db.users 
     api_list=[] 
     login_user = users.find({'username': request.form['username']}) 
     for i in login_user: 
       api_list.append(i) 
      print (api_list) 
      if api_list != []: 
        #print (api_list[0]['password'].decode('utf-8'),
         bcrypt.hashpw(request.form['password'].encode('utf-8'),
         api_list[0]['password']).decode('utf-8')) 
       if api_list[0]['password'].decode('utf-8') == 
         bcrypt.hashpw(request.form['password'].encode('utf-8'),
         api_list[0]['password']).decode('utf-8'): 
           session['logged_in'] = api_list[0]['username'] 
           return redirect(url_for('index')) 
           return 'Invalide username/password!' 
       else: 
         flash("Invalid Authentication") 

      return 'Invalid User!' 

```

这是在应用程序级别设置安全性的一种方式，以便应用程序数据可以得到保护。

**OAuth/OpenID**

OAuth 是授权的开放标准，在允许用户使用第三方凭据进行身份验证的网站中非常常见，通常是电子邮件 ID。

以下是使 OAuth 比其他安全措施更好的一些关键特性：

+   它与任何操作系统或安装无关

+   它简单易用

+   它更可靠并提供高性能

+   它专门为需要集中身份验证方法的分布式系统设计

+   这是一个免费使用的基于开源的身份提供者服务器软件

+   它支持基于云的身份提供者，如 Google、Auth0、LinkedIn 等

+   它也被称为 SSO（单一登录或基于令牌的身份验证）

**设置管理员帐户**

OAuth 没有服务来授予**JWT**（**JSON Web Token**，一种用于在各方之间传输声明的 URL 安全 JSON 格式）。您可以在[`jwt.io/introduction/`](https://jwt.io/introduction/)了解更多关于 JWT 的信息。

身份提供者负责为依赖第三方授权的 Web 应用程序对用户进行身份验证。

您可以根据自己的喜好选择任何身份提供者，因为它们之间的功能是相似的，但在功能方面会有所不同。在本章中，我将向您展示如何使用 Google Web 应用程序（这是来自 Google 的开发者 API）和 Auth0 第三方应用程序进行身份验证。

**使用 Auth0 帐户设置**

在这个部分，我们将在 Google 开发者工具中设置一个用于身份验证的帐户，并在一个名为**Auth0**（[auth0.com](http://auth0.com)）的第三方免费应用程序中设置。

让我们在 Auth0（[auth0.com](http://auth0.com)）中启动帐户设置，唯一的要求是需要一个电子邮件 ID 进行注册或注册。请参考以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00090.jpeg)

一旦您注册/注册了 Auth0 帐户，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00091.jpeg)

前面的屏幕是仪表板，我们可以在其中看到用户登录到应用程序的登录活动。它还展示了用户的登录尝试，并记录了用户的活动。简而言之，仪表板可以让您了解应用程序的用户活动。

现在我们需要为我们的应用程序添加一个新的客户端，所以点击“+NEW CLIENT”按钮进行创建。一旦您点击“+NEW CLIENT”按钮，将会出现以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00092.jpeg)

前面的截图是自解释的--您需要为客户端提供一个用户定义的名称（通常名称应与应用程序相关）。此外，您需要选择应用程序的类别。回到我们的案例，我已经给出了名称`My App`，并选择了第二个选项，即单页 Web 应用程序，因为我们正在使用其中提到的技术。或者，您也可以选择常规 Web 应用程序--它也可以正常工作。这些类别用于区分我们正在编写的应用程序的种类，因为很可能我们可能在一个帐户下开发数百个应用程序。

单击“CREATE”按钮以继续创建客户端。创建完成后，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00093.jpeg)

在前面截图中看到的部分中，有许多自动生成的设置，我们需要将它们与我们的 Web 应用程序集成。以下是其中一些部分的定义：

+   **客户端 ID**：这是分配给特定应用程序的唯一 ID

+   **域**：这类似于身份验证服务器，在应用程序登录时将被调用

+   **客户端密钥**：这是一个秘密密钥，应该保密，不要与任何人分享，因为这可能会导致安全漏洞

+   **客户端类型**：这定义了应用程序的类型

+   **允许的回调 URL**：这指定了用户身份验证后允许的回调 URL，例如`http://localhost:5000/callback`

+   **允许的注销 URL**：这定义了在用户注销时允许访问的 URL，例如`http://localhost:5000/logout`

+   **令牌端点身份验证方法**：这定义了身份验证的方法，可以是无、或者 post、或者基本

Auth0 帐户的其他功能可能对管理您的应用程序有用，如下所示：

+   **SSO 集成**：在这个部分，你可以设置与 Slack、Salesforce、Zoom 等其他第三方应用程序的 SSO 登录！[](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00094.jpeg)

+   **连接**：这定义了你想为你的应用定义的认证类型，比如数据库（用户名-密码数据库）、社交（与社交媒体网站如谷歌、LinkedIn 等现有账户集成）、企业（用于企业应用如 AD、谷歌应用等）、或者无密码（通过短信、电子邮件等）。默认情况下，用户名-密码认证是启用的。

+   **APIs**：在这个部分，你可以管理你的应用的**Auth0 管理 API**，并进行测试，如下截图所示：![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00095.jpeg)

+   **日志**：这个部分跟踪你在 Auth0 账户上的活动，对于调试和在威胁时识别可疑活动非常有用。参考以下截图以了解更多关于日志的信息：![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00096.jpeg)

这些是 Auth0 账户的最重要功能，可以帮助你以高效的方式管理你的 Web 应用程序安全。

现在，我们的 Auth0 管理员账户已经设置好，准备与我们的 Web 应用集成。

**设置谷歌 API 账户**

谷歌 API 使用 OAuth 2.0 协议进行认证和授权。谷歌支持常见的 OAuth 2.0 场景，比如用于 Web 服务器、安装和客户端应用程序的场景。

首先，使用你的谷歌账户登录到谷歌 API 控制台（[`console.developers.google.com`](https://console.developers.google.com)）以获取 OAuth 客户端凭据，比如客户端 ID、客户端密钥等。你将需要这些凭据来与你的应用集成。一旦你登录，你将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00097.jpeg)

前面的屏幕展示了谷歌库 API 为其不同的谷歌产品提供的服务。现在，点击左侧面板中的凭据，导航到下一个屏幕，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00098.jpeg)

现在，点击创建凭据，然后点击 OAuth 客户端 ID 选项，以启动从 API 管理器生成客户端凭据。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00099.jpeg)

现在我们需要提供一些关于我们应用的信息；你必须记住这些细节，这些是我们在 OAuth 账户创建时提供的。一旦准备好，并填写了必填字段，点击创建以生成凭据。

一旦客户端 ID 创建完成，你将看到以下屏幕，其中包含与客户端 ID 相关的信息（凭据）：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00100.jpeg)

记住，绝对不要与任何人分享客户端 ID 的详细信息。如果你这样做了，立即重置。现在我们的谷歌 API 账户已经准备好与我们的 Web 应用集成了。

**将 Web 应用与 Auth0 账户集成**

为了将 Auth0 账户与我们的应用集成，我们需要为我们的回调创建一个新的路由。这个路由将在用户从 Auth0 账户进行认证后设置会话。因此，让我们将以下代码添加到`app.py`文件中：

```py
    @app.route('/callback') 
    def callback_handling(): 
      code = request.args.get('code') 
      get_token = GetToken('manishsethis.auth0.com') 
      auth0_users = Users('manishsethis.auth0.com') 
      token = get_token.authorization_code(os.environ['CLIENT_ID'], 
                                        os.environ['CLIENT_SECRET'],
      code, 'http://localhost:5000/callback') 
      user_info = auth0_users.userinfo(token['access_token']) 
      session['profile'] = json.loads(user_info) 
    return redirect('/dashboard') 

```

正如你在前面的代码中看到的，我使用了我们从 Auth0 账户控制台获取的客户端凭据。这些是我们在客户端创建时生成的凭据。

现在让我们添加路由/仪表板，用户在认证后被重定向到该路由：

```py
    @app.route("/dashboard") 
    def dashboard(): 
      return render_template('index.html', user=session['profile']) 

```

前面的路由简单地调用`index.html`，并将会话详细信息作为参数传递给`index.html`。

现在我们需要修改我们的`index.html`来通过 Auth0 触发身份验证。有两种触发方式。第一种是将 Auth0 域作为登陆页面，这意味着一旦他们访问 URL（[`http://localhost:5000`](http://localhost:5000)），用户将被重定向到 Auth0 账户的登陆页面。另一种方式是通过提供一个按钮来手动触发。

在本章的范围内，我们将使用手动触发，其中 Auth0 账户可以作为登录应用程序的替代方式。

让我们在`login.html`中添加以下代码。此代码将在登录页面上显示一个按钮，如果您点击该按钮，它将触发 Auth0 用户注册页面：

```py
   <center><button onclick="lock.show();">Login using Auth0</button>
     </center> 
   <script src="img/lock.min.js"> 
     </script> 
   <script> 
    var lock = new Auth0Lock(os.environ['CLIENT_ID'],
     'manishsethis.auth0.com', { 
      auth: { 
       redirectUrl: 'http://localhost:5000/callback', 
       responseType: 'code', 
       params: { 
         scope: 'openid email' // Learn about scopes:
         https://auth0.com/docs/scopes 
        } 
       } 
     }); 
   </script> 

```

在我们测试应用程序之前，我们还需要处理一件事情--如何使我们的应用程序了解会话详细信息。

由于我们的`index.html`获取会话值并在我们的主页上展示它们，因此它用于管理用户的推文。

因此，请按照以下方式更新`index.html`的 body 标签：

```py
     <h1></h1> 
     <div align="right"> Welcome {{ user['given_name'] }}</div> 
     <br> 
     <div id="react"></div> 

```

之前的代码需要在用户界面上显示用户的全名。接下来，您需要按照以下方式更新`localStorage`会话详细信息：

```py
    <script> 
      // Check browser support 
      if (typeof(Storage) !== "undefined") { 
     // Store 
      localStorage.setItem("sessionid","{{ user['emailid'] }}" ); 
     // Retrieve 
      document.getElementById("react").innerHTML =  
      localStorage.getItem("sessionid"); 
      } else { 
        document.getElementById("react").innerHTML = "Sorry, your 
        browser does not support Web Storage..."; 
      } 
    </script> 

```

我们现在几乎完成了。我希望您记得，当您在我们的微服务 API 中为特定用户发布推文时，我们已经设置了身份验证检查。我们需要删除这些检查，因为在这种情况下，我们使用 Auth0 进行身份验证。

太棒了！运行您的应用程序，并查看是否可以在[`http://localhost:5000/`](http://localhost:5000/)看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00101.jpeg)

接下来，点击“使用 Auth0 登录”按钮，以获取 Auth0 登录/注册面板，如下图所示。

提供所需的详细信息，然后点击立即注册，它将在 Auth0 帐户中注册。请记住，在这种情况下，您不会看到任何通过电子邮件直接登录的方式，因为我们使用用户名密码进行身份验证。如果您想直接通过电子邮件注册，那么您需要在社交连接部分启用 google-OAuth2 方式扩展。一旦您启用它，您将能够看到您的注册页面如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00102.jpeg)

一旦您成功注册，您将被重定向到主页，在那里您可以发布推文。如果您看到以下屏幕，那就意味着它起作用了：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00103.jpeg)

在这里需要注意的一件重要的事情是，对于每个注册，都会在您的 Auth0 帐户中创建一个用户详细信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00104.jpeg)

太棒了！现在您的应用程序已与 Auth0 帐户集成，您可以跟踪使用您的应用程序的用户。

**将您的 Google API 与 Web 应用程序集成**

将您的 Google API 与您的 Web 应用程序集成与我们在 Auth0 集成中看到的非常相似。您需要按照接下来列出的步骤进行 Google API 的集成：

1.  **收集 OAuth 凭据**：如在 Google API 客户端设置中讨论的那样，我们已经生成了客户端凭据。我们需要捕获诸如客户端 ID、客户端密钥等详细信息。

1.  **从 Google 授权服务器获取访问令牌**：在您的应用程序用户可以登录并访问私人数据之前，它需要生成由 Google 提供的身份验证令牌，该令牌充当用户的验证器。单个访问令牌可以授予对多个 API 的不同程度的访问权限。范围参数包含有关用户将具有访问权限的程度的信息，即用户可以从哪些 API 中查看数据。令牌的请求取决于您的应用程序的开发方式。

1.  **将令牌保存到 API**：一旦应用程序接收到令牌，它会将该令牌发送到 Google API HTTP 授权标头。如前所述，该令牌被授权执行基于范围参数定义的一定范围 API 上的操作。

1.  **刷新令牌**：定期刷新令牌是最佳实践，以避免任何安全漏洞。

1.  **令牌过期**：定期检查令牌过期是一个好习惯，这使得应用程序更加安全；这是强烈推荐的。

由于我们正在开发基于 Python 的应用程序，您可以按照以下链接的文档 URL，了解有关在以下链接实现 Google-API 令牌身份验证的信息：

[`developers.google.com/api-client-library/python/guide/aaa_oauth`](https://developers.google.com/api-client-library/python/guide/aaa_oauth)。

一旦用户经过身份验证并开始使用应用程序，您可以在 API 管理器（[`console.developers.google.com/apis/`](https://console.developers.google.com/apis/)）上监视用户登录活动，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00105.jpeg)

使用谷歌进行身份验证设置略微困难，并需要监督。这就是为什么开发人员选择使用像 Auth0 这样的工具，它可以直接与谷歌集成。

**Windows 身份验证**

历史上，即使应用程序部署在内部或私有云上，也更倾向于用于局域网和企业网站。然而，出于许多原因，这并不适合云原生安全选项。

有关 Windows 身份验证的更多信息，请访问链接[`en.wikipedia.org/wiki/Integrated_Windows_Authentication`](https://en.wikipedia.org/wiki/Integrated_Windows_Authentication)。我们已展示了这些安全方法供您了解，但我们的身份验证方法保持不变。

# 开发安全启用的 Web 应用程序

随着**万维网**（**WWW**）上 Web 应用程序的增加，对应用程序安全性的担忧也在增加。现在，我们心中首先出现的问题是为什么我们需要安全启用的应用程序--这个问题的答案是相当明显的。但它的基本原则是什么？以下是我们应该牢记的原则：

+   如果黑客熟悉应用程序创建时使用的语言，他可以轻易利用您的应用程序。这就是为什么我们启用诸如 CORS 之类的技术来保护我们的代码。

+   应该只授予组织中非常有限的人员对应用程序及其数据的访问权限。

+   身份验证和授权是一种保护您的应用程序免受互联网和私人网络威胁的方式。

所有这些因素，或者我应该说，原则，都驱使我们创建安全启用的应用程序。

# 摘要

在本章中，我们首先定义了不同应用程序堆栈上的安全性，以及根据您的偏好和应用程序要求如何实施或集成不同的应用程序安全措施。

到目前为止，我们已经讨论了应用程序构建。但是从现在开始，我们将完全专注于使用 DevOps 工具将我们的应用程序从开发阶段移至生产阶段的平台构建。因此，事情将变得更加有趣。敬请关注后续章节。


# 第九章：持续交付

在之前的章节中，我们努力构建我们的应用程序，并为云环境做好准备。由于我们的应用程序现在稳定了，准备好进行首次发布，我们需要开始考虑平台（即云平台）以及可以帮助我们将应用程序移至生产环境的工具。

本章讨论以下主题：

+   介绍持续集成和持续交付

+   了解 Jenkins 的持续集成

# 持续集成和持续交付的演变

现在，很多人都在谈论**CI**（持续集成）和**CD**（持续交付），经过审查不同技术人员的观点，我相信每个人对 CI 和 CD 都有不同的理解，对它们仍然存在一些困惑。让我们深入了解并理解它们。

为了理解持续集成，你需要先了解**SDLC**（系统开发生命周期）和**敏捷软件开发**过程的背景，这可以帮助你在构建和发布过程中。

# 了解 SDLC

SDLC 是规划、开发、测试和部署软件的过程。这个过程包括一系列阶段，每个阶段都需要前一个阶段的结果来继续。以下图表描述了 SDLC：

！[](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00106.jpeg)

让我们详细了解每个阶段：

+   **需求分析**：这是问题分析的初始阶段，业务分析师进行需求分析，并了解业务需求。需求可以是组织内部的，也可以是来自客户的外部的。需求包括问题的范围，可以是改进系统或构建新系统，成本分析和项目目标。

+   **设计**：在这个阶段，准备和批准软件解决方案特性的设计。这包括流程图、文档、布局等。

+   **实施**：在这个阶段，根据设计进行实际实施。通常，开发人员根据设计阶段定义的目标开发代码。

+   **测试**：在这个阶段，开发的代码由**QA**（质量保证）团队在不同的场景下进行测试。每个模块都使用单元测试和集成测试进行测试。如果测试失败，开发人员会被告知 bug，然后需要修复。

+   **部署**/**发布**：在这个阶段，经过测试的功能被移至生产环境供客户审查。

+   **演进**：这个阶段得到客户对开发、测试和发布的升级的审查。

# 敏捷软件开发过程

敏捷软件开发过程是传统软件开发的替代方案。它更像是一个帮助频繁和高效地发布生产版本的过程，而且 bug 很少。

敏捷过程基于以下原则：

+   软件升级和客户反馈的持续交付每个阶段

+   在开发周期的任何阶段都欢迎额外的改进

+   稳定版本应该频繁发布（每周）

+   业务团队和开发人员之间的持续沟通

+   持续改进朝着技术卓越和良好设计

+   工作软件是进展的主要衡量标准

+   持续适应不断变化的情况

# 敏捷软件开发过程是如何工作的？

在敏捷软件开发过程中，完整系统被划分为不同阶段，所有模块或功能都在迭代中交付，来自不同领域的跨职能团队（如规划、单元测试、设计、需求分析、编码等）同时工作。因此，每个团队成员都参与了这个过程，没有一个人闲着，而在传统的 SDLC 中，当软件处于开发阶段时，其余团队要么闲置，要么被低效利用。所有这些使得敏捷过程比传统模式更有优势。以下图表显示了敏捷开发过程的工作流程信息：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00107.jpeg)

在上图中，您不会找到需求分析或设计阶段，因为这些都在高级规划中累积。

以下是敏捷过程中的事件顺序：

1.  我们从初始规划开始，这为我们提供了关于软件功能的详细信息，然后在高级规划中定义了目标。

1.  一旦目标确定，开发人员就开始为所需功能编写代码。一旦软件升级准备就绪，测试团队（QA）就开始执行单元测试和集成测试。

1.  如果发现任何错误，立即修复，然后将代码交付给客户测试（即在阶段或预生产环境）。在这个阶段，代码尚未发布。

1.  如果代码通过了所有基于客户的测试，这可能是基于 UI 的测试，那么代码就会推送到生产环境；否则，它会再次迭代相同的周期。

现在我们已经了解了敏捷工作流程，让我们了解其优势，这些优势如下所列：

+   在敏捷开发中，每个功能都可以频繁快速地开发和演示。这里的想法是在部署之前一周左右开发没有错误的功能。这确保了客户对额外功能的满意。

+   没有专门的开发、测试或其他团队。有一个团队，由 8-10 名成员组成（根据需求），每个成员都能够做任何事情。

+   敏捷推动团队合作。

+   它需要最少的文档。

+   敏捷最适合并行功能开发。

看到了前面的优势，现在公司已经开始在他们的软件开发中采用敏捷 SDLC。

到目前为止，我们一直在研究作为软件开发一部分采用的方法。现在让我们来看看敏捷过程的一个非常关键的方面，即持续集成，这使得我们的开发工作更加轻松。

# 持续集成

持续集成是将代码合并到主干代码库的过程。简而言之，持续集成帮助开发人员在开发和生成测试结果时通过创建频繁的构建来测试他们的新代码，并且如果一切正常，然后将代码合并到主干代码。

通过以下图表可以理解这一点，它描述了 SDLC 期间出现的问题：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00108.jpeg)

基本上，持续集成期间会出现以下类型的问题：

+   集成前构建失败

+   集成失败

+   构建失败（集成后）

为了解决这些问题，开发人员需要修改代码以修复它，并且整个集成过程会重复，直到功能成功部署。

# Jenkins - 一个持续集成工具

Jenkins 是一个开源工具，用于执行持续集成和构建自动化。它与其他任何持续集成工具（如 Bamboo（CirclCI））具有相同的目的，即在开发阶段尽早测试代码。

在 Jenkins 中，您定义了一组指令，用于在不同的应用环境（开发、预生产阶段等）部署您的应用程序。

在继续设置 Jenkins 作业（基本上是项目）并了解 Jenkins 插件之前，让我们首先根据我们的要求设置 Jenkins 并进行配置。

# 安装 Jenkins

在任何环境中，无论是 Linux（Debian，Red Hat 等），Windows 还是 macOS，Jenkins 的安装都很简单。

# 先决条件

确保您的 Ubuntu 系统上已安装 Java 8。如果尚未安装，可以按照以下链接中给出的说明进行操作：

[`medium.com/appliedcode/how-to-install-java-8-jdk-8u45-on-ubuntu-linuxmint-via-ppa-1115d64ae325`](https://medium.com/appliedcode/how-to-install-java-8-jdk-8u45-on-ubuntu-linuxmint-via-ppa-1115d64ae325).

# 在基于 Debian（Ubuntu）的系统上安装

按照下面列出的步骤在基于 Debian 的系统上安装 Jenkins：

1.  我们通过执行以下命令将 Jenkins 密钥添加到 APT 软件包列表来开始 Jenkins 安装：

```py
 $ wget -q -O - https://pkg.jenkins.io/debian/jenkins-ci.org.key | sudo apt-key add -

```

1.  接下来，更新源文件，需要与之通信以验证密钥的服务器，如下所示：

```py
      $ sudo sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'

```

1.  更新源列表文件后，通过在终端执行以下命令来更新 APT 存储库：

```py
      $ sudo apt-get update -y

```

1.  现在我们准备在 Ubuntu 上安装 Jenkins；使用以下命令来执行：

```py
      $ sudo apt-get install jenkins  -y 

```

1.  现在安装完成后，请记住 Jenkins 默认运行在端口`8080`上。但是，如果您想在不同的端口上运行它，那么您需要更新 Jenkins 配置文件（`/etc/default/jenkins`）中的以下行：

```py
      HTTP_PORT=8080

```

1.  接下来，使用此 URL 检查 Jenkins GUI：

+   如果安装在本地，则转到[`http://localhost:8080/`](http://localhost:8080/)

+   如果安装在远程机器上，请转到[`http://ip-address:8080`](http://ip-address:8080)

请记住，在这种情况下，我们安装了 Jenkins 版本（2.61）；之前和即将到来的步骤对于 Jenkins 版本 2.x.x 也是有效的。

如果您看到以下屏幕，这意味着您的安装成功了：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00109.jpeg)

如前面的图像所示，在安装 Jenkins 的系统内有一个存储默认密码的路径。

这证明 Jenkins 已成功安装。

**在 Windows 上安装** Jenkins 在 Windows 上的安装非常简单。通常，在 Windows 机器上，Jenkins 不作为服务运行。但是，如果您想将其作为服务启用（这是可选的），您可以按照以下 URL 完整安装 Windows 的 Jenkins 文档：

[`wiki.Jenkins-ci.org/display/JENKINS/Installing+Jenkins+as+a+Windows+service#InstallingJenkinsasaWindowsservice-InstallJenkinsasaWindowsservice`](https://wiki.Jenkins-ci.org/display/JENKINS/Installing+Jenkins+as+a+Windows+service#InstallingJenkinsasaWindowsservice-InstallJenkinsasaWindowsservice).

# 配置 Jenkins

现在是时候配置 Jenkins 了，因此，让我们从指定路径（即`/var/lib/Jenkins/secrets/initialAdminPassword`）中获取密码，将其粘贴到安装向导中提供的空格中，然后单击“继续”。单击“继续”后，您应该看到类似以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00110.jpeg)

在下一个屏幕上，您将看到可以安装我们需要的集成插件的屏幕。现在我们将选择“安装建议的插件”选项。请注意，我们也可以在初始配置后安装其他插件。所以，不用担心！

一旦单击“安装建议的插件”，您将看到以下屏幕，显示插件安装的进度：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00111.jpeg)

插件安装可能需要一段时间。所有这些插件都是 Jenkins 建议的，因为您可能在项目相关工作中需要它们。

插件安装完成后，它会要求您创建一个管理员用户来访问 Jenkins 控制台。请注意，为了设置 Jenkins，我们使用了临时凭据。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00112.jpeg)

输入用户详细信息后，单击“保存并完成”以完成设置。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00113.jpeg)

您的 Jenkins 设置已成功完成。

# 自动化 Jenkins

在本节中，我们将介绍 Jenkins 配置的不同部分，并将看看如何成功创建我们的第一个作业并构建我们的应用程序。

理想情况下，成功登录后，我们的 Jenkins 主页应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00114.jpeg)

# 保护 Jenkins

强烈建议设置 Jenkins 安全性，使您的控制台安全，因为我们正在将我们的应用程序暴露给 Jenkins。

从 Jenkins 主页，单击“管理 Jenkins”以导航到 Jenkins 的设置部分，然后单击右侧窗格中的“配置全局安全性”以打开安全面板。

在配置全局安全性部分，我们可以管理用户授权，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00115.jpeg)

如前面的屏幕截图所示，您可以根据其角色为用户定义访问列表。通常，在大型组织中，根据使用情况为不同的人提供用户访问权限，以便维护 Jenkins 安全性。通常，我们要么使用基于 Unix 的用户/组数据库，要么使用 Jenkins 自己的用户数据库。

# 插件管理

插件管理非常重要，因为这些插件使我们能够将不同的环境（可能是云平台）或本地资源与 Jenkins 集成，并且使我们能够管理资源上的数据，如应用服务器、数据库服务器等。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00116.jpeg)

从管理 Jenkins 面板中，选择管理插件选项以打开管理插件面板，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00117.jpeg)

在此面板中，您可以安装、卸载和升级系统中的任何特定插件。从同一面板，您还可以升级 Jenkins。

# 版本控制系统

Jenkins 主要用于构建特定应用程序代码，或在任何基础设施平台上部署代码（即用于持续部署）。

如今，组织将其应用程序代码存储在任何版本控制系统中，例如 Git，管理员具有集中控制，并可以根据用户角色提供所需的访问权限。此外，由于我们正在谈论持续集成，因此建议将应用程序代码存储在具有版本控制的集中位置，以维护代码的完整性。

为了保持版本代码，请确保您从管理插件面板安装 Git 插件。

要通过 Jenkins 克隆 Git 存储库，您需要为 Jenkins 系统输入电子邮件和用户名。为此，请切换到作业目录，并运行以下 Git 配置命令：

```py
# Need to configure the Git email and user for the Jenkins job 

# switch to the job directory 
cd /var/lib/Jenkins/jobs/myjob/workspace 

# setup name and email 
sudo git config user.name "Jenkins" 
sudo git config user.email "test@gmail.com" 

```

这需要设置以便从存储库下载代码，或在 Git 中合并分支时，以及其他情况下。

# 设置 Jenkins 作业

现在我们准备设置我们的第一个 Jenkins 作业。如前所述，每个作业都是为执行特定任务而创建的，可以是个别的，也可以是流水线的。

根据 Andrew Phillips 的说法，理想情况下，流水线将软件交付过程分解为各个阶段。每个阶段旨在从不同角度验证新功能的质量，以验证新功能，并防止错误影响用户。如果遇到任何错误，将以报告的形式返回反馈，并确保达到所需的软件质量。

为了启动作业创建，在 Jenkins 主页上，单击左侧的“新项目”，或单击右侧窗格中的“创建新作业”链接：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00118.jpeg)

单击后，它将打开一个向导，询问您的项目/作业名称以及要创建的作业类型，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00119.jpeg)

描述已经提供，以及项目类型，以便给我们一个 Jenkins 中可用不同选项的概述。这些类型需要被选择，因为它们基于类型有不同的配置。

请注意，由于我们正在使用最新的 Jenkins 版本，可能一些项目类型在旧版本中可能不存在，因此请确保您安装了最新的 Jenkins。

现在，我们将选择自由风格项目，指定一个唯一的作业名称，然后单击“确定”以继续配置我们的作业。单击“确定”后，您将看到以下页面：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00120.jpeg)

在前面的页面中，您可以定义作业的详细信息，例如项目名称、描述、GitHub 项目等。

接下来，单击“源代码管理”选项卡；您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00121.jpeg)

在前面的部分中，您将定义您的源代码详细信息。如果您之前在配置部分中还没有设置 Jenkins 用户凭据，那么您也需要设置 Jenkins 用户凭据。如果尚未设置，请单击凭据旁边的“添加”按钮。它将打开一个弹出窗口，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00122.jpeg)

您在此处定义的用户（即管理员）需要在代码存储库中具有访问权限。

有多种方式可以为存储库上的所述用户设置身份验证，这些方式在“种类”（下拉菜单）中定义：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00123.jpeg)

重要的是要注意，Jenkins 将立即测试与所提到的存储库 URL 的凭据。如果失败，它将显示您在此截图中看到的错误：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00124.jpeg)

假设凭据与存储库 URL 匹配，让我们继续单击“构建触发器”选项卡以滚动它。以下屏幕显示了可以对作业进行连续部署的构建触发器选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00125.jpeg)

这个构建触发器部分非常重要，因为它决定了您的构建应该运行多频繁，以及触发构建的参数。例如，如果您希望在每次 Git 提交后构建您的应用程序，您可以选择“当更改被推送到 GitBucket 时构建”的选项。

因此，一旦开发人员在存储库的某个分支（通常是主分支）中提交任何更改，那么此作业将自动触发。这就像是在存储库顶部的一个钩子，它会跟踪其中的活动。或者，如果您想要定期构建您的应用程序或运行此作业，那么您可以指定类似于这样的条件-- `H/15 * * * *`--在轮询 SCM 以安排中，这意味着此作业将每 15 分钟运行一次。这类似于我们通常在基于 Linux 的系统中设置的 cron 作业。

接下来的两个部分，**构建环境**和**构建**，是为与工作区相关的任务定义的。由于我们正在处理一个基于 Python 的应用程序，并且我们已经构建了我们的应用程序，所以我们现在可以跳过这些部分。但是，如果您有一个用 Java 编写的应用程序或.NET 应用程序，您可以使用 ANT 和 Maven 构建工具，并分支构建。或者，如果您想构建一个基于 Python 的应用程序，那么可以使用诸如 pyBuilder ([`pybuilder.github.io/`](http://pybuilder.github.io/))之类的工具。以下屏幕显示了构建选项：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00126.jpeg)

完成后，您可以单击下一个选项卡，即后构建操作。这用于定义构建成功后需要执行的操作。由于这一部分，Jenkins 也可以用作持续部署工具。因此，在此后构建操作中，您可以指定应用程序需要部署的平台，例如 AWS EC2 机器、Code deploy、Azure VM 或其他平台。

在持续集成的后构建部分中，我们还可以执行诸如成功构建后的 Git 合并、在 Git 上发布结果等操作。此外，您还可以为利益相关者设置电子邮件通知，以便通过电子邮件向他们提供有关构建结果的更新。有关更多详细信息，请参见以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00127.jpeg)

就这样。一旦填写了必要的细节，点击保存以保存配置。现在您已经准备好构建您的应用程序了--点击左侧面板中的立即构建链接，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00128.jpeg)

注意：对于第一次构建执行，如果您尚未设置轮询 SCM 或构建触发器部分，则需要手动触发它。

这是我们目前从 Jenkins 那里得到的有关作业创建的所有信息。然而，在接下来的章节中，我们将使用 Jenkins 作为持续交付和持续集成工具，部署我们在之前章节中创建的 React 应用程序到 AWS、Azure 或 Docker 等不同平台上。我们还将看到 AWS 服务与 Jenkins 的集成，通过单次提交自动化将应用程序交付到 GitHub 存储库。

# 理解持续交付

持续交付是一种软件工程实践，其中生产就绪的功能被生产并部署到生产环境。

持续交付的主要目标是在不考虑平台的情况下执行成功的应用程序部署，无论是大规模分布式系统还是复杂的生产环境。

在跨国公司中，我们始终确保应用程序代码处于稳定且可部署状态，即使有许多开发人员同时在不同的应用程序组件上工作。在持续交付中，我们还确保单元测试和集成测试成功进行，使其达到生产就绪状态。

# 持续交付的需求

人们普遍认为，如果我们尝试更频繁地部署软件，我们应该预期系统的稳定性和可靠性水平会降低，但这并不完全正确。持续交付提供了一些实践，为愿意在竞争激烈的市场中发布稳定可靠软件的组织提供了令人难以置信的竞争优势。

持续交付的实践给我们带来了以下重要的好处：

+   **无风险发布**：软件发布中的主要要求是最小或零停机时间。毕竟，这始终与业务有关，用户不应因频繁发布而受到影响。通过使用 BlueGreenDeployment（[`martinfowler.com/bliki/BlueGreenDeployment.html`](https://martinfowler.com/bliki/BlueGreenDeployment.html)）等模式，我们可以在部署过程中实现零停机时间。

+   **竞争市场**：在持续交付中，所有团队，如构建和部署团队、测试团队、开发人员等，都共同合作，使不同的活动如测试、集成等每天都发生。这使得功能发布过程更快（一周或两周），我们将频繁地将功能发布到生产环境供客户使用。

+   **质量改进**：在持续交付中，开发人员无需担心测试过程，因为流水线会处理这一过程，并向 QA 团队展示结果。这使得 QA 团队和开发人员能够更仔细地进行探索性测试、可用性测试以及性能和安全性测试，从而改善客户体验。

+   **更好的产品**：通过在构建、测试、部署和环境设置中使用持续交付，我们减少了软件增量变更的成本和交付成本，从而使产品在一段时间内变得更好。

# 持续交付与持续部署

持续交付和持续部署在构建、测试和软件发布周期方面相似，但在*流程*方面略有不同，您可以从以下图表中了解到：

在下一章中，我们将讨论基于容器技术的 Docker。我相信你们大多数人之前都听说过 Docker，所以请继续关注对 Docker 的深入了解。我们下一章见！

在持续部署中，经过所有测试检查的生产就绪代码直接部署到生产环境，这使得软件发布频繁。但在持续交付的情况下，除非由相关部门手动触发或批准，否则不会部署生产就绪的应用程序代码。

# 总结

在整个章节中，我们讨论了像 Jenkins 这样的 CI 和 CD 工具，并且也看了它们的不同功能。在这个阶段理解这些工具非常重要，因为大多数处理云平台的公司都使用这些流程进行软件开发和部署。所以，现在您已经了解了部署流水线，您可以开始了解我们将部署应用程序的平台了。

（图片已省略）


# 第十章：将您的服务 Docker 化

既然我们已经从上一章了解了持续集成和持续交付/部署，现在是深入研究基于容器的技术，比如 Docker，我们将在其中部署我们的应用程序的正确时机。在本章中，我们将看一下 Docker 及其特性，并在 Docker 上部署我们的云原生应用。

本章将涵盖以下主题：

+   了解 Docker 及其与虚拟化的区别

+   在不同操作系统上安装 Docker 和 Docker Swarm

+   在 Docker 上部署云原生应用

+   使用 Docker Compose

# 了解 Docker

Docker 是一个**容器管理系统**（**CMS**），它使您能够将应用程序与基础架构分离，这样更容易开发、部署和运行应用程序。它对管理**Linux 容器**（**LXC**）很有用。这让您可以创建镜像，并对容器执行操作，以及对容器运行命令或操作。

简而言之，Docker 提供了一个在被称为**容器**的隔离环境中打包和运行应用程序的平台，然后在不同的软件发布环境中进行部署，如阶段、预生产、生产等。

**Docker**与任何**传统 VM**相比都更轻量，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00130.jpeg)

# 关于 Docker 与虚拟化的一些事实

仍然成功地在传统 VM 上工作的组织有很多。话虽如此，有些组织已经将他们的应用程序迁移到了 Docker 上，或者准备这样做。以下是 Docker 比虚拟机具有更多潜力的几个原因：

+   在比较 Docker 和虚拟机时，Docker 的系统开销比虚拟机低。

+   其次，在 Docker 环境中的应用程序通常比虚拟机性能更高。

+   而 VM 软件技术名为**Hypervisor**，它充当 VM 环境和底层硬件之间的代理，提供必要的抽象层；在 Docker 中，我们有 Docker 引擎，它比 Docker 机器给我们更多的控制。

+   此外，正如您在上图中所看到的，Docker 在 Docker 环境中共享**主机操作系统**，而虚拟机需要自己的操作系统进行应用程序部署。这使得 Docker 更轻量化，可以更快地启动和销毁，与虚拟机相比。Docker 类似于在主机操作系统上运行的任何其他进程。

+   在云原生应用的情况下，我们需要在每个开发阶段之后快速测试我们的微服务，Docker 将是一个很好的平台选项来测试我们的应用程序，这是强烈推荐的。

# Docker Engine - Docker 的支柱

Docker Engine 是一个客户端服务器应用程序，具有以下组件：

+   **Dockerd**：这是一个守护进程，以在主机操作系统的后台持续运行，以跟踪 Docker 容器属性，如状态（启动/运行/停止）

+   **Rest API**：这提供了与守护程序交互并在容器上执行操作的接口

+   **Docker 命令行**：这提供了命令行界面来创建和管理 Docker 对象，如镜像、容器、网络和卷

# 设置 Docker 环境

在本节中，我们将看一下在不同操作系统上安装 Docker 的过程，比如 Debian 和 Windows 等。

# 在 Ubuntu 上安装 Docker

设置 Docker 非常简单。市场上主要有两个版本的 Docker。

Docker Inc.拥有**容器化**Docker 产品，将 Docker **商业支持**（**CS**）版更名为 Docker **企业版**（**EE**），并将 Docker Engine 转换为 Docker **社区版**（**CE**）。

EE 和 CE 有一些变化；显然，商业支持是其中之一。但是，在 Docker 企业版中，他们围绕容器内容、平台插件等构建了一些认证。

在本书中，我们将使用 Docker 社区版，因此我们将从更新 APT 存储库开始：

```py
$ apt-get update -y 

```

现在，让我们按照以下步骤从 Docker 官方系统添加 GPG 密钥：

```py
$ sudo apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys 58118E89F3A912897C070ADBF76221572C52609D 

```

然后让我们将 Docker 存储库添加到 Ubuntu 的 APT 源列表中：

```py
$ sudo apt-add-repository 'deb https://apt.dockerproject.org/repo ubuntu-xenial main' 

```

有时，在 Ubuntu 14.04/16.04 中找不到`apt-add-repository`实用程序。为了安装所述的实用程序，请使用以下命令安装`software-properties-common`软件包：**$ sudo apt-get install software-properties-common -y**。

接下来，更新 APT 软件包管理器以下载最新的 Docker 列表，如下所示：

```py
$ apt-get update -y

```

如果您想从 Docker 存储库而不是默认的 14.04 存储库下载并安装 Docker Engine，请使用以下命令：

**$ apt-cache policy docker-engine**。

您将在终端上看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00131.jpeg)

现在，我们准备安装我们的 Docker Engine，所以让我们执行以下命令来安装它：

```py
$ sudo apt-get install -y docker-engine -y 

```

由于 Docker 依赖于一些系统库，可能会遇到类似于以下截图显示的错误：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00132.jpeg)

如果遇到此类错误，请确保已安装这些库并且版本已定义。

Docker Engine 安装成功后，现在是时候通过执行以下命令来验证它了：

```py
$ docker -v   
Docker version 17.05.0-ce, build 89658be 

```

如果您看到类似于前面终端显示的版本，则我们可以开始了。

要获取有关 Docker 的帮助，可以执行以下命令：

```py
$ docker help 

```

如果您真的想使用 Docker 企业版，可以按照官方 Docker 网站上显示的安装步骤进行操作（[`docs.docker.com/engine/installation/linux/ubuntu/`](https://docs.docker.com/engine/installation/linux/ubuntu/)）。

# 在 Windows 上安装

理想情况下，Windows 不适合 Docker，这就是为什么您在 Windows 系统上看不到容器技术的原因。话虽如此，我们有一些解决方法。其中之一是使用 Chocolatey。

为了使用 Chocolatey 在 Windows 系统上安装 Docker，请按照以下步骤进行操作：

1.  从官方网站安装 Chocolatey（[`chocolatey.org/install`](https://chocolatey.org/install)）。

在前面的链接中显示了安装 Chocolatey 的几种方法。

1.  安装了 Chocolatey 后，您只需在 cmd 或 PowerShell 中执行以下命令：

```py
 $ choco install docker

```

这将在 Windows 7 和 8 操作系统上安装 Docker。

同样，如果您想使用 Docker 企业版，可以按照此链接中显示的步骤进行操作：

[`docs.docker.com/docker-ee-for-windows/install/#install-docker-ee`](https://docs.docker.com/docker-ee-for-windows/install/#install-docker-ee)。

# 设置 Docker Swarm

Docker Swarm 是 Docker 机器池的常用术语。 Docker Swarm 非常有用，因为它可以快速扩展或缩小基础架构，用于托管您的网站。

在 Docker Swarm 中，我们可以将几台 Docker 机器组合在一起，作为一个单元共享其资源，例如 CPU、内存等，其中一台机器成为我们称之为领导者的主机，其余节点作为工作节点。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00133.jpeg)

# 设置 Docker 环境

在本节中，我们将通过从 Docker 机器中选择领导者并将其余机器连接到领导者来设置 Docker Swarm。

# 假设

以下是 Docker 环境的一些假设：

+   我们将使用两台机器，可以是虚拟机或来自云平台的实例，以演示为目的命名为 master 和 node1。此外，我们已经按照 Docker 安装部分中描述的过程在这两台机器上安装了 Docker。

+   端口`2377`必须打开以便主节点和节点 1 之间进行通信。

+   确保应用程序访问所需的端口应该是打开的；我们将需要端口`80`来使用 nginx，就像我们的示例中一样。

+   主 Docker 机器可以基于任何类型的操作系统，例如 Ubuntu、Windows 等。

现在，让我们开始我们的 Docker Swarm 设置。

# 初始化 Docker 管理器

此时，我们需要决定哪个节点应该成为领导者。让我们选择主节点作为我们的 Docker 管理器。因此，请登录到主机并执行以下命令，以初始化此机器为 Docker Swarm 的领导者：

```py
$ docker swarm init --advertise-addr master_ip_address 

```

此命令将设置提供的主机为主（领导者），并为节点生成一个连接的令牌。请参考以下输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00134.jpeg)

需要记住的一些重要点：

+   不要与任何人分享您的令牌和 IP 地址

+   其次，在故障转移的情况下可能会有多个主节点

# 将节点 1 添加到主节点

现在我们已经选择了领导者，我们需要添加一个新节点到集群中以完成设置。登录到节点 1 并执行前面命令输出中指定的以下命令：

```py
$ docker swarm join     --token SWMTKN-1-
1le69e43paf0vxyvjdslxaluk1a1mvi5lb6ftvxdoldul6k3dl-
1dr9qdmbmni5hnn9y3oh1nfxp    master-ip-address:2377 

```

您可以参考以下截图输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00135.jpeg)

这意味着我们的设置是成功的。让我们检查它是否已添加到主 Docker 机器中。

执行以下命令进行验证：

```py
$ docker node ls 

```

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00136.jpeg)

# 测试 Docker Swarm

既然我们已经设置了 Docker Swarm，现在是时候在其上运行一些服务了，比如 nginx 服务。在主 Docker 机器上执行以下命令，以在端口`80`上启动您的 nginx 服务：

```py
$ docker service create  --detach=false -p 80:80 --name webserver
nginx 

```

前面命令的输出应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00137.jpeg)

让我们使用以下 Docker 命令来查看我们的服务是否正在运行：

```py
$ docker service ps webserver 

```

前面命令的输出应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00138.jpeg)

其他一些验证命令如下：

要验证哪些服务正在运行以及在哪个端口上，请使用以下命令：

```py
$ docker service ls 

```

如果您看到类似以下截图的输出，那么一切正常：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00139.jpeg)

要扩展服务的 Docker 实例，请使用以下命令：

```py
$ docker service scale webserver=3 

```

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00140.jpeg)

通过访问其默认页面来检查我们的 nginx 是否已经启动。尝试在浏览器中输入`http://master-ip-address:80/`。如果您看到以下输出，则您的服务已成功部署：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00141.jpeg)

太棒了！在接下来的部分，我们将在 Docker 机器上部署我们的云原生应用程序。

# 在 Docker 上部署应用程序

在本节中，我们将部署我们的云原生应用程序，这是我们在前几章中开发的。然而，在我们开始创建应用程序架构之前，有一些 Docker 的概念是应该了解的，其中一些如下：

+   **Docker 镜像**：这些基本上是库和部署在其上的应用程序的组合。这些图像可以从 Docker Hub 公共存储库下载，或者您也可以创建自定义图像。

+   **Dockerfile**：这是一个配置文件，用于构建可以在以后运行 Docker 机器的图像。

+   **Docker Hub**：这是一个集中的存储库，您可以在其中保存图像，并可以在团队之间共享。

我们将在应用部署过程中使用所有这些概念。此外，我们将继续使用我们的 Docker Swarm 设置来部署我们的应用程序，因为我们不想耗尽资源。

我们将遵循这个架构来部署我们的应用程序，我们将我们的应用程序和 MongoDB（基本上是应用程序数据）部署在单独的 Docker 实例中，因为建议始终将应用程序和数据分开：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00142.jpeg)

# 构建和运行我们的 MongoDB Docker 服务

在本节中，我们将创建 Dockerfile 来构建`MongoDB`，其中将包含所有信息，例如基本图像、要公开的端口、如何安装`MongoDB`服务等。

现在，让我们登录到您的 Docker 主（领导）帐户，并使用以下内容创建名为`Dockerfile`的 Docker 文件：

```py
    # MongoDB Dockerfile 
    # Pull base image. 
    FROM ubuntu 
    MAINTAINER Manish Sethi<manish@sethis.in> 
    # Install MongoDB. 
    RUN \ 
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 
    7F0CEB10 && \ 
    echo 'deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart
    dist 10gen' > /etc/apt/sources.list.d/mongodb.list && \ 
    apt-get update && \ 
    apt-get install -y mongodb-org && \ 
    rm -rf /var/lib/apt/lists/* 

    # Define mountable directories. 
    VOLUME ["/data/db"] 

    # Define working directory. 
    WORKDIR /data 

    # Define default command. 
    CMD ["mongod"] 

    # Expose ports. 
    EXPOSE 27017 
    EXPOSE 28017 

```

保存它，在我们继续之前，让我们了解其不同的部分，如下所示：

```py
    # Pull base image. 
    FROM ubuntu 

```

上面的代码将告诉您从 Docker Hub 拉取 Ubuntu 公共图像，并将其作为基础图像运行以下命令：

```py
    # Install MongoDB 
    RUN \ 
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 
    7F0CEB10 && \ 
    echo 'deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart 
    dist 10gen' > /etc/apt/sources.list.d/mongodb.list && \ 
    apt-get update && \ 
    apt-get install -y mongodb-org && \ 
    rm -rf /var/lib/apt/lists/*

```

上面的代码部分类似于我们手动执行这些命令为`MongoDB`；但是，在这种情况下，Docker 会自动处理。

接下来是卷部分，这在某种程度上是可选的。它正在创建可挂载的目录，我们可以在其中存储数据以在外部卷中保持安全。

```py
    # Define mountable directories. 
    VOLUME ["/data/db"] 

```

接下来的部分是通过这些端口公开的，用户/客户端将能够与 MongoDB 服务器进行通信：

```py
    EXPOSE 27017 
    EXPOSE 28017 

```

保存文件后，执行以下命令构建图像：

```py
$ docker build --tag mongodb:ms-packtpub-mongodb

```

构建图像可能需要大约 4-5 分钟，这取决于互联网带宽和系统性能。

以下屏幕显示了 Docker 构建命令的输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00143.jpeg)

在前面的截图中，由于显示了成功构建，现在您可以查看图像列表以验证是否存在具有所述标记名称（**ms-packtpub-mongodb**）的图像。

使用以下命令列出图像：

```py
$ docker images

```

以下屏幕列出了可用的 Docker 图像：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00144.jpeg)

太棒了！我们的图像已经存在。现在让我们使用以下命令在主 Docker 机器上运行`mongodb`服务：

```py
$ docker run -d -p 27017:27017 -p 28017:28017 --name mongodb mongodb:ms-packtpub-mongodb mongod --rest --httpinterface

```

在输出中，您将获得一个随机的 Docker ID，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00145.jpeg)

通过执行`docker ps`命令来检查 Docker 容器的状态。它的输出应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00146.jpeg)

很少有开发人员和系统管理员知道`mongoDB`服务有一个 HTTP 接口，我们使用端口`28017`进行了暴露。

因此，如果我们尝试在浏览器中访问`http://your-master-ip-address:28017/`，我们将看到类似于以下截图的屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00147.jpeg)

太棒了！我们的 MongoDB 现在已经运行起来了！

在我们继续为应用程序启动容器之前，让我们了解一下 Docker Hub 对我们有何用处。

# Docker Hub - 它是关于什么的？

根据 Docker Hub 官方文档，Docker Hub 是一个基于云的注册表服务，允许您链接到代码存储库，构建图像并对其进行测试，并存储手动推送的图像，并链接到 Docker Cloud，以便您可以将图像部署到您的主机。

简而言之，Docker Hub 是一个集中存储图像的地方，全球任何人都可以访问，只要他们具有所需的权限，并且可以执行围绕图像的操作，以在其主机上部署和运行其应用程序。

Docker Hub 的优点如下：

+   Docker Hub 提供了自动创建构建的功能，如果源代码存储库中报告了任何更改

+   它提供了 WebHook，用于在成功推送到存储库后触发应用程序部署

+   它提供了创建私有工作空间以存储图像的功能，并且只能在您的组织或团队内部访问

+   Docker Hub 与您的版本控制系统（如 GitHub、BitBucket 等）集成，这对持续集成和交付非常有用

现在，让我们看看如何将我们的自定义`MongoDB`图像推送到我们最近创建的私有存储库。

首先，您需要在[`hub.docker.com`](https://hub.docker.com)创建一个帐户并激活它。一旦登录，您需要根据自己的喜好创建私有/公共存储库，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00148.jpeg)

单击“创建”按钮设置仓库，您将被重定向到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00149.jpeg)

Docker Hub 在免费帐户上只提供一个私有仓库。

现在我们已经创建了仓库，让我们回到我们的主 Docker 机器并执行以下命令：

```py
$ docker login

```

这将要求您输入 Docker Hub 帐户的凭据，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00150.jpeg)

登录成功后，是时候使用以下命令为要推送到仓库的镜像打标签了：

```py
$ docker tag mongodb:ms-packtpub-mongodb manishsethis/docker-packtpub

```

如果我们不指定标签，那么它将默认使用最新的标签。

标签创建完成后，是时候将标签推送到仓库了。使用以下命令来执行：

```py
$ docker push manishsethis/docker-packtpub

```

以下屏幕显示了 Docker `push`命令的输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00151.jpeg)

推送完成后，您将在 Docker Hub 的“标签”选项卡中看到镜像，如此处所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00152.jpeg)

这意味着您的镜像已成功推送。

要拉取此镜像，您只需使用以下命令：

```py
$ docker pull manishsethis/docker-packtpub

```

哦，哇！这太简单了，只要您有凭据，就可以从任何地方访问它。

还有其他 Docker 注册表提供者，如 AWS（EC2 容器注册表）、Azure（Azure 容器注册表）等。

目前，这就是我们从 Docker Hub 那边得到的全部内容。在本章中，我们将继续使用 Docker Hub 来推送镜像。

现在继续，我们准备将我们的云原生应用部署到另一个容器中，但在此之前，我们需要使用 Dockerfile 为其构建一个镜像。因此，让我们创建一个名为`app`的目录，并创建一个空的 Dockerfile，其中包含以下内容：

```py
 FROM ubuntu:14.04 
    MAINTAINER Manish Sethi<manish@sethis.in> 

    # no tty 
    ENV DEBIAN_FRONTEND noninteractive 

    # get up to date 
    RUN apt-get -qq update --fix-missing 

    # Bootstrap the image so that it includes all of our dependencies 
    RUN apt-get -qq install python3  python-dev python-virtualenv
 python3-pip --assume-yes 
    RUN sudo apt-get install build-essential autoconf libtool libssl-
 dev libffi-dev --assume-yes 
 # Setup locale 
    RUN export LC_ALL=en_US.UTF-8 
    RUN export LANG=en_US.UTF-8 
    RUN export LANGUAGE=en_US.UTF-8 

    # copy the contents of the cloud-native-app(i.e. complete
 application) folder into the container at build time 
 COPY cloud-native-app/ /app/ 

    # Create Virtual environment 
    RUN mkdir -p /venv/ 
    RUN virtualenv /venv/ --python=python3 

    # Python dependencies inside the virtualenv 
    RUN /venv/bin/pip3 install -r /app/requirements.txt 

    # expose a port for the flask development server 
    EXPOSE 5000 

    # Running our flask application  
    CMD cd /app/ && /venv/bin/python app.py 

```

我相信我之前已经解释了 Dockerfile 中大部分部分，尽管还有一些部分需要解释。

```py
  COPY cloud-native-app/ /app/ 

```

在 Dockerfile 的前面部分，我们将应用程序的内容，即代码，从本地机器复制到 Docker 容器中。或者，我们也可以使用 ADD 来执行相同的操作。

`CMD`是我们想要在 Docker 容器内执行的命令的缩写，它在 Dockerfile 中定义如下：

```py
# Running our flask application  
CMD cd /app/ && /venv/bin/python app.py 

```

现在保存文件并运行以下命令来构建镜像：

```py
$ docker build --tag cloud-native-app:latest .

```

这可能需要一些时间，因为需要安装和编译许多库。每次更改后构建镜像是一个好习惯，以确保镜像与当前配置更新。输出将类似于此处显示的输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00153.jpeg)

确保构建过程的每个部分都成功。

现在我们已经准备好了我们的镜像，是时候使用最新的镜像启动我们的容器了。

执行以下命令来启动容器，并始终记住要暴露端口`5000`以访问我们的应用程序：

```py
$ docker run -d -p 5000:5000  --name=myapp  cloud-native-app:latest

```

现在运行`docker ps`命令来检查容器状态：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00154.jpeg)

正如你所看到的，`myapp`容器中有两个容器在运行：我们的应用程序在运行，而`mongodb`容器中将运行您的`mongodb`服务。

接下来，检查应用程序的 URL（`http://your-master-ip-address:5000/`）。如果看到以下屏幕，这意味着我们的应用程序已成功部署，并且我们在 Docker 上已经上线了：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00155.jpeg)

现在我们可以通过创建新用户并登录，然后发布推文来测试我们的应用程序。我不会再次执行，因为我们在创建应用程序时已经执行过了。

根据经验，我知道应用程序和数据库（即 MongoDB）之间的通信可能会存在一些挑战，因为应用程序和数据库都在单独的容器中，可能在单独的网络中。为了解决这种问题，您可以创建一个网络，并将两个容器连接到该网络。

举例来说，如果我们需要为我们的容器（`myapp`和`mongodb`）这样做，我们将按照以下步骤进行：

1.  使用以下命令创建一个单独的网络：

```py
      $ docker network create -d bridge --subnet 172.25.0.0/16
      mynetwork

```

1.  现在我们已经创建了网络，可以使用以下命令将两个容器添加到这个网络中：

```py
      $ docker network connect mynetwork  myapp
      $ docker network connect mynetwork  mongodb

```

1.  为了找到分配给这些容器的 IP，我们可以使用以下命令：

```py
      $ docker inspect --format '{{ .NetworkSettings.IPAddress }}'
      $(docker ps -q)

```

这个网络的创建是一种设置应用程序和数据库之间通信的替代方式。

好了，我们已经在 Docker 上部署了我们的应用程序，并了解了它的不同概念。唯一剩下的概念是 Docker Compose。让我们了解一下它是什么，以及它与其他工具有何不同。

# Docker Compose

根据官方 Docker Compose 网站（[`docs.docker.com/compose/overview/`](https://docs.docker.com/compose/overview/)），Compose 是一个用于定义和运行多容器 Docker 应用程序的工具。使用 Compose，您可以使用 Compose 文件来配置应用程序的服务。

简单来说，它帮助我们以更简单和更快的方式构建和运行我们的应用程序。

在前一节中，我们部署应用程序并构建镜像时，首先创建了一个 Dockerfile，然后执行了`Docker build`命令来构建它。一旦构建完成，我们通常使用`docker run`命令来启动容器，但是，在 Docker Compose 中，我们将定义一个包含配置细节的`.yml`文件，例如端口、执行命令等。

首先，Docker Compose 是一个独立于 Docker Engine 的实用程序，可以根据您所使用的操作系统类型使用以下链接进行安装：

`https://docs.docker.com/compose/install/`。

安装完成后，让我们看看如何使用 Docker Compose 来运行我们的容器。假设我们需要使用 Docker Compose 运行云原生应用程序容器。我们已经为其生成了 Dockerfile，并且应用程序也在相同的位置（路径）上。

接下来，使用以下内容，我们需要在与 Dockerfile 相同的位置创建一个`Docker-compose.yml`文件：

```py
    #Compose.yml 
    version: '2' 
    services: 
    web: 
     build: . 
      ports: 
      - "5000:5000" 
      volumes: 
       - /app/ 
     flask: 
      image: "cloud-native-app:latest" 

```

在`docker-compose.yml`中添加配置后，保存并执行`docker-compose up`命令。构建镜像后，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00156.jpeg)

此外，如果查看容器的状态，您会发现多个容器（在我们的情况下，`app_web-1`和`app_flask_1`）由 compose 启动，这就是为什么它对于需要大规模基础设施的多容器应用程序非常有用，因为它创建了类似 Docker Swarm 的 Docker 机器集群。以下屏幕显示了 Docker 机器的状态：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00157.jpeg)

太棒了！我们还通过 Docker-compose 部署了我们的应用程序。现在您可以尝试访问应用程序的公共 URL（[`your-ip-address:5000`](http://your-ip-address:5000)）来确认成功部署应用程序。

最后，确保将您的镜像推送到 Docker Hub 以将其保存在集中式存储库中。由于我们已经推送了 MongoDB 镜像，请使用以下命令来推送`cloud-native-app`镜像：

```py
$ docker tag cloud-native-app:latest manishsethis/docker-packtpub:cloud-native-app
$ docker push manishsethis/docker-packtpub:cloud-native-app

```

我们应该看到类似的输出，用于 Docker `push`命令如下：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00158.jpeg)

# 总结

在本章中，我们首先看了一个最有趣的技术--Docker--，它是基于容器的。我们研究了 Docker 周围的不同概念，已经部署了我们的应用程序，并研究了我们如何通过 Docker 来管理它。我们还探索了使用 Docker Compose 和 Dockerfile 部署应用程序的多种方式。

在接下来的章节中，情况将变得更加有趣，因为我们最终将接触到云平台，根据我们的应用程序在平台上构建基础设施，并尝试部署它。所以，请继续关注下一章！到时见。


# 第十一章：在 AWS 平台上部署

在上一章中，我们看到了我们应用程序的一个平台，名为 Docker。它可以隔离您的应用程序，并可用于响应来自客户的应用程序请求。在本章中，我们将向您介绍云平台，特别是 AWS（亚马逊云服务），主要涉及 IaaS（基础设施）和 PaaS（平台即服务）服务。我们还将看看如何构建基础设施并部署我们的应用程序。

本章包括以下主题：

+   介绍 AWS 及其服务

+   使用 Terraform/CloudFormation 构建应用程序基础设施

+   使用 Jenkins 进行持续部署

# 开始使用亚马逊云服务（AWS）

亚马逊云服务（AWS）是一个安全的云平台。它在 IaaS 和 PaaS 方面提供各种服务，包括计算能力、数据库存储和内容传递，有助于扩展应用程序，并在全球范围内发展我们的业务。AWS 是一个公共云，根据云计算概念，它以按需交付和按使用量付费的方式提供所有资源。

您可以在[`aws.amazon.com/`](https://aws.amazon.com/)了解更多关于 AWS 及其服务的信息。

如在第一章中指定的，*介绍云原生架构和微服务*，您需要创建一个 AWS 账户才能开始使用这些服务。您可以使用以下链接创建一个账户：

[`medium.com/appliedcode/setup-aws-account-1727ce89353e`](https://medium.com/appliedcode/setup-aws-account-1727ce89353e)

登录后，您将看到以下屏幕，其中展示了 AWS 及其类别。一些服务处于测试阶段。我们将使用与计算和网络相关的一些服务来构建我们应用程序的基础设施：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00159.jpeg)

一些常用的 AWS 应用服务如下：

+   EC2（弹性计算云）：这是 AWS 提供的计算服务，简单来说，它提供了一个服务器。

+   ECS（弹性容器服务）：这类似于位于公共云（即亚马逊）上的 Docker 服务。它仅在 EC2 机器上管理 Docker。您可以在亚马逊云中轻松设置 Docker 集群，而不是在本地创建 Docker 集群，而且开销更小。

+   EBS（弹性 Beanstalk）：这是一个 PaaS 服务，您只需上传代码，并指定需要多少基础设施（基本上是应用服务器（EC2））。EBS 将负责创建机器，并在其上部署代码。

+   S3（简单存储服务）：这是 AWS 提供的存储服务，我们通常将应用程序数据或静态内容存储在其中，可用于静态网站托管。我们将用它进行持续部署。

+   Glacier：这是另一个存储服务，主要用于备份，因为成本较低，因此数据存储和检索能力较慢，与 S3 相比。

+   VPC（虚拟专用网络）：这是一个网络服务，可以让您控制资源的可访问性。我们将使用此服务来保护我们的基础设施。此服务非常有用，可用于保护我们的应用程序服务和数据库服务，并仅向外部世界公开所需的选择性资源。

+   CloudFront：这是一个内容传递服务，可以在全球范围内分发您在 S3 中的内容，并确保无论请求源的位置如何，都可以快速检索到。

+   CloudFormation：这为开发人员和系统管理员提供了一种简单的方式来创建和管理一组相关的 AWS 资源，例如以代码形式进行配置和更新。我们将使用此服务来构建我们的基础设施。

+   **CloudWatch**：此服务跟踪您的资源活动。它还以日志的形式跟踪 AWS 账户上的任何活动，这对于识别任何可疑活动或账户被盗非常有用。

+   **IAM（身份和访问管理）**：这项服务正如其名，非常有用于管理 AWS 账户上的用户，并根据他们的使用和需求提供角色/权限。

+   **Route 53**：这是一个高可用和可扩展的云 DNS 云服务。我们可以将我们的域名从其他注册商（如 GoDaddy 等）迁移到 Route 53，或者购买 AWS 的域名。

AWS 提供了许多其他服务，本章无法涵盖。如果您有兴趣并希望探索其他服务，可以查看 AWS 产品列表（[`aws.amazon.com/products/`](https://aws.amazon.com/products/)）。

我们将使用大部分前述的 AWS 服务。让我们开始按照我们的应用程序在 AWS 上构建基础设施。

# 在 AWS 上构建应用程序基础设施

在我们的应用程序的这个阶段，系统架构师或 DevOps 人员进入画面，并提出不同的基础设施计划，这些计划既安全又高效，足以处理应用程序请求，并且成本效益高。

就我们的应用程序而言，我们将按照以下图像构建其基础设施：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00160.jpeg)

我们将按照前述的应用程序架构图为我们的应用程序构建基础设施，其中包括一些 AWS 服务，如 EC2、VPC、Route 53 等。

有三种不同的方式可以在 AWS 云上配置您的资源，分别是：

+   **管理控制台**：这是我们已经登录的用户界面，可以用于在云上启动资源。（查看此链接以供参考：[`console.aws.amazon.com/console/`](https://console.aws.amazon.com/console/home?region=us-east-1)）

+   **编程方式**：我们可以使用一些编程语言，如 Python、Ruby 等来创建资源，为此 AWS 创建了不同的开发工具，如 Codecom。此外，您可以使用 SDK 根据您喜欢的语言创建资源。您可以查看[`aws.amazon.com/tools/`](https://aws.amazon.com/tools/) 了解更多信息。

+   AWS CLI（命令行界面）：它是建立在 Python SDK 之上的开源工具，提供与 AWS 资源交互的命令。您可以查看链接：[`docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html`](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-welcome.html) 了解其工作原理，并了解在您的系统上设置此工具的步骤。

创建资源非常简单直接，所以我们不会涵盖这一点，但您可以查看 AWS 文档（[`aws.amazon.com/documentation/`](https://aws.amazon.com/documentation/)）来了解如何操作。

我将向您展示如何使用 Terraform 和名为 CloudFormation 的基于 AWS 的服务构建基础设施。

# 生成身份验证密钥

身份验证是任何产品或平台的重要功能，用于检查试图访问产品并执行操作的用户的真实性，同时保持系统安全。由于我们将使用 API 访问 AWS 账户，我们需要授权密钥来验证我们的请求。现在，一个重要的 AWS 服务进入了叫做**IAM**（身份和访问管理）的画面。

在 IAM 中，我们定义用户并生成访问/密钥，并根据我们想要使用它访问的资源分配角色。

强烈建议永远不要以根用户身份生成访问/密钥，因为默认情况下它将对您的账户拥有完全访问权限。

以下是创建用户和生成访问/密钥的步骤：

1.  转到[`console.aws.amazon.com/iam/home?region=us-east-1#/home`](https://console.aws.amazon.com/iam/home?region=us-east-1#/home)；您应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00161.jpeg)

1.  现在，点击左窗格中的第三个选项，名为用户。如果您的帐户是新的，您将看不到用户。现在，让我们创建一个新用户--为此，请点击右窗格中的“添加用户”按钮：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00162.jpeg)

1.  一旦您点击“添加用户”按钮，将加载一个新页面，并要求输入用户名以及您希望用户访问帐户的方式。例如，如果您打算仅将此用户`manish`用于编程目的，那么建议您取消选中 AWS 管理控制台访问框，以便用户无需使用 AWS 管理控制台登录。参考以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00163.jpeg)

1.  完成后，点击屏幕右下方的“下一步：权限”按钮。接下来，您需要选择要授予此用户的权限，我们称之为 IAM 策略。这意味着现在用户应该能够根据定义的策略访问资源，以及用户在资源上允许的操作类型。现在，我们向此用户添加“Power User Access”策略。

1.  在内部，Power User Access 将具有 JSON 格式的策略，类似于这样：

```py
     { 
       "Version": "2012-10-17", 
       "Statement": [ 
            { 
              "Effect": "Allow", 
              "NotAction": [ 
                "iam:*", 
                "organizations:*" 
              ], 
              "Resource": "*" 
            }, 
            { 
              "Effect": "Allow", 
                "Action": "organizations:DescribeOrganization", 
                "Resource": "*" 
            } 
          ] 
      } 

```

有关 IAM 策略的更多信息，请阅读以下链接中的文档：[`docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html`](http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)

使用 Microsoft Active Directory 的读者可以使用 AD 连接器轻松地将 AD 与 IAM 集成。有关更多信息，请阅读以下链接中提供的文章：[`aws.amazon.com/blogs/security/how-to-connect-your-on-premises-active-directory-to-aws-using-ad-connector/`](https://aws.amazon.com/blogs/security/how-to-connect-your-on-premises-active-directory-to-aws-using-ad-connector/)

考虑以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00164.jpeg)

1.  一旦您为用户添加了策略，请点击屏幕右下方的“下一步：审查”按钮以继续。

1.  下一个屏幕将要求您进行审查，一旦确定，您可以点击“创建用户”按钮来创建用户：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00165.jpeg)

1.  一旦您点击“创建用户”按钮，用户将被创建，并且策略将附加到用户上。您现在将看到以下屏幕，其中自动生成了访问密钥和秘密密钥，您需要保密，并且绝对不与任何人分享：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00166.jpeg)

1.  现在我们的访问/秘密密钥已生成，是时候在 AWS 上构建我们的应用程序基础架构了。我们将使用以下工具来实现：

+   Terraform：这是一个用于在不同云平台上构建基础架构的开源工具

+   **CloudFormation**：这些是使用 AWS 资源构建应用程序基础架构的 AWS 服务

# Terraform - 一个构建基础架构的工具

Terraform 是一个用于在不同云平台（如 AWS、Azure 等）上构建、管理和版本化基础架构的工具。它可以管理基础架构的低级组件，如计算、存储、网络等。

在 Terraform 中，我们指定描述应用程序基础架构的资源规范的配置文件。Terraform 描述执行计划和要实现的期望状态。然后，它根据规范开始构建资源，并在构建后跟踪基础架构的当前状态，始终执行增量执行，如果配置发生更改。

以下是 Terraform 的一些特点：

+   Terraform 将您的数据中心描述为蓝图，可以进行版本控制，并可以管理为代码。

+   Terraform 在实际实施之前为您提供执行计划，这有助于您将执行计划与期望结果进行匹配。

+   Terraform 可以帮助您设计所有资源并并行创建资源。它可以让您了解资源之间的依赖关系，并确保在创建资源之前满足这些依赖关系。

+   凭借其洞察力，它可以让开发人员更好地控制基础架构的修改，减少人为错误。

在 Terraform 中，我们将 AWS 中的每项服务都视为需要创建的资源，因此我们需要为其创建提供其创建所需的强制属性。现在，让我们开始创建资源：

1.  首先，我们需要创建**VPC**（虚拟私有云），在其中启动所有其他资源。

注意：根据约定，我们需要按照`.tf`文件扩展名创建所有文件。

1.  所以，让我们创建一个空的`main.tf`文件。添加以下代码，用于设置服务提供商的访问和秘钥以进行身份验证：

```py
    # Specify the provider and access details 
        provider "aws" { 
          region = "${var.aws_region}" 
          access_key = "${var.aws_access_key}" 
          secret_key = "${var.aws_secret_key}" 
     } 

```

1.  正如您在前面的代码中所看到的，有一个值`${var.aws_region}`。实际上，这是一个约定，将所有值保存在一个名为`variables.tf`的单独文件中，所以我们在这里这样做。让我们用以下内容更改`variables.tf`文件：

```py
     variable "aws_access_key" { 
          description = "AWS access key" 
          default = ""                    # Access key 
      } 

     variable "aws_secret_key" { 
         description = "AWS secret access key" 
         default = ""                          # Secret key 
      } 

      variable "aws_region" { 
          description = "AWS region to launch servers." 
          default = "us-east-1" 
      } 

```

1.  接下来，我们需要创建 VPC 资源，所以让我们将以下代码添加到`main.tf`中：

```py
      # Create a VPC to launch our instances into 
        resource "aws_vpc" "default" { 
          cidr_block = "${var.vpc_cidr}" 
          enable_dns_hostnames = true 
          tags { 
            Name = "ms-cloud-native-app" 
          } 
      } 

```

1.  我们使用了一个变量，需要在`variables.tf`中定义如下：

```py
       variable "vpc_cidr"{ 
          default = "10.127.0.0/16"             # user defined 
       } 

```

1.  一旦定义了 VPC 资源，我们需要创建一个子网，该子网将与 EC2 机器、弹性负载均衡器或其他资源关联。因此，将以下代码添加到`main.tf`中：

```py
        # Create a subnet to launch our instances into 
        resource "aws_subnet" "default" { 
          vpc_id                  = "${aws_vpc.default.id}" 
          cidr_block              = "${var.subnet_cidr}" 
          map_public_ip_on_launch = true 
        } 

      Now, define the variable we have used in above code in 
      variables.tf 
      variable "subnet_cidr"{ 
       default = "10.127.0.0/24" 
      } 

```

1.  由于我们希望我们的资源可以从互联网访问，因此我们需要创建一个互联网网关，并将其与我们的子网关联，以便其中创建的资源可以通过互联网访问。

注意：我们可以创建多个子网来保护我们资源的网络。

1.  将以下代码添加到`main.tf`中：

```py
     # Create an internet gateway to give our subnet access to the
     outside world 
     resource "aws_internet_gateway" "default" { 
     vpc_id = "${aws_vpc.default.id}" 
      } 

     # Grant the VPC internet access on its main route table 
     resource "aws_route" "internet_access" { 
     route_table_id         = "${aws_vpc.default.main_route_table_id}" 
     destination_cidr_block = "0.0.0.0/0" 
     gateway_id             = "${aws_internet_gateway.default.id}" 

```

1.  接下来，我们需要确保您将启动 EC2 机器的子网为机器提供公共地址。这可以通过将下面给出的代码添加到您的`main.tf`中来实现：

```py
     # Create a subnet to launch our instances into 
     resource "aws_subnet" "default" { 
       vpc_id                  = "${aws_vpc.default.id}" 
       cidr_block              = "${var.subnet_cidr}" 
       map_public_ip_on_launch = true 
     } 

```

1.  一旦配置完成，就该开始创建应用服务器和 MongoDB 服务器了。

1.  最初，我们需要创建依赖资源，例如安全组，否则无法启动 EC2。

1.  将以下代码添加到`main.tf`中以创建安全组资源：

```py
    # the instances over SSH and HTTP 
    resource "aws_security_group" "default" { 
    name        = "cna-sg-ec2" 
    description = "Security group of app servers" 
    vpc_id      = "${aws_vpc.default.id}" 

    # SSH access from anywhere 
    ingress { 
     from_port   = 22 
     to_port     = 22 
     protocol    = "tcp" 
     cidr_blocks = ["0.0.0.0/0"] 
    } 

    # HTTP access from the VPC 
    ingress { 
      from_port   = 5000 
      to_port     = 5000 
      protocol    = "tcp" 
      cidr_blocks = ["${var.vpc_cidr}"] 
     } 

     # outbound internet access 
     egress { 
      from_port   = 0 
      to_port     = 0 
      protocol    = "-1" 
      cidr_blocks = ["0.0.0.0/0"] 
    } 
   } 

```

1.  在这个安全组中，我们只打开`22`和`5000`端口，以便进行 ssh 和访问我们的应用程序。

1.  接下来，我们需要添加/创建 ssh 密钥对，您可以在本地机器上生成并上传到 AWS，也可以从 AWS 控制台生成。在我们的情况下，我使用`ssh-keygen`命令在本地机器上生成了一个 ssh 密钥。现在，为了在 AWS 中创建 ssh 密钥对资源，将以下代码添加到`main.tf`中：

```py
   resource "aws_key_pair" "auth" { 
     key_name   = "${var.key_name}" 
      public_key = "${file(var.public_key_path)}" 
   }   

```

1.  添加以下代码片段到`variables.tf`文件中以为变量提供参数：

```py
    variable "public_key_path" { 
      default = "ms-cna.pub" 
    } 

```

1.  现在我们已经创建了依赖资源，是时候创建应用服务器（即 EC2 机器）了。因此，将以下代码片段添加到`main.tf`中：

```py
    resource "aws_instance" "web" { 
     # The connection block tells our provisioner how to 
     # communicate with the resource (instance) 
      connection { 
       # The default username for our AMI 
        user = "ubuntu" 
        key_file = "${var.key_file_path}" 
        timeout = "5m" 
      } 
     # Tags for machine 
     tags {Name = "cna-web"} 
     instance_type = "t2.micro" 
     # Number of EC2 to spin up 
      count = "1" 
      ami = "${lookup(var.aws_amis, var.aws_region)}" 
      iam_instance_profile = "CodeDeploy-Instance-Role" 
      # The name of our SSH keypair we created above. 
      key_name = "${aws_key_pair.auth.id}" 

     # Our Security group to allow HTTP and SSH access 
     vpc_security_group_ids = ["${aws_security_group.default.id}"] 
     subnet_id = "${aws_subnet.default.id}" 
    } 

```

1.  我们在 EC2 配置中使用了一些变量，因此需要在`variables.tf`文件中添加变量值：

```py
    variable "key_name" { 
      description = "Desired name of AWS key pair" 
      default = "ms-cna" 
    } 

   variable "key_file_path" { 
      description = "Private Key Location" 
      default = "~/.ssh/ms-cna" 
   } 

    # Ubuntu Precise 12.04 LTS (x64) 
     variable "aws_amis" { 
       default = { 
        eu-west-1 = "ami-b1cf19c6" 
        us-east-1 = "ami-0a92db1d" 
        #us-east-1 = "ami-e881c6ff" 
        us-west-1 = "ami-3f75767a" 
        us-west-2 = "ami-21f78e11" 
     } 
   } 

```

太好了！现在我们的应用服务器资源配置已经准备好了。现在，我们已经添加了应用服务器配置，接下来，我们需要为 MongoDB 服务器添加类似的设置，这对于保存我们的数据是必要的。一旦两者都准备好了，我们将创建 ELB（这将是用户应用访问的入口点），然后将应用服务器附加到 ELB。

让我们继续添加 MongoDB 服务器的配置。

# 配置 MongoDB 服务器

为 MongoDB 服务器的创建添加以下代码到`main.tf`：

```py
    resource "aws_security_group" "mongodb" { 
     name        = "cna-sg-mongodb" 
     description = "Security group of mongodb server" 
     vpc_id      = "${aws_vpc.default.id}" 

    # SSH access from anywhere 
    ingress { 
      from_port   = 22 
      to_port     = 22 
      protocol    = "tcp" 
      cidr_blocks = ["0.0.0.0/0"] 
     } 

    # HTTP access from the VPC 
    ingress { 
      from_port   = 27017 
      to_port     = 27017 
      protocol    = "tcp" 
      cidr_blocks = ["${var.vpc_cidr}"] 
     } 
    # HTTP access from the VPC 
     ingress { 
      from_port   = 28017 
      to_port     = 28017 
      protocol    = "tcp" 
      cidr_blocks = ["${var.vpc_cidr}"] 
      } 

    # outbound internet access 
    egress { 
      from_port   = 0 
      to_port     = 0 
      protocol    = "-1" 
      cidr_blocks = ["0.0.0.0/0"] 
     } 
   } 

```

接下来，我们需要为 MongoDB 服务器添加配置。还要注意，在以下配置中，我们在创建 EC2 机器时提供了 MongoDB 安装的服务器：

```py
    resource "aws_instance" "mongodb" { 
    # The connection block tells our provisioner how to 
    # communicate with the resource (instance) 
    connection { 
     # The default username for our AMI 
     user = "ubuntu" 
     private_key = "${file(var.key_file_path)}" 
     timeout = "5m" 
     # The connection will use the local SSH agent for authentication. 
     } 
    # Tags for machine 
    tags {Name = "cna-web-mongodb"} 
    instance_type = "t2.micro" 
    # Number of EC2 to spin up 
    count = "1" 
    # Lookup the correct AMI based on the region 
    # we specified 
    ami = "${lookup(var.aws_amis, var.aws_region)}" 
    iam_instance_profile = "CodeDeploy-Instance-Role" 
    # The name of our SSH keypair we created above. 
     key_name = "${aws_key_pair.auth.id}" 

     # Our Security group to allow HTTP and SSH access 
     vpc_security_group_ids = ["${aws_security_group.mongodb.id}"] 

     subnet_id = "${aws_subnet.default.id}" 
     provisioner "remote-exec" { 
      inline = [ 
        "sudo echo -ne '\n' | apt-key adv --keyserver 
         hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10", 
       "echo 'deb http://repo.mongodb.org/apt/ubuntu trusty/mongodb- 
        org/3.2 multiverse' | sudo tee /etc/apt/sources.list.d/mongodb-
         org-3.2.list", 
       "sudo apt-get update -y && sudo apt-get install mongodb-org --
       force-yes -y", 
       ] 
     } 
   } 

```

仍然需要配置的最后一个资源是弹性负载均衡器，它将平衡客户请求以提供高可用性。

# 配置弹性负载均衡器

首先，我们需要通过将以下代码添加到`main.tf`来为我们的 ELB 创建安全组资源：

```py
    # A security group for the ELB so it is accessible via the web 
     resource "aws_security_group" "elb" { 
     name        = "cna_sg_elb" 
     description = "Security_group_elb" 
     vpc_id      = "${aws_vpc.default.id}" 

    # HTTP access from anywhere 
    ingress { 
      from_port   = 5000 
      to_port     = 5000 
      protocol    = "tcp" 
      cidr_blocks = ["0.0.0.0/0"] 
     } 

    # outbound internet access 
    egress { 
      from_port   = 0 
      to_port     = 0 
      protocol    = "-1" 
      cidr_blocks = ["0.0.0.0/0"] 
     } 

```

现在，我们需要添加以下配置来创建 ELB 资源，并将应用服务器添加到其中：

```py
    resource "aws_elb" "web" { 
    name = "cna-elb" 

     subnets         = ["${aws_subnet.default.id}"] 
     security_groups = ["${aws_security_group.elb.id}"] 
     instances       = ["${aws_instance.web.*.id}"] 
     listener { 
       instance_port = 5000 
       instance_protocol = "http" 
       lb_port = 80 
       lb_protocol = "http" 
      } 
     } 

```

现在，我们已经准备好运行 Terraform 配置了。

我们的基础设施配置已准备就绪，可以部署了。使用以下命令来了解执行计划是一个很好的做法：

```py
$ terraform plan

```

最后一个命令的输出应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00167.jpeg)

如果您没有看到任何错误，您可以执行以下命令来实际创建资源：

```py
$ terraform apply

```

输出应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00168.jpeg)

目前，我们还没有与我们注册的域，但如果我们已经在 Route 53 中注册并配置了域名，我们需要在`main.tf`中创建一个额外的资源，为我们的应用添加一个条目。我们可以使用以下代码来实现：

```py
    resource "aws_route53_record" "www" { 
      zone_id = "${var.zone_id}" 
      name = "www.domain.com" 
      type = "A" 
      alias { 
       name = "${aws_elb.web.dns_name}" 
       zone_id = "${aws_elb.web.zone_id}" 
       evaluate_target_health = true 
      } 
    } 

```

这就是我们需要做的一切。另外，使您的基础设施高度可用的另一种快速且最关键的方法是创建一个基于服务器指标使用（CPU 或内存）的自动扩展服务。我们提供条件来决定是否需要扩展我们的基础设施，以便我们的应用性能应该看到更少的延迟。

为了做到这一点，您可以在[`www.terraform.io/docs/providers/aws/r/autoscaling_group.html`](https://www.terraform.io/docs/providers/aws/r/autoscaling_group.html)查看 Terraform 文档。

目前，我们的应用尚未部署，我们将使用 Code Deploy 服务使用持续交付来部署我们的应用，我们将在本章的后面部分讨论。

在此之前，让我们看看如何使用 AWS 提供的名为**CloudFormation**的云平台服务创建相同的设置。

# CloudFormation - 使用代码构建基础设施的 AWS 工具

CloudFormation 是 AWS 的一个服务，它的工作方式类似于 Terraform。但是，在 CloudFormation 中，我们不需要访问/秘钥。相反，我们需要创建一个 IAM 角色，该角色将具有启动所需的所有资源的访问权限，以构建我们的应用。

您可以使用 YAML 或 JSON 格式编写您的 CloudFormation 配置。

让我们通过使用 CloudFormation 开始我们的基础设施设置，构建 VPC，在那里我们将创建一个 VPC，一个公共子网和一个私有子网。

让我们创建一个新文件`vpc.template`，其中 VPC 和子网（公共和私有）的配置如下：

```py
"Resources" : { 

   "VPC" : { 
     "Type" : "AWS::EC2::VPC", 
     "Properties" : { 
       "CidrBlock" : "172.31.0.0/16", 
       "Tags" : [ 
         {"Key" : "Application", "Value" : { "Ref" : "AWS::StackName"} }, 
         {"Key" : "Network", "Value" : "Public" } 
       ] 
     } 
   }, 
"PublicSubnet" : { 
     "Type" : "AWS::EC2::Subnet", 
     "Properties" : { 
       "VpcId" : { "Ref" : "VPC" }, 
       "CidrBlock" : "172.31.16.0/20", 
       "AvailabilityZone" : { "Fn::Select": [ "0", {"Fn::GetAZs": {"Ref": "AWS::Region"}} ]}, 
       "Tags" : [ 
         {"Key" : "Application", "Value" : { "Ref" : "AWS::StackName"} }, 
         {"Key" : "Network", "Value" : "Public" } 
       ] 
     } 
   }, 
   "PrivateSubnet" : { 
     "Type" : "AWS::EC2::Subnet", 
     "Properties" : { 
       "VpcId" : { "Ref" : "VPC" }, 
       "CidrBlock" : "172.31.0.0/20", 
       "AvailabilityZone" : { "Fn::Select": [ "0", {"Fn::GetAZs": {"Ref": "AWS::Region"}} ]}, 
       "Tags" : [ 
         {"Key" : "Application", "Value" : { "Ref" : "AWS::StackName"} }, 
         {"Key" : "Network", "Value" : "Public" } 
       ] 
     } 
   }, 

```

上述配置是以 JSON 格式编写的，以便让您了解 JSON 配置。此外，我们还需要指定路由表和互联网网关的配置如下：

```py
"PublicRouteTable" : { 
     "Type" : "AWS::EC2::RouteTable", 
     "Properties" : { 
       "VpcId" : {"Ref" : "VPC"}, 
       "Tags" : [ 
         {"Key" : "Application", "Value" : { "Ref" : "AWS::StackName"} }, 
         {"Key" : "Network", "Value" : "Public" } 
       ] 
     } 
   }, 

   "PublicRoute" : { 
     "Type" : "AWS::EC2::Route", 
     "Properties" : { 
       "RouteTableId" : { "Ref" : "PublicRouteTable" }, 
       "DestinationCidrBlock" : "0.0.0.0/0", 
       "GatewayId" : { "Ref" : "InternetGateway" } 
     } 
   }, 

   "PublicSubnetRouteTableAssociation" : { 
     "Type" : "AWS::EC2::SubnetRouteTableAssociation", 
     "Properties" : { 
       "SubnetId" : { "Ref" : "PublicSubnet" }, 
       "RouteTableId" : { "Ref" : "PublicRouteTable" } 
     } 
   } 
 }, 

```

现在我们已经有了可用的配置，是时候从 AWS 控制台为 VPC 创建一个堆栈了。

# AWS 上的 VPC 堆栈

执行以下步骤，从 AWS 控制台为 VPC 创建一个堆栈：

1.  转到[`console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new`](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new)使用 CloudFormation 创建一个新的堆栈。您应该看到一个如此截图所示的屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00169.jpeg)

提供模板文件的路径，然后点击“下一步”按钮。

1.  在下一个窗口中，我们需要指定堆栈名称，这是我们堆栈的唯一标识符，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00170.jpeg)

提供堆栈名称，然后点击“下一步”。

1.  下一个屏幕是可选的；如果我们想设置**SNS**（**通知服务**）或为其添加 IAM 角色，我们需要在这里添加它：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00171.jpeg)

如果要启用通知和 IAM 角色，请添加详细信息，然后点击“下一步”。

1.  下一个屏幕是用于审查细节，并确保它们正确以创建堆栈：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00172.jpeg)

准备好后，点击“创建”来启动堆栈创建。在创建时，您可以检查事件以了解资源创建的状态。

您应该会看到一个类似于这样的屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00173.jpeg)

在前面的屏幕上，您将能够看到堆栈的进度，如果出现错误，您可以使用这些事件来识别它们。

一旦我们的 VPC 堆栈准备好，我们需要在我们的 VPC 中创建 EC2、ELB 和自动缩放资源。我们将使用 YAML 格式来为您提供如何以 YAML 格式编写配置的概述。

您可以在`<repository 路径>`找到完整的代码。我们将使用`main.yml`文件，其中包含有关您需要启动实例的 VPC 和子网的详细信息。

1.  为了启动堆栈，请转到以下链接：

[`console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new`](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new)

在启动配置中将会有一个变化--不再在文件中指定值，而是在提供细节的时候在 AWS 控制台中指定，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00174.jpeg)

1.  请参考以下截图，提供您想要部署应用程序的实例细节：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00175.jpeg)

1.  一旦您在上一个屏幕中提供了所有的细节，向下滚动到下一部分，在那里它将要求 ELB 的细节，如下一张截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00176.jpeg)

剩下的步骤对于创建 AWS CloudFormation 堆栈来说是一样的。为了添加 MongoDB 服务器，我们需要在`main.yml`中添加 EC2 机器的配置。

在 AWS CloudFormation 中创建配置是很简单的，因为 AWS 提供了一些模板，我们可以用作创建我们的模板的参考。以下是模板的链接：

[`aws.amazon.com/cloudformation/aws-cloudformation-templates/﻿`](https://aws.amazon.com/cloudformation/aws-cloudformation-templates/)

这就是我们为构建基础设施所做的一切；现在是我们的应用程序在应用服务器上部署的时候了。

# 云原生应用程序的持续部署

在前面的部分，我们成功地设置了基础设施，但我们还没有部署应用程序。此外，我们需要确保进一步的部署应该使用持续部署来处理。由于我们的开发环境在本地机器上，我们不需要设置持续集成周期。然而，对于许多开发人员协作工作的大型公司，我们需要使用 Jenkins 设置一个单独的持续集成管道。在我们的情况下，我们只需要持续部署。我们的持续部署管道将是这样的：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00177.jpeg)

# 它是如何工作的

它从开发人员将新代码推送到其版本控制系统的主分支开始（在我们的情况下，它是 GitHub）。一旦新代码被推送，Jenkins 的 GitHub 插件根据其定义的工作检测到更改，并触发 Jenkins 作业将新代码部署到其基础设施。然后 Jenkins 与 Code Deploy 通信，触发代码到 Amazon EC2 机器。由于我们需要确保我们的部署是成功的，我们可以设置一个通知部分，它将通知我们部署的状态，以便在需要时可以回滚。

# 持续部署管道的实施

让我们首先从配置 AWS 服务开始，从 Code Deploy 开始，这将帮助我们在可用的应用服务器上部署应用程序。

1.  最初，当您切换到代码部署服务时（[`us-west-1.console.aws.amazon.com/codedeploy/`](https://us-west-1.console.aws.amazon.com/codedeploy/)），您应该会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00178.jpeg)

前面的屏幕截图是 Code Deploy 的介绍页面，展示了其功能。

1.  点击页面中间的“立即开始”按钮以继续前进。

1.  接下来，您应该看到以下屏幕，该屏幕将建议您部署一个示例应用程序，这对于初始阶段来说是可以的。但是由于我们已经建立了基础设施，在这种情况下，我们需要选择自定义部署--这将跳过演练。因此，选择该选项，然后单击“下一步”。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00179.jpeg)

1.  点击“跳过演练”以继续前进。

1.  在下一个向导屏幕中，有几个需要审查的部分。

第一部分将要求您创建应用程序--您需要提供用户定义的应用程序名称和部署组名称，这是强制性的，因为它成为您的应用程序的标识符：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00180.jpeg)

1.  向下滚动到下一部分，该部分讨论您希望为应用程序选择的部署类型。有两种方法，定义如下：

+   **蓝/绿部署**：在这种类型中，在部署过程中，会启动新实例并向其部署新代码，如果其健康检查正常，则会替换为旧实例，然后旧实例将被终止。这适用于生产环境，客户无法承受停机时间。

+   **原地部署**：在这种部署类型中，新代码直接部署到现有实例中。在此部署中，每个实例都会脱机进行更新。

我们将选择**原地部署**，但选择会随着用例和产品所有者的决定而改变。例如，像 Uber 或 Facebook 这样的应用程序，在部署时无法承受停机时间，将选择蓝/绿部署，这将为它们提供高可用性。

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00181.jpeg)

1.  让我们继续下一节，讨论应用程序将要部署的基础设施。我们将指定实例和 ELB 的详细信息，如此屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00182.jpeg)

1.  在下一部分中，我们将定义部署应用程序的方式。例如，假设您有 10 个实例。您可能希望一次在所有这些实例上部署应用程序，或者一次一个，或者一次一半。我们将使用默认选项，即`CodeDeployDefault.OneAtATime`：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00183.jpeg)

在本节中，我们还需要指定一个服务角色，Code Deploy 需要该角色来在您的 AWS 资源上执行操作，更具体地说是在 EC2 和 ELB 上。

要了解更多有关服务角色创建的信息，请转到此链接的 AWS 文档：[`docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create.html`](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create.html)

1.  提供所需信息后，点击“创建应用程序”。

一旦您的应用程序准备就绪，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00184.jpeg)

现在我们已经准备好部署。我们只需要在 Jenkins 中创建一个作业，并添加一个带有 CodeDeploy 详细信息的后置构建部分。

作业的创建类似于我们在上一章中解释的内容。但是需要进行以下几个更改：

1.  首先，我们需要确保已安装了一些 Jenkins 插件，即 AWS CodeDeploy Plugin for Jenkins，Git 插件，GitHub 插件等。

1.  安装了插件后，您应该在后置构建操作列表中看到新的操作，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00185.jpeg)

1.  接下来，您需要选择“部署应用程序到 AWS CodeDeploy”操作。将添加一个新部分，我们需要提供在 AWS 控制台中创建的 CodeDeploy 应用程序的详细信息，如此屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-web-zh/raw/master/docs/cld-ntv-py/img/00186.jpeg)

1.  我们还需要提供在本章开头部分创建的访问/秘钥，即*生成认证密钥*。这是必要的，因为 Jenkins 在打包应用程序后需要将其上传到 S3，并指示 CodeDeploy 从指定的存储桶部署最新构建。

我们需要做的就是这些。现在我们的 Jenkins 作业已经准备好部署应用程序了。试一下，应该会像黄油一样顺利。

# 总结

这一章在各个方面都非常有趣。首先，你对 AWS 服务有了基本的了解，以及如何充分利用它们。接下来，我们探讨了我们在 AWS 云上应用程序的架构，这将塑造你对未来可能计划创建的不同应用程序/产品的架构设计的看法。我们还使用了 Terraform，这是一个第三方工具，用于将基础架构构建为 AWS 代码。最后，我们部署了我们的应用程序，并使用 Jenkins 创建了一个持续的部署流水线。在下一章中，我们将探索微软拥有的另一个云平台--Microsoft Azure。保持活力，准备好在接下来的章节中探索 Azure。到时见！
