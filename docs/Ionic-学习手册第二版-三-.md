# Ionic 学习手册第二版（三）

> 原文：[`zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60`](https://zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：构建 Riderr 应用程序

根据我们迄今所学的知识，我们将构建一个帮助用户预订行程的应用程序。该应用程序使用 Uber 提供的 API（[`uber.com/`](https://uber.com/)），这是一个流行的叫车服务提供商，并将其与 Ionic 应用程序集成。在这个应用程序中，我们将处理以下内容：

+   集成 Uber OAuth 2.0

+   集成 REST API

+   与设备功能交互

+   使用 Google API

+   最后，预订行程

本章的主要目的是展示如何同时使用 REST API 和设备功能，如地理位置和 InappBrowser，来使用 Ionic 构建真实世界的应用程序。

# 应用程序概述

我们将要构建的应用程序名为 Riderr。Riderr 帮助用户在两个地点之间预订出租车。该应用程序使用 Uber 提供的 API（[`uber.com/`](https://uber.com/)）来预订行程。在这个应用程序中，我们不会集成 Uber 的所有 API。我们将实现一些端点，显示用户的信息以及用户的行程信息，以及一些帮助我们预订行程、查看当前行程和取消行程的端点。

为了实现这一点，我们将使用 Uber 的 OAuth 来对用户进行认证，以便我们可以显示用户的信息并代表用户预订行程。

这是一个快速预览，一旦我们完成应用程序的构建，它将会是什么样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00094.jpeg)

注意：无论是图书出版公司还是我都不对由于使用 Uber 生产 API 而导致的金钱损失或账户禁止负责。请在使用 Uber 生产 API 之前仔细阅读 API 说明。

# Uber API

在这一部分，我们将介绍我们将在 Riderr 应用程序中使用的各种 API。我们还将生成一个客户端 ID、客户端密钥和服务器令牌，我们将在发出请求时使用。

# 认证

访问 Uber API 有三种认证机制：

+   服务器令牌

+   单点登录（SSO）

+   OAuth 2.0

为了代表用户发出请求、访问用户的个人信息并代表用户预订行程，我们需要一个 OAuth 2.0 访问令牌。因此，我们将遵循 OAuth 2.0 机制。

如果您对 OAuth 2.0 机制不熟悉，请参阅[`www.bubblecode.net/en/2016/01/22/understanding-oauth2/`](http://www.bubblecode.net/en/2016/01/22/understanding-oauth2/)或[`www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2`](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2)。

# 在 Uber 注册

在我们进一步进行之前，我们需要一个 Uber 账户来登录并在 Uber 注册一个新的应用程序。如果您没有账户，您可以使用 Uber 应用程序很容易地创建一个。

一旦您创建了 Uber 账户，导航至[`developer.uber.com/dashboard/create`](https://developer.uber.com/dashboard/create)，登录并填写以下表格：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00095.jpeg)

然后点击创建。这将在 Uber 注册一个新的应用程序，并为该应用程序创建一个客户端 ID、客户端密钥和服务器令牌。接下来，在同一页面上点击授权选项卡（我们在那里找到客户端 ID）。将重定向 URL 更新为`http://localhost/callback`。这非常重要。如果我们不这样做，Uber 就不知道在认证后将用户发送到哪里。

使用客户端 ID 和客户端密钥的组合，我们请求访问令牌。然后，使用这个访问令牌，我们将代表用户访问 Uber 资源。

为了进一步进行，您需要对 OAuth 2.0 有一个相当好的理解，因为我们将在我们的应用程序中实现它。

# API

在这个应用程序中，我们将从 Uber 使用以下 API：

+   `/authorize`：[`developer.uber.com/docs/riders/references/api/v2/authorize-get`](https://developer.uber.com/docs/riders/references/api/v2/authorize-get)。此端点允许应用将用户重定向到授权页面。当我们开始使用应用时，我们将深入研究此端点。

+   `/token`：此端点使用`/authorize`端点返回的代码，并请求访问令牌。然后使用此令牌进行进一步的请求。API 文档：[`developer.uber.com/docs/riders/references/api/v2/token-post`](https://developer.uber.com/docs/riders/references/api/v2/token-post)。

+   `/me`：此端点返回用户信息，以访问令牌作为输入。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/me-get`](https://developer.uber.com/docs/riders/references/api/v1.2/me-get)。

+   `/history`：此端点返回用户的 Uber 乘车历史。此端点需要特殊权限（特权范围）。但是，对于我们的示例，由于这是一个开发应用程序，我们将使用具有完全访问权限范围的此端点。但是，如果您想要对应用程序进行生产部署，请参考[`developer.uber.com/docs/riders/guides/scopes`](https://developer.uber.com/docs/riders/guides/scopes)获取更多信息。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/history-get`](https://developer.uber.com/docs/riders/references/api/v1.2/history-get)。

+   `/payment-methods`：此端点返回用户可用的付款选项。此端点还需要特权范围。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/payment-methods-get`](https://developer.uber.com/docs/riders/references/api/v1.2/payment-methods-get)。

+   `/products`：此端点返回在特定位置支持的产品列表。在我所居住的地方 - 印度海得拉巴 - Uber 提供 Uber Pool，Uber Go，Uber X 和 Uber SUV。这些在城市内的不同地方也有所不同。在城市的某些地方，我还可以使用 Uber Moto。使用此端点，我们将获取在特定位置支持的产品。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/products-get`](https://developer.uber.com/docs/riders/references/api/v1.2/products-get)。

+   `/request/estimate`：在我们请求乘车之前，我们需要从 Uber 获取车费估算。如果用户对车费估算满意，我们将发出实际请求。此端点接受所需信息，并返回车费对象。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/requests-estimate-post`](https://developer.uber.com/docs/riders/references/api/v1.2/requests-estimate-post)。

+   `/requests`：此端点接受车费 ID，产品 ID，出发地点和目的地点，并预订乘车。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/requests-post`](https://developer.uber.com/docs/riders/references/api/v1.2/requests-post)。

+   `/requests/current`：如果有的话，此端点将返回当前乘车的详细信息。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/requests-current-get`](https://developer.uber.com/docs/riders/references/api/v1.2/requests-current-get)。

+   `/requests/current`：如果有的话，此端点将取消/删除当前的乘车。API 文档：[`developer.uber.com/docs/riders/references/api/v1.2/requests-current-delete`](https://developer.uber.com/docs/riders/references/api/v1.2/requests-current-delete)。

注意：您可以参考[`developer.uber.com/docs/riders/introduction`](https://developer.uber.com/docs/riders/introduction)获取其他可用的 API。

# 构建 Riderr

现在我们已经了解了 API 列表，我们将开始使用 Ionic 应用程序。

# 应用程序的脚手架

本章的下一步是搭建一个新的 Ionic 空白应用程序，并开始集成 Uber API。

创建一个名为`chapter7`的新文件夹，在`chapter7`文件夹内打开一个新的命令提示符/终端，并运行以下命令：

```html
ionic start -a "Riderr" -i app.example.riderr riderr blank --v2

```

这将为我们搭建一个新的空白项目。

# Uber API 服务

在本节中，我们将开始使用与 Uber API 接口的服务层进行工作。我们将在 Ionic 应用程序内实现上述端点。

应用程序搭建完成后，进入`src`文件夹并创建一个名为`services`的新文件夹。在`services`文件夹内，创建一个名为`uber.service.ts`的文件。我们将在这里编写所有 Uber 集成逻辑。

在您喜欢的文本编辑器中打开`riderr`项目，并导航到`riderr/src/services/uber.service.ts`。我们要做的第一件事是添加所需的导入。将以下内容添加到`uber.services.ts`文件的顶部：

```html
import { Injectable } from '@angular/core'; 
import { LoadingController } from 'ionic-angular'; 
import { Http, Headers, Response, RequestOptions } from '@angular/http'; 
import { InAppBrowser } from '@ionic-native/in-app-browser'; 
import { Storage } from '@ionic/storage'; 
import { Observable } from 'rxjs/Observable';

```

我们已经包括

+   `Injectable`：将当前类标记为提供程序

+   `LoadingController`：在进行网络请求时显示消息；`Http`，`Headers`，`Response`和`RequestOptions`用于处理`http`请求

+   `InAppBrowser`：实现 OAuth 2.0 而不使用服务器获取访问令牌

+   `存储`：用于存储访问令牌

+   `Observable`：用于更好地处理异步请求

接下来，我们将定义类和类级变量：

```html
@Injectable() 
export class UberAPI { 
  private client_secret: string = 'igVTjJAByDAVfKYgaNGX1MgvoWNmsuTI_OYJz7eq'; 
  private client_id: string = '9i2dK88Ovw0WvH3wmS-H0JA6ZF5Z2GP1'; 
  private redirect_uri: string = 'http://localhost/callback'; 
  private scopes: string = 'profile history places request'; 
  // we will be using the sandbox URL for our app 
  private UBERSANDBOXAPIURL = 'https://sandbox-api.uber.com/v1.2/'; 
  // private UBERAPIURL = 'https://api.uber.com/v1.2/'; 
  private TOKENKEY = 'token'; // name of the key in storage 
  private loader; // reference to the loader 
  private token; // copy of token in memory 
}

client_secret and client_id from the new app you have registered with Uber. Do notice the scopes variable. It is here that we are requesting permission to access privileged content from Uber on the user's behalf.
```

注意：完成此示例后，我将删除前面注册的应用程序。因此，请确保您拥有自己的`client_secret`和`client_id`。

接下来是构造函数：

```html
//snipp -> Inside the class 
    constructor(private http: Http, 
    private storage: Storage, 
    private loadingCtrl: LoadingController, 
    private inAppBrowser: InAppBrowser) { 
      // fetch the token on load 
      this.storage.get(this.TOKENKEY).then((token) => { 
        this.token = token; 
      }); 
    }

```

在`constructor`中，我们已经实例化了`Http`，`Storage`和`LoadingController`类，我们还从内存中获取访问令牌并将其保存在内存中以供将来使用。

对于我们向 Uber API 发出的每个请求（除了认证请求），我们需要将访问令牌作为标头的一部分发送。我们有以下方法将帮助我们完成这一点：

```html
// snipp 
  private createAuthorizationHeader(headers: Headers) { 
    headers.append('Authorization', 'Bearer ' + this.token); 
    headers.append('Accept-Language', 'en_US'); 
    headers.append('Content-Type', 'application/json'); 
  }

```

接下来，我们需要一个方法，返回一个布尔值，指示用户是否已经认证并且我们有一个令牌可以向 Uber API 发出请求：

```html
// snipp 
  isAuthenticated(): Observable<boolean> { 
    this.showLoader('Autenticating...'); 
    return new Observable<boolean>((observer) => { 
      this.storage.ready().then(() => { 
        this.storage.get(this.TOKENKEY).then((token) => { 
          observer.next(!!token); // !! -> converts truthy falsy to 
          boolean. 
          observer.complete(); 
          this.hideLoader(); 
        }); 
      }); 
    }); 
  }

```

此方法将查询存储中是否存在令牌。如果令牌存在，`observer`返回`true`，否则返回`false`。我们将在所有 API 的末尾实现`showLoader()`和`hideLoader()`。

如果用户已经认证，用户已登录。这意味着我们需要一个选项，用户退出登录。由于 API 服务器是无状态的，它不维护任何会话信息以使其失效。因此，通过从存储中清除令牌，我们使客户端端的会话失效：

```html
// snipp 
  logout(): Observable<boolean> { 
    return new Observable<boolean>((observer) => { 
      this.storage.ready().then(() => { 
        this.storage.set(this.TOKENKEY, undefined); 
        this.token = undefined; 
        observer.next(true); 
        observer.complete(); 
      }); 
    }); 
  }

```

现在我们将编写我们的第一个与 Uber API 交互的 API 方法。这是认证方法：

```html
// snipp 
auth(): Observable<boolean> { 
    return new Observable<boolean>(observer => { 
      this.storage.ready().then(() => { 
        let browser = 
        this.inAppBrowser.create
        (`https://login.uber.com/oauth/v2/authorize?           
        client_id=${this.client_id}&
        response_type=code&scope=${this.scopes}
        &redirect_uri=${this.redirect_uri}`, '_blank',  
        'location=no,clearsessioncache=yes,clearcache=yes'); 
        browser.on('loadstart').subscribe((event) => { 
          let url = event.url; 

          // console.log(url); 
          // URLS that get fired 

          // 1\. https://login.uber.com/oauth/v2/authorize?
          client_id=9i2dK88Ovw0WvH3wmS-
          H0JA6ZF5Z2GP1&response_type=
          code&scope=profile%20history%20places%20request

          // 2\. https://auth.uber.com/login/? 
          next_url=https%3A%2F%2Flogin.uber.com
          %2Foauth%...520places%2520request
          &state=Pa2ONzlEGsB4M41VLKOosWTlj9snJqJREyCFrEhfjx0%3D 

          // 3\. https://login.uber.com/oauth/v2/authorize?
          client_id=9i2dK88Ovw0WvH3wmS-
          H0JA...ry%20places%20request&
          state=Pa2ONzlEGsB4M41VLKOosWTlj9snJqJREyCFrEhfjx0%3D 

          // 4\. http://localhost/callback?state=
          Pa2ONzlEGsB4M41VLKOosWTlj9snJqJREyCFrEhfjx0%3D&
          code=9Xu6ueaNhUN1uZVvqvKyaXPhMj8Bzb#_ 

          // we are interested in #4 
          if (url.indexOf(this.redirect_uri) === 0) { 
            browser.close(); 
            let resp = (url).split("?")[1]; 
            let responseParameters = resp.split("&"); 
            var parameterMap: any = {}; 

            for (var i = 0; i < responseParameters.length; i++) { 
              parameterMap[responseParameters[i].split("=")[0]] = 
              responseParameters[i].split("=")[1]; 
            } 

            // console.log('parameterMap', parameterMap); 
            /* 
              { 
                "state": 
                "W9Ytf2cicTMPMpMgwh9HfojKv7gQxxhrcOgwffqdrUM%3D", 
                "code": "HgSjzZHfF4GaG6x1vzS3D96kGtJFNB#_" 
              } 
            */ 

            let headers = new Headers({ 
              'Content-Type': "application/x-www-form-urlencoded" 
            }); 
            let options = new RequestOptions({ headers: headers }); 
            let data = 
            `client_secret=${this.client_secret}
            &client_id=${this.client_id}&grant_type=
            authorization_code&redirect_uri=
            ${this.redirect_uri}&code=${parameterMap.code}`; 

            return 
            this.http.post
            ('https://login.uber.com/oauth/v2/token', data, options) 
              .subscribe((data) => { 
                let respJson: any = data.json(); 
                // console.log('respJson', respJson); 
                /* 
                  { 
                    "last_authenticated": 0, 
                    "access_token": "snipp", 
                    "expires_in": 2592000, 
                    "token_type": "Bearer", 
                    "scope": "profile history places request", 
                    "refresh_token": "26pgA43ZvQkxEQi7qYjMASjfq6lg8F" 
                  } 
                */ 

                this.storage.set(this.TOKENKEY, respJson.access_token); 
                this.token = respJson.access_token; // load it up in 
                memory 
                observer.next(true); 
                observer.complete(); 
              }); 
          } 
        }); 
      }); 
    }); 
  }

```

在这种方法中发生了很多事情。我们使用 Ionic Native 的 InAppBrowser（[`ionicframework.com/docs/native/in-app-browser/`](https://ionicframework.com/docs/native/in-app-browser/)）插件将用户重定向到授权端点。授权端点（`https://login.uber.com/oauth/v2/authorize?client_id=${this.client_id}&response_type=code&scope=${this.scopes}&redirect_uri=${this.redirect_uri}`）需要客户端 ID，范围和重定向 URL。

`redirect_uri`是一个重要的参数，因为 Uber API 在认证后将应用程序重定向到该 URL。在我们的应用程序内部，我们通过`browser.on('loadstart')`监听 URL 更改事件。我们正在寻找以`http://localhost/callback`开头的 URL。如果匹配此 URL，我们将关闭浏览器并从 URL 中提取代码。

一旦我们获得代码，我们需要交换相同的代码以获得访问令牌。这将是`auth()`的下一部分，通过传递`client_secret`，`client_id`，`redirect_uri`和`code`从`https://login.uber.com/oauth/v2/token`获取令牌。一旦我们收到访问令牌，我们将其保存到存储中。

注意：要了解更多关于存储的信息，请参考[`ionicframework.com/docs/storage/`](https://ionicframework.com/docs/storage)或*第四章*中的*存储服务*部分。

现在我们有了访问令牌，我们将向 Uber API 发出请求以获取、发布和删除数据。

我们要实现的第一个 API 方法将用于获取用户的信息：

```html
// snipp 
  getMe(): Observable<Response> { 
    this.showLoader(); 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.get(this.UBERSANDBOXAPIURL + 'me', { 
      headers: headers 
    }); 
  }

```

请注意，我正在向 Uber Sandbox API URL 发出 API 请求，而不是向生产服务发出请求。在您对实施有信心之前，这总是一个好主意。Uber Sandbox API 和 Uber API 具有非常相似的实施，除了沙箱环境中的数据不是实时的，它遵循与 Uber API 相同的规则。在生产环境中，请记住更新 API 基础。

接下来是历史 API：

```html
// snipp 
  getHistory(): Observable<Response> { 
    this.showLoader(); 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.get(this.UBERSANDBOXAPIURL + 'history', { 
      headers: headers 
    }); 
  }

```

标头将传递给每个需要访问令牌来处理请求的请求。

接下来是支付方式端点：

```html
// snipp 
  getPaymentMethods(): Observable<Response> { 
    this.showLoader(); 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.get(this.UBERSANDBOXAPIURL + 'payment-methods', { 
      headers: headers 
    }); 
  }

```

前面三个端点将返回用户和用户乘车信息。下一个端点将返回在给定位置支持的产品列表：

```html
// snipp 
  getProducts(lat: Number, lon: Number): Observable<Response> { 
    this.showLoader(); 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.get(this.UBERSANDBOXAPIURL + 'products?latitude=' 
    + lat + '&longitude=' + lon, { 
      headers: headers 
    }); 
  }

```

此方法将用于显示可用的产品或乘车类型的列表。

在实际预订行程之前，我们需要先获取费用估算。我们将使用`requestRideEstimates()`方法来实现这一点：

```html
//snipp 
  requestRideEstimates(start_lat: Number, end_lat: Number, start_lon: Number, end_lon: Number): Observable<Response> { 
    this.showLoader(); 
    // before booking 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.post(this.UBERSANDBOXAPIURL + 'requests/estimate', { 
      "start_latitude": start_lat, 
      "start_longitude": start_lon, 
      "end_latitude": end_lat, 
      "end_longitude": end_lon 
    }, { headers: headers }); 
  }

```

一旦我们获得了费用估算并且用户接受了它，我们将使用`requestRide()`发起预订请求：

```html
// snipp 
  requestRide(product_id: String, fare_id: String, start_lat: Number, end_lat: Number, start_lon: Number, end_lon: Number): Observable<Response> { 
    this.showLoader(); 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.post(this.UBERSANDBOXAPIURL + 'requests', { 
      "product_id": product_id, 
      "fare_id": fare_id, 
      "start_latitude": start_lat, 
      "start_longitude": start_lon, 
      "end_latitude": end_lat, 
      "end_longitude": end_lon 
    }, { headers: headers }); 
  }

```

该方法返回预订的状态。在沙箱环境中，不会预订乘车。如果您真的想要预订实际的乘车，您可以更改 API URL 并发起实际的预订。请记住，Uber 司机将真正给您打电话来接您。如果您取消乘车，将收取适当的取消费用。

注意：图书出版公司和我都不对由 Uber 导致的金钱损失或帐户禁止负责。在使用 Uber 生产 API 之前，请仔细阅读 API 说明。

由于 Uber 只允许从一个帐户一次预订一次乘车，我们可以使用`getCurrentRides()`来获取当前乘车信息：

```html
//snipp 
  getCurrentRides(lat: Number, lon: Number): Observable<Response> { 
    this.showLoader(); 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.get(this.UBERSANDBOXAPIURL + 'requests/current', { 
      headers: headers 
    }); 
  }

```

最后，要取消乘车，我们将使用`cancelCurrentRide()`发出删除请求：

```html
// snipp 
  cancelCurrentRide(): Observable<Response> { 
    this.showLoader(); 
    let headers = new Headers(); 
    this.createAuthorizationHeader(headers); 
    return this.http.delete(this.UBERSANDBOXAPIURL + 
    'requests/current', { 
      headers: headers 
    }); 
  }

```

显示和隐藏处理加载程序的两个实用方法如下：

```html
// snipp 
private showLoader(text?: string) { 
    this.loader = this.loadingCtrl.create({ 
      content: text || 'Loading...' 
    }); 
    this.loader.present(); 
  } 

  public hideLoader() { 
    this.loader.dismiss(); 
  }

```

有了这个，我们已经添加了所有我们将用来与 Uber API 交互的必需 API。

# 集成

现在我们已经有了所需的 API 服务，我们将创建所需的视图来表示这些数据。

当我们搭建应用程序时，将为我们创建一个名为`home`的页面。但是，由于在我们的应用程序中，一切都从认证开始，我们将首先生成一个登录页面。然后我们将使其成为应用程序的第一个页面。要生成一个新页面，请运行以下命令：

```html
ionic generate page login

```

接下来，我们需要更新`riderr/src/app/app.module.ts`中的页面引用。按照所示更新`@NgModule`。

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 
import { LoginPage } from '../pages/login/login'; 

import { UberAPI } from '../services/uber.service'; 
import { IonicStorageModule } from '@ionic/storage'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
    LoginPage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp), 
    IonicStorageModule.forRoot() 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage, 
    LoginPage 
  ], 
  providers: [{ provide: ErrorHandler, useClass: IonicErrorHandler }, 
      UberAPI, 
    StatusBar, 
    SplashScreen, 
  ] 
}) 
export class AppModule { }

```

随着我们的进展，我们将生成并添加剩余的页面。

注意：随着 Ionic 不断发展，页面的类名和结构可能会发生变化。但在 Ionic 中开发应用程序的要点将保持不变。

接下来，我们将更新`app.component.ts`以加载登录页面作为第一个页面。按照所示更新`riderr/src/app/app.component.ts`。

```html
import { Component } from '@angular/core'; 
import { Platform } from 'ionic-angular'; 
import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 

import { LoginPage } from '../pages/login/login'; 

@Component({ 
  templateUrl: 'app.html' 
}) 
export class MyApp { 
  rootPage = LoginPage; 

  constructor(platform: Platform, statusBar: StatusBar, splashScreen: SplashScreen) { 
    platform.ready().then(() => { 
      statusBar.styleDefault(); 
      splashScreen.hide(); 
    }); 
  }

```

现在我们将更新`LoginPage`组件。首先是`login.html`页面。按照所示更新`riderr2/src/pages/login/login.html`。

```html
<ion-content padding text-center> 
  <img src="img/logo.png" alt="Riderr Logo"> 
  <h2>Welcome to The Riderr App</h2> 
  <h3>This app uses Uber APIs to help you book a cab</h3> 
  <br><br><br> 
    <button ion-button color="primary" full (click)="auth()">Login with Uber</button> 
</ion-content>

```

您可以在这里找到`logo.png`：[`www.dropbox.com/s/8tdfgizjm24l3nx/logo.png?dl=0`](https://www.dropbox.com/s/8tdfgizjm24l3nx/logo.png?dl=0)。下载后，将图像移动到`assets/icon`文件夹中。

接下来，按照所示更新`riderr/src/pages/login/login.ts`。

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 
import { UberAPI } from '../../services/uber.service'; 
import { HomePage } from '../home/home'; 

@Component({ 
  selector: 'page-login', 
  templateUrl: 'login.html' 
}) 
export class LoginPage { 

  constructor(private api: UberAPI, private navCtrl: NavController) { 
    // check if the user is already authenticated 
    this.api.isAuthenticated().subscribe((isAuth) => { 
      if (isAuth) { 
        this.navCtrl.setRoot(HomePage); 
      } 
      // else relax! 
    }); 
  } 

  auth() { 
    this.api.auth().subscribe((isAuthSuccess) => { 
      this.navCtrl.setRoot(HomePage); 
    }, function(e) { 
      // handle this in a user friendly way. 
      console.log('Fail!!', e); 
    }); 
  } 
}

```

在上述代码中，我们包括了所需的依赖项。在构造函数中，我们使用`UberAPI`类中创建的`isAuthenticated()`来检查用户是否已经验证。如果用户点击了 Uber 登录按钮，我们调用`auth()`，这将调用`UberAPI`类的`auth()`。

如果用户成功验证，我们将用户重定向到“主页”。否则我们什么也不做。

假设用户已成功验证，用户将被重定向到主页。我们将基于主页的侧边菜单进行操作。侧边菜单将包含导航到应用程序中各种页面的链接。

我们将更新`riderr/src/pages/home/home.html`如下所示：

```html
<ion-menu [content]="content" (ionClose)="ionClosed()" (ionOpen)="ionOpened()"> 
    <ion-header> 
        <ion-toolbar> 
            <ion-title>Menu</ion-title> 
        </ion-toolbar> 
    </ion-header> 
    <ion-content> 
        <ion-list> 
            <button ion-item menuClose 
            (click)="openPage(bookRidePage)"> 
                Book Ride 
            </button> 
            <button ion-item menuClose (click)="openPage(profilePage)"> 
                Profile 
            </button> 
            <button ion-item menuClose (click)="openPage(historyPage)"> 
                Rides 
            </button> 
            <button ion-item menuClose 
            (click)="openPage(paymentMethodsPage)"> 
                Payment Methods 
            </button> 
            <button ion-item menuClose (click)="logout()"> 
                Logout 
            </button> 
        </ion-list> 
    </ion-content> 
</ion-menu> 
<ion-nav #content [root]="rootPage" swipeBackEnabled="false"></ion-nav>

```

上述代码是不言自明的。要了解有关菜单的更多信息，请参阅[`ionicframework.com/docs/api/components/menu/Menu/`](https://ionicframework.com/docs/api/components/menu/Menu/)。

接下来，我们将更新`HomePage`类。如下所示更新`riderr2/src/pages/home/home.ts`：

```html
import { Component } from '@angular/core'; 
import { BookRidePage } from '../book-ride/book-ride'; 
import { ProfilePage } from '../profile/profile'; 
import { HistoryPage } from '../history/history'; 
import { PaymentMethodsPage } from '../payment-methods/payment-methods'; 
import { LoginPage } from '../login/login'; 
import { UberAPI } from '../../services/uber.service'; 
import { NavController, Events } from 'ionic-angular'; 
import { ViewChild } from '@angular/core'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 

  private rootPage; 
  private bookRidePage; 
  private profilePage; 
  private historyPage; 
  private paymentMethodsPage; 

  @ViewChild(BookRidePage) bookRide : BookRidePage; 

  constructor(private uberApi: UberAPI, 
    private navCtrl: NavController, 
    public events: Events) { 
    this.rootPage = BookRidePage; 

    this.bookRidePage = BookRidePage; 
    this.profilePage = ProfilePage; 
    this.historyPage = HistoryPage; 
    this.paymentMethodsPage = PaymentMethodsPage; 
  } 

  // http://stackoverflow.com/a/38760731/1015046 
  ionOpened() { 
    this.events.publish('menu:opened', ''); 
  } 

  ionClosed() { 
    this.events.publish('menu:closed', ''); 
  } 

  ngAfterViewInit() { 
    this.uberApi.isAuthenticated().subscribe((isAuth) => { 
      if (!isAuth) { 
        this.navCtrl.setRoot(LoginPage); 
        return; 
      } 
    }); 
  } 

  openPage(p) { 
    this.rootPage = p; 
  } 

  logout(){ 
    this.uberApi.logout().subscribe(() => { 
      this.navCtrl.setRoot(LoginPage); 
    }); 
  } 
}

```

在这里，我们已经导入了所需的类。我们将在接下来的几个步骤中生成缺失的页面。请注意`@ViewChild()`装饰器。当我们使用谷歌地图时，我们将通过它和`ionOpened()`和`ionClosed()`进行操作。

视图初始化后，我们检查用户是否已经验证。如果没有，我们将用户重定向到登录页面。`openPage()`将根页面设置为菜单中选择的页面。`logout()`清除令牌并将用户重定向到登录页面。

现在我们将创建所需的页面。

首先，大部分操作发生的页面 - `bookRide`页面。运行以下命令：

```html
ionic generate page bookRide

```

这将生成一个新页面。页面创建后，打开`riderr/src/app/app.module.ts`并将`BookRidePage`添加到`@NgModule()`的`declarations`和`entryComponents`属性中。

`BookRidePage`是整个应用程序中最复杂的页面之一。首先，我们显示一个带有用户当前位置的谷歌地图。我们获取用户当前位置的可用产品并显示它们。

在我们进一步进行之前，我需要提到一个奇怪的 bug，当在 Ionic 应用程序中使用谷歌地图和地图上的点击事件时会发生。

在谷歌地图上，我们显示一个标记和一个带有用户当前位置的信息窗口。单击标记或信息窗口将重定向用户以设置目的地位置以预订乘车。为此，我们需要监听地图上的点击事件。当在非谷歌地图组件上工作时，如侧边菜单、警报等，这会导致问题。您可以在此处阅读有关该问题的更多信息：[`github.com/driftyco/ionic/issues/9942#issuecomment-280941997`](https://github.com/driftyco/ionic/issues/9942#issuecomment-280941997)。

因此，为了解决这个 bug，除了谷歌地图组件之外的任何点击交互，我们需要禁用谷歌地图上的点击监听器，一旦完成，我们需要重新启用它。

回到`riderr/src/pages/home/home.ts`中的`ionOpened()`和`ionClosed()`，每当菜单打开或关闭时，我们都会从中触发自定义事件。这样，当菜单打开时，我们会禁用地图上的点击监听器，并在用户选择菜单项后启用点击监听器。在`ionOpened()`和`ionClosed()`中，我们只触发了事件。我们将在`riderr/src/pages/book-ride/book-ride.ts`中处理相同的问题。

现在我们已经意识到了问题，我们可以进一步进行。我们将首先实现菜单和地图 HTML。更新`riderr/src/pages/book-ride/book-ride.html`如下所示：

```html
<ion-header> 
    <ion-navbar> 
        <button ion-button menuToggle> 
            <ion-icon name="menu"></ion-icon> 
        </button> 
        <ion-title>Riderr</ion-title> 
        <ion-buttons end> 
            <button *ngIf="isRideinProgress" ion-button color="danger" 
            (click)="cancelRide()"> 
                Cancel Ride 
            </button> 
        </ion-buttons> 
    </ion-navbar> 
</ion-header> 
<ion-content> 
    <div #map id="map"></div> 
    <div class="prods-wrapper"> 
        <div *ngIf="!isRideinProgress"> 
            <h3 *ngIf="!products">Fetching Products</h3> 
            <ion-grid *ngIf="products"> 
                <ion-row> 
                    <ion-col *ngFor="let p of products" [ngClass]="
                    {'selected' : p.isSelected}"> 
                        <div class="br" (click)="productClick(p)"> 
                            <h3>{{p.display_name.replace('uber', '')}}
                            </h3> 
                        </div> 
                    </ion-col> 
                </ion-row> 
            </ion-grid> 
        </div> 
        <div *ngIf="isRideinProgress"> 
            <h3 text-center>Ride In Progress</h3> 
            <p text-center>Ideally the ride information would be 
            displayed here.</p> 
        </div> 
    </div> 
</ion-content>

```

在页眉中，我们有一个取消进行中乘车的按钮。我们将填充`BookRidePage`类中的`isRideinProgress`属性，该属性管理此处显示的页面状态。`ion-grid`组件显示了当前用户位置支持的产品列表。

还要注意，我们已经添加了`<div #map id="map"></div>`。这将是地图出现的地方。

为了清理 UI，我们将添加一些样式。按照以下方式更新`riderr/src/pages/book-ride/book-ride.scss`：

```html
page-book-ride { 
    #map { 
        height: 88%; 
    } 
    .prods-wrapper { 
        height: 12%; 
    } 
    .br { 
        padding: 3px; 
        text-align: center; 
    } 
    ion-col.selected { 
        color: #eee; 
        background: #333; 
    } 
    ion-col { 
        background: #eee; 
        color: #333; 
        border: 1px solid #ccc; 
    } 
    ion-col:last-child .br { 
        border: none; 
    } 
}

```

接下来，我们将更新`BookRidePage`类。有很多方法，所以我将按照执行顺序分几部分分享它们。

在`riderr/src/pages/book-ride/book-ride.ts`中，我们将首先更新所需的导入：

```html
import { Component } from '@angular/core'; 
import { UberAPI } from '../../services/uber.service'; 
import { 
  Platform, 
  NavController, 
  AlertController, 
  ModalController, 
  Events 
} from 'ionic-angular'; 
import { Diagnostic } from '@ionic-native/diagnostic'; 
import { Geolocation } from '@ionic-native/geolocation'; 
import { 
  GoogleMaps, 
  GoogleMap, 
  GoogleMapsEvent, 
  LatLng, 
  CameraPosition, 
  MarkerOptions, 
  Marker 
} from '@ionic-native/google-maps';  
import { AutocompletePage } from '../auto-complete/auto-complete';

```

`@Component`装饰器将保持不变。

接下来，我们将声明一些类级别的变量：

```html
// snipp 
  private map: GoogleMap; 
  private products; 
  private fromGeo; 
  private toGeo; 
  private selectedProduct; 
  private isRideinProgress: boolean = false; 
  private currentRideInfo; 

```

然后定义构造函数：

```html
  // snipp 
constructor(private uberApi: UberAPI, 
    private platform: Platform, 
    private navCtrl: NavController, 
    private alertCtrl: AlertController, 
    private modalCtrl: ModalController, 
    private diagnostic: Diagnostic, 
    private geoLocation: Geolocation, 
    private googleMaps: GoogleMap, 
    public events: Events) { }

```

一旦视图被初始化，使用`ngAfterViewInit()`钩子，我们将开始获取用户的地理位置：

```html
// snipp 
ngAfterViewInit() { 
    //https://github.com/mapsplugin/cordova-plugin-googlemaps/issues/1140 
    this.platform.ready().then(() => { 
      this.requestPerms(); 

      //https://github.com/driftyco/ionic/issues/9942#issuecomment-
      280941997 
      this.events.subscribe('menu:opened', () => { 
        this.map.setClickable(false); 
      }); 
      this.events.subscribe('menu:closed', () => { 
        this.map.setClickable(true); 
      }); 
    }); 
  }

```

但在获取地理位置之前，我们需要请求用户允许我们访问位置服务。

还要注意为`menu:opened`和`menu:closed`事件实现的监听器。这是我们如何根据侧边菜单的状态禁用地图上的点击并重新启用它。继续我们的开发：

```html
// snipp 
private requestPerms() { 
    let that = this; 
    function success(statuses) { 
      for (var permission in statuses) { 
        switch (statuses[permission]) { 
          case that.diagnostic.permissionStatus.GRANTED: 
            // console.log("Permission granted to use " + permission); 
            that.fetCords(); 
            break; 
          case that.diagnostic.permissionStatus.NOT_REQUESTED: 
            console.log("Permission to use " + permission + " has not 
            been requested yet"); 
            break; 
          case that.diagnostic.permissionStatus.DENIED: 
            console.log("Permission denied to use " + permission + " - 
            ask again?"); 
            break; 
          case that.diagnostic.permissionStatus.DENIED_ALWAYS: 
            console.log("Permission permanently denied to use " + 
            permission + " - guess we won't be using it then!"); 
            break; 
        } 
      } 
    } 

    function error(e) { 
      console.log(e); 
    } 

    this.diagnostic.requestRuntimePermissions([ 
      that.diagnostic.permission.ACCESS_FINE_LOCATION, 
      that.diagnostic.permission.ACCESS_COARSE_LOCATION 
    ]).then(success).catch(error); 
  }

```

使用来自`@ionic-native`/`diagnostic`的 Diagnostic 插件，我们请求运行时权限。这将显示一个弹出窗口，询问用户是否应用程序可以访问用户的地理位置。如果用户允许应用程序，我们将在成功回调中收到`Diagnostic.permissionStatus.GRANTED`状态。然后，我们将尝试获取用户的坐标。如果需要，其他情况可以得到优雅的处理：

```html
// snipp 
  private isExecuted = false; 
  private fetCords() { 
    // this needs to be called only once 
    // since we are requesting 2 permission 
    // this will be called twice. 
    // hence the isExecuted 
    if (this.isExecuted) return; 
    this.isExecuted = true; 
    // maps api key : AzaSyCZhTJB1kFAP70RuwDts6uso9e3DCLdRWs 
    // ionic plugin add cordova-plugin-googlemaps --variable 
    API_KEY_FOR_ANDROID="AzaSyCZhTJB1kFAP70RuwDts6uso9e3DCLdRWs" 
    this.geoLocation.getCurrentPosition().then((resp) => { 
      // resp.coords.latitude 
      // resp.coords.longitude 
      // console.log(resp); 
      this.fromGeo = resp.coords; 
      // Get the products at this location 
      this.uberApi.getProducts(this.fromGeo.latitude, 
      this.fromGeo.longitude).subscribe((data) => { 
        this.uberApi.hideLoader(); 
        this.products = data.json().products; 
      }); 
      // Trip in progress? 
      this 
        .uberApi 
        .getCurrentRides(this.fromGeo.latitude, this.fromGeo.longitude) 
        .subscribe((crrRides) => { 
          this.currentRideInfo = crrRides.json(); 
          this.isRideinProgress = true; 
          this.uberApi.hideLoader(); 
          // check for existing rides before processing 
          this.loadMap(this.fromGeo.latitude, this.fromGeo.longitude); 
        }, (err) => { 
          if (err.status === 404) { 
            // no rides availble 
          } 
          this.isRideinProgress = false; 
          this.uberApi.hideLoader(); 
          // check for existing rides before processing 
          this.loadMap(this.fromGeo.latitude, this.fromGeo.longitude); 
        }); 
    }).catch((error) => { 
      console.log('Error getting location', error); 
    }); 
  }

```

`fetCords()`将使用 Geolocation Ionic Native 插件来获取用户的坐标。一旦我们收到位置，我们将发起一个请求来获取产品，传入用户的纬度和经度。同时，我们使用 Uber API 的`getCurrentRides()`来检查是否有正在进行的乘车。

一旦响应到达，我们将调用`loadMap()`来绘制所需的地图。

完成代码演示后，我们将安装所有必需的 Cordova 插件和 Ionic Native 模块：

```html
// snipp 
private loadMap(lat: number, lon: number) { 
    let element: HTMLElement = document.getElementById('map'); 
    element.innerHTML = ''; 
    this.map = undefined; 
    this.map = this.googleMaps.create(element); 
    let crrLoc: LatLng = new LatLng(lat, lon); 
    let position: CameraPosition = { 
      target: crrLoc, 
      zoom: 18, 
      tilt: 30 
    }; 

    this.map.one(GoogleMapsEvent.MAP_READY).then(() => { 
      // move the map's camera to position 
      this.map.moveCamera(position); // works on iOS and Android 

      let markerOptions: MarkerOptions = { 
        position: crrLoc, 
        draggable: true, 
        title: this.isRideinProgress ? 'Ride in Progess' : 'Select 
        Destination >', 
        infoClick: (() => { 
          if (!this.isRideinProgress) { 
            this.selectDestination(); 
          } 
        }), 
        markerClick: (() => { 
          if (!this.isRideinProgress) { 
            this.selectDestination(); 
          } 
        }) 
      }; 

      this.map.addMarker(markerOptions) 
        .then((marker: Marker) => { 
          marker.showInfoWindow(); 
        }); 

      // a rare bug 
      // loader doesn't hide 
      this.uberApi.hideLoader(); 
    });
}

```

`loadMap()`获取用户的地理位置，创建一个标记在该位置，并使用相机 API 将视角移动到该点。标记上有一个简单的信息文本，选择目的地 >，当点击时，用户将进入一个屏幕以输入目的地来预订乘车。

`infoClick()`和`markerClick()`注册一个回调来执行`selectDestination()`，只有当没有正在进行的乘车时：

```html
// snipp 
  private productClick(product) { 
    // console.log(product); 
    // set the active product in the UI 
    for (let i = 0; i < this.products.length; i++) { 
      if (this.products[i].product_id === product.product_id) { 
        this.products[i].isSelected = true; 
      } else { 
        this.products[i].isSelected = false; 
      } 
    } 

    this.selectedProduct = product; 
  }

```

要预订乘车，用户应该选择一个产品。`productClick()`通过根据用户在主页上的选择设置产品为所选产品来处理这个问题。

一旦产品被选择并且用户的位置可用，我们可以要求用户输入目的地位置，以便我们可以检查车费估算：

```html
// snipp 
private selectDestination() { 
    if (this.isRideinProgress) { 
      this.map.setClickable(false); 
      let alert = this.alertCtrl.create({ 
        title: 'Only one ride!', 
        subTitle: 'You can book only one ride at a time.', 
        buttons: ['Ok'] 
      }); 
      alert.onDidDismiss(() => { 
        this.map.setClickable(true); 
      }); 
      alert.present(); 
    } else { 
      if (!this.selectedProduct) { 
        // since the alert has a button 
        // we need to first stop the map from  
        // listening. Then process the alert 
        // then renable 
        this.map.setClickable(false); 
        let alert = this.alertCtrl.create({ 
          title: 'Select Ride', 
          subTitle: 'Select a Ride type to continue (Pool or Go or X)', 
          buttons: ['Ok'] 
        }); 
        alert.onDidDismiss(() => { 
          this.map.setClickable(true); 
        }); 
        alert.present(); 
      } else { 
        this.map.setClickable(false); 
        let modal = this.modalCtrl.create(AutoCompletePage); 
        modal.onDidDismiss((data) => { 
          this.map.setClickable(true); 
          this.toGeo = data; 
          this 
            .uberApi 
            .requestRideEstimates(this.fromGeo.latitude, 
             this.toGeo.latitude, this.fromGeo.longitude, 
             this.toGeo.longitude) 
            .subscribe((data) => { 
              this.uberApi.hideLoader(); 
              this.processRideFares(data.json()); 
            }); 

        }); 
        modal.present(); 
      } 
    } 
  }

```

`selectDestination()`负责目的地选择以及获取乘车估算。`selectDestination()`内部的第一个 if 条件是为了确保用户只有一个正在进行的乘车。第二个 if 条件检查是否至少有一个`selectedProduct`。如果一切顺利，我们将调用`AutoCompletePage`作为一个模态，用户可以使用 Google Places 服务搜索地点。一旦使用此服务选择了一个地点，我们将获取目的地的地理位置。然后将所需的信息传递给`requestRideEstimates()`来获取估算。

一旦我们完成了`BookRidePage`，我们将开始处理`AutoCompletePage`。当我们从`requestRideEstimates()`获取车费时，我们将向用户呈现相同的信息：

```html
// snipp 
private processRideFares(fareInfo: any) { 
    // ask the user if the fare is okay,  
    // if yes, book the cab 
    // else, do nothing 
    console.log('fareInfo', fareInfo); 
    this.map.setClickable(false); 
    let confirm = this.alertCtrl.create({ 
      title: 'Book Ride?', 
      message: 'The fare for this ride would be ' 
      + fareInfo.fare.value 
      + ' ' + fareInfo.fare.currency_code + '.\n And it will take         
      approximately ' + 
      (fareInfo.trip.duration_estimate / 60) + ' mins.', 
      buttons: [ 
        { 
          text: 'No', 
          handler: () => { 
            this.map.setClickable(true); 
          } 
        }, 
        { 
          text: 'Yes', 
          handler: () => { 
            this.map.setClickable(true); 
            this 
              .uberApi 
              .requestRide(this.selectedProduct.product_id, 
               fareInfo.fare.fare_id, this.fromGeo.latitude, 
                this.toGeo.latitude, this.fromGeo.longitude, 
                this.toGeo.longitude) 
              .subscribe((rideInfo) => { 
                this.uberApi.hideLoader(); 
                // console.log('rideInfo', rideInfo.json()); 
                // Since we are making requests to the sandbox url 
                // the request will always be in processing. 
                // Once the request has been submitted, we need to  
                // keep polling the getCurrentRides() API 
                // to get the ride information 
                // WE ARE NOT GOING TO DO THAT! 
                this.isRideinProgress = true; 
                this.currentRideInfo = rideInfo.json(); 
              }); 
          } 
        } 
      ] 
    }); 
    confirm.present(); 
  }

```

`processRideFares()`以车费信息作为输入并向用户呈现车费。如果用户对车费和时间估计满意，我们会使用`requestRide()`向 Uber 发出预订乘车的请求。

最后，如果用户想要取消当前的乘车，我们提供`cancelRide()`：

```html
// snipp 
  private cancelRide() { 
    this 
      .uberApi 
      .cancelCurrentRide() 
      .subscribe((cancelInfo) => { 
        this.uberApi.hideLoader(); 
        this.isRideinProgress = false; 
        this.currentRideInfo = undefined; 
      }); 
  }

```

这将是一个调用`cancelCurrentRide()`。

现在我们已经完成了`BookRidePage`所需的逻辑，我们将创建`AutoCompletePage`。运行以下命令：

```html
ionic generate page autoComplete

```

完成后，我们需要将`AutoCompletePage`添加到`riderr/src/app/app.module.ts`中：

```html
import { AutoCompletePage } from '../pages/auto-complete/auto-complete';

```

将`AutoCompletePage`引用添加到`@NgModule()`的`declarations`和`entryComponents`属性中。

`AutoCompletePage`类将包含与 Google Places 服务一起使用以搜索地点所需的逻辑。首先，我们将处理`auto-complete.html`。打开`riderr/src/pages/auto-complete/auto-complete.html`并按照以下方式更新它：

```html
<ion-header> 
    <ion-toolbar> 
        <ion-title>Enter address</ion-title> 
        <ion-searchbar id="q" [(ngModel)]="autocomplete.query" [showCancelButton]="true" (ionInput)="updateSearch()" (ionCancel)="dismiss()"></ion-searchbar> 
    </ion-toolbar> 
</ion-header> 
<ion-content> 
    <ion-list> 
        <!-- (click) is buggy at times, hmmm? --> 
        <ion-item *ngFor="let item of autocompleteItems" tappable (click)="chooseItem(item)"> 
            {{ item.description }} 
        </ion-item> 
    </ion-list> 
</ion-content>

```

我们有一个搜索栏和一个`ion-list`来显示搜索结果。接下来，我们将处理`auto-complete.ts`。打开`riderr/src/pages/auto-complete/auto-complete.ts`并按照以下方式更新它：

```html
import { Component, NgZone } from '@angular/core'; 
import { ViewController } from 'ionic-angular'; 

@Component({ 
  templateUrl: 'auto-complete.html' 
}) 

// http://stackoverflow.com/a/40854384/1015046 
export class AutocompletePage { 
  autocompleteItems; 
  autocomplete; 
  ctr: HTMLElement = document.getElementById("q"); 
  service = new google.maps.places.AutocompleteService(); 
  geocoder = new google.maps.Geocoder(); 

  constructor(public viewCtrl: ViewController, private zone: NgZone) { 
    this.autocompleteItems = []; 
    this.autocomplete = { 
      query: '' 
    }; 
  } 

  dismiss() { 
    this.viewCtrl.dismiss(); 
  } 

  chooseItem(item: any) { 
    // we need the lat long 
    // so we will make use of the  
    // geocoder service 
    this.geocoder.geocode({ 
      'placeId': item.place_id 
    }, (responses) => { 
      // send the place name 
      // & latlng back 
      this.viewCtrl.dismiss({ 
        description: item.description, 
        latitude: responses[0].geometry.location.lat(), 
        longitude: responses[0].geometry.location.lng() 
      }); 
    }); 
  } 

  updateSearch() { 
    if (this.autocomplete.query == '') { 
      this.autocompleteItems = []; 
      return; 
    } 
    let that = this; 
    this.service.getPlacePredictions({ 
      input: that.autocomplete.query, 
      componentRestrictions: { 
        country: 'IN' 
      } 
    }, (predictions, status) => { 
      that.autocompleteItems = []; 
      that.zone.run(function() { 
        predictions = predictions || []; 
        predictions.forEach(function(prediction) { 
          that.autocompleteItems.push(prediction); 
        }); 
      }); 
    }); 
  } 
}

```

在这里，我们使用`google.maps.places.AutocompleteService`来获取用户搜索时的预测。

重要的一点要注意的是，地点和地理编码器服务不作为 Ionic Native 插件提供。因此，我们将使用 Google Maps JavaScript 库来访问地点和地理编码器服务。为此，我们将安装 typings 和 Google Maps。我们将在最后安装这个。

用户找到地点后，他们将点击位置，这将触发`chooseItem()`。在`chooseItem()`内，我们将获取`place_id`并获取所选位置的地理坐标，并将其传递回`BookRidePage`类中`selectDestination()`内的`modal.onDidDismiss()`。然后流程就像我们在`BookRidePage`类中看到的那样。

现在，我们将实现`profile`，`history`和`paymentMethods`端点。要生成所需的页面，请运行以下命令：

```html
ionic generate page profile 
ionic generate page history 
ionic generate page paymentMethods

```

接下来，我们将同样添加到`riderr/src/app/app.module.ts`中。`app.module.ts`的最终版本将如下所示：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 
import { LoginPage } from '../pages/login/login'; 
import { BookRidePage } from '../pages/book-ride/book-ride'; 
import { AutocompletePage } from '../pages/auto-complete/auto-complete'; 
import { ProfilePage } from '../pages/profile/profile'; 
import { HistoryPage } from '../pages/history/history'; 
import { PaymentMethodsPage } from '../pages/payment-methods/payment-methods'; 

import { UberAPI } from '../services/uber.service'; 
import { Storage } from '@ionic/storage'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { Diagnostic } from '@ionic-native/diagnostic'; 

// export function provideStorage() { 
//   return new Storage();  
// } 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage, 
    LoginPage, 
    BookRidePage, 
    AutocompletePage, 
    ProfilePage, 
    HistoryPage, 
    PaymentMethodsPage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage, 
    LoginPage, 
    BookRidePage, 
    AutocompletePage, 
    ProfilePage, 
    HistoryPage, 
    PaymentMethodsPage 
  ], 
  providers: [{ provide: ErrorHandler, useClass: IonicErrorHandler }, 
    UberAPI, 
    // {provide: Storage, useFactory: provideStorage}, 
    Storage, 
    StatusBar, 
    SplashScreen, 
    Diagnostic 
  ] 
}) 
export class AppModule { }

```

现在我们将更新我们已经搭建好的三个页面。这些页面中的几乎所有内容都相当容易理解。

`riderr/src/pages/profile/profile.html`中的 HTML 将如下所示：

```html
<ion-header> 
    <ion-navbar>s 
        <button ion-button menuToggle> 
            <ion-icon name="menu"></ion-icon> 
        </button> 
        <ion-title>Riderr</ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <h2 text-center>Your Profile</h2> 
    <hr> 
    <ion-list *ngIf="profile"> 
        <ion-item> 
            <ion-avatar item-left> 
                <img src="img/{{profile.picture}}"> 
            </ion-avatar> 
            <h2>{{profile.first_name}} {{profile.last_name}}</h2> 
            <h3>{{profile.email}}</h3> 
            <p>{{profile.promo_code}}</p> 
        </ion-item> 
    </ion-list> 
</ion-content>

```

`riderr/src/pages/profile/profile.ts`中所需的逻辑如下所示：

```html
import { Component } from '@angular/core'; 
import { UberAPI } from '../../services/uber.service'; 

@Component({ 
  selector: 'page-profile', 
  templateUrl: 'profile.html' 
}) 
export class ProfilePage { 
  private profile; 
  constructor(private uberApi: UberAPI) { } 

  ngAfterViewInit() { 
    this.uberApi.getMe().subscribe((data) => { 
      // console.log(data.json()); 
      this.profile = data.json(); 
      // need a clean way to fix this! 
      this.uberApi.hideLoader(); 
    }, (err) => { 
      console.log(err); 
      this.uberApi.hideLoader(); 
    }); 
  } 
}

```

接下来，我们将处理`HistoryPage`。`riderr/src/pages/history/history.html`中的 HTML 将如下所示：

```html
<ion-header> 
    <ion-navbar> 
        <button ion-button menuToggle> 
            <ion-icon name="menu"></ion-icon> 
        </button> 
        <ion-title>Riderr</ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <h2 text-center>Your Ride History</h2> 
    <hr> 
    <h3 text-center *ngIf="total">Showing last {{count}} of {{total}} rides</h3> 
    <ion-list> 
        <ion-item *ngFor="let h of history"> 
            <h2>{{ h.start_city.display_name }}</h2> 
            <h3>Completed at {{ h.end_time | date: 'hh:mm a'}}</h3> 
            <p>Distance : {{ h.distance }} Miles</p> 
        </ion-item> 
    </ion-list> 
</ion-content>

```

`riderr/src/pages/history/history.ts`中的相关逻辑如下所示：

```html
import { Component } from '@angular/core'; 
import { UberAPI } from '../../services/uber.service'; 

@Component({ 
  selector: 'page-history', 
  templateUrl: 'history.html' 
}) 
export class HistoryPage { 
  history: Array<any>; 
  total: Number; 
  count: Number; 

  constructor(private uberApi: UberAPI) { } 

  ngAfterViewInit() { 
    this.uberApi.getHistory().subscribe((data) => { 
      // console.log(data.json()); 
      let d = data.json(); 
      this.history = d.history; 
      this.total = d.count; 
      this.count = d.history.length; 

      // need a clean way to fix this! 
      this.uberApi.hideLoader(); 
    }, (err) => { 
      console.log(err); 
      this.uberApi.hideLoader(); 
    }); 
  } 
}

```

最后，我们将实现支付方式。相同的 HTML 将在`riderr/src/pages/payment-methods/payment-methods.html`中如下所示：

```html
<ion-header> 
    <ion-navbar> 
        <button ion-button menuToggle> 
            <ion-icon name="menu"></ion-icon> 
        </button> 
        <ion-title>Riderr</ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <h2 text-center>Your Payment Methods</h2> 
    <hr> 
    <ion-list *ngIf="payment_methods"> 
        <ion-item *ngFor="let pm of payment_methods"> 
            <h2>{{ pm.type }}</h2> 
            <h3>{{ pm.description }}</h3> 
        </ion-item> 
    </ion-list> 
</ion-content>

```

`riderr/src/pages/payment-methods/payment-methods.ts`中所需的逻辑如下所示：

```html
import { Component } from '@angular/core'; 
import { UberAPI } from '../../services/uber.service'; 

@Component({ 
  selector: 'page-payment-methods', 
  templateUrl: 'payment-methods.html' 
}) 
export class PaymentMethodsPage { 
  payment_methods; 

  constructor(private uberApi: UberAPI) { } 

  ngAfterViewInit() { 
    this.uberApi.getPaymentMethods().subscribe((data) => { 
      // console.log(data.json()); 
      this.payment_methods = data.json().payment_methods; 
      // need a clean way to fix this! 
      this.uberApi.hideLoader(); 
    }, (err) => { 
      console.log(err); 
      this.uberApi.hideLoader(); 
    }); 
  } 
}

```

有了这个，我们完成了所需的代码。接下来，我们将安装所需的插件和库。

# 安装依赖项

运行以下命令安装此应用所需的 Cordova 插件：

```html
ionic plugin add cordova.plugins.diagnostic 
ionic plugin add cordova-plugin-geolocation 
ionic plugin add cordova-plugin-inappbrowser 
ionic plugin add cordova-sqlite-storage 
ionic plugin add cordova-custom-config

```

以及它们的 Ionic Native 模块：

```html
npm install --save @ionic-native/google-maps 
npm install --save @ionic-native/Geolocation 
npm install --save @ionic-native/diagnostic 
npm install --save @ionic-native/in-app-browser 
npm install --save @ionic/storage

```

接下来，我们将安装 Google Maps 的 Cordova 插件。但在安装之前，我们需要获取一个 API 密钥。使用[`developers.google.com/maps/documentation/android-api/signup`](https://developers.google.com/maps/documentation/android-api/signup)上的 Get A Key 按钮来启用 Android 应用的 Google Maps API 并获取一个密钥。对于 iOS，请转到以下页面：[`developers.google.com/maps/documentation/ios-sdk/get-api-key`](https://developers.google.com/maps/documentation/ios-sdk/get-api-key)。

获得 API 密钥后，运行以下命令：

```html
ionic plugin add cordova-plugin-googlemaps --variable API_KEY_FOR_ANDROID=" AIzaSyCZhTJB1kFAP70RuwDtt6uso9e3DCLdRWs" --variable API_KEY_FOR_IOS="AIzaSyCZhTJB1kFAP70RuwDtt6uso9e3DCLdRWs"

```

注意：请使用您的密钥更新上述命令。

接下来，为了使用 Google Maps Places 服务，我们需要获取一个用于通过 JavaScript 访问地图服务的 API 密钥。转到[`developers.google.com/maps/documentation/JavaScript/get-api-key`](https://developers.google.com/maps/documentation/javascript/get-api-key)获取 JavaScript 的密钥。然后打开`riderr/src/index.html`并在文档的头部添加以下引用：

```html
<script src="img/js?v=3&libraries=places&key=AIzaSyDmFpX80vy5p0YTuXGAgVJzWTkZfDqPl_s"></script>

```

接下来，为了让 TypeScript 编译器不对`riderr/src/pages/auto-complete/auto-complete.ts`中的`google`变量抱怨，我们需要添加所需的 typings。运行以下命令：

```html
npm install typings --global

```

接下来，运行以下命令：

```html
typings install dt~google.maps --global --save

```

打开`riderr/tsconfig.json`并将`"typings/*.d.ts"`添加到`"include"`数组中，如下所示：

```html
{ 
  "compilerOptions": { 
    "allowSyntheticDefaultImports": true, 
    "declaration": false, 
    "emitDecoratorMetadata": true, 
    "experimentalDecorators": true, 
    "lib": [ 
      "dom", 
      "es2015" 
    ], 
    "module": "es2015", 
    "moduleResolution": "node", 
    "sourceMap": true, 
    "target": "es5" 
  }, 
  "include": [ 
    "src/**/*.ts", 
    "typings/*.d.ts" 
  ], 
  "exclude": [ 
    "node_modules" 
  ], 
  "compileOnSave": false, 
  "atom": { 
    "rewriteTsconfig": false 
  } 
}

```

有关如何安装 Google 地图的 TypeScript typings，请参阅：[`stackoverflow.com/a/40854384/1015046`](http://stackoverflow.com/a/40854384/1015046) 获取更多信息。

最后，我们需要请求互联网访问和网络访问权限。打开`riderr/config.xml`并按照以下方式更新`<platform name="android"></platform>`：

```html
<platform name="android"> 
        <allow-intent href="market:*" /> 
        <config-file target="AndroidManifest.xml" parent="/*"> 
            <uses-permission android:name="android.permission.INTERNET" 
            /> 
            <uses-permission 
            android:name="android.permission.ACCESS_FINE_LOCATION" /> 
            <uses-permission 
            android:name="android.permission.ACCESS_COARSE_LOCATION" /> 
        </config-file> 
    </platform>

```

然后在页面顶部的 widget 标签中添加`xmlns:android=http://schemas.android.com/apk/res/android`，如下所示：

```html
<widget id="app.example.riderr" version="0.0.1"   >

```

这就结束了*安装依赖项*部分。

# 测试应用

让我们继续测试该应用。首先，我们需要添加所需的平台。运行`ionic platform add android`或`ionic platform add ios`。

要测试该应用程序，我们需要模拟器或实际设备。

一旦设备/模拟器设置好，我们可以运行`ionic run android`或`ionic run ios`命令。

流程如下：

首先，用户启动应用程序。将呈现登录屏幕，如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00096.jpeg)

一旦用户点击“使用 Uber 登录”，我们将用户重定向到 Uber 授权屏幕，在那里用户将使用他们的 Uber 帐户登录：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00097.jpeg)

认证成功后，将显示同意屏幕，并列出应用程序请求的权限列表：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00098.jpeg)

一旦用户允许应用访问数据，我们将用户重定向到主页。

在主页上，我们提供了访问用户位置的同意弹出窗口：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00099.jpeg)

一旦获得批准，我们将获得用户的地理位置，并使用该位置获取产品。

以下是完全加载的主屏幕截图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00100.jpeg)

菜单如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00101.jpeg)

从这里，用户可以查看他们的个人资料：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00102.gif)

他们可以查看他们的乘车历史：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00103.gif)

他们还可以查看他们的付款方式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00104.gif)

在用户选择目的地之前，他们需要选择一个产品：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00105.jpeg)

一旦他们选择了产品，他们可以选择要乘坐的目的地：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00106.jpeg)

现在，我们制作车费明细并显示相同的内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00107.jpeg)

如果用户同意，我们将预订乘车并显示乘车信息：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00108.jpeg)

请注意应用程序右上角的取消乘车按钮。这将取消当前的乘车。

再次提醒，我们正在调用沙盒 API URL。如果您想请求实际乘车服务，请在`riderr/src/services/uber.service.ts`中将`UBERSANDBOXAPIURL`更新为`UBERAPIURL`。

使用 Uber（生产）API 时，当我们请求乘车时，我们会收到处理响应。我们可以继续轮询几次以获取当前乘车信息。如果您发出实际乘车请求，响应将如下所示：

```html
{ 
    "status": "accepted", 
    "product_id": "18ba4578-b11b-49a6-a992-a132f540b027", 
    "destination": { 
        "latitude": 17.445949, 
        "eta": 34, 
        "longitude": 78.350058 
    }, 
    "driver": { 
        "phone_number": "+910000000000", 
        "rating": 4.6, 
        "picture_url": 
        "https:\/\/d1w2poirtb3as9.cloudfront.net\
        /605de11c25139a1de469.jpeg", 
        "name": "John Doe", 
        "sms_number": null 
    }, 
    "pickup": { 
        "latitude": 17.4908514, 
        "eta": 13, 
        "longitude": 78.3375952 
    }, 
    "request_id": "1beaae05-8d43-4711-951c-25dd5293c2f9", 
    "location": { 
        "latitude": 17.4875583, 
        "bearing": 338, 
        "longitude": 78.33165 
    }, 
    "vehicle": { 
        "make": "Maruti Suzuki", 
        "picture_url": null, 
        "model": "Swift Dzire", 
        "license_plate": "XXXXXXXX" 
    }, 
    "shared": false 
}

```

您可以相应地构建您的界面。

# 摘要

在本章中，我们已经通过 Ionic 构建了一个应用，并将其与 Uber API 以及使用 Ionic Native 的设备功能集成。我们还使用了 Google Places Service 作为原始 JavaScript 库，并使用 typings 将其与我们的 Ionic 应用集成。

在下一章中，我们将看一下将 Ionic 1 应用迁移到 Ionic 2。如果您从 Ionic 1 迁移到 Ionic 3，这也适用。


# 第八章：Ionic 2 迁移指南

在本章中，我们将看看如何将现有的 Ionic 1 应用迁移到 Ionic 2/Ionic 3。我们首先将使用 Ionic 1 构建一个简单的 Todo 应用，然后了解如何将其迁移到 Ionic 2：

+   为什么要迁移？

+   构建一个简单的 Ionic 1 Todo 应用

+   迁移计划

+   将 Ionic 1 Todo 应用迁移到 Ionic 2

如果您想要从 Ionic 1 迁移到 Ionic 3，本迁移指南仍然有效。请参考第十一章，*Ionic 3*，以更好地了解 Ionic 3 中的变化。

# 为什么要迁移？

到目前为止，在这本书中，我们已经学习了使用 Ionic 2 构建应用的过程，但并不了解 Ionic 1。但就现实世界而言，已经有数千个应用程序使用了 Ionic 1 部署。这些应用可以利用 Ionic 2 的改进功能来提高应用体验。

在软件世界中迁移代码是一项艰巨的任务。在我们的情况下，迁移更加复杂，因为我们不仅要将 Ionic 1 的库升级到 Ionic 2，还要将这些库所写的语言本身升级，例如，从 ES5 到 ES6 和 TypeScript。

JavaScript 应用程序的新生态主要围绕 ES6、TypeScript 和 Web 组件展开。适应这些以利用最新技术就是 Angular 2 所做的。Ionic 2 也做到了这一点。

在我看来，有这么多的变化，将一个完全运行良好的应用程序从 Ionic 1 迁移到 Ionic 2 应该谨慎对待，只有在必要时才需要这样做。

*如果事情顺利，为什么要改变呢？*

当涉及将应用程序基础从 Ionic 1 更改为 Ionic 2 时，有些人称之为迁移，但我称之为重写。

# Todo 应用 - Ionic v1

在本节中，我们将使用 Ionic 1 构建一个 Todo 应用。我们将构建的应用几乎包含了典型 Ionic 应用的所有特性。我们将拥有：

+   路由

+   持久性

+   本地通知

+   REST API 集成

两页 Todo 应用中的第一页将是登录页面，第二页将是我们处理 Todos 的页面。我们将使用`LocalStorage`来保存认证状态以及我们将创建的 Todos。当用户创建、更新或删除待办事项时，我们还将显示本地通知。显示本地通知更多地是与设备功能进行接口的 Ionic 应用。最后，我们将发出对[`www.ipify.org/`](https://www.ipify.org/)的 REST API 请求，以获取我们从中访问此应用的设备的 IP 地址。

最终应用程序将如下图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00109.jpeg)

# 构建应用程序

现在我们已经有了一个建设的想法，让我们开始吧。创建一个名为`chapter8`的文件夹，并在`chapter8`文件夹内打开一个新的命令提示符/终端并运行：

```html
ionic start -a "TodoApp-v1" -i app.example.todoapp_v1 todoapp_v1  blank

```

我们正在使用 Ionic v1 搭建一个空白项目。请注意，我们没有使用`--v2`标志。一旦项目被搭建，就在你喜欢的文本编辑器中打开它。

在我们开始处理这两个页面之前，我们将创建所需的服务。我们将创建五个服务：

+   LocalStorage 服务：与 LocalStorage 进行交互

+   本地通知服务：与`$cordovaLocalNotification`进行交互

+   IP 服务：与[`api.ipify.org`](https://api.ipify.org)进行交互

+   认证服务：管理认证

+   Todos 服务：管理 Todos

为此，我们将在`www/js`文件夹内创建另一个名为`services.js`的文件。打开`todoapp_v1/www/js/services.js`并添加以下代码：

```html
angular.module('starter') 
.service('LS', function($window) { // local storage 
    this.set = function(key, value) { 
        // http://stackoverflow.com/a/23656919/1015046 
        $window.localStorage.setItem(key, 
        $window.angular.toJson(value)); 
    } 

    this.get = function(key) { 
        return $window.JSON.parse($window.localStorage.getItem(key)); 
    } 

    this.remove = function(key) { 
        $window.localStorage.removeItem(key); 
    } 
})

```

`LS`服务公开了对 HTML5 `localStorage`的包装器。

接下来，在同一文件中为本地通知服务添加一个包装器，在`LS`服务之后：

```html
// snipp 
.service('LN', function($ionicPlatform, $cordovaLocalNotification) { // local notifications 
    var i = 1; 
    this.show = function(text) { 
        $ionicPlatform.ready(function() { 
            var notifPromise = $cordovaLocalNotification.schedule({ 
                id: i++, 
                title: 'Todo App', 
                text: text 
            }) 
            return notifPromise; 
        }); 
    } 
})

```

在编写代码结束时，我们将从`ngCordova`添加所需的依赖项。

接下来，我们将添加`IP`服务以与[`api.ipify.org`](https://api.ipify.org)进行交互并获取用户的 IP 地址。追加以下代码：

```html
// snipp 
.service('IP', function ($http) { 
    this.get = function(){ 
        return $http.get('https://api.ipify.org/?format=json'); 
    } 
})

```

最后，管理身份验证和待办事项的两个关键服务。添加以下代码：

```html
// snipp 
.service('AUTH', function(LS) { 
    var LS_AUTH_KEY = 'auth'; 
    this.login = function(user) { 
        if (user.email === 'a@a.com', user.password === 'a') { 
            LS.set(LS_AUTH_KEY, true); 
            return true; 
        } else { 
            return false; 
        } 
    } 

    this.isAuthenticated = function() { 
        return !!LS.get(LS_AUTH_KEY); 
    } 

    this.logout = function() { 
        LS.remove(LS_AUTH_KEY); 
    } 

}) 

.service('TODOS', function(LS) { 
    var LS_TODOS_KEY = 'todos'; 

    this.set = function(todos) { 
        LS.set(LS_TODOS_KEY, todos); 
    } 

    this.get = function() { 
        return LS.get(LS_TODOS_KEY) || []; 
    } 
});

```

通过这样，我们已经完成了所需的服务。

由于这将是一个双页面应用程序，我们将使用 State 路由器来定义和管理路由。打开`todoapp_v1/www/js/app.js`并在`run`方法下添加以下`config`部分：

```html
.config(function($stateProvider, $urlRouterProvider) { 
    $stateProvider 
        .state('login', { 
            url: '/login', 
            templateUrl: 'templates/login.html', 
            controller: 'LoginCtrl' 
        }) 
        .state('home', { 
            url: '/home', 
            templateUrl: 'templates/home.html', 
            controller: 'HomeCtrl' 
        }); 
    // if none of the above states are matched, use this as the fallback 
    $urlRouterProvider.otherwise('/login'); 
});

```

在上述片段中，我们定义了两个路由 - 登录和主页。现在我们需要创建所需的模板和控制器。

在`www/js`文件夹中创建一个名为`controllers.js`的新文件。打开`todoapp_v1/www/js/controllers.js`和`LoginCtrl`，如下面的代码所示：

```html
angular.module('starter') 

.controller('LoginCtrl', function($scope, AUTH, $state, $ionicHistory, $ionicPopup) { 

    // check Auth before proceeding 
    if (AUTH.isAuthenticated()) { 
        $state.go('home'); 
    } 

    // hardcode the test user 
    $scope.user = { 
        email: 'a@a.com', 
        password: 'a' 
    } 

    $scope.login = function() { 
        if (AUTH.login($scope.user)) { 
            // remove all views in stack 
            // this way when the user clicks on the  
            // back button on the home page 
            // we do not show the login screen again 
            $ionicHistory.clearHistory(); 
            $state.go('home'); 
        } else { 
            $ionicPopup.alert({ 
                title: 'LOGIN FAILED', 
                template: 'Either the email or password is invalid.' 
            }); 
        }; 
    } 
})

```

在这里，我们正在检查用户是否已经经过身份验证，如果是，我们将用户重定向到主页。`login()`接受用户的凭据并使用`AUTH.login()`验证它们。如果身份验证失败，我们将使用`$ionicPopup`服务显示警报。

接下来，我们将按照以下代码添加`HomeCtrl`：

```html
// snipp 

.controller('HomeCtrl', function($scope, $state, AUTH, TODOS, $ionicHistory, $ionicPopup, $ionicListDelegate, LN) { 

    $scope.todo = {}; 
    // check Auth before proceeding 
    if (!AUTH.isAuthenticated()) { 
        $state.go('login'); 
    } 

    // fetch todos on load 
    $scope.todos = TODOS.get(); 

    $scope.add = function() { 
        //reset 
        $scope.todo.text = ''; 
        var addTodoPopup = $ionicPopup.show({ 
            template: '<input type="text" ng-model="todo.text">', 
            title: 'Add Todo', 
            subTitle: 'Enter a Todo To Do', 
            scope: $scope, 
            buttons: [ 
                { text: 'Cancel' }, { 
                    text: '<b>Save</b>', 
                    type: 'button-positive', 
                    onTap: function(e) { 
                        // validation 
                        if (!$scope.todo.text) { 
                            e.preventDefault(); 
                        } else { 
                            return $scope.todo.text; 
                        } 
                    } 
                } 
            ] 
        }); 

        addTodoPopup.then(function(text) { 
            if (text) { 
                var todo = { 
                    text: text, 
                    isCompleted: false 
                }; 

                $scope.todos.push(todo); 
                // save it to LS 
                TODOS.set($scope.todos); 
                LN.show('Todo Created'); 
            } 
        }); 
    } 

    $scope.update = function(todo) { 
        todo.isCompleted = !todo.isCompleted; 
        $ionicListDelegate.closeOptionButtons(); 
        // update LS 
        TODOS.set($scope.todos); 
        LN.show('Todo Updated'); 
    } 

    $scope.delete = function($index, todo) { 

        var deleteConfirmPopup = $ionicPopup.confirm({ 
            title: 'Delete Todo', 
            template: 'Are you sure you want to delete "' + todo.text + 
            '"? ' 
        }); 

        deleteConfirmPopup.then(function(res) { 
            if (res) { 
                $scope.todos.splice($index, 1); 
                // update LS 
                TODOS.set($scope.todos); 
                LN.show('Todo Deleted'); 
            } 
        }); 
    } 

    $scope.logout = function() { 
        AUTH.logout(); 
        $ionicHistory.clearHistory(); 
        $state.go('login'); 
    } 
});

```

我们首先检查身份验证。接下来，我们获取所有的待办事项。我们在`HomeCtrl`范围上定义了四种方法：`add()`，`update()`，`delete()`和`logout()`。

添加方法用于添加新的待办事项。我们使用`$ionicPopup`服务显示一个弹出窗口，用户在其中输入待办事项文本。一旦待办事项被添加，我们使用`LN`服务推送一个本地通知。

更新方法在本地存储中更新待办事项的`isCompleted`属性，并推送一个指示相同内容的本地通知。

删除方法显示一个确认框，询问用户确认删除操作。如果用户确认删除，我们将从集合中删除待办事项并将集合持久化到本地存储中。为了完成删除过程，我们推送一个本地通知指示待办事项已被删除。

最后，注销方法清除身份验证状态并将用户重定向回登录页面。

现在我们已经完成了控制器，我们将开始处理所需的模板。在`www`文件夹中创建一个名为`templates`的新文件夹。在模板文件夹中，创建一个名为`login.html`的文件。打开`todoapp_v1/www/templates/login.html`并按照以下代码进行更新：

```html
<ion-view view-> 
    <ion-content> 
        <div class="list"> 
            <label class="item item-input"> 
                <span class="input-label">Username</span> 
                <input type="email" ng-model="user.email" 
                placeholder="Enter your email"> 
            </label> 
            <label class="item item-input"> 
                <span class="input-label">Password</span> 
                <input type="password" ng-model="user.password" 
                placeholder="Enter your password"> 
            </label> 
            <button ng-click="login()" class="button button-positive 
            button-full" ng-disabled="!user.email || !user.password"> 
                Login 
            </button> 
        </div> 
    </ion-content> 
    <ion-footer-bar align- class="bar-positive"> 
        <h1 class="title">Your IP : {{ip}}</h1> 
    </ion-footer-bar> 
</ion-view>

```

我们有一个简单的登录表单。在页脚中，我们将显示用户的 IP 地址。为了获取用户的 IP 地址，我们将按照以下代码更新`todoapp_v1/www/js/app.js`中的`run`方法：

```html
// snipp 
.run(function($ionicPlatform, IP, $rootScope) { 
    $ionicPlatform.ready(function() { 
        if (window.cordova && window.cordova.plugins.Keyboard) { 
            cordova.plugins.Keyboard.hideKeyboardAccessoryBar(true); 
            cordova.plugins.Keyboard.disableScroll(true); 
        } 
        if (window.StatusBar) { 
            StatusBar.styleDefault(); 
        } 

        IP.get().then(function(resp) { 
            // console.log(resp.data); 
            $rootScope.ip = resp.data.ip; 
        }); 
    }); 
}) 
// snipp

```

我们将 IP 地址存储在根作用域上。

接下来，在`www/templates`文件夹中创建一个名为`home.html`的新文件。按照以下代码更新`todoapp_v1/www/templates/home.html`：

```html
<ion-view view-> 
    <ion-nav-bar class="bar-default"> 
        <ion-nav-buttons side="right"> 
            <button class="button button-assertive" ng-click=" 
            logout()"> 
                Logout 
            </button> 
        </ion-nav-buttons> 
    </ion-nav-bar> 
    <ion-content> 
        <ion-list can-swipe="true"> 
            <ion-item> 
                <button class="button button-full button-positive" ng-
                click="add()"> 
                    Add Todo 
                </button> 
            </ion-item> 
            <ion-item ng-repeat="todo in todos"> 
                <h2 ng-class="{ 'strike' : todo.isCompleted}">
                {{todo.text}}</h2> 
                <ion-option-button class="button-assertive icon ion-
                trash-a" ng-click="delete($index, todo)">
                </ion-option-button> 
                <ion-option-button class="button-positive icon" ng-               
                class="{'ion-checkmark-round' : 
                !todo.isCompleted, 'ion-close-round' :
                todo.isCompleted}" ng-click="update(todo)">
                </ion-option-button> 
            </ion-item> 
            <ion-item ng-if="todos.length > 0"> 
                <p class="text-center">Swipe left for options</p> 
            </ion-item> 
            <ion-item ng-if="todos.length === 0"> 
                <h2 class="text-center">No Todos</h2> 
            </ion-item> 
        </ion-list> 
    </ion-content> 
    <ion-footer-bar align- class="bar-positive"> 
        <h1 class="title">Your IP : {{ip}}</h1> 
    </ion-footer-bar> 
</ion-view>

```

当用户标记`todo`为已完成时，为了视觉效果，我们添加了一个名为`strike`的类。打开`todoapp_v1/www/css/style.css`并按照以下代码进行更新：

```html
.strike{ 
  text-decoration: line-through; 
  color: #999; 
}

```

通过这样，我们已经完成了实现所需代码。现在，我们将添加所需的依赖项并更新`www/index.html`。

首先，我们将为我们的项目添加`ngCordova`([`ngcordova.com/`](http://ngcordova.com/))支持。运行以下命令：

```html
bower install ngCordova --save

```

接下来是本地通知插件：([`ngcordova.com/docs/plugins/localNotification/`](http://ngcordova.com/docs/plugins/localNotification/)) cordova plugin add: [`github.com/katzer/cordova-plugin-local-notifications.git`](https://github.com/katzer/cordova-plugin-local-notifications.git)。

现在，我们将更新`www/index.html`以添加`ngCordova`依赖项。添加以下内容：

```html
<script src="img/ng-cordova.js"></script> before <script src="img/cordova.js"></script>.

```

接下来，添加对`services.js`和`controllers.js`的引用：

```html
<script src="img/services.js"></script> 
<script src="img/controllers.js"></script>

```

在`app.js`已经被包含之后。接下来，将按照以下代码更新 body 部分：

```html
<ion-pane> 
        <ion-nav-bar class="bar-positive"> 
        </ion-nav-bar> 
        <ion-nav-view></ion-nav-view> 
</ion-pane>

```

我们已经添加了`<ion-nav-view></ion-nav-view>`以支持路由。

现在，打开`todoapp_v1/www/js/app.js`并更新启动模块定义为：`angular.module('starter', ['ionic', 'ngCordova'])`

就是这样！现在我们需要做的就是添加一个平台并开始测试使用 Ionic v1 构建的待办事项应用程序：

```html
ionic platform add android or ionic platform add ios

```

然后运行以下命令：

```html
ionic run android or ionic run ios

```

然后我们应该看到登录页面出现：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00110.jpeg)

成功登录后，我们应该能够添加新的待办事项：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00111.jpeg)

我们可以更新待办事项或删除待办事项：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00112.jpeg)

当添加、更新或删除待办事项时，我们会推送本地通知：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00113.jpeg)

通过这样，我们完成了构建 Ionic 1 待办事项应用程序。

# 迁移计划

现在我们完成了 Ionic v1 待办事项应用程序，我们将开始考虑将其迁移到 Ionic 2。

注意：如果您计划从 Ionic 1 迁移到 Ionic 3，您将遵循类似的方法。

计划很简单；我们将使用`--v2`标志搭建一个新的空白模板，并开始组合东西。以下表格将是一个很好的起点：

| **组件** | **Ionic 1** | **Ionic 2** |
| --- | --- | --- |
| Ionic 起始模板 | 空白 | 空白 |
| 引导应用程序 | ng-app | `NgModule` |
| 导航 | 状态路由器 | `NavController` |
| 组件 | 模板和控制器 | `@Component` |
| 服务/工厂 | 服务提供者 | `@Injectable Provider` |
| 持久性 | 本地存储 | Storage API |
| 设备交互 | `NgCordova` | Ionic Native |
| 本地通知 | `$cordovaLocalNotification`服务 | LocalNotifications 类 |

现在我们知道了高级映射，我们将从头开始在 v2 中搭建一个新的空白模板。

在`chapter8`文件夹中，打开一个新的命令提示符/终端并运行：

```html
ionic start -a "TodoApp-v2" -i app.example.todoapp_v2 todoapp_v2  blank --v2

```

完成搭建后，`cd`进入`todoapp_v2`文件夹。我们将生成所需的组件和提供者。运行以下命令：

```html
 ionic generate page login

```

这将生成登录页面。接下来，三个提供者：

```html
ionic generate provider auth 
ionic generate provider todos 
ionic generate provider IP

```

由于我们在 Ionic 2 中使用了 Storage API，我们不会为此创建单独的提供者。

现在我们有了所需的页面和提供者，我们将引导应用程序。

打开`todoapp_v2/src/app/app.module.ts`并进行所需的导入：

```html
// snipp 
import { LoginPage } from '../pages/login/login'; 

import { Auth } from '../providers/auth'; 
import { Todos } from '../providers/todos'; 
import { IP } from '../providers/ip'; 

import { IonicStorageModule } from '@ionic/storage'; 
import { LocalNotifications } from '@ionic-native/local-notifications';

```

接下来，我们将按照以下代码更新`@NgModule`：

```html
@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage, 
    LoginPage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp), 
    IonicStorageModule.forRoot() 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage, 
    LoginPage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    {provide: ErrorHandler, useClass: IonicErrorHandler}, 
    Auth, 
    Todos, 
    IP, 
    LocalNotifications 
  ] 
})

```

就像我们在 Ionic 1 应用程序中所做的那样，我们将在最后安装所需的依赖项。

打开`todoapp_v2/src/app/app.component.ts`并将`rootPage`更新为`LoginPage`。我们将从`'../pages/home/home';`更新`import { HomePage }`到`import { LoginPage }`和`rootPage = HomePage;`到`rootPage = LoginPage;`

现在，我们将更新提供者。打开`todoapp_v2/src/providers/ip.ts`并按照以下代码进行更新：

```html
import { Injectable } from '@angular/core'; 
import { Http, Response } from '@angular/http'; 
import { Observable } from 'rxjs/Observable'; 

@Injectable() 
export class IP { 
  constructor(private http: Http) {} 

  get() : Observable <Response>{ 
    return this.http.get('https://api.ipify.org/?format=json'); 
  } 
}

```

接下来，打开`todoapp_v2/src/providers/auth.ts`。按照以下内容进行更新：

```html
import { Injectable } from '@angular/core'; 
import { Storage } from '@ionic/storage'; 

@Injectable() 
export class Todos { 
  private LS_TODOS_KEY = 'todos'; 

  constructor(private storage: Storage) { } 

  set(todos): void { 
    this.storage.set(this.LS_TODOS_KEY, todos); 
  } 

  get(): Promise<any> { 
    return this.storage.get(this.LS_TODOS_KEY); 
  } 
}

```

最后，打开`todoapp_v2/src/providers/auth.ts`并按照以下内容进行更新：

```html
import { Injectable } from '@angular/core'; 
import { Storage } from '@ionic/storage'; 

@Injectable() 
export class Auth { 
  private LS_AUTH_KEY = 'auth'; 

  constructor(private storage: Storage) { } 

  login(user: any): Boolean { 
    if (user.email === 'a@a.com', user.password === 'a') { 
      this.storage.set(this.LS_AUTH_KEY, true) 
      return true; 
    } else { 
      return false; 
    } 
  } 

  isAuthenticated(): Promise<Storage> { 
    return this.storage.get(this.LS_AUTH_KEY); 
  } 

  logout(): void { 
    this.storage.set(this.LS_AUTH_KEY, undefined); 
  } 
}

```

前面的三个提供者非常简单。它们复制了 Ionic 1 中所示的相同逻辑，只是这些是用 TypeScript 编写的，遵循 Angular 2 的结构。

现在，我们将在页面上进行工作。首先是登录页面。打开`todoapp_v2/src/pages/login/login.ts`并按照以下代码进行更新：

```html
import { Component } from '@angular/core'; 
import { NavController, AlertController } from 'ionic-angular'; 
import { HomePage } from '../home/home'; 
import { Auth } from '../../providers/auth'; 
import { IP } from '../../providers/ip'; 

@Component({ 
  selector: 'page-login', 
  templateUrl: 'login.html' 
}) 
export class LoginPage { 
  userIp = ''; 
  user = { 
    email: 'a@a.com', 
    password: 'a' 
  } 

  constructor( 
    public navCtrl: NavController, 
    public alertCtrl: AlertController, 
    private auth: Auth, 
    private ip: IP) { 

    // check if the user is already  
    // authenticated 
    auth.isAuthenticated().then((isAuth) => { 
      if (isAuth) { 
        navCtrl.setRoot(HomePage); 
      } 
    }); 

    // Get the user's IP 
    ip.get().subscribe((data) => { 
      this.userIp = data.json().ip; 
    }); 
  } 

  login() { 
    if (this.auth.login(this.user)) { 
      this.navCtrl.setRoot(HomePage); 
    } else { 
      let alert = this.alertCtrl.create({ 
        title: 'LOGIN FAILED', 
        subTitle: 'Either the email or password is invalid.', 
        buttons: ['OK'] 
      }); 
      alert.present(); 
    } 
  } 
}

```

这个文件中的逻辑与 Ionic 1 应用程序中的`LoginCtrl`的逻辑非常相似。接下来，我们将按照以下代码更新`todoapp_v2/src/pages/login/login.html`：

```html
<ion-header class="positive"> 
    <ion-navbar> 
        <ion-title>Todo App (v2)</ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content> 
    <ion-list> 
        <ion-item> 
            <ion-label fixed>Username</ion-label> 
            <ion-input type="email" placeholder="Enter your email" 
            [(ngModel)]="user.email"></ion-input> 
        </ion-item> 
        <ion-item> 
            <ion-label fixed>Password</ion-label> 
            <ion-input type="password" placeholder="Enter your 
            password" [(ngModel)]="user.password"></ion-input> 
        </ion-item> 
    </ion-list> 
    <button ion-button full (click)="login()" [disabled]="!user.email || !user.password">Login</button> 
</ion-content> 
<ion-footer>
  <h3>Your IP : {{userIp}}</h3>
</ion-footer>

```

页面结构与 Ionic 1 完全相同，只是我们与组件交互的方式不同；`[(ngModel)]`语法用于双向数据绑定`(ng-model)`和`(click)`语法用于按钮上的事件处理`(ng-click).`

请注意`ion-header`上的 positive 类。我们将使用这个类来为页面提供几乎相同的外观和感觉，就像我们在 Ionic 1 应用程序中所做的那样。

现在我们将在`todoapp_v2/src/pages/home/home.ts`上进行工作。按照以下代码更新`todoapp_v2/src/pages/home/home.ts`：

```html
import { Component } from '@angular/core'; 
import { LocalNotifications } from '@ionic-native/local-notifications'; 
import { NavController, AlertController } from 'ionic-angular'; 
import { LoginPage } from '../login/login'; 
import { Auth } from '../../providers/auth'; 
import { IP } from '../../providers/ip'; 
import { Todos } from '../../providers/todos'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  private i = 1; // ID for notifications 
  userIp = ''; 
  userTodos = []; 

  constructor( 
    public navCtrl: NavController, 
    public alertCtrl: AlertController, 
    private localNotifications: LocalNotifications, 
    private auth: Auth, 
    private ip: IP, 
    private todos: Todos) { 

    // check if the user is authenticated 
    auth.isAuthenticated().then((isAuth) => { 
      if (!isAuth) { 
        navCtrl.setRoot(LoginPage); 
      } 
    }); 

    // fetch todos on load 
    this.todos.get().then((_todos) => { 
      this.userTodos = _todos || []; 
    }); 

    // Get the user's IP 
    ip.get().subscribe((data) => { 
      this.userIp = data.json().ip; 
    }); 
  } 

  add() { 
    let addTodoPopup = this.alertCtrl.create({ 
      title: 'Add Todo', 
      inputs: [ 
        { 
          name: 'text', 
          placeholder: 'Enter a Todo To Do' 
        } 
      ], 
      buttons: [ 
        { 
          text: 'Cancel', 
          role: 'cancel', 
          handler: (data) => { 
            // console.log('Cancel clicked'); 
          } 
        }, 
        { 
          text: 'Save', 
          handler: (data) => { 
            if (data.text) { 
              let todo = { 
                text: data.text, 
                isCompleted: false 
              }; 
              this.userTodos.push(todo); 
              // store the todos 
              this.todos.set(this.userTodos); 
              this.notify('Todo Created'); 

            } else { 
              return false; 
            } 
          } 
        } 

      ] 
    }); 
    addTodoPopup.present(); 
  } 

  update(todo, slidingItem) { 
    todo.isCompleted = !todo.isCompleted; 
    // store the todos 
    this.todos.set(this.userTodos); 
    slidingItem.close(); 
    this.notify('Todo Updated'); 
  } 

  delete(todo, index) { 
    let alert = this.alertCtrl.create({ 
      title: 'Delete Todo', 
      message: 'Are you sure you want to delete "' + todo.text + '"? ', 
      buttons: [ 
        { 
          text: 'No', 
          role: 'cancel', 
          handler: () => { 
            // console.log('Cancel clicked'); 
          } 
        }, 
        { 
          text: 'Yes', 
          handler: () => { 
            this.userTodos.splice(index, 1); 
            this.todos.set(this.userTodos); 
            this.notify('Todo Deleted'); 
          } 
        } 
      ] 
    }); 
    alert.present(); 

  } 

  logout() { 
    this.auth.logout(); 
    this.navCtrl.setRoot(LoginPage); 
  } 

  private notify(text) { 
    this.localNotifications.schedule({ 
      id: this.i++, 
      title: 'Todo App', 
      text: text, 
    }); 
  } 
}

```

这里复制了`HomeCtrl`的相同逻辑。唯一的关键区别是`notify()`被用作包装器来呈现本地通知，不像在 Ionic 1 应用程序中，我们为此使用了一个服务。

更新后的 `todoapp_v2/src/pages/home/home.html` 如下所示：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title>Todo App (v2)</ion-title> 
        <ion-buttons end> 
            <button ion-button color="danger" (click)="logout()"> 
                Logout 
            </button> 
        </ion-buttons> 
    </ion-navbar> 
</ion-header> 
<ion-content> 
    <button ion-button full (click)="add()"> 
        Add Todo 
    </button> 
    <ion-list can-swipe="true"> 
        <ion-item-sliding *ngFor="let todo of userTodos" #slidingItem> 
            <ion-item [class.strike]="todo.isCompleted"> 
                {{todo.text}} 
            </ion-item> 
            <ion-item-options side="right"> 
                <button ion-button icon-only (click)="update(todo, 
                slidingItem)"> 
                    <ion-icon [name]="todo.isCompleted ? 'close' : 
                    'checkmark'"></ion-icon> 
                </button> 
                <button ion-button icon-only color="danger" 
                (click)="delete(todo, index)"> 
                    <ion-icon name="trash"></ion-icon> 
                </button> 
            </ion-item-options> 
        </ion-item-sliding> 
        <ion-item *ngIf="userTodos.length > 0"> 
            <p text-center>Swipe left for options</p> 
        </ion-item> 
        <ion-item *ngIf="userTodos.length === 0"> 
            <h2 class="text-center">No Todos</h2> 
        </ion-item> 
    </ion-list> 
</ion-content> 
<ion-footer> 
    <h3>Your IP : {{userIp}}</h3> 
</ion-footer>

```

最后是样式。打开 `todoapp_v2/src/app/app.scss` 并添加以下 CSS 规则：

```html
ion-header.positive ion-navbar .toolbar-background, 
ion-footer, 
{ 
    background-color: #387ef5; 
} 

ion-header.positive .toolbar-title, 
ion-footer { 
    color: #fff; 
} 

.toolbar-title, 
ion-footer { 
    text-align: center; 
} 

ion-navbar button[color=danger]{ 
    background: #f53d3d; 
    color: #fff; 
    border-radius: 4px 
} 

.strike { 
    text-decoration: line-through; 
    color:#999; 
}

```

这结束了我们的编码部分。现在，我们将安装所需的依赖项。首先是与存储相关的依赖项，运行以下命令：

```html
ionic plugin add cordova-sqlite-storage -save 
npm install --save @ionic/storage

```

接下来是本地通知的依赖项：

```html
ionic plugin add de.appplant.cordova.plugin.local-notification 
npm install --save @ionic-native/local-notifications

```

这应该满足所需的依赖关系。

现在，我们将添加一个平台并测试应用程序：

```html
ionic platform add android or ionic platform add ios

```

然后运行以下命令：

```html
ionic run android or ionic run ios

```

然后您应该看到登录页面弹出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00114.jpeg)

管理待办事项的主页：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00115.jpeg)

最后是推送的通知：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00116.jpeg)

通过这个，我们已经完成了将我们的 Ionic 1 Todo 应用程序迁移到 Ionic 2。希望这个例子给出了一些关于如何将 Ionic 1 应用程序迁移到 Ionic 2 以及 Ionic 3 的想法。

# 摘要

在本章中，我们已经了解了构建一个简单的 Ionic 1 Todo 应用程序的过程。接下来，我们准备了一个粗略的迁移计划，并按照相同的计划将 Ionic 1 Todo 应用程序迁移到 Ionic 2。我们已经看到了在迁移和利用最新功能（如 Ionic Native 和 Storage API）方面，Ionic 1 和 Ionic 2 应用程序之间的一些关键区别。

请查看第十一章，*Ionic 3*，以了解 Ionic 2 和 Ionic 3 之间的区别。

在下一章中，我们将测试我们迁移的 Ionic 2 Todo 应用程序。
