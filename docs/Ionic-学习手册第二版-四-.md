# Ionic 学习手册第二版（四）

> 原文：[`zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60`](https://zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：测试 Ionic 2 应用

在本章中，我们将讨论如何测试使用 Cordova（和 Ionic 2）构建的移动混合应用。测试可以在多个层面进行，首先是单元测试，然后是端到端测试，最后将应用部署到实际设备上并执行测试。在本章中，我们将对我们在第八章中构建的 Ionic 2 Todo 应用执行以下测试：

+   单元测试

+   端到端测试

+   使用 AWS 设备农场进行猴子或模糊测试

+   使用 AWS 设备农场进行测试

# 测试方法学

在应用开发领域，测试进入应用开发生命周期的两种方式。一种是更传统的方式，其中首先进行开发，然后根据要求设计和执行测试运行。另一种更有效的方式是采用**测试驱动开发**（**TDD**）。经过一段时间的验证，TDD 已被证明是一种更无缺陷的应用开发方式。您可以在这里阅读更多关于 TDD 的信息：[`agiledata.org/essays/tdd.html`](http://agiledata.org/essays/tdd.html)。

TDD 的副产品是**行为驱动测试**（**BDT**）。BDT 更多地围绕行为测试而不是需求测试。单元测试和 BDT 的自动化测试的良好组合将产生一个具有最小错误的优秀产品。由于 BDT 涉及更多以用户为中心的测试，因此可以在测试阶段轻松发现最终用户可能在测试阶段遇到的问题。

在本章中，我们将遵循测试应用的更传统流程，即在构建后进行测试。我们将实施单元测试、端到端测试，然后将应用上传到 AWS 设备农场并进行猴子测试。

# 设置单元测试环境

Ionic CLI 构建的应用在撰写本章的当天不包括任何测试设置。因此，我们需要自己添加所需的测试设置。

# 设置项目

首先，我们将创建一个名为`chapter9`的新文件夹，并将`chapter8`文件夹中的`todoapp_v2`复制到`chapter9`文件夹中。

通过从`chapter9/todoapp_v2`文件夹的根目录运行`npm install`来安装依赖项（如果缺少）。

运行`ionic serve`，查看应用是否按预期工作。当您创建、更新和删除`todo`时，您可能会在控制台中看到警告，指出 Cordova 环境不存在。这是因为我们在浏览器中使用本地通知插件。

我们将为单元测试我们的 Todo 应用进行环境设置，该设置基于文章：*Ionic 2 Unit Testing Setup: The Best Way* ([`www.roblouie.com/article/376/ionic-2-set-up-unit-testing-the-best-way/`](http://www.roblouie.com/article/376/ionic-2-set-up-unit-testing-the-best-way/))。

要开始，我们将安装 Karma 和 Jasmine：

+   **Karma**：Karma 是一个在 Node.js 上运行的 JavaScript 测试运行器。引用 Karma 的文档，*Karma 本质上是一个工具，它生成一个 Web 服务器，针对连接的每个浏览器执行源代码与测试代码。对每个浏览器的每个测试的结果进行检查，并通过命令行显示给开发人员，以便他们可以看到哪些浏览器和测试通过或失败。*

我们将使用 Karma 来执行我们将要编写的测试用例：

+   **Jasmine**：Jasmine 是一个用于测试 JavaScript 代码的行为驱动开发框架。它不依赖于任何其他 JavaScript 框架。它不需要 DOM。它具有清晰明了的语法，因此我们可以轻松编写测试。

我们将使用 Jasmine 来定义我们的测试并编写断言。通常我们会通过编写一个描述块来开始测试。然后我们开始使用`it`构造定义我们的测试用例。

例如：

```html
describe('Component: MyApp Component', () => { 
  it('should be created', () => { 
     // assertions go here 
  }); 
});

```

断言是简单的比较语句，用于验证实际结果和期望结果：

```html
expect(1 + 1).toBe(2); 
expect(!!true).toBeTruthy();

```

依此类推。

现在我们对 Karma 和 Jasmine 有了基本的了解，我们将安装所需的依赖项。

在安装过程中，如果出现任何错误，请更新到最新版本的 Node.js。

要安装 Karma，请运行以下命令：

```html
npm install -g karma-cli

```

接下来，安装 Jasmine 和相关依赖项：

```html
npm install --save-dev @types/jasmine@2.5.41 @types/node html-loader jasmine karma karma-webpack ts-loader karma-sourcemap-loader karma-jasmine karma-jasmine-html-reporter angular2-template-loader karma-chrome-launcher null-loader karma-htmlfile-reporter

```

完成后，我们将添加所需的配置文件。

在`todoapp_v2`文件夹的根目录下创建一个名为`test-config`的新文件夹。在`test-config`文件夹内，创建一个名为`webpack.test.js`的文件。使用以下代码更新`todoapp_v2/test-config/webpack.test.js`：

```html
var webpack = require('webpack'); 
var path = require('path'); 

module.exports = {
    devtool: 'inline-source-map',
    resolve: {
        extensions: ['.ts', '.js']
    },
    module: {
        rules: [{
            test: /.ts$/,
            loaders: [{
                loader: 'ts-loader'
            }, 'angular2-template-loader']
        }, {
            test: /.html$/,
            loader: 'html-loader'
        }, {
            test: /.(png|jpe?g|gif|svg|woff|woff2|ttf|eot|ico)$/,
            loader: 'null-loader'
        }]
    },
    plugins: [
        new webpack.ContextReplacementPlugin(
            // The (|/) piece accounts for 
            path separators in *nix and Windows
            /angular(|/)core(|/)
            (esm(|/)src|src)(|/)linker/,
            root('./src'), // location of your src
            {} // a map of your routes
        )
    ]
};

function root(localPath) { 
    return path.resolve(__dirname, localPath); 
}

```

接下来，在`test-config`文件夹内创建另一个名为`karma-test-shim.js`的文件。使用以下代码更新`todoapp_v2/test-config/karma-test-shim.js`：

```html
Error.stackTraceLimit = Infinity; 

require('core-js/es6'); 
require('core-js/es7/reflect'); 

require('zone.js/dist/zone'); 
require('zone.js/dist/long-stack-trace-zone'); 
require('zone.js/dist/proxy'); 
require('zone.js/dist/sync-test'); 
require('zone.js/dist/jasmine-patch'); 
require('zone.js/dist/async-test'); 
require('zone.js/dist/fake-async-test'); 

var appContext = require.context('../src', true, /.spec.ts/); 

appContext.keys().forEach(appContext); 

var testing = require('@angular/core/testing'); 
var browser = require('@angular/platform-browser-dynamic/testing'); 

testing.TestBed.initTestEnvironment(browser.BrowserDynamicTestingModule, browser.platformBrowserDynamicTesting());

```

最后，在`test-config`文件夹内创建一个名为`karma.conf.js`的文件。使用以下代码更新`todoapp_v2/test-config/karma.conf.js`：

```html
var webpackConfig = require('./webpack.test.js'); 
module.exports = function(config) { 
    var _config = { 
        basePath: '', 
        frameworks: ['jasmine'], 
        files: [ 
            { pattern: './karma-test-shim.js', watched: true } 
        ], 
        preprocessors: { 
            './karma-test-shim.js': ['webpack', 'sourcemap'] 
        }, 
        webpack: webpackConfig, 
        webpackMiddleware: { 
            stats: 'errors-only' 
        }, 
        webpackServer: { 
            noInfo: true 
        }, 
        reporters: ['html', 'dots'], 
        htmlReporter: { 
            outputFile: './unit-test-report.html', 
            pageTitle: 'Todo App Unit Tests', 
            subPageTitle: 'Todo App Unit Tests Report', 
            groupSuites: true, 
            useCompactStyle: true, 
            useLegacyStyle: true 
        }, 
        port: 9876, 
        colors: true, 
        logLevel: config.LOG_INFO, 
        autoWatch: true, 
        browsers: ['Chrome'], 
        singleRun: true 
    }; 
    config.set(_config); 
};

```

有了这些，我们完成了运行单元测试所需的基本配置。

前面提到的文章本身包含了我们添加的三个配置文件的所需信息。有关更多信息，请参阅：[`angular.io/docs/ts/latest/guide/webpack.html#!#test-configuration`](https://angular.io/docs/ts/latest/guide/webpack.html#!#test-configuration)。

# 编写单元测试

现在我们已经完成了所需的设置，我们将开始编写单元测试。单元测试写在与源文件相邻的文件中，文件名后面加上`.spec`。例如，如果我们为`app.component.ts`编写测试用例，我们将在相同的文件夹中创建一个名为`app.component.spec.ts`的文件，并编写所需的测试用例。

有关更多信息，请参阅[`angular.io/docs/ts/latest/guide/testing.html#!#q-spec-file-location`](https://angular.io/docs/ts/latest/guide/testing.html#!#q-spec-file-location)和[`angular.io/docs/ts/latest/guide/style-guide.html#!#02-10`](https://angular.io/docs/ts/latest/guide/style-guide.html#!#02-10)。

首先，我们将开始编写应用组件的测试。我们将测试以下情况：

+   如果组件已创建。

+   如果`rootPage`设置为`LoginPage`。

现在，在`todoapp_v2/src/app`文件夹内创建一个名为`app.component.spec.ts`的文件。使用以下代码更新`todoapp_v2/src/app/app.component.spec.ts`：

```html
import { async, TestBed } from '@angular/core/testing'; 
import { IonicModule } from 'ionic-angular'; 
import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { MyApp } from './app.component'; 
import { LoginPage } from '../pages/login/login'; 

describe('Component: MyApp Component', () => { 
  let fixture; 
  let component; 

  beforeEach(async(() => { 
    TestBed.configureTestingModule({ 
      declarations: [MyApp], 
      imports: [ 
        IonicModule.forRoot(MyApp) 
      ], 
      providers: [ 
        StatusBar, 
        SplashScreen 
      ] 
    }) 
  })); 

  beforeEach(() => { 
    fixture = TestBed.createComponent(MyApp); 
    component = fixture.componentInstance; 
  }); 

  it('should be created', () => { 
    expect(component instanceof MyApp).toBe(true); 
  }); 

  it('should set the rootPage as LoginPage', () => { 
    expect(component.rootPage).toBe(LoginPage); 
  }); 

});

```

有很多事情要做。首先，我们导入了所需的依赖项。接下来，我们添加了描述块。在描述块内，我们添加了`beforeEach()`。`beforeEach()`在每次测试执行之前运行。在第一个`beforeEach()`中，我们定义了`TestBed`。在第二个`beforeEach()`中，我们创建了所需的组件并获取了它的实例。

`TestBed`配置和初始化了单元测试的环境。要深入了解 Angular 2 中的测试设置和执行方式，请查看：*Testing Angular 2, Julie Ralph*，网址：[`www.youtube.com/watch?v=f493Xf0F2yU`](https://www.youtube.com/watch?v=f493Xf0F2yU)。

一旦`TestBed`被定义并且组件被初始化，我们就编写我们的测试用例。

注意：我们已经用`async`包装了`beforeEach()`的回调函数。`async`不会让下一个测试开始，直到所有待处理的任务都完成。要了解何时在测试中使用`async`，请参考*Angular 2 Testing -- Async function call --when to use*：[`stackoverflow.com/a/40127164/1015046`](http://stackoverflow.com/a/40127164/1015046)。

接下来，我们将测试登录页面。

在`todoapp_v2/src/pages/login`文件夹内创建一个名为`login.spec.ts`的文件。我们将测试以下内容：

+   组件已创建

+   `userIp`变量被初始化为空字符串。

+   用户对象包含值为`a@a.com`的电子邮件

+   用户对象包含值为`a`的密码

使用以下代码更新`todoapp_v2/src/pages/login/login.spec.ts`：

```html
import { async, TestBed } from '@angular/core/testing'; 
import { IonicModule, NavController, AlertController } from 'ionic-angular'; 
import { IonicStorageModule } from '@ionic/storage'; 
import { MyApp } from '../../app/app.component'; 
import { LoginPage } from './login'; 
import { Auth } from '../../providers/auth'; 
import { IP } from '../../providers/ip'; 

describe('Component: Login Component', () => { 
  let fixture; 
  let component; 

  beforeEach(async(() => { 
    TestBed.configureTestingModule({ 
      declarations: [ 
        MyApp, 
        LoginPage 
      ], 
      imports: [ 
        IonicModule.forRoot(MyApp), 
        IonicStorageModule.forRoot() 
      ], 
      providers: [ 
        Auth, 
        IP, 
        NavController, 
        AlertController 
      ] 
    }) 
  })); 

  beforeEach(() => { 
    fixture = TestBed.createComponent(LoginPage); 
    component = fixture.componentInstance; 
  }); 

  it('should be created', () => { 
    expect(component instanceof LoginPage).toBe(true); 
  }); 

  it('should initialize `userIp` to ''', () => { 
    expect(component.userIp).toBe(''); 
  }); 

  it('should initialize `user`', () => { 
    expect(component.user.email).toBe('a@a.com'); 
    expect(component.user.password).toBe('a'); 
  }); 

});

```

上述代码相当容易理解。

接下来，我们转向主页组件。在`todoapp_v2/src/pages/home`文件夹内创建一个名为`home.spec.ts`的文件。在这个组件中，我们将测试以下内容：

+   组件是否已创建

+   `userIp`变量是否初始化为空字符串

+   `userTodos`变量是否初始化为空数组

+   当本地通知被触发时（这是我们对 Ionic Native 插件进行单元测试的方式）

使用以下代码更新`todoapp_v2/src/pages/home/home.spec.ts`：

```html
import { async, TestBed } from '@angular/core/testing'; 
import { IonicModule, NavController, AlertController } from 'ionic-angular'; 
import { MyApp } from '../../app/app.component'; 
import { HomePage } from './home'; 
import { LoginPage } from '../login/login'; 
import { IonicStorageModule } from '@ionic/storage'; 
import { LocalNotifications } from '@ionic-native/local-notifications'; 
import { LocalNotificationsMocks } from '../../mocks/localNotificationMocks'; 
import { Auth } from '../../providers/auth'; 
import { IP } from '../../providers/ip'; 
import { Todos } from '../../providers/todos'; 

describe('Component: Home Component', () => { 
  let fixture; 
  let component; 
  let localNotif; 

  beforeEach(async(() => { 
    TestBed.configureTestingModule({ 
      declarations: [ 
        MyApp, 
        HomePage, 
        LoginPage 
      ], 
      imports: [ 
        IonicModule.forRoot(MyApp), 
        IonicStorageModule.forRoot() 
      ], 
      providers: [ 
        Auth, 
        Todos, 
        IP, 
        { provide: LocalNotifications, useClass: 
          LocalNotificationsMocks }, 
        NavController, 
        AlertController 
      ] 
    }) 
  })); 

  beforeEach(() => { 
    fixture = TestBed.createComponent(HomePage); 
    component = fixture.componentInstance; 
    localNotif = new LocalNotificationsMocks(); 
  }); 

  it('should be created', () => { 
    expect(component instanceof HomePage).toBe(true); 
  }); 

  it('should initialize `userIp` to ''', () => { 
    expect(component.userIp).toBe(''); 
  }); 

  it('should initialize `userTodos`', () => { 
    expect(component.userTodos.length).toBe(0); 
  }); 

  // this is how we mock and test 
  // ionic-native plugins 
  it('should return null when a new notification is scheduled', () => { 
    expect(component.notify()).toBe(localNotif.schedule()); 
  }); 
});

```

从上述代码中需要注意的关键事项是提供者的属性传递给`TestBed.configureTestingModule()`。由于我们在模拟环境中运行测试，其中没有 Cordova，我们需要模拟或模拟`LocalNotifications`服务。

我们这样做的方式是创建另一个名为`LocalNotificationsMocks`的类，并在调用`LocalNotifications`时使用它。在`LocalNotificationsMocks`中，我们实现了返回预定义值的虚拟方法来模拟服务。

因此，我们将为`LocalNotifications`创建一个模拟服务。在`src`文件夹内创建一个名为 mocks 的文件夹。在`mocks`文件夹内，创建一个名为`localNotificationMocks.ts`的文件。使用以下代码更新`todoapp_v2/src/mocks/localNotificationMocks.ts`：

```html
export class LocalNotificationsMocks { 
  public schedule(config: any): void { 
    // https://github.com/driftyco/ionic-
    native/blob/5aa484c024d7cac3b6628c5dd8694395e8a29ed4/src/%40ionic-
    native/plugins/local-notifications/index.ts#L160 
    return; 
  } 
}

```

我们正在覆盖`schedule()`以根据原始定义返回 void。

完成组件测试后，接下来我们将测试提供者。

在`todoapp_v2/src/providers`文件夹内创建一个名为`ip.spec.ts`的文件。在这个提供者中，我们将模拟一个 HTTP 请求，并将模拟响应的输出与硬编码的响应进行比较。我们将测试以下情况：

+   提供者是否被构建

+   从模拟后端服务获取 IP 地址

打开`todoapp_v2/src/providers/ip.spec.ts`并使用以下代码进行更新：

```html
import { async, TestBed, inject } from '@angular/core/testing'; 
import { IP } from './ip'; 
import { Headers, Http, HttpModule, BaseRequestOptions, XHRBackend, Response, ResponseOptions } from '@angular/http'; 
import { MockBackend, MockConnection } from '@angular/http/testing'; 

// https://kendaleiv.com/angular-2-mockbackend-service-testing-template-using-testbed/ 
describe('Service: IPService', () => { 
  let service; 
  let http; 

  const mockResponse = { 
    ip: '11:22:33:44' 
  }; 

  beforeEach(async(() => { 
    TestBed.configureTestingModule({ 
      imports: [ 
        HttpModule 
      ], 
      providers: [ 
        MockBackend, 
        BaseRequestOptions, 
        { 
          provide: Http, 
          useFactory: (backend, options) => new Http(backend, options), 
          deps: [MockBackend, BaseRequestOptions] 
        }, 
        IP 
      ] 
    }) 
  })); 

  it('should construct', async(inject( 
    [IP, MockBackend], (ipService, mockBackend) => { 
      expect(ipService).toBeDefined(); 
    }))); 

  it('should get IP equal to `11:22:33:44`', async(inject( 
    [IP, MockBackend], (ipService, mockBackend) => { 

      mockBackend.connections.subscribe(conn => { 
        conn.mockRespond(new Response(new ResponseOptions({ body: JSON.stringify(mockResponse) }))); 
      }); 

      const result = ipService.get(); 

      result.subscribe((res) => { 
        expect(res.json()).toEqual({ 
          ip: '11:22:33:44' 
        }); 
      }); 
    }))); 
});

```

请注意 HTTP 的提供者。我们已经将它连接到`MockBackend`，并在发出请求时返回一个`mockResponse`。

接下来是 Auth 提供者。在`todoapp_v2/src/providers`文件夹内创建一个名为`auth.spec.ts`的文件。我们将在这个提供者中测试以下内容：

+   提供者是否被构建

+   成功使用有效凭据登录

+   使用无效凭据成功失败

+   `isAuthenticated()`的值

+   `logout()`时`authStatus`的值

打开`todoapp_v2/src/providers/auth.spec.ts`并使用以下代码进行更新：

```html
import { async, TestBed, inject } from '@angular/core/testing'; 
import { Auth } from './auth'; 
import { IonicStorageModule } from '@ionic/storage'; 
import { StorageMocks } from '../mocks/storageMocks'; 

let validUser = { 
  email: 'a@a.com', 
  password: 'a' 
} 

let inValidUser = { 
  email: 'a@a.com', 
  password: 'b' 
} 

describe('Service: AuthService', () => { 
  beforeEach(async(() => { 
    TestBed.configureTestingModule({ 
      imports: [ 
        IonicStorageModule.forRoot() 
      ], 
      providers: [ 
        Auth, 
        { provide: IonicStorageModule, useClass: StorageMocks }, 
      ] 
    }); 

  })); 

  it('should construct', async(inject( 
    [Auth, IonicStorageModule], (authService, ionicStorageModule) => { 
      expect(authService).toBeDefined(); 
    }))); 

  it('should login user with valid credentials', async(inject( 
    [Auth, IonicStorageModule], (authService, ionicStorageModule) => { 
      expect(authService.login(validUser)).toBeTruthy(); 
    }))); 

  it('should not login user with invalid credentials', async(inject( 
    [Auth, IonicStorageModule], (authService, ionicStorageModule) => { 
      expect(authService.login(inValidUser)).toBeFalsy(); 
    }))); 

  it('should return the auth status as true', async(inject( 
    [Auth, IonicStorageModule], (authService, ionicStorageModule) => { 
      // log the user in! 
      authService.login(validUser); 
      let result = authService.isAuthenticated(); 

      result.then((status) => { 
        expect(status).toBeTruthy(); 
      }) 
    }))); 

  it('should set auth to falsy on logout', async(inject( 
    [Auth, IonicStorageModule], (authService, ionicStorageModule) => { 
      // log the user in! 
      let authStatus = authService.login(validUser); 
      // check if login is successful 
      expect(authStatus).toBeTruthy(); 

      // trigger logout 
      let result = authService.logout(); 
      result.then((status) => { 
        expect(status).toBeFalsy(); 
      }); 
    }))); 

});

```

为了成功执行上述测试用例，我们需要模拟`IonicStorageModule`。在`todoapp_v2/src/mocks`文件夹内创建一个名为`storageMocks.ts`的新文件。使用以下代码更新`todoapp_v2/src/mocks/storageMocks.ts`：

```html
export class StorageMocks { 
  // mock store   
  store = {}; 

  public get(key) { 
    return new Promise((resolve, reject) => { 
      resolve(this.store[key]); 
    }); 
  } 

  public set(key, value){ 
    return new Promise((resolve, reject) => { 
      this.store[key] = value; 
      resolve(this.store[key]); 
    }); 
  } 
}

```

在这里，我们正在使用内存对象覆盖`IonicStorageModule`的行为。

我们将要测试的最后一个提供者是 Todos。在`todoapp_v2/src/providers`文件夹内创建一个名为`todos.spec.ts`的文件。我们将测试以下内容：

+   提供者是否被构建

+   Todos 的初始长度为`0`

+   保存一个 todo

+   更新一个 todo

+   删除一个 todo

打开`todoapp_v2/src/providers/todos.spec.ts`并进行以下更新：

```html
import { async, TestBed, inject } from '@angular/core/testing'; 
import { Todos } from './todos'; 
import { IonicStorageModule } from '@ionic/storage'; 
import { StorageMocks } from '../mocks/storageMocks'; 

let todos = [{ 
  text: 'Buy Eggs', 
  isCompleted: false 
}]; 

describe('Service: TodoService', () => { 
  beforeEach(async(() => { 
    TestBed.configureTestingModule({ 
      imports: [ 
        IonicStorageModule.forRoot() 
      ], 
      providers: [ 
        Todos, 
        { provide: IonicStorageModule, useClass: StorageMocks }, 
      ] 
    }); 

  })); 

  it('should construct', async(inject( 
    [Todos, IonicStorageModule], (todoService, ionicStorageModule) => { 
      expect(todoService).toBeDefined(); 
    }))); 

  it('should fetch 0 todos initally', async(inject( 
    [Todos, IonicStorageModule], (todoService, ionicStorageModule) => { 
      let result = todoService.get(); 
      result.then((todos) => { 
        expect(todos).toBeFalsy(); 
      }); 
    }))); 

  it('should save a todo', async(inject( 
    [Todos, IonicStorageModule], (todoService, ionicStorageModule) => { 
      let result = todoService.set(todos); 
      result.then((_todos) => { 
        expect(_todos).toEqual(todos); 
        expect(_todos.length).toEqual(1); 
      }); 
    }))); 

   it('should update a todo', async(inject( 
    [Todos, IonicStorageModule], (todoService, ionicStorageModule) => { 
      let todo = todos[0]; 
      todo.isCompleted = true; 
      todos[0] = todo; 
      let result = todoService.set(todos); 
      result.then((_todos) => { 
        expect(_todos[0].isCompleted).toBeTruthy(); 
      }); 
    })));  

   it('should delete a todo', async(inject( 
    [Todos, IonicStorageModule], (todoService, ionicStorageModule) => { 
      todos.splice(0, 1); 
      let result = todoService.set(todos); 
      result.then((_todos) => { 
        expect(_todos.length).toEqual(0); 
      }); 
    })));  

});

```

请注意提供者中的`StorageMocks`设置。通过这样做，我们已经完成了编写测试用例。下一步是执行。

# 执行单元测试

为了开始执行过程，我们将在`package.json`文件中添加一个脚本，这样我们就可以通过在命令提示符/终端中执行`npm test`来轻松运行测试。

打开`package.json`并在 scripts 部分添加以下行：

```html
"test": "karma start --reporters html ./test-config/karma.conf.js"

```

现在运行以下命令：

```html
npm test

```

然后，您应该看到浏览器启动并执行我们的测试用例。命令提示符/终端日志应该看起来像这样：

```html
todoapp_v2 npm test

> ionic-hello-world@ test /chapter9/todoapp_v2
> karma start --reporters html ./test-config/karma.conf.js

webpack: Compiled successfully.
webpack: Compiling...
ts-loader: Using typescript@2.0.9 and 
    /chapter9/todoapp_v2/tsconfig.json

webpack: Compiled successfully.
26 03 2017 23:26:55.201:INFO [karma]: Karma v1.5.0 server started 
    at http://0.0.0.0:9876/
26 03 2017 23:26:55.204:INFO [launcher]: Launching browser Chrome 
    with unlimited concurrency
26 03 2017 23:26:55.263:INFO [launcher]: Starting browser Chrome
26 03 2017 23:26:57.491:INFO [Chrome 56.0.2924 (Mac OS X 10.12.1)]: 
    Connected on socket DHM_DNgQakmVtg7RAAAA with id 44904930

```

您还应该看到一个名为`unit-test-report.html`的文件创建在`test-config`文件夹内。如果在浏览器中打开此文件，您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00117.jpeg)

上表总结了执行的测试。

# driftyco/ionic-unit-testing-example

在撰写本章的三天前，Ionic 团队发布了一篇博客文章，表明他们将支持单元测试和端到端测试，并且这将成为 Ionic 脚手架项目本身的一部分。更多信息可以在这里找到：[`blog.ionic.io/basic-unit-testing-in-ionic/`](http://blog.ionic.io/basic-unit-testing-in-ionic/)。

这个项目是基于 Ionic 2 测试领域中的一些非常有价值的贡献者，正如博客文章中所提到的。截至今天，*driftyco/ionic-unit-testing-example*（[`github.com/driftyco/ionic-unit-testing-example`](https://github.com/driftyco/ionic-unit-testing-example)）存储库没有完整的实现，只支持单元测试。

但到书出版时，他们可能已经推出了。`driftyco/ionic-unit-testing-example`内的设置应该仍然与我们在这里遵循的设置相同。我提醒您这一点，以便您可以关注该项目。

# E2E 测试

在单元测试中，我们已经测试了代码单元。在端到端测试中，我们将测试完整的功能，比如登录或注销，或者获取 IP 地址等等。在这里，我们将整个应用程序作为一个整体来看，而不仅仅是一个功能的一部分。有些人也将这称为集成测试。

我们将使用 Protractor 来帮助我们执行 E2E 测试。我们仍然会使用 Jasmine 来描述我们的测试，只是测试运行器从 Karma 变为 Protractor。

引用自[`www.protractortest.org`](http://www.protractortest.org)：

"Protractor 是一个用于 Angular 应用程序的端到端测试框架。Protractor 在真实浏览器中运行测试，与用户交互。"

YouTube 上有很多视频，深入解释了 Protractor 和 Selenium，以及 Protractor 的各种 API，可以用于测试，如果您想了解更多关于 Protractor 的信息。

我们将要进行的测试如下：

+   登录到应用程序

+   验证登录

+   注销应用程序

+   验证注销

# 设置项目

我将按照名为“E2E（端到端）测试在 Ionic 2 中的介绍”（[`www.joshmorony.com/e2e-end-to-end-testing-in-ionic-2-an-introduction/`](https://www.joshmorony.com/e2e-end-to-end-testing-in-ionic-2-an-introduction/)）的文章来设置 E2E 环境。

我们将使用相同的示例来实现单元测试。

首先通过运行以下命令安装 protractor：

```html
npm install protractor --save-dev

```

接下来，安装`webdriver-manager`并更新它：

```html
npm install -g webdriver-manager
webdriver-manager update

```

现在，我们将通过运行以下命令安装 Protractor 的依赖项：

```html
npm install jasmine-spec-reporter ts-node connect @types/jasmine@2.5.41 
@types/node --save-dev

```

请注意 Jasmine 类型的版本。它是硬编码为`2.5.41`。在撰写本文时，TypeScript 版本的 Jasmine 类型与 Ionic 2 项目存在一些冲突。如果您正在使用 Ionic 3.0，则应该已经解决了这个问题。

接下来，在`todoapp_v2`项目文件夹的根目录下，创建一个名为`protractor.conf.js`的文件。使用以下代码更新`todoapp_v2/protractor.conf.js`：

```html
var SpecReporter = require('jasmine-spec-reporter').SpecReporter; 

exports.config = { 
    allScriptsTimeout: 11000, 
    directConnect: true, 
    capabilities: { 
        'browserName': 'chrome' 
    }, 
    framework: 'jasmine', 
    jasmineNodeOpts: { 
        showColors: true, 
        defaultTimeoutInterval: 30000, 
        print: function() {} 
    }, 
    specs: ['./e2e/**/*.e2e-spec.ts'], 
    baseUrl: 'http://localhost:8100', 
    useAllAngular2AppRoots: true, 
    beforeLaunch: function() { 

        require('ts-node').register({ 
            project: 'e2e' 
        }); 

        require('connect')().use(require('serve-static')
        ('www')).listen(8100); 

    }, 
    onPrepare: function() { 
        jasmine.getEnv().addReporter(new SpecReporter()); 
    } 
}

```

这个文件定义了 Protractor 和 Selenium 的启动属性。

接下来，我们将在`todoapp_v2`文件夹的根目录下创建一个名为`e2e`的文件夹。在`todoapp_v2/e2e`文件夹内，创建一个名为`tsconfig.json`的文件。使用以下代码更新`todoapp_v2/e2e/tsconfig.json`：

```html
{ 
  "compilerOptions": { 
    "sourceMap": true, 
    "declaration": false, 
    "moduleResolution": "node", 
    "emitDecoratorMetadata": true, 
    "experimentalDecorators": true, 
    "lib": [ 
      "es2016" 
    ], 
    "outDir": "../dist/out-tsc-e2e", 
    "module": "commonjs", 
    "target": "es6", 
    "types":[ 
      "jasmine", 
      "node" 
    ] 
  } 
}

```

这完成了我们的端到端测试设置。现在，我们将开始编写测试。

# 编写 E2E 测试

现在我们已经完成了所需的设置，我们将开始编写测试。在`todoapp_v2/e2e`文件夹内创建一个名为`test.e2e-spec.ts`的新文件。

如前所述，我们将执行一个简单的测试--登录到应用程序，验证登录，从应用程序注销，并验证注销。所需的测试应该如下所示：

```html
import { browser, element, by, ElementFinder } from 'protractor'; 

// https://www.joshmorony.com/e2e-end-to-end-testing-in-ionic-2-an-introduction/ 
describe('Check Navigation : ', () => { 

  beforeEach(() => { 
    browser.get(''); 
  }); 

  it('should have `Todo App (v2)` as the title text on the Login Page', 
  () => { 
      expect(element(by.css('.toolbar-title')) 
        .getAttribute('innerText')) 
        .toContain('Todo App (v2)'); 

  }); 

  it('should be able to login with prefilled credentials', () => { 
    element(by.css('.scroll-content > button')).click().then(() => { 
      // Wait for the page transition 
      browser.driver.sleep(3000); 

      // check if we have really redirected 
      expect(element(by.css('.scroll-content > button')) 
        .getAttribute('innerText')) 
        .toContain('ADD TODO'); 

      expect(element(by.css('h2.text-center')) 
        .getAttribute('innerText')) 
        .toContain('No Todos'); 

      expect(element(by.css('ion-footer > h3')) 
        .getAttribute('innerText')) 
        .toContain('Your IP : 183.82.232.178'); 

    }); 

  }); 

  it('should be able to logout', () => { 
     element(by.css('ion-buttons > button')).click().then(() => { 

      // Wait for the page transition 
      browser.driver.sleep(3000); 

      // check if we have really redirected 
      expect(element(by.css('.toolbar-title')) 
        .getAttribute('innerText')) 
        .toContain('Todo App (v2)'); 
    }); 
  }); 

});

```

前面的代码是不言自明的。请注意，我已经将我的 IP 地址硬编码以在测试时进行验证。在开始执行 E2E 测试之前，请更新 IP 地址。

# 执行 E2E 测试

现在我们已经完成了测试的编写，我们将执行相同的测试。在项目的根目录下打开命令提示符/终端，并运行以下命令：

```html
protractor

```

您可能会遇到一个错误，看起来像这样：

```html
// snipp
Error message: Could not find update-config.json. Run 'webdriver-
manager update' to download binaries.
// snipp

```

如果是这样，请运行以下命令：

```html
./node_modules/protractor/bin/webdriver-manager update

```

然后运行`protractor`或`./node_modules/.bin/protractor`。

然后您应该会看到浏览器启动并导航到应用程序。如果一切顺利，您应该会在命令提示符/终端中看到以下输出：

```html
![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00118.jpeg)  todoapp_v2 ./node_modules/.bin/protractor
[00:37:27] I/launcher - Running 1 instances of WebDriver
[00:37:27] I/direct - Using ChromeDriver directly...
Spec started

 Check Navigation :
![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00119.jpeg) should have `Todo App (v2)` as the title text on the Login Page
![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00119.jpeg) should be able to login with prefilled credentials
![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00119.jpeg) should be able to logout

Executed 3 of 3 specs SUCCESS in 11 secs.
[00:37:40] I/launcher - 0 instance(s) of WebDriver still running
[00:37:40] I/launcher - chrome #01 passed

```

通过这样，我们完成了对 Ionic 应用的两种主要测试。

我们要做的最后一个测试是使用 AWS 设备农场。

注意：在测试 Cordova 功能时，您可以像之前看到的那样模拟它们。我们将在执行 E2E 测试之前直接更新`app.module.ts`，而不是更新测试床。但是请记住在测试完成后将其改回来。

# 代码覆盖率

检查代码覆盖率是测试过程中非常重要的活动。代码覆盖率帮助我们了解我们编写的代码有多少被测试了。您可以参考*karma-coverage* ([`github.com/karma-runner/karma-coverage`](https://github.com/karma-runner/karma-coverage)) 模块和 *remap-istanbul* ([`github.com/SitePen/remap-istanbul`](https://github.com/SitePen/remap-istanbul)) 模块来实现代码覆盖率。

您还可以参考*如何向 Angular 2 项目添加测试覆盖报告*：[`www.angularonrails.com/add-test-coverage-report-angular-2-project/`](https://www.angularonrails.com/add-test-coverage-report-angular-2-project/) 进行进一步参考。

# AWS 设备农场

现在我们已经对我们的应用进行了单元测试和端到端测试，我们将部署应用到实际设备上并进行测试。

要在实际设备上开始测试，我们需要借用或购买这些设备，这对于一个一次性的应用来说可能并不实际。这就是设备农场的概念出现的地方。设备农场是各种设备的集合，可以通过 Web 界面访问。这些设备可以通过 Web 进行访问和测试，方式类似于在实际设备上进行测试。

市面上有很多提供按需付费设备农场的供应商。在许多设备农场的试错之后，我对 AWS 设备农场有了一些好感。它简单易用，并且在错误日志、截图和视频方面非常详细。后者真的可以帮助您在特定设备上识别终端用户或错误崩溃报告中报告的问题。

截至撰写本章的日期，AWS 每个设备每分钟收费$0.17，前 250 分钟免费。或者如果您是重度用户，您也可以根据您的使用情况订阅无限测试计划。这从每月$250 起。

在这个主题中，使用 AWS 设备农场，我们将上传我们在第八章 *Ionic 2 迁移指南*中迁移的 Todo 应用的 APK，并执行两个测试：

+   Monkey 测试应用，看看应用是否崩溃

+   在实际设备上手动测试应用

# 设置 AWS 设备农场

在我们开始在实际设备上测试之前，我们将设置一个新的 AWS 账户，如果您还没有的话。您可以转到[`aws.amazon.com/`](https://aws.amazon.com/) 进行注册和登录。

一旦您进入 AWS 控制台，从页面头部的服务选项中选择设备农场。设备农场是 AWS 区域不可知的。您不需要在特定区域才能访问它。

一旦您进入 AWS 设备农场的主页，您应该会看到一个像这样的屏幕：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00120.jpeg)

点击“开始”。这将提示我们输入项目名称。在 Device Farm 中，项目是我们要执行的测试类型、要测试的设备类型或应用程序版本的逻辑分组。

我将把我的项目命名为`Todo App v1`。当我有另一个版本时，我将把它命名为`Todo App v2`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00121.jpeg)

注意：这里的`v1`指的是我们的 Todo 应用的 v1 版本，而不是使用 Ionic v1 构建的 Todo 应用。

点击“创建项目”，你应该会进入项目主页。

# 设置 Todo 应用

现在我们准备测试我们的应用，让我们继续构建它。转到`todoapp_v2`文件夹并打开一个新的命令提示符/终端。运行`ionic platform add android`或`ionic platform add ios`，然后构建应用程序：

```html
ionic build

```

在这个例子中，我将为 Android 构建并使用 APK 进行设备测试。构建完成后，转到`todoapp_v2/platforms/android/build/outputs/apk`文件夹，你应该会找到一个名为`android-debug.apk`的文件。我们将上传这个 APK 文件进行测试。

iOS 测试的流程也类似，只是我们上传 IPA 文件。

# 对 Todo 应用进行猴子测试

猴子测试或模糊测试是一种自动化测试技术，测试执行器将输入随机输入，在应用程序或页面的随机部分执行随机点击，以查看应用程序是否崩溃。要了解更多关于猴子测试的信息，请参考：[`en.wikipedia.org/wiki/Monkey_testing`](https://en.wikipedia.org/wiki/Monkey_testing)。

Device Farm 将这作为在设备上测试应用程序的良好起点。

一旦我们进入项目主页，我们应该会看到两个选项卡：自动化测试和远程访问：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00122.jpeg)

在自动化测试选项卡上，点击“创建新运行”。在“选择您的应用程序”部分，选择您的选择，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00123.jpeg)

接下来上传 APK 或 IPA 文件。一旦应用程序成功上传，我们应该会看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00124.jpeg)

点击“下一步”。

在配置测试部分，选择内置：模糊，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00125.jpeg)

还有其他自动化测试框架，如 Appium 或 Calabash，也可以用来构建自动化测试套件。Device Farm 也支持这些框架。

点击“下一步”。

这是我们选择目标设备的地方。默认情况下，AWS Device Farm 选择顶级设备。我们可以选择这个，也可以构建自己的设备池：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00126.jpeg)

在这个例子中，我将选择顶部设备。

点击“下一步”以进入指定设备状态部分。在这里，如果需要，我们可以覆盖设备功能：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00127.jpeg)

我们将保持现状。

点击“下一步”，在这里我们设置测试的估计时间。我选择了每个设备 5 分钟，如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00128.jpeg)

点击“确认并开始运行”以启动猴子测试。这将需要大约 25 分钟才能完成。你可以去跑步，喝咖啡，做瑜伽，基本上你需要度过 25 分钟。

现在测试已经完成，你应该会看到这样的屏幕：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00129.jpeg)

看起来 Todo 应用在五台设备上通过了猴子测试。如果我们点击该行，我们应该会看到结果的深入分析：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00130.jpeg)

正如你从前面的步骤中看到的那样，我们可以查看每个设备的结果和所有设备的截图。为了获得更深入的见解，我们将点击一个设备：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00131.jpeg)

正如你从前面的图片中看到的那样，我们还可以查看测试执行视频、日志、性能和截图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00132.jpeg)

性能概述如前面的截图所示。

这有助于我们快速在各种设备上对我们的应用进行一些随机测试。

# 在各种设备上手动测试 Todo 应用

在本节中，我们将远程访问设备并在其上测试我们的应用程序。当用户报告您无法在其他设备上复制的特定设备上的错误时，此功能非常有用。

要开始手动测试，请导航到项目主页，然后单击“远程访问”选项卡。然后单击“开始新会话”按钮。

这将重定向到另一个页面，在那里我们需要选择一个设备，如图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00133.jpeg)

我选择了一个 Android 设备，并通过单击“确认并开始会话”来启动了一个新会话。这将启动一个新会话：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00134.jpeg)

一旦设备可用，我们应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00135.jpeg)

默认情况下，我们最近上传的 APK 将安装在此设备上。否则，您可以使用右上角的“安装应用程序”来安装特定应用程序，如前面的屏幕截图所示。

我已经从菜单中导航到`TodoApp-v2`，如图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00136.jpeg)

启动应用程序后，我们可以进行登录、管理待办事项、查看通知等操作：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00137.jpeg)

测试完成后，我们可以停止会话。会话成功终止后，我们可以以可下载的格式获取日志、视频和网络流量的副本以进行进一步调试：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00138.jpeg)

通过这种方式，我们已经看到了如何在各种设备上手动测试应用程序。

# 自动化测试

除了上述测试应用的方法之外，我们还可以使用诸如 Appium（[`appium.io/`](http://appium.io/)）之类的框架构建自动化测试用例。通过使用设备农场，我们可以上传 APK 或 IPA，然后进行自动化测试套件。然后我们选择一组设备并在它们上执行测试。

您可以查阅*自动化混合应用*（[`appium.io/slate/en/master/?ruby#automating-hybrid-apps`](http://appium.io/slate/en/master/?ruby#automating-hybrid-apps)）和*使用 Smoke Tests 和 Appium 验证 Cordova 或 PhoneGap 构建*（[`ezosaleh.com/verifying-a-cordovaphonegap-build-with-smoke-tests-appium`](http://ezosaleh.com/verifying-a-cordovaphonegap-build-with-smoke-tests-appium)）来了解为混合应用编写自动化测试的想法。

如果选择，您也可以在模拟器中本地运行这些自动化测试。

# 总结

在本章中，我们已经介绍了测试的两种主要方法-单元测试和端到端测试。我们使用 Karma 和 Jasmine 对 Todo 应用进行了单元测试。我们使用 Protractor 和 Jasmine 进行了端到端测试。我们还使用了 AWS 设备农场的模糊测试来测试我们的应用，以及通过在我们选择的远程设备上安装应用程序来进行测试。

在下一章中，我们将看一下发布和管理 Ionic 应用程序。


# 第十章：发布 Ionic 应用

在本章中，我们将介绍三种为 Ionic 应用生成安装程序的方法。一种是使用 PhoneGap 构建服务，第二种是使用 Cordova CLI，最后一种是使用 Ionic 包服务。我们将为 Android 和 iOS 操作系统生成安装程序。本章将涵盖以下主题：

+   生成图标和启动屏幕

+   验证 config.xml

+   使用 PhoneGap 构建服务生成安装程序

+   使用 Cordova CLI 生成安装程序

+   使用 Ionic 包生成服务

# 为应用程序准备分发

现在我们已经成功构建了 Ionic 应用，我们希望进行分发。通过应用商店是触及更广泛受众的最佳方式。但是，在开始分发应用之前，我们将需要特定于应用的图标和启动屏幕。启动屏幕是完全可选的，取决于产品理念。

# 设置图标和启动屏幕

默认情况下，当您运行以下代码时：

```html
ionic platform add android 

```

或者

```html
ionic platform add ios

```

CLI 会自动添加一个名为资源的新文件夹。您可以在第七章中查看这一点，*构建 Riderr 应用*。资源文件夹包括 Ionic 或 Android 或两者的子文件夹，具体取决于您添加了多少个平台，在每个文件夹中，您将看到两个名为图标和启动的子文件夹。

如果您的应用程序使用启动屏幕，则可以保留启动文件夹，否则删除该文件夹以节省最终应用程序安装程序的几个字节。

要生成图标，您可以获取大于 1024 x 1024 的图标副本，并使用任何服务，例如以下服务，为 Android 和 iOS 生成图标和启动屏幕：

+   [`icon.angrymarmot.org/`](http://icon.angrymarmot.org/)

+   [`makeappicon.com/`](http://makeappicon.com/)

我与上述任何服务都没有关联。您使用这些服务需自担风险。

或者，更好的是，您可以将名为`icon.png`和`splash.png`的文件放在资源文件夹中，并运行以下代码：

```html
ionic resources 

```

这将负责将您的图像上传到 Ionic 云，根据需要调整其大小，并将其保存回资源文件夹。

请注意，您正在将内容上传到公共/ Ionic 云中。

如果您只想转换图标，可以使用以下方法：

```html
ionic resources --icon

```

如果只需要启动屏幕，可以使用以下方法：

```html
ionic resources --splash

```

您可以使用[`code.ionicframework.com/resources/icon.psd`](http://code.ionicframework.com/resources/icon.psd)来设计您的图标，使用[`code.ionicframework.com/resources/splash.psd`](http://code.ionicframework.com/resources/splash.psd)来设计您的启动屏幕。

您可以将`icon.png`图像，`icon.psd`文件或 icon.ai 文件放在资源文件夹的根目录，ionic 资源将会自动处理！

# 更新 config.xml

+   正如我们已经知道的那样，`config.xml`是 Cordova API 信任的唯一真相来源，用于生成特定于操作系统的安装程序。因此，在我们开始部署过程之前，需要对此文件进行彻底验证。您可以按照清单来确保所有事情都就绪：

+   小部件 ID 已定义并有效

+   小部件版本已定义并有效

+   在应用更新的情况下，小部件版本已更新并有效

+   名称标签已定义并有效

+   描述已定义并有效

+   作者信息已定义并有效

+   访问标签已定义并且限制在所需的域内（[`github.com/apache/cordova-plugin-whitelist#network-request-whitelist`](https://github.com/apache/cordova-plugin-whitelist#network-request-whitelist)）

+   允许导航已定义并且限制在所需的域内（[`github.com/apache/cordova-plugin-whitelist#navigation-whitelist`](https://github.com/apache/cordova-plugin-whitelist#navigation-whitelist)）

+   允许意图已定义并且限制在所需的域内（[`github.com/apache/cordova-plugin-whitelist#intent-whitelist`](https://github.com/apache/cordova-plugin-whitelist#intent-whitelist)）

+   交叉检查偏好设置

+   交叉检查图标和启动图片的路径

+   交叉检查权限（如果有的话）

+   使用内容安全策略元标记（[`github.com/apache/cordova-plugin-whitelist#content-security-policy`](https://github.com/apache/cordova-plugin-whitelist#content-security-policy)）更新`index.html`

一旦以上点都经过验证，我们将开始安装程序生成过程。

# PhoneGap 构建服务

我们将首先看一下使用 PhoneGap 构建服务生成应用程序安装程序的方法。这可能是为 Android 和 iOS 生成安装程序的最简单方法。

这个过程非常简单。我们将整个项目上传到 PhoneGap 构建服务，它会负责构建安装程序。

如果你认为上传完整项目不切实际，你可以只上传`www`文件夹。但是，你需要做以下更改。

1.  将`config.xml`移动到`www`文件夹内。

1.  将资源文件夹移动到`www`文件夹内。

1.  在`config.xml`中更新资源文件夹的路径。

如果你经常做以上操作，我建议使用一个构建脚本来生成一个带有以上更改的 PhoneGap 构建`Deployable`文件夹。

如果你计划只为 Android 发布你的应用程序，你不需要做任何其他事情。但是，如果你计划生成 iOS 安装程序，你需要获得一个苹果开发者账户，并按照[`docs.build.phonegap.com/en_US/signing_signing-ios.md.html`](http://docs.build.phonegap.com/en_US/signing_signing-ios.md.html)中的步骤生成所需的证书。

你也可以按照[`docs.build.phonegap.com/en_US/signing_signing-android.md.html`](http://docs.build.phonegap.com/en_US/signing_signing-android.md.html)中提到的步骤签署你的 Android 应用程序。

一旦你拥有所需的证书和密钥，我们就可以开始生成安装程序了。你可以按照以下步骤使过程变得简单：

1.  创建一个 PhoneGap 账户并登录（[`build.phonegap.com/plans`](https://build.phonegap.com/plans)）

1.  接下来，转到[`build.phonegap.com/people/edit`](https://build.phonegap.com/people/edit)，选择 Signing Keys 选项卡，并上传 iOS 和 Android 证书。

1.  接下来，转到：[`build.phonegap.com/apps`](https://build.phonegap.com/apps)，点击 New App。作为*免费计划*的一部分，只要从公共 Git 存储库中拉取，你可以拥有尽可能多的应用。或者，你可以从私有存储库创建私有应用，或者通过上传 ZIP 文件创建。

1.  为了测试服务，你可以创建一个`.zip`文件（不是`.rar`或`.7z`），具有以下文件夹结构：

+   `App`（根文件夹）

+   `config`.xml

+   `resources`（文件夹）

+   `www`（文件夹）

这就是 PhoneGap 构建工作所需的一切。

1.  将 ZIP 文件上传到[`build.phonegap.com/apps`](https://build.phonegap.com/apps)并创建应用程序。

这个过程通常需要大约一分钟来完成它的魔力。

有时，你可能会从构建服务中看到意外的错误。等一会儿，然后再试一次。根据流量的不同，有时构建过程可能会比预期的时间长一些。

# 使用 Cordova CLI 生成安装程序

我们将看一下使用 Cordova CLI 创建安装程序。

# Android 安装程序

首先，我们将看一下使用 CLI 为 Android 生成安装程序。你可以按照以下步骤进行：

1.  在项目的根目录打开一个新的命令提示符/终端。

1.  使用以下命令移除不需要的插件：

```html
 ionic plugin rm cordova-plugin-console

```

1.  使用以下命令在发布模式下构建应用程序：

```html
      cordova build --release android

```

这将在发布模式下生成一个未签名的安装程序，并将其放置在`<<ionic project>>/platforms/android/build/outputs/apk/android-release-unsigned.apk`。

1.  接下来，我们需要创建一个签名密钥。如果你已经有一个签名密钥，或者你正在更新一个现有的应用程序，你可以跳过下一步。

1.  私钥是使用 keytool 生成的。我们将创建一个名为 deploy-keys 的文件夹，并将所有这些密钥保存在那里。创建文件夹后，运行`cd`命令进入文件夹并运行以下命令：

```html
      keytool -genkey -v -keystore app-name-release-key.keystore -alias 
      alias_name -keyalg RSA -keysize 2048 -validity 10000 

```

您将被问到以下问题，您可以按照所示回答：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00139.jpeg)

如果您丢失了此文件，您将永远无法提交更新到应用商店。

注意：要了解有关 keytool 和签名过程的更多信息，请参阅[`developer.android.com/studio/publish/app-signing.html`](https://developer.android.com/studio/publish/app-signing.html)。

1.  这是一个可选步骤，您也可以将`android-release-unsigned.apk`复制到`deploy-keys`文件夹中，并从那里运行以下命令。我会把文件留在原地。

1.  接下来，我们使用 jarsigner 工具对未签名的 APK 进行签名：

```html
      jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore app-name-
      release-key.keystore ../platforms/android/build/outputs/apk/android-
      release-unsigned.apk my-ionic-app

```

将要求输入密码，这是您在创建密钥库时的第一步输入的密码。签名过程完成后，现有的`android-release-unsigned.apk`将被替换为同名的已签名版本。

我们正在从 deploy-keys 文件夹内运行上述命令。

1.  最后，我们运行`zipalign`工具来优化 APK：

```html
      zipalign -v 4 ../platforms/android/build/outputs/apk/android-release-
      unsigned.apk my-ionic-app.apk

```

上述命令将在`deploy-keys`文件夹中创建`my-ionic-app.apk`。

现在，您可以将此 APK 提交到应用商店。

# iOS 安装程序

接下来，我们将使用 XCode 为 iOS 生成安装程序。您可以按照给定的步骤进行：

1.  在项目的根目录打开新的命令提示符/终端。

1.  删除不需要的插件：

```html
 ionic plugin rm cordova-plugin-console

```

1.  运行：

```html
 ionic build -release ios

```

1.  导航到 platforms/iOS 并使用 XCode 启动`projectname.xcodeproj`。

1.  一旦项目在 XCode 中，选择产品，然后从导航菜单中选择存档。

1.  接下来，选择窗口并从导航菜单中选择组织者。您将看到一个创建的存档列表。

1.  点击我们现在创建的快照存档，然后点击提交。进行帐户验证，然后应用将被上传到 iStore。

1.  最后，您需要登录 iTunes 商店设置截图、描述等。

这结束了使用 Cordova CLI 生成安装程序的过程。

# 离子包

在本节中，我们将看一下 Ionic Package。

# 上传项目到 Ionic 云

使用 Ionic 云服务生成安装程序非常简单。首先，我们通过运行以下命令将我们的应用上传到我们的 Ionic 帐户：

```html
ionic upload

```

在执行上述命令之前，请登录您的 Ionic 帐户。

如果您的项目涉及敏感信息，请在将应用上传到云之前与 Ionic 许可证进行交叉检查。

上传应用后，将为您的应用生成一个应用 ID。您可以在项目根目录下的`ionic.config.json`文件中找到应用 ID。

# 生成所需的密钥

您需要按照“使用 Cordova CLI 生成安装程序”部分的第 5 步，Android 安装程序子部分，获取密钥库文件。

接下来，我们使用 ionic package 命令生成安装程序：

```html
ionic package <command> [options]

```

选项将包括以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00140.jpeg)

例如，如果您想要以发布模式为 Android 生成安装程序，将如下所示：

```html
ionic package release android -k app-name-release-key.keystore -a my-ionic-app -w 12345678 -r 12345678 -o ./ -e arvind.ravulavaru@gmail.com -p 12345678

```

我们正在从 deploy-keys 文件夹内运行上述命令。

同样，iOS 的上述命令将如下所示：

```html
ionic package release ios -c certificate-file -d password -f profilefile -o ./ -e arvind.ravulavaru@gmail.com -p 12345678

```

# 摘要

在本章中，我们看到了如何发布和管理 Ionic 应用。我们看到了如何使用 PhoneGap 构建服务、使用 Cordova CLI 以及最后使用 Ionic Package 生成安装程序。

在下一章中，我们将看一下 Ionic 3 和 Ionic 2 与 Ionic 3 之间的主要区别。

请注意，到目前为止我们学到的几乎所有概念在 Ionic 3 中仍然适用。


# 第十一章：Ionic 3

在《学习 Ionic，第二版》的最后一章中，我们将看一下 Ionic 框架的最新变化--Ionic 3。我们还将简要介绍 Angular 及其发布。在本章中，我们将讨论以下主题：

+   Angular 4

+   Ionic 3

+   Ionic 3 的更新

+   Ionic 2 与 Ionic 3

# Angular 4

自 Angular 2 发布以来，Angular 团队一直致力于使 Angular 成为一个稳定可靠的应用程序框架。2017 年 3 月 23 日，Angular 团队发布了 Angular 4。

什么？Angular 4？Angular 3 怎么了！！

简而言之，Angular 团队采用了语义化版本控制（[`semver.org/`](http://semver.org/)）来管理框架内所有包和依赖关系。在这个过程中，其中一个包（`@angular/router`）已经完全升级了一个主要版本，类似于以下情况，由于路由包的更改。：

| **框架** | **版本** |
| --- | --- |
| `@angular/core` | v2.3.0 |
| `@angular/compiler` | v2.3.0 |
| `@angular/compiler-cli` | v2.3.0 |
| `@angular/http` | v2.3.0 |
| `@angular/router` | V3.3.0 |

由于这种不一致性和为了避免未来的混淆，Angular 团队选择了 Angular 4 而不是 Angular 3。

此外，未来 Angular 版本的**暂定发布时间表**如下所示：

| **版本** | **发布日期** |
| --- | --- |
| Angular 5 | 2017 年 9 月/10 月 |
| Angular 6 | 2018 年 3 月 |
| Angular 7 | 2018 年 9 月/10 月 |

您可以在[`angularjs.blogspot.in/2016/12/ok-let-me-explain-its-going-to-be.html`](http://angularjs.blogspot.in/2016/12/ok-let-me-explain-its-going-to-be.html)上了解更多信息。

随着 Angular 4 的发布，一些重大的底层变化已经发生。以下是 Angular 4 的更新：

+   更小更快，生成的代码更小

+   `Animation`包的更新

+   `*ngIf`和`*ngFor`的更新

+   升级到最新的 TypeScript 版本

要了解更多关于此版本的信息，请参阅[`angularjs.blogspot.in/2017/03/angular-400-now-available.html`](http://angularjs.blogspot.in/2017/03/angular-400-now-available.html)。

由于 Ionic 遵循 Angular，他们已经将 Ionic 框架从版本 2 升级到版本 3，以将其基本 Angular 版本从 2 升级到 4。

# Ionic 3

随着 Angular 4 的发布，Ionic 已经升级并转移到了 Ionic 3。

Ionic 版本 3（[`blog.ionic.io/ionic-3-0-has-arrived/`](https://blog.ionic.io/ionic-3-0-has-arrived/)）增加了一些新功能，如 IonicPage 和 LazyLoading。他们还将基本版本的 Angular 更新到了版本 4，并发布了一些关键的错误修复。有关更多信息，请参阅 3.0.0 的变更日志：[`github.com/driftyco/ionic/compare/v2.3.0...v3.0.0`](https://github.com/driftyco/ionic/compare/v2.3.0...v3.0.0)。

Ionic 2 到 Ionic 3 的变化并不像我们从 Ionic 1 到 Ionic 2 看到的那样是破坏性的。Ionic 3 的变化更多地是增强和错误修复，这是在 Ionic 2 的基础上进行的。

# Ionic 3 的更新

现在，我们将看一下 Ionic 3 的一些关键更新。

# TypeScript 更新

对于 Ionic 3 的发布，Ionic 团队已经将 TypeScript 的版本更新到了最新版本。最新版本的 TypeScript 在构建时间和类型检查等方面有所增强。有关 TypeScript 更新的完整列表，请参阅 TypeScript 2.2 发布说明：[`www.typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html`](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-2-2.html)。

# Ionic 页面装饰器

Ionic 页面装饰器有助于更好地实现深度链接。如果你还记得我们在第四章中的导航示例，*Ionic 装饰器和服务*，我们在使用 Nav Controller 推送和弹出页面时引用了实际的类名。

我在这里指的是`example9/src/pages/home/home.ts`：

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 
import { AboutPage } from '../about/about'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 

  constructor(public navCtrl: NavController) {} 

  openAbout(){ 
   this.navCtrl.push(AboutPage); 
  } 
} 

```

我们可以使用`@IonicPage`装饰器来实现相同的功能，如图所示。

让我们更新`example9/src/pages/about/about.ts`，如图所示：

```html
import { Component } from '@angular/core'; 
import { NavController, IonicPage } from 'ionic-angular'; 

@IonicPage({ 
   name : 'about' 
}) 
@Component({ 
  selector: 'page-about', 
  templateUrl: 'about.html' 
}) 
export class AboutPage { 

  constructor(public navCtrl: NavController) {} 

  goBack(){ 
   this.navCtrl.pop(); 
  } 
} 

```

请注意，`@IonicPage`装饰器已经添加到`@Component`装饰器中。现在，我们将更新`example9/src/pages/home/home.ts`，如图所示：

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 

  constructor(public navCtrl: NavController) {} 

  openAbout(){ 
   this.navCtrl.push('about'); 
  } 
} 

```

请注意`this.navCtrl.push()`的更改。现在，我们不再传递类的引用，而是传递了我们在`example9/src/pages/about/about.ts`中的`@IonicPage`装饰器属性的名称。此外，现在页面将在 URL 中添加名称，即[`localhost:8100/#/about`](http://localhost:8100/#/about)。

要了解更多关于 Ionic 页面装饰器的信息，请访问[`ionicframework.com/docs/api/navigation/IonicPage`](http://ionicframework.com/docs/api/navigation/IonicPage)。

还要查看 IonicPage 模块[`ionicframework.com/docs/api/IonicPageModule/`](http://ionicframework.com/docs/api/IonicPageModule/)，将多个页面/组件捆绑到一个子模块中，并在`app.module.ts`的`@NgModule`中引用相同的内容。

# 懒加载

懒加载是 Ionic 3 发布的另一个新功能。懒加载让我们在需要时才加载页面。这将改善应用程序的启动时间并提高整体体验。

您可以通过访问[`docs.google.com/document/d/1vGokwMXPQItZmTHZQbTO4qwj_SQymFhRS_nJmiH0K3w/edit`](https://docs.google.com/document/d/1vGokwMXPQItZmTHZQbTO4qwj_SQymFhRS_nJmiH0K3w/edit)来查看在 Ionic 应用程序中实现懒加载的过程。

在撰写本章时，Ionic 3 已经发布了大约一周。CLI 和脚手架应用程序中存在一些问题/不一致。希望这些问题在书籍发布时能够得到解决。

# Ionic 2 与 Ionic 3

在本书中，所有示例都是以 Ionic 2 为目标编写的。话虽如此，如果您使用 Ionic 3 开发您的 Ionic 应用程序，代码应该不会有太大变化。在所有脚手架应用程序中，您将注意到一个关键的区别是引入了 IonicPage 装饰器和 IonicPage 模块。

您可以随时参考 Ionic 文档，以获取有关这些 API 的最新版本的更多信息。

# 总结

通过这一点，我们结束了我们的 Ionic 之旅。

简而言之，我们从理解为什么选择 Angular、为什么选择 Ionic 和为什么选择 Cordova 开始。然后，我们看到移动混合应用程序的工作原理以及 Cordova 和 Ionic 的适用性。接下来，我们看了 Ionic 的各种模板，并了解了 Ionic 组件、装饰器和服务。之后，我们看了 Ionic 应用程序的主题设置。

接下来，我们学习了 Ionic Native，并了解了如何使用它。利用这些知识，我们构建了一个 Riderr 应用程序，该应用程序实现了 REST API，使用 Ionic Native 与设备功能进行交互，并让您感受到可以使用 Ionic 构建的完整应用程序的感觉。

之后，我们看了迁移 Ionic 1 应用程序到 Ionic 2 以及如何测试 Ionic 2 应用程序。在第十章，*发布 Ionic 应用程序*，我们看到了如何发布和管理我们的应用程序。

在本章中，我们看到了 Ionic 3 的关键变化。

查看附录获取更多有用信息和一些可以在生产应用程序中进行测试/使用的 Ionic 服务。


# 附录

本书的主要目的是让读者尽可能熟悉 Ionic。因此，我从第一章到第十一章采用了渐进式的方法，从 Cordova 的基础知识到使用 Angular Ionic 和 Cordova 构建应用程序。我们非常专注于学习 Ionic 的最低要求。

在本附录中，我将展示一些您可以探索的 Ionic CLI 和 Ionic Cloud 的更多选项。

# Ionic CLI

Ionic CLI 每天都在变得更加强大。由于我们在整本书中一直在使用 Ionic CLI 2.1.14，我将讨论相同的选项。Ionic CLI 2.2.2 或更高版本也应该几乎具有相同的选项。

# Ionic login

您可以通过以下三种方式之一登录到 Ionic Cloud 帐户。

首先，使用提示：

```html
ionic login

```

其次，无提示：

```html
ionic login --email arvind.ravulavaru@gmail.com --password 12345678

```

最后，使用环境变量。您可以将`IONIC_EMAIL`和`IONIC_PASSWORD`设置为环境变量，Ionic CLI 将在不提示的情况下使用它们。这可能有点不安全，因为密码将以纯文本形式存储。

注意：您需要拥有 Ionic Cloud 帐户才能成功进行身份验证。

# Ionic start

首先，我们将看一下无 Cordova 标志选项。

# 无 Cordova

start 命令是创建新的 Ionic 应用程序的最简单方式之一。在本书中，我们一直使用 start 命令来始终创建一个新的 Cordova 和 Ionic 项目。

此外，Ionic 也可以在没有 Cordova 的情况下使用。

要在没有 Cordova 的情况下创建一个 Ionic 项目，您需要使用`-w`标志或`--no-cordova`标志运行 start 命令：

```html
ionic start -a "My Mobile Web App" -i app.web.mymobile -w myMobileWebApp sidemenu

```

生成的项目应该如下所示：

```html
. 
├── bower.json 
├── gulpfile.js 
├── ionic.config.json 
├── package.json 
├── scss 
│   ├── ionic.app.scss 
├── www 
    ├── css 
    ├── img 
    ├── index.html 
    ├── js 
    ├── lib 
    ├── manifest.json 
    ├── service-worker.js 
    ├── templates

```

现在，像往常一样，您可以`cd`进入`myMobileWebApp`文件夹并运行`ionic serve`。

# 初始化支持 SCSS 的项目

初始化一个默认启用 SCSS 的项目，可以使用`-s`或`--sass`标志运行 start 命令：

```html
ionic start -a "My Sassy App" -i app.my.sassy --sass mySassyApp blank

```

注意：此命令在编写代码的当天不起作用。

# 列出所有 Ionic 模板

要查看所有可用模板的列表，请使用`-l`或`--list`标志运行 Ionic start：

```html
ionic start -l

```

截至今天，这些是可用的模板：

```html
    blank ................ A blank starter project for Ionic
complex-list ......... A complex list starter template
maps ................. An Ionic starter project using Google Maps 
    and a side menu
salesforce ........... A starter project for Ionic and Salesforce
sidemenu ............. A starting project for Ionic using a side 
    menu with navigation in the content area
tabs ................. A starting project for Ionic using a simple 
    tabbed interface
tests ................ A test of different kinds of page navigation 

```

# 应用 ID

如果您使用 Ionic Cloud 服务，您将为在云上创建的每个项目分配一个应用 ID（有关更多信息，请参阅本章中的 Ionic Cloud 部分）。此应用 ID 将驻留在项目根目录下的`ionic.config.json`文件中。

当您创建一个新项目时，应用 ID 为空。如果您想将当前创建的项目与云上现有的应用关联起来，可以使用`--io-app-id`标志运行 start 命令，并将其传递给云生成的应用 ID：

```html
ionic start -a "My IonicIO App" -i app.io.ionic --io-app-id "b82348b5" myIonicIOApp blank

```

现在，`ionic.config.json`应该如下所示：

```html
    {
 "name": "My IonicIO App",
 "app_id": "b82348b5"
}

```

# Ionic link

可以随时通过运行以下命令将本地创建的项目链接到云项目（有关更多信息，请参阅本章中的 Ionic Cloud 应用程序部分）：

```html
ionic link b82348b5

```

或者，您可以通过运行以下命令删除现有的应用 ID：

```html
ionic link --reset

```

# Ionic info

要查看已安装的库及其版本，请运行此命令：

```html
ionic info

```

信息应该如下所示：

```html
Cordova CLI: 6.4.0  
Ionic CLI Version: 2.1.14 
Ionic App Lib Version: 2.1.7 
ios-deploy version: 1.8.4  
ios-sim version: 5.0.6  
OS: macOS Sierra 
Node Version: v6.10.1 
Xcode version: Xcode 8.2.1 Build version 8C1002

```

# Ionic state

使用 Ionic state 命令，您可以管理 Ionic 项目的状态。假设您正在为 Ionic 应用程序测试一些插件和平台。但是，如果它们失败，您不想使用它们。在这种情况下，您将使用保存和恢复命令。

您可以通过使用`--nosave`标志将插件或平台避免保存到`package.json`文件中：

```html
ionic plugin add cordova-plugin-console --nosave

```

现在，您已经使用`--nosave`标志测试了您的应用程序，并且一切似乎都很正常。现在，您想将它们添加到您的`package.json`，您可以运行：

```html
ionic state save

```

此命令查找您安装的插件和平台，然后将所需的信息添加到`package.json`文件中。您还可以选择仅通过分别使用`--plugins`或`--platforms`标志运行前述命令来保存插件或平台。

一旦您添加了一堆插件，事情并不如预期那样工作，您可以通过运行以下命令重置到先前的状态：

```html
ionic state reset

```

如果您想将应用程序恢复到 Cordova 插件和平台列表中，您可以在`package.json`中更新相同并运行：

```html
ionic state restore

```

注意：`reset`命令会删除`platforms`和`plugins`文件夹并重新安装它们，而`restore`只会在`platforms`和`plugins`文件夹中恢复丢失的平台和插件。

# Ionic 资源

当您添加新平台时，默认情况下会创建`resources`文件夹，并为给定平台创建图标和启动画面。这些图标和启动画面是默认图像。如果您想要为项目使用您的标志或图标，您只需要运行 Ionic 资源命令。

此命令将在`resources`文件夹中查找名为`icon.png`的图像，以为该操作系统的所有设备创建图标，并在`resources`文件夹中查找名为`splash.png`的图像，以为该操作系统的所有设备创建启动画面。

您可以用您的品牌图像替换这两个图像并运行：

```html
    ionic resources

```

如果您只想转换图标，可以传入`-i`标志，如果只想转换启动画面，则可以传入`-s`标志。

注意：您还可以使用`.png`和`.psd`（示例模板：[`code.ionicframework.com/resources/icon.psd`](http://code.ionicframework.com/resources/icon.psd)和[`code.ionicframework.com/resources/splash.psd`](http://code.ionicframework.com/resources/splash.psd)）或`.ai`文件来生成图标。您可以在此处找到更多信息：[`blog.ionic.io/automating-icons-and-splash-screens/`](http://blog.ionic.io/automating-icons-and-splash-screens/)。

# Ionic 服务器，模拟和运行

Ionic 提供了一种在浏览器、模拟器和设备中运行 Ionic 应用程序的简便方法。这三个命令中的每一个都带有一堆有用的选项。

如果您希望在调试时在模拟器和实际设备上运行实时重新加载，则可以使用`-l`标志进行实时重新加载，并使用`-c`启用在提示中打印 JavaScript 控制台错误。这绝对是 Ionic CLI 中最好且最常用的实用程序。此命令可以节省至少 30%的调试时间：

```html
ionic serve -l -c
ionic emulate -l -c
ionic run -l -c

```

在使用 Ionic serve 时，您可以使用以下标志：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00141.jpeg)

如果您的应用程序在 Android 和 iOS 上具有不同的外观和感觉，您可以通过运行同时测试这两个应用程序：

```html
ionic serve --lab

```

您可以根据需要浏览先前列出的其他选项。

在使用 Ionic run 和 emulate 时，您可以使用以下选项：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00142.jpeg)

这是相当不言自明的。

# Ionic 上传和共享

您可以通过运行将当前的 Ionic 项目上传到您的 Ionic Cloud 帐户：

```html
ionic upload

```

注意：您需要拥有 Ionic Cloud 帐户才能使用此功能。

一旦应用程序上传完成，您可以前往[`apps.ionic.io/apps`](https://apps.ionic.io/apps)查看新更新的应用程序。您可以使用共享命令与任何人分享此应用程序，并传递预期人员的电子邮件地址：

```html
ionic share arvind.ravulavaru@gmail.com

```

# Ionic 帮助和文档

随时可以通过运行查看所有 Ionic CLI 命令的列表：

```html
ionic -h

```

您可以通过运行来打开文档页面：

```html
ionic docs

```

要查看可用文档列表，您可以运行：

```html
ionic docs ls

```

打开特定文档，您可以运行：

```html
ionic docs ionicBody

```

# Ionic Creator

如此惊人的 Ionic Creator 尚未适用于 Ionic 2。更多信息请参见：[`docs.usecreator.com/docs/ionic-2-support-roadmap`](http://docs.usecreator.com/docs/ionic-2-support-roadmap)。

# Ionic Cloud

您可以在[`apps.ionic.io/apps`](https://apps.ionic.io/apps)上创建和管理您的 Ionic 应用程序。在前述命令中，我们所指的应用程序 ID 是在使用[`apps.ionic.io/apps`](https://apps.ionic.io/apps)界面创建新应用程序时生成的应用程序 ID。

您可以通过单击[`apps.ionic.io/apps`](https://apps.ionic.io/apps)页面内的“新应用”按钮来创建新应用程序。创建应用程序后，您可以单击应用程序名称，然后将转到应用程序详细信息页面。

您可以通过单击应用程序详细信息页面上的“设置”链接来更新应用程序设置。

注意：您可以在这里阅读有关设置 Ionic 应用程序的更多信息：[`docs.ionic.io/`](http://docs.ionic.io/)。

Ionic 云还提供其他服务，如 Auth、IonicDB、Deploy、Push 和 Package。

要使用这些服务中的任何一个，我们需要首先搭建一个 Ionic 应用程序，然后通过运行以下命令将此应用程序添加到 Ionic 云中：

```html
ionic io init

```

接下来，您可以安装云客户端以与应用程序交互：

```html
npm install @ionic/cloud-angular --save

```

完成后，我们在`src/app/app.module.ts`中设置云设置：

```html
import { CloudSettings, CloudModule } from '@ionic/cloud-angular'; 

const cloudSettings: CloudSettings = { 
  'core': { 
    'app_id': 'APP_ID' 
  } 
}; 

@NgModule({ 
  declarations: [ ... ], 
  imports: [ 
    IonicModule.forRoot(MyApp), 
    CloudModule.forRoot(cloudSettings) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ ... ], 
  providers: [ ... ] 
}) 
export class AppModule {}

```

现在我们已经准备好使用 Ionic 云服务了。

# 认证

使用 Auth 服务，我们可以轻松地对用户进行各种社交服务进行身份验证。我们不仅可以使用 Google、Twitter 和 LinkedIn 等社交服务，还可以设置简单的电子邮件和密码验证。您可以在这里查看身份验证提供程序的列表：[`docs.ionic.io/services/auth/#authentication-providers`](http://docs.ionic.io/services/auth/#authentication-providers)。

使用`Auth`服务，这是我们管理身份验证的方式：

```html
import { Auth, UserDetails, IDetailedError } from '@ionic/cloud-angular'; 

@Component({ 
   selector : 'auth-page' 
}) 
export class AuthPage { 
   private testUser: UserDetails = { 'email': 'user@domain.con', 'password': 'password' }; 

    // construct 
    constructor( 
        private auth: Auth, 
        private user: User) {} 

    signup() { 
        this.auth.signup(testUser).then(() => { 
            // testUser is now registered 
            console.log(this.user) 
            this.updateLastLogin(); // update user data 
        }, (err: IDetailedError < string[] > ) => { 
            for (let e of err.details) { 
                if (e === 'conflict_email') { 
                    alert('Email already exists.'); 
                } else { 
                    // handle other errors 
                } 
            } 
        }); 
    } 

    signin() { 
        this.auth.login('basic', testUser).then(() => { 
            // testUser is now loggedIn 
        }); 
    } 

    signout() { 
        this.auth.logout(); 
    } 

    updateLastLogin() { 
        if (this.auth.isAuthenticated()) { 
            this.user.set('lastLogin', new Date()); 
        } 
    } 
}

Auth service refer to: http://docs.ionic.io/services/auth/.
```

# IonicDB

IonicDB 是一个无需担心可扩展性、数据管理和安全性的云托管实时数据库。如果您有使用 Firebase 或 Parse 的经验，IonicDB 与这些非常相似。

使用 IonicDB 的一个简单示例如下：

```html
import {Database} from '@ionic/cloud-angular'; 

@Component({ 
    selector: 'todos-page' 
}) 
export class TodosPage { 
    public todos: Array < string > ; 

    constructor(private db: Database) { 
        db.connect(); 
        db.collection('todos').watch().subscribe((todos) => { 
            this.todos = todos; 
        }, (error) => { 
            console.error(error); 
        }); 
    } 

    createTodo (todoText: string) { 
        this.db.collection('todos').store({ text: todoText, isCompleted: false }); 
    } 
}

```

有关 IonicDB 的更多选项，请参阅[`docs.ionic.io/services/database/`](http://docs.ionic.io/services/database/)。

# 部署

部署是另一个强大的服务，用户设备上安装的应用程序可以进行更新，而无需用户从应用商店更新。可以使用部署推送不涉及二进制更改的任何更改。

有关部署的更多信息，请参阅：[`docs.ionic.io/services/deploy`](http://docs.ionic.io/services/deploy)

# 推送

推送服务允许应用程序所有者向其用户发送推送通知。推送服务还允许应用程序所有者根据类型对设备进行分段和定位，并允许仅向某些段发送通知。

推送通知使用 Phonegap Push 插件（[`github.com/phonegap/phonegap-plugin-push`](https://github.com/phonegap/phonegap-plugin-push)）与 FCM（Firebase Cloud Messaging）用于 Android 和 iOS 设备的 iOS 推送。

有关推送的更多信息，请参阅：[`docs.ionic.io/services/push/`](http://docs.ionic.io/services/push/)。

# 打包

使用 Ionic 打包服务，开发人员可以为 Ionic 项目生成 APK 和 IPA，以与其他开发人员和测试人员共享。同样生成的 APK 和 IPA 也可以提交到 Play 商店和应用商店。

有关打包的更多信息，请参阅：[`docs.ionic.io/services/package/`](http://docs.ionic.io/services/package/)。

# 摘要

在《学习 Ionic，第二版》的最后一章中，我们介绍了 Ionic CLI 的一些关键功能，并介绍了 Ionic 云服务。

希望这本书给您提供了一些关于开始使用 Ionic 2 的想法。

感谢您的阅读。

--阿文德·拉夫拉瓦鲁。
