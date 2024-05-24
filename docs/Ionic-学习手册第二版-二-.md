# Ionic 学习手册第二版（二）

> 原文：[`zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60`](https://zh.annas-archive.org/md5/2E3063722C921BA19E4DD3FA58AA6A60)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Ionic 装饰器和服务

在上一章中，我们通过了一些 Ionic 组件，使用这些组件可以轻松构建时尚的移动混合应用程序。在这一章中，我们将使用 Ionic 2 的装饰器和服务。整个 Ionic 2 生态系统分为两部分：组件和服务 API。组件包括按钮、卡片和列表，正如我们在上一章中看到的，服务 API 包括平台、`config`、`NavController`、`Storage`等等。

在这一章中，我们将看一下以下主题：

+   Ionic 模块

+   组件装饰器

+   配置服务

+   平台服务

+   存储 API

# 装饰器

在我们开始使用 Ionic 内置装饰器之前，我们将快速了解装饰器是什么，以及它们如何让我们的生活变得更容易。

简单来说，装饰器是一个接受类并扩展其行为而不实际修改它的函数。

例如，如果我们有一个人类，并且我们想要向类中添加关于这个人的更多信息，比如年龄和性别，我们可以很容易地做到这一点。

以下是我们如何在 TypeScript 中编写自己的装饰器的示例：

```html
@MoreInfo({ 
    age: 5, 
    gender: 'male' 
}) 
class Person { 
    constructor(private firstName, private lastName) {} 
}

```

`MoreInfo`装饰器看起来会像这样：

```html
function MoreInfo(config) { 
    return function (target) { 
        Object.defineProperty(target.prototype, 'age', {value: () => config.age}); 
        Object.defineProperty(target.prototype, 'gender', {value: () => config.gender}); 
    } 
}

```

同样，Ionic 还提供了两个装饰器：

+   Ionic 模块或`NgModule`装饰器

+   组件装饰器

# Ionic 模块

Ionic 模块或`NgModule`装饰器引导 Ionic 应用程序。如果我们打开任何现有的 Ionic 项目并查看`src/app/app.module.ts`文件，我们会看到以下内容：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 
import { AboutPage } from '../pages/about/about'; 
import { ContactPage } from '../pages/contact/contact'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage, 
    AboutPage, 
    ContactPage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage, 
    AboutPage, 
    ContactPage 
  ], 
  providers: [{ provide: ErrorHandler, useClass: IonicErrorHandler }] 
}) 
export class AppModule { }

```

这是我们引导 Ionic 应用程序的地方。这个应用程序也可以通过在`IonicModule`上使用`forRoot`来配置。`forRoot`同时负责提供和配置服务。

在`IonicModule`上实现`forRoot`的一个示例看起来像这样：

```html
import { IonicApp, IonicModule } from 'ionic-angular'; 
import { MyApp } from './app.component'; 

@NgModule({ 
    declarations: [MyApp], 
    imports: [ 
        IonicModule.forRoot(MyApp, { 
            backButtonText: 'Go Back', 
            iconMode: 'ios', 
            modalEnter: 'modal-slide-in', 
            modalLeave: 'modal-slide-out', 
            tabsPlacement: 'bottom', 
            pageTransition: 'ios' 
        }, {}) 
    ], 
    bootstrap: [IonicApp], 
    entryComponents: [MyApp], 
    providers: [] 
})

```

平台特定的配置也可以被传递，如下所示：

```html
import { IonicApp, IonicModule } from 'ionic-angular'; 
import { MyApp } from './app.component'; 

@NgModule({ 
    declarations: [MyApp], 
    imports: [ 
        IonicModule.forRoot(MyApp, { 
            backButtonText: 'Go Back', 
            platforms: { 
                ios: { 
                    iconMode: 'ios', 
                    modalEnter: 'modal-slide-in', 
                    modalLeave: 'modal-slide-out', 
                    tabbarPlacement: 'bottom', 
                    pageTransition: 'ios-transition', 
                }, 
                android: { 
                    iconMode: 'md', 
                    modalEnter: 'modal-md-slide-in', 
                    modalLeave: 'modal-md-slide-out', 
                    tabbarPlacement: 'top', 
                    pageTransition: 'md-transition', 
                } 
            } 

        }, {}) 
    ], 
    bootstrap: [IonicApp], 
    entryComponents: [MyApp], 
    providers: [] 
})

```

您可以在[`ionicframework.com/docs/v2/api/IonicModule/`](https://ionicframework.com/docs/v2/api/IonicModule/)了解更多关于 Ionic 模块的信息，关于配置请访问：[`ionicframework.com/docs/v2/api/config/Config/`](https://ionicframework.com/docs/v2/api/config/Config/)，关于`NgModule`请访问[`angular.io/docs/ts/latest/guide/ngmodule.html`](https://angular.io/docs/ts/latest/guide/ngmodule.html)。

# 组件装饰器

`Component`装饰器标记一个类为 Angular 组件，并收集组件配置元数据。一个简单的组件装饰器看起来像这样：

```html
import { Component } from '@angular/core'; 
import { Platform } from 'ionic-angular'; 
import { StatusBar, Splashscreen } from 'ionic-native'; 

import { HomePage } from '../pages/home/home'; 

@Component({ 
  templateUrl: 'app.html' 
}) 
export class MyApp { 
  rootPage = HomePage; 

  constructor(platform: Platform) { 
    platform.ready().then(() => { 
    StatusBar.styleDefault(); 
       Splashscreen.hide(); 
    }); 
  } 
}

```

组件包括所有 Ionic 和 Angular 核心组件和指令，因此我们不需要显式声明指令属性。只有子/父组件上的依赖属性需要显式指定。

要了解更多关于`Component`装饰器的信息，请参考[`angular.io/docs/ts/latest/api/core/index/Component-decorator.html`](https://angular.io/docs/ts/latest/api/core/index/Component-decorator.html)。

# 导航

在上一章中，我们看到了在两个页面之间进行导航的基本实现。在本节中，我们将更深入地研究相同的内容。

首先，我们将脚手架一个空白的 Ionic 应用程序。创建一个名为`chapter4`的新文件夹，在该文件夹内打开一个新的命令提示符/终端，并运行以下命令：

```html
ionic start -a "Example 9" -i app.example.nine example9 blank --v2

```

一旦应用程序被脚手架化，`cd`进入`example9`文件夹。如果我们导航到`example9/src/app/app.component.ts`，我们应该看到由名为`MyApp`的类定义的 App 组件。如果我们导航到相应的模板`example9/src/app/app.html`，我们应该看到`ion-nav`组件。

`ion-nav`组件接受一个名为 root 的输入属性。root 属性指示哪个组件将充当根组件/根页面。在这个例子中，我们已经从我们的`MyApp`类(`example9/src/app/app.component.ts`)中指定了 Home Page 作为`root`。

现在我们将生成一个名为 about 的新页面，使用 Ionic CLI 的 generate 命令。运行以下命令：

```html
ionic generate page about

```

这个命令将在`src/pages`文件夹内创建一个新的组件。

如果我们查看`example9/src/pages/home/`和`example9/src/pages/about/`的内容，我们应该会看到两个独立的组件。

在我们开始将这两个页面连接在一起之前，我们首先需要使用`@NgModule`注册关于页面。打开`example9/src/app/app.module.ts`并按照以下方式更新它：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 
import { AboutPage } from '../pages/about/about'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage, 
    AboutPage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage, 
    AboutPage 
  ], 
  providers: [{provide: ErrorHandler, useClass: IonicErrorHandler}] 
}) 
export class AppModule {}

```

接下来，我们将在主页上添加一个按钮，当我们点击它时，我们将显示关于页面。按照以下方式更新`example9/src/pages/home/home.html`：

```html
<ion-header> 
  <ion-navbar> 
    <ion-title> 
      Home Page 
    </ion-title> 
  </ion-navbar> 
</ion-header> 

<ion-content padding> 
   <button ion-button color="secondary" (click)="openAbout()">Go To About</button> 
</ion-content>

```

接下来，我们将添加页面之间导航的逻辑。按照以下方式更新`example9/src/pages/home/home.ts`：

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

使用`this.navCtrl.push(AboutPage);`，我们从主页跳转到关于页面。

如果我们保存文件并执行`ionic serve`，我们应该会看到带有按钮的主页。当我们点击按钮时，我们应该会看到关于页面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00049.jpeg)

现在，如果我们想要导航回去，我们可以使用自动生成的返回按钮，或者我们可以在关于页面上创建一个按钮返回。为了做到这一点，请按照以下方式更新`example9/src/pages/about/about.html`：

```html
<ion-header> 
  <ion-navbar> 
    <ion-title>About Page</ion-title> 
  </ion-navbar> 
</ion-header> 

<ion-content padding> 
   <button ion-button color="light" (click)="goBack()">Back</button> 
</ion-content>

```

并按照以下方式更新`example9/src/pages/about/about.ts`：

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

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

请注意`this.navCtrl.pop();`--这是我们从视图中弹出页面的方法。

如果我们保存所有文件并返回浏览器，然后从主页导航到关于，我们应该会看到一个返回按钮。点击它将会带我们回到主页。

这是一个简单的例子，说明了我们如何将两个页面连接在一起。

除此之外，我们还有页面事件，指示页面的各个阶段。为了更好地理解这一点，我们将按照以下方式更新`example9/src/pages/about/about.ts`：

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 

@Component({ 
  selector: 'page-about', 
  templateUrl: 'about.html' 
}) 
export class AboutPage { 

  constructor(public navCtrl: NavController) { } 

  goBack() { 
    this.navCtrl.pop(); 
  } 

  ionViewDidLoad() { 
    console.log("About page: ionViewDidLoad Fired"); 
  } 

  ionViewWillEnter() { 
    console.log("About page: ionViewWillEnter Fired"); 
  } 

  ionViewDidEnter() { 
    console.log("About page: ionViewDidEnter Fired"); 
  } 

  ionViewWillLeave() { 
    console.log("About page: ionViewWillLeave Fired"); 
  } 

  ionViewDidLeave() { 
    console.log("About page: ionViewDidLeave Fired"); 
  } 

  ionViewWillUnload() { 
    console.log("About page: ionViewWillUnload Fired"); 
  } 

  ionViewDidUnload() { 
    console.log("About page: ionViewDidUnload Fired"); 
  } 
}

```

保存所有文件，导航到浏览器，从主页导航到关于，然后返回，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00050.jpeg)

基于此，我们可以挂接到各种事件，并在需要时采取相应的行动。

# 在页面之间传递数据

到目前为止，我们已经看到了如何从一个页面移动到另一个页面。现在，使用`NavParams`，我们将从一个页面传递数据到另一个页面。

在相同的`example9`项目中，我们将添加这个功能。在主页上，我们将呈现一个文本框，供用户输入数据。一旦用户输入数据并点击转到关于，我们将获取`textbox`的值，并将其传递到关于页面，并在关于页面中打印我们在主页上捕获的文本。

要开始，我们将按照以下方式更新`example9/src/pages/home/home.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Home Page 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <ion-list> 
        <ion-item> 
            <ion-label color="primary">Enter</ion-label> 
            <ion-input placeholder="Something..." #text></ion-input> 
        </ion-item> 
    </ion-list> 
    <button ion-button color="secondary" (click)="openAbout(text.value)">Go To About</button> 
</ion-content>

```

请注意，我们已经更新了`openAbout`方法以获取文本值。接下来，我们将更新`example9/src/pages/home/home.ts`：

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

  openAbout(text){ 
    text = text || 'Nothing was entered'; 

    this.navCtrl.push(AboutPage, { 
      data : text 
    }); 
  } 
}

```

请注意我们传递给`navCtrl`的 push 方法的第二个参数。这是我们如何从主页传递数据。现在我们将更新`example9/src/pages/about/about.ts`以捕获数据：

```html
import { Component } from '@angular/core'; 
import { NavController, NavParams } from 'ionic-angular'; 

@Component({ 
  selector: 'page-about', 
  templateUrl: 'about.html' 
}) 
export class AboutPage { 
  text: string; 

  constructor(public navCtrl: NavController, public navParams: NavParams) {  
    this.text = navParams.get('data'); 
  } 

  goBack() { 
    this.navCtrl.pop(); 
  } 

  /// SNIPP :: Page events... 
}

```

为了捕获数据，我们需要从`ionic-angular`中导入`NavParams`。并且使用`navParams.get(data);`，我们在构造函数中获取从主页传递过来的数据。

最后，为了在关于页面中显示数据，请按照以下方式更新`example9/src/pages/about/about.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title>About Page</ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <label>Text Entered : {{text}}</label> 
    <br> 
    <button ion-button color="light" (click)="goBack()">Back</button> 
</ion-content>

```

保存所有文件并返回浏览器，我们应该能够看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00051.jpeg)

现在我们知道如何将两个页面连接在一起并在它们之间传递数据。

我们可以使用`@IonicPage`装饰器实现导航和延迟加载。您可以在第十一章中找到更多关于此的信息，*Ionic 3*。

# 配置服务

该服务允许您配置和设置特定于应用程序的首选项。

为了在各种组件中跨平台或在同一平台内定制应用程序的外观和感觉，我们使用配置服务。

为了更好地理解这项服务，我们将搭建一个新的应用程序并与之一起工作。运行以下命令：

```html
ionic start -a "Example 10" -i app.example.ten example10 tabs --v2

```

然后运行`ionic serve --lab`。

这将在实验室视图中运行选项卡应用程序，我们可以在其中同时看到 Android iOS 和 Windows 应用程序。

我们还可以使用以下 URL 在三个平台视图中查看 Ionic 应用程序：

iOS：[`localhost:8100/?ionicplatform=ios`](http://localhost:8100/?ionicplatform=ios) Android：[`localhost:8100/?ionicplatform=android`](http://localhost:8100/?ionicplatform=android) Windows：[`localhost:8100/?ionicplatform=windows`](http://localhost:8100/?ionicplatform=windows)

我们应该看到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00052.jpeg)

配置设置在`@NgModule`上。如果我们打开`example10/src/app/app.module.ts`，我们应该找到`NgModule`装饰器，在其中我们可以找到`IonicModule.forRoot(MyApp)`。

简单的配置看起来像这样：

```html
//... snipp 
imports: [ 
    IonicModule.forRoot(MyApp, { 
        mode: 'md' 
    }) 
  ], 
//.. snipp

```

这将使外观和感觉默认为材料设计，而不考虑平台。我们应该能够看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00053.jpeg)

您还可以像这样设置其他配置值：

```html
//.. snipp 
imports: [ 
    IonicModule.forRoot(MyApp, { 
      backButtonText: 'Go Back', 
      iconMode: 'ios', 
      modalEnter: 'modal-slide-in', 
      modalLeave: 'modal-slide-out', 
      tabsPlacement: 'bottom', 
      pageTransition: 'ios', 
    }) 
  ], 
//... snipp

```

前面的值相当自明。

配置中的属性可以在应用程序级别、平台级别和组件级别进行覆盖。

例如，您可以在应用程序级别以及平台级别覆盖`tabberPlacement`属性，如下所示：

```html
//..snipp 
imports: [ 
    IonicModule.forRoot(MyApp, { 
      tabsPlacement: 'bottom', // bottom for all platforms 
      platforms: { 
        ios: { 
          tabsPlacement: 'top', // top only for iOS 
        } 
      } 
    }) 
  ], 
//...snipp

```

我们将看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00054.jpeg)

我们也可以在组件级别进行覆盖。更新`example10/src/pages/tabs/tabs.html`如下：

```html
<ion-tabs tabsPlacement="top"> 
  <ion-tab [root]="tab1Root" tabTitle="Home" tabIcon="home"></ion-tab> 
  <ion-tab [root]="tab2Root" tabTitle="About" tabIcon="information-circle"></ion-tab> 
  <ion-tab [root]="tab3Root" tabTitle="Contact" tabIcon="contacts"></ion-tab> 
</ion-tabs>

```

我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00055.jpeg)

为了快速测试，我们还可以在 URL 中设置配置属性，而不定义任何覆盖。例如，要测试将选项卡放在顶部时的外观，我们可以转到此 URL：[`localhost:8100/?ionicTabsPlacement=top`](http://localhost:8100/?ionicTabsPlacement=top)

我们还可以在配置中设置自定义属性，并在以后提取它们。例如，我们可以设置以下属性：

```html
config.set('ios', 'themePref', 'dark');

```

然后我们可以使用以下方法获取值：

```html
config.get('themePref');

```

我们可以从`ionic-angular`导入`config`，例如`import {Config} from 'ionic-angular';`，然后在构造函数中初始化`config`：`constructor(private config : Config) { //**// }`

# 平台服务

平台服务返回有关当前平台的可用信息。Ionic 的新版平台服务提供了更多信息，帮助我们根据设备类型定制应用程序。

为了更好地了解平台服务，我们将创建一个空白应用程序。运行以下命令：

```html
ionic start -a "Example 11" -i app.example.eleven example11 blank --v2

```

然后运行`ionic serve`启动空白应用程序。

现在我们将在`example11/src/pages/home/home.ts`中添加对 Platform 类的引用。更新`home.ts`如下：

```html
import { Component } from '@angular/core'; 
import { Platform } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  constructor(public platform: Platform) {} 
}

```

现在我们将开始使用`Platform`类的各种功能。

我们要查看的第一个是`userAgent`字符串。要访问`userAgent`，我们可以在平台上执行`userAgent()`。

更新`example11/src/pages/home/home.html`内容部分如下：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Ionic Blank 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <ion-card> 
        <ion-card-header> 
            Platform : User Agent 
        </ion-card-header> 
        <ion-card-content> 
            {{platform.userAgent()}} 
        </ion-card-content> 
    </ion-card> 
</ion-content>

```

我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00056.jpeg)

接下来，我们将找出应用程序正在运行的平台；为此，我们将更新`home.html`中的`ion-content`内容如下：

```html
<ion-card> 
    <ion-card-header> 
      Platform : platformName 
    </ion-card-header> 
    <ion-card-content> 
      <ion-list> 
        <ion-item> 
          android : {{platform.is('android')}} 
        </ion-item> 
        <ion-item> 
          cordova : {{platform.is('cordova')}} 
        </ion-item> 
        <ion-item> 
          core : {{platform.is('core')}} 
        </ion-item> 
        <ion-item> 
          ios : {{platform.is('ios')}} 
        </ion-item> 
        <ion-item> 
          ipad : {{platform.is('ipad')}} 
        </ion-item> 
        <ion-item> 
          iphone : {{platform.is('iphone')}} 
        </ion-item> 
        <ion-item> 
          mobile : {{platform.is('mobile')}} 
        </ion-item> 
        <ion-item> 
          mobileweb : {{platform.is('mobileweb')}} 
        </ion-item> 
        <ion-item> 
          phablet : {{platform.is('phablet')}} 
        </ion-item> 
        <ion-item> 
          tablet : {{platform.is('tablet')}} 
        </ion-item> 
        <ion-item> 
          windows : {{platform.is('windows')}} 
        </ion-item> 
      </ion-list> 
    </ion-card-content> 
  </ion-card>

```

当浏览器刷新时，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00057.jpeg)

正如我们从屏幕截图中看到的，当在浏览器中运行时，前面的平台名称是这些值。

现在，让我们添加浏览器平台并查看是否有任何更改。运行以下命令：

```html
ionic platform add browser 

```

然后运行：

```html
ionic run browser

```

您应该能够在浏览器中看到 Ionic 应用程序启动，并且现在输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00058.jpeg)

如果我们仔细观察，我们可以看到在前面的屏幕截图中，`cordova`现在设置为`true`。

使用前面的平台名称，我们可以轻松定制应用程序并调整用户体验。

要了解有关平台服务的更多信息，请参阅[`ionicframework.com/docs/api/platform/Platform/`](http://ionicframework.com/docs/api/platform/Platform/)

# 存储服务

在本节中，我们将研究存储服务。Ionic 的 Storage 类帮助我们与应用程序在原生容器中运行时可用的各种存储选项进行交互。

引用 Ionic 文档：

Storage 是一种存储键/值对和 JSON 对象的简单方法。Storage 在底层使用各种存储引擎，根据平台选择最佳的存储引擎。

在本机应用上下文中运行时，Storage 将优先使用 SQLite，因为它是最稳定和广泛使用的基于文件的数据库之一，并且避免了一些像 localstorage 和 IndexedDB 这样的问题，比如操作系统决定在低磁盘空间情况下清除这些数据。

在 Web 或作为渐进式 Web 应用运行时，Storage 将尝试使用 IndexedDB、WebSQL 和 localstorage，按照这个顺序。

现在，要开始使用 Storage 类，我们将创建一个新的应用。运行以下命令：

```html
ionic start -a "Example 12" -i app.example.twelve example12 blank --v2 

```

然后运行`ionic serve`在浏览器中启动它。

为了了解如何使用 Storage，我们将构建一个简单的用户管理应用。在这个应用中，我们可以添加用户，将数据持久化存储，然后稍后删除它。这个应用的主要目的是探索 Storage 类。

最终的应用将看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00059.jpeg)

在开始使用`Storage`类之前，我们需要将其添加到我们的`Ionic`项目中。运行以下命令：

```html
npm install --save @ionic/storage

```

接下来，我们需要将其添加为提供者。按照以下方式更新`example12/src/app/app.module.ts`：

```html
import { BrowserModule } from '@angular/platform-browser'; 
import { ErrorHandler, NgModule } from '@angular/core'; 
import { IonicApp, IonicErrorHandler, IonicModule } from 'ionic-angular'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { StatusBar } from '@ionic-native/status-bar'; 

import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 
import { IonicStorageModule } from '@ionic/storage'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
  ], 
  imports: [ 
    BrowserModule, 
    IonicModule.forRoot(MyApp), 
    IonicStorageModule.forRoot() 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    {provide: ErrorHandler, useClass: IonicErrorHandler} 
  ] 
}) 
export class AppModule {}

```

接下来，我们将构建界面。打开`example12/src/pages/home/home.html`。首先我们将更新头部如下：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Manage Users 
        </ion-title> 
    </ion-navbar> 
</ion-header>

```

接下来，在内容部分，我们将创建两个部分，一个用于用户输入姓名和年龄的表单，另一个用于显示用户列表的部分：

```html
<ion-content padding> 
    <div> 
        <ion-list> 
            <ion-item> 
                <ion-label fixed>Name</ion-label> 
                <ion-input type="text" placeholder="Enter Name" #name>
                </ion-input> 
            </ion-item> 
            <ion-item> 
                <ion-label fixed>Age</ion-label> 
                <ion-input type="number" placeholder="Enter Age" #age> 
                </ion-input> 
            </ion-item> 
        </ion-list> 
        <button ion-button full color="primary" (click)="addUser(name, 
        age)" [disabled]="!name.value || !age.value">Create 
        User</button> 
    </div> 
    <div *ngIf="users.length > 0"> 
        <h3 style="text-align: center;" padding>Users</h3> 
        <ion-card *ngFor="let user of users"> 
            <ion-card-content> 
                <ion-label>Name : {{user.name}}</ion-label> 
                <ion-label>Age : {{user.age}}</ion-label> 
                <button ion-button color="danger" 
                (click)="removeUser(user)">Delete User</button> 
            </ion-card-content> 
        </ion-card> 
    </div> 
</ion-content>

```

接下来，我们将开始处理逻辑。按照以下方式更新`example12/src/pages/home/home.ts`：

```html
import { Component } from '@angular/core'; 
import { NavController } from 'ionic-angular'; 
import { Storage } from '@ionic/storage'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  users: any[] = []; 

  constructor(private navCtrl: NavController, private storage: Storage) { 
    // get all the users from storage on load 
    this.getUsers(); 
  } 

  getUsers() { 
    this.storage.ready().then(() => { 
      this.storage.forEach((v, k, i) => { 
        if (k.indexOf('user-') === 0) { 
          this.users.push(v); 
        } 
      }); 
    }); 
  } 

  addUser(name, age) { 
    this.storage.ready().then(() => { 
      let user = { 
        id: this.genRandomId(), 
        name: name.value, 
        age: age.value 
      }; 
      // save it to the storage 
      this.storage.set('user-' + user.id, user); 
      // update the inmemory variable to refresh the UI 
      this.users.push(user); 
      // reset the form 
      name.value = ''; 
      age.value = ''; 
    }); 
  } 

  removeUser(user) { 
    this.storage.ready().then(() => { 
      // remove from storage 
      this.storage.remove('user-' + user.id); 
      // update the inmemory variable to refresh the UI 
      this.users.splice(this.users.indexOf(user), 1); 
    }); 
  } 

  genRandomId() { 
    return Math.floor(Math.random() * 9999); // up to 4 digits random number 
  } 

}

```

在上面的代码中，首先我们从`@ionic/storage`中导入了`Storage`。接下来，在构造函数中实例化了相同的内容。

我们创建了一个名为`users`的类变量，用于在内存中存储我们创建的所有用户。在构造函数内部，我们调用`getUsers()`来在加载时从存储中获取用户。我们创建了两个函数，`addUser()`和`removeUser()`，用于添加用户和删除用户。

由于存储是一个键值存储，我们使用用户的 ID 创建存储的键。例如，如果用户的 ID 是 1，我们将键创建为`user-1`。这样，我们知道存储中属于我们应用的所有键都以*user*开头，以防其他实体在同一个应用中使用 Storage。

我们使用`genRandomId()`来生成一个 1 到 9999 之间的随机数。

如果我们保存所有文件，返回浏览器，并打开控制台，我们应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00060.jpeg)

请注意控制台中的消息。这条消息告诉我们数据将被存储在 asynStorage 中。因此，在 Chrome 中，它将是 IndexedDB。

因此，在 Chrome 中，如果我们在开发工具中点击应用程序选项卡并导航到 IndexedDB，我们应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00061.jpeg)

现在，让我们使用表单添加一个用户。更新后的屏幕和存储应该如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00062.jpeg)

现在，点击删除后，我们应该看到存储已清除，并且 UI 更新后没有任何用户。

因此，使用存储，我们可以在 Ionic 应用中轻松开始处理数据持久性，而不必担心底层实现。

如果需要，我们可以覆盖`IonicStorageModule.forRoot()`如下：

```html
IonicStorageModule.forRoot({
  name: 'appDB',
  driverOrder: ['indexeddb', 'sqlite', 'websql']
})

```

您可以在这里找到更多配置和属性：[`ionicframework.com/docs/storage/`](https://ionicframework.com/docs/storage/)

通过这样，我们完成了 Ionic 中 Storage 的概述。

# 摘要

在本章中，我们已经介绍了 Ionic 的两个主要装饰器。然后我们介绍了配置和平台服务，并看到了如何根据平台和配置自定义应用程序。之后，我们介绍了 Ionic 中的存储 API。请参考第十一章，*Ionic 3*，了解全新的`IonicPage`指令和`IonicPage`模块。

在下一章中，我们将学习如何为 Ionic 应用创建主题。


# 第五章：Ionic 和 SCSS

在本章中，我们将介绍使用 Ionic 进行主题设置。Ionic 中的主题设置简单且易于实现。Ionic 团队在简化和模块化 Ionic 中的主题设置方面付出了很大的努力。简而言之，Ionic 中的主题设置发生在组件级别，以及平台级别（iOS、Android 和 WP）。Ionic 使用 SCSS 来处理主题设置。在本章中，我们将介绍以下主题：

+   Sass 与 SCSS

+   使用 SCSS 变量

+   平台级别和页面/组件级别的覆盖

# 什么是 Sass？

引用自 Sass 文档：

“Sass 是 CSS 的扩展，为基本语言增添了力量和优雅。”

它允许我们使用变量、嵌套规则、mixin、内联导入等，所有这些都是完全兼容 CSS 的语法。Sass 有助于保持大型样式表的良好组织，并快速启动小型样式表。

简单来说，Sass 使 CSS 可编程。但是，本章的标题是 SCSS；为什么我们要谈论 Sass 呢？嗯，Sass 和 SCSS 基本上是相同的 CSS 预处理器，每个都有自己的编写预 CSS 语法的方式。

SCSS 是作为另一个名为 HAML（[`haml.info/`](http://haml.info/)）的预处理器的一部分而开发的，由 Ruby 开发人员，因此它继承了很多来自 Ruby 的语法风格，例如缩进、无大括号和无分号。

一个示例的 Sass 文件看起来像这样：

```html
// app.sass 

brand-primary= blue 

.container 
    color= !brand-primary 
    margin= 0px auto 
    padding= 20px 

=border-radius(!radius) 
    -webkit-border-radius= !radius 
    -moz-border-radius= !radius 
    border-radius= !radius 

* 
    +border-radius(0px) 

```

通过 Sass 编译器运行，它将返回以下代码：

```html
.container { 
  color: blue; 
  margin: 0px auto; 
  padding: 20px; 
} 

* { 
  -webkit-border-radius: 0px; 
  -moz-border-radius: 0px; 
  border-radius: 0px; 
}

```

好老的 CSS。但是你有没有注意到`brand-primary`作为一个变量，在容器类内替换它的值？以及`border-radius`作为一个函数（也称为 mixin），在调用时生成所需的 CSS 规则？是的，这是 CSS 编程中缺失的一部分。你可以尝试前面的转换：[`sasstocss.appspot.com/`](http://sasstocss.appspot.com/)，看看 Sass 是如何编译成 CSS 的。

习惯于基于大括号的编码语言的人会觉得这种编写代码的方式有点困难。所以，SCSS 应运而生。

Sass 代表**Syntactically Awesome Style Sheets**，SCSS 代表**Sassy CSS**。因此，SCSS 基本上与 Sass 相同，除了类似于 CSS 的语法。前面的 Sass 代码，如果用 SCSS 编写，会变成这样：

```html
$brand-primary: blue; 

.container{ 
    color: !brand-primary; 
    margin: 0px auto; 
    padding: 20px; 
} 

@mixin border-radius($radius) { 
    -webkit-border-radius: $radius; 
    -moz-border-radius: $radius; 
    border-radius: $radius; 
} 

* { 
    @include border-radius(5px); 
}

```

这看起来更接近 CSS 本身，对吧？而且它很有表现力。Ionic 使用 SCSS 来为其组件设置样式。

如果你想了解更多关于 SCSS 与 Sass 的信息，你可以查看：[`thesassway.com/editorial/sass-vs-scss-which-syntax-is-better`](http://thesassway.com/editorial/sass-vs-scss-which-syntax-is-better)。

现在我们对 SCSS 和 Sass 是什么以及如何使用它们有了基本的了解，我们将利用它们在我们的 Ionic 应用程序中来维护和设置主题。

# Ionic 和 SCSS

默认情况下，Ionic 已经集成了 SCSS。与早期版本不同，在那个版本中，人们必须在项目中设置 SCSS，在 Ionic 2 中，主题设置变得更加模块化和简单。主题设置可以发生在两个级别：

+   在平台级别

+   在页面/组件级别

应用级别的主题设置几乎总是我们所需要的。我们会根据我们的品牌更改应用程序的颜色，由于 Ionic 使用了 SCSS 映射，颜色直接被组件继承。此外，我们可以根据需要添加、重命名和删除颜色。映射中唯一需要的颜色是主要颜色。如果颜色因模式而异，iOS、MD 和 WP 颜色可以进一步自定义。

如果我们希望保持我们的样式与那些页面/组件隔离并特定于它们，页面/组件级别的主题设置非常有帮助。这是应用程序开发的基于组件的方法的最大优势之一。我们可以保持我们的组件模块化和可管理，同时防止样式和功能从一个组件泄漏到另一个组件，除非有意为之。

为了掌握 Ionic 中的主题设置，我们将搭建一个新的选项卡应用程序并设置相同的主题。如果需要，创建一个名为`chapter5`的新文件夹，然后打开一个新的命令提示符/终端。运行以下命令：

```html
ionic start -a "Example 13" -i app.example.thirteen example13 tabs 
--v2

```

一旦应用程序被脚手架搭建，运行`ionic serve`在浏览器中查看应用程序。我们要处理的第一件事是颜色。打开`example13/src/theme/variables.scss`，我们应该会看到一个名为`$colors`的变量映射。

为了快速测试颜色方案，将`$colors`映射中的主要变量的值从`#387ef5`更改为`red`。我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00063.jpeg)

如前所述，主要是唯一的强制值。

颜色映射也可以扩展以添加我们自己的颜色。例如，在`example13/src/pages/home/home.html`上，让我们添加一个带有属性名称`purple`的按钮，看起来会像这样：

```html
<ion-content padding> 
    <button ion-button color="purple">A Purple Button</button> 
</ion-content>

```

在`$colors`映射中，添加一个新的键值：`purple: #663399`。完整的映射看起来像这样：

```html
$colors: ( 
  primary:    red, 
  secondary:  #32db64, 
  danger:     #f53d3d, 
  light:      #f4f4f4, 
  dark:       #222, 
  purple:     #663399 
);

```

现在，如果我们返回到页面，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00064.jpeg)

确实很简单地向我们的应用程序添加新颜色。

我们可以通过添加基础和对比属性来进一步定制主题颜色。基础将是元素的背景，对比将是文本颜色。

为了测试上述功能，打开`example13/src/pages/about/about.html`，并按照下面的代码添加一个浮动操作按钮：

```html
<ion-content padding> 
  <button ion-fab color="different">FAB</button> 
</ion-content>

color=different to the FAB. We will be using this variable name to apply styles.
```

我们更新的`$colors`映射将如下所示：

```html
$colors: ( 
  primary:    red, 
  secondary:  #32db64, 
  danger:     #f53d3d, 
  light:      #f4f4f4, 
  dark:       #222, 
  purple:     #663399, 
  different: ( 
    base: #4CAF50, 
    contrast: #F44336 
  ) 
);

```

注意：这将为所有不同的 Ionic 组件生成样式。如果它们不是根组件的一部分，请不要将 SCSS 变量放在映射中。

保存所有文件后导航到关于选项卡时，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00065.jpeg)

主题设置很简单吧？

# 页面级别覆盖

我们可以通过在两个不同页面中的同一组件上应用不同的样式，将相同的主题应用到下一个级别。例如，我们将使标签在关于页面和联系页面中看起来不同。这是我们将如何实现它的方式。

在`example13/src/pages/about/about.html`中，我们将在`ion-content`部分内添加一个新的标签，如下面的代码所示：

```html
<ion-content padding> 
  <button ion-fab color="different">FAB</button> 
  <label>This is a label that looks different from the one on Contact Page</label> 
</ion-content>

```

我们将在`example13/src/pages/about/about.scss`中添加所需的样式，如下面的代码所示：

```html
page-about { 
    label { 
        border: 2px solid #FF5722; 
        background: #FF5722; 
    } 
}

```

同样，我们将在`example13/src/pages/contact/contact.html`中的`ion-content`部分内添加另一个标签，如下面的代码所示：

```html
<ion-content> 
    <label>This is a label that looks different from the one on About Page</label> 
</ion-content>

```

我们将在`example13/src/pages/contact/contact.scss`中添加所需的样式，如下面的代码所示：

```html
page-contact { 
    label { 
        border: 2px solid #009688; 
        background: #009688; 
        margin: 20px; 
        margin-top: 100px; 
        display: block; 
    } 
}

```

现在，如果我们保存所有文件并返回到浏览器中的关于页面，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00066.jpeg)

联系页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00067.jpeg)

正如我们从上图中看到的，我们正在使用页面级样式来区分这两个组件。上面的截图是一个简单的例子，说明了我们如何在不同页面的同一组件中拥有多种样式。

# 平台级别覆盖

既然我们已经看到了如何在页面级别应用样式，让我们看看 Ionic 主题是如何简化在平台级别管理样式的。当在多个具有自己独特样式的设备上查看同一应用程序时，平台级样式是适用的。

在使用 Ionic 时，我们定义模式，其中模式是应用程序运行的平台。默认情况下，Ionic 会在`ion-app`元素上添加与模式相同的类名。例如，如果我们在 Android 上查看应用程序，body 将具有名为`md`的类，其中`md`代表**material design**。

为了快速检查这一点，我们将打开`http://localhost:8100/?ionicplatform=ios`，然后在开发者工具中检查 body 元素。我们应该会看到`ion-app`元素带有一个名为`ios`的类，以及其他类：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00068.jpeg)

如果我们打开`http://localhost:8100/?ionicplatform=android`，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00069.jpeg)

如果我们打开`http://localhost:8100/?ionicplatform=windows`，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00070.jpeg)

截至今天，Ionic 有三种模式：

| **平台** | **模式** | **描述** |
| --- | --- | --- |
| iOS | ios | 对所有组件应用 iOS 样式 |
| Android | md | 对所有组件应用 Material Design 样式 |
| Windows | wp | 对所有组件应用 Windows 样式 |
| Core | md | 如果我们不在上述设备中的任何一个上，应用将默认获得 Material Design 样式 |

更多信息请参阅：[`ionicframework.com/docs/theming/platform-specific-styles/`](http://ionicframework.com/docs/theming/platform-specific-styles/)。

我们将在`example13/src/theme/variables.scss`文件的注释提供的部分中定义特定于平台的样式。

为了理解特定于平台的样式，我们将为`navbar`应用不同的背景颜色并更改文本颜色。 

打开`example13/src/theme/variables.scss`并在注释中说`App Material Design Variables`的部分下添加以下样式：

```html
// App Material Design Variables 
// --------------------------------------------------

// Material Design only Sass variables can go here 
.md{ 
  ion-navbar .toolbar-background { 
      background: #FF5722; 
  } 

  ion-navbar .toolbar-title { 
      color: #fff; 
  } 
}

```

现在，当我们保存文件并导航到`http://localhost:8100/?ionicplatform=android`，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00071.jpeg)

请注意`.md`类，其中嵌套了样式。这就是使样式特定于平台的原因。

类似地，我们更新`App iOS Variables`部分：

```html
// App iOS Variables 
// -------------------------------------------------- 
// iOS only Sass variables can go here 
.ios{ 
  ion-navbar .toolbar-background { 
      background: #2196F3; 
  } 

  ion-navbar .toolbar-title { 
      color: #fff; 
  } 
}

```

然后我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00072.jpeg)

最后，对于 Windows，我们将根据以下代码更新`App Windows Variables`部分：

```html
// App Windows Variables 
// -------------------------------------------------- 
// Windows only Sass variables can go here 
.wp{ 
  ion-navbar .toolbar-background { 
      background: #9C27B0; 
  } 

  ion-navbar .toolbar-title { 
      color: #fff; 
  } 
}

```

我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00073.jpeg)

我们已经在第四章中看到了如何使用`config`属性将应用的模式更改为`md`、`ios`或`wp`。

我们也可以动态设置平台并应用样式。

为了理解这一点，我们将使用徽章组件。只有在 Windows 平台上，徽章组件才不会有任何边框半径，但我们希望使用动态属性来覆盖这种行为。

```html
ion-content section:
```

```html
<ion-item> 
        <ion-icon name="logo-dropbox" item-left></ion-icon> 
        Files 
        <ion-badge item-right [attr.round-badge]="isWindows ? '' : null">175</ion-badge> 
    </ion-item>

```

如果我们注意到在`ion-badge`上，我们有一个条件属性`[attr.round-badge]="isWindows ? '' : null"`。如果平台是 Windows，我们将添加一个名为`round-badge`的新属性，并根据以下代码更新`example13/src/pages/contact/contact.ts`：

```html
import { Component } from '@angular/core'; 
import { Platform } from 'ionic-angular'; 

@Component({ 
  selector: 'page-contact', 
  templateUrl: 'contact.html' 
}) 
export class ContactPage { 
  isWindows: Boolean; 

  constructor(public platform: Platform) { 
    this.isWindows = platform.is('windows'); 
  } 
}

```

我们已经在构造函数中定义了`isWindows`的值。现在，如果我们保存所有文件并导航到`http://localhost:8100/?ionicplatform=windows`，我们应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00074.jpeg)

如果我们检查徽章，我们应该看到添加了属性`round-badge`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00075.jpeg)

我们可以导航到其他平台并验证相同的内容。

如果我们观察，徽章容器的边框有`0px`的边框半径。现在我们将在`example13/src/theme/variables.scss`的`App Windows Variables`部分中添加所需的覆盖。

代码片段如下所示：

```html
.wp{ 
  // snipp 

  ion-badge[round-badge]{ 
    border-radius: 12px; 
  } 
}

```

现在，即使对于 Windows 平台，我们也可以看到`border-radius`被应用：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00076.jpeg)

这是我们可以实现特定于平台的覆盖的另一种方式。

# 组件级别的覆盖

到目前为止，我们所见到的自定义大多是在页面和平台级别上。如果我们想要自定义 Ionic 提供的组件以匹配我们品牌的外观和感觉呢？

这也可以很容易地实现，这要归功于 Ionic 团队，他们已经在暴露变量名称以自定义属性的方面走了额外的一英里。

如果我们导航到[`ionicframework.com/docs/theming/overriding-ionic-variables/`](http://ionicframework.com/docs/theming/overriding-ionic-variables/)，我们将看到一个可过滤的表格，我们可以在其中找到可以覆盖的特定于组件的变量：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00077.jpeg)

# 主题一个示例组件

为了快速检查这一点，我们将在当前应用的主页上实现覆盖加载栏。当用户登陆到这个标签页时，我们将以编程方式触发加载弹出窗口，并根据平台的不同，我们将自定义组件的外观和感觉，以展示组件可以根据我们的意愿进行自定义。

根据以下代码更新`example13/src/pages/home/home.ts`：

```html
import { Component } from '@angular/core'; 
import { LoadingController } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 

  constructor(public loadingCtrl: LoadingController) { 
    this.presentLoading(); 
  } 

  presentLoading() { 
    let loader = this.loadingCtrl.create({ 
      content: "Please wait...", 
      duration: 3000 
    }); 
    loader.present(); 
  } 
}

```

我们定义了一个名为`presentLoading`的函数，并在构造函数中调用它。这将在页面加载时显示加载条。

如果我们保存此页面并导航到三个不同的平台，我们将看到特定于该特定平台的样式。在这个例子中，我们将使所有的加载条看起来（几乎）一样，不管平台如何。我们将通过搞乱`SCSS`变量来实现相同的效果。

如果我们导航到[`ionicframework.com/docs/theming/overriding-ionic-variables/`](http://ionicframework.com/docs/theming/overriding-ionic-variables/)并过滤`loading-ios`，我们将看到一堆与加载弹出样式相关的 SCSS 变量。同样，如果我们搜索`loading-md`，我们将找到与 Android 相关的 SCSS 变量。最后，如果我们搜索`loading-wp`，我们会找到 Windows 平台的 SCSS 变量。

我们将使用前面的变量名并自定义外观和感觉。打开`example13/src/theme/variables.scss`。在定义了`@import 'ionic.globals';`之后，在定义颜色映射之前，我们将添加组件级别的覆盖。如果你看的是被注释的 SCSS 文件，你会看到一个名为`Shared Variables`的部分。这是我们添加变量覆盖的地方。

我们取了一些 SCSS 变量，并修改了它们的属性，如下所示的代码：

```html
// Overriding Loading Popup for iOS  
// >> Start 
$loading-ios-background: #2196F3; 
$loading-ios-border-radius: 0px; 
$loading-ios-text-color: #fff; 
$loading-ios-spinner-color: #eee; 
// >> End 

// Overriding Loading Popup for Android  
// >> Start 
$loading-md-background: #2196F3; 
$loading-md-border-radius: 0px; 
$loading-md-text-color: #fff; 
$loading-md-spinner-color: #eee; 
// >> End 

// Overriding Loading Popup for Windows  
// >> Start 
$loading-wp-background: #2196F3; 
$loading-wp-border-radius: 0px; 
$loading-wp-text-color: #fff; 
$loading-wp-spinner-color: #eee; 
// >> End

```

现在，如果我们导航到`http://localhost:8100/?ionicplatform=ios`，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00078.jpeg)

如果我们导航到`http://localhost:8100/?ionicplatform=android`，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00079.jpeg)

最后，如果我们导航到`http://localhost:8100/?ionicplatform=windows`，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00080.jpeg)

我们也可以添加自定义 CSS，使它们看起来都一样。

通过这样，我们完成了对 Ionic 应用在平台级别和页面/组件级别进行主题设置的概述。

# 摘要

在本章中，我们已经看到了如何为 Ionic 应用设置主题。我们还看到了如何可以轻松地在平台级别和页面/组件级别实现样式。

在下一章中，我们将看一下 Ionic Native。Ionic Native 对于 Ionic 1 来说就像 ngCordova 一样。我们将深入探讨如何将设备功能与 Ionic 应用集成。


# 第六章：Ionic Native

在本章中，我们将研究如何将设备特定功能（如网络、电池状态、相机等）集成到 Ionic 应用程序中。为了开始探索这一点，我们将首先研究 Cordova 插件，然后使用 Ionic Native。

在本章中，我们将看一下：

+   设置特定于平台的 SDK

+   使用 Cordova 插件 API

+   使用 Ionic Native

+   测试一些 Ionic Native 插件

# 设置特定于平台的 SDK

在我们开始与设备特定功能交互之前，我们需要在本地机器上设置该设备操作系统的 SDK。官方上，Ionic 支持 iOS、Android 和 Windows 手机平台。尽管如此，Ionic 可以在任何可以运行 HTML、CSS 和 JavaScript 的设备上使用。

以下是如何在本地机器上设置移动 SDK 的链接。不幸的是，如果没有设置，我们无法继续本章节（和书籍）。让我们看一下以下链接：

+   **Android**：[`cordova.apache.org/docs/en/latest/guide/platforms/android/`](https://cordova.apache.org/docs/en/latest/guide/platforms/android/)

+   **iOS**：[`cordova.apache.org/docs/en/6.x/guide/platforms/ios/`](https://cordova.apache.org/docs/en/6.x/guide/platforms/ios/)

+   **Windows**：[`cordova.apache.org/docs/en/6.x/guide/platforms/wp8/`](https://cordova.apache.org/docs/en/6.x/guide/platforms/wp8/)

注意：对于其他支持的操作系统，您可以查看[`cordova.apache.org/docs/en/6.x/guide/overview/`](https://cordova.apache.org/docs/en/6.x/guide/overview/)。

在本书中，我们只会使用 Android 和 iOS。您也可以为其他移动平台采用类似的方法。在我们继续之前，我们需要确保设置已经完成，并且按预期工作。

# Android 设置

确保已安装 SDK 并且 Android 工具在您的路径中：

+   在计算机的任何位置的命令提示符/终端中运行：`android`。这将启动 Android SDK 管理器。确保您已安装最新版本的 Android，或者您正在针对安装特定版本。

+   运行以下命令：

```html
      android avd

```

+   这将启动 Android 虚拟设备管理器。确保至少设置了一个 AVD。如果还没有这样做，您可以通过单击“创建”按钮轻松完成。您可以按照以下选项填写选项：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00081.jpeg)

# iOS 设置

确保您已安装 Xcode 和所需工具，并且已全局安装`ios-sim`和`ios-deploy`：

```html
npm install -g ios-sim
npm install -g ios-deploy

```

iOS 设置只能在苹果设备上完成。Windows 开发人员无法从 Windows 设备部署 iOS 应用程序，因为需要 Xcode。

# 测试设置

让我们看看如何测试 Android 和 iOS 的设置。

# 测试 Android

为了测试设置，我们将创建一个新的 Ionic 应用程序，并使用 Android 和 iOS 模拟器进行模拟。我们将首先创建一个选项卡应用程序。创建一个名为`chapter6`的文件夹，并打开一个新的命令提示符/终端。运行以下命令：

```html
ionic start -a "Example 14" -i app.example.fourteen example14 tabs --v2

```

要在 Android 模拟器上模拟应用程序，首先需要为此项目添加 Android 平台支持，然后模拟它：

添加 Android 平台，请运行以下命令：

```html
ionic platform add android

```

完成后，请运行以下命令：

```html
ionic emulate android

```

一段时间后，您将看到模拟器启动，并且应用程序将在模拟器内部部署和执行。如果您已经使用原生 Android 应用程序工作过，您就知道 Android 模拟器有多慢。如果您没有，它非常慢。Android 模拟器的替代方案是 Genymotion ([`www.genymotion.com`](https://www.genymotion.com))。Ionic 也与 Genymotion 很好地集成在一起。

Genymotion 有两种版本，一种是免费的，另一种是商业使用的。免费版本功能有限，只能用于个人使用。

您可以从以下网址下载 Genymotion 的副本：[`www.genymotion.com/#!/store`](https://www.genymotion.com/#!/store)。

安装 Genymotion 后，请使用您喜欢的 Android SDK 创建一个新的虚拟设备。我的配置如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00082.jpeg)

接下来，我们启动模拟器并让其在后台运行。现在 Genymotion 正在运行，我们需要告诉 Ionic 使用 Genymotion 而不是 Android 模拟器来模拟应用程序。为此，我们使用以下命令：

```html
ionic run android

```

而不是这个：`ionic emulate android`。

这将部署应用程序到 Genymotion 模拟器，您可以立即看到应用程序，而不像使用 Android 模拟器那样需要等待。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00083.jpeg)

确保在运行应用程序之前，Genymotion 在后台运行。

如果 Genymotion 对您来说有点大，您可以简单地将 Android 手机连接到计算机并运行以下命令：

```html
ionic run android

```

这将部署应用程序到实际设备。

要设置 Android USB 调试，请参考：[`developer.android.com/studio/run/device.html`](https://developer.android.com/studio/run/device.html)。

Genymotion 的早期截图来自个人版，因为我没有许可证。在开发阶段，我通常与我的 Android 手机一起使用 iOS 模拟器。一旦整个开发完成，我会从设备农场购买设备时间，并在目标设备上进行测试。

如果在连接 Android 手机到计算机时遇到问题，请检查您是否能够在命令提示符/终端中运行`adb device`并在此处看到您的设备。您可以在[`developer.android.com/studio/command-line/adb.html`](https://developer.android.com/studio/command-line/adb.html)找到有关**Android 调试桥**（**ADB**）的更多信息。

# 测试 iOS

要测试 iOS，我们将首先添加 iOS 平台支持，就像我们为 Android 做的那样，然后模拟它。

运行以下命令：

```html
ionic platform add ios

```

然后运行：`ionic emulate ios`。

您应该看到默认的模拟器启动，最后，应用程序将出现在模拟器中，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00084.jpeg)

要部署到苹果设备，您可以运行以下命令：

```html
ionic run ios

```

确保在继续之前能够模拟/运行应用程序。

# 使用 Cordova 插件入门

根据 Cordova 文档：

“插件是一种注入代码的包，允许应用程序呈现的 Cordova WebView 与其运行的本机平台进行通信。插件提供对设备和平台功能的访问，这些功能通常对基于 Web 的应用程序不可用。所有主要的 Cordova API 功能都是作为插件实现的，还有许多其他可用的插件，可以启用诸如条形码扫描仪、NFC 通信或定制日历界面等功能…”

换句话说，Cordova 插件是访问设备特定功能的窗口。Cordova 团队已经构建了需要的插件，以便几乎可以与所有设备特定功能一起使用。还有社区贡献的插件，可以提供围绕设备特定功能的定制包装。

您可以在这里搜索现有的插件：[`cordova.apache.org/plugins/`](https://cordova.apache.org/plugins/)。

在本章的过程中，我们将探索一些插件。由于我们专注于 Ionic 特定的开发，我们将使用 Ionic CLI 添加插件。在幕后，Ionic CLI 调用 Cordova CLI 来执行必要的操作。

# Ionic 插件 API

在处理插件时，我们将使用四个主要命令。

# 添加插件

此 CLI 命令用于向项目添加新插件：

```html
ionic plugin add org.apache.cordova.camera

```

您也可以使用这个：

```html
ionic plugin add cordova-plugin-camera

```

# 删除插件

此 CLI 命令用于从项目中删除插件：

```html
ionic plugin rm org.apache.cordova.camera

```

您也可以使用这个：

```html
ionic plugin rm cordova-plugin-camera

```

# 列出已添加的插件

此 CLI 命令用于列出项目中的所有插件，例如：

```html
ionic plugin ls

```

# 搜索插件

此 CLI 命令用于从命令行搜索插件，例如：

```html
ionic plugin search scanner barcode

```

# Ionic Native

现在我们已经了解了如何使用 Cordova 插件，我们将创建一个新项目并与我们的 Ionic 应用程序集成 Cordova 插件。

Ionic 为我们提供了一个简单的包装器，以 TypeScript 的方式处理 Cordova 插件。在所有插件都采用 ES6/TS 方法之前，我们需要一种方法在我们的 Ionic 应用程序中使用这些插件。

进入 Ionic Native。Ionic Native 是当今 ES5 Cordova 插件的 ES6/TypeScript 实现，因此您可以导入所需的插件并在 TypeScript 中使用它们。Ionic 团队在以 TypeScript 绑定的形式向我们提供插件方面做得非常好。

# Ionic Native 测试驱动

为了测试，我们将创建一个新项目并执行以下命令：

1.  运行以下命令：

```html
      ionic start -a "Example 15" -i app.example.fifteen 
      example15 blank --v2

```

并`cd`到`example15`文件夹中。

1.  让我们搜索电池状态插件并将其添加到我们的项目中。运行以下命令：

```html
      ionic plugin search battery status

```

1.  这将启动默认浏览器并将您导航到：[`cordova.apache.org/plugins/?q=battery%20status`](http://cordova.apache.org/plugins/?q=battery%20status)。根据你找到的插件名称，你可以将该插件添加到项目中。所以，在我们的情况下，要将电池状态插件添加到项目中，我们将运行以下命令：

```html
       ionic plugin add cordova-plugin-battery-status.

```

这将向我们当前的项目中添加电池状态插件（[`github.com/apache/cordova-plugin-battery-status`](https://github.com/apache/cordova-plugin-battery-status)）。在 Ionic Native 的文档中也可以找到相同的内容：[`ionicframework.com/docs/native/battery-status/`](https://ionicframework.com/docs/native/battery-status/)。

要查看已安装的所有插件，运行以下命令：

```html
ionic plugin ls

```

然后，你应该看到以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00085.jpeg)

除了添加 Cordova 插件之外，我们还需要为电池状态添加所需的 Ionic Native 模块。运行以下命令：

```html
npm install --save @ionic-native/battery-status

```

添加模块后，我们需要在`example15/src/app/app.module.ts`中将其标记为提供者。打开`example15/src/app/app.module.ts`并按照所示进行更新：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { BatteryStatus } from '@ionic-native/battery-status'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    BatteryStatus, 
    {provide: ErrorHandler, useClass: IonicErrorHandler} 
  ] 
}) 
export class AppModule {}

```

现在，我们可以开始使用电池状态插件。打开`example15/src/pages/home/home.ts`并使用以下代码进行更新：

```html
import { Component } from '@angular/core'; 
import { BatteryStatus } from 'ionic-native'; 
import { Platform } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  level: Number; 
  isPlugged: Boolean; 

  constructor(platform: Platform) { 
    platform.ready().then(() => { 
      BatteryStatus.onChange().subscribe( 
        (status) => { 
          this.level = status.level; 
          this.isPlugged = status.isPlugged; 
        } 
      ); 
    }); 
  } 
}

```

这就是 Ionic Native 如何公开`BatteryStatus`。

接下来，按照以下方式更新`example15/src/pages/home/home.html`中的`ion-content`部分：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Battery Status 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <h2>level : {{level}}</h2> 
    <h2>isPluggedIn : {{isPlugged}}</h2> 
</ion-content>

```

现在运行以下命令：

```html
ionic serve

```

你将在页面上看不到任何输出，如果你打开开发工具，你会在控制台中看到一个警告，上面写着：

```html
Native: tried calling StatusBar.styleDefault, but Cordova is not 
available. 
Make sure to include cordova.js or run in a device/simulator

```

这意味着我们不能直接在浏览器中运行插件；它们需要一个环境来执行，比如 Android、iOS 或 Windows。

为了测试应用程序（和插件），我们将添加一个 Android 平台或一个 iOS 平台：

```html
ionic platform add android

```

你也可以使用以下命令：

```html
ionic platform add ios

```

然后执行以下命令之一：

+   `ionic emulate android`

+   `ionic emulate ios`

+   `ionic run android`

+   `ionic run ios`

运行任何一个前面的命令都会显示以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00086.jpeg)

现在你知道如何向你的 Ionic 应用程序中添加 Cordova 插件并对其进行测试。在接下来的部分中，我们将使用更多的插件。来自 Genymotion 的前面的屏幕截图是我个人使用许可证的。这些图片仅用于说明目的。

# Cordova 白名单插件

在继续使用 Ionic Native 之前，我们将花一些时间来了解一个关键的 Cordova 插件--白名单插件：[`github.com/apache/cordova-plugin-whitelist`](https://github.com/apache/cordova-plugin-whitelist)。

从白名单插件的 Cordova 文档中：

“域白名单是一种安全模型，用于控制应用程序无法控制的外部域的访问。Cordova 提供了一个可配置的安全策略，用于定义可以访问哪些外部站点。”

因此，如果我们希望更好地控制我们的应用程序在处理来自其他来源的内容时的行为方式，我们应该使用白名单插件。您可能已经注意到，此插件已添加到我们的 Ionic 应用程序中。如果此插件尚未添加到 Ionic/Cordova 应用程序中，您可以通过运行以下命令轻松添加：

```html
ionic plugin add https://github.com/apache/cordova-plugin-
whitelist.git

```

一旦添加了插件，您可以更新`config.xml`文件以进行导航白名单 - 允许您的应用程序在 WebView 内打开的链接，以允许链接到`example.com`。

您将添加以下代码：

```html
<allow-navigation href="http://example.com/*" />

```

如果要使您的 WebView 链接到任何网站，您需要添加以下内容：

```html
<allow-navigation href="http://*/*" /> 
<allow-navigation href="https://*/*" /> 
<allow-navigation href="data:*" />

```

您还可以添加意图白名单，其中可以指定允许在设备上浏览的链接列表。例如，从我们的自定义应用程序中打开短信应用程序：

```html
<allow-intent href="sms:*" />

```

或简单的网页：

```html
<allow-intent href="https://*/*" />

```

您还可以使用此插件在应用程序上强制执行**内容安全策略**（**CSP**）（[`content-securitypolicy.com/`](http://content-securitypolicy.com/)）。您只需要在`www/index.html`文件中添加`meta`标签，如下所示：

```html
<!-- Allow XHRs via https only --> 
<meta http-equiv="Content-Security-Policy" content="default-src 'self' https:">

```

这是白名单插件的快速介绍。此插件适用于：

+   Android 4.0.0 或更高版本

+   iOS 4.0.0 或更高版本

请记住添加并配置此插件；否则，外部链接将无法工作。

# 使用 Ionic Native 处理 Cordova 插件

在之前的示例中，我们已经看到了如何将设备功能（例如电池状态）与我们的 Ionic 应用程序集成。现在，我们将探索更多类似的插件，并看看如何实现它们。

# 设备

我们将在本节中首先查看的插件是设备插件。此插件描述了设备的硬件和软件规格。

您可以在此处了解有关此插件的更多信息：[`github.com/apache/cordova-plugin-device`](https://github.com/apache/cordova-plugin-device)或[`ionicframework.com/docs/native/device/`](https://ionicframework.com/docs/native/device/)。

让我们搭建一个新的空白应用程序，然后向其中添加设备插件：

```html
ionic start -a "Example 16" -i app.example.sixteen example16 blank --v2

```

应用程序搭建完成后，`cd`进入`example16`文件夹。现在我们将添加设备插件，运行以下命令：

```html
ionic plugin add cordova-plugin-device

```

这将添加设备插件。完成后，我们将添加 Ionic 本机设备模块。运行以下命令：

```html
npm install --save @ionic-native/device

```

添加模块后，我们需要在`example16/src/app/app.module.ts`中将其标记为提供者。按照以下方式更新`example16/src/app/app.module.ts`：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { Device } from '@ionic-native/device'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    Device, 
    { provide: ErrorHandler, useClass: IonicErrorHandler } 
  ] 
}) 
export class AppModule { }

```

接下来，通过运行`ionic platform add ios`或`ionic platform add android`来添加 iOS 或 Android 平台之一。

现在，我们将添加与设备插件相关的代码。打开`example16/src/pages/home/home.ts`并按照以下方式更新类：

```html
import { Component } from '@angular/core'; 
import { Device } from '@ionic-native/device'; 
import { Platform } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  cordova: String; 
  model: String; 
  devicePlatform: String; 
  uuid: String; 
  version: String; 
  manufacturer: String; 
  isVirtual: Boolean; 
  serial: String; 

  constructor(private platform: Platform, 
    private device: Device) { 
    platform.ready().then(() => { 
      let device = this.device; 
      this.cordova = device.cordova; 
      this.model = device.model; 
      this.devicePlatform = device.platform; 
      this.uuid = device.uuid; 
      this.version = device.version; 
      this.manufacturer = device.manufacturer; 
      this.isVirtual = device.isVirtual; 
      this.serial = device.serial; 
    }); 
  } 
}

```

接下来，按照以下方式更新`example16/src/pages/home/home.html`：

```html
<ion-header> 
  <ion-navbar> 
    <ion-title> 
      Ionic Blank 
    </ion-title> 
  </ion-navbar> 
</ion-header> 

<ion-content padding> 
  <table> 
    <tr> 
      <td>cordova</td> 
      <td>{{cordova}}</td> 
    </tr> 
    <tr> 
      <td>model</td> 
      <td>{{model}}</td> 
    </tr> 
    <tr> 
      <td>platform</td> 
      <td>{{platform}}</td> 
    </tr> 
    <tr> 
      <td>uuid</td> 
      <td>{{uuid}}</td> 
    </tr> 
    <tr> 
      <td>version</td> 
      <td>{{version}}</td> 
    </tr> 
    <tr> 
      <td>manufacturer</td> 
      <td>{{manufacturer}}</td> 
    </tr> 
    <tr> 
      <td>isVirtual</td> 
      <td>{{isVirtual}}</td> 
    </tr> 
    <tr> 
      <td>serial</td> 
      <td>{{serial}}</td> 
    </tr> 
  </table> 
</ion-content>

```

保存所有文件，最后运行`ionic emulate ios`或`ionic emulate android`。我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00087.gif)

如前面的屏幕截图所示，设备是 Nexus 6P。

# 吐司

我们将要使用的下一个插件是 Toast 插件。此插件显示文本弹出窗口，不会阻止用户与应用程序的交互。

您可以在这里了解有关此插件的更多信息：[`github.com/EddyVerbruggen/Toast-PhoneGap-Plugin`](https://github.com/EddyVerbruggen/Toast-PhoneGap-Plugin)或[`ionicframework.com/docs/native/toast/`](https://ionicframework.com/docs/native/toast/)。

我们将使用以下命令搭建一个新的空白应用程序：

```html
ionic start -a "Example 17" -i 
app.example.seventeen example17 blank --v2

```

应用程序搭建完成后，`cd`进入`example17`文件夹。现在我们将添加 Toast 插件，运行：

```html
ionic plugin add cordova-plugin-x-toast

```

然后我们将添加 Ionic Native Toast 模块：

```html
npm install --save @ionic-native/toast

```

接下来，我们将在`example17/src/app/app.module.ts`中将 Toast 添加为提供者。按照以下方式更新`example17/src/app/app.module.ts`：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { Toast } from '@ionic-native/toast'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    Toast, 
    {provide: ErrorHandler, useClass: IonicErrorHandler} 
  ] 
}) 
export class AppModule {}

```

完成后，通过运行以下命令添加 iOS 或 Android 平台之一：

```html
ionic platform add ios

```

或：

```html
ionic platform add android

```

现在，我们将添加与 Toast 插件相关的代码。打开`example17/src/pages/home/home.ts`并按照文件中所示进行更新：

```html
import { Component } from '@angular/core'; 
import { Toast } from '@ionic-native/toast'; 
import { Platform } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 

  constructor(private platform: Platform, private toast: Toast) { 
    platform.ready().then(() => { 
      toast.show("I'm a toast", '5000', 'center').subscribe( 
        (toast) => { 
          console.log(toast); 
        } 
      ); 
  }); 
  } 

}

```

保存所有文件并运行：

```html
ionic emulate ios or ionic emulate android

```

您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00088.jpeg)

要了解有关 Toast 插件 API 方法的更多信息，请参阅：[`ionicframework.com/docs/native/toast/`](http://ionicframework.com/docs/native/toast/)。

# 对话框

我们接下来要使用的插件是对话框插件。这会触发警报、确认和提示窗口。

您可以从这里了解有关插件的更多信息：[`github.com/apache/cordova-plugin-dialogs`](https://github.com/apache/cordova-plugin-dialogs) 和 [`ionicframework.com/docs/native/dialogs/`](https://ionicframework.com/docs/native/dialogs/)。

首先，为对话框插件搭建一个新的空白应用程序：

```html
ionic start -a "Example 18" -i app.example.eightteen example18 blank --v2

```

应用程序搭建完成后，`cd`进入`example18`文件夹。现在，我们将添加对话框插件，运行：

```html
ionic plugin add cordova-plugin-dialogs

```

之后，我们将为对话框添加 Ionic Native 模块。运行以下命令：

```html
npm install --save @ionic-native/dialogs

```

接下来，将对话框添加为提供者。按照以下步骤更新`example18/src/app/app.module.ts`：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { Dialogs } from '@ionic-native/dialogs'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    Dialogs, 
    {provide: ErrorHandler, useClass: IonicErrorHandler} 
  ] 
}) 
export class AppModule {}

```

完成后，通过运行以下命令添加 iOS 或 Android 平台之一：

```html
ionic platform add ios

```

或者：

```html
ionic platform add android

```

现在，我们将添加与对话框插件相关的代码。打开`example18/src/pages/home/home.ts`并更新为所述的代码文件：

```html
import { Component } from '@angular/core'; 
import { Dialogs } from '@ionic-native/dialogs'; 
import { Platform } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  name: String; 

  constructor(private dialogs: Dialogs, private platform: Platform) { 
    platform.ready().then(() => { 
      dialogs 
        .prompt('Name Please?', 'Identity', ['Cancel', 'Ok'], 'John 
        McClane') 
        .then((result) => { 
          if (result.buttonIndex == 2) { 
            this.name = result.input1; 
          } 
        }); 
    }); 
  } 
}

```

接下来，我们将按照以下方式更新`example18/src/pages/home/home.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Reveal Your Identity 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    Hello {{name}}!! 
</ion-content>

```

保存所有文件，最后运行以下命令：

```html
    ionic emulate ios or ionic emulate android

```

我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00089.jpeg)

要了解有关对话框插件 API 方法的更多信息，请参阅：[`ionicframework.com/docs/native/dialogs/`](https://ionicframework.com/docs/native/dialogs/)。

# 本地通知

我们接下来要使用的插件是本地通知插件。该插件主要用于通知或提醒用户与应用相关的活动。有时，当后台活动正在进行时，也会显示通知，比如大文件上传。

您可以从这里了解有关插件的更多信息：[`github.com/katzer/cordova-plugin-local-notifications`](https://github.com/katzer/cordova-plugin-local-notifications) 和 [`ionicframework.com/docs/native/local-notifications/`](https://ionicframework.com/docs/native/local-notifications/)。

首先，为本地通知插件搭建一个新的空白应用程序：

```html
ionic start -a "Example 19" -i 
app.example.nineteen example19 blank --v2

```

应用程序搭建完成后，`cd`进入`example19`文件夹。现在，我们将添加本地通知插件，运行以下命令：

```html
ionic plugin add de.appplant.cordova.plugin.local-notification

```

接下来，添加 Ionic Native 模块：

```html
npm install --save @ionic-native/local-notifications

```

并在`example19/src/app/app.module.ts`中更新提供者：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { LocalNotifications } from '@ionic-native/local-notifications'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    LocalNotifications, 
    {provide: ErrorHandler, useClass: IonicErrorHandler} 
  ] 
}) 
export class AppModule {}

```

完成后，通过运行以下命令添加 iOS 或 Android 平台之一：

```html
ionic platform add ios

```

或者：

```html
ionic platform add android

```

现在，我们将添加与本地通知插件相关的代码。打开`example19/src/pages/home/home.ts`并按照以下方式更新：

```html
import { Component } from '@angular/core'; 
import { LocalNotifications } from '@ionic-native/local-notifications'; 
import { Platform } from 'ionic-angular'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  defaultText: String = 'Hello World'; 

  constructor(private localNotifications: LocalNotifications, private platform: Platform) { } 

  triggerNotification(notifText) { 
    this.platform.ready().then(() => { 

      notifText = notifText || this.defaultText; 
      this.localNotifications.schedule({ 
        id: 1, 
        text: notifText, 
      }); 
    }); 
  } 

}

```

接下来，我们将按照以下方式更新`example19/src/pages/home/home.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Local Notification 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <div class="list"> 
        <label class="item item-input"> 
            <span class="input-label">Enter Notification text</span> 
            <input type="text" #notifText [ngModel]="defaultText"> 
        </label> 
        <label class="item item-input"> 
            <button ion-button color="dark" (click)=" 
            triggerNotification(notifText.value)">Notify</button> 
        </label> 
    </div> 
</ion-content>

```

保存所有文件，然后运行以下命令：

```html
ionic server android

```

或者：

```html
ionic server ios

```

我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00090.gif)

现在，当我们查看通知栏时，应该看到本地通知：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00091.jpeg)

要了解有关对话框插件 API 方法的更多信息，请参阅：[`ionicframework.com/docs/native/local-notifications/`](https://ionicframework.com/docs/native/local-notifications/)。

# 地理位置

我们要查看的最后一个插件是地理位置插件，它可以帮助获取设备的坐标。

您可以从这里了解有关插件的更多信息：[`github.com/apache/cordova-plugin-geolocation`](https://github.com/apache/cordova-plugin-geolocation) 和 [`ionicframework.com/docs/native/geolocation/`](https://ionicframework.com/docs/native/geolocation/)。

首先，为地理位置插件搭建一个新的空白应用程序：

```html
ionic start -a "Example 20" -i app.example.twenty example20 blank --v2

```

应用程序搭建完成后，`cd`进入`example20`文件夹。现在，我们将添加地理位置插件，运行以下命令：

```html
ionic plugin add cordova-plugin-geolocation

```

接下来，运行以下命令以添加 Ionic Native 模块：

```html
npm install --save @ionic-native/geolocation

```

现在，我们注册提供者。更新`example20/src/app/app.module.ts`：

```html
import { NgModule, ErrorHandler } from '@angular/core'; 
import { IonicApp, IonicModule, IonicErrorHandler } from 'ionic-angular'; 
import { MyApp } from './app.component'; 
import { HomePage } from '../pages/home/home'; 

import { StatusBar } from '@ionic-native/status-bar'; 
import { SplashScreen } from '@ionic-native/splash-screen'; 
import { Geolocation } from '@ionic-native/geolocation'; 

@NgModule({ 
  declarations: [ 
    MyApp, 
    HomePage 
  ], 
  imports: [ 
    IonicModule.forRoot(MyApp) 
  ], 
  bootstrap: [IonicApp], 
  entryComponents: [ 
    MyApp, 
    HomePage 
  ], 
  providers: [ 
    StatusBar, 
    SplashScreen, 
    Geolocation, 
    {provide: ErrorHandler, useClass: IonicErrorHandler} 
  ] 
}) 
export class AppModule {}

```

完成后，通过运行以下命令添加 iOS 或 Android 平台之一：

```html
ionic platform add ios

```

或者：

```html
ionic platform add android

```

现在，我们将添加与地理位置插件相关的代码。打开`example20/src/pages/home/home.ts`并更新如下：

```html
import { Component } from '@angular/core'; 
import { Platform } from 'ionic-angular'; 
import { Geolocation } from '@ionic-native/geolocation'; 

@Component({ 
  selector: 'page-home', 
  templateUrl: 'home.html' 
}) 
export class HomePage { 
  latitude: Number = 0; 
  longitude: Number = 0; 
  accuracy: Number = 0; 

  constructor(private platform: Platform, 
    private geolocation: Geolocation) { 
    platform.ready().then(() => { 
      geolocation.getCurrentPosition().then((position) => { 
        this.latitude = position.coords.latitude; 
        this.longitude = position.coords.longitude; 
        this.accuracy = position.coords.accuracy; 
      }); 
    }); 
  } 
}

```

接下来，按照以下代码更新`example20/src/pages/home/home.html`：

```html
<ion-header> 
    <ion-navbar> 
        <ion-title> 
            Ionic Blank 
        </ion-title> 
    </ion-navbar> 
</ion-header> 
<ion-content padding> 
    <ul class="list"> 
        <li class="item"> 
            Latitude : {{latitude}} 
        </li> 
        <li class="item"> 
            Longitude : {{longitude}} 
        </li> 
        <li class="item"> 
            Accuracy : {{accuracy}} 
        </li> 
    </ul> 
</ion-content>

```

保存所有文件，最后运行以下命令：

```html
ionic emulate ios

```

或：

```html
ionic emulate android

```

我们应该能够看到以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00092.jpeg)

一旦权限被提供，我们应该能够看到以下截图中显示的值：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/lrn-ionic-2e/img/00093.gif)

我的 Google Nexus 6P 运行 Android Nougat，其中有一个名为运行时权限的新功能。这允许用户在运行时而不是在安装应用程序时给予权限。您可以在这里了解更多关于该功能的信息：[`developer.android.com/training/permissions/requesting.html`](https://developer.android.com/training/permissions/requesting.html)。

要了解有关 Geolocation 插件 API 方法的更多信息，请参考：[`ionicframework.com/docs/native/geolocation/`](https://ionicframework.com/docs/native/geolocation/)。

前面的例子应该已经很好地展示了你如何使用 Ionic Native。

# 摘要

在本章中，我们已经了解了 Cordova 插件是什么，以及它们如何在现有的 Ionic 应用程序中使用。我们首先建立了一个用于 Android 和 iOS 的本地开发环境，然后学习了如何模拟和运行 Ionic 应用程序。接下来，我们探索了如何将 Cordova 插件添加到 Ionic 项目中并使用它们。最后，借助 Ionic Native，我们在 Ionic 应用程序中注入了插件并与它们一起工作。

在下一章中，我们将利用到目前为止所学到的知识来构建一个名为 Riderr 的应用程序。利用 Uber 提供的公共 API，我们将构建一个应用程序，通过它，乘客可以预订 Uber 车辆。
