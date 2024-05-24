# Angular 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7`](https://zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：*第七章*：理解 Angular 导航和路由

关于 Angular 最令人惊奇的事情之一是，它是一个完整的生态系统（一个框架），而不是一个库。在这个生态系统中，Angular 路由器是最关键的学习和理解之一。在本章中，您将学习有关 Angular 中路由和导航的一些非常酷的技术。您将学习如何保护您的路由，监听路由更改，并配置路由更改的全局操作。

以下是本章将涵盖的配方：

+   使用 CLI 创建带有路由的 Angular 应用程序和模块

+   特性模块和延迟加载路由

+   使用路由守卫对路由进行授权访问

+   处理路由参数

+   在路由更改之间显示全局加载器

+   预加载路由策略

## 技术要求

对于本章的配方，请确保您的机器上已安装**Git**和**Node.js**。您还需要安装`@angular/cli`包，您可以在终端中使用`npm install -g @angular/cli`来完成。本章的代码可以在[`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter07`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter07)找到。

# 使用 CLI 创建带有路由的 Angular 应用程序

如果你问我 7-8 年前我们是如何创建 Web 应用程序项目的，你会惊讶地发现当时有多么困难。幸运的是，软件开发行业的工具和标准已经发展，当涉及到 Angular 时，启动项目变得非常容易。你甚至可以直接配置不同的东西。在这个配方中，您将使用 Angular CLI 创建一个全新的 Angular 项目，并在创建项目时启用路由配置。

## 准备就绪

我们要处理的项目没有起始文件。所以，你可以直接从克隆的存储库中将`chapter07/start_here`文件夹打开到 Visual Studio Code 应用程序中。

## 如何做…

我们将首先使用 Angular CLI 创建应用程序。它将默认启用路由。同样，接下来，我们将创建一些带有组件的特性模块，但它们将具有急切加载的路由。所以，让我们开始吧：

1.  首先，打开终端，确保你在`chapter07/start_here`文件夹内。进入后，运行以下命令：

```ts
ng new basic-routing-app --routing --style scss
```

该命令应该为您创建一个新的 Angular 应用程序，并启用路由，并选择 SCSS 作为您的样式选择。

1.  运行以下命令在浏览器中打开应用程序：

```ts
cd basic-routing app
ng serve -o
```

1.  现在，通过运行以下命令创建一个顶级组件命名为`landing`：

```ts
ng g c landing
```

1.  从`app.component.html`中删除所有内容，只保留`router-outlet`，如下所示：

```ts
<router-outlet></router-outlet>
```

1.  现在，通过将其添加到`app-routing.module.ts`文件中，将`LandingComponent`设置为默认路由，如下所示：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { LandingComponent } from './landing/landing.component';
const routes: Routes = [{
  path: '',
  redirectTo: 'landing',
  pathMatch: 'full'
}, {
  path: 'landing',
  component: LandingComponent
}];
...
```

1.  刷新页面，你应该会看到 URL 自动更改为`http://localhost:4200/landing`，因为应用程序重定向到默认路由。

1.  用以下代码替换`landing.component.html`的内容：

```ts
<div class="landing">
  <div class="landing__header">
    <div class="landing__header__main">
      Creating an Angular app with routes using CLI
    </div>
    <div class="landing__header__links">
      <div class="landing__header__links__link">
        Home
      </div>
      <div class="landing__header__links__link">
        About
      </div>
    </div>
  </div>
  <div class="landing__body">
    Landing Works
  </div>
</div>
```

1.  现在，在`landing.component.scss`文件中为头部添加一些样式，如下所示：

```ts
.landing {
  display: flex;
  flex-direction: column;
  height: 100%;
  &__header {
    height: 60px;
    padding: 0 20px;
    background-color: #333;
    color: white;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    &__main {
      flex: 1;
    }
  }
}
```

1.  如下所示，为头部链接添加样式：

```ts
.landing {
  ...
  &__header {
    ...
    &__links {
      padding: 0 20px;
      display: flex;
      &__link {
        margin-left: 16px;
        &:hover {
          color: #ececec;
          cursor: pointer;
        }
      }
    }
  }
}
```

1.  此外，在`&__header`选择器之后添加着陆页面主体的样式，如下所示：

```ts
.landing {
  ...
  &__header {
   ...
  }
  &__body {
    padding: 30px;
    flex: 1;
    display: flex;
    justify-content: center;
    background-color: #ececec;
  }
}
```

1.  最后，为了使一切看起来好看，将以下样式添加到`styles.scss`文件中：

```ts
html, body {
  width: 100%;
  height: 100%;
  margin: 0;
  padding: 0;
}
```

1.  现在，通过在项目根目录中运行以下命令，为`home`和`about`路由添加特性模块：

```ts
ng g m home
ng g c home
ng g m about
ng g c about
```

1.  接下来，在你的`app.module.ts`文件中导入`HomeModule`和`AboutModule`如下所示：

```ts
...
import { LandingComponent } from './landing/landing.component';
import { HomeModule } from './home/home.module';
import { AboutModule } from './about/about.module';
@NgModule({
  declarations: [...],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HomeModule,
    AboutModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

1.  现在，我们可以配置路由。修改`app-routing.module.ts`文件以添加适当的路由，如下所示：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { AboutComponent } from './about/about.component';
import { HomeComponent } from './home/home.component';
import { LandingComponent } from './landing/landing.component';
const routes: Routes = [{
  path: '',
  redirectTo: 'landing',
  pathMatch: 'full'
}, {
  path: 'landing',
  component: LandingComponent
}, {
  path: 'home',
  component: HomeComponent
}, {
  path: 'about',
  component: AboutComponent
}];
...
```

1.  我们可以很快为我们的`Home`和`About`组件添加样式。将以下 CSS 添加到`home.component.scss`文件和`about.component.scss`文件中：

```ts
:host {
  display: flex;
  width: 100%;
  height: 100%;
  justify-content: center;
  align-items: center;
  background-color: #ececec;
  font-size: 24px;
}
```

1.  现在，我们可以将我们的链接绑定到着陆页面的适当路由上。修改`landing.component.html`如下所示：

```ts
<div class="landing">
  <div class="landing__header">
    <div class="landing__header__links">
      <div class="landing__header__links__link"       routerLink="/home">
        Home
      </div>
      <div class="landing__header__links__link"       routerLink="/about">
        About
      </div>
    </div>
  </div>
  <div class="landing__body">
    Landing Works
  </div>
</div>
```

太棒了！在短短几分钟内，借助令人惊叹的 Angular CLI 和 Angular 路由器的帮助，我们能够创建一个着陆页面、两个特性模块和特性路由（尽管是急加载的），并且我们也对一些东西进行了样式化。现代网络的奇迹！

现在您已经知道了基本路由是如何实现的，接下来请查看下一节以了解它是如何工作的。

## 它是如何工作的...

当我们在创建应用程序时使用`--routing`参数，或者在创建模块时，Angular CLI 会自动创建一个名为`<your module>-routing.module.ts`的模块文件。该文件基本上包含一个路由模块。在这个示例中，我们只是创建了特性模块而没有路由，以使实现更简单和更快。在下一个示例中，您还将了解有关模块内路由的信息。无论如何，由于我们已经创建了急切加载的特性模块，这意味着所有特性模块的 JavaScript 都会在应用程序加载时加载。您可以检查 Chrome DevTools 中的**Network**选项卡，并查看`main.js`文件的内容，因为它包含了所有我们的组件和模块。请参阅以下屏幕截图，其中显示了`main.js`文件中`AboutComponent`和`HomeComponent`的代码：

![图 7.1 - 包含 AboutComponent 和 HomeComponent 代码的 main.js](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.1_B15150.jpg)

图 7.1 - 包含 AboutComponent 和 HomeComponent 代码的 main.js

由于我们已经确定了在应用程序启动时所有示例中的组件都是急切加载的，因此有必要了解这是因为我们在`AppModule`的`imports`数组中导入了`HomeModule`和`AboutModule`。

## 另请参阅

+   Angular 路由器文档（[`angular.io/guide/router`](https://angular.io/guide/router)）

# 特性模块和延迟加载路由

在上一个示例中，我们学习了如何创建一个具有急切加载路由的基本路由应用程序。在这个示例中，您将学习如何使用特性模块来延迟加载它们，而不是在应用程序加载时加载它们。对于这个示例，我们将假设我们已经有了路由，并且只需要延迟加载它们。

## 准备工作

此示例中的项目位于`chapter07/start_here/lazy-loading-modules`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这将在新的浏览器选项卡中打开应用程序，您应该看到应用程序如下所示：

![图 7.2 - lazy-loading-modules 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.2_B15150.jpg)

图 7.2 - lazy-loading-modules 应用程序运行在 http://localhost:4200

现在我们的应用程序在本地运行，让我们在下一节中看看这个示例的步骤。

## 如何做…

如*图 7.2*所示，我们在`main.js`文件中有所有的组件和模块。因此，`main.js`文件的大小约为 23.4 KB。我们将修改代码和路由结构以实现懒加载。结果，当我们实际导航到它们时，路由的特定文件将被加载：

1.  首先，我们必须使我们的目标模块能够被懒加载。为此，我们将不得不为`AboutModule`和`HomeModule`分别创建一个`<module>-routing.module.ts`文件。因此，让我们在`about`和`home`文件夹中都创建一个新文件：

a) 将第一个文件命名为`about-routing.module.ts`，并向其中添加以下代码：

```ts
// about-routing.module.ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { AboutComponent } from './about.component';
const routes: Routes = [{
  path: '',
  component: AboutComponent
}];
@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class AboutRoutingModule { }
```

b) 将第二个文件命名为`home-routing.module.ts`，并向其中添加以下代码：

```ts
// home-routing.module.ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { HomeComponent } from './home.component';
const routes: Routes = [{
  path: '',
  component: HomeComponent
}];
@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule]
})
export class HomeRoutingModule { }
```

1.  现在，我们将这些路由模块添加到相应的模块中，也就是说，我们将在`HomeModule`中导入`HomeRoutingModule`，如下所示：

```ts
// home.module.ts
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HomeComponent } from './home.component';
import { HomeRoutingModule } from './home-routing.module';
@NgModule({
  declarations: [HomeComponent],
  imports: [
    CommonModule,
    HomeRoutingModule
  ]
})
export class HomeModule { }
```

在`AboutModule`中添加`AboutRoutingModule`，如下所示：

```ts
// about.module.ts
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AboutComponent } from './about.component';
import { AboutRoutingModule } from './about-routing.module';
@NgModule({
  declarations: [AboutComponent],
  imports: [
    CommonModule,
    AboutRoutingModule
  ]
})
export class AboutModule { }
```

1.  我们的模块现在能够被懒加载。我们现在只需要懒加载它们。为了这样做，我们需要修改`app-routing.module.ts`并更改我们的配置，以便在`about`和`home`路由中使用 ES6 导入，如下所示：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule } from '@angular/router';
import { LandingComponent } from './landing/landing.component';
const routes: Routes = [{
  path: '',
  redirectTo: 'landing',
  pathMatch: 'full'
}, {
  path: 'landing',
  component: LandingComponent
}, {
  path: 'home',
  loadChildren: () => import('./home/home.module').then   (m => m.HomeModule)
}, {
  path: 'about',
  loadChildren: () => import('./about/about.module').  then(m => m.AboutModule)
}];
@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

1.  最后，我们将从`AppModule`的`imports`数组中移除`AboutModule`和`HomeModule`的导入，以便我们可以直接获得所需的代码拆分。`app.module.ts`的内容应如下所示：

```ts
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LandingComponent } from './landing/landing.component';
import { HomeModule } from './home/home.module'; ← Remove
import { AboutModule } from './about/about.module'; ← Remove
@NgModule({
  declarations: [
    AppComponent,
    LandingComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HomeModule, ← Remove
    AboutModule ← Remove
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

刷新应用程序，您会看到`main.js`文件的捆绑大小已经降至 18.1 KB，之前大约为 23.4 KB。请参阅以下截图：

![图 7.3 - 应用程序加载时 main.js 的大小减小](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.3_B15150.jpg)

图 7.3 - 应用程序加载时 main.js 的大小减小

但是主页和关于路由呢？懒加载呢？嗯，从标题中点击**主页**路由，您会看到专门为该路由在**网络**选项卡中下载的新 JavaScript 文件。这就是懒加载的作用！请参阅以下截图：

![图 7.4 - 主页路由被懒加载](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.4_B15150.jpg)

图 7.4 - 主页路由被懒加载

太棒了！你刚刚变得懒惰了！开玩笑的。你刚刚学会了在你的 Angular 应用程序中懒加载路由和特性模块的艺术。现在你也可以向你的朋友展示这个。

## 它是如何工作的…

Angular 使用模块，通常将功能分解为模块。正如我们所知，`AppModule` 作为 Angular 应用的入口点，Angular 将在构建过程中导入和捆绑在 `AppModule` 中导入的任何内容，从而生成 `main.js` 文件。然而，如果我们想要延迟加载我们的路由/功能模块，我们需要避免直接在 `AppModule` 中导入功能模块，并使用 `loadChildren` 方法来加载功能模块的路由，以实现按需加载。这就是我们在这个示例中所做的。需要注意的是，路由在 `AppRoutingModule` 中保持不变。但是，我们必须在我们的功能路由模块中放置 `path: ''`，因为这将合并 `AppRoutingModule` 中的路由和功能路由模块中的路由，从而成为 `AppRoutingModule` 中定义的内容。这就是为什么我们的路由仍然是 `'about'` 和 `'home'`。

## 另请参阅

+   在 Angular 中延迟加载模块（[`angular.io/guide/lazy-loading-ngmodules`](https://angular.io/guide/lazy-loading-ngmodules)）

# 使用路由守卫授权访问路由

您的 Angular 应用程序中并非所有路由都应该被世界上的每个人访问。在这个示例中，我们将学习如何在 Angular 中创建路由守卫，以防止未经授权的访问路由。

## 准备工作

这个示例的项目位于 `chapter07/start_here/using-route-guards` 中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这应该在新的浏览器标签中打开应用程序，您应该看到应用程序如下：

![图 7.5 – using-route-guards 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.5_B15150.jpg)

图 7.5 – using-route-guards 应用程序运行在 http://localhost:4200

现在应用程序在本地运行，让我们在下一节中看到示例的步骤。

## 如何做…

我们已经设置了一个带有一些路由的应用程序。您可以以员工或管理员身份登录以查看应用程序的待办事项清单。但是，如果您点击标题中的任何两个按钮，您会发现即使没有登录，您也可以导航到管理员和员工部分。这就是我们要防止发生的事情。请注意，在 `auth.service.ts` 文件中，我们已经有了用户登录的方式，并且我们可以使用 `isLoggedIn()` 方法来检查用户是否已登录。

1.  首先，让我们创建一个路由守卫，只有在用户登录时才允许用户转到特定的路由。我们将其命名为`AuthGuard`。通过在项目根目录中运行以下命令来创建它：

```ts
ng g guard guards/Auth
```

运行命令后，您应该能够看到一些选项，选择我们想要实现的接口。

1.  选择`CanActivate`接口并按“Enter”。

1.  现在，在`auth.guard.ts`文件中添加以下逻辑来检查用户是否已登录，如果用户未登录，我们将重定向用户到登录页面，即`'/auth'`路由：

```ts
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, UrlTree, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService } from '../services/auth.service';
@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(private auth: AuthService, private router:   Router) {  }
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot): Observable<boolean |     UrlTree> | Promise<boolean | UrlTree> | boolean |     UrlTree {
      const loggedIn = !!this.auth.isLoggedIn();
      if (!loggedIn) {
        this.router.navigate(['/auth']);
        return false;
      }
    return true;
  }
}
```

1.  现在，让我们在`app-routing.module.ts`文件中为 Admin 和 Employee 路由应用`AuthGuard`，如下所示：

```ts
...
import { AuthGuard } from './guards/auth.guard';
const routes: Routes = [{...}, {
  path: 'auth',
  loadChildren: () => import('./auth/auth.module').then   (m => m.AuthModule)
}, {
  path: 'admin',
  loadChildren: () => import('./admin/admin.module').  then(m => m.AdminModule),
  canActivate: [AuthGuard]
}, {
  path: 'employee',
  loadChildren: () => import('./employee/employee.  module').then(m => m.EmployeeModule),
  canActivate: [AuthGuard]
}];
...
export class AppRoutingModule { }
```

如果您现在注销并尝试点击标题中的“员工部门”或“管理员部门”按钮，您会注意到在登录之前无法转到路由。如果您尝试直接在地址栏中输入路由的 URL 并按“Enter”，情况也是如此。

1.  现在，我们将尝试创建一个守卫，一个用于员工路由，一个用于管理员路由。依次运行以下命令，并为两个守卫选择`CanActivate`接口：

```ts
ng g guard guards/Employee
ng g guard guards/Admin
```

1.  既然我们已经创建了守卫，让我们首先为`AdminGuard`放置逻辑。我们将尝试查看已登录的用户类型。如果是管理员，则允许导航，否则我们会阻止它。在`admin.guard.ts`中添加以下代码：

```ts
...
import { UserType } from '../constants/user-type';
import { AuthService } from '../services/auth.service';
...
export class AdminGuard implements CanActivate {
  constructor(private auth: AuthService) {}
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot): Observable<boolean |     UrlTree> | Promise<boolean | UrlTree> | boolean |     UrlTree {
    return this.auth.loggedInUserType === UserType.Admin;
  }
}
```

1.  在`app-routing.module.ts`中的 Admin 路由中添加`AdminGuard`如下：

```ts
...
import { AdminGuard } from './guards/admin.guard';
import { AuthGuard } from './guards/auth.guard';
const routes: Routes = [{
  path: '',
 ...
}, {
  path: 'auth',
 ...
}, {
  path: 'admin',
  loadChildren: () => import('./admin/admin.module').  then(m => m.AdminModule),
  canActivate: [AuthGuard, AdminGuard]
}, {
  path: 'employee',
  ...
}];
...
```

现在尝试注销并以员工身份登录。然后尝试点击标题中的“管理员部门”按钮。您会注意到您现在无法转到清单的管理员部分。这是因为我们已经放置了`AdminGuard`，而您现在并未以管理员身份登录。以管理员身份登录应该可以正常工作。

1.  类似地，我们将在`employee.guard.ts`中添加以下代码：

```ts
...
import { UserType } from '../constants/user-type';
import { AuthService } from '../services/auth.service';
@Injectable({
  providedIn: 'root'
})
export class EmployeeGuard implements CanActivate {
  constructor(private auth: AuthService) {}
  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot): Observable<boolean |     UrlTree> | Promise<boolean | UrlTree> | boolean |     UrlTree {
    return this.auth.loggedInUserType === UserType.    Employee;
  } 
}
```

1.  现在，在`app-routing.module.ts`中的 Employee 路由中添加`EmployeeGuard`如下：

```ts
...
import { EmployeeGuard } from './guards/employee.guard';
const routes: Routes = [
  ...
, {
  path: 'employee',
  loadChildren: () => import('./employee/employee.  module').then(m => m.EmployeeModule),
  canActivate: [AuthGuard, EmployeeGuard]
}];
...
```

现在，只有适当的路由应该可以通过检查已登录的用户类型来访问。

太棒了！现在在保护路由方面，您是一个授权专家。伴随着强大的力量，也伴随着巨大的责任。明智地使用它。

## 工作原理…

路由守卫的`CanActivate`接口是我们的配方的核心，因为它对应于 Angular 中每个路由都可以具有`CanActivate`属性的守卫数组的事实。当应用守卫时，它应该返回一个布尔值或`UrlTree`。我们在配方中专注于布尔值的使用。我们可以直接使用 promise 或者使用 Observable 来返回布尔值。这使得守卫即使在远程数据中也非常灵活。无论如何，对于我们的配方，我们通过检查用户是否已登录（对于`AuthGuard`）以及检查特定路由是否已登录预期类型的用户（`AdminGuard`和`EmployeeGuard`）来使其易于理解。

## 另请参阅

+   在 Angular 路由中防止未经授权的访问（[`angular.io/guide/router#preventing-unauthorized-access`](https://angular.io/guide/router#preventing-unauthorized-access)）

# 使用路由参数

无论是构建使用 Node.js 的 REST API 还是配置 Angular 中的路由，设置路由都是一门绝对的艺术，特别是在处理参数时。在这个配方中，您将创建一些带参数的路由，并学习如何在路由激活后在组件中获取这些参数。

## 准备工作

这个配方的项目位于`chapter07/start_here/working-with-route-params`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器标签中打开应用程序。一旦页面打开，你应该看到一个用户列表。

1.  点击第一个用户，你应该看到以下视图：

![图 7.6 - 用户详细信息未带来正确的用户](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.6_B15150.jpg)

图 7.6 - 用户详细信息未带来正确的用户

现在我们的应用程序在本地运行，让我们在下一节中看看配方的步骤。

## 如何做…

目前的问题是，我们有一个用于打开用户详细信息的路由，但在`UserDetailComponent`中我们不知道点击了哪个用户，也就是说，从服务中获取哪个用户。因此，我们将实现路由参数，将用户的 ID（`uuid`）从主页传递到用户详细信息页面：

1.  首先，我们必须使我们的用户路由能够接受名为`uuid`的路由参数。这将是一个**必需**参数，这意味着没有传递这个参数，路由将无法工作。让我们修改`app-routing.module.ts`来添加这个必需参数到路由定义中，如下所示：

```ts
...
import { UserDetailComponent } from './user-detail/user-detail.component';
const routes: Routes = [
  ...
, {
  path: 'user/:uuid',
  component: UserDetailComponent
}];
...
```

通过这个改变，在主页上点击用户将不再起作用。如果你尝试，你会看到以下错误，因为`uuid`是一个必需的参数：

![图 7.7 - Angular 抱怨无法匹配请求的路由](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.7_B15150.jpg)

图 7.7 - Angular 抱怨无法匹配请求的路由

1.  错误的修复很容易；我们需要在导航到用户路由时传递`uuid`。让我们通过修改`user-card.component.ts`文件来实现这一点：

```ts
import { Component, Input, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { IUser } from '../../interfaces/user.interface';
@Component({
  selector: 'app-user-card',
  templateUrl: './user-card.component.html',
  styleUrls: ['./user-card.component.scss']
})
export class UserCardComponent implements OnInit {
  @Input('user') user: IUser;
  constructor(private router: Router) { }
  ngOnInit(): void {
  }
  cardClicked() {
    this.router.navigate(['    /user/${this.user.login.uuid}'])
  }
}
```

现在我们能够导航到特定用户的路由，并且你也应该能够在地址栏中看到 UUID，如下所示：

![图 7.8 - UUID 显示在地址栏中](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.8_B15150.jpg)

图 7.8 - UUID 显示在地址栏中

1.  为了从`UserService`中获取当前用户，我们需要在`UserDetailComponent`中获取`uuid`值。现在，当从`UserDetailComponent`调用`UserService`的`getUser`方法时，我们发送的是`null`。为了使用用户的 ID，我们可以通过导入`ActivatedRoute`服务从路由参数中获取`uuid`值。更新`user-detail.component.ts`如下：

```ts
...
import { ActivatedRoute } from '@angular/router';
...
export class UserDetailComponent implements OnInit, OnDestroy {
  user: IUser;
  similarUsers: IUser[];
  constructor(
    private userService: UserService,
    private route: ActivatedRoute
  ) {}
  ngOnInit() {
    ...
  }
  ngOnDestroy() {
  }
}
```

1.  我们将在`UserDetailComponent`中创建一个名为`getUserAndSimilarUsers`的新方法，并将代码从`ngOnInit`方法移动到新方法中，如下所示：

```ts
...
export class UserDetailComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    const userId = null;
    this.getUserAndSimilarUsers(userId);
  }
  getUserAndSimilarUsers(userId) {
    this.userService.getUser(userId)
      .pipe(
        mergeMap((user: IUser) => {
          this.user = user;
          return this.userService.          getSimilarUsers(userId);
        })
      ).subscribe((similarUsers: IUser[]) => {
        this.similarUsers = similarUsers;
      })
  }
  ...
}
```

1.  现在我们已经对代码进行了一些重构，让我们尝试使用`ActivatedRoute`服务从路由参数中访问`uuid`，并将其传递到我们的`getUserAndSimilarUsers`方法中，如下所示：

```ts
...
import { mergeMap, takeWhile } from 'rxjs/operators';
import { ActivatedRoute } from '@angular/router';
...
export class UserDetailComponent implements OnInit, OnDestroy {
  componentIsAlive = false;
  constructor(private userService: UserService, private   route: ActivatedRoute ) {}
  ngOnInit() {
    this.componentIsAlive = true;
    this.route.paramMap
      .pipe(
        takeWhile (() => this.componentIsAlive)
      )
      .subscribe((params) => {
        const userId = params.get('uuid');
        this.getUserAndSimilarUsers(userId);
      })
  }
  getUserAndSimilarUsers(userId) {...}
  ngOnDestroy() {
   this.componentIsAlive = false;
  }
}
```

太棒了！通过这个改变，你可以尝试在主页上刷新应用，然后点击任何用户。你应该能够看到当前用户以及加载的相似用户。要了解食谱背后的所有魔法，请参见下一节。

## 它是如何工作的…

一切都始于我们将路由路径更改为 `user/:userId`。这使得 `userId` 成为我们路由的必需参数。拼图的另一部分是在 `UserDetailComponent` 中检索此参数，然后使用它来获取目标用户，以及类似的用户。为此，我们使用 `ActivatedRoute` 服务。`ActivatedRoute` 服务包含了关于当前路由的许多必要信息，因此我们能够通过订阅 `paramMap` 可观察对象来获取当前路由的 `uuid` 参数，因此即使在用户页面停留时参数发生变化，我们仍然执行必要的操作。请注意，我们还创建了一个名为 `componentIsAlive` 的属性。正如您在我们之前的示例中所看到的，我们将它与 `takeWhile` 操作符一起使用，以便在用户从页面导航离开或组件被销毁时自动取消订阅可观察流。

## 另请参阅

+   英雄之旅教程 - `ActivatedRoute` 服务的示例用法（[`angular.io/guide/router-tutorial-toh#route-parameters-in-the-activatedroute-service`](https://angular.io/guide/router-tutorial-toh#route-parameters-in-the-activatedroute-service)）

+   链接参数数组 - Angular 文档（[`angular.io/guide/router#link-parameters-array`](https://angular.io/guide/router#link-parameters-array)）

# 在路由更改之间显示全局加载程序

构建快速响应的用户界面对于赢得用户至关重要。对于最终用户来说，应用程序变得更加愉快，对于应用程序的所有者/创建者来说，这可能带来很多价值。现代网络的核心体验之一是在后台发生某些事情时显示加载程序。在这个示例中，您将学习如何在您的 Angular 应用程序中创建一个全局用户界面加载程序，每当应用程序中发生路由转换时都会显示。

## 准备工作

我们将要使用的项目位于克隆存储库中的 `chapter07/start_here/routing-global-loader` 中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行 `npm install` 以安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这应该会在新的浏览器标签页中打开应用程序，您应该会看到如下所示：

![图 7.9 - routing-global-loader 应用程序正在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.9_B15150.jpg)

图 7.9 - routing-global-loader 应用程序正在 http://localhost:4200 上运行

现在我们的应用程序在本地运行，让我们在下一节中看一下这个示例的步骤。

## 如何做…

对于这个示例，我们有一个包含几个路由的应用程序。我们已经创建了`LoaderComponent`，在路由更改期间我们必须使用它：

1.  我们将从整个应用程序默认显示`LoaderComponent`开始。为此，请在`app.component.html`文件中在具有`content`类的`div`之前添加`<app-loader>`选择器，如下所示：

```ts
<div class="toolbar" role="banner" id="toolbar">
  ...
</div>
<app-loader></app-loader>
<div class="content" role="main">
  <div class="page-section">
    <router-outlet></router-outlet>
  </div>
</div>
```

1.  现在，我们将在`AppComponent`类中创建一个属性来有条件地显示加载程序。我们将在路由期间将此属性标记为`true`，并在路由完成时将其标记为`false`。在`app.component.ts`文件中创建属性如下：

```ts
...
export class AppComponent {
  isLoadingRoute = false;
  // DO NOT USE THE CODE BELOW IN PRODUCTION
  // IT WILL CAUSE PERFORMANCE ISSUES
  constructor(private auth: AuthService, private router:   Router) {
  }
  get isLoggedIn() {
    return this.auth.isLoggedIn();
  }
  logout() {
    this.auth.logout();
    this.router.navigate(['/auth']);
  }
}
```

1.  现在，我们将确保只有在`isLoadingRoute`属性为`true`时才显示`<app-loader>`。为此，请更新`app.component.html`模板文件，包括以下`*ngIf`语句：

```ts
...
<app-loader *ngIf="isLoadingRoute"></app-loader>
<div class="content" role="main">
  <div class="page-section">
    <router-outlet></router-outlet>
  </div>
</div>
```

1.  现在`*ngIf`语句已经就位，我们需要以某种方式将`isLoadingRoute`属性设置为`true`。为了做到这一点，我们将监听路由服务的`events`属性，并在`NavigationStart`事件发生时采取行动。修改`app.component.ts`文件中的代码如下：

```ts
import { Component } from '@angular/core';
import { NavigationStart, Router } from '@angular/router';
import { AuthService } from './services/auth.service';
...
export class AppComponent {
  isLoadingRoute = false;
  // DO NOT USE THE CODE BELOW IN PRODUCTION
  // IT WILL CAUSE PERFORMANCE ISSUES
  constructor(private auth: AuthService, private router:   Router) {
    this.router.events.subscribe((event) => {
      if (event instanceof NavigationStart) {
        this.isLoadingRoute = true;
      }
    })
  }
  get isLoggedIn() {...}
  logout() {...}
}
```

如果您刷新应用程序，您会注意到`<app-loader>`永远不会消失。它现在一直显示着。这是因为我们没有在任何地方将`isLoadingRoute`属性标记为`false`。

1.  要将`isLoadingRoute`标记为`false`，我们需要检查三种不同的事件：`NavigationEnd`，`NavigationError`和`NavigationCancel`。让我们添加一些逻辑来处理这三个事件，并将属性标记为`false`：

```ts
import { Component } from '@angular/core';
import { NavigationCancel, NavigationEnd, NavigationError, NavigationStart, Router } from '@angular/router';
...
export class AppComponent {
  ...
  constructor(private auth: AuthService, private router:   Router) {
    this.router.events.subscribe((event) => {
      if (event instanceof NavigationStart) {
        this.isLoadingRoute = true;
      }
      if (
        event instanceof NavigationEnd ||
        event instanceof NavigationError ||
        event instanceof NavigationCancel
      ) {
        this.isLoadingRoute = false;
      }
    })
  }
  get isLoggedIn() {...}
  logout() {...}
}
```

然后！我们现在有一个全局加载程序，在不同页面之间的路由导航期间显示。

重要提示

在本地运行应用程序时，您将体验到可能是最佳的互联网条件（特别是如果您没有获取远程数据）。因此，您可能根本看不到加载程序，或者只能看到它一小部分时间。为了能够更长时间地看到它，请打开 Chrome DevTools，转到**网络**选项卡，模拟缓慢的 3G，刷新应用程序，然后在路由之间导航。

如果路由具有静态数据，那么您只会在首次导航到该路由时看到加载程序。下次导航到相同的路由时，它可能已经被缓存，因此全局加载程序可能不会显示。

恭喜完成了这个示例。现在你可以在 Angular 应用程序中实现一个全局加载器，它将从导航开始到导航结束都会显示。

## 工作原理…

路由器服务是 Angular 中非常强大的服务。它有很多方法以及我们可以在应用程序中用于不同任务的 Observables。对于这个示例，我们使用了`events` Observable。通过订阅`events` Observable，我们可以监听`Router`服务通过 Observable 发出的所有事件。对于这个示例，我们只对`NavigationStart`、`NavigationEnd`、`NavigationError`和`NavigationCancel`事件感兴趣。`NavigationStart`事件在路由器开始导航时发出。`NavigationEnd`事件在导航成功结束时发出。`NavigationCancel`事件在导航由于**路由守卫**返回`false`或由于某种原因使用`UrlTree`而被取消时发出。`NavigationError`事件在导航期间由于任何原因出现错误时发出。所有这些事件都是`Event`类型的，我们可以通过检查它是否是目标事件的实例来确定事件的类型，使用`instanceof`关键字。请注意，由于我们在`AppComponent`中订阅了`Router.events`属性，我们不必担心取消订阅，因为应用程序中只有一个订阅，而且`AppComponent`在应用程序的整个生命周期中都不会被销毁。

## 另请参阅

+   路由器事件文档（[`angular.io/guide/router#router-events`](https://angular.io/guide/router#router-events)）

+   路由器服务文档（[`angular.io/api/router/Router`](https://angular.io/api/router/Router)）

# 预加载路由策略

我们已经熟悉了如何在导航时延迟加载不同的特性模块。尽管有时，您可能希望预加载后续路由，以使下一个路由导航即时进行，甚至可能希望根据应用程序的业务逻辑使用自定义预加载策略。在这个示例中，您将了解`PreloadAllModules`策略，并将实现一个自定义策略来精选应该预加载哪些模块。

## 准备工作

我们要处理的项目位于克隆存储库中的`chapter07/start_here/route-preloading-strategies`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器标签中打开应用程序，你应该看到类似以下的内容：

![图 7.10 - 在 http://localhost:4200 上运行的 route-preloading-strategies 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.10_B15150.jpg)

图 7.10 - 在 http://localhost:4200 上运行的 route-preloading-strategies 应用程序

1.  使用*Ctrl* + *Shift* + *C*在 Windows 上或*Cmd* + *Shift* + *C*在 Mac 上打开 Chrome DevTools。

1.  转到**网络**选项卡，并仅筛选 JavaScript 文件。你应该看到类似这样的内容：

![图 7.11 - 应用加载时加载的 JavaScript 文件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.11_B15150.jpg)

图 7.11 - 应用加载时加载的 JavaScript 文件

现在我们的应用程序在本地运行，让我们看看下一节

## 如何做…

请注意*图 7.11*中我们如何在注销状态下自动加载`auth-auth-module.js`文件。尽管`AuthModule`中的路由都配置为惰性加载，但我们仍然可以看看如果我们使用`PreloadAllModules`策略，然后自定义预加载策略会发生什么：

1.  我们将首先尝试`PreloadAllModules`策略。要使用它，让我们修改`app-routing.module.ts`文件如下：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule, PreloadAllModules } from '@angular/router';
const routes: Routes = [...];
@NgModule({
  imports: [RouterModule.forRoot(routes, {
    preloadingStrategy: PreloadAllModules
  })],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

如果刷新应用程序，你应该看到不仅`auth-auth-module.js`文件，还有 Admin 和 Employee 的模块文件，如下所示：

![图 7.12 - 使用 PreloadAllModules 策略加载的 JavaScript 文件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.12_B15150.jpg)

图 7.12 - 使用 PreloadAllModules 策略加载的 JavaScript 文件

到目前为止一切顺利。但是如果我们只想预加载 Admin 模块，假设我们的应用主要面向管理员？我们将为此创建一个自定义预加载策略。

1.  让我们通过在项目中运行以下命令来创建一个名为`CustomPreloadStrategy`的服务：

```ts
ng g s services/custom-preload-strategy
```

1.  为了在 Angular 中使用我们的预加载策略服务，我们的服务需要实现`@angular/router`包中的`PreloadingStrategy`接口。修改新创建的服务如下：

```ts
import { Injectable } from '@angular/core';
import { PreloadingStrategy } from '@angular/router';
@Injectable({
  providedIn: 'root'
})
export class CustomPreloadStrategyService implements PreloadingStrategy {
  constructor() { }
}
```

1.  接下来，我们需要实现我们的服务的`PreloadingStrategy`接口中的`preload`方法，以使其正常工作。让我们修改`CustomPreloadStrategyService`以实现`preload`方法，如下所示：

```ts
import { Injectable } from '@angular/core';
import { PreloadingStrategy, Route } from '@angular/router';
import { Observable, of } from 'rxjs';
@Injectable({
  providedIn: 'root'
})
export class CustomPreloadStrategyService implements PreloadingStrategy {
  constructor() { }
  preload(route: Route, load: () => Observable<any>):   Observable<any> {
    return of(null)
  }
}
```

1.  现在，我们的`preload`方法返回`of(null)`。相反，为了决定要预加载哪些路由，我们将在我们的路由定义中添加一个对象作为`data`对象，其中包含一个名为`shouldPreload`的布尔值。让我们通过修改`app-routing.module.ts`来快速完成这一点：

```ts
...
const routes: Routes = [{...}, {
  path: 'auth',
  loadChildren: () => import('./auth/auth.module').then(m => m.AuthModule),
  data: { shouldPreload: true }
}, {
  path: 'admin',
  loadChildren: () => import('./admin/admin.module').  then(m => m.AdminModule),
  data: { shouldPreload: true }
}, {
  path: 'employee',
  loadChildren: () => import('./employee/employee.  module').then(m => m.EmployeeModule),
  data: { shouldPreload: false }
}];
...
```

1.  所有`shouldPreload`设置为`true`的路由应该被预加载，如果它们设置为`false`，那么它们就不应该被预加载。我们将创建两种方法。一种是我们想要预加载路由的情况，另一种是我们不想要预加载路由的情况。让我们修改`custom-preload-strategy.service.ts`，添加以下方法：

```ts
export class CustomPreloadStrategyService implements PreloadingStrategy {
  ...
  loadRoute(route: Route, loadFn: () => Observable<any>):   Observable<any> {
    console.log('Preloading done for route: ${route.    path}')
    return loadFn();
  }
  noPreload(route: Route): Observable<any> {
    console.log('No preloading set for: ${route.path}');
    return of(null);
  }
  ...
}
```

1.  太棒了！现在我们必须在`preload`方法中使用*步骤 6*中创建的方法。让我们修改方法，使用路由定义中`data`对象的`shouldPreload`属性。代码应该如下所示：

```ts
...
export class CustomPreloadStrategyService implements PreloadingStrategy {
...
  preload(route: Route, load: () => Observable<any>):   Observable<any> {
    try {
      const { shouldPreload } = route.data;
      return shouldPreload ? this.loadRoute(route, load)       : this.noPreload(route);
    }
    catch (e) {
      console.error(e);
      return this.noPreload(route);
    }
  }
}
```

1.  最后一步是使用我们自定义的预加载策略。为了这样做，修改`app-routing-module.ts`文件如下：

```ts
import { NgModule } from '@angular/core';
import { Routes, RouterModule, PreloadAllModules ← Remove } from '@angular/router';
import { CustomPreloadStrategyService } from './services/custom-preload-strategy.service';
const routes: Routes = [...];
@NgModule({
  imports: [RouterModule.forRoot(routes, {
    preloadingStrategy: CustomPreloadStrategyService
  })],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

看！如果您现在刷新应用并监视**网络**选项卡，您会注意到只有 Auth 和 Admin 的 JavaScript 文件被预加载，而 Employee 模块没有预加载，如下所示：

![图 7.13-仅使用自定义预加载策略预加载 Auth 和 Admin 模块](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.13_B15150.jpg)

图 7.13-仅使用自定义预加载策略预加载 Auth 和 Admin 模块

您还可以查看控制台日志，查看哪些路由已经预加载。您应该看到以下日志：

![图 7.14-仅预加载 Auth 和 Admin 模块的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_7.14_B15150.jpg)

图 7.14-仅预加载 Auth 和 Admin 模块的日志

现在您已经完成了这个教程，看看下一节关于这是如何工作的。

## 它是如何工作的...

Angular 提供了一种很好的方法来为我们的特性模块实现自定义预加载策略。我们可以很容易地决定哪些模块应该预加载，哪些不应该。在这个教程中，我们学习了一种非常简单的方法，通过在路由配置的`data`对象中添加一个名为`shouldPreload`的属性来配置预加载。我们创建了自己的自定义预加载策略服务，命名为`CustomPreloadStrategyService`，它实现了`@angular/router`包中的`PreloadingStrategy`接口。这个想法是使用`PreloadingStrategy`接口中的`preload`方法，它允许我们决定一个路由是否应该预加载。这是因为 Angular 会使用我们的自定义预加载策略遍历每个路由，并决定哪些路由应该预加载。就是这样。现在我们可以将`data`对象中的`shouldPreload`属性分配给我们想要在应用启动时预加载的任何路由。

## 另请参阅

+   `web.dev`上的路由预加载策略文章（[`web.dev/route-preloading-in-angular/`](https://web.dev/route-preloading-in-angular/)）


# 第八章：*第八章*：精通 Angular 表单

获取用户输入是几乎任何现代应用程序的一个重要部分。无论是对用户进行身份验证、征求反馈意见，还是填写业务关键表单，知道如何实现和呈现表单给最终用户始终是一个有趣的挑战。在本章中，您将了解 Angular 表单以及如何使用它们创建出色的用户体验。

以下是本章将要涵盖的示例：

+   创建您的第一个模板驱动 Angular 表单

+   使用模板驱动表单进行表单验证

+   测试模板驱动表单

+   创建您的第一个响应式表单

+   使用响应式表单进行表单验证

+   创建一个异步验证器函数

+   测试响应式表单

+   使用响应式表单控件进行去抖动

+   使用`ControlValueAccessor`编写自定义表单控件

# 技术要求

对于本章的示例，请确保您的计算机上已安装了**Git**和**NodeJS**。您还需要安装`@angular/cli`包，可以在终端中使用`npm install -g @angular/cli`来安装。本章的代码可以在[`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter08`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter08)找到。

# 创建您的第一个模板驱动 Angular 表单

让我们在这个示例中开始熟悉 Angular 表单。在这个示例中，您将了解模板驱动表单的基本概念，并将使用模板驱动表单 API 创建一个基本的 Angular 表单。

## 准备工作

此示例中的项目位于`chapter08/start_here/template-driven-forms`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这将在新的浏览器选项卡中打开应用程序，并且您应该看到以下视图：

![图 8.1-在 http://localhost:4200 上运行的模板驱动表单应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.1_B15150.jpg)

图 8.1-在 http://localhost:4200 上运行的模板驱动表单应用程序

## 如何做…

我们已经有一个 Angular 应用程序，其中已经有一个发布日志组件和一堆设置，例如`src/app/classes`文件夹下的`ReleaseLog`类。因此，在这个示例中，我们将创建一个模板驱动表单，允许用户选择一个应用程序并提交一个发布版本。让我们开始吧：

1.  首先，在项目的根目录中打开终端，并创建一个发布表单组件，如下所示：

```ts
ng g c components/release-form
```

该命令应在`src/app/components`文件夹中创建一个名为`ReleaseFormComponent`的新组件。

1.  将新创建的组件添加到`VersionControlComponent`的模板中，并修改`version-control.component.html`文件如下：

```ts
<div class="version-control">
  <app-release-form></app-release-form>
  <app-release-logs [logs]="releaseLogs"></app-release-  logs>
</div>
```

接下来，让我们调整一些样式，以便在`VersionControlComponent`中使用发布表单。

1.  修改`version-control.component.scss`文件如下：

```ts
:host {
  ...
  min-width: 400px;
  .version-control {
    display: flex;
    justify-content: center;
  }
  app-release-logs,
  app-release-form {
    flex: 1;
  }
  app-release-form {
    margin-right: 20px;
  }
}
```

在`ReleaseFormComponent`模板中，我们将有两个输入。一个用于选择我们要发布的应用程序，另一个用于我们要发布的版本。

1.  让我们修改`release-form.component.ts`文件，将`Apps`枚举添加为一个本地属性，以便我们稍后可以在模板中使用：

```ts
import { Component, OnInit } from '@angular/core';
import { IReleaseLog } from 'src/app/classes/release-log';
import { Apps } from 'src/app/constants/apps';
...
export class ReleaseFormComponent implements OnInit {
  apps = Object.values(Apps);
  newLog: IReleaseLog = {
    app: Apps.CALENDAR,
    version: '0.0.0'
  };
  constructor() { }
  ngOnInit(): void {
  }
}
```

1.  现在让我们添加我们表单的模板。修改`release-form.component.html`文件，并添加以下代码：

```ts
<form>
  <div class="form-group">
    <label for="appName">Select App</label>
    <select class="form-control" id="appName" required>
      <option value="">--Choose--</option>
      <option *ngFor="let app of apps"       [value]="app">{{app}}</option>
    </select>
  </div>
  <div class="form-group">
    <label for="versionNumber">Version Number</label>
    <input type="text" class="form-control"     id="versionNumber" aria-describedby="versionHelp"     placeholder="Enter version number">
    <small id="versionHelp" class="form-text     text-muted">Use semantic versioning (x.x.x)</small>
  </div>
  <button type="submit" class="btn btn-primary">  Submit</button>
</form>
```

1.  现在我们需要集成模板驱动表单。让我们在`app.module.ts`文件中添加`FormsModule`，如下所示：

```ts
...
import { ReleaseFormComponent } from './components/release-form/release-form.component';
import { FormsModule } from '@angular/forms';
@NgModule({
  declarations: [...],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule
  ],
  ...
})
export class AppModule { }
```

1.  现在我们可以让我们的表单在模板中工作。让我们修改`release-form.component.html`文件，为表单创建一个模板变量，命名为`#releaseForm`。我们还将使用`[(ngModel)]`绑定来针对`newLog`属性的适当值：

```ts
<form #releaseForm="ngForm">
  <div class="form-group">
    <label for="appName">Select App</label>
    <select name="app" [(ngModel)]="newLog.app"     class="form-control" id="appName" required>
      <option value="">--Choose--</option>
      <option *ngFor="let app of apps"       [value]="app">{{app}}</option>
    </select>
  </div>
  <div class="form-group">
    <label for="versionNumber">Version Number</label>
    <input name="version" [(ngModel)]="newLog.version"     type="text" class="form-control" id="versionNumber"     aria-describedby="versionHelp" placeholder="Enter     version number">
    <small id="versionHelp" class="form-text text-    muted">Use semantic versioning (x.x.x)</small>
  </div>
  <button type="submit" class="btn btn-primary">  Submit</button>
</form>
```

1.  创建一个当表单提交时将被调用的方法。修改`release-form.component.ts`文件，添加一个名为`formSubmit`的新方法。当调用此方法时，我们将使用 Angular 的`@Output`发射器发出`ReleaseLog`的新实例，如下所示：

```ts
import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { NgForm } from '@angular/forms';
import { IReleaseLog, ReleaseLog } from 'src/app/classes/release-log';
...
export class ReleaseFormComponent implements OnInit {
  @Output() newReleaseLog = new   EventEmitter<ReleaseLog>();
  apps = Object.values(Apps);
  ...
  ngOnInit(): void {
  }
  formSubmit(form: NgForm): void {
    const { app, version } = form.value;
    const newLog: ReleaseLog = new ReleaseLog(app,     version)
    this.newReleaseLog.emit(newLog);
  }
}
```

1.  现在更新模板，使用表单提交上的`formSubmit`方法，并修改`release-form.component.html`文件如下：

```ts
<form  #releaseForm="ngForm" (ngSubmit)="formSubmit(releaseForm)">
  ...
</form>
```

1.  现在我们需要修改`VersionControlComponent`以便对新发布日志进行操作。为了这样做，修改`version-control.component.html`文件，以便监听来自`ReleaseFormComponent`的`newReleaseLog`输出事件，如下所示：

```ts
<div class="version-control">
  <app-release-form (newReleaseLog)="addNewReleaseLog   ($event)"></app-release-form>
  <app-release-logs [logs]="releaseLogs"></app-release-  logs>
</div>
```

1.  太棒了！让我们在`version-control.component.ts`文件中创建`addNewReleaseLog`方法，并将接收到的`ReleaseLog`添加到`releaseLogs`数组中。您的代码应如下所示：

```ts
...
export class VersionControlComponent implements OnInit {
  releaseLogs: ReleaseLog[] = [];
  ...
  addNewReleaseLog(log: ReleaseLog) {
    this.releaseLogs.unshift(log);
  }
}
```

太棒了！在几分钟内，我们就能够在 Angular 中创建我们的第一个模板驱动表单。如果现在刷新应用程序并尝试创建一些发布，您应该会看到类似以下内容的东西：

![图 8.2 - 模板驱动表单应用程序最终输出](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.2_B15150.jpg)

图 8.2 - 模板驱动表单应用程序最终输出

现在您已经了解了如何创建模板驱动表单，让我们看看下一节，了解它是如何工作的。

## 它是如何工作的…

在 Angular 中使用模板驱动表单的关键在于`FormsModule`，`ngForm`指令，通过使用`ngForm`指令创建**模板变量**，并在模板中为输入使用`[(ngModel)]`双向数据绑定以及`name`属性。我们首先创建了一个带有一些输入的简单表单。然后，我们添加了`FormsModule`，这是必须的，用于使用`ngForm`指令和`[(ngModel)]`双向数据绑定。一旦我们添加了该模块，我们就可以在`ReleaseFormComponent`中使用该指令和数据绑定，使用新创建的本地属性命名为`newLog`。请注意，它可以是`ReleaseLog`类的实例，但我们将其保留为`IReleaseLog`类型的对象，因为我们不使用`ReleaseLog`类的`message`属性。通过使用`[(ngModel)]`和`#releaseForm`模板变量，我们可以使用 Angular 的`<form>`指令的`ngSubmit`发射器提交表单。请注意，我们将`releaseForm`变量传递给`formSubmit`方法，这样可以更容易地测试功能。提交表单时，我们使用表单的值创建一个新的`ReleaseLog`项目，并使用`newReleaseLog`输出发射器发射它。请注意，如果为新发布日志提供无效的`version`，应用程序将抛出错误并且不会创建发布日志。这是因为我们在`ReleaseLog`类的`constructor`中验证了版本。最后，当`VersionControlComponent`捕获到`newReleaseLog`事件时，它调用`addNewReleaseLog`方法，将我们新创建的发布日志添加到`releaseLogs`数组中。由于`releaseLogs`数组作为`@Input()`传递给`ReleaseLogsComponent`，因此它会立即显示出来。

## 另请参阅

+   在 Angular 中构建模板驱动表单：[`angular.io/guide/forms#building-a-template-driven-form`](https://angular.io/guide/forms#building-a-template-driven-form)

# 使用模板驱动表单进行表单验证

良好的用户体验是获得更多喜欢使用您的应用程序的用户的关键。而使用表单是用户并不真正喜欢的事情之一。为了确保用户在填写表单上花费最少的时间，并且尽快完成，我们可以实现表单验证，以确保用户尽快输入适当的数据。在这个配方中，我们将看看如何在模板驱动表单中实现表单验证。

## 准备工作

这个配方的项目位于`chapter08/start_here/tdf-form-validation`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器选项卡中打开应用程序，并且您应该看到应用程序如下所示：

![图 8.3 - 运行在 http://localhost:4200 上的 TDF 表单验证应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.3_B15150.jpg)

图 8.3 - 运行在 http://localhost:4200 上的 TDF 表单验证应用程序

现在我们已经在本地运行了应用程序，让我们在下一节中看看这个配方涉及的步骤。

## 如何做…

我们现在有了上一个配方中的应用程序，一个简单的 Angular 应用程序，使用`ngForm`和`ngModel`指令创建一个模板驱动表单。该表单用于创建发布日志。在这个配方中，我们将在用户输入时使这个表单更好地验证输入。让我们开始吧：

1.  首先，我们将从`@angular/forms`包中添加一些验证器，这些验证器是响应式表单 API 的一部分。我们将对两个输入应用**required**验证，并对版本输入应用**regex**验证。我们需要为我们的两个输入创建模板变量。我们将分别命名它们为`nameInput`和`versionInput`。修改`release-form.component.html`文件中的代码，使其如下所示：

```ts
<form  #releaseForm="ngForm" (ngSubmit)="formSubmit(releaseForm)">
  <div class="form-group">
    <label for="appName">Select App</label>
    <select #nameInput="ngModel" name="app"     [(ngModel)]="newLog.app" class="form-control"     id="appName" required>
      <option value="">--Choose--</option>
      <option *ngFor="let app of apps"       [value]="app">{{app}}</option>
    </select>
  </div>
  <div class="form-group">
    <label for="versionNumber">Version Number</label>
    <input #versionInput="ngModel" name="version"     [(ngModel)]="newLog.version" type="text"     class="form-control" id="versionNumber" aria-    describedby="versionHelp" placeholder="Enter     version number" required>
    <small id="versionHelp" class="form-text     text-muted">Use semantic versioning (x.x.x)</small>
  </div>
  <button type="submit" class="btn btn-primary">  Submit</button>
</form>
```

1.  现在我们可以使用模板变量来应用验证。让我们从名称输入开始。在验证方面，名称输入不应为空，并且应从选择框中选择一个应用程序。当输入无效时，让我们显示一个默认的 Bootstrap 警报。修改`release-form.component.html`文件中的代码。它应该如下所示：

```ts
<form  #releaseForm="ngForm" (ngSubmit)="formSubmit(releaseForm)">
  <div class="form-group">
    <label for="appName">Select App</label>
    <select #nameInput="ngModel" name="app"     [(ngModel)]="newLog.app" class="form-control"     id="appName" required>
      <option value="">--Choose--</option>
      <option *ngFor="let app of apps"       [value]="app">{{app}}</option>
    </select>
    <div [hidden]="nameInput.valid || nameInput.pristine"     class="alert alert-danger">
      Please choose an app
    </div>
  </div>
  <div class="form-group">
    ...
  </div>
  <button type="submit" class="btn btn-primary">Submit   </button>
</form>
```

1.  要验证版本名称输入，我们需要应用来自`src/app/constants/regexes.ts`文件的`SEMANTIC_VERSION`正则表达式。将常量添加为`ReleaseFormComponent`类中的本地属性，添加到`release-form.component.ts`文件中，如下所示：

```ts
...
import { Apps } from 'src/app/constants/apps';
import { REGEXES } from 'src/app/constants/regexes';
...
export class ReleaseFormComponent implements OnInit {
  @Output() newReleaseLog = new   EventEmitter<ReleaseLog>();
  apps = Object.values(Apps);
  versionInputRegex = REGEXES.SEMANTIC_VERSION;
  ...
}
```

1.  现在，在模板中使用`versionInputRegex`来应用验证并显示相关错误。修改`release-form.component.html`文件，使代码如下所示：

```ts
<form  #releaseForm="ngForm" (ngSubmit)="formSubmit(releaseForm)">
  <div class="form-group">
    ...
  </div>
  <div class="form-group">
    <label for="versionNumber">Version Number</label>
    <input #versionInput="ngModel"     [pattern]="versionInputRegex" name="version"     [(ngModel)]="newLog.version" type="text"     class="form-control" id="versionNumber" aria-    describedby="versionHelp" placeholder="Enter     version number" required>
    <small id="versionHelp" class="form-text     text-muted">Use semantic versioning (x.x.x)</small>
    <div
      [hidden]="versionInput.value &&       (versionInput.valid || versionInput.pristine)"
      class="alert alert-danger"
    >
      Please write an appropriate version number
    </div>
  </div>
  <button type="submit" class="btn btn-primary">  Submit</button>
</form>
```

1.  刷新应用程序，并尝试通过从“选择应用程序”下拉菜单中选择名为**--选择--**的第一个选项，并清空版本输入字段来使两个输入无效。您应该会看到以下错误：![图 8.4 - 使用 ngModel 和验证显示输入错误](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.4_B15150.jpg)

图 8.4 - 使用 ngModel 和验证显示输入错误

1.  接下来，我们将添加一些样式，使我们的输入在验证时更加直观。让我们在`release-form.component.scss`文件中添加一些样式，如下所示：

```ts
:host {
  /* Error messages */
  .alert {
    margin-top: 16px;
  }
  /* Valid form input */
  .ng-valid[required], .ng-valid.required  {
    border-bottom: 3px solid #259f2b;
  }
  /* Invalid form input */
  .ng-invalid:not(form)  {
    border-bottom: 3px solid #c92421;
  }
}
```

1.  最后，让我们围绕表单提交进行验证。如果输入值无效，我们将禁用**提交**按钮。让我们修改`release-form.component.html`模板如下：

```ts
<form #releaseForm="ngForm" (ngSubmit)="formSubmit(releaseForm)">
  <div class="form-group">
    ...
  </div>
  <div class="form-group">
    ...
  </div>
  <button type="submit" [disabled]="releaseForm.invalid"   class="btn btn-primary">Submit</button>
</form>
```

如果现在刷新应用程序，您会发现只要一个或多个输入无效，提交按钮就会被禁用。

太棒了！您刚学会了如何验证模板驱动表单，并使模板驱动表单的整体用户体验稍微好一些。

## 它是如何工作的...

本教程的核心组件是`ngForm`和`ngModel`指令。我们可以很容易地确定提交按钮是否应该可点击（未禁用），这取决于表单是否有效，也就是说，如果表单中的所有输入都具有有效值。请注意，我们在`<form>`元素上使用了使用`#releaseForm="ngForm"`语法创建的模板变量。这是由于`ngForm`指令能够导出为模板变量。因此，我们能够在提交按钮的`[disabled]`绑定中使用`releaseForm.invalid`属性来有条件地禁用它。我们还根据输入可能无效的条件显示单个输入的错误。在这种情况下，我们显示 Bootstrap 的`alert`元素（带有 CSS 类`alert`的`<div>`）。我们还在表单输入上使用 Angular 提供的类`ng-valid`和`ng-invalid`，以根据输入值的有效性以某种方式突出显示输入。这个教程有趣的地方在于，我们通过确保应用程序名称的输入包含一个非假值来验证它，其中`<select>`框的第一个`<option>`的值为`""`。更有趣的是，我们还通过在输入上绑定`[pattern]`到一个正则表达式来验证用户输入版本名称。否则，我们将不得不等待用户提交表单，然后才能进行验证。因此，我们通过在用户输入版本时提供错误信息来提供出色的用户体验。

## 另请参阅

+   显示和隐藏验证错误消息（Angular 文档）：[`angular.io/guide/forms#show-and-hide-validation-error-messages`](https://angular.io/guide/forms#show-and-hide-validation-error-messages)

+   NgForm 文档：`https://angular.io/api/forms/NgForm`

# 测试模板驱动表单

为了确保我们为最终用户构建健壮且无错误的表单，最好是对表单进行测试。这样可以使代码更具弹性，更不容易出错。在本教程中，您将学习如何使用单元测试来测试模板驱动表单。

## 准备工作

本教程的项目位于`chapter08/start_here/testing-td-forms`中。

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器选项卡中打开应用程序，您应该会看到应用程序如下所示：

![图 8.5 - 正在运行的 Testing Template-Driven Forms 应用程序，网址为 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.5_B15150.jpg)

图 8.5 - 正在运行的 Testing Template-Driven Forms 应用程序，网址为 http://localhost:4200

现在我们已经在本地运行了应用程序，让我们在下一节中看看这个配方涉及的步骤。

## 如何做…

我们有来自上一个配方的应用程序，其中包含用于创建发布日志的模板驱动表单。该表单还对输入应用了验证。让我们开始研究如何测试这个表单：

1.  首先，运行以下命令来运行单元测试：

```ts
npm run test
```

运行命令后，您应该看到打开一个新的 Chrome 窗口来运行单元测试。我们六个测试中的一个测试失败了。您可能会在自动化的 Chrome 窗口中看到类似以下内容：

![图 8.6 - 使用 Karma 和 Jasmine 在自动化 Chrome 窗口中运行单元测试](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.6_B15150.jpg)

图 8.6 - 使用 Karma 和 Jasmine 在自动化 Chrome 窗口中运行单元测试

1.  `ReleaseFormComponent > should create`测试失败了，因为我们没有将`FormsModule`添加到测试中。注意`Export of name 'ngForm' not found`错误。让我们在`release-form.component.spec.ts`中的测试模块配置中导入`FormsModule`，如下所示：

```ts
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { FormsModule } from '@angular/forms';
import { ReleaseFormComponent } from './release-form.component';
describe('ReleaseFormComponent', () => {
  ...
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ ReleaseFormComponent ],
      imports: [ FormsModule ]
    })
    .compileComponents();
  });
  ...
  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
```

如果您现在查看测试，您应该看到所有测试都通过了，如下所示：

![图 8.7 - 在适当的测试中导入 FormsModule 后，所有测试都通过了](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.7_B15150.jpg)

图 8.7 - 在适当的测试中导入 FormsModule 后，所有测试都通过了

为了正确测试表单，我们将添加一些测试，一个用于成功的输入，一个用于每个无效的输入。为此，我们需要访问我们组件中的表单，因为我们正在编写单元测试。

1.  让我们在`release-form.component.ts`文件中使用`@ViewChild()`装饰器来访问我们组件类中的`#releaseForm`，如下所示：

```ts
import { Component, EventEmitter, OnInit, Output, ViewChild } from '@angular/core';
...
@Component({
  selector: 'app-release-form',
  templateUrl: './release-form.component.html',
  styleUrls: ['./release-form.component.scss']
})
export class ReleaseFormComponent implements OnInit {
  @Output() newReleaseLog = new   EventEmitter<ReleaseLog>();
  @ViewChild('releaseForm') releaseForm: NgForm;
  apps = Object.values(Apps);
  versionInputRegex = REGEXES.SEMANTIC_VERSION;
  ...
}
```

1.  现在让我们添加一个新的测试。我们将编写一个测试，用于验证当两个输入都具有有效值时的情况。将测试添加到`release-form.component.spec.ts`文件中，如下所示：

```ts
import { ComponentFixture, TestBed, fakeAsync } from '@angular/core/testing';
import { ReleaseFormComponent } from './release-form.component';
describe('ReleaseFormComponent', () => {
  ...
  it('should create', () => {
    expect(component).toBeTruthy();
  });
  it('should submit a new release log with the correct   input values', fakeAsync( () => {
    expect(true).toBeFalsy();
  }));
});
```

1.  到目前为止，新的测试失败了。让我们尝试填写表单中的值，提交按钮，并确保我们的`@Output`发射器命名为`newReleaseLog`从`releaseForm`中发射出正确的值。测试的内容应该如下所示：

```ts
...
import { ReleaseLog } from 'src/app/classes/release-log';
...
it('should submit a new release log with the correct input values', fakeAsync(async () => {
    const submitButton = fixture.nativeElement.    querySelector('button[type="submit"]');
    const CALENDAR_APP = component.apps[2];
    spyOn(component.newReleaseLog, 'emit');
    await fixture.whenStable(); // wait for Angular     to configure the form
    component.releaseForm.controls[    'version'].setValue('2.2.2');
    component.releaseForm.controls[    'app'].setValue(CALENDAR_APP);
    submitButton.click();
    const expectedReleaseLog = new ReleaseLog(CALENDAR_    APP, '2.2.2');
    expect(component.newReleaseLog.emit)    .toHaveBeenCalledWith(expectedReleaseLog);
  }));
```

当你保存文件时，你应该看到新的测试通过了预期的值。它应该出现在 Chrome 标签页中如下所示：

![图 8.8 - 成功提交表单的新测试通过](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.8_B15150.jpg)

图 8.8 - 成功提交表单的新测试通过

1.  让我们为表单中提供了不正确版本的情况添加一个测试。提交按钮应该被禁用，并且`formSubmit`方法应该抛出错误。在`release-form.component.spec.ts`文件中添加一个新的测试，如下所示：

```ts
...
describe('ReleaseFormComponent', () => {
  ...
  it('should submit a new release log with the correct   input values', fakeAsync(async () => {
    const submitButton = fixture.nativeElement.    querySelector('button[type="submit"]');
    const CALENDAR_APP = component.apps[2];
    spyOn(component.newReleaseLog, 'emit');
    await fixture.whenStable(); // wait for Angular     to configure the form
    const expectedError = 'Invalid version provided.     Please provide a valid version as     (major.minor.patch)';
    component.releaseForm.controls[    'version'].setValue('x.x.x');
    component.releaseForm.controls[    'app'].setValue(CALENDAR_APP);
    expect(() => component.formSubmit(component.    releaseForm))
      .toThrowError(expectedError);
    fixture.detectChanges();
    expect(submitButton.hasAttribute(    'disabled')).toBe(true);
    expect(component.newReleaseLog.emit)    .not.toHaveBeenCalled();
  }));
});
```

1.  让我们添加最后一个测试，确保当我们没有为发布日志选择应用程序时，提交按钮被禁用。在`release-form.component.spec.ts`文件中添加一个新的测试，如下所示：

```ts
...
describe('ReleaseFormComponent', () => {
  ...
  it('should disable the submit button when we   don\'t have an app selected', fakeAsync(async () => {
    const submitButton = fixture.nativeElement.    querySelector('button[type="submit"]');
    spyOn(component.newReleaseLog, 'emit');
    await fixture.whenStable(); // wait for Angular     to configure the form
    component.releaseForm.controls[    'version'].setValue('2.2.2');
    component.releaseForm.controls[    'app'].setValue(null);
    fixture.detectChanges();
    expect(submitButton.hasAttribute(    'disabled')).toBe(true);
    expect(component.newReleaseLog.emit     ).not.toHaveBeenCalled();
  }));
});
```

如果你查看 Karma 测试窗口，你应该看到所有新的测试都通过了，如下所示：

![图 8.9 - 针对该配方的所有测试都通过](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.9_B15150.jpg)

图 8.9 - 针对该配方的所有测试都通过

太棒了！现在你已经掌握了一堆测试模板驱动表单的技巧。其中一些技巧可能仍需要一些解释。请查看下一节，了解它是如何工作的。

## 它是如何工作的…

测试模板驱动表单可能有点挑战，因为它取决于表单的复杂程度，您想要测试的用例以及这些用例的复杂程度。在我们的配方中，我们首先在`ReleaseFormComponent`的测试文件的导入中包含了`FormsModule`。这确保了测试知道`ngForm`指令，并且不会抛出相关错误。对于所有成功输入的测试，我们对`ReleaseFormComponent`类中定义的`newReleaseLog`发射器的`emit`事件进行了监听。这是因为我们知道当输入正确时，用户应该能够点击提交按钮，因此在`formSubmit`方法内，`newReleaseLog`发射器的`emit`方法将被调用。请注意，我们在每个测试中都使用了`fixture.whenStable()`。这是为了确保 Angular 已经完成了编译，我们的`ngForm`，命名为`#releaseForm`，已经准备就绪。对于`当版本不正确时应禁用提交按钮`的测试，我们依赖于`formSubmit`抛出错误。这是因为我们知道无效的版本将在创建新的发布日志时导致`ReleaseLog`类的`constructor`中出错。这个测试中有一个有趣的地方是我们使用了以下代码：

```ts
expect(() => component.formSubmit(component.releaseForm))
      .toThrowError(expectedError);
```

这里有趣的是，我们需要自己调用 `formSubmit` 方法，并使用 `releaseForm`。我们不能只写 `expect(component.formSubmit(component.releaseForm)).toThrowError(expectedError);`，因为那样会直接调用函数并导致错误。所以，我们需要在这里传递一个匿名函数，Jasmine 将调用这个匿名函数，并期望这个匿名函数抛出一个错误。最后，我们通过在 `fixture.nativeElement` 上使用 `querySelector` 来获取按钮，然后使用 `submitButton.hasAttribute('disabled')` 检查提交按钮上的 `disabled` 属性，以确保我们的提交按钮是启用还是禁用的。

## 参见

+   测试模板驱动表单：[`angular.io/guide/forms-overview#testing-template-driven-forms`](https://angular.io/guide/forms-overview#testing-template-driven-forms)

# 创建您的第一个响应式表单

在之前的配方中，您已经了解了模板驱动表单，并且现在有信心使用它们构建 Angular 应用程序。现在猜猜？响应式表单甚至更好。许多知名的工程师和企业在 Angular 社区推荐使用响应式表单。原因是在构建复杂表单时，它们的易用性。在这个配方中，您将构建您的第一个响应式表单，并学习其基本用法。

## 准备工作

这个配方的项目位于 `chapter08/start_here/reactive-forms` 中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

1.  点击第一个用户的名称，您应该看到以下视图：

![图 8.10 – 响应式表单应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.10_B15150.jpg)

图 8.10 – 响应式表单应用程序在 http://localhost:4200 上运行

现在我们已经在本地运行了应用程序，让我们在下一节中看看这个配方涉及的步骤。

## 如何做…

到目前为止，我们有一个具有 `ReleaseLogsComponent` 的应用程序，它显示了我们创建的一堆发布日志。我们还有 `ReleaseFormComponent`，它通过表单创建发布日志。现在我们需要使用 Reactive forms API 将当前表单变成一个响应式表单。让我们开始吧：

1.  首先，我们需要将 `ReactiveFormsModule` 导入到我们的 `AppModule` 的导入中。让我们通过修改 `app.module.ts` 文件来做到这一点：

```ts
...
import { ReleaseFormComponent } from './components/release-form/release-form.component';
import { ReactiveFormsModule } from '@angular/forms';
@NgModule({
  declarations: [...],
  imports: [
    BrowserModule,
    AppRoutingModule,
    ReactiveFormsModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

1.  让我们现在创建响应式表单。我们将在`ReleaseFormComponent`类中创建一个带有所需控件的`FormGroup`。修改`release-form.component.ts`文件如下：

```ts
...
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { REGEXES } from 'src/app/constants/regexes';
@Component(...)
export class ReleaseFormComponent implements OnInit {
  apps = Object.values(Apps);
  versionInputRegex = REGEXES.SEMANTIC_VERSION;
  releaseForm = new FormGroup({
    app: new FormControl('', [Validators.required]),
    version: new FormControl('', [
      Validators.required,
      Validators.pattern(REGEXES.SEMANTIC_VERSION)
    ]),
  })
  ...
}
```

1.  现在我们已经有了名为`releaseForm`的表单，让我们在模板中使用它来绑定表单。修改`release-form.component.html`文件如下：

```ts
<form [formGroup]="releaseForm">
  ...
</form>
```

1.  太棒了！现在我们已经绑定了表单组，我们还可以绑定单个表单控件，这样当我们最终提交表单时，我们可以获取每个单独表单控件的值。进一步修改`release-form.component.html`文件如下：

```ts
<form [formGroup]="releaseForm">
  <div class="form-group">
    ...
    <select formControlName="app" class="form-control"     id="appName" required>
      ...
    </select>
  </div>
  <div class="form-group">
    ...
    <input formControlName="version" type="text"     class="form-control" id="versionNumber" aria-    describedby="versionHelp" placeholder="Enter     version number">
    <small id="versionHelp" class="form-text     text-muted">Use semantic versioning (x.x.x)</small>
  </div>
  ...
</form>
```

1.  让我们决定当我们提交这个表单时会发生什么。我们将在模板中调用一个名为`formSubmit`的方法，并在表单提交时传递`releaseForm`。修改`release-form.component.html`文件如下：

```ts
<form [formGroup]="releaseForm" (ngSubmit)="formSubmit(releaseForm)">
  ...
</form>
```

1.  `formSubmit`方法目前还不存在。让我们现在在`ReleaseFormComponent`类中创建它。我们还将在控制台上记录该值，并使用`@Output`发射器发射该值。修改`release-form.component.ts`文件如下：

```ts
import { Component, OnInit, Output, EventEmitter } from '@angular/core';
...
import { ReleaseLog } from 'src/app/classes/release-log';
...
@Component(...)
export class ReleaseFormComponent implements OnInit {
  @Output() newReleaseLog = new   EventEmitter<ReleaseLog>();
  apps = Object.values(Apps);
  ...
  formSubmit(form: FormGroup): void {
    const { app, version } = form.value;
    console.log({app, version});
    const newLog: ReleaseLog = new ReleaseLog(app,     version)
    this.newReleaseLog.emit(newLog);
  }
}
```

如果您现在刷新应用程序，填写完表单，然后点击**提交**，您应该在控制台上看到如下日志：

![图 8.11 - 显示使用响应式表单提交的值的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.11_B15150.jpg)

图 8.11 - 显示使用响应式表单提交的值的日志

1.  由于我们通过`newReleaseLog`输出发射器发射了新创建的发布日志的值，我们可以在`version-control.component.html`文件中监听此事件，并相应地添加新日志。让我们修改文件如下：

```ts
<div class="version-control">
  <app-release-form (newReleaseLog)="addNewReleaseLog   ($event)"></app-release-form>
  <app-release-logs [logs]="releaseLogs">  </app-release-logs>
</div>
```

1.  刷新应用程序，您应该看到新的发布日志被添加到发布日志视图中。您还应该在控制台上看到日志，如下面的截图所示：

![图 8.12 - 在表单提交时添加到日志视图的新日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.12_B15150.jpg)

图 8.12 - 在表单提交时添加到日志视图的新日志

太棒了！现在你知道如何使用响应式表单 API 创建基本的响应式表单了。请参考下一节，了解它是如何工作的。

## 它是如何工作的…

该食谱始于我们的 Angular 应用程序中有一个基本的 HTML 表单，没有与之绑定的 Angular 魔法。我们首先在 `AppModule` 中导入了 `ReactiveFormsModule`。如果您正在使用所选编辑器的 Angular 语言服务，当您导入 `ReactiveFormsModule` 到应用程序中并且没有将其与响应式表单绑定时，您可能会看到一个错误，换句话说，没有与 `FormGroup` 绑定。好吧，这就是我们做的。我们使用 `FormGroup` 构造函数创建了一个响应式表单，并使用 `FormControl` 构造函数创建了相关的表单控件。然后，我们监听了 `<form>` 元素上的 `ngSubmit` 事件，以提取 `releaseForm` 的值。完成后，我们使用 `@Ouput()` 命名为 `newReleaseLog` 发射了这个值。请注意，我们还定义了此发射器将发射的值的类型为 `IReleaseLog`；定义这些是一个好习惯。这个发射器是必需的，因为 `ReleaseLogsComponent` 是组件层次结构中 `ReleaseFormComponent` 的兄弟组件。因此，我们通过父组件 `VersionControlComponent` 进行通信。最后，我们在 `VersionControlComponent` 模板中监听 `newReleaseLog` 事件的发射，并通过 `addNewReleaseLog` 方法向 `releaseLogs` 数组添加新日志。并且这个 `releaseLogs` 数组被传递给 `ReleaseLogsComponent`，它会显示所有添加的日志。

## 另请参阅

+   Angular 的响应式表单指南：[`angular.io/guide/reactive-forms`](https://angular.io/guide/reactive-forms)

# 使用响应式表单进行表单验证

在上一篇食谱中，您学会了如何创建一个响应式表单。现在，我们将学习如何测试它们。在这个食谱中，您将学习一些测试响应式表单的基本原则。我们将使用上一篇食谱中的相同示例（发布日志应用程序），并实现多个测试用例。

## 准备工作

我们将要使用的项目位于克隆存储库中的 `chapter08/start_here/validating-reactive-forms` 中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这应该会在新的浏览器标签中打开应用程序，您应该会看到它如下所示：

![图 8.13 – 在 http://localhost:4200 上运行的验证响应式表单应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.13_B15150.jpg)

图 8.13 – 在 http://localhost:4200 上运行的验证响应式表单应用程序

现在我们已经在本地运行了应用程序，让我们在下一节中看看这个配方涉及的步骤。

## 如何做...

对于这个配方，我们使用的是已经实现了响应式表单的发布日志应用程序，尽管到目前为止我们还没有任何输入验证。如果你只是选择一个应用程序并提交表单，你会在控制台上看到以下错误：

![图 8.14 - 在没有表单验证的情况下提交响应式表单应用程序时出错](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.14_B15150.jpg)

图 8.14 - 在没有表单验证的情况下提交响应式表单应用程序时出错

我们将加入一些表单验证来增强用户体验，并确保表单不能使用无效输入提交。让我们开始：

1.  首先，我们将从`@angular/forms`包中添加一些验证，这些验证是响应式表单 API 的一部分。我们将在两个输入上应用`required`验证器，并在`version`表单控件上应用`pattern`验证器。更新`release-form.component.ts`文件如下：

```ts
import { Component, OnInit, Output, EventEmitter } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
...
import { REGEXES } from 'src/app/constants/regexes';
@Component({...})
export class ReleaseFormComponent implements OnInit {
  ...
  versionInputRegex = REGEXES.SEMANTIC_VERSION;
  releaseForm = new FormGroup({
    app: new FormControl('', Validators.required),
    version: new FormControl('', [
      Validators.required,
      Validators.pattern(this.versionInputRegex)
    ]),
  })
  ...
}
```

1.  现在我们将在视图中添加提示，以在选择无效输入时向用户显示错误。修改`release-form.component.html`文件如下：

```ts
<form [formGroup]="releaseForm" (ngSubmit)="formSubmit(releaseForm)">
  <div class="form-group">
    <label for="appName">Select App</label>
    <select formControlName="app" class="form-control"     id="appName">
      ...
    </select>
    <div
      [hidden]="releaseForm.get('app').valid ||       releaseForm.get('app').pristine"
      class="alert alert-danger">
      Please choose an app
    </div>
  </div>
  <div class="form-group">
    ...
    <small id="versionHelp" class="form-text     text-muted">Use semantic versioning (x.x.x)</small>
    <div [hidden]="releaseForm.get('version').valid ||     releaseForm.get('version').pristine"
      class="alert alert-danger">
      Please write an appropriate version number
    </div>
  </div>
  <button type="submit" class="btn btn-primary">Submit   </button>
</form>
```

1.  我们还将添加一些样式来以更好的 UI 显示错误。将以下样式添加到`release-form.component.scss`文件中：

```ts
:host {
  /* Error messages */
  .alert {
    margin-top: 16px;
  }
  /* Valid form input */
  .ng-valid:not(form),
  .ng-valid.required {
    border-bottom: 3px solid #259f2b;
  }
  /* Invalid form input */
  .ng-invalid:not(form) {
    border-bottom: 3px solid #c92421;
  }
}
```

刷新应用程序，当输入值错误时，你应该看到带有红色边框的输入。一旦输入或选择无效输入，错误将如下所示：

![图 8.15 - 显示无效输入值的红色边框](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.15_B15150.jpg)

图 8.15 - 显示无效输入值的红色边框

1.  最后，让我们围绕表单提交进行验证。如果输入无效，我们将禁用**提交**按钮。让我们修改`release-form.component.html`模板如下：

```ts
<form [formGroup]="releaseForm" (ngSubmit)="formSubmit(releaseForm)">
  <div class="form-group">
    ...
  </div>
  <div class="form-group">
    ...
  </div>
  <button type="submit" [disabled]="releaseForm.invalid"   class="btn btn-primary">Submit</button>
</form>
```

如果现在刷新应用程序，你会看到只要一个或多个输入无效，提交按钮就会被禁用。

这就结束了这个配方。让我们看看下一节，看看它是如何工作的。

## 它是如何工作的...

我们通过添加验证器开始了这个教程，Angular 已经提供了一堆验证器，包括`Validators.email`、`Validators.pattern`和`Validators.required`。我们在教程中分别为应用程序名称和版本的输入使用了`required`验证器和`pattern`验证器。之后，为了显示无效输入的提示/错误，我们添加了一些条件样式，以在输入上显示底部边框。我们还添加了一些`<div>`元素，带有`class="alert alert-danger"`，这些基本上是 Bootstrap 警报，用于显示表单控件的无效值的错误。请注意，我们使用以下模式来隐藏错误元素：

```ts
[hidden]="releaseForm.get(CONTROL_NAME).valid || releaseForm.get(CONTROL_NAME).pristine"
```

我们使用`.pristine`条件来确保一旦用户选择了正确的输入并修改了输入，我们再次隐藏错误，以便在用户输入或进行其他选择时不显示错误。最后，我们确保即使表单控件的值无效，表单也无法提交。我们使用`[disabled]="releaseForm.invalid"`来禁用提交按钮。

## 另见

+   Angular 验证响应式表单的文档：[`angular.io/guide/reactive-forms#validating-form-input`](https://angular.io/guide/reactive-forms#validating-form-input)

# 创建一个异步验证器函数

在 Angular 中，表单验证非常简单，原因在于 Angular 提供了超级棒的验证器。这些验证器是同步的，意味着一旦您更改输入，验证器就会启动并立即提供有关值有效性的信息。但有时，您可能会依赖于后端 API 的一些验证。这些情况需要一种称为异步验证器的东西。在本教程中，您将创建您的第一个异步验证器。

## 准备工作

我们将要使用的项目位于克隆存储库中的`chapter08/start_here/asynchronous-validator`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这将在新的浏览器选项卡中打开应用程序，您应该看到类似以下内容的内容：

![图 8.16 - 异步验证器应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.16_B15150.jpg)

图 8.16 - 异步验证器应用程序在 http://localhost:4200 上运行

现在我们的应用程序正在运行，让我们在下一节中看看这个配方涉及的步骤。

如何做到...

我们已经在发布日志应用程序中设置了一些内容。我们在`src/assets`文件夹中有一个`data.json`文件，其中包含发布日志的每个目标应用程序的版本。我们将创建一个异步验证器，以确保每个应用程序的新版本都比`data.json`文件中指定的版本大。让我们开始：

1.  首先，我们将为该配方创建异步验证器函数。让我们在`version.service.ts`文件的`VersionService`类中创建一个名为`versionValidator`的方法，如下所示：

```ts
...
import { compareVersion } from 'src/app/utils';
import { AbstractControl, AsyncValidatorFn, ValidationErrors } from '@angular/forms';
import { Observable, of } from 'rxjs';
@Injectable({...})
export class VersionService {
  ...
  versionValidator(appNameControl: AbstractControl):   AsyncValidatorFn {
    // code here
  }
  ...
}
```

1.  现在我们将定义验证器函数的内容。让我们修改`versionValidator`方法如下：

```ts
versionValidator(appNameControl: AbstractControl): AsyncValidatorFn {
  return (control: AbstractControl):   Observable<ValidationErrors> => {
  // if we don't have an app selected, do not validate
  if (!appNameControl.value) {
    return of(null);
  }
  return this.getVersionLog().pipe(
    map(vLog => {
      const newVersion = control.value;
      const previousVersion = vLog[appNameControl.value];
      // check if the new version is greater than          previous version
      return compareVersion(newVersion, previousVersion)       === 1 ? null : {
        newVersionRequired: previousVersion
      };
    }))
  }
}
```

1.  现在我们已经有了验证器函数，让我们将其添加到版本号的表单控件中。修改`release-form.component.ts`文件如下：

```ts
import { Component, OnInit, Output, EventEmitter } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { IReleaseLog, ReleaseLog } from 'src/app/classes/release-log';
import { Apps } from 'src/app/constants/apps';
import { REGEXES } from 'src/app/constants/regexes';
import { VersionService } from 'src/app/core/services/version.service';
@Component({...})
export class ReleaseFormComponent implements OnInit {
  ...
  constructor(private versionService: VersionService) { }
  ngOnInit(): void {
    this.releaseForm.get('version')    .setAsyncValidators(
      this.versionService.versionValidator(
        this.releaseForm.get('app')
      )
    )
  }
  ...
}
```

1.  现在我们将使用验证器来增强表单的用户体验，修改`release-form.component.html`文件。为了方便使用，让我们使用`*ngIf`指令将内容包装在`<ng-container>`元素中，并在模板中创建一个变量用于版本表单控件，如下所示：

```ts
<form [formGroup]="releaseForm" (ngSubmit)="formSubmit(releaseForm)">
  <ng-container *ngIf="releaseForm.get('version')   as versionControl">
    <div class="form-group">
      ...
    </div>
    <div class="form-group">
      ...
    </div>
    <button type="submit" [disabled]="releaseForm.    invalid" class="btn btn-primary">Submit</button>
  </ng-container>
</form>
```

1.  现在让我们添加错误消息。我们将使用我们的自定义错误`newVersionRequired`，从验证器函数中显示错误，当指定的版本不比先前的版本更新时。修改`release-form.component.html`文件如下：

```ts
<form [formGroup]="releaseForm" (ngSubmit)="formSubmit(releaseForm)">
  <ng-container *ngIf="releaseForm.get('version')   as versionControl">
    <div class="form-group">
      ...
    </div>
    <div class="form-group">
      <label for="versionNumber">Version Number</label>
      <input formControlName="version" type="text"       class="form-control" id="versionNumber"       aria-describedby="versionHelp" placeholder="Enter       version number">
      ...
      <div *ngIf="(versionControl.      getError('newVersionRequired') &&       !versionControl.pristine)"
        class="alert alert-danger">
        The version number should be greater         than the last version '{{versionControl.        errors['newVersionRequired']}}'
      </div>
    </div>
    <button [disabled]="releaseForm.invalid"     class="btn btn-primary">Submit</button>
  </ng-container>
</form>
```

尝试选择一个应用程序并添加一个较低的版本号，现在您应该看到以下错误：

![图 8.17 - 提供较低版本号时显示的错误](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.17_B15150.jpg)

图 8.17 - 提供较低版本号时显示的错误

1.  目前的一个问题是，我们能够在异步验证进行时提交表单。这是因为 Angular 默认情况下会将错误标记为`null`，直到验证完成。为了解决这个问题，我们可以在模板中显示一个加载消息，而不是**提交**按钮。修改`release-form.component.html`文件如下：

```ts
<form [formGroup]="releaseForm" (ngSubmit)="formSubmit(releaseForm)">
  <ng-container *ngIf="releaseForm.get('version')   as versionControl">
    <div class="form-group">
      ...
    </div>
    <div class="form-group">
      ...
    </div>
    <button *ngIf="versionControl.status     !== 'PENDING'; else loader" type="submit"     [disabled]="releaseForm.invalid" class="btn      btn-primary">Submit</button>
  </ng-container>
  <ng-template #loader>
    Please wait...
  </ng-template>
</form>
```

如果您刷新应用程序，选择一个应用程序，并输入一个有效的版本号，您应该看到以下**请稍候...**消息：

![图 8.18 - 异步验证进行时的加载消息](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.18_B15150.jpg)

图 8.18 - 异步验证进行时的加载消息

1.  我们仍然有一个问题，即用户可以快速输入并按*Enter*提交表单。为了防止这种情况发生，让我们在`release-form.component.ts`文件的`formSubmit`方法中添加一个检查，如下所示：

```ts
  formSubmit(form: FormGroup): void {
    if (form.get('version').status === 'PENDING') {
      return;
    }
    const { app, version } = form.value;
    ...
  }
```

1.  最后，我们还有另一个问题要处理。如果我们选择了一个有效的版本号并更改了应用程序，尽管逻辑上是错误的，我们仍然可以提交带有输入版本号的表单。为了处理这个问题，我们应该在`'app'`表单控件的值发生变化时更新`'version'`表单控件的验证。为此，请按照以下方式修改`release-form.component.ts`文件：

```ts
import { Component, OnInit, Output, EventEmitter, OnDestroy } from '@angular/core';
...
import { takeWhile } from 'rxjs/operators';
...
@Component({...})
export class ReleaseFormComponent implements OnInit, OnDestroy {
  @Output() newReleaseLog = new   EventEmitter<IReleaseLog>();
  isComponentAlive = false;
  apps = Object.values(Apps);
  ...
  ngOnInit(): void {
    this.isComponentAlive = true;
    this.releaseForm.get     ('version').setAsyncValidators(...)
    this.releaseForm.get('app').valueChanges
      .pipe(takeWhile(() => this.isComponentAlive))
      .subscribe(() => {
        this.releaseForm.get         ('version').updateValueAndValidity();
      })
  }
  ngOnDestroy() {
    this.isComponentAlive = false;
  }
  ...
}
```

很棒！现在你知道如何在 Angular 中为响应式表单创建异步验证器函数了。既然你已经完成了这个示例，请参考下一节，看看它是如何工作的。

## 它是如何工作的...

Angular 提供了一种非常简单的方法来创建异步验证器函数，它们也非常方便。在这个示例中，我们首先创建了名为`versionValidator`的验证器函数。请注意，我们为验证器函数命名了一个名为`appNameControl`的参数。这是因为我们想要获取正在验证版本号的应用程序名称。还要注意，我们将返回类型设置为`AsyncValidatorFn`，这是 Angular 所要求的。验证器函数应该返回一个`AsyncValidatorFn`，这意味着它将返回一个函数（让我们称之为**内部函数**），该函数接收一个`AbstractControl`并返回一个`ValidatorErrors`的`Observable`。在内部函数中，我们使用`VersionService`的`getVersionLog()`方法，使用`HttpClient`服务获取`data.json`文件。一旦我们从`data.json`中获取了特定应用程序的版本，我们就将表单中输入的版本与`data.json`中的值进行比较，以验证输入。请注意，我们并不只是返回一个`ValidationErrors`对象，其中`newVersionRequired`属性设置为`true`，而是实际上将其设置为`previousVersion`，以便稍后向用户显示。

创建验证器函数后，我们通过在`ReleaseFormComponent`类中使用`FormControl.setAsyncValidators()`方法将其附加到版本名称的表单控件上。然后我们在模板中使用名为`newVersionRequired`的验证错误来显示错误消息，以及来自`data.json`文件的版本。

我们还需要处理这样一种情况，即在验证进行中，表单控件在验证完成之前是有效的。这使我们能够在版本名称的验证正在进行时提交表单。我们通过检查`FormControl.status`的值是否为`'PENDING'`来处理这个问题，在这种情况下，我们隐藏提交按钮，并在此期间显示**请等待…**消息。请注意，我们还在`ReleaseFormComponent`类的`formSubmit`方法中添加了一些逻辑，以检查版本号的`FormControl.status`是否为`'PENDING'`，在这种情况下，我们只需执行`return;`。

食谱中的另一个有趣之处是，如果我们添加了一个有效的版本号并更改了应用程序，我们仍然可以提交表单。我们通过向`'app'`表单控件的`.valueChanges`添加订阅来处理这个问题，因此每当这种情况发生时，我们使用`.updateValueAndValidity()`方法在`'version'`表单控件上触发另一个验证。

## 参见

+   AsyncValidator Angular 文档：[`angular.io/api/forms/AsyncValidator#provide-a-custom-async-validator-directive`](https://angular.io/api/forms/AsyncValidator#provide-a-custom-async-validator-directive)

# 测试响应式表单

为了确保我们为最终用户构建健壮且无错误的表单，围绕您的表单编写测试是一个非常好的主意。这使得代码更具弹性，更不容易出错。在这个食谱中，您将学习如何使用单元测试测试您的模板驱动表单。

## 做好准备

此处的项目位于`chapter08/start_here/testing-reactive-forms`：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器标签中打开应用程序，您应该看到应用程序如下：

![图 8.19 - 在 http://localhost:4200 上运行的测试响应式表单应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.19_B15150.jpg)

图 8.19 - 在 http://localhost:4200 上运行的测试响应式表单应用程序

现在我们的应用程序在本地运行，让我们在下一节中看看这个食谱涉及的步骤。

## 如何做…

我们有一个使用一些验证实现的响应式表单的 Release Logs 应用程序。在这个食谱中，我们将为表单实现一些测试。让我们开始吧：

1.  首先，在单独的终端窗口中运行以下命令来运行单元测试：

```ts
yarn test
```

运行命令后，你应该看到一个新的 Chrome 窗口实例被打开，运行测试如下：

![图 8.20 - 单元测试与 Karma 和 Jasmine 在自动化 Chrome 窗口中运行

图 8.20 - 单元测试与 Karma 和 Jasmine 在自动化 Chrome 窗口中运行

图 8.20 - 单元测试与 Karma 和 Jasmine 在自动化 Chrome 窗口中运行

1.  让我们为所有输入都有有效值的情况添加第一个测试。在这种情况下，我们应该提交表单，并通过`newReleaseLog`输出的发射器发出表单的值。修改`release-form.component.spec.ts`文件如下：

```ts
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReleaseLog } from 'src/app/classes/release-log';
...
describe('ReleaseFormComponent', () => {
  ...
  it('should submit a new release log with the correct   input values', (() => {
    const app = component.apps[2];
    const version = '2.2.2';
    const expectedReleaseLog = new ReleaseLog(app,     version);
    spyOn(component.newReleaseLog, 'emit');
    component.releaseForm.setValue({ app, version });
    component.formSubmit(component.releaseForm);
    expect(component.newReleaseLog.emit)    .toHaveBeenCalledWith(expectedReleaseLog);
  }));
});
```

如果你现在查看测试，你应该看到新的测试通过如下：

![图 8.21 - 成功输入的测试用例通过](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.21_B15150.jpg)

![图 8.21 - 成功输入的测试用例通过

1.  让我们为表单中提供了不正确版本的情况添加一个测试。**提交**按钮应该被禁用，并且`formSubmit`方法应该抛出错误。在你的`release-form.component.spec.ts`文件中添加一个新的测试，如下所示： 

```ts
...
describe('ReleaseFormComponent', () => {
  ...
  it('should throw an error for a new release log with   the incorrect version values', (() => {
    const submitButton = fixture.nativeElement.    querySelector('button[type="submit"]');
    const app = component.apps[2];
    const version = 'x.x.x';
    spyOn(component.newReleaseLog, 'emit');
    const expectedError = 'Invalid version provided.     Please provide a valid version as (major.minor.    patch)';
    component.releaseForm.setValue({ app, version });
    expect(() => component.formSubmit(component.    releaseForm))
      .toThrowError(expectedError);
    expect(submitButton.hasAttribute(    'disabled')).toBe(true);
    expect(component.newReleaseLog.emit     ).not.toHaveBeenCalled();
  }));
});
```

1.  让我们添加我们的最终测试，确保当我们没有为发布日志选择应用程序时，**提交**按钮被禁用。在`release-form.component.spec.ts`文件中添加一个新的测试，如下所示：

```ts
...
describe('ReleaseFormComponent', () => {
  ...
  it('should disable the submit button when we   don\'t have an app selected', (() => {
    const submitButton = fixture.nativeElement.    querySelector('button[type="submit"]');
    spyOn(component.newReleaseLog, 'emit');
    const app = '';
    const version = '2.2.2';
    component.releaseForm.setValue({ app, version });
    submitButton.click();
    fixture.detectChanges();
    expect(submitButton.hasAttribute(    'disabled')).toBe(true);
    expect(component.newReleaseLog.emit     ).not.toHaveBeenCalled();
  }));
});
```

如果你查看 Karma 测试窗口，你应该看到所有新的测试都通过了如下：

![图 8.22 - 所有测试通过了食谱](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.22_B15150.jpg)

![图 8.22 - 所有测试用例通过了食谱

太棒了！现在你知道如何为响应式表单编写一些基本的测试了。请参考下一节，了解它是如何工作的。

## 它是如何工作的...

测试响应式表单甚至不需要在 Angular 10 中将`ReactiveFormsModule`导入测试模块。对于我们食谱中的所有测试，我们都对`ReleaseFormComponent`类中定义的`newReleaseLog`发射器的`emit`事件进行了监听。这是因为我们知道当输入正确时，用户应该能够单击**提交**按钮，因此在`formSubmit`方法内，将调用`newReleaseLog`发射器的`emit`方法。对于涵盖`'version'`表单控件有效性的测试，我们依赖于`formSubmit`抛出错误。这是因为我们知道无效的版本将在创建新的发布日志时导致`ReleaseLog`类的`constructor`中出错。在这个测试中有一个有趣的地方是我们使用了以下代码：

```ts
expect(() => component.formSubmit(component.releaseForm))
      .toThrowError(expectedError);
```

有趣的是，我们需要自己调用`formSubmit`方法来调用`releaseForm`。我们不能只写`expect(component.formSubmit(component.releaseForm)).toThrowError(expectedError);`，因为那样会直接调用函数并导致错误。所以我们需要在这里传递一个匿名函数，Jasmine 会调用这个匿名函数，并期望这个匿名函数抛出一个错误。最后，我们通过在`fixture.nativeElement`上使用`querySelector`来获取按钮，然后使用`submitButton.hasAttribute('disabled')`来检查**提交**按钮上的`disabled`属性，确保我们的**提交**按钮是启用还是禁用。

## 另请参阅

+   测试响应式表单：[`angular.io/guide/forms-overview#testing-reactive-forms`](https://angular.io/guide/forms-overview#testing-reactive-forms)

# 使用反弹与响应式表单控件

如果您正在构建一个中到大型规模的 Angular 应用程序，并使用响应式表单，那么您肯定会遇到一种情况，您可能希望在响应式表单上使用反弹。这可能是出于性能原因，或者为了节省 HTTP 调用。因此，在这个示例中，您将学习如何在响应式表单控件上使用反弹。

## 准备工作

我们要处理的项目位于克隆存储库中的`chapter08/start_here/using-debounce-with-rfc`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这将在新的浏览器选项卡中打开应用程序，并且您应该看到如下所示：

![图 8.23 - 使用反弹与响应式表单控件应用程序正在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.23_B15150.jpg)

图 8.23 - 使用反弹与响应式表单控件应用程序正在 http://localhost:4200 上运行

现在，您会注意到每输入一个字符，我们就会向 API 发送一个新的 HTTP 请求，如下所示：

![图 8.24 - 在输入时发送的多个 HTTP 调用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.24_B15150.jpg)

图 8.24 - 在输入时发送的多个 HTTP 调用

现在我们的应用程序在本地运行，让我们在下一节中看看这个示例涉及的步骤。

## 如何做…

对于这个示例，我们使用一个使用 RandomUser.me API 获取用户的应用程序。如*图 8.24*所示，我们在输入变化时发送新的 HTTP 调用。让我们开始避免这样做的示例：

1.  将防抖功能添加到表单中非常容易。让我们在`home.component.ts`文件中使用`debounceTime`操作符，如下所示：

```ts
...
import { debounceTime, takeWhile } from 'rxjs/operators';
@Component({...})
export class HomeComponent implements OnInit, OnDestroy {
  searchDebounceTime = 300;
  ...
  ngOnInit() {
    ...
    this.searchUsers();
    this.searchForm.get('username').valueChanges
      .pipe(
        debounceTime(this.searchDebounceTime),
        takeWhile(() => !!this.componentAlive)
      )
      .subscribe(() => {
        this.searchUsers();
      })
  }
}
```

嗯，有趣的是，就任务而言，这就是本节的全部内容。但我确实希望能给您带来更多。因此，我们将编写一些有趣的测试。

1.  现在我们将添加一个测试，以确保在`searchDebounceTime`过去之前不会调用我们的`searchUsers`方法。在`home.component.spec.ts`文件中添加以下测试：

```ts
import { HttpClientModule } from '@angular/common/http';
import { waitForAsync, ComponentFixture, discardPeriodicTasks, fakeAsync, TestBed, tick } from '@angular/core/testing';
import { HomeComponent } from './home.component';
describe('HomeComponent', () => {
  ...
  it('should not send an http request before the   debounceTime of 300ms', fakeAsync(async () => {
    spyOn(component, 'searchUsers');
    component.searchForm.get(    'username').setValue('iri');
    tick(component.searchDebounceTime - 10);     // less than desired debounce time
    expect(component.searchUsers     ).not.toHaveBeenCalled();
    discardPeriodicTasks();
  }));
});
```

1.  现在我们将为`searchDebounceTime`过去并且应该已调用`searchUsers()`方法的情况添加一个测试。在`home.component.spec.ts`文件中添加以下新测试：

```ts
...
describe('HomeComponent', () => {
  ...
  it('should send an http request after the debounceTime   of 300ms', fakeAsync(async () => {
    spyOn(component, 'searchUsers');
    component.searchForm.get(    'username').setValue('iri');
    tick(component.searchDebounceTime + 10); // more     than desired debounce time
    expect(component.searchUsers     ).toHaveBeenCalled();
    discardPeriodicTasks();
  }));
});
```

如果刷新 Karma 测试 Chrome 窗口，您将看到所有测试都通过了，如下所示：

![图 8.25 - 本节所有测试都通过](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.25_B15150.jpg)

图 8.25 - 本节所有测试都通过

1.  现在，运行`npm start`命令再次启动应用程序。然后，在输入到搜索框时监视网络调用。您会看到`debounceTime`操作符在您停止输入 300 毫秒后只调用 1 次，如下截图所示：

![图 8.26 - 在 300 毫秒防抖后仅发送一个网络调用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.26_B15150.jpg)

图 8.26 - 在 300 毫秒防抖后仅发送一个网络调用

太棒了！现在，您知道如何在响应式表单控件中使用防抖，以及如何编写测试来检查防抖是否正常工作。这就结束了本节。让我们参考下一节，看看它是如何工作的。

## 工作原理…

本节的主要任务非常简单。我们只是从`rxjs`包中使用了`debounceTime`操作符，并将其与我们的响应式表单控件的`.valueChanges` Observable 一起使用。由于我们在`.subscribe()`方法之前在`.pipe()`操作符中使用它，所以每当我们改变输入的值，无论是输入值还是按下退格键，它都会根据`searchDebounceTime`属性等待`300ms`，然后调用`searchUsers()`方法。

我们还在这个食谱中编写了一些测试。请注意，我们对`searchUsers()`方法进行了间谍，因为每当我们更改`'username'`表单控件的值时，它就应该被调用。我们将测试函数包装在`fakeAsync`方法中，这样我们就可以控制测试中用例的异步行为。然后我们使用`FormControl.setValue()`方法设置表单控件的值，这应该在经过`searchDebounceTime`的时间后触发作为`.subscribe()`方法参数提供的方法。然后我们使用`tick()`方法和`searchDebounceTime`的值，这样就模拟了时间的异步流逝。然后我们编写我们的`expect()`块来检查`searchUsers()`方法是否应该被调用。最后，在测试结束时，我们使用`discardPeriodicTasks()`方法。我们使用这个方法是为了避免出现`Error: 1 periodic timer(s) still in the queue.`错误，以及我们的测试工作。

## 另请参阅

+   RxJS DebounceTime 操作符：[`rxjs-dev.firebaseapp.com/api/operators/debounceTime`](https://rxjs-dev.firebaseapp.com/api/operators/debounceTime)

# 使用 ControlValueAccessor 编写自定义表单控件

Angular 表单很棒。虽然它们支持默认的 HTML 标签，如 input、textarea 等，但有时，您可能希望定义自己的组件，以从用户那里获取值。如果这些输入的变量是您已经在使用的 Angular 表单的一部分，那就太好了。

在这个食谱中，您将学习如何使用 ControlValueAccessor API 创建自己的自定义表单控件，这样您就可以在模板驱动表单和响应式表单中使用表单控件。

## 准备工作

这个食谱的项目位于`chapter08/start_here/custom-form-control`中：

1.  在 Visual Studio Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序，您应该会看到以下视图：

![图 8.27 - 自定义表单控件应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.27_B15150.jpg)

图 8.27 - 自定义表单控件应用程序在 http://localhost:4200 上运行

现在我们的应用程序在本地运行，让我们在下一节中看看这个食谱涉及的步骤。

## 如何做…

我们有一个简单的 Angular 应用。它有两个输入和一个**提交**按钮。输入用于评论，要求用户为这个虚构物品的评分和任何评论提供价值。我们将使用 ControlValueAccessor API 将评分输入转换为自定义表单控件。让我们开始吧：

1.  让我们为我们的自定义表单控件创建一个组件。在项目根目录中打开终端并运行以下命令：

```ts
ng g c components/rating
```

1.  现在我们将为评分组件创建星星 UI。修改`rating.component.html`文件如下：

```ts
<div class="rating">
  <div
    class="rating__star"
    [ngClass]="{'rating__star--active': (
      (!isMouseOver && value  >= star) ||
      (isMouseOver && hoveredRating  >= star)
    )}"
    (mouseenter)="onRatingMouseEnter(star)"
    (mouseleave)="onRatingMouseLeave()"
    (click)="selectRating(star)"
    *ngFor="let star of [1, 2, 3, 4, 5]; let i = index;">
    <i class="fa fa-star"></i>
  </div>
</div>
```

1.  在`rating.component.scss`文件中为评分组件添加样式如下：

```ts
.rating {
  display: flex;
  margin-bottom: 10px;
  &__star {
    cursor: pointer;
    color: grey;
    padding: 0 6px;
    &:first-child {
      padding-left: 0;
    }
    &:last-child {
      padding-right: 0;
    }
    &--active {
      color: orange;
    }
  }
}
```

1.  我们还需要修改`RatingComponent`类来引入必要的方法和属性。让我们修改`rating.component.ts`文件如下：

```ts
...
export class RatingComponent implements OnInit {
  value = 2;
  hoveredRating = 2;
  isMouseOver = false;

  ...
  onRatingMouseEnter(rating: number) {
    this.hoveredRating = rating;
    this.isMouseOver = true;
  }
  onRatingMouseLeave() {
    this.hoveredRating = null;
    this.isMouseOver = false;
  }
  selectRating(rating: number) {
    this.value = rating;
  }
}
```

1.  现在我们需要在`home.component.html`文件中使用这个评分组件而不是已有的输入。修改文件如下：

```ts
<div class="home">
  <div class="review-container">
    ...
    <form class="input-container" [formGroup]=    "reviewForm" (ngSubmit)="submitReview(reviewForm)">
      <div class="mb-3">
        <label for="ratingInput" class="form-        label">Rating</label>
        <app-rating formControlName="rating">        </app-rating>
      </div>
      <div class="mb-3">
        ...
      </div>
      <button id="submitBtn" [disabled]="reviewForm.      invalid" class="btn btn-dark" type="submit">      Submit</button>
    </form>
  </div>
</div>
```

如果现在刷新应用并悬停在星星上，你会看到颜色随着悬停而改变。选定的评分也会被突出显示如下：

![图 8.28 - 悬停在星星上的评分组件](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.28_B15150.jpg)

图 8.28 - 悬停在星星上的评分组件

1.  现在让我们为我们的评分组件实现`ControlValueAccessor`接口。它需要实现一些方法，我们将从`onChange()`和`onTouched()`方法开始。修改`rating.component.ts`文件如下：

```ts
import { Component, OnInit } from '@angular/core';
import { ControlValueAccessor } from '@angular/forms';
@Component({...})
export class RatingComponent implements OnInit, ControlValueAccessor {
  ...
  constructor() { }
  onChange: any = () => { };
  onTouched: any = () => { };
  ngOnInit(): void {
  }
  ...
  registerOnChange(fn: any){
    this.onChange = fn;
  }
  registerOnTouched(fn: any) {
    this.onTouched = fn;
  }
}
```

1.  我们现在将添加必要的方法来在需要时禁用输入并设置表单控件的值，换句话说，`setDisabledState()`和`writeValue()`方法。我们还将在`RatingComponent`类中添加`disabled`和`value`属性如下：

```ts
import { Component, Input, OnInit } from '@angular/core';
import { ControlValueAccessor } from '@angular/forms';
@Component({...})
export class RatingComponent implements OnInit, ControlValueAccessor {
  ...
  isMouseOver = false;
  @Input() disabled = false;
  constructor() { }
  ...
  setDisabledState(isDisabled: boolean): void {
    this.disabled = isDisabled;
  }
  writeValue(value: number) {
    this.value = value;
  }
}
```

1.  需要使用`disabled`属性来防止在其值为`true`时进行任何 UI 更改。`value`变量的值也不应该被更新。修改`rating.component.ts`文件如下：

```ts
...
@Component({...})
export class RatingComponent implements OnInit, ControlValueAccessor {
  ...
  isMouseOver = false;
  @Input() disabled = true;
  ...

  onRatingMouseEnter(rating: number) {
    if (this.disabled) return;
    this.hoveredRating = rating;
    this.isMouseOver = true;
  }
  ...
  selectRating(rating: number) {
    if (this.disabled) return;
    this.value = rating;
  }
  ...
}
```

1.  让我们确保将`value`变量的值发送到`ControlValueAccessor`，因为这是我们以后要访问的内容。同时，让我们将`disabled`属性设置回`false`。修改`RatingComponent`类中的`selectRating`方法如下：

```ts
...
@Component({...})
export class RatingComponent implements OnInit, ControlValueAccessor {
  ...
  @Input() disabled = false;
  constructor() { }
  ...
  selectRating(rating: number) {
    if (this.disabled) return;
    this.value = rating;
    this.onChange(rating);
  }
  ...
}
```

1.  我们需要告诉 Angular，我们的`RatingComponent`类有一个值访问器，否则在`<app-rating>`元素上使用`formControlName`属性会抛出错误。让我们向`RatingComponent`类的装饰器添加一个`NG_VALUE_ACCESSOR`提供者，如下所示：

```ts
import { Component, forwardRef, Input, OnInit } from '@angular/core';
import { ControlValueAccessor, NG_VALUE_ACCESSOR } from '@angular/forms';
@Component({
  selector: 'app-rating',
  templateUrl: './rating.component.html',
  styleUrls: ['./rating.component.scss'],
  providers: [{
    provide: NG_VALUE_ACCESSOR,
    useExisting: forwardRef(() => RatingComponent),
    multi: true
  }]
})
export class RatingComponent implements OnInit, ControlValueAccessor {
  ...
}
```

如果现在刷新应用程序，选择一个评分，然后点击**提交**按钮，你应该看到以下值被记录：

![图 8.29-使用自定义表单控件记录的表单值](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_8.29_B15150.jpg)

图 8.29-使用自定义表单控件记录的表单值

看吧！你刚刚学会了如何使用`ControlValueAccessor`创建自定义表单控件。请参考下一节以了解它是如何工作的。

## 它是如何工作的...

我们通过创建一个组件来开始这个配方，我们可以用它来为我们必须提交的评论提供评分。我们首先添加了评分组件的模板和样式。请注意，我们在每个星元素上都使用了`[ngClass]`指令，以有条件地添加`rating__star--active`类。现在让我们讨论每个条件：

+   `(isMouseOver && hoveredRating >= star)`: 这个条件依赖于`isMouseOver`和`hoveredRating`变量。`isMouseOver`变量在我们悬停在任何星星上时立即变为`true`，当我们离开星星时又变回`false`。这意味着只有在我们悬停在星星上时它才为`true`。`hoveredRating`告诉我们我们当前悬停在哪颗星星上，并且被赋予星星的值，换句话说，一个从`1`到`5`的值。因此，只有当我们悬停时，且悬停星星的评分大于当前星星的值时，这个条件才为真。因此，如果我们悬停在第四颗星星上，所有值从`1`到`4`的星星都会被高亮显示，因为它们会有`rating__star--active`类有条件地分配给它们。

+   `(!isMouseOver && value >= star)`: 这个条件依赖于我们之前讨论过的`isMouseOver`变量和`value`变量。`value`变量保存了所选评分的值，在我们点击星星时更新。因此，当我们没有鼠标悬停并且`value`变量的值大于当前星星时，应用这个条件。当`value`变量被赋予一个较大的值，并且尝试悬停在一个值较小的星星上时，所有值大于悬停星星的星星都不会被高亮显示，这是特别有益的。

然后我们在每个星星上使用了三个事件：`mouseenter`，`mouseleave`和`click`，然后分别使用我们的`onRatingMouseEnter`，`onRatingMouseLeave`和`selectRating`方法。所有这些都是为了确保整个 UI 流畅，并具有良好的用户体验。然后我们为我们的评分组件实现了`ControlValueAccessor`接口。当我们这样做时，我们需要定义`onChange`和`onTouched`方法为空方法，我们如下所示：

```ts
onChange: any = () => { };
onTouched: any = () => { };
```

然后我们使用`ControlValueAccessor`中的`registerOnChange`和`registerOnTouched`方法将我们的方法分配如下：

```ts
registerOnChange(fn: any){
  this.onChange = fn;
}
registerOnTouched(fn: any) {
  this.onTouched = fn;
}
```

我们注册了这些函数，因为每当我们在组件中进行更改并希望让`ControlValueAccessor`知道值已更改时，我们需要自己调用`onChange`方法。我们在`selectRating`方法中这样做，以确保当我们选择评分时，我们将表单控件的值设置为所选评分的值：

```ts
selectRating(rating: number) {
  if (this.disabled) return;
  this.value = rating;
  this.onChange(rating);
}
```

另一种情况是当我们需要知道表单控件的值是从组件外部更改的。在这种情况下，我们需要将更新后的值分配给`value`变量。我们在`ControlValueAccessor`接口的`writeValue`方法中这样做：

```ts
writeValue(value: number) {
  this.value = value;
}
```

如果我们不希望用户为评分提供值怎么办？换句话说，我们希望评分表单控件被禁用。为此，我们做了两件事。首先，我们将`disabled`属性用作`@Input()`，这样我们可以在需要时从父组件传递和控制它。其次，我们使用了`ControlValueAccessor`接口的`setDisabledState`方法，因此每当表单控件的`disabled`状态发生变化时，除了`@Input()`之外，我们自己设置`disabled`属性。

最后，我们希望 Angular 知道这个`RatingComponent`类具有值访问器。这样我们就可以使用响应式表单 API，特别是使用`<app-rating>`选择器的`formControlName`属性，并将其用作表单控件。为此，我们使用`NG_VALUE_ACCESSOR`注入令牌将我们的`RatingComponent`类作为提供者提供给其`@Component`定义装饰器，如下所示：

```ts
@Component({
  selector: 'app-rating',
  templateUrl: './rating.component.html',
  styleUrls: ['./rating.component.scss'],
  providers: [{
    provide: NG_VALUE_ACCESSOR,
    useExisting: forwardRef(() => RatingComponent),
    multi: true
  }]
})
export class RatingComponent implements OnInit, ControlValueAccessor {}
```

请注意，我们在其中使用`forwardRef()`方法的`useExisting`属性提供了我们的`RatingComponent`类。我们需要提供`multi: true`，因为 Angular 本身使用`NG_VALUE_ACCESSOR`注入令牌注册一些值访问器，还可能有第三方表单控件。

一旦我们设置好了一切，我们可以在`home.component.html`文件中如下使用`formControlName`来使用我们的评分组件：

```ts
<app-rating formControlName="rating"></app-rating>
```

## 参见

+   通过 Thoughtram 在 Angular 中自定义表单控件：[`blog.thoughtram.io/angular/2016/07/27/custom-form-controls-in-angular-2.html`](https://blog.thoughtram.io/angular/2016/07/27/custom-form-controls-in-angular-2.html)

+   ControlValueAccessor 文档：[`angular.io/api/forms/ControlValueAccessor`](https://angular.io/api/forms/ControlValueAccessor)
