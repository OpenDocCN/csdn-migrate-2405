# Angular NativeScript 移动开发（一）

> 原文：[`zh.annas-archive.org/md5/289e6d84a31dea4e7c2b3cd2576adf55`](https://zh.annas-archive.org/md5/289e6d84a31dea4e7c2b3cd2576adf55)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

NativeScript 是由 Progress 构建的开源框架，可使用 Angular、TypeScript 甚至传统的 JavaScript 构建真正的本地移动应用程序。Angular 也是由 Google 构建的开源框架，提供声明性模板、依赖注入和丰富的模块来构建应用程序。Angular 的多功能视图处理架构允许您的视图呈现为真正的本地 UI 组件--适用于 iOS 或 Android--具有流畅的可用性的优越性能。Angular 中视图呈现层的解耦，再加上 NativeScript 中本地 API 的强大功能，共同打造了令人兴奋的 NativeScript for Angular 的强大组合。

本书侧重于构建 iOS 和 Android 上的 Angular 移动应用程序所需了解的关键概念。我们将构建一个有趣的多轨录音工作室应用程序，涉及到您在开始构建自己的应用程序时需要了解的强大的本地关键概念。拥有正确的结构对于开发一个可扩展且易于维护和移植的应用程序至关重要，因此我们将从使用 Angular 的@NgModule 进行项目组织开始。我们将使用 Angular 组件构建我们的第一个视图，然后创建服务，我们可以通过 Angular 的依赖注入来使用。

您将了解 NativeScript 的 tns 命令行实用程序，以在 iOS 和 Android 上运行应用程序。我们将集成第三方插件来构建一些核心功能。接下来，我们将集成@ngrx 存储加效果，以建立一些可靠的实践（受 Redux 启发）来处理状态管理。如果应用程序看起来不好或提供出色的用户体验，那么拥有良好的数据流和坚实的架构是毫无意义的，因此我们将使用 SASS 为我们的应用程序打磨样式。之后，我们将处理调试问题，并投入一些时间编写测试，以防止将来出现错误。最后，我们将使用 webpack 捆绑我们的应用程序，并将其部署到 Apple 应用商店和 Google Play。

在书的结尾，您将了解构建用于 Angular 应用程序的 NativeScript 所需的大部分关键概念。

# 本书内容

第一章，*使用@NgModule 塑造应用*，讨论了@NgModule 装饰器，它清晰地定义了应用中的功能段。这将是项目的组织单位。在开始构建应用之前，通过花点时间思考可能需要/想要的各种单元/部分/模块，您将获得许多好处。

第二章，*功能模块*，教会您使用功能模块来构建应用程序，在未来提供了许多维护优势，并减少了整个应用程序中代码的重复。

第三章，*通过组件构建我们的第一个视图*，实际上让我们第一次看到我们的应用程序，我们需要为我们的第一个视图构建一个组件。

第四章，*使用 CSS 创建更漂亮的视图*，介绍了如何使用一些 CSS 类将我们的第一个视图变得非常惊人。我们还将重点介绍如何利用 NativeScript 的核心主题来提供一致的样式框架。

第五章，*路由和延迟加载*，允许用户在应用程序中各种视图之间导航，需要设置路由。Angular 提供了一个强大的路由器，与 NativeScript 结合使用时，可以与 iOS 和 Android 上的本机移动页面导航系统紧密配合。此外，我们将设置各种路由的延迟加载，以确保应用程序的启动时间尽可能快速。

第六章，*在 iOS 和 Android 上运行应用程序*，着重介绍了如何通过 NativeScript 的 tns 命令行实用程序在 iOS 和 Android 上运行我们的应用程序。

第七章，*构建多轨播放器*，涵盖了插件集成，并通过 NativeScript 直接访问了 iOS 上的 Objective C/Swift API 和 Android 上的 Java API。

第八章，*构建音频录制器*，使用本机 API 为 iOS 和 Android 构建音频录制器。

第九章，*增强您的视图*，充分利用了 Angular 的灵活性和 NativeScript 的强大功能，以充分发挥应用程序用户界面的潜力。

第十章，*@ngrx/store + @ngrx/effects 进行状态管理*，通过 ngrx 管理应用状态的单一存储。

第十一章，*使用 SASS 进行优化*，集成了 nativescript-dev-sass 插件，以 SASS 优化我们应用的样式。

第十二章，*单元测试*，设置 Karma 单元测试框架，以未来证明我们的应用。

第十三章，*使用 Appium 进行集成测试*，为集成测试设置 Appium。

第十四章，*使用 webpack 打包进行部署准备*，使用 webpack 优化发布包。

第十五章，*发布到 Apple 应用商店*，让我们通过 Apple 应用商店分发我们的应用。

第十六章，*发布到 Google Play*，让我们通过 Google Play 分发我们的应用。

# 您需要准备什么

本书假定您正在使用 NativeScript 3 或更高版本和 Angular 4.1 或更高版本。如果您计划进行 iOS 开发，您将需要安装 XCode 的 Mac 来运行配套应用。您还应该安装了 Android SDK 工具，并且至少有一个模拟器，最好是运行 API 24 或更高版本的 7.0.0。

# 本书适合对象

本书适用于所有类型的软件开发人员，他们对 iOS 和 Android 的移动应用开发感兴趣。它专门为那些已经对 TypeScript 有一般了解并且具有一些基本水平的 Angular 特性的人提供帮助。刚开始接触 iOS 和 Android 移动应用开发的 Web 开发人员也可能从本书的内容中获益良多。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："支持各种常见属性（`填充`、`字体大小`、`字重`、`颜色`、`背景颜色`等）。此外，简写的边距/填充也同样有效，即填充：15 5。"

代码块设置如下：

```ts
[default]
export class AppComponent {}
```

当我们希望引起您对代码块特定部分的注意时，相关行或项目会以粗体显示：

```ts
[default]
public init() {
 const item = {};
 item.volume = 1; }
```

任何命令行输入或输出都以以下方式书写：

```ts
 # tns run ios --emulator
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如在菜单或对话框中，会以这样的方式出现在文本中："再次运行我们的应用程序，现在当我们点击“记录”按钮时，我们会看到登录提示"。

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：使用@NgModule 塑造形状

在这一章中，我们将通过一些扎实的项目组织练习来启动，为使用 NativeScript for Angular 构建一个令人惊叹的应用做好准备。我们希望为您提供一些重要且强大的概念，以便在规划架构时考虑，为您铺平道路，使开发体验更加顺畅，具备可扩展性。

将 Angular 与 NativeScript 结合使用提供了丰富的有用范例和工具来构建和规划您的应用程序。正如常说的那样，伴随着巨大的力量而来的是巨大的责任，尽管这种技术组合非常棒，可以创建令人惊叹的应用程序，但它们也可以用于创建一个过度工程化且难以调试的应用程序。让我们花一些时间来进行一些练习，以帮助避免常见的陷阱，并真正释放这种技术堆栈的全部潜力。

我们将向您介绍 Angular 的`@NgModule`装饰器，我们将专门使用它来帮助将我们的应用程序代码组织成具有明确目的和可移植性的逻辑单元。我们还将介绍一些我们将在架构中使用的 Angular 概念，例如依赖注入服务。在建立了坚实的基础后，我们将迅速接近第三章末尾的时候首次运行我们的应用程序。

在本章中，我们将涵盖以下主题：

+   什么是 NativeScript for Angular？

+   设置您的本机移动应用程序

+   项目组织

+   架构规划

+   `@NgModule`装饰器

+   `@Injectable`装饰器

+   将您的应用程序分解为模块

# 心理准备

在开始编码之前，您可以通过绘制出应用程序需要的各种服务和功能，极大地增强项目的开发体验。这样做将有助于减少代码重复，构建数据流，并为未来快速功能开发铺平道路。

服务是一种通常处理处理和/或为您的应用程序提供数据的类。您对这些服务的使用不需要知道数据来自何处的具体细节，只需知道它可以向服务询问其目的，然后它就会发生。

# 素描练习

对此的一个很好的练习是勾画出您的应用视图之一的大致想法。您可能还不知道它会是什么样子，没关系；这只是一个思考用户期望的练习，是引导您的思维过程进入您需要构建的各个部分或模块的第一步。这也将帮助您考虑应用需要管理的各种状态。

以我们即将构建的应用**TNSStudio**（**Telerik NativeScript**（**TNS**））为例。我们将在第二章 *特性模块*中更详细地介绍我们的应用是什么，以及它将具体执行的任务。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00005.jpeg)

从上到下，我们可以看到一个带有菜单按钮、标志和录音按钮的标题。然后，我们有用户录制的音轨列表，每个音轨都有一个（重新）录制按钮和一个独奏或静音按钮。

从这个草图中，我们可以考虑应用可能需要提供的几个服务：

+   播放器服务

+   录音服务

+   持久存储服务可记住用户为录音混音中的每个音轨设置的音量级别设置，或者用户是否已经通过身份验证。

我们还可以了解应用可能需要管理的各种状态：

+   用户录音/音轨列表

+   应用是否正在播放音频

+   应用是否处于录音模式或非录音模式

# 低级思维

提供一些低级服务也是有利的，这些服务提供了便捷的 API 来访问诸如 HTTP 远程请求和/或日志记录等内容。这样做将使您能够创建您或您的团队喜欢使用的与低级 API 交互时的独特特性。例如，也许您的后端 API 需要设置一个独特的标头，以及为每个请求设置一个特殊的身份验证标头。创建一个围绕 HTTP 服务的低级包装器将使您能够隔离这些独特特性，并为您的应用提供一致的 API，以确保所有 API 调用都在一个地方得到增强。

此外，您的团队可能希望能够将所有日志代码导入第三方日志分析器（用于调试或其他性能相关指标）。使用精简代码创建围绕某些框架服务的低级包装器将使您的应用能够快速适应这些潜在需求。

# 使用@NgModule 进行模块化

然后，我们可以考虑将这些服务分解为组织单元或模块。

Angular 为我们提供了`@NgModule`装饰器，它将帮助我们定义这些模块的外观以及它们为我们的应用程序提供了什么。为了尽可能地保持应用程序的引导/启动时间尽快，我们可以以这样的方式组织我们的模块，以便在应用程序启动后延迟加载一些服务/功能。用少量所需代码引导一个模块将有助于将启动阶段保持在最低限度。

# 我们应用程序的模块拆分

以下是我们将如何通过模块来组织我们的应用程序：

1.  `CoreModule`：提供一个良好的基础层，包括低级服务、组件和实用程序。例如与日志记录、对话框、HTTP 和其他各种常用服务的交互。

1.  `AnalyticsModule`******：潜在地，您可以拥有一个模块，为您的应用程序提供处理分析的各种服务。

1.  `PlayerModule`*****：提供我们的应用程序播放音频所需的一切。

1.  `RecorderModule`*****：提供我们的应用程序录制音频所需的一切。

*(*)*这些被视为*功能模块。*(**)*我们将在本书的示例中省略此模块，但在此提到它是为了上下文。

# 模块的好处

使用类似的组织方式为您和您的团队提供了几个有利的事情：

+   **高度的可用性**：通过设计低级的`CoreModule`，您和您的团队有机会以独特的方式设计如何使用常用服务，不仅适用于您现在构建的应用程序，还适用于将来的更多应用程序。当使用低级服务时，您可以轻松地将`CoreModule`移动到完全不同的应用程序中，并获得您为该应用程序设计的所有相同独特 API。

+   **将您自己的应用程序代码视为“功能模块”**：这样做将帮助您专注于应用程序应该提供的独特能力，而不是`CoreModule`提供的内容，同时减少代码的重复。

+   **鼓励和增强快速开发**：通过将常用功能限制在我们的`CoreModule`中，我们减轻了在我们的功能模块中担心这些细节的负担。我们可以简单地注入`CoreModule`提供的服务并使用这些 API，而不必重复自己。

+   **可维护性**：将来，如果由于应用程序需要与低级服务进行交互而需要更改底层细节，只需在一个地方（`CoreModule`服务中）进行更改，而不是在应用程序的不同部分可能分散的冗余代码。

+   **性能**：将应用程序拆分为模块将允许您在启动时仅加载您需要的模块，然后在需要时延迟加载其他功能。最终，这将导致更快的应用程序启动时间。

# 考虑因素？

您可能会想，为什么不将播放器/录音机模块合并成一个模块？

**答案**：我们的应用程序只允许在注册用户经过身份验证时进行录制。因此，考虑经过身份验证的上下文的潜力以及仅对经过身份验证的用户（如果有）可访问的功能是有益的。这将使我们能够进一步微调我们的应用程序的加载性能，使其在需要时仅加载所需的内容。

# 入门

我们假设您已经在计算机上正确安装了 NativeScript。如果没有，请按照[`nativescript.org`](https://nativescript.org)上的安装说明进行操作。安装完成后，我们需要使用 shell 提示符创建我们的应用程序框架：

```ts
tns create TNSStudio --ng
```

`tns`代表 Telerik NativeScript。这是您将用于创建、构建、部署和测试任何 NativeScript 应用程序的主要命令行用户界面（CLI）工具。

这个命令将创建一个名为`TNSStudio`的新文件夹。里面是您的主项目文件夹，包括构建应用程序所需的一切。它将包含与此项目相关的所有内容。创建项目文件夹后，您需要做一件事才能拥有一个完全可运行的应用程序。那就是为 Android 和/或 iOS 添加运行时：

```ts
cd TNSStudio
tns platform add ios
tns platform add android
```

如果您使用的是 Macintosh，您可以为 iOS 和 Android 构建。如果您在 Linux 或 Windows 设备上运行，Android 是您可以在本地计算机上编译的唯一平台。

# 创建我们的模块外壳

尚未编写服务实现的情况下，我们可以通过开始定义它应该提供什么来大致了解我们的`CoreModule`将会是什么样子，使用`NgModule`：

让我们创建`app/modules/core/core.module.ts`：

```ts
// angular
import { NgModule } from '@angular/core';
@NgModule({})
export class CoreModule { }
```

# 可注入的服务

现在，让我们为我们的服务创建模板。请注意，这里导入了可注入的装饰器，以声明我们的服务将通过 Angular 的**依赖注入**（**DI**）系统提供，这允许这些服务被注入到可能需要它的任何类构造函数中。DI 系统提供了一个很好的方式来保证这些服务将被实例化为单例并在我们的应用程序中共享。值得注意的是，如果我们不想让它们成为单例，而是希望为组件树的某些分支创建唯一的实例，我们也可以在组件级别提供这些服务。在这种情况下，我们希望将它们创建为单例。我们将在我们的`CoreModule`中添加以下内容：

+   `LogService`：用于传输所有控制台日志的服务。

+   `DatabaseService`：处理我们的应用程序需要的任何持久数据的服务。对于我们的应用程序，我们将实现原生移动设备的存储选项，例如应用程序设置，作为一个简单的键/值存储。但是，你也可以在这里实现更高级的存储选项，例如通过 Firebase 进行远程存储。

创建`app/modules/core/services/log.service.ts`：

```ts
// angular
import { Injectable } from '@angular/core';
@Injectable()
export class LogService {
}
```

另外，创建`app/modules/core/services/database.service.ts`：

```ts
// angular
import { Injectable } from '@angular/core';
@Injectable()
export class DatabaseService {
}
```

# 一致性和标准

为了保持一致性并减少我们的导入长度，并为更好的可扩展性做准备，让我们在`app/modules/core/services`中也创建一个`index.ts`文件，它将导出我们的服务的`const`集合，并按字母顺序导出这些服务（以保持整洁）：

```ts
import { DatabaseService } from './database.service';
import { LogService } from './log.service';

export const PROVIDERS: any[] = [
  DatabaseService,
  LogService
];

export * from './database.service';
export * from './log.service';
```

本书中我们将遵循组织的类似模式。

# 完成 CoreModule

我们现在可以修改我们的`CoreModule`来使用我们创建的内容。我们还将利用这个机会导入`NativeScriptModule`，这是我们的应用程序需要与其他 NativeScript for Angular 功能一起使用的。因为我们知道我们将全局使用这些功能，我们还可以指定它们被导出，这样当我们导入和使用我们的`CoreModule`时，我们就不需要担心在其他地方导入`NativeScriptModule`。我们的`CoreModule`修改应该如下所示：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module';
// angular
import { NgModule } from '@angular/core';
// app
import { PROVIDERS } from './services';
@NgModule({
  imports: [
    NativeScriptModule
  ],
  providers: [
    ...PROVIDERS
  ],
  exports: [
    NativeScriptModule
  ]
})
export class CoreModule { }
```

现在，我们已经为我们的`CoreModule`建立了一个良好的起点，我们将在接下来的章节中实现其细节。

# 总结

在本章中，我们为我们的应用程序打下了坚实的基础。您学会了如何从模块的角度思考应用程序的架构。您还学会了如何利用 Angular 的`@NgModule`装饰器来构建这些模块。最后，我们现在有了一个很好的基础架构，可以在其上构建我们的应用程序。

现在您已经掌握了一些关键概念，我们可以继续进入我们应用程序的核心部分，即功能模块。让我们深入了解我们应用程序的主要功能，继续构建我们的服务层在第二章中，*功能模块*。我们很快将在第三章中为我们的应用程序创建一些视图，并在 iOS 和 Android 上运行应用程序，*通过组件构建我们的第一个视图*。


# 第二章：功能模块

我们将继续通过搭建我们的应用的核心功能模块来构建我们应用的基础，即播放器和录音机。我们还将要记住，录音功能只有在用户进行身份验证时才会被加载和可用。最后，我们将完成我们在第一章中创建的`CoreModule`中的服务的实现，*使用@NgModule 塑造*。

在本章中，我们将涵盖以下主题：

+   创建功能模块

+   应用功能的分离

+   设置`AppModule`以有效地引导，仅在我们第一个视图中需要时加载功能模块

+   使用 NativeScript 的`application-settings`模块作为我们的键/值存储

+   提供在一个地方控制我们应用的调试日志的能力

+   创建一个新的服务，该服务将使用其他服务来演示我们可扩展的架构

# 播放器和录音机模块

让我们创建两个主要功能模块的框架。请注意，我们还将`NativeScriptModule`添加到以下两个模块的导入中：

1.  `PlayerModule`：它将提供特定于播放器的服务和组件，无论用户是否经过身份验证都可以使用。

让我们创建`app/modules/player/player.module.ts`：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 
// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';

@NgModule({
  imports: [ NativeScriptModule ]
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class PlayerModule { }
```

1.  `RecorderModule`：这将提供特定于录音的服务和组件，仅在用户进行身份验证并首次进入录音模式时才会加载。

让我们创建`app/modules/recorder/recorder.module.ts`：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 

// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';

@NgModule({
  imports: [ NativeScriptModule ],
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class RecorderModule { }
```

# 我们数据的共享模型

在我们创建服务之前，让我们为我们的应用将使用的核心数据创建一个接口和模型实现。`TrackModel`将表示具有以下内容的单个轨道：

+   `filepath`：（到本地文件）

+   `name`：（用于我们的视图）

+   `order`：位置（用于轨道的视图列表）

+   `volume`：我们希望我们的播放器能够以不同的音量级别设置混合不同的轨道。

+   `solo`：我们是否只想在我们的混音中听到这个轨道

我们还将为我们的模型添加一个方便的构造函数，该构造函数将使用对象来初始化我们的模型。

创建`app/modules/core/models/track.model.ts`，因为它将在我们的播放器和录音机之间共享：

```ts
export interface ITrack {
  filepath?: string;
  name?: string;
  order?: number;
  volume?: number;
  solo?: boolean;
}
export class TrackModel implements ITrack {
  public filepath: string;
  public name: string;
  public order: number;
  public volume: number = 1; // set default to full volume
  public solo: boolean;

  constructor(model?: any) {
    if (model) {
      for (let key in model) {
        this[key] = model[key];
      }
    }
  }
}
```

# 搭建服务 API

现在，让我们创建我们的服务将为我们的应用程序提供的 API。从`PlayerService`开始，我们可以想象以下 API 可能对管理轨道和控制播放很有用。大部分内容应该是相当不言自明的。我们以后可能会重构这个，但这是一个很好的开始：

+   `playing: boolean;`

+   `tracks: Array<ITrack>;`

+   `play(index: number): void;`

+   `pause(index: number): void;`

+   `addTrack(track: ITrack): void;`

+   `removeTrack(track: ITrack): void;`

+   `reorderTrack(track: ITrack, newIndex: number): void;`

创建`app/modules/player/services/player.service.ts`并且存根一些方法；其中一些我们可以继续实现：

```ts
// angular
import { Injectable } from '@angular/core';

// app
import { ITrack } from '../../core/models';
@Injectable()
export class PlayerService {

  public playing: boolean;
  public tracks: Array<ITrack>;

  constructor() {
    this.tracks = [];
  }

  public play(index: number): void {
    this.playing = true;
  }
  public pause(index: number): void {
    this.playing = false;
  }
  public addTrack(track: ITrack): void {
    this.tracks.push(track);
  }
  public removeTrack(track: ITrack): void {
    let index = this.getTrackIndex(track);
    if (index > -1) {
      this.tracks.splice(index, 1);
    }
  }
  public reorderTrack(track: ITrack, newIndex: number) {
    let index = this.getTrackIndex(track);
    if (index > -1) {
      this.tracks.splice(newIndex, 0, this.tracks.splice(index, 1)[0]);
    }
  }
  private getTrackIndex(track: ITrack): number {
    let index = -1;
    for (let i = 0; i < this.tracks.length; i++) {
      if (this.tracks[i].filepath === track.filepath) {
        index = i;
        break;
      }
    }
    return index;
  }
}
```

现在，让我们按照标准导出这个服务给我们的模块。

创建`app/modules/player/services/index.ts`：

```ts
import { PlayerService } from './player.service';

export const PROVIDERS: any[] = [
  PlayerService
];

export * from './player.service';
```

最后，修改我们的`PlayerModule`以指定正确的提供者，这样我们最终的模块应该如下所示：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 

// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';

// app
import { PROVIDERS } from './services';

@NgModule({
  imports: [ NativeScriptModule ],
  providers: [ ...PROVIDERS ],
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class PlayerModule { }
```

接下来，我们可以设计`RecorderService`来提供一个简单的录制 API。

创建`app/modules/recorder/services/recorder.service.ts`：

+   `record(): void`

+   `stop(): void`

```ts
// angular
import { Injectable } from '@angular/core';
@Injectable()
export class RecorderService {
  public record(): void { }
  public stop(): void { }
}
```

现在，按照标准导出这个服务给我们的模块。

创建`app/modules/recorder/services/index.ts`：

```ts
import { RecorderService } from './recorder.service';

export const PROVIDERS: any[] = [
  RecorderService
];

export * from './recorder.service';
```

最后，修改我们的`RecorderModule`以指定正确的提供者，这样我们最终的模块应该如下所示：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 

// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';

// app
import { PROVIDERS } from './services';

@NgModule({
  imports: [ NativeScriptModule ],
  providers: [ ...PROVIDERS ],
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class RecorderModule { }
```

我们的两个主要功能模块已经搭好架子，准备就绪，让我们重新审视我们在第一章“使用@NgModule 进入形状”中创建的两个低级服务，并提供实现。

# 实现 LogService

日志记录是您在应用程序的开发生命周期以及在生产中想要的重要工具。它可以帮助您调试，以及获得对应用程序使用方式的重要见解。通过一个单一的路径运行所有日志也提供了一个机会，通过翻转开关重新路由所有应用程序日志到其他地方。例如，您可以使用第三方调试跟踪服务，如 TrackJS（[`trackjs.com`](https://trackjs.com)），通过 Segment（[`segment.com`](https://segment.com)）。您将希望通过日志记录运行应用程序的许多重要方面，它是一个很好的地方，可以有很多控制和灵活性。

让我们打开`app/modules/core/services/log.service.ts`并开始工作。让我们首先定义一个静态布尔值，它将作为一个简单的标志，在我们的`AppModule`中可以切换启用/禁用。让我们还添加一些有用的方法：

```ts
import { Injectable } from '@angular/core';

@Injectable()
export class LogService {

 public static ENABLE: boolean = true;

 public debug(msg: any, ...formatParams: any[]) {
   if (LogService.ENABLE) {
     console.log(msg, formatParams);
   }
 }

 public error(msg: any, ...formatParams: any[]) {
   if (LogService.ENABLE) {
     console.error(msg, formatParams);
   }
 }

 public inspect(obj: any) {
   if (LogService.ENABLE) {
     console.log(obj);
     console.log('typeof: ', typeof obj);
     if (obj) {
       console.log('constructor: ', obj.constructor.name);
       for (let key in obj) {
         console.log(`${key}: `, obj[key]);
       }
     }
   }
  }
}
```

+   `debug`：这将作为我们最常用的日志输出 API。

+   `error`：当我们知道某种条件是错误时，这将有助于识别我们日志中的这些位置。

+   `inspect`：有时查看对象可以帮助找到错误或帮助我们了解我们的应用程序在任何给定时刻的状态。

有了我们实现的`LogService`，我们现在将在整个应用程序和本书的其余部分中使用它，而不是直接使用控制台。

# 实现 DatabaseService

我们的`DatabaseService`需要提供几件事情：

+   一个持久存储来保存和检索我们的应用程序需要的任何数据。

+   它应该允许存储任何类型的数据；然而，我们特别希望它处理 JSON 序列化。

+   我们将要存储的所有数据的静态键。

+   静态引用保存的用户？是的，它可以。然而，这引出了一个我们将在一会儿讨论的观点。

关于第一项，我们可以使用 NativeScript 的`application-settings`模块。在底层，该模块提供了一个一致的 API，用于处理两个本机移动 API：

+   **iOS**：`NSUserDefaults`：[`developer.apple.com/reference/foundation/userdefaults`](https://developer.apple.com/reference/foundation/userdefaults)

+   **Android**：`SharedPreferences`：[`developer.android.com/reference/android/content/SharedPreferences.html`](https://developer.android.com/reference/android/content/SharedPreferences.html)

关于序列化 JSON 数据，`application-settings`模块提供了`setString`和`getString`方法，这将允许我们将其与`JSON.stringify`和`JSON.parse`一起使用。

在整个代码库中使用字符串值来引用应保持不变的相同键的几个不同位置可能会出现错误。因此，我们将保留一个类型化（用于类型安全）的静态哈希，其中包含我们的应用程序将使用的有效键。我们可能目前只知道一个（经过身份验证的用户为`'current-user'`），但创建这个将提供一个单一的地方来随着时间的推移扩展这些。

四个？我们将在一会儿讨论四个。

打开`app/modules/core/services/database.service.ts`并修改它，以提供类似于 Web 的`localStorage` API 的简化 API：

```ts
// angular
import { Injectable } from '@angular/core';

// nativescript
import * as appSettings from 'application-settings';

interface IKeys {
  currentUser: string;
}
@Injectable()
export class DatabaseService {

  public static KEYS: IKeys = {
    currentUser: 'current-user'
  };

  public setItem(key: string, value: any): void {
    appSettings.setString(key, JSON.stringify(value));
  }

  public getItem(key: string): any {
    let item = appSettings.getString(key);
    if (item) {
      return JSON.parse(item);
    } 
    return item;
  }

  public removeItem(key: string): void {
    appSettings.remove(key);
  }
}
```

该服务现在提供了一种通过`setItem`存储对象的方式，该方式通过`JSON.stringify`确保对象被正确存储为字符串。它还提供了一种通过`getItem`检索值的方式，该方式还通过`JSON.parse`处理反序列化为对象。我们还有`remove` API 来简单地从持久存储中删除值。最后，我们有一个对我们持久存储将跟踪的所有有效键的静态引用。

那么，关于保存用户的静态引用呢？

我们希望能够轻松地从应用程序的任何位置访问我们经过身份验证的用户。为简单起见，我们可以在`DatabaseService`中提供一个静态引用，但我们的目标是清晰地分离关注点。由于我们知道我们将希望能够显示一个模态框，要求用户注册并解锁那些录制功能，因此管理这一点的新服务是有意义的。由于我们设计了可扩展的架构，我们可以轻松地将另一个服务添加到其中，所以现在让我们这样做！

# 创建`AuthService`来帮助处理我们应用程序的经过身份验证的状态。

对于我们的`AuthService`的一个重要考虑是要理解我们应用程序中的某些组件可能会受益于在经过身份验证状态发生变化时得到通知。这是利用 RxJS 的一个完美用例。RxJS 是一个非常强大的库，用于简化使用可观察对象处理变化的数据和事件。可观察对象是一种数据类型，您不仅可以使用它来监听事件，还可以对事件进行过滤、映射、减少，并在发生任何事情时运行代码序列。通过使用可观察对象，我们可以大大简化我们的异步开发。我们将使用一种特定类型的可观察对象，称为`BehaviorSubject`来发出我们的组件可以订阅的更改。

创建`app/modules/core/services/auth.service.ts`并添加以下内容：

```ts
// angular
import { Injectable } from '@angular/core';

// lib
import { BehaviorSubject } from 'rxjs/BehaviorSubject';

// app
import { DatabaseService } from './database.service';
import { LogService } from './log.service';

@Injectable()
export class AuthService {

 // access our current user from anywhere
 public static CURRENT_USER: any;

 // subscribe to authenticated state changes
 public authenticated$: BehaviorSubject<boolean> = 
   new BehaviorSubject(false);

 constructor(
   private databaseService: DatabaseService,
   private logService: LogService
 ) {
   this._init();
 } 

 private _init() {
   AuthService.CURRENT_USER = this.databaseService
     .getItem(DatabaseService.KEYS.currentUser);
   this.logService.debug(`Current user: `,
     AuthService.CURRENT_USER);
   this._notifyState(!!AuthService.CURRENT_USER);
 }

 private _notifyState(auth: boolean) {
   this.authenticated$.next(auth);
 }
}
```

这里有一些有趣的事情正在发生。我们立即让我们设计的另外两个服务`LogService`和`DatabaseService`开始工作。它们帮助我们检查用户是否已保存/经过身份验证，并记录结果。

当我们的服务通过 Angular 的依赖注入系统构建时，我们还调用了一个`private _init`方法。这允许我们立即检查持久存储中是否存在经过身份验证的用户。然后，我们调用一个私有的可重用方法`_notifyState`，它将在我们的`authenticated$`可观察对象上发出`true`或`false`。这将为其他组件提供一个很好的方式，通过订阅这个可观察对象，轻松地得到通知当身份验证状态发生变化时。我们已经使`_notifyState`可重用，因为我们将来要实现的登录和注册方法将能够在 UI 中显示的模态返回结果时使用它。

我们现在可以很容易地将`AuthService`添加到我们的`PROVIDERS`中，而且我们不需要做任何其他事情来确保它被添加到我们的`CoreModule`中，因为我们的`PROVIDERS`已经被添加到`CoreModule`中。

我们所需要做的就是修改`app/modules/core/services/index.ts`并添加我们的服务：

```ts
import { AuthService } from './auth.service';
import { DatabaseService } from './database.service';
import { LogService } from './log.service';

export const PROVIDERS: any[] = [
 AuthService,
 DatabaseService,
 LogService
];

export * from './auth.service';
export * from './database.service';
export * from './log.service';
```

等等！有一件重要的事情我们想要做，以确保我们的 AuthService 初始化！

Angular 的依赖注入系统只会实例化在某处被注入的服务。虽然我们在`CoreModule`中将所有服务指定为提供者，但直到它们在某处被注入之前，它们实际上都不会被构建！

打开`app/app.component.ts`并用以下内容替换它：

```ts
// angular
import { Component } from '@angular/core';

// app
import { AuthService } from './modules/core/services';

@Component({
 selector: 'my-app',
 templateUrl: 'app.component.html',
})
export class AppComponent {

 constructor(private authService: AuthService) { }

}
```

我们通过将其指定为组件构造函数的参数来注入我们的`AuthService`。这将导致 Angular 构造我们的服务。我们代码中的所有后续注入都将接收相同的单例。

# 准备引导 AppModule

我们现在已经为我们的特性模块建立了一个良好的设置，现在是时候将它们全部汇集在我们的根`AppModule`中，负责引导我们的应用程序。

只引导初始视图所需的内容。延迟加载其余部分。

保持应用程序的引导尽可能快速是很重要的。为了实现这一点，我们只想在初始视图中引导应用程序所需的主要功能，并在需要时进行延迟加载其余部分。我们知道我们希望我们的低级服务在应用程序中随时可用和准备就绪，所以我们肯定会希望`CoreModule`是最前面的。

我们的草图中的初始视图将从播放器和列表中的 2-3 个轨迹开始，因此用户可以立即回放我们将与应用程序一起提供的预先录制轨迹的混音，以进行演示。因此，我们将指定在我们的应用程序引导时预先加载`PlayerModule`，因为这将是我们希望立即参与的主要功能。

我们将设置路由配置，当用户点击初始视图右上角的录制按钮开始录制会话时，将懒加载我们的`RecorderModule`。

考虑到这一点，我们可以设置位于`app/app.module.ts`的`AppModule`如下：

```ts
// angular 
import { NgModule } from '@angular/core'; 

// app
import { AppComponent } from './app.component';
import { CoreModule } from './modules/core/core.module';
import { PlayerModule } from './modules/player/player.module'; 

@NgModule({ 
  imports: [ 
    CoreModule, 
    PlayerModule 
  ], 
  declarations: [AppComponent],
  bootstrap: [AppComponent] 
})
export class AppModule { }
```

# 总结

在整个过程中，我们一直在努力创建一个坚实的基础来构建我们的应用程序。我们创建了一个`CoreModule`来提供一些低级服务，如日志记录和持久存储，并设计了该模块，以便根据需要轻松扩展更多服务。此外，该模块是可移植的，并且可以与您公司自己的特殊功能一起放入其他项目中。

在典型的应用程序开发中，您可能希望在整个过程中在 iOS 和/或 Android 模拟器上运行您的应用程序，以便再次检查一些设计/架构选择，这是明智的！我们还没有做到这一点，因为我们在这里预先规划了一个应用程序，并希望您专注于我们正在做出的选择以及原因。

我们还创建了我们的应用程序核心竞争力所需的两个主要功能模块，`PlayerModule`和`RecorderModule`。播放器将预先设置为加载 2-3 个已录制的轨迹，并在启动时准备好播放，因此我们将使用`PlayerModule`功能引导我们的应用程序。

我们将提供一种简单的方式，允许用户注册一个帐户，这将允许他们记录自己的轨迹以投入混音中。一旦他们登录，他们将能够通过路由进入录制模式，该模式将懒加载`RecorderModule`。

在下一章中，我们将创建我们的第一个视图，配置我们的路由，并最终看到我们的应用程序的第一印象。


# 第三章：我们的第一个视图通过组件构建

我们在第二章 *特性模块*中努力构建我们应用程序的基础，现在是时候最终看一眼我们正在处理的内容了。这就是将我们的草图从屏幕上的移动设备上获取第一个视图的过程。

使用 NativeScript 为 Angular 构建视图与为 Web 构建视图并没有太大的不同。我们将使用 Angular 的 Component 装饰器来构建各种组件，以实现我们所需的可用性。我们将使用 NativeScript XML 而不是 HTML 标记，这是一个非常强大、简单而简洁的抽象，可以在 iOS 和 Android 上使用所有本地视图组件。

我们不会在这里涵盖您可以访问的所有组件的好处和类型；但是要了解更多信息，我们建议阅读以下任何一本书：

+   [`www.packtpub.com/web-development/getting-started-nativescript`](https://www.packtpub.com/web-development/getting-started-nativescript)

+   [`www.manning.com/books/nativescript-in-action`](https://www.manning.com/books/nativescript-in-action)

在本章中，我们将涵盖以下主题：

+   使用 Component 装饰器来组合我们的视图

+   创建可重用的组件

+   使用管道创建自定义视图过滤器

+   在 iOS 和 Android 模拟器上运行应用程序

# 我们的第一个视图通过组件构建

如果我们从第一章 *使用@NgModule 塑造应用程序*中查看我们的草图，我们可以看到应用程序顶部有一个标题，其中包含我们的应用程序标题和右侧的记录按钮。我们还可以看到一些播放器控件的轨道列表在底部。我们可以将我们的 UI 设计的这些关键元素基本上分解为三个主要组件。一个组件已经由 NativeScript 框架提供，ActionBar，我们将使用它来表示顶部标题。

NativeScript 提供了许多丰富的视图组件来构建我们的 UI。标记不是 HTML，而是 XML，具有`.html`扩展名，这可能看起来不太寻常。使用`.html`扩展名用于 NativeScript for Angular 的 XML 视图模板的原因是，自定义渲染器([`github.com/NativeScript/nativescript-angular`](https://github.com/NativeScript/nativescript-angular))使用 DOM 适配器来解析视图模板。每个 NativeScript XML 组件代表各自平台上的真正本地视图小部件。

对于另外两个主要组件，我们将使用 Angular 的 Component 装饰器。在应用程序开发周期的这个阶段，思考封装的 UI 功能部分非常重要。我们将把我们的曲目列表封装为一个组件，将播放器控件封装为另一个组件。在这个练习中，我们将使用从抽象视角到每个组件的实现细节的外部到内部的方法来构建我们的 UI。

首先，让我们专注于我们 Angular 应用程序中的根组件，因为它将定义我们第一个视图的基本布局。打开`app/app.component.html`，清空其内容，并用以下内容替换，以从我们的草图中勾勒出初始 UI 概念：

```ts
<ActionBar title="TNSStudio">
</ActionBar>
<GridLayout rows="*, 100" columns="*">
  <track-list row="0" col="0"></track-list>
  <player-controls row="1" col="0"></player-controls>
</GridLayout>
```

我们用`ActionBar`和主视图的主要布局容器`GridLayout`来表达我们的观点。在 NativeScript 中，每个视图都以布局容器作为根节点开始（在任何`ActionBar`或`ScrollView`之外），就像在 HTML 标记中使用`div`标签一样。在撰写本文时，NativeScript 提供了六种布局容器：`StackLayout`、`GridLayout`、`FlexboxLayout`、`AbsoluteLayout`、`DockLayout`和`WrapLayout`。对于我们的布局，`GridLayout`将很好地工作。

# 关于 GridLayout

GridLayout 是你在 NativeScript 应用程序中将使用的三种最常用的布局之一（其他两种是 FlexboxLayout 和 StackLayout）。这是一个允许您轻松构建复杂布局的布局。使用 GridLayout 非常类似于 HTML 中的增强表格。基本上，您要将屏幕区域分成所需的部分。它将允许您告诉列（或行）成为屏幕剩余宽度（和高度）的百分比。网格支持三种类型的值；**绝对大小**，剩余空间的百分比和使用的空间。

对于**绝对大小**，只需输入数字。例如，`100`表示它将使用 100 dp 的空间。

另一个**dp**的名字是**dip**。它们是一样的。设备无关像素（也称为密度无关像素、DIP 或 DP）是基于计算机持有的坐标系统的测量单位，代表了应用程序使用的像素的抽象，然后由底层系统转换为物理像素。

如果你考虑到最小的支持的 iOS 设备，它的屏幕宽度为 320dp。对于其他设备，如平板电脑，一些宽度为 1024 dp。因此，100 dp 几乎是 iOS 手机屏幕的三分之一，而在平板电脑上则是屏幕的十分之一。因此，在使用固定的绝对值时，这是您需要考虑的事情。通常最好使用使用的空间而不是固定值，除非您需要将列限制为特定大小。

要使用**剩余空间**为基础的值，也就是 `***`，`***` 告诉它使用剩余空间的其余部分。如果列（或行）设置为 `*`，`*`，那么空间将被分成两个相等的剩余空间。同样，`rows="*,*,*,*,*"` 将指定五个相等大小的行。您还可以指定诸如 `columns="2*,3*,*"` 这样的东西，您将得到三列；第一列将是屏幕的六分之二，第二列将是屏幕的三分之一，最后一列将是屏幕的六分之一（即 2+3+1 = 6）。这使您在如何使用剩余空间方面具有极大的灵活性。

第三种大小类型是**使用的空间**。所以发生的情况是网格内的内容被测量，然后列被分配为该列（或行）中使用的最大尺寸。当您有一个包含数据的网格，但不确定大小或者您并不在乎时，这是非常有用的；您只是希望它看起来不错。因此，这是自动关键字。我可能会写 `columns="auto,auto,*,auto"`。这意味着列 1、2 和 4 将根据这些列内的内容自动调整大小；而列 3 将使用剩下的空间。这对于布局整个屏幕或屏幕的部分非常有用，您希望它看起来某种特定的样子。

GridLayout 是最好的布局之一的最后一个原因是，当您将项目分配给 GridLayout 时，您实际上可以将多个项目分配给相同的行和/或列，并且可以使用行或列跨度来允许项目使用多个行和/或列。

要分配一个对象，你只需通过 `row="0"` 和/或 `col="0"` 进行分配（请记住这些是基于索引的位置）。您还可以使用 `rowSpan` 和 `colSpan` 来使元素跨越多行和/或列。总的来说，GridLayout 是最通用的布局，可以让您轻松地创建几乎任何您在应用程序中需要的布局。

# 回到我们的布局

在网格内，我们声明了一个`track-list`组件来表示我们的曲目列表，它将垂直伸展，占据所有的垂直空间，只留下`player-controls`的高度为 100。我们将`track-list`指定为`row="0" col="0"`，因为行和列是基于索引的。通过 GridLayout 的`*`在 rows 属性中定义了灵活（剩余）的垂直高度。网格的底部部分（第 1 行）将表示播放器控件，允许用户播放/暂停混音并移动播放位置。

现在我们已经以相当抽象的方式定义了应用程序的主视图，让我们深入研究我们需要构建的两个自定义组件，`track-list`和`player-controls`。

# 构建 TrackList 组件

曲目列表应该是所有录制曲目的列表。列表中的每一行都应该提供一个单独的录制按钮，以重新录制，另外还应该提供一个用于显示用户提供的标题的名称标签。它还应该提供一个开关，允许用户独奏特定的曲目。

我们可以注入`PlayerService`并将其声明为`public`，以便我们可以直接绑定到服务的 tracks 集合。

我们还可以模拟一些绑定来启动一些操作，比如`record`操作。现在，让我们允许传入一个 track，并通过`LogService`打印出对该 track 的检查。

让我们从创建`app/modules/player/components/track-list/track-list.component.ts`（配套的`.html`模板）开始：

```ts
// angular
import { Component, Input } from '@angular/core';

// app
import { ITrack } from '../../../core/models';
import { LogService } from '../../../core/services';
import { PlayerService } from '../../services/player.service';

@Component({
 moduleId: module.id,
 selector: 'track-list',
 templateUrl: 'track-list.component.html'
})
export class TrackListComponent {

 constructor(
   private logService: LogService,
   public playerService: PlayerService
 ) { }

 public record(track: ITrack) {
   this.logService.inspect(track);
 }
}
```

对于视图模板`track-list.component.html`，我们将使用强大的`ListView`组件。这个小部件代表了 iOS 上的原生 UITableView（[`developer.apple.com/reference/uikit/uitableview`](https://developer.apple.com/reference/uikit/uitableview)）和 Android 上的原生 ListView（[`developer.android.com/guide/topics/ui/layout/listview.html`](https://developer.android.com/guide/topics/ui/layout/listview.html)），提供了 60fps 的虚拟滚动和重用行。它在移动设备上的性能是无与伦比的：

```ts
<ListView [items]="playerService.tracks">
  <ng-template let-track="item">
    <GridLayout rows="auto" columns="75,*,100">
      <Button text="Record" (tap)="record(track)" 
          row="0" col="0"></Button>
      <Label [text]="track.name" row="0" col="1"></Label>
      <Switch [checked]="track.solo" row="0" col="2">
      </Switch>
    </GridLayout>
  </ng-template>
</ListView>
```

这个视图模板有很多内容，让我们来仔细检查一下。

由于我们在组件构造函数中将`playerService`声明为`public`，我们可以通过标准的 Angular 绑定语法`[items]`直接绑定到其 tracks，这将是我们的列表将迭代的集合。

内部的`template`节点允许我们封装列表中每一行的布局方式。它还允许我们声明一个变量名（`let-track`）作为我们的迭代器引用。

我们从一个 GridLayout 开始，因为每一行都将包含一个录制按钮（允许重新录制轨道），我们将为其分配宽度为 75。这个按钮将绑定到`tap`事件，如果用户经过身份验证，将激活一个录制会话。

然后，我们将有一个标签来显示轨道的用户提供的名称，我们将分配`*`以确保它扩展以填充左侧和右侧列之间的水平空间。我们使用文本属性来绑定到`track.name`。

最后，我们将使用`switch`来允许用户在混音中切换独奏轨道。这提供了`checked`属性，允许我们将`track.solo`属性绑定到。

# 构建一个对话框包装服务来提示用户

如果你还记得第一章中的*使用 @NgModule 进入形式*，录制是一个只能由经过身份验证的用户使用的功能。因此，当他们点击每个轨道的录制按钮时，我们将希望提示用户进行登录对话框。如果他们已经登录，我们将希望提示他们确认是否要重新录制轨道，以确保良好的可用性。

我们可以通过导入一个提供跨平台一致 API 的 NativeScript 对话框服务来直接处理这个对话框。NativeScript 框架的`ui/dialogs`模块（[`docs.nativescript.org/ui/dialogs`](https://docs.nativescript.org/ui/dialogs)）是一个非常方便的服务，允许您创建原生警报、确认、提示、操作和基本登录对话框。然而，我们可能希望为 iOS 和 Android 提供自定义的原生对话框实现，以获得更好的用户体验。有几个插件提供非常优雅的原生对话框，例如，[`github.com/NathanWalker/nativescript-fancyalert`](https://github.com/NathanWalker/nativescript-fancyalert)。

为了为这种丰富的用户体验做好准备，让我们构建一个快速的 Angular 服务，我们可以注入并在任何地方使用，这将使我们能够轻松地在将来实现这些美好的东西。

由于这应该被视为我们应用的“核心”服务，让我们创建`app/modules/core/services/dialog.service.ts`：

```ts
// angular
import { Injectable } from '@angular/core';

// nativescript
import * as dialogs from 'ui/dialogs';

@Injectable()
export class DialogService {

  public alert(msg: string) {
    return dialogs.alert(msg);
  }

  public confirm(msg: string) {
    return dialogs.confirm(msg);
  }

  public prompt(msg: string, defaultText?: string) {
    return dialogs.prompt(msg, defaultText);
  }

  public login(msg: string, userName?: string, password?: string) {
    return dialogs.login(msg, userName, password);
  }

  public action(msg: string, cancelButtonText?: string, 
    actions?: string[]) {
    return dialogs.action(msg, cancelButtonText, actions);
  }
}
```

乍一看，这似乎非常浪费！为什么要创建一个提供与已经存在于 NativeScript 框架中的服务完全相同 API 的包装器？

是的，确实，在这个阶段看起来是这样。然而，我们正在为将来处理这些对话框的灵活性和强大性做准备。敬请关注可能涵盖这种有趣而独特的整合的潜在奖励章节。

在我们继续使用这个服务之前，我们需要做的最后一件事是确保它被添加到我们的核心服务`PROVIDERS`集合中。这将确保 Angular 的 DI 系统知道我们的新服务是一个有效的可用于注入的令牌。

打开`app/modules/core/services/index.ts`并进行以下修改：

```ts
import { AuthService } from './auth.service';
import { DatabaseService } from './database.service';
import { DialogService } from './dialog.service';
import { LogService } from './log.service';

export const PROVIDERS: any[] = [
 AuthService,
 DatabaseService,
 DialogService,
 LogService
];

export * from './auth.service';
export * from './database.service';
export * from './dialog.service';
export * from './log.service';
```

我们现在准备好注入和使用我们的新服务。

# 将 DialogService 集成到我们的组件中

让我们打开`track-list.component.ts`并注入`DialogService`以在我们的记录方法中使用。我们还需要确定用户是否已登录，以有条件地显示登录对话框或确认提示，因此让我们也注入`AuthService`：

```ts
// angular
import { Component, Input } from '@angular/core';

// app
import { ITrack } from '../../../core/models';
import { AuthService, LogService, DialogService } from '../../../core/services';
import { PlayerService } from '../../services/player.service';

@Component({
  moduleId: module.id,
  selector: 'track-list',
  templateUrl: 'track-list.component.html'
})
export class TrackListComponent {

 constructor(
   private authService: AuthService,
   private logService: LogService,
   private dialogService: DialogService,
   public playerService: PlayerService
 ) { }

 public record(track: ITrack, usernameAttempt?: string) {
   if (AuthService.CURRENT_USER) {
     this.dialogService.confirm(
       'Are you sure you want to re-record this track?'
     ).then((ok) => {
       if (ok) this._navToRecord(track);
     });
   } else {
     this.authService.promptLogin(
       'Provide an email and password to record.',
       usernameAttempt
     ).then(
       this._navToRecord.bind(this, track), 
       (usernameAttempt) => {
         // initiate sequence again
         this.record(track, usernameAttempt);
       }
     ); 
    }
  }

  private _navToRecord(track: ITrack) {
    // TODO: navigate to record screen
    this.logService.debug('yes, re-record', track);
  }
}
```

现在，记录方法首先检查用户是否经过静态`AuthService.CURRENT_USER`引用进行了身份验证，该引用是在应用启动时通过 Angular 的依赖注入首次构建`AuthService`时设置的（参见第二章，*特性模块*）。

如果用户已经通过身份验证，我们会呈现一个确认对话框以确保操作是有意的。

如果用户没有经过身份验证，我们希望提示用户登录。为了减少本书的负担，我们将假设用户已经通过后端 API 注册，因此我们不会要求用户注册。

我们需要在`AuthService`中实现`promptLogin`方法来持久保存用户的登录凭据，这样他们每次返回应用时都会自动登录。现在，记录方法提供了一个额外的可选参数`usernameAttempt`，当在用户输入验证错误后重新启动登录序列时，这将有助于重新填充登录提示的用户名字段。我们不会在这里对用户输入进行彻底的验证，但至少可以对有效的电子邮件进行轻量级检查。

在您自己的应用中，您可能应该进行更多的用户输入验证。

为了保持关注点的清晰分离，打开`app/modules/core/services/auth.service.ts`来实现`promptLogin`。以下是带有修改的整个服务：

```ts
// angular
import { Injectable } from '@angular/core';

// lib
import { BehaviorSubject } from 'rxjs/BehaviorSubject';

// app
import { DatabaseService } from './database.service';
import { DialogService } from './dialog.service';
import { LogService } from './log.service';

@Injectable()
export class AuthService {

 // access our current user from anywhere
 public static CURRENT_USER: any;

 // subscribe to authenticated state changes
 public authenticated$: BehaviorSubject<boolean> = 
   new BehaviorSubject(false);

 constructor(
 private databaseService: DatabaseService,
 private dialogService: DialogService,
 private logService: LogService
 ) {
   this._init();
 } 

 public promptLogin(msg: string, username: string = '')
   : Promise<any> {
   return new Promise((resolve, reject) => {
     this.dialogService.login(msg, username, '')
       .then((input) => {
         if (input.result) { // result = false when canceled
           if (input.userName && 
               input.userName.indexOf('@') > -1) {
               if (input.password) {
                 // persist user credentials
                 this._saveUser(
                   input.userName, input.password
                 );
                 resolve();
               } else {
                 this.dialogService.alert(
                   'You must provide a password.'
                 ).then(reject.bind(this, input.userName));
               }
           } else {
             // reject, passing userName back
             this.dialogService.alert(
               'You must provide a valid email address.'
             ).then(reject.bind(this, input.userName));
           }
         }
       });
     });
 }

 private _saveUser(username: string, password: string) {
   AuthService.CURRENT_USER = { username, password };
   this.databaseService.setItem(
     DatabaseService.KEYS.currentUser,
     AuthService.CURRENT_USER
   );
   this._notifyState(true);
 }

  private _init() {
    AuthService.CURRENT_USER =
      this.databaseService
      .getItem(DatabaseService.KEYS.currentUser);
    this.logService.debug(
      `Current user: `, AuthService.CURRENT_USER
    );
    this._notifyState(!!AuthService.CURRENT_USER);
  }

  private _notifyState(auth: boolean) {
    this.authenticated$.next(auth);
  }
}
```

我们使用`dialogService.login`方法打开本机登录对话框，允许用户输入用户名和密码。一旦他们选择确定，我们对输入进行最小的验证，如果成功，就会继续通过`DatabaseService`持久保存用户名和密码。否则，我们只是警告用户有错误，并拒绝我们的承诺，传递输入的用户名。这样可以通过重新显示带有输入的用户名的登录对话框来帮助用户，以便他们更容易地进行更正。

完成这些服务级细节后，`track-list`组件看起来非常不错。然而，在我们进行这项工作时，我们应该采取一个额外的步骤。如果您还记得，我们的 TrackModel 包含一个 order 属性，这将帮助用户方便地按照他们喜欢的方式对曲目进行排序。

# 创建一个 Angular 管道 - OrderBy

Angular 提供了 Pipe 装饰器，以便轻松创建视图过滤器。让我们首先展示我们将如何在视图中使用它。您可以看到它看起来非常类似于 Unix shell 脚本中使用的命令行管道；因此，它被命名为：`Pipe`：

```ts
<ListView [items]="playerService.tracks | orderBy: 'order'">
```

这将获取`playerService.tracks`集合，并确保通过每个`TrackModel`的`order`属性对其进行排序，以便在视图中显示。

由于我们可能希望在应用程序的任何视图中使用这个，让我们将这个管道作为`CoreModule`的一部分添加。创建`app/modules/core/pipes/order-by.pipe.ts`，以下是我们将如何实现`OrderByPipe`：

```ts
import { Pipe } from '@angular/core';

@Pipe({
 name: 'orderBy'
})
export class OrderByPipe {

 // Comparator method
 static comparator(a: any, b: any): number {
   if (a === null || typeof a === 'undefined') a = 0;
   if (b === null || typeof b === 'undefined') b = 0;

   if ((isNaN(parseFloat(a)) || !isFinite(a)) || 
       (isNaN(parseFloat(b)) || !isFinite(b))) {
      // lowercase strings
      if (a.toLowerCase() < b.toLowerCase()) return -1;
      if (a.toLowerCase() > b.toLowerCase()) return 1;
   } else {
     // ensure number values
     if (parseFloat(a) < parseFloat(b)) return -1;
     if (parseFloat(a) > parseFloat(b)) return 1;
   }

   return 0; // values are equal
 }

 // Actual value transformation
 transform(value: Array<any>, property: string): any {
   return value.sort(function (a: any, b: any) {
     let aValue = a[property];
     let bValue = b[property];
     let comparison = OrderByPipe
                      .comparator(aValue, bValue);
     return comparison;
   });
 } 
}
```

我们不会详细介绍这里发生了什么，因为在 JavaScript 中对集合进行排序是非常典型的。为了完成这一点，确保`app/modules/core/pipes/index.ts`遵循我们的标准约定：

```ts
import { OrderByPipe } from './order-by.pipe';

export const PIPES: any[] = [
 OrderByPipe
];
```

最后，导入前面的集合以与`app/modules/core/core.module.ts`一起使用。以下是所有修改的完整文件：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 

// angular
import { NgModule } from '@angular/core';

// app
import { PIPES } from './pipes';
import { PROVIDERS } from './services';

@NgModule({
 imports: [
   NativeScriptModule
 ],
 declarations: [
   ...PIPES
 ],
 providers: [
   ...PROVIDERS
 ],
 exports: [
   NativeScriptModule,
   ...PIPES
 ]
})
export class CoreModule { }
```

由于管道是视图级别的实现，我们确保它们作为`exports`集合的一部分添加，以允许其他模块使用它们。

现在，如果我们在这一点上运行我们的应用程序，您会注意到我们在`track-list.component.html`视图模板上使用的`OrderBy`管道*不会*工作！

Angular 模块在彼此之间进行隔离编译。

这是一个需要理解的关键点：Angular 将声明`TrackListComponent`的`PlayerModule`编译到自身中，以孤立的方式。由于我们将`OrderByPipe`声明为`CoreModule`的一部分，而`PlayerModule`目前对`CoreModule`没有依赖，`TrackListComponent`被编译时并不知道`OrderByPipe`！你会在控制台中看到生成的错误：

```ts
CONSOLE ERROR file:///app/tns_modules/tns-core-modules/trace/trace.js:160:30: ns-renderer: ERROR BOOTSTRAPPING ANGULAR
CONSOLE ERROR file:///app/tns_modules/tns-core-modules/trace/trace.js:160:30: ns-renderer: Template parse errors:
 The pipe 'orderBy' could not be found ("
 </ListView>-->

 <ListView [ERROR ->][items]="playerService.tracks | orderBy: 'order'">
   <ng-template let-track="item">
     <GridLayout rows"): TrackListComponent@10:10
```

为了解决这个问题，我们希望确保`PlayerModule`知道来自`CoreModule`的与视图相关的声明（如管道或其他组件），方法是确保`CoreModule`作为`PlayerModule`的`imports`集合的一部分添加进去。这也为我们提供了一个额外的便利。如果你注意到，`CoreModule`指定`NativeScriptModule`作为一个导出，这意味着导入`CoreModule`的任何模块将从中获得`NativeScriptModule`。以下是允许所有内容一起工作的`PlayerModule`的最终修改：

```ts
// angular
import { NgModule } from '@angular/core';

// app
import { CoreModule } from '../core/core.module';
import { COMPONENTS } from './components';
import { PROVIDERS } from './services';

@NgModule({
 imports: [
   CoreModule 
 ],
 providers: [...PROVIDERS],
 declarations: [...COMPONENTS],
 exports: [...COMPONENTS]
})
export class PlayerModule { }
```

现在我们可以继续进行`player-controls`组件。

# 构建 PlayerControls 组件

我们的播放器控件应该包含一个用于整个混音的播放/暂停切换按钮。它还应该呈现一个滑块控件，允许我们快进和倒带我们的播放。

让我们创建`app/modules/player/components/player-controls/player-controls.component.html`（带有匹配的`.ts`）：

```ts
<GridLayout rows="100" columns="75,*" row="1" col="0">
  <Button [text]="playStatus" (tap)="togglePlay()" row="0" col="0"></Button>
  <Slider minValue="0" [maxValue]="duration" 
          [value]="currentTime" row="0" col="1"></Slider>
</GridLayout>
```

我们从一个具有明确的 100 高度的单行`GridLayout`开始。然后，第一列将被限制为 75 宽，以容纳我们的播放/暂停切换按钮。然后，第二列将占据其余的水平空间，用`*`表示，使用`Slider`组件。这个组件由 NativeScript 框架提供，允许我们将`maxValue`属性绑定到我们混音的总持续时间，以及将值绑定到播放的`currentTime`。

然后，对于`player-controls.component.ts`：

```ts
// angular
import { Component, Input } from '@angular/core';

// app
import { ITrack } from '../../../core/models';
import { LogService } from '../../../core/services';
import { PlayerService } from '../../services';

@Component({
 moduleId: module.id,
 selector: 'player-controls',
 templateUrl: 'player-controls.component.html'
})
export class PlayerControlsComponent {

 public currentTime: number = 0; 
 public duration: number = 0; 
 public playStatus: string = 'Play';

 constructor(
   private logService: LogService,
   private playerService: PlayerService
 ) { }

 public togglePlay() {
   let playing = !this.playerService.playing;
   this.playerService.playing = playing;
   this.playStatus = playing ? 'Stop' : 'Play';
 }

}
```

目前，我们已经直接将`currentTime`和`duration`放在了组件上，但是以后我们会将它们重构到`PlayerService`中。最终，当我们在后续章节实现处理音频的插件时，与我们的播放器相关的所有状态都将来自于`PlayerService`。`togglePlay`方法也只是为一些一般行为设置了存根，切换我们按钮的文本为播放或停止。

# 快速预览

在这一点上，我们将快速查看我们到目前为止构建的内容。目前，我们的播放器服务返回一个空的曲目列表。为了查看结果，我们应该向其中添加一些虚拟数据。例如，在`PlayerService`中，我们可以添加：

```ts
constructor() {
  this.tracks = [
    {name: "Guitar"},
    {name: "Vocals"},
  ];
}
```

如果它不够漂亮，不要感到惊讶；我们将在下一章中涵盖这一点。我们也不会涵盖我们目前可用的所有运行时命令；我们将在第六章 *在 iOS 和 Android 上运行应用程序* 中彻底涵盖这一点。

# 在 iOS 上预览

你需要在安装了 XCode 的 Mac 上预览 iOS 应用程序：

```ts
tns run ios --emulator
```

这将启动 iOS 模拟器，你应该会看到以下截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00006.jpeg)

# 在 Android 上预览

你需要安装 AndroidSDKk 和工具才能在 Android 模拟器上预览：

```ts
tns run android --emulator
```

这将启动一个 Android 模拟器，你应该会看到以下截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00007.jpeg)

恭喜！我们有了我们的第一个视图。嘿，没人说它会很漂亮！

# 总结

我们已经开始了第二部分的组件构建，我们已经布置了我们的根组件`app.component.html`来容纳我们的主视图，你将学习到`GridLayout`，一个非常有用的布局容器。

Angular 的组件装饰器使我们能够轻松构建`TrackListComponent`和`PlayerControlsComponent`。我们还学会了如何构建一个 Angular `Pipe` 来帮助我们的视图保持我们的曲目列表有序。Angular 的`NgModule`教会了我们需要确保任何与视图相关的声明都被正确导入。这种 Angular 设计模式有助于保持模块隔离，作为可以通过相互导入模块相互混合的独立代码单元。

我们还增强了一些服务，以支持我们对组件所需的一些可用性。

最后，我们能够快速地看一下我们正在构建的东西。尽管目前还不够漂亮，但我们可以看到事情正在逐渐成形。

在第四章 *使用 CSS 创建更漂亮的视图* 中，你将学习如何使用 CSS 来美化我们的视图。


# 第四章：使用 CSS 创建更美观的视图

NativeScript 为原生应用程序开发带来的许多关键好处之一是能够使用标准 CSS 为原生视图组件设置样式。您会发现对许多常见和高级属性有很好的支持；然而，有些属性没有直接对应，而其他属性则完全是原生视图布局的独特之处。

让我们看看如何使用一些 CSS 类将我们的第一个视图变得非常惊人。您还将学习如何利用 NativeScript 的核心主题来提供一致的样式框架以构建。

在本章中，我们将涵盖以下主题：

+   使用 CSS 来为视图设置样式

+   了解典型 Web 样式和原生样式之间的一些区别

+   使用特定于平台的文件解锁 NativeScript 的功能

+   学习如何使用 nativescript-theme-core 样式框架插件

+   调整 iOS 和 Android 上状态栏的背景颜色和文本颜色

# 是时候开始优雅了

让我们首先看看我们应用程序主要的`app.css`文件，位于`App`目录中：

```ts
/*
In NativeScript, the app.css file is where you place CSS rules that
you would like to apply to your 

entire application. Check out
http://docs.nativescript.org/ui/styling for a full list of the CSS
selectors and 

properties you can use to style UI components.

/*
For example, the following CSS rule changes the font size 

of all UI
components that have the btn class name.
*/
.btn {
  font-size: 18;
}

/*
In many cases you may want to use the NativeScript core theme instead
of writing your own CSS rules. For a full list 

of class names in the theme
refer to http://docs.nativescript.org/ui/theme.
*/
@import 'nativescript-

theme-core/css/core.light.css';
```

默认情况下，`--ng`模板提示了您可以选择的两个选项来构建您的 CSS：

+   编写自定义类

+   将 nativescript-theme-core 样式框架插件用作基础。

让我们探索第一个选项片刻。在`.btn`类之后添加以下内容：

```ts
.btn {
  font-size: 18;
}

.row {
 padding: 15 5;
 background-color: yellow;
}

.row .title {
 font-size: 25;
 color: #444;
 font-weight: bold;
}

Button {
 background-color: red;
 color: white;
}
```

从这个简单的例子中，您可能会立即注意到一些有趣的事情：

+   `padding`不使用您在 Web 样式中熟悉的`px`后缀。

+   不用担心，使用`px`后缀不会伤害您。

+   从 NativeScript 3.0 开始，支持发布单位，因此您可以使用 dp（设备独立像素）或`px`（设备像素）。

如果未指定单位，则将使用 dp。对于宽度/高度和边距，您还可以在 CSS 中使用百分比作为单位类型。

+   支持各种常见属性（`padding`，`font size`，`font weight`，`color`，`background color`等）。同样，简写的`margin/padding`也可以使用，即`padding: 15 5`。

+   您可以使用标准的十六进制颜色名称，例如黄色，或者使用简写代码，例如＃444。

+   CSS 作用域与您期望的一样，即`.row .title { ...`。

+   元素/标签/组件名称可以进行全局样式设置。

尽管您可以按标签/组件名称设置样式，但不建议这样做。我们将向您展示一些有趣的原生设备注意事项。

现在，让我们打开 `app/modules/player/components/track-list/track-list.component.html` 并在我们的模板中添加 `row` 和 `title` 类：

```ts
<ListView [items]="playerService.tracks | orderBy: 'order'">
  <template let-track="item">

<GridLayout rows="auto" columns="100,*,100" class="row">
      <Button text="Record" (tap)

="record(track)" row="0" col="0"></Button>
      <Label [text]="track.name" row="0" col="1" 

class="title"></Label>
      <Switch row="0" col="2"></Switch>

</GridLayout>
  </template>
</ListView>
```

让我们快速预览一下使用 `tns run ios --emulator` 会发生什么，你应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00008.jpeg)

如果您在 Android 中使用 `tns run android --emulator`，您应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00009.jpeg)

我们可以看到，在两个平台上，这些样式都得到了一致的应用，同时仍然保持了每个平台的独特特征。例如，iOS 保持了按钮的扁平设计美学，开关提供了熟悉的 iOS 感觉。相比之下，在 Android 上，按钮保留了其微妙的默认阴影和全大写文本，同时保留了熟悉的 Android 开关。

然而，有一些微妙的（可能不理想的）差异是重要的理解和解决的。从这个例子中，我们可能注意到以下内容：

1.  Android 的按钮左右边距比 iOS 宽。

1.  行标题的对齐不一致。在 iOS 上，默认情况下，标签是垂直居中的；然而，在 Android 上，它是对齐到顶部的。

1.  如果您点击“记录”按钮查看登录对话框，您还会注意到一些非常不理想的东西：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00010.jpeg)

第 3 项可能是最令人惊讶和意想不到的。它展示了全局样式元素/标签/组件名称不建议的主要原因之一。由于原生对话框默认使用 `Buttons`，我们添加的一些全局 `Button` 样式正在渗入对话框（特别是 `color: white`）。为了解决这个问题，我们可以确保适当地限定所有组件名称：

```ts
.row Button {
 background-color: red;
 color: white;
} 
```

或者更好的是，只需在按钮上使用一个类名：

```ts
.row .btn {
 background-color: red;
 color: white;
} <Button text="Record" (tap)="record(track)" row="0" col="0" 

class="btn"></Button>
```

为了解决第 2 项（行标题对齐），我们可以介绍 NativeScript 的一个特殊功能：根据运行平台构建特定于平台的文件的能力。让我们创建一个新文件 `app/common.css`，并将 `app/app.css` 的所有内容重构到这个新文件中。然后，让我们创建另外两个新文件 `app/app.ios.css` 和 `app/app.android.css`（然后删除 `app.css`，因为它将不再需要），两个文件的内容如下：

```ts
@import './common.css';
```

这将确保我们的共享通用样式被导入到 iOS 和 Android 的 CSS 中。现在，我们有一种方法来应用特定于平台的样式修复！

让我们通过修改 `app/app.android.css` 来解决垂直对齐问题：

```ts
@import './common.css';

.row .title {
  vertical-align: center;
}
```

这为我们现在添加了仅适用于 Android 的额外样式调整：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00011.jpeg)

非常好，好多了。

要解决问题＃1，如果我们希望在两个平台上的按钮具有相同的边距，我们需要应用更多特定于平台的调整。

此时，您可能想知道您需要自己进行多少调整来解决一些特定于平台的问题。您会高兴地知道，并没有详尽的清单，但是非常高昂的 NativeScript 社区共同努力创造了更好的东西，一个一致的类似于 bootstrap 的核心主题，提供了许多这些微妙的调整，比如标签的垂直对齐和许多其他微妙的调整。

# 认识 NativeScript 核心主题

所有新的 NativeScript 项目都安装了一个核心主题，并且可以立即使用。如前所述，您可以选择两种选项来为您的应用程序设置样式。前面的部分概述了您在从头开始为您的应用程序设置样式时可能遇到的一些问题。

让我们来看看 Option #2：使用`nativescript-theme-core`插件。这个主题是为了扩展和构建而构建的。它提供了各种各样的实用类，用于间距、着色、布局、着色皮肤等等。由于它提供了坚实的基础和令人惊叹的灵活性，我们将在这个主题的基础上构建我们应用的样式。

值得一提的是，`nativescript-theme-`前缀是有意为之的，因为它有助于提供一个在`npm`上搜索所有 NativeScript 主题的常用前缀。如果您设计并发布自己的自定义 NativeScript 主题，建议使用相同的前缀。

让我们移除我们的自定义样式，只留下核心主题。然而，我们不会使用默认的浅色皮肤，而是使用深色皮肤。现在我们的`app/common.css`文件应该是这样的：

```ts
@import 'nativescript-theme-core/css/core.dark.css';
```

现在，我们希望开始使用核心主题提供的一些类来为我们的组件分类。您可以在这里了解所有类的完整列表：[`docs.nativescript.org/ui/theme`](https://docs.nativescript.org/ui/theme)。

从`app/app.component.html`开始，让我们添加以下类：

```ts
<ActionBar title="TNSStudio" class="action-bar">
</ActionBar>
<GridLayout 

rows="*, 100" columns="*" class="page">
  <track-list row="0" col="0"></track-list>
  <player-controls row="1" col="0"></player-controls>
</GridLayout>
```

`action-bar`类确保我们的皮肤能够适当地应用于应用程序的标题，并为 iOS 和 Android 上的`ActionBar`提供微妙的一致性调整。

`page`类确保我们的皮肤应用于整个页面。在任何给定的组件视图上，将此类应用于根布局容器非常重要。

通过这两个调整，我们现在应该在 iOS 上看到这个：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00012.jpeg)

而这是在 Android 上的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00013.jpeg)

您会注意到`ListView`的另一个 iOS/Android 差异。iOS 默认具有白色背景，而 Android 似乎具有透明背景，允许皮肤页面颜色透过显示。让我们继续使用核心主题中更多的类来为我们的组件分类，这有助于解决这些细微差别。打开`app/modules/player/components/track-list/track-list.component.html`并添加以下类：

```ts
<ListView [items]="playerService.tracks | orderBy: 'order'" class="list-group">
  <ng-

template let-track="item">
    <GridLayout rows="auto" columns="100,*,100" class="list-group-

item">
      <Button text="Record" (tap)="record(track)" row="0" col="0" class="c-

ruby"></Button>
      <Label [text]="track.name" row="0" col="1" 

class="h2"></Label>
      <Switch row="0" col="2" 

class="switch"></Switch>
    </GridLayout>
  </ng-template>
</ListView>
```

父类`list-group`有助于将所有内容范围限定到`list-group-item`。然后，我们添加`c-ruby`来为我们的录音按钮添加一些红色。有几种皮肤颜色提供了姓氏：`c-sky`，`c-aqua`，`c-charcoal`，`c-purple`等等。在这里查看所有这些：[`docs.nativescript.org/ui/theme#color-schemes`](https://docs.nativescript.org/ui/theme#color-schemes)。

然后我们在标签中添加`h2`，使其字体大小增加一点。最后，`switch`类有助于标准化轨道独奏开关。

现在我们在 iOS 上有了这个：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00014.jpeg)

而我们在 Android 上有了这个：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00015.jpeg)

让我们继续前进到我们的最后一个组件（目前为止），`player-controls`。打开`app/modules/player/components/player-controls/player-controls.component.html`并添加以下内容：

```ts
<GridLayout rows="100" columns="100,*" row="1" col="0" class="p-x-10">
  <Button 

[text]="playStatus" (tap)="togglePlay()" row="0" col="0" class="btn btn-primary w-

100"></Button>
  <Slider minValue="0" [maxValue]="duration" [value]="currentTime" row="0" col="1" 

class="slider"></Slider>
</GridLayout>
```

首先，我们添加`p-x-10`类来为左/右容器（`GridLayout`）添加`10`填充。然后，我们为我们的播放/暂停按钮添加`btn btn-primary w-100`。`w-100`类将按钮的宽度设置为`100`。然后，我们为我们的滑块添加`slider`类。

现在，在 iOS 上事情开始有所进展：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00016.jpeg)

在 Android 上看起来将如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00017.jpeg)

哇，好了，现在事情正在逐渐成形。随着我们的进行，我们将继续对事情进行更多的打磨，但是这个练习已经展示了您可以多快地使用核心主题中的许多类来调整您的样式。

# 调整 iOS 和 Android 上状态栏的背景颜色和文本颜色

您可能已经注意到，在 iOS 上，状态栏文本是黑色的，与我们的深色皮肤不太搭配。此外，我们可能希望改变 Android 的状态栏色调。NativeScript 提供了对原生 API 的直接访问，因此我们可以轻松地将它们更改为我们想要的样子。这两个平台处理它们的方式不同，因此我们可以有条件地为每个平台更改状态栏。

打开 `app/app.component.ts`，让我们添加以下内容：

```ts
// angular
import { Component } from '@angular/core';

// nativescript
import { isIOS } from 'platform';
import { topmost } from 'ui/frame';
import * as app from 'application';

// app
import { AuthService } from 

'./modules/core/services';

declare var android;

@Component({
  moduleId: 

module.id,
  selector: 'my-app',
  templateUrl: 'app.component.html',
})
export class AppComponent {

  constructor(
    private authService: AuthService
  ) { 
    if (isIOS) {
 /**
 * 0 = black text
 * 1 = white text
 */
 topmost().ios.controller.navigationBar.barStyle = 1;
 } else {
 // adjust text to darker color
 let decorView = 

app.android.startActivity.getWindow()
 .getDecorView();
 decorView.setSystemUiVisibility(android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
 }
  }
}
```

这将使 iOS 状态栏文本变为白色：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00018.jpeg)

条件的第二部分调整 Android 以在状态栏中使用深色文本：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00019.jpeg)

在此期间，让我们也调整 `ActionBar` 的背景颜色，为其增添一些亮点。在 iOS 上，状态栏的背景颜色采用 `ActionBar` 的背景颜色，而在 Android 上，状态栏的背景颜色必须通过 `App_Resources` 中的 Android `colors.xml` 进行调整。从 iOS 开始，让我们打开 `app/common.css` 并添加以下内容：

```ts
.action-bar {
  background-color:#101B2E;
}
```

这将为 iOS 的 `ActionBar` 着色如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00020.jpeg)

对于 Android，我们希望我们的状态栏背景呈现与我们 `ActionBar` 背景相衬的色调。为此，我们要打开 `app/App_Resources/Android/values/colors.xml` 并进行以下调整：

```ts
<?xml version="1.0" encoding="utf-8"?>
<resources>
  <color 

name="ns_primary">#F5F5F5</color>
  <color 

name="ns_primaryDark">#284472</color>
  <color name="ns_accent">#33B5E5</color>

<color name="ns_blue">#272734</color>
</resources>
```

这是 Android 上的最终结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00021.jpeg)

# 总结

最终为我们的应用程序添加外观是令人耳目一新和有趣的；然而，我们当然还没有完成样式设置。我们将继续通过 CSS 磨练视图，并很快引入 SASS 来在即将到来的章节中进一步完善它。然而，本章介绍了您在通过 CSS 设置应用程序时需要注意的各种考虑因素。

您已经了解到常见的 CSS 属性是受支持的，并且我们还看到了 iOS 和 Android 处理某些默认特性的差异。具有特定于平台的 CSS 覆盖的能力是一个很好的好处，也是您想要利用在跨平台 NativeScript 应用程序中的特殊能力。了解如何在两个平台上控制状态栏的外观是实现应用程序所需外观和感觉的关键。

在下一章中，我们将暂时停止样式设置，转而深入研究通过延迟加载进行路由和导航，为我们的应用程序的一般可用性流程做好准备。准备好深入了解我们应用程序中更有趣的 Angular 部分。


# 第五章：路由和懒加载

路由对于任何应用程序的稳定可用性流程至关重要。让我们了解移动应用程序的路由配置的关键要素，以充分利用 Angular 路由器给我们带来的所有灵活性。

在本章中，我们将涵盖以下主题：

+   配置 Angular 路由器与 NativeScript 应用程序

+   按路由懒加载模块

+   为 Angular 的`NgModuleFactoryLoader`提供`NSModuleFactoryLoader`

+   了解如何在`page-router-outlet`与`router-outlet`结合使用

+   学习如何在多个延迟加载模块之间共享单例服务

+   使用身份验证守卫保护需要有效身份验证的视图

+   了解如何使用`NavigationButton`自定义后退移动导航

+   通过引入后期功能需求来利用我们灵活的路由设置

# 在 66 号公路上踏上你的旅程

当我们开始沿着这条充满冒险的高速公路旅行时，让我们从在本地服务站停下来，确保我们的车辆状态良好。进入`app`的根目录，构建一个新的附加到我们车辆引擎的模块：路由模块。

创建一个新的路由模块`app/app.routing.ts`，内容如下：

```ts
import { NgModule } from '@angular/core';
import { NativeScriptRouterModule } 
  from 'nativescript-angular/router';
import { Routes } from '@angular/router';

const routes: Routes = [
  {
    path: '',
    redirectTo: '/mixer/home',
    pathMatch: 'full'
  },
  {
    path: 'mixer',
    loadChildren: () => require('./modules/mixer/mixer.module')['MixerModule']
  },
  {
    path: 'record',
    loadChildren: () => require('./modules/recorder/recorder.module')['RecorderModule']
  }
];

@NgModule({
  imports: [
    NativeScriptRouterModule.forRoot(routes)
  ],
  exports: [
    NativeScriptRouterModule
  ]
})
export class AppRoutingModule { }
```

将根路径`''`定义为重定向到一个延迟加载模块提供了非常灵活的路由配置，正如你将在本章中看到的那样。您将看到一个新模块`MixerModule`，我们马上就会创建。实际上，它将在很大程度上成为当前`AppComponent`的样子。以下是您使用类似于此路由配置时获得的一些优势列表：

+   通过急切加载仅有最少的根模块配置，然后懒加载第一个路由模块，使应用启动时间保持快速

+   为我们提供了利用`page-router-outlet`和`router-outlet`的能力，结合主/细节导航以及`clearHistory`交换页面导航

+   将路由配置责任隔离到相关模块，随着时间的推移，这种方式会更加灵活

+   如果我们决定更改用户最初呈现的初始页面，可以轻松地在将来针对不同的**起始页面**进行定位

这使用`NativeScriptRoutingModule.forRoot(routes)`，因为这应该被视为我们应用程序路由配置的根。

我们还导出 `NativeScriptRoutingModule`，因为我们将在稍后将这个 `AppRoutingModule` 导入到我们的根 `AppModule` 中。这使得路由指令可用于我们根模块的根组件。

# 为 NgModuleFactoryLoader 提供 NSModuleFactoryLoader

默认情况下，Angular 的内置模块加载器使用 SystemJS；然而，NativeScript 提供了一个增强的模块加载器称为 `NSModuleFactoryLoader`。让我们在主路由模块中提供这个，以确保所有我们的模块都是用它加载而不是 Angular 的默认模块加载器。

对 `app/app.routing.ts` 进行以下修改：

```ts
import { NgModule, NgModuleFactoryLoader } from '@angular/core';
import { NativeScriptRouterModule, NSModuleFactoryLoader } from 'nativescript-angular/router';

const routes: Routes = [
  {
    path: '',
    redirectTo: '/mixer/home',
    pathMatch: 'full'
  },
  {
    path: 'mixer',
    loadChildren: './modules/mixer/mixer.module#MixerModule'
  },
  {
    path: 'record',
    loadChildren: './modules/recorder/recorder.module#RecorderModule',
    canLoad: [AuthGuard]
  }
];

@NgModule({
  imports: [
    NativeScriptRouterModule.forRoot(routes)
  ],
  providers: [
    AuthGuard,
    {
 provide: NgModuleFactoryLoader,
 useClass: NSModuleFactoryLoader
 }
  ],
  exports: [
    NativeScriptRouterModule
  ]
})
export class AppRoutingModule { }
```

现在，我们可以使用标准的 Angular 懒加载语法通过 `loadChildren` 来指定默认的 `NgModuleFactoryLoader`，但应该使用 NativeScript 增强的 `NSModuleFactoryLoader`。我们不会详细介绍 `NSModuleFactoryLoader` 提供的内容，因为在这里已经很好地解释了：[`www.nativescript.org/blog/optimizing-app-loading-time-with-angular-2-lazy-loading`](https://www.nativescript.org/blog/optimizing-app-loading-time-with-angular-2-lazy-loading)，而且我们还有很多内容要在本书中介绍。

很好。有了这些升级，我们可以离开服务店，继续沿着高速公路前行。让我们继续实现我们的新路由设置。

打开 `app/app.component.html`；将其内容剪切到剪贴板，并用以下内容替换：

```ts
<page-router-outlet></page-router-outlet>
```

这将成为我们视图级实现的基础。 `page-router-outlet` 允许任何组件插入自己的位置，无论是单个平面路由还是具有自己子视图的路由。它还允许其他组件视图推送到移动导航栈，实现主/细节移动导航和后退历史记录。

为了使 `page-router-outlet` 指令工作，我们需要我们的根 `AppModule` 导入我们的新 `AppRoutingModule`。我们还将利用这个机会删除之前导入的 `PlayerModule`。打开 `app/app.module.ts` 并进行以下修改：

```ts
// angular
import { NgModule } from '@angular/core';

// app
import { CoreModule } from './modules/core/core.module';
import { AppRoutingModule } from './app.routing';
import { AppComponent } from './app.component';

@NgModule({
 imports: [
   CoreModule,
   AppRoutingModule
 ],
 declarations: [AppComponent],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

# 创建 MixerModule

这个模块实际上不会有什么新东西，因为它将作为之前我们根组件视图的重新定位。然而，它将引入一个额外的好处：能够定义自己的内部路由。

创建 `app/modules/mixer/components/mixer.component.html`，并粘贴从 `app.component.html` 中剪切的内容：

```ts
<ActionBar title="TNSStudio" class="action-bar"></ActionBar><GridLayout rows="*, 100" columns="*" class="page">  
  <track-list row="0" col="0"></track-list>  
  <player-controls row="1" col="0"></player-controls></GridLayout>
```

然后创建一个匹配的 `app/modules/mixer/components/mixer.component.ts`：

```ts
import { Component } from '@angular/core';

@Component({ 
  moduleId: module.id, 
  selector: 'mixer', 
  templateUrl: 'mixer.component.html'
})
export class MixerComponent {}
```

现在，我们将创建`BaseComponent`，它将作为不仅是前面的`MixerComponent`，还有任何其他我们可能想要在其位置呈现的子视图组件的占位符。例如，我们的混音器可能希望允许用户将单个轨道从混音器中弹出并放入一个隔离的视图中以处理音频效果。

在`app/modules/mixer/components/base.component.ts`中创建以下内容：

```ts
// angular
import { Component } from '@angular/core';

@Component({
 moduleId: module.id,
 selector: 'mixer-base',
 template: `<router-outlet></router-outlet>`
})
export class BaseComponent { }
```

这提供了一个插槽，用于插入我们的混音器配置的任何子路由，其中之一是`MixerComponent`本身。由于视图只是一个简单的`router-outlet`，因此没有必要创建单独的`templateUrl`，所以我们在这里直接内联了它。

现在，我们准备实现`MixerModule`；创建`app/modules/mixer/mixer.module.ts`，其中包含以下内容：

```ts
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';
import { NativeScriptRouterModule } from 
  'nativescript-angular/router';
import { Routes } from '@angular/router';

import { PlayerModule } from '../player/player.module';
import { BaseComponent } from './components/base.component';
import { MixerComponent } from 
  './components/mixer.component';

const COMPONENTS: any[] = [
  BaseComponent,
  MixerComponent
]

const routes: Routes = [
  {
    path: '',
    component: BaseComponent,
    children: [
      {
        path: 'home',
        component: MixerComponent
      }
    ]
  }
];

@NgModule({
  imports: [
    PlayerModule,
    NativeScriptRouterModule.forChild(routes)
  ],
  declarations: [
    ...COMPONENTS
  ],
  schemas: [
    NO_ERRORS_SCHEMA
  ]
})
export class MixerModule { }
```

我们已经导入了`PlayerModule`，因为混音器使用了在那里定义的组件/小部件（即`track-list`和`player-controls`）。我们还利用了`NativeScriptRouterModule.forChild(routes)`方法来指示这些特定的子路由。我们的路由配置在根路径`' '`处设置了 BaseComponent，将`'home'`定义为`MixerComponent`。如果您还记得，我们应用的`AppRoutingModule`配置了我们应用的根路径，如下所示：

```ts
...
{
  path: '',
  redirectTo: '/mixer/home',
  pathMatch: 'full'
},
...
```

这将直接路由到`MixerComponent`，在这里被定义为`'home'`。如果需要，我们可以通过将`redirectTo`指向混音器的不同子视图来轻松地将启动页面定向到不同的视图。由于`BaseComponent`只是一个`router-outlet`，在我们的混音器路由的根路径`' '`下定义的任何子级（由我们整个应用的路由视为`'/mixer'`）都将直接插入到该视图插槽中。如果您现在运行这个，您应该会看到我们之前的相同的启动页面。

恭喜！您的应用启动时间现在很快，您已经懒加载了第一个模块！

但是，有一些令人惊讶的事情需要注意：

+   您可能会注意到在启动页面出现之前会有一个快速的白色闪烁（至少在 iOS 上是这样）

+   您可能会注意到控制台日志打印了“当前用户：”两次

我们将分别解决这些问题。

1.  在启动页面显示之前去除闪屏。

这是正常的，是默认页面背景颜色白色的结果。为了提供无缝的启动体验，打开`app/common.css`文件，并将全局`Page`类定义放在这里，将背景颜色着色为与我们的`ActionBar`背景颜色相同：

```ts
Page {
  background-color:#101B2E;
}
```

现在，不会再出现白屏，应用程序的启动将显得无缝。

1.  控制台日志会打印两次“当前用户：”

Angular 的依赖注入器由于延迟加载而导致了这个问题。

这段代码来自`app/modules/core/services/auth.service.ts`，我们在这里有一个私有的`init`方法，它是从服务的构造函数中调用的。

```ts
...
@Injectable()
export class AuthService {
   ...
   constructor(
     private databaseService: DatabaseService,
     private logService: LogService
   ) {
     this._init();
   } 
  ...
  private _init() {
    AuthService.CURRENT_USER = this.databaseService.getItem(
      DatabaseService.KEYS.currentUser);
    this.logService.debug(`Current user: `,
 AuthService.CURRENT_USER);
    this._notifyState(!!AuthService.CURRENT_USER);
  }
  ...
}
```

等等！这是什么意思？这意味着`AuthService`被构造了两次吗？！

是的。它是的。:(

我能听到车轮的尖叫声，就在此刻，你把这次高速公路冒险转向了沟渠里。;)

这绝对是一个巨大的问题，因为我们绝对打算让`AuthService`成为一个可以在任何地方注入并共享以提供我们应用程序当前认证状态的全局共享单例。

现在我们必须解决这个问题，但在看一个可靠的解决方案之前，让我们先稍微偏离一下，了解一下为什么会发生这种情况。

# 了解 Angular 的依赖注入器在延迟加载模块时的行为

我们将直接从 Angular 官方文档(`https://angular.io/guide/ngmodule-faq#!#q-why-child-injector`)中引用，而不是重述细节，这完美地解释了这一点：

Angular 会将`@NgModule.providers`添加到应用程序根注入器，除非该模块是延迟加载的。对于延迟加载的模块，Angular 会创建一个子注入器，并将模块的提供者添加到子注入器中。

这意味着一个模块的行为会有所不同，取决于它是在应用程序启动期间加载还是在后来进行延迟加载。忽视这种差异可能会导致不良后果。

为什么 Angular 不像对急切加载模块那样将延迟加载的提供者添加到应用程序根注入器中呢？

答案根植于 Angular 依赖注入系统的一个基本特性。一个注入器可以添加提供者，直到它第一次被使用。一旦注入器开始创建和提供服务，它的提供者列表就被冻结了；不允许添加新的提供者。

当应用程序启动时，Angular 首先会将根注入器配置为所有急切加载模块的提供者，然后创建其第一个组件并注入任何提供的服务。一旦应用程序开始，应用程序根注入器就关闭了新的提供者。

时间过去了，应用逻辑触发了一个模块的延迟加载。Angular 必须将延迟加载模块的提供者添加到某个注入器中。它不能将它们添加到应用程序根注入器，因为该注入器对新提供者是关闭的。因此，Angular 为延迟加载模块上下文创建一个新的子注入器。

如果我们看一下我们的根`AppModule`，我们可以看到它导入了`CoreModule`，其中提供了`AuthService`：

```ts
...
@NgModule({
  imports: [
    CoreModule,
    AppRoutingModule
  ],
  declarations: [AppComponent],
  bootstrap: [AppComponent],
  schemas: [NO_ERRORS_SCHEMA]
})
export class AppModule { }
```

如果我们再看一下`PlayerModule`，我们可以看到它也导入了`CoreModule`，因为`PlayerModule`的组件使用了它声明的`OrderByPipe`以及它提供的一些服务（即`AuthService`，`LogService`和`DialogService`）：

```ts
...
@NgModule({
  imports: [
    CoreModule
  ],
  providers: [...PROVIDERS],
  declarations: [...COMPONENTS],
  exports: [...COMPONENTS],
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class PlayerModule { }
```

由于我们新的路由配置，`PlayerModule`现在是延迟加载的，与`MixerModule`一起加载。这会导致 Angular 的依赖注入器为我们的延迟加载的`MixerModule`注册一个新的子注入器，其中包括`PlayerModule`，它还带来了它导入的`CoreModule`，其中定义了那些提供者，包括`AuthService`，`LogService`等等。当 Angular 注册`MixerModule`时，它将注册整个新模块中定义的所有提供者，包括它的导入模块与新的子注入器，从而产生这些服务的新实例。

Angular 的文档还提供了一个推荐的模块设置来解决这种情况，所以让我们再次从`https://angular.io/guide/ngmodule-faq#!#q-module-recommendations`进行改述：

SharedModule

创建一个`SharedModule`，其中包含你在应用程序中到处使用的组件、指令和管道。这个模块应该完全由声明组成，其中大部分是导出的。`SharedModule`可以重新导出其他小部件模块，比如`CommonModule`，`FormsModule`，以及你最广泛使用的 UI 控件模块。`SharedModule`不应该有提供者，原因在之前已经解释过。它导入或重新导出的模块也不应该有提供者。如果你偏离了这个指南，要知道你在做什么以及为什么。在你的特性模块中导入`SharedModule`，无论是在应用启动时加载的模块还是以后延迟加载的模块。

创建一个`CoreModule`，其中包含应用启动时加载的单例服务的提供者。只在根`AppModule`中导入`CoreModule`。永远不要在任何其他模块中导入`CoreModule`。

考虑将`CoreModule`作为一个纯服务模块，不包含任何声明。

好哇！这是一个很好的建议。特别值得注意的是最后一行：

考虑将 CoreModule 变成一个纯服务模块，没有声明。

所以，我们已经有了`CoreModule`，这是一个好消息，但我们希望将其变成一个*纯服务模块，没有声明*。我们还*只在根 AppModule 中导入 CoreModule。永远不要在任何其他模块中导入 CoreModule。*然后，我们可以创建一个新的`SharedModule`，只提供*……**在应用程序中到处使用的组件、指令和管道*。

让我们创建`app/modules/shared/shared.module.ts`，如下所示：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 

// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';

// app
import { PIPES } from './pipes';

@NgModule({
  imports: [
    NativeScriptModule
  ],
  declarations: [
    ...PIPES
  ],
  exports: [
    NativeScriptModule,
    ...PIPES
  ],
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class SharedModule {}
```

对于`PIPES`，我们只是将 pipes 目录从`app/modules/core`移动到`app/modules/shared`文件夹中。现在，`SharedModule`是我们可以自由导入到需要任何管道或未来共享组件/指令的多个不同模块中的一个。它不会像这个建议所提到的那样定义任何服务提供者：

出于之前解释的原因，`SharedModule`不应该有提供者，也不应该有任何导入或重新导出的模块有提供者。

然后，我们可以调整`CoreModule`（位于`app/modules/core/core.module.ts`中）如下，使其成为一个纯服务模块，没有声明：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module'; 
import { NativeScriptFormsModule } from 'nativescript-angular/forms'; 
import {NativeScriptHttpModule } from 'nativescript-angular/http';
// angular
import { NgModule, Optional, SkipSelf } from '@angular/core';

// app
import { PROVIDERS } from './services';

const MODULES: any[] = [
  NativeScriptModule,
  NativeScriptFormsModule,
  NativeScriptHttpModule
];

@NgModule({
  imports: [
    ...MODULES
  ],
  providers: [
    ...PROVIDERS
  ],
  exports: [
    ...MODULES
  ]
})
export class CoreModule {
  constructor (
    @Optional() @SkipSelf() parentModule: CoreModule) {
    if (parentModule) {
      throw new Error(
        'CoreModule is already loaded. Import it in the AppModule only');
    }
  }
}
```

这个模块现在只定义了提供者，包括`AuthService`、`DatabaseService`、`DialogService`和`LogService`，这些都是我们在书中之前创建的，并且我们希望确保它们是真正的单例，无论它们是在惰性加载的模块中使用还是不使用。

为什么我们使用`...PROVIDERS`扩展符号而不是直接分配集合？

出于可扩展性的原因。将来，如果我们需要添加额外的提供者或覆盖提供者，我们只需简单地在模块中添加到集合中即可。导入和导出也是一样。

我们还利用这个机会导入一些额外的模块，以确保它们也在整个应用程序中全局使用。`NativeScriptModule`、`NativeScriptFormsModule`和`NativeScriptHttpModule`都是重要的模块，可以在 Angular 的各种提供程序中覆盖某些 Web API，以增强我们的应用程序使用本机 API。例如，应用程序将使用本机 HTTP API 而不是`XMLHttpRequest`（这是一个 Web API），从而提高 iOS 和 Android 的网络性能。我们还确保将它们导出，这样我们的根模块就不再需要导入它们，而是只需导入`CoreModule`。

最后，我们定义了一个构造函数，以帮助我们在将来防止意外地将`CoreModule`导入到其他懒加载模块中。

我们还不知道`PlayerModule`提供的`PlayerService`是否会被`RecorderModule`所需，后者也将被懒加载。如果将来出现这种情况，我们还可以将`PlayerService`重构为`CoreModule`，以确保它是整个应用程序中共享的真正单例。现在，我们将它留在`PlayerModule`中。

现在让我们根据我们所做的工作做最后的调整，来收紧一切。

`app/modules/player/player.module.ts`文件现在应该是这样的：

```ts
// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';

// app
import { SharedModule } from '../shared/shared.module';
import { COMPONENTS } from './components';
import { PROVIDERS } from './services';

@NgModule({
  imports: [ SharedModule ],
  providers: [ ...PROVIDERS ],
  declarations: [ ...COMPONENTS ],
  exports: [
    SharedModule,
    ...COMPONENTS
  ],
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class PlayerModule { }
```

`app/modules/recorder/recorder.module.ts`文件现在应该是这样的：

```ts
// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';

// app
import { SharedModule } from '../shared/shared.module';
import { PROVIDERS } from './services';

@NgModule({
 imports: [ SharedModule ],
 providers: [ ...PROVIDERS ],
 schemas: [ NO_ERRORS_SCHEMA ]
})
export class RecorderModule { }
```

请注意，我们现在导入`SharedModule`而不是`CoreModule`。这使我们能够通过导入`SharedModule`在整个应用程序中共享指令、组件和管道（基本上是模块声明部分中的任何内容）。

我们的根`AppModule`在`app/app.module.ts`中保持不变：

```ts
// angular
import { NgModule } from '@angular/core';

// app
import { CoreModule } from './modules/core/core.module';
import { AppRoutingModule } from './app.routing';
import { AppComponent } from './app.component';

@NgModule({
  imports: [
    CoreModule,
    AppRoutingModule
  ],
  declarations: [ AppComponent ],
  bootstrap: [ AppComponent ]
})
export class AppModule { }
```

任何模块（懒加载或非懒加载）仍然可以注入`CoreModule`提供的任何服务，因为根`AppModule`现在导入了`CoreModule`。这允许 Angular 的根注入器仅构建一次由`CoreModule`提供的服务。然后，每当这些服务被注入到任何地方（*无论是在懒加载模块还是非懒加载模块中*），Angular 都会首先询问父注入器（在懒加载模块的情况下，它将是子注入器）是否有该服务，如果在那里找不到，它将询问下一个父注入器，一直到根注入器，最终找到这些单例提供的地方。

嗯，我们在这个沙漠小镇度过了美好的时光。让我们沿着高速公路前往超安全的 51 区，那里的模块可以被锁定多年，除非提供适当的授权。

# 为 RecorderModule 创建 AuthGuard

我们应用的一个要求是，录制功能应该被锁定并且在用户认证之前无法访问。这为我们提供了有用户基础的能力，并且如果需要的话，未来可能引入付费功能。

Angular 提供了在我们的路由上插入守卫的能力，这些守卫只会在特定条件下激活。这正是我们需要实现这个功能要求的，因为我们已经将`'/record'`路由隔离为懒加载`RecorderModule`，其中包含所有的录制功能。我们只希望在用户认证时才允许访问`'/record'`路由。

让我们在一个新的文件夹中创建`app/guards/auth-guard.service.ts`，以便扩展性，因为我们可能会增长并在这里创建其他守卫。

```ts
import { Injectable } from '@angular/core';
import { Route, CanActivate, CanLoad } from '@angular/router';
import { AuthService } from '../modules/core/services/auth.service';

@Injectable()
export class AuthGuard implements CanActivate, CanLoad {

  constructor(private authService: AuthService) { }

  canActivate(): Promise<boolean> {
    return new Promise((resolve, reject) => {
      if (this._isAuth()) {
        resolve(true);
      } else {
        // login sequence to continue prompting
        let promptSequence = (usernameAttempt?: string) => {
          this.authService.promptLogin(
            'Authenticate to record.',
            usernameAttempt
          ).then(() => {
            resolve(true); 
          }, (usernameAttempt) => {
            if (usernameAttempt === false) {
              // user canceled prompt
              resolve(false);
            } else {
              // initiate sequence again
              promptSequence(usernameAttempt);
            }
          });
        };
        // start login prompt sequence
        // require auth before activating
        promptSequence();
      }
    });
  }

  canLoad(route: Route): Promise<boolean> {
    // reuse same logic to activate
    return this.canActivate();
  }

  private _isAuth(): boolean {
    // just get the latest value from our BehaviorSubject
    return this.authService.authenticated$.getValue();
  }
}
```

我们能够利用`AuthService`的`BehaviorSubject`来使用`this.authService.authenticated$.getValue()`来获取最新的值，以确定认证状态。我们使用这个值来立即通过`canActivate`钩子激活路由（或者通过`canLoad`钩子加载模块）如果用户已经认证。否则，我们通过服务的方法显示登录提示，但这次我们将其包装在重新提示序列中，直到成功认证或者用户取消提示为止。

对于这本书，我们不会连接到任何后端服务来进行真正的服务提供商认证。我们会把这部分留给你在你自己的应用中完成。我们只会将你在登录提示中输入的电子邮件和密码持久化为有效用户，经过非常简单的输入验证。

请注意，`AuthGuard`是一个可注入的服务，就像其他服务一样，所以我们需要确保它被添加到`AppRoutingModule`的提供者元数据中。现在我们可以使用以下突出显示的修改来保护我们的路由，以在`app/app.routing.ts`中使用它：

```ts
...
import { AuthGuard } from './guards/auth-guard.service';

const routes: Routes = [
  ...
  {
    path: 'record',
    loadChildren: 
      './modules/recorder/recorder.module#RecorderModule',
    canLoad: [AuthGuard]
  }
];

@NgModule({
  ...
  providers: [
    AuthGuard,
    ...
  ],
  ...
})
export class AppRoutingModule { }
```

为了尝试这个功能，我们需要为我们的`RecorderModule`添加子路由，因为我们还没有这样做。打开`app/modules/recorder/recorder.module.ts`并添加以下突出显示的部分：

```ts
// nativescript
import { NativeScriptModule } from 'nativescript-angular/nativescript.module';
import { NativeScriptRouterModule } from 'nativescript-angular/router';

// angular
import { NgModule, NO_ERRORS_SCHEMA } from '@angular/core';
import { Routes } from '@angular/router';

// app
import { SharedModule } from '../shared/shared.module';
import { PROVIDERS } from './services';
import { RecordComponent } from './components/record.component';

const COMPONENTS: any[] = [
 RecordComponent
]

const routes: Routes = [
 {
 path: '',
 component: RecordComponent
 }
];

@NgModule({
  imports: [
    SharedModule,
    NativeScriptRouterModule.forChild(routes)
  ],
  declarations: [ ...COMPONENTS ],
  providers: [ ...PROVIDERS ],
  schemas: [ NO_ERRORS_SCHEMA ]
})
export class RecorderModule { }
```

现在我们有了一个合适的子路由配置，当用户导航到`'/record'`路径时，将显示单个`RecordComponent`。我们不会展示`RecordComponent`的细节，因为你可以参考书籍仓库中的第五章，*路由和懒加载*分支。然而，目前在`app/modules/recorder/components/record.component.html`中，它只是一个存根组件，只显示一个简单的标签，所以我们可以试一下。

最后，我们需要一个按钮，可以路由到我们的`'/record'`路径。如果我们回顾一下我们最初的草图，我们想要一个 Record 按钮显示在`ActionBar`的右上角，所以现在让我们实现它。

打开`app/modules/mixer/components/mixer.component.html`并添加以下内容：

```ts
<ActionBar title="TNSStudio" class="action-bar">
  <ActionItem nsRouterLink="/record" ios.position="right">
 <Button text="Record" class="action-item"></Button>
 </ActionItem>
</ActionBar>
<GridLayout rows="*, 100" columns="*" class="page">
  <track-list row="0" col="0"></track-list>
  <player-controls row="1" col="0"></player-controls>
</GridLayout>
```

现在，如果我们在 iOS 模拟器中运行这个程序，我们会注意到我们在`ActionBar`中的 Record 按钮没有任何作用！这是因为`MixerModule`只导入了以下内容：

```ts
@NgModule({
  imports: [
    PlayerModule,
    NativeScriptRouterModule.forChild(routes)
  ],
  ...
})
export class MixerModule { }
```

`NativeScriptRouterModule.forChild(routes)`方法只是配置路由，但不会使各种路由指令，如`nsRouterLink`，可用于我们的组件。

既然你之前学到了`SharedModule`应该用来声明你想要在你的模块中共享的各种指令、组件和管道（无论是懒加载还是不懒加载），这是一个很好的机会来利用它。

打开`app/modules/shared/shared.module.ts`并进行以下突出显示的修改：

```ts
...
import { NativeScriptRouterModule } from 'nativescript-angular/router'; 
...

@NgModule({
  imports: [
    NativeScriptModule, 
    NativeScriptRouterModule
  ],
  declarations: [
    ...PIPES
  ],
  exports: [
    NativeScriptModule,
    NativeScriptRouterModule,
    ...PIPES
  ],
  schemas: [NO_ERRORS_SCHEMA]
})
export class SharedModule { }
```

现在，回到`MixerModule`，我们可以调整导入以使用`SharedModule`：

```ts
...
import { SharedModule } from '../shared/shared.module'; 
@NgModule({
  imports: [
    PlayerModule,
    SharedModule,
    NativeScriptRouterModule.forChild(routes)
  ],
  ...
})
export class MixerModule { }
```

这确保了通过利用我们应用程序范围的`SharedModule`，`MixerModule`中现在包含并可用于使用的`NativeScriptRouterModule`暴露的所有指令。

再次运行我们的应用程序，现在当我们点击`ActionBar`中的 Record 按钮时，我们会看到登录提示。如果我们输入一个格式正确的电子邮件地址和任何密码，它将保留这些详细信息，登录我们，并在 iOS 上显示`RecordComponent`如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00022.jpeg)

您可能会注意到一些非常有趣的事情。`ActionBar`从我们通过 CSS 分配的背景颜色和按钮颜色现在显示默认的蓝色。这是因为`RecordComponent`没有定义`ActionBar`；因此，它会恢复到一个具有默认返回按钮的默认样式的`ActionBar`，该按钮将采用刚刚导航离开的页面的标题。'/record'路由还使用了`page-router-outlet`的能力将组件推送到移动导航栈上。`RecordComponent`被动画化显示，同时允许用户选择左上角按钮进行导航返回（将导航历史后退一步）。

要修复`ActionBar`，让我们在`RecordComponent`视图中添加`ActionBar`和自定义的`NavigationButton`（一个模拟移动设备默认返回导航按钮的`NativeScript`视图组件）。我们可以对`app/modules/record/components/record.component.html`进行调整：

```ts
<ActionBar title="Record" class="action-bar">
  <NavigationButton text="Back"
    android.systemIcon="ic_menu_back">
  </NavigationButton>
</ActionBar>
<StackLayout class="p-20">
  <Label text="TODO: Record" class="h1 text-center"></Label>
</StackLayout>
```

现在，这看起来好多了。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00023.jpeg)

如果我们在 Android 上运行这个，并使用任何电子邮件/密码组合登录以保持用户登录，它将显示相同的`RecordComponent`视图；然而，您会注意到另一个有趣的细节。我们已经设置 Android 显示一个标准的返回箭头系统图标作为`NavigationButton`，但是当点击该箭头时，它不会做任何事情。Android 的默认行为依赖于设备旁边的物理硬件返回按钮，靠近主页按钮。然而，我们可以通过向`NavigationButton`添加一个点击事件来提供一致的体验，这样 iOS 和 Android 都会对点击返回按钮做出相同的反应。对模板进行以下修改：

```ts
<ActionBar title="Record" icon="" class="action-bar">
  <NavigationButton (tap)="back()" text="Back" 
    android.systemIcon="ic_menu_back">
  </NavigationButton>
</ActionBar>
<StackLayout class="p-20">
  <Label text="TODO: Record" class="h1 text-center"></Label>
</StackLayout>
```

然后，我们可以使用 Angular 的`RouterExtensions`服务在`app/modules/recorder/components/record.component.ts`中实现`back()`方法。

```ts
// angular
import { Component } from '@angular/core';
import { RouterExtensions } from 'nativescript-angular/router';

@Component({
 moduleId: module.id,
 selector: 'record',
 templateUrl: 'record.component.html'
})
export class RecordComponent { 

  constructor(private router: RouterExtensions) { }

  public back() {
    this.router.back();
  }
}
```

现在，除了硬件返回按钮之外，Android 的返回按钮也可以被点击以进行导航。iOS 简单地忽略了点击事件处理程序，因为它使用了`NavigationButton`的默认本机行为。相当不错。以下是`RecordComponent`在 Android 上的外观：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00024.jpeg)

我们将在接下来的章节中实现一个不错的录音视图。

现在，我们肯定是在 66 号公路上巡航！

我们已经实现了延迟加载路由，提供了`AuthGuard`来保护我们应用的录音功能不被未经授权的使用，并在这个过程中学到了很多。*然而，我们刚意识到在游戏的最后阶段我们缺少了一个非常重要的功能*。我们需要一种方法来随着时间的推移处理几种不同的混音。默认情况下，我们的应用可能会启动最后打开的混音，但我们希望创建新的混音（让我们称之为**作品**）并将单独的音轨的全新混音记录为独立的作品。我们需要一个新的路由来显示这些作品，我们可以适当地命名，这样我们就可以来回跳转并处理不同的素材。

# 处理晚期功能需求 - 管理作品

现在是时候处理 66 号公路上的意外交通了。我们遇到了一个晚期的功能需求，意识到我们需要一种管理任意数量不同混音的方法，这样我们就可以随着时间的推移处理不同的素材。我们可以将每个混音称为音轨的作品。

好消息是，我们已经花了相当多的时间来设计一个可扩展的架构，我们即将收获我们的劳动成果。现在对晚期功能需求的回应变得像在附近愉快地散步一样。让我们通过花点时间来处理这个新功能，展示我们应用架构的优势。

让我们首先为我们将创建的新`MixListComponent`定义一个新的路由。打开`app/modules/mixer/mixer.module.ts`并进行以下突出显示的修改：

```ts
...
import { MixListComponent } from './components/mix-list.component';
import { PROVIDERS } from './services';

const COMPONENTS: any[] = [
  BaseComponent,
  MixerComponent,
  MixListComponent
]

const routes: Routes = [
  {
    path: '',
    component: BaseComponent,
    children: [
      {
 path: 'home',
 component: MixListComponent
 },
 {
 path: ':id',
 component: MixerComponent
 }
    ]
  }
];

@NgModule({
   ...
   providers: [
 ...PROVIDERS
 ]
})
export class MixerModule { }
```

我们正在改变最初的策略，不再将`MixerComponent`作为主页起始页面呈现，而是将在稍后创建一个新的`MixListComponent`来代表`'home'`起始页面，这将是我们正在处理的所有作品的列表。我们仍然可以让`MixListComponent`在应用启动时自动选择最后选择的作品，以方便以后使用。我们现在已经将`MixerComponent`定义为带参数的路由，因为它将始终代表我们的一个工作作品，由`':id'`参数路由标识，这将解析为类似`'/mixer/1'`的路由。我们还导入了我们将在稍后创建的`PROVIDERS`。

让我们修改`CoreModule`提供的`DatabaseService`，以帮助为我们的新数据需求提供一个恒定的持久化键。我们将希望通过这个恒定的键名持久保存用户创建的作品。打开`app/modules/core/services/database.service.ts`并进行以下高亮修改：

```ts
...
interface IKeys {
  currentUser: string;
  compositions: string;
}

@Injectable()
export class DatabaseService {

  public static KEYS: IKeys = {
    currentUser: 'current-user',
    compositions: 'compositions'
  };
...
```

让我们还创建一个新的数据模型来表示我们的作品。创建`app/modules/shared/models/composition.model.ts`：

```ts
import { ITrack } from './track.model';

export interface IComposition {
  id: number;
  name: string;
  created: number;
  tracks: Array<ITrack>;
  order: number;
}
export class CompositionModel implements IComposition {
  public id: number;
  public name: string;
  public created: number;
  public tracks: Array<ITrack> = [];
  public order: number;

  constructor(model?: any) {
    if (model) {
      for (let key in model) {
        this[key] = model[key];
      }
    }
    if (!this.created) this.created = Date.now();
    // if not assigned, just assign a random id
    if (!this.id)
      this.id = Math.floor(Math.random() * 100000);
  }
}
```

然后，坚持我们的惯例，打开`app/modules/shared/models/index.ts`并重新导出这个新模型：

```ts
export * from './composition.model';
export * from './track.model';
```

现在我们可以在一个新的数据服务中使用这个新模型和数据库键来构建这个新功能。创建`app/modules/mixer/services/mixer.service.ts`：

```ts
// angular
import { Injectable } from '@angular/core';

// app
import { ITrack, IComposition, CompositionModel } from '../../shared/models';
import { DatabaseService } from '../../core/services/database.service';
import { DialogService } from '../../core/services/dialog.service';

@Injectable()
export class MixerService {

  public list: Array<IComposition>;

  constructor(
    private databaseService: DatabaseService,
    private dialogService: DialogService
  ) {
    // restore with saved compositions or demo list
    this.list = this._savedCompositions() || 
      this._demoComposition();
  } 

  public add() {
    this.dialogService.prompt('Composition name:')
      .then((value) => {
        if (value.result) {
          let composition = new CompositionModel({
            id: this.list.length + 1,
            name: value.text,
            order: this.list.length // next one in line
          });
          this.list.push(composition);
          // persist changes
          this._saveList();
        }
      });
  }

  public edit(composition: IComposition) {
    this.dialogService.prompt('Edit name:', composition.name)
      .then((value) => {
        if (value.result) {
          for (let comp of this.list) {
            if (comp.id === composition.id) {
              comp.name = value.text;
              break;
            }
          }
          // re-assignment triggers view binding change
          // only needed with default change detection
          // when object prop changes in collection
          // NOTE: we will use Observables in ngrx chapter
          this.list = [...this.list];
          // persist changes
          this._saveList();
        }
      });
  }

  private _savedCompositions(): any {
    return this.databaseService
      .getItem(DatabaseService.KEYS.compositions);
  }

  private _saveList() {
    this.databaseService
      .setItem(DatabaseService.KEYS.compositions, this.list);
  }

  private _demoComposition(): Array<IComposition> {
    // Starter composition to demo on first launch
    return [
      {
        id: 1,
        name: 'Demo',
        created: Date.now(),
        order: 0,
        tracks: [
          {
            id: 1,
            name: 'Guitar',
            order: 0
          },
          {
            id: 2,
            name: 'Vocals',
            order: 1
          }
        ]
      }
    ]
  }
}
```

现在我们有了一个服务，它将提供一个列表来绑定我们的视图，以显示用户保存的作品。它还提供了一种添加和编辑作品以及在第一次应用启动时为良好的首次用户体验播种演示作品的方法（*我们稍后会为演示添加实际的曲目*）。

按照我们的惯例，让我们也添加`app/modules/mixer/services/index.ts`，如下所示，我们刚才在`MixerModule`中导入过：

```ts
import { MixerService } from './mixer.service';

export const PROVIDERS: any[] = [
  MixerService
];

export * from './mixer.service';
```

现在让我们创建`app/modules/mixer/components/mix-list.component.ts`来使用和投影我们的新数据服务：

```ts
// angular
import { Component } from '@angular/core';

// app
import { MixerService } from '../services/mixer.service';

@Component({
  moduleId: module.id,
  selector: 'mix-list',
  templateUrl: 'mix-list.component.html'
})
export class MixListComponent {

  constructor(public mixerService: MixerService) { } 
}
```

对于视图模板，`app/modules/mixer/components/mix-list.component.html`：

```ts
<ActionBar title="Compositions" class="action-bar">
  <ActionItem (tap)="mixerService.add()" 
    ios.position="right">
    <Button text="New" class="action-item"></Button>
  </ActionItem>
</ActionBar>
<ListView [items]="mixerService.list | orderBy: 'order'" 
  class="list-group">
  <ng-template let-composition="item">
    <GridLayout rows="auto" columns="100,*,auto" 
      class="list-group-item">
      <Button text="Edit" row="0" col="0" 
        (tap)="mixerService.edit(composition)"></Button>
      <Label [text]="composition.name"
        [nsRouterLink]="['/mixer', composition.id]"
        class="h2" row="0" col="1"></Label>
      <Label [text]="composition.tracks.length" 
        class="text-right" row="0" col="2"></Label>
    </GridLayout>
  </ng-template>
</ListView>
```

这将把我们的`MixerService`用户保存的作品列表呈现到视图中，并且当我们首次启动应用时，它将被预先加载一个样本**演示**作品，其中包含两个录音，以便用户可以玩耍。现在 iOS 首次启动的情况如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00025.jpeg)

我们可以创建新的作品并编辑现有作品的名称。我们还可以点击作品的名称来查看`MixerComponent`；然而，我们需要调整组件来抓取路由`':id'`参数并将其视图连接到所选的作品。打开`app/modules/mixer/components/mixer.component.ts`并添加高亮部分：

```ts
// angular
import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Subscription } from 'rxjs/Subscription';

// app
import { MixerService } from '../services/mixer.service';
import { CompositionModel } from '../../shared/models';

@Component({
 moduleId: module.id,
 selector: 'mixer',
 templateUrl: 'mixer.component.html'
})
export class MixerComponent implements OnInit, OnDestroy {

  public composition: CompositionModel; 
 private _sub: Subscription;

 constructor(
 private route: ActivatedRoute,
 private mixerService: MixerService
 ) { } 

 ngOnInit() {
 this._sub = this.route.params.subscribe(params => {
 for (let comp of this.mixerService.list) {
 if (comp.id === +params['id']) {
 this.composition = comp;
 break;
 }
 }
 });
 } 

 ngOnDestroy() {
 this._sub.unsubscribe();
 }
}
```

我们可以注入 Angular 的 `ActivatedRoute` 来订阅路由的参数，这样我们就可以访问 `id`。因为它默认会以字符串形式传入，所以我们使用 `+params['id']` 将其转换为数字，以便在服务列表中定位到该组合。我们为选定的 `composition` 分配一个本地引用，这样我们就可以在视图中绑定它。与此同时，我们还将在 `ActionBar` 中添加一个名为 `List` 的按钮，用于返回到我们的组合（*稍后，我们将实现字体图标来显示在它们的位置*）。打开 `app/modules/mixer/components/mixer.component.html` 并进行以下突出显示的修改：

```ts
<ActionBar [title]="composition.name" class="action-bar">
  <ActionItem nsRouterLink="/mixer/home">
 <Button text="List" class="action-item"></Button>
 </ActionItem>
  <ActionItem nsRouterLink="/record" ios.position="right">
    <Button text="Record" class="action-item"></Button>
  </ActionItem>
</ActionBar>
<GridLayout rows="*, 100" columns="*" class="page">
  <track-list [tracks]="composition.tracks" row="0" col="0"></track-list>
  <player-controls row="1" col="0"></player-controls>
</GridLayout>
```

这样我们就可以在 `ActionBar` 的标题中显示所选组合的名称，并将其轨道传递给 `track-list`。我们需要向 `track-list` 添加 `Input`，以便它呈现组合的轨道，而不是它现在绑定的虚拟数据。让我们打开 `app/modules/player/components/track-list/track-list.component.ts` 并添加一个 `Input`：

```ts
...
export class TrackListComponent {

 @Input() tracks: Array<ITrack>;

 ...
}
```

以前，`TrackListComponent` 视图绑定到了 `playerService.tracks`，所以让我们调整组件的视图模板，使其绑定到我们的新 `Input`，这将代表用户实际选择的组合中的轨道**：**

```ts
<ListView [items]="tracks | orderBy: 'order'" class="list-group">
  <template let-track="item">
    <GridLayout rows="auto" columns="100,*,100" class="list-group-item">
      <Button text="Record" (tap)="record(track)" row="0" col="0" class="c-ruby"></Button>
      <Label [text]="track.name" row="0" col="1" class="h2"></Label>
      <Switch [checked]="track.solo" row="0" col="2" class="switch"></Switch>
    </GridLayout>
  </template>
</ListView>
```

现在我们的应用程序中有以下顺序来满足这个晚期功能需求，我们只需在这里的几页材料中就完成了：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00026.jpeg)

它在 Android 上的工作方式完全相同，同时保留其独特的本机特性。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00027.jpeg)

然而，您可能会注意到，Android 上的 `ActionBar` 默认为所有 `ActionItem` 都在右侧。我们想要向您展示的最后一个技巧是平台特定的视图模板的能力。哦，不要担心那些丑陋的 Android 按钮；我们稍后会为它们集成字体图标。

在您认为合适的地方创建平台特定的视图模板。这样做将帮助您为每个平台调整视图，必要时使其高度可维护。

让我们创建 `app/modules/mixer/components/action-bar/action-bar.component.ts`：

```ts
// angular
import { Component, Input } from '@angular/core';

@Component({
  moduleId: module.id,
  selector: 'action-bar',
  templateUrl: 'action-bar.component.html'
})
export class ActionBarComponent {

  @Input() title: string;
}
```

然后您可以创建一个特定于 iOS 的视图模板：`app/modules/mixer/components/action-bar/action-bar.component.ios.html`：

```ts
<ActionBar [title]="title" class="action-bar">
  <ActionItem nsRouterLink="/mixer/home">
    <Button text="List" class="action-item"></Button>
  </ActionItem>
  <ActionItem nsRouterLink="/record" ios.position="right">
    <Button text="Record" class="action-item"></Button>
  </ActionItem>
</ActionBar>
```

以及一个特定于 Android 的视图模板：`app/modules/mixer/components/action-bar/action-bar.component.android.html`：

```ts
<ActionBar class="action-bar">
  <GridLayout rows="auto" columns="auto,*,auto" class="action-bar">
    <Button text="List" nsRouterLink="/mixer/home" class="action-item" row="0" col="0"></Button>
    <Label [text]="title" class="action-bar-title text-center" row="0" col="1"></Label>
    <Button text="Record" nsRouterLink="/record" class="action-item" row="0" col="2"></Button>
  </GridLayout>
</ActionBar>
```

然后我们可以在 `app/modules/mixer/components/mixer.component.html` 中使用它：

```ts
<action-bar [title]="composition.name"></action-bar>
<GridLayout rows="*, 100" columns="*" class="page">
  <track-list [tracks]="composition.tracks" row="0" col="0"></track-list>
  <player-controls row="1" col="0"></player-controls>
</GridLayout>
```

只需确保将其添加到`app/modules/mixer/mixer.module.ts`中的`MixerModule`的`COMPONENTS`中：

```ts
...
import { ActionBarComponent } from './components/action-bar/action-bar.component';
...

const COMPONENTS: any[] = [
  ActionBarComponent,
  BaseComponent,
  MixerComponent,
  MixListComponent
];
...
```

看这里！

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ns-ng-mobi-dev/img/00028.jpeg)

# 摘要

我们已经到达了 66 号公路的终点，希望您和我们一样感到兴奋。本章介绍了一些有趣的 Angular 概念，包括使用惰性加载模块进行路由配置，以保持应用程序启动时间快；使用本机文件处理 API 构建自定义模块加载器；将`router-outlet`的灵活性与 NativeScript 的`page-router-outlet`相结合；掌握并理解惰性加载模块的单例服务；保护依赖授权访问的路由；以及处理晚期功能需求，展示我们出色可扩展的应用程序设计。

本章将总结我们应用程序的一般可用性流程，此时，我们已经准备好进入我们应用程序的核心竞争力：**通过 iOS 和 Android 丰富的本机 API 处理音频**。

在深入讨论之前，在下一章中，我们将花一点时间来检查 NativeScript 的各种`tns`命令行参数，以运行我们的应用程序，以便全面了解我们现在可以使用的工具。
