# TypeScript 高级编程项目（四）

> 原文：[`zh.annas-archive.org/md5/412B7599C0C63C063566D3F1FFD02ABF`](https://zh.annas-archive.org/md5/412B7599C0C63C063566D3F1FFD02ABF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 Firebase 进行 Angular 基于云的地图

在过去的几章中，我们花了相当多的时间编写我们自己的后端系统，以返回信息给客户端。在过去的几年里，有一种趋势是使用第三方云系统。云系统可以帮助降低编写应用程序的成本，因为其他公司提供了我们需要使用的所有基础设施，并负责测试、升级等。在本章中，我们将研究如何使用必应地图团队和 Firebase 的云基础设施来提供数据存储。

本章将涵盖以下主题：

+   注册必应地图

+   计费云功能的含义

+   注册 Firebase

+   添加地图组件

+   使用地图搜索功能

+   使用`EventEmitter`来通知父组件子组件事件

+   响应地图事件以添加和删除自己的兴趣点

+   在地图上叠加搜索结果

+   整理事件处理程序

+   将数据保存到 Cloud Firestore

+   配置 Cloud Firestore 身份验证

# 技术要求

完成的项目可以从[`github.com/PacktPublishing/Advanced-TypeScript-3-Programming-Projects/tree/master/Chapter07`](https://github.com/PacktPublishing/Advanced-TypeScript-3-Programming-Projects/tree/master/Chapter07)下载。

下载项目后，您将需要使用`npm install`命令安装软件包要求。

# 现代应用程序和转向云服务

在整本书中，我们一直在专注于编写应用程序，其中我们控制应用程序运行的基础设施以及数据的物理存储位置。在过去的几年里，趋势是摆脱这种类型的应用程序，转向其他公司通过所谓的**基于云的服务**提供这种基础设施的模式。*云服务*已经成为一个用来描述使用其他公司的按需服务的总称营销术语，依赖于它们提供应用程序功能、安全性、扩展性、备份功能等。其背后的想法是，我们可以通过让其他人为我们处理这些功能来减少资本成本，从而使我们能够编写利用这些功能的应用程序。

在本章中，我们将研究如何使用微软和谷歌的基于云的服务，因此我们将研究注册这些服务的过程，使用它们的含义，以及如何在我们最终的 Angular 应用程序中使用它们。

# 项目概述

对于我们最后的 Angular 应用程序，我们将使用必应地图服务来展示我们日常使用的地图类型，以搜索位置。我们将进一步使用微软的本地洞察服务来搜索当前可见地图区域内的特定业务类型。这是我在为这本书制定计划时最激动人心的两个应用程序之一，因为我对基于地图的系统情有独钟。

除了显示地图，我们还可以通过直接点击地图上的点来选择地图上的兴趣点。这些点将由彩色图钉表示。我们将保存这些点的位置和名称，以及它们在谷歌的基于云的数据库中。

这个应用程序应该需要大约一个小时来完成，只要你在 GitHub 上的代码旁边工作。

在本章中，我们将不再提供如何使用`npm`添加软件包，或者如何创建 Angular 应用程序、组件等的详细信息，因为到这个时候你应该已经熟悉如何做这些了。

完成后，应用程序应该看起来像这样（也许不要放大到纽卡斯尔）：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/a0f765d2-db52-41cc-88eb-8488d2516510.png)

# 开始使用 Angular 中的必应地图

这是我们最后一个 Angular 应用程序，所以我们将以与之前章节中创建应用程序相同的方式开始。同样，我们将使用 Bootstrap，而不是 Angular Material。

我们在本章中要专注的包如下：

+   `bootstrap`

+   `bingmaps`

+   `firebase`

+   `guid-typescript`

由于我们将把我们的代码连接到基于云的服务，我们首先必须注册它们。在本节中，我们将看看我们需要做什么来注册。

# 注册必应地图

如果我们想要使用必应地图，我们必须注册必应地图服务。导航到[`www.bingmapsportal.com`](https://www.bingmapsportal.com)并单击“登录”按钮。这需要一个 Windows 帐户，所以如果你没有一个，你需要设置一个。现在，我们假设你有一个 Windows 帐户可用：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/082d18cf-f170-4e4b-b7e7-0efef3da47b2.png)

当我们登录时，我们需要创建一个密钥，我们的应用程序将使用它来向必应地图服务标识自己，以便他们知道我们是谁，并可以跟踪我们的地图使用情况。从“我的帐户”选项中，选择“我的密钥”：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/871b25e0-38ce-4aef-a2e5-975fe4c172d0.png)

当密钥屏幕出现时，你会看到一个名为“点击此处创建新密钥”的链接。点击链接将显示以下屏幕：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/c03c1b67-b41c-45c7-977e-d4058f3f05ff.png)

这个屏幕上的大部分信息都相当容易理解。应用程序名称用于在我们有多个密钥并且需要搜索它们时使用。URL 不需要设置，但如果我部署到不同的 Web 应用程序，我喜欢这样做。这是一个方便的方式来记住哪个密钥与哪个应用程序相关联。由于我们不打算使用付费企业服务，我们唯一可用的密钥类型是基本的。

应用程序类型可能是这里最重要的字段，从我们的角度来看。我们可以选择多种应用程序类型，每种类型都有关于它可以接受的交易数量的限制。我们将坚持使用 Dev/Test，它限制我们在一年的时间内累计的可计费交易次数为 125,000 次。

当我们在本章中使用本地洞察代码时，这将生成可计费的交易。如果你不想承担任何费用的风险，我建议你禁用执行此搜索的代码。

当我们点击“创建”时，我们的地图密钥被创建，并且可以通过点击表中出现的“显示密钥”或“复制密钥”链接来获取。现在我们已经设置好了地图密钥所需的一切，让我们继续注册数据库。

# 注册 Firebase

Firebase 需要一个 Google 帐户。假设我们有一个可用的 Google 帐户，我们可以在[`console.firebase.google.com/`](https://console.firebase.google.com/)上访问 Firebase 的功能。当出现这个屏幕时，点击“添加项目”按钮开始添加 Firebase 支持的过程：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/1d9dd8ac-8931-4642-88ce-77e2c20ff855.png)

为项目选择一个有意义的名称。在我们创建项目之前，我们应该阅读使用 Firebase 的条款和条件，并在同意时勾选复选框。请注意，如果我们选择共享 Google Analytics 的使用统计数据，我们应该阅读适当的条款和条件，并勾选控制器-控制器条款复选框：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/ae904ea1-6b3a-4983-8162-a7d375eb5e19.png)

点击“创建项目”后，我们现在可以访问 Firebase 项目。虽然 Firebase 作为云服务提供商不仅仅是一个数据库，还提供存储、托管等功能，但我们只是使用数据库选项。当我们点击数据库链接时，会出现 Cloud Firestore 屏幕，我们需要点击“创建数据库”来开始创建数据库的过程：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/f550f6f4-904d-429c-b822-81af8bd6ac94.png)

每当我在本章中提到 Firebase 时，我是在简单地说这是 Firebase 云平台的 Firestore 功能。

在创建数据库时，我们需要选择要应用于我们的数据库的安全级别。我们在这里有两个选项。我们可以从数据库被锁定开始，以便禁用读写。然后，通过编写数据库将检查以确定是否允许写入的规则来启用对数据库的访问。

然而，为了我们的目的，我们将以测试模式开始，这允许对数据库进行无限读写：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/78fe0e8c-0642-4993-a5c7-305d5fdbd2d7.png)

与 Bing 地图类似，Firebase 有使用限制和成本影响。我们正在创建一个 Spark 计划数据存储，这是免费的 Firebase 版本。这个版本有硬性限制，比如每月只能存储 1GB 的数据，每天可以读取 50000 次，每天可以写入 20000 次。有关定价和限制的详细信息，请阅读[`firebase.google.com/pricing`](https://firebase.google.com/pricing)/。

一旦我们点击了启用并有一个可用的数据库，我们需要能够访问 Firebase 为我们创建的密钥和项目详细信息。要找到这些信息，请点击菜单上的项目概述链接。按钮弹出一个屏幕，显示我们需要复制到我们的项目的详细信息：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/85b83eb6-5b9f-44b1-a89c-344c0bca061e.png)

我们现在已经设置好了云基础设施，并且有了我们需要的密钥和详细信息。我们现在准备编写我们的应用程序。

# 使用 Angular 和 Firebase 创建 Bing Maps 应用程序

在过去几年中，增长最快的应用程序类型之一是地图应用程序的爆炸，无论是用于您的卫星导航系统还是在手机上运行 Google 地图。在这些应用程序的底层，有由微软或谷歌等公司开发的地图服务。我们将使用 Bing 地图服务来为我们的应用程序添加地图支持。

我们的地图应用程序有以下要求：

+   点击位置将把该位置添加为兴趣点

+   添加兴趣点时，将显示一个信息框，显示有关它的详细信息

+   再次点击兴趣点将删除它

+   兴趣点将被保存到数据库中

+   用户将能够移动兴趣点，更新数据库中的详细信息

+   在可用的情况下，将自动检索并显示商业信息

# 添加地图组件

我们将为这一步创建两个 Angular 组件，一个叫做`MappingcontainerComponent`，另一个叫做`MapViewComponent`。

我将它们分开，因为我想使用`MappingcontainerComponent`来包含引导程序基础设施，而`MapViewComponent`将只包含地图本身。如果你愿意，你可以将它们合并在一起，但是为了清晰地描述每个部分的情况，对我来说在这里创建两个组件更容易。这意味着我们需要在这两个组件之间引入一些协调，这将加强我们在第五章中介绍的`EventEmitter`行为，*Angular ToDo App with GraphQL and Apollo*。

在为这些组件添加任何内容之前，我们需要编写一些模型和服务，以提供我们的地图和数据访问所需的基础设施。

# 兴趣点

每个兴趣点都由一个图钉表示，并且可以表示为纬度和经度坐标，以及它的名称。

纬度和经度是地理术语，用于准确标识地球上的位置。纬度告诉我们某物距赤道有多远，纬度为 0。这意味着正数表示我们在赤道以北，负数表示我们在赤道以南。经度告诉我们我们距离地球的中心线有多远，按照惯例，这条线穿过伦敦的格林威治。同样，如果我们向东移动，数字是正数，而从格林威治线向西移动意味着数字将是负数。

表示此模型如下所示：

```ts
export class PinModel {
  id: string;
  lat: number;
  long: number;
  name: string;
}
```

在本节中，我们将引用图钉和兴趣点。它们都代表同一件事，因此我们将交替使用它们。

当我们创建一个实例时，我们将使用 GUID 来表示它。由于 GUID 是唯一的，我们将其用作查找兴趣点的便捷方式。这并不是我们将在数据库中存储模型的确切表示，因为此标识符旨在用于跟踪地图上的图钉，而不是用于跟踪数据库中的图钉。为此，我们将添加一个单独的模型，用于在数据库中存储模型项：

```ts
export interface PinModelData extends PinModel {
 storageId: string;
}
```

我们将其创建为接口，因为 Firebase 只希望接收数据，而不希望有围绕它的类基础设施。我们也可以将`PinModel`创建为接口，但是实例化它的语法稍微麻烦一些，这就是为什么我们选择将其创建为类的原因。

有了这些模型，我们现在准备连接到 Firebase。我们将使用官方的 Angular Firebase 库`AngularFire`，而不是直接使用 Firebase 的`npm`。这个库的`npm`引用是`@angular/fire`。

当我们设置我们的 Firebase 数据存储时，我们得到了需要创建一个唯一标识连接的设置。我们将把这些设置复制到我们的`environment.ts`和`environment.prod.ts`文件中。当我们将应用程序发布到生产环境时，Angular 会将`environment.prod.ts`重新映射到环境文件，以便我们可以拥有单独的开发和生产设置：

```ts
firebase: {
  apiKey: "AIzaSyC0MzFxTtvt6cCvmTGE94xc5INFRYlXznw",
  authDomain: "advancedtypescript3-mapapp.firebaseapp.com",
  databaseURL: "https://advancedtypescript3-mapapp.firebaseio.com",
  projectId: "advancedtypescript3-mapapp",
  storageBucket: "advancedtypescript3-mapapp.appspot.com",
  messagingSenderId: "6102469443"
}
```

通常不建议在开发和生产系统中使用相同的端点，因此您可以创建一个单独的 Firebase 实例来保存生产映射信息，并将其存储在`environment.prod.ts`中。

在`app.module`中，我们将导入`AngularFire`模块，然后在导入中引用它们。当我们引用`AngularFireModule`时，我们调用静态的`initializeApp`方法，该方法将使用`environment.firebase`设置来建立与 Firebase 的连接。

首先，`import`语句如下：

```ts
import { AngularFireModule } from '@angular/fire';
import { AngularFirestoreModule } from '@angular/fire/firestore';
import { AngularFireStorageModule } from '@angular/fire/storage';
```

接下来，我们设置 Angular 的`imports`：

```ts
imports: [
  BrowserModule,
  HttpClientModule,
  AngularFireModule.initializeApp(environment.firebase),
  AngularFireStorageModule,
  AngularFirestoreModule
],
```

对于 Firebase 的功能，有一个服务作为与数据库交互的单一实现点是有帮助的。这就是为什么我们将创建一个`FirebaseMapPinsService`：

```ts
export class FirebaseMapPinsService {
}
```

在这个类中，我们将使用`AngularFire`的一个功能，称为`AngularFirestoreCollection`。Firebase 公开了`Query`和`CollectionReference`类型，以对数据库中的基础数据执行 CRUD 操作。`AngularFirestoreCollection`将此行为封装成一个方便的流。我们将通用类型设置为`PinModelData`，以说明将保存到数据库中的数据是什么：

```ts
private pins: AngularFirestoreCollection<PinModelData>;
```

我们的服务将提供一个模型，创建一个`PinModelData`数组的可观察对象，连接到`pins`属性。我们将这一切连接在一起的方式在构造函数中，该构造函数接收`AngularFirestore`。通过传递将存储在数据库中的集合名称，`pins`集合与底层集合相关联（将数据保存为 JSON 文档）。我们的`Observable`监听集合上的`valueChanges`，如下所示：

```ts
constructor(private readonly db: AngularFirestore) { 
  this.pins = db.collection<PinModelData>('pins');
  this.model = this.pins.valueChanges();
}
```

在设计这个应用程序时，我做出的一个决定是，从 UI 中删除标记应该导致从数据库中删除相关的兴趣点。由于它没有被任何其他东西引用，我们不需要将其保留为引用数据。删除数据就像使用`doc`从数据存储中获取基础文档记录一样简单，然后将其删除：

```ts
Delete(item: PinModelData) {
  this.pins.doc(item.storageId).delete();
}
```

当用户添加一个兴趣点时，我们希望在数据库中创建相应的条目，但当他们移动标记时，我们希望更新记录。我们可以将逻辑合并到一个方法中，因为我们知道一个具有空`storageId`的记录之前没有保存到数据库中。因此，我们使用 Firebase 的`createId`方法为其提供一个唯一的 ID。如果`storageId`存在，那么我们就要更新它：

```ts
Save(item: PinModelData) {
  if (item.storageId === '') {
    item.storageId = this.db.createId();
    this.pins.doc(item.storageId).set(item);
  }
  else {
    this.pins.doc(item.storageId).update(item);
  }
}
```

# 表示地图标记

我们可以很好地将标记保存到数据库中，但我们还需要一种方法来表示地图上的标记，以便在地图会话期间显示它们并根据需要移动它们。这个类还将作为与数据服务的连接。我们将要编写的类将演示 TypeScript 3 中引入的一个巧妙的小技巧，称为**rest tuples**，并且起始如下：

```ts
export class PinsModel {
  private pins: PinModelData[] = [];
  constructor(private firebaseMapService: FirebaseMapService) { }
}
```

我们要引入的第一个功能涉及在用户点击地图时添加标记的数据。这个方法的签名看起来有点奇怪，所以我们将花一两分钟来解释它是如何工作的。签名看起来像这样：

```ts
public Add(...args: [string, string, ...number[]]);
```

当我们看到`...args`作为最后（或唯一）参数时，我们立刻想到的是我们将使用 REST 参数。如果我们从开始就分解参数列表，我们可以将其看作是这样开始的：

```ts
public Add(arg_1: string, arg_2: string, ...number[]);
```

这几乎看起来是有道理的，但在那里还有另一个 REST 参数。这基本上意味着我们可以在元组的末尾有任意数量的数字。我们必须对此应用`...`，而不仅仅是应用`number[]`，是因为我们需要展开元素。如果我们只使用数组格式，我们将不得不在调用代码中将元素推入这个数组。有了元组中的 REST 参数，我们可以取出数据，保存到数据库中，并将其添加到我们的`pins`数组中，就像这样：

```ts
public Add(...args: [string, string, ...number[]]) {   const data: PinModelData = {   id: args[0],   name: args[1],   lat: args[2],   long: args[3],   storageId: ''   };   this.firebaseMapService.Save(data);   this.pins.push(data);  }
```

使用这样的元组的含义是，调用代码必须确保将值放入正确的位置。

当我们到达调用这个代码的地方时，我们可以看到我们的方法是这样调用的：

```ts
this.pinsModel.Add(guid.toString(), geocode, e.location.latitude, e.location.longitude);
```

当用户在地图上移动标记时，我们将使用类似的技巧来更新其位置。我们所需要做的就是在数组中找到模型并更新其数值。我们甚至需要更新名称，因为移动标记的行为将改变标记的地址。我们在数据服务上调用相同的`Save`方法，就像我们在`Add`方法中所做的那样：

```ts
public Move(...args: [string,string, ...number[]]) {   const pinModel: PinModelData = this.pins.find(x => x.id === args[0]);   if (pinModel) {   pinModel.name = args[1];   pinModel.lat = args[2];   pinModel.long = args[3];  }   this.firebaseMapService.Save(pinModel);  }
```

其他类也需要访问数据库中的数据。我们在这里面临两个选择——我们可以让其他类也使用 Firebase 地图服务，并且可能错过对这个类的调用，或者我们可以使这个类成为地图服务的唯一访问点。我们将依赖这个类成为与`FirebaseMapPinsService`的唯一联系点，这意味着我们需要通过`Load`方法公开`model`：

```ts
public Load(): Observable<PinModelData[]>{   return this.firebaseMapService.model;  }
```

删除兴趣点使用的方法签名比添加或移动兴趣点简单得多。我们只需要记录的客户端端`id`，然后使用它来找到`PinModelData`项目并调用`Delete`从 Firebase 中删除。一旦我们删除了记录，我们就会找到这条记录的本地索引，并通过对数组进行拼接来删除它：

```ts
public Remove(id: string) {
  const pinModel: PinModelData = this.pins.find(x => x.id === id);
  this.firebaseMapService.Delete(pinModel);
  const index: number = this.pins.findIndex(x => x.id === id);
  if (index >= 0) {
    this.pins.splice(index,1);
  }
}
```

# 尝试有趣的地图搜索

当涉及到获取用户放置或移动图钉的位置名称时，我们希望这是自动发生的。我们真的不希望用户在映射时必须手动输入这个值，映射可以自动为我们选择。这意味着我们将不得不使用映射功能来为我们获取这些信息。

必应地图有许多可选模块，我们可以选择使用，这些模块使我们能够进行基于位置的搜索等操作。为了做到这一点，我们将创建一个名为`MapGeocode`的类，它将为我们进行搜索：

```ts
export class MapGeocode {
}
```

您可能注意到，对于我们的一些类，我们是在没有创建服务的情况下创建它们的。这意味着我们将不得不手动实例化这个类。这没问题，因为我们可以手动控制我们类的生命周期。如果你愿意，在重新创建代码时，你可以将`MapGeocode`等类转换为服务并注入它。

由于搜索是一个可选功能，我们需要加载它。为此，我们将传入我们的地图并使用`loadModule`来加载`Microsoft.Maps.Search`模块，传入`SearchManager`的新实例作为选项：

```ts
private searchManager: Microsoft.Maps.Search.SearchManager;
constructor(private map: Microsoft.Maps.Map) {
  Microsoft.Maps.loadModule('Microsoft.Maps.Search', () => {
    this.searchManager = new Microsoft.Maps.Search.SearchManager(this.map);
  });
}
```

我们要做的所有事情就是编写一个执行查找的方法。由于这可能是一个耗时的操作，我们需要将其设置为`Promise`类型，返回将被填充为名称的字符串。在这个`Promise`中，我们创建一个包含位置的请求和一个回调，当`reverseGeocode`方法执行时，将使用位置的名称更新`Promise`中的回调。有了这个，我们调用`searchManager.reverseGeocode`来执行搜索：

```ts
public ReverseGeocode(location: Microsoft.Maps.Location): Promise<string> {
  return new Promise<string>((callback) => {
    const request = {
      location: location,
      callback: function (code) { callback(code.name); }
    };
    if (this.searchManager) {
      this.searchManager.reverseGeocode(request);
    }
  });
}
```

在编码中，名称很重要。在地图制作中，当我们进行地理编码时，我们将物理地址转换为位置。将位置转换为地址的行为称为**反向地理编码**。这就是为什么我们的方法有一个相当繁琐的名字`ReverseGeocode`。

还有另一种类型的搜索需要考虑。我们希望进行一种使用可见地图区域（视口）来识别该区域内的咖啡店的搜索。为此，我们将使用微软的新 Local Insights API 来搜索特定区域内的企业等内容。目前这种实现有一个限制，即 Local Insights 仅适用于美国地址，但计划在其他国家和地区推出此功能。

为了证明我们仍然可以在服务中使用地图，我们将创建一个`PointsOfInterestService`，它接受一个`HttpClient`，我们将使用它来获取 REST 调用的结果：

```ts
export class PointsOfInterestService {
  constructor(private http: HttpClient) {}
}
```

REST 调用端点接受一个查询，告诉我们我们感兴趣的企业类型，用于执行搜索的位置以及地图密钥。同样，我们的搜索功能可能是长时间运行的，所以我们将返回一个`Promise`，这次是一个自定义的`PoiPoint`，返回纬度和经度，以及企业的名称：

```ts
export interface PoiPoint {
  lat: number,
  long: number,
  name: string
}
```

当我们调用 API 时，我们将使用`http.get`，它返回一个 observable。我们将使用`pipe`和`map`来使用`MapData`对结果进行转换。我们将订阅结果并解析结果（注意我们并不真正知道返回类型，所以我们将其留空为`any`）。返回类型可以包含多个`resourceSets`，大多用于一次性进行多种类型的查询，但我们只需要关注初始的`resourceSet`，然后用它来提取资源。以下代码显示了我们从这次搜索中感兴趣的元素的格式。当我们完成解析结果后，我们将取消订阅搜索订阅，并在`Promise`上回调刚刚添加的点：

```ts
public Search(location: location): Promise<PoiPoint[]> {
  const endpoint = `https://dev.virtualearth.net/REST/v1/LocalSearch/?query=coffee&userLocation=${location[0]},${location[1]}&key=${environment.mapKey}`;
  return new Promise<PoiPoint[]>((callback) => {
    const subscription: Subscription = this.http.get(endpoint).pipe(map(this.MapData))
    .subscribe((x: any) => {
      const points: PoiPoint[] = [];
      if (x.resourceSets && x.resourceSets.length > 0 && x.resourceSets[0].resources) {
        x.resourceSets[0].resources.forEach(element => {
          if (element.geocodePoints && element.geocodePoints.length > 0) {
            const poi: PoiPoint = {
              lat: element.geocodePoints[0].coordinates[0],
              long: element.geocodePoints[0].coordinates[1],
              name: element.name
            };
            points.push(poi)
          }
        });
      }
      subscription.unsubscribe();
      callback(points);
    })
  });
}
```

在我们的查询中，我们只是在一个点上搜索——如果需要的话，我们可以很容易地扩展到在我们的视图范围内搜索一个边界框，方法是接受地图边界框并将`userLocation`更改为`userMapView=${boundingBox{0}},${boundingBox{1}},${boundingBox{2}},${boundingBox{3}}`（其中`boundingBox`是一个矩形）。有关扩展搜索的更多细节，请参见[`docs.microsoft.com/en-us/previous-versions/mt832854(v=msdn.10)`](https://docs.microsoft.com/en-us/previous-versions/mt832854(v=msdn.10))。

现在我们已经完成了地图搜索功能和数据库功能，是时候在屏幕上实际放置地图了。让我们现在来处理这个问题。

# 将 Bing 地图添加到屏幕上

就像我们之前讨论的那样，我们将使用两个组件来显示地图。让我们从`MapViewComponent`开始。这个控件的 HTML 模板非常简单：

```ts
<div #myMap style='width: 100%; height: 100%;'> </div> 
```

是的，这确实是我们的 HTML 的全部内容。它背后发生的事情要复杂一些，这就是我们将学习 Angular 如何让我们连接到标准 DOM 事件的地方。我们通常不显示整个`@Component`元素，因为它几乎是样板代码，但在这种情况下，我们将不得不做一些稍微不同的事情。这是我们组件的第一部分：

```ts
@Component({
  selector: 'atp-map-view',
  templateUrl: './map-view.component.html',
  styleUrls: ['./map-view.component.scss'],
  host: {
  '(window:load)' : 'Loaded()'
  } }) export class MapViewComponent implements OnInit {
  @ViewChild('myMap') myMap: { nativeElement: string | HTMLElement; };    constructor() { }    ngOnInit() {  }
}
```

在`@Component`部分，我们将窗口加载事件挂钩到`Loaded`方法。我们很快会添加这个方法，但现在知道这是我们如何将组件挂钩到主机事件的方式很重要。在组件内部，我们使用`@ViewChild`来挂钩到我们模板中的`div`。基本上，这允许我们通过名称引用视图内的元素，以便我们可以以某种任意的方式处理它。

我们添加`Loaded`方法的原因是因为 Bing 地图有一个特别讨厌的习惯，即在 Chrome 或 Firefox 等浏览器中不正常工作，除非我们在`window.load`事件中挂接地图。我们将在模板中添加一个`div`语句来托管地图，使用一系列地图加载选项，包括地图凭据和默认缩放级别：

```ts
Loaded() {   // Bing has a nasty habit of not working properly in browsers like 
  // Chrome if we don't hook the map up 
 // in the window.load event.   const map = new Microsoft.Maps.Map(this.myMap.nativeElement, {   credentials: environment.mapKey,   enableCORS: true,   zoom: 13   });
  this.map.emit(map);
}
```

如果我们想选择特定类型的地图类型来显示，我们可以在地图加载选项中设置如下：

```ts
mapTypeId:Microsoft.Maps.MapTypeId.road
```

我们的`MapViewComponent`将托管在另一个组件内部，因此我们将创建一个`EventEmitter`，我们可以用它来通知父组件。我们已经在我们的`Loaded`方法中添加了发射代码，将刚加载的地图传回给父组件：

```ts
@Output() map = new EventEmitter();
```

现在让我们添加父容器。大部分模板只是用来创建带有行和列的 Bootstrap 容器。在`div`列内，我们将托管刚刚创建的子组件。同样，我们可以看到我们使用了`EventEmitter`，所以当地图被发射时，它触发`MapLoaded`事件：

```ts
<div class="container-fluid h-100">
 <div class="row h-100">
 <div class="col-12">
 <atp-map-view (map)="MapLoaded($event)"></atp-map-view>
 </div>
 </div> </div>
```

大多数映射容器代码现在应该是我们熟悉的领域。我们注入`FirebaseMapPinsService`和`PointsOfInterestService`，我们用它们在`MapLoaded`方法中创建`MapEvents`实例。换句话说，当`atp-map-view`组件触发`window.load`时，填充的 Bing 地图就会回来：

```ts
export class MappingcontainerComponent implements OnInit {   private map: Microsoft.Maps.Map;
  private mapEvents: MapEvents;
  constructor(private readonly firebaseMapPinService: FirebaseMapPinsService, 
private readonly poi: PointsOfInterestService) { }    ngOnInit() {
 }    MapLoaded(map: Microsoft.Maps.Map) {
  this.map = map;
  this.mapEvents = new MapEvents(this.map, new PinsModel(this.firebaseMapPinService), this.poi);
 } }
```

关于显示地图的说明——我们确实需要设置`html`和`body`的高度，以使其延伸到浏览器窗口的全高。在`styles.scss`文件中设置如下：

```ts
html,body {
  height: 100%; }
```

# 地图事件和设置标记

我们有地图，我们有逻辑来将兴趣点保存到数据库并在内存中移动它们。我们唯一没有的是处理用户实际从地图本身创建和管理标记的代码。现在是时候纠正这种情况并添加一个`MapEvents`类来为我们处理这个问题。就像`MapGeocode`、`PinModel`和`PinsModel`类一样，这个类是一个独立的实现。让我们从添加以下代码开始：

```ts
export class MapEvents {
  private readonly geocode: MapGeocode;
  private infoBox: Microsoft.Maps.Infobox;

  constructor(private map: Microsoft.Maps.Map, private pinsModel: PinsModel, private poi: PointsOfInterestService) {

  }
}
```

`Infobox`是在将兴趣点添加到屏幕上时出现的框。我们可以在添加每个兴趣点时添加一个新的，但这将是一种资源浪费。相反，我们将添加一个单独的`Infobox`，并在添加新点时重用它。为此，我们将添加一个辅助方法，检查之前是否已设置`Infobox`。如果之前没有设置，我们将实例化`Infobox`的新实例，输入图钉位置、标题和描述。我们将使用`setMap`来设置此`Infobox`将出现在的地图实例。当我们重用这个`Infobox`时，我们只需要在选项中设置相同的值，然后将可见性设置为`true`：

```ts
private SetInfoBox(title: string, description: string, pin: Microsoft.Maps.Pushpin): void {
  if (!this.infoBox) {
    this.infoBox = new Microsoft.Maps.Infobox(pin.getLocation(), { title: title, description: description });
    this.infoBox.setMap(this.map);
  return;
  }
  this.infoBox.setOptions({
    title: title,
    description: description,
    location: pin.getLocation(),
    visible: true
  });
}
```

在我们添加从地图中选择点的能力之前，我们还需要向这个类添加一些辅助方法。我们要添加的第一个方法是从本地见解搜索中获取兴趣点并将它们添加到地图上。在这里，我们可以看到我们添加图钉的方式是创建一个绿色的`Pushpin`，然后将其添加到我们的 Bing 地图上的正确`Location`。我们还添加了一个事件处理程序，以响应对图钉的点击，并使用我们刚刚添加的方法显示`Infobox`：

```ts
AddPoi(pois: PoiPoint[]): void {
  pois.forEach(poi => {
    const pin: Microsoft.Maps.Pushpin = new Microsoft.Maps.Pushpin(new Microsoft.Maps.Location(poi.lat, poi.long), {
      color: Microsoft.Maps.Color.fromHex('#00ff00')
    });
    this.map.entities.push(pin);
    Microsoft.Maps.Events.addHandler(pin, 'click', (x) => {
      this.SetInfoBox('Point of interest', poi.name, pin);
    });
  })
}
```

下一个辅助方法更复杂，所以我们将分阶段添加它。当用户在地图上单击时，将调用`AddPushPin`代码。签名如下：

```ts
AddPushPin(e: any): void {
}
```

在这个方法中，我们要做的第一件事是创建一个`Guid`，用于在添加`PinsModel`条目时使用，并在点击位置添加一个可拖动的`Pushpin`：

```ts
const guid: Guid = Guid.create();
const pin: Microsoft.Maps.Pushpin = new Microsoft.Maps.Pushpin(e.location, {
  draggable: true
});
```

有了这个方法，我们将调用之前编写的`ReverseGeocode`方法。当我们从中获取结果时，我们将添加我们的`PinsModel`条目，并在显示`Infobox`之前将`Pushpin`推到地图上：

```ts
this.geocode.GeoCode(e.location).then((geocode) => {
  this.pinsModel.Add(guid.toString(), geocode, e.location.latitude, e.location.longitude);
  this.map.entities.push(pin);
  this.SetInfoBox('User location', geocode, pin);
});
```

我们还没有完成这个方法。除了添加一个`Pushpin`，我们还必须能够拖动它，以便用户在拖动图钉时选择一个新的位置。我们将使用`dragend`事件来移动图钉。同样，我们之前付出的辛苦工作得到了回报，因为我们有一个简单的机制来`Move` `PinsModel`并显示我们的`Infobox`：

```ts
const dragHandler = Microsoft.Maps.Events.addHandler(pin, 'dragend', (args: any) => {
  this.geocode.GeoCode(args.location).then((geocode) => {
    this.pinsModel.Move(guid.toString(), geocode, args.location.latitude, args.location.longitude);
    this.SetInfoBox('User location (Moved)', geocode, pin);
  });
});
```

最后，当用户点击图钉时，我们希望从`PinsModel`和地图中删除图钉。当我们为`dragend`和`click`添加事件处理程序时，我们将处理程序保存到变量中，以便我们可以使用它们从地图事件中删除事件处理程序。自我整理是一个好习惯，特别是在处理事件处理程序之类的事情时：

```ts
const handler = Microsoft.Maps.Events.addHandler(pin, 'click', () => {
  this.pinsModel.Remove(guid.toString());
  this.map.entities.remove(pin);

  // Tidy up our stray event handlers.
  Microsoft.Maps.Events.removeHandler(handler);
  Microsoft.Maps.Events.removeHandler(dragHandler);
});
```

好了，我们的辅助方法已经就位。现在我们只需要更新构造函数，以便在地图上单击以设置兴趣点并在用户查看的视口发生变化时搜索本地见解。让我们从响应用户在地图上单击开始：

```ts
this.geocode = new MapGeocode(this.map);
Microsoft.Maps.Events.addHandler(map, 'click', (e: any) => {
  this.AddPushPin(e);
});
```

在这里，我们不需要将处理程序存储为变量，因为我们将其与在浏览器中运行时不会被移除的东西关联起来，即地图本身。

当用户移动地图以便查看其他区域时，我们需要执行本地见解搜索，并根据返回的结果添加兴趣点。我们将事件处理程序附加到地图`viewchangeend`事件以触发此搜索：

```ts
Microsoft.Maps.Events.addHandler(map, 'viewchangeend', () => {
  const center = map.getCenter();
  this.poi.Search([center.latitude, center.longitude]).then(pointsOfInterest => {
    if (pointsOfInterest && pointsOfInterest.length > 0) {
      this.AddPoi(pointsOfInterest);
    }
  })
})
```

我们不断看到事先准备方法可以节省我们很多时间。我们只是利用`PointsOfInterestService.Search`方法来进行本地见解搜索，然后将结果传递给我们的`AddPoi`方法。如果我们不想执行本地见解搜索，我们可以简单地删除此事件处理程序，而无需进行任何搜索。

我们唯一剩下要做的就是处理从数据库加载我们的标记。这里的代码是我们已经看到的用于添加`click`和`dragend`处理程序的代码的变体，但我们不需要执行地理编码，因为我们已经有了每个兴趣点的名称。因此，我们不打算重用`AddPushPin`方法。相反，我们将选择在整个部分内联执行。加载订阅如下所示：

```ts
const subscription = this.pinsModel.Load().subscribe((data: PinModelData[]) => {
  data.forEach(pinData => {
    const pin: Microsoft.Maps.Pushpin = new Microsoft.Maps.Pushpin(new Microsoft.Maps.Location(pinData.lat, pinData.long), {
      draggable: true
    });
    this.map.entities.push(pin);
    const handler = Microsoft.Maps.Events.addHandler(pin, 'click', () => {
      this.pinsModel.Remove(pinData.id);
      this.map.entities.remove(pin);
    Microsoft.Maps.Events.removeHandler(handler);
      Microsoft.Maps.Events.removeHandler(dragHandler);
    });
    const dragHandler = Microsoft.Maps.Events.addHandler(pin, 'dragend', (args: any) => {
      this.geocode.GeoCode(args.location).then((geocode) => {
        this.pinsModel.Move(pinData.id, geocode, args.location.latitude, args.location.longitude);
        this.map.entities.push(pin);
    this.SetInfoBox('User location (moved)', geocode, pin);
      });
    });
  });
  subscription.unsubscribe();
  this.pinsModel.AddFromStore(data);
});
```

需要注意的是，由于我们正在处理订阅，一旦完成订阅，我们就会从中`取消订阅`。订阅应返回一个`PinModelData`项目数组，我们可以遍历并根据需要添加元素。

就是这样。我们现在已经有了一个可用的映射解决方案。这是我最期待写的章节之一，因为我喜欢映射应用程序。我希望你和我一样享受这个过程。然而，在我们离开这一章之前，如果你想防止人们未经授权访问数据，你可以在下一节中应用这些知识。

# 保护数据库

这一部分是提供数据库安全性所需的可选概述。您可能还记得，当我们创建 Firestore 数据库时，我们设置了访问权限，以便任何人都可以完全不受限制地访问。在开发小型测试应用程序时这没问题，但通常不适用于商业应用程序的部署。

我们将更改数据库的配置，以便只有在授权 ID 设置时才允许读/写访问。为此，请在数据库中选择“规则”选项卡，并将`if request.auth.uid != null;`添加到规则列表中。`match /{document=**}`的格式简单地意味着这个规则适用于列表中的任何文档。可以设置只适用于特定文档的规则，但在这样的应用程序环境中并没有太多意义。

请注意，这样做意味着我们必须添加身份验证，就像我们在第六章中所做的那样，*使用 Socket.IO 构建聊天室应用程序*。设置这一点超出了本章的范围，但从上一章复制导航并提供登录功能应该很简单：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/7bd73cd5-8073-493f-aefe-9725e47bee1c.png)

这是一段相当漫长的旅程。我们经历了注册不同在线服务的过程，并将映射功能引入了我们的代码。与此同时，我们还看到了如何使用 TypeScript 支持在 Angular 应用程序中搭建脚手架，而无需生成和注册服务。现在，您应该能够拿起这段代码，并尝试添加您真正想要的映射功能。

# 摘要

在本章中，我们已经完成了使用 Microsoft 和 Google 的云服务引入 Angular 项目的工作，这些云服务以 Bing Maps 和 Firebase 云服务的形式存储数据。我们注册了这些服务，并从中获取了相关信息，以便为客户端访问它们。在编写代码的过程中，我们创建了与 Firestore 数据库一起工作的类，并与 Bing Maps 交互，执行诸如基于用户点击搜索地址、在地图上添加标记以及使用本地洞察力搜索咖啡店等操作。

继续我们的 TypeScript 之旅，我们介绍了 rest 元组。我们还看到如何向 Angular 组件添加代码以响应浏览器主机事件。

在下一章中，我们将重新审视 React。这一次，我们将创建一个使用 Docker 包含各种微服务的有限微服务 CRM。

# 问题

1.  Angular 如何允许我们与主机元素交互？

1.  纬度和经度是什么？

1.  逆地理编码的目的是什么？

1.  我们使用哪项服务来存储我们的数据？


# 第八章：使用 React 和微服务构建 CRM

在我们使用 REST 服务的先前章节中，我们专注于有一个用于处理 REST 调用的单个站点。现代应用程序经常使用微服务，可能托管在基于容器的系统（如 Docker）中。

在本章中，我们将学习如何使用 Swagger 创建托管在多个 Docker 容器中的一组微服务来设计我们的 REST API。我们的 React 客户端应用程序将负责将这些微服务整合在一起，创建一个简单的客户关系管理（CRM）系统。

本章将涵盖以下主题：

+   理解 Docker 和容器

+   微服务是什么，它们的用途是什么

+   将单片架构分解为微架构

+   共享通用的服务器端功能

+   使用 Swagger 设计 API

+   在 Docker 中托管微服务

+   使用 React 连接到微服务

+   在 React 中使用路由

# 技术要求

完成的项目可以从[`github.com/PacktPublishing/Advanced-TypeScript-3-Programming-Projects/tree/master/Chapter08`](https://github.com/PacktPublishing/Advanced-TypeScript-3-Programming-Projects/tree/master/Chapter08)下载。

下载项目后，您将需要使用`npm install`命令安装软件包要求。由于服务分布在多个文件夹中，您将需要逐个安装每个服务。

# 理解 Docker 和微服务

由于我们正在构建一个使用 Docker 容器托管的微服务系统，所以我们需要事先了解一些术语和理论。

在本节中，我们将在继续了解微服务是什么、它们旨在解决什么问题以及如何将单片应用程序拆分为更模块化的服务之前，先看一下常见的 Docker 术语及其含义。

# Docker 术语

如果您是 Docker 的新手，您将遇到许多围绕它的术语。了解这些术语将有助于我们在设置服务器时，因此让我们从基础知识开始。

# 容器

如果您在互联网上看到过任何 Docker 文献，这可能是您已经遇到的术语。容器是运行实例，接收运行应用程序所需的各种软件。这是我们的起点。容器是从镜像构建的，您可以自己构建或从中央 Docker 数据库下载。容器可以向其他容器、主机操作系统甚至向更广泛的世界开放，使用端口和卷。容器的一个重要卖点是它们易于设置和创建，并且可以快速停止和启动。

# 镜像

正如我们在上一段中所介绍的，容器最初是一个镜像。已经有大量可供使用的镜像，但我们也可以创建自己的镜像。创建镜像时，创建步骤会被缓存，以便轻松重复使用。

# 端口

这对您来说可能已经很熟悉了。Docker 中的端口术语与操作系统中的端口术语完全相同。这些是对主机操作系统可见的 TCP 或 UDP 端口，或者连接到外部世界的端口。当我们的应用程序在内部使用相同的端口号但使用不同的端口号向外界公开时，本章后面将会有一些有趣的代码。

# 卷

可视化卷的最简单方法是将其视为共享文件夹。创建容器时，卷被初始化，并允许我们持久保存数据，无论容器的生命周期如何。

# 注册表

实际上，注册表可以被视为 Docker 世界的应用商店。它存储可以下载的 Docker 镜像，并且本地镜像可以以类似于将应用程序推送到应用商店的方式推送回注册表。

# Docker Hub

Docker Hub 是最初由 Docker 提供的 Docker 注册表。该注册表存储了大量的 Docker 镜像，其中一些来自 Docker，一些是由软件团队为其构建的。

在本章中，我们不打算涵盖安装 Docker，因为安装和设置 Docker 本身就是一个章节，特别是因为在 Windows 上安装 Docker 与在 macOS 或 Linux 上安装 Docker 是不同的体验。但我们将使用的命令来组合 Docker 应用程序和检查实例的状态不会改变，所以我们会在需要时进行覆盖。

# 微服务

在企业软件世界中很难不听到微服务这个术语。这是一种架构风格，将所谓的单体系统拆分为一系列服务。这种架构的特点是服务范围紧凑且可测试。服务应该松散耦合，以限制它们之间的依赖关系——将这些服务组合在一起应该由最终应用程序来完成。这种松散耦合促进了它们可以独立部署的想法，服务通常专注于业务能力。

尽管我们可能会听到来自营销大师和咨询公司的声音，他们希望销售服务，但微服务并不总是应用的合适选择。有时，保持单体应用可能更好。如果我们无法使用前面段落中概述的所有想法来拆分应用程序，那么应用程序很可能不适合作为微服务的候选。

与我们迄今为止在本书中涵盖的许多内容不同，例如模式，微服务没有官方批准的定义。你不能遵循一个清单并说，“这是一个微服务，因为它正在执行 a、b 和 c”。相反，对于构成微服务的内容的共识观点已经发展，基于看到什么有效和什么无效，演变成一系列特征。对于我们的目的，构成微服务的重要属性包括以下内容：

+   该服务可以独立部署，不依赖于其他微服务。

+   该服务基于业务流程。微服务应该是粒度细小的，因此将它们组织在单一的业务领域周围有助于从小而专注的组件创建大规模应用程序。

+   服务之间的语言和技术可以是不同的。这为我们提供了在必要时利用最佳和最合适的技术的机会。例如，我们可能有一个服务在内部托管，而另一个服务可能在 Azure 等云服务中托管。

+   服务应该规模小。这并不意味着它不应该有太多代码；相反，它意味着它只专注于一个领域。

# 使用 Swagger 设计我们的 REST API

在开发 REST 驱动的应用程序时，我发现使用 Swagger 的功能非常有用。Swagger 具有许多功能，使其成为我们想要执行诸如创建 API 文档、为 API 创建代码和测试 API 等操作时的首选工具。

我们将使用 Swagger UI 来原型化检索人员列表的能力。从这里，我们可以生成与我们的 API 一起使用的文档。虽然我们可以从中生成代码，但我们将使用可用的工具来查看我们最终 REST 调用的*形状*，然后使用我们之前创建的数据模型来实现自己的实现。我喜欢这样做的原因有两个。首先，我喜欢打造小而干净的数据模型，我发现原型可以让我可视化模型。其次，有很多生成的代码，我发现当我自己编写代码时更容易将我的数据模型与数据库联系起来。

在本章中，我们将自己编写代码，但我们将使用 Swagger 来原型设计我们想要交付的内容。

我们需要做的第一件事是登录 Swagger：

1.  从主页，点击登录。这会弹出一个对话框，询问我们要登录哪个产品，即 SwaggerHub 或 Swagger Inspector。Swagger Inspector 是一个用于测试 API 的好工具，但由于我们将开发 API，我们将登录 SwaggerHub。以下截图显示了它的外观：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/eed2dbdb-d965-4190-9be0-ddbf0bf2eae0.png)

1.  如果您没有 Swagger 帐户，可以通过注册或使用 GitHub 帐户从这里创建一个。为了创建一个 API，我们需要选择创建新的>创建新的 API。在模板下拉菜单中选择 None，并填写如下：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/408868db-6a1b-44f9-8a05-748d562714f3.png)

1.  在这个阶段，我们准备开始填写我们的 API。我们得到的开箱即用的是以下内容：

```ts
swagger: '2.0'
info:
  version: '1.0'
  title: 'Advanced TypeScript 3 - CRM'
  description: ''
paths: {}
# Added by API Auto Mocking Plugin
host: virtserver.swaggerhub.com
basePath: /user_id/AdvancedTypeScript3CRM/1.0
schemes:
 - https
```

让我们开始构建这个 API。首先，我们要创建 API 路径的开始。我们需要创建的任何路径都放在`paths`节点下。Swagger 编辑器在构建 API 时验证输入，所以不用担心在填写时出现验证错误。在我们的示例中，我们将创建 API 来检索我们添加到数据库中的所有人的数组。因此，我们从这里开始，我们的 API 端点，替换`paths: {}`行：

```ts
paths:
  /people:
    get:
     summary: "Retrieves the list of people from Firebase"
     description: Returns a list of people
```

因此，我们已经说过我们的 REST 调用将使用`GET`动词发出。我们的 API 将返回两种状态，`HTTP 200`和`HTTP 400`。让我们通过在`responses`节点中填充这些状态的开始来提供这一点。当我们返回`400`错误时，我们需要创建定义我们将通过网络返回的内容的模式。`schema`返回一个包含单个`message`字符串的`object`，如下所示：

```ts
     responses:
        200:
        400:
          description: Invalid request 
          schema:
            type: object
            properties: 
              message:
                type: string
```

由于我们的 API 将返回一个人的数组，我们的模式被定义为一个`array`。构成人的`items`与我们在服务器代码中讨论的模型相对应。因此，通过填写我们`200`响应的`schema`，我们得到了这个：

```ts
          description: Successfully returned a list of people 
          schema:
            type: array
            items:
              type: object
              properties:
                ServerID:
                  type: string
                FirstName:
                  type: string
                LastName:
                  type: string
                Address:
                  type: object
                  properties:
                    Line1: 
                      type: string
                    Line2: 
                      type: string
                    Line3: 
                      type: string
                    Line4: 
                      type: string
                    PostalCode: 
                      type: string
                    ServerID: 
                      type: string
```

这是编辑器中我们的`schema`的样子：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/29dbb934-da56-4d77-b897-bef2ab2516ad.png)

现在我们已经看到了 Swagger 如何用于原型设计我们的 API，我们可以继续定义我们想要构建的项目。

# 使用 Docker 创建微服务应用

我们要编写的项目是 CRM 系统的一个小部分，用于维护有关客户的详细信息并为这些客户添加潜在客户。应用程序的工作方式是用户创建地址；当他们添加有关联系人的详细信息时，他们将从他们已经创建的地址列表中选择地址。最后，他们可以创建使用他们已经添加的联系人的潜在客户。这个系统的想法是，以前，应用程序使用一个大数据库来存储这些信息，我们将把它分解成三个独立的服务。

与 GitHub 代码一起工作，本章应该需要大约三个小时才能完成。完成后，应用程序应如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/5b119141-e7c1-42f6-8830-50256b3fad64.png)

完成这些后，我们将继续看如何为 Docker 创建应用程序，以及这如何补充我们的项目。

# 使用 Docker 创建微服务应用的入门

在本章中，我们将再次使用 React。除了使用 React，我们还将使用 Firebase 和 Docker，托管 Express 和 Node。我们的 React 应用程序与 Express 微服务之间的 REST 通信将使用 Axios 完成。

如果您在 Windows 10 上进行开发，请安装 Windows 版的 Docker Desktop，可在此处下载：[`hub.docker.com/editions/community/docker-ce-desktop-windows`](https://hub.docker.com/editions/community/docker-ce-desktop-windows)。

要在 Windows 上运行 Docker，您需要安装 Hyper-V 虚拟化。

如果您想在 macOS 上安装 Docker Desktop，请前往[`hub.docker.com/editions/community/docker-ce-desktop-mac`](https://hub.docker.com/editions/community/docker-ce-desktop-mac)。

Docker Desktop 在 Mac 上运行在 OS X Sierra 10.12 和更新的 macOS 版本上。

我们将要构建的 CRM 应用程序演示了如何将多个微服务集成到一个统一的应用程序中，最终用户不知道我们的应用程序正在使用来自多个数据源的信息。

我们应用程序的要求如下：

+   CRM 系统将提供输入地址的功能。

+   系统将允许用户输入有关一个人的详细信息。

+   当有关一个人的详细信息被输入时，用户可以选择之前输入的地址。

+   系统将允许用户输入有关潜在客户的详细信息。

+   数据将保存到云数据库中。

+   人员、潜在客户和地址信息将从单独的服务中检索。

+   这些单独的服务将由 Docker 托管。

+   我们的用户界面将作为一个 React 系统创建。

我们一直在努力实现在我们的应用程序中共享功能的能力。我们的微服务将通过尽可能共享尽可能多的公共代码，然后只添加它们需要定制的数据，来将这种方法推向更高水平。我们之所以能够这样做，是因为我们的服务在需求上是相似的，所以它们可以共享很多公共代码。

我们的微服务应用程序从单体应用程序的角度开始。该应用程序由一个系统管理所有的人员、地址和潜在客户。我们将对这个单体应用程序进行适当的处理，并将其分解成更小、离散的部分，其中每个组成部分都存在于其他部分之外。在这里，潜在客户、地址和人员都存在于自己独立的服务中。

我们将从我们的`tsconfig`文件开始。在之前的章节中，每章都有一个服务，一个`tsconfig`文件。我们将通过拥有一个根级`tsconfig.json`文件来改变这种情况。我们的服务将都使用它作为一个共同的基础：

1.  让我们从创建一个名为`Services`的文件夹开始，它将作为我们服务的基础。在此之下，我们将创建单独的`Addresses`、`Common`、`Leads`和`People`文件夹，以及我们的基础`tsconfig`文件。

1.  当我们完成这一步时，我们的`Services`文件夹应该如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/7a971ac6-66c1-4955-8cc0-b99205dc692a.png)

1.  现在，让我们添加`tsconfig`设置。这些设置将被我们将要托管的所有服务共享：

```ts
{
  "compileOnSave": true,
  "compilerOptions": {
    "target": "es5",
    "module": "commonjs",
    "removeComments": true,
    "strict": true,
    "esModuleInterop": true,
    "inlineSourceMap": true,
    "experimentalDecorators": true,
  }
}
```

您可能已经注意到我们在这里还没有设置输出目录。我们将稍后再进行设置。在进行这一步之前，我们将开始添加将由我们的微服务共享的公共功能。我们的共享功能将被添加到`Common`文件夹中。我们将要添加的一些内容应该看起来非常熟悉，因为我们在之前的章节中构建了类似的服务器代码。

我们的服务将保存到 Firebase，因此我们将从编写我们的数据库代码开始。我们需要安装的`npm`包是`firebase`和`@types/firebase`。在添加这些的同时，我们还应该导入`guid-typescript`以及我们之前安装的基本 node`cors`和`express`包。

当每个服务将数据保存到数据库时，它将以相同的基本结构开始。我们将有一个`ServerID`，我们将使用 GUID 自己设置。我们将使用的基本模型如下所示：

```ts
export interface IDatabaseModelBase {
  ServerID: string;
}
```

我们将创建一个`abstract`基类，它将与`IDatabaseModelBase`的实例一起工作，使我们能够`Get`记录，`GetAll`记录和`Save`记录。与 Firebase 一起工作的美妙之处在于，虽然它是一个强大的系统，但我们必须编写的代码来完成这些任务非常简短。让我们从类定义开始：

```ts
export abstract class FirestoreService<T extends IDatabaseModelBase> {
  constructor(private collection: string) { }
}
```

正如你所看到的，我们的类是通用的，这告诉我们每个服务都将扩展`IDatabaseModelBase`并在其特定的数据库实现中使用它。集合是将在 Firebase 中写入的集合的名称。对于我们的目的，我们将共享一个 Firebase 实例来存储不同的集合，但我们的架构之美在于如果我们不想要，我们不需要这样做。如果需要，我们可以使用单独的 Firebase 存储；事实上，在生产环境中通常会发生这种情况。

我们添加我们的`GET`方法是没有意义的，如果我们没有保存任何数据，所以我们要做的第一件事是编写我们的`Save`方法。毫不奇怪，我们的`Save`方法将是异步的，因此它将返回一个`Promise`：

```ts
public Save(item: T): Promise<T> {
  return new Promise<T>(async (coll) => {
    item.ServerID = Guid.create().toString();
    await firebase.firestore().collection(this.collection).doc(item.ServerID).set(item);
    coll(item);
  });
}
```

可能看起来奇怪的是`async (coll)`的代码。由于我们使用了`=>`，我们创建了一个简化的函数。由于这是一个函数，我们在其中添加了`async`关键字，以指示代码可以在其中使用`await`。如果我们没有将其标记为`async`，那么我们将无法在其中使用`await`。

我们的代码在调用一系列方法设置数据之前为`ServerID`分配了一个 GUID。让我们分块处理代码，看看每个部分的作用。正如我们在第七章中讨论的那样，*使用 Firebase 进行 Angular 基于云的映射*，Firebase 提供的不仅仅是数据库服务，所以我们需要做的第一件事是访问数据库部分。如果我们在这里不遵循方法链接，我们可以将其写成如下形式：

```ts
const firestore: firebase.firestore.Firestore = firebase.firestore();
```

在 Firestore 中，我们不是将数据保存在表中，而是将其保存在命名集合中。一旦我们有了`firestore`，我们就会得到`CollectionReference`。在前面的代码片段之后，我们可以将其重写如下：

```ts
const collection: firebase.firestore.CollectionReference = firestore.collection(this.collection);
```

一旦我们有了`CollectionReference`，我们就可以使用我们在方法中之前设置的`ServerID`来访问单个文档。如果我们不提供自己的 ID，系统会为我们创建一个：

```ts
const doc: firebase.firestore.DocumentReference = collection.doc(item.ServerID);
```

现在，我们需要设置我们要写入数据库的数据：

```ts
await doc.set(item);
```

这将把数据保存到 Firestore 中适当的集合中的文档中。我不得不承认，虽然我喜欢输入可以像这样分解的代码的能力，但是如果可以使用方法链接，我很少这样做。当链中的下一步逻辑上从前一步逻辑上逻辑上跟随时，我经常将方法链接在一起，因为如果没有经过前面的步骤，就无法到达下一步，而且这样做可以让我很容易地将步骤序列可视化。

一旦项目保存到数据库中，我们将返回保存的项目，包括`ServerID`，返回到调用代码，以便可以立即使用。这就是这行代码的作用：

```ts
coll(item);
```

我们`FirestoreService`的下一步是添加`GET`方法。这个方法，像`Save`方法一样，是一个`async`方法，返回一个包装在 promise 中的`T`类型的单个实例。由于我们知道 ID，我们的 Firestore 代码的绝大部分是相同的。不同之处在于我们调用`get()`，然后用它来返回数据：

```ts
public async Get(id: string): Promise<T> {
  const qry = await firebase.firestore().collection(this.collection).doc(id).get();
  return <T>qry.data();
}
```

猜猜看？我们还有一个`async GetAll`方法要写，这次返回一个`T`数组。由于我们想要检索多个记录，而不仅仅是单个文档，我们在我们的`collection`上调用`get()`。一旦我们有了记录，我们使用一个简单的`forEach`来构建我们需要返回的数组：

```ts
public async GetAll(): Promise<T[]> {
  const qry = await firebase.firestore().collection(this.collection).get();
  const items: T[] = new Array<T>();
  qry.forEach(item => {
    items.push(<T>item.data());
  });
  return items;
}
```

我们的数据库代码已经就位，让我们看看实际情况是什么样子。我们将从`Addresses`服务开始，创建一个扩展`IDatabaseModelBase`的`IAddress`接口：

```ts
export interface IAddress extends IDatabaseModelBase {
  Line1 : string,
  Line2 : string,
  Line3 : string,
  Line4 : string,
  PostalCode : string
}
```

有了`IAddress`，我们现在可以创建将我们的服务与我们将在 Firebase 中存储的`addresses`集合联系起来的类。通过我们的努力，`AddressesService`就像这样简单：

```ts
export class AddressesService extends FirestoreService<IAddress> {
  constructor() {
    super('addresses');
  }
}
```

您可能想知道数据模型和数据库访问的代码是否与其他微服务一样简单。让我们看看我们的`People`接口和数据库服务是什么样子的：

```ts
export interface IPerson extends IDatabaseModelBase {
  FirstName: string;
  LastName: string;
  Address: IAddress;
}
export class PersonService extends FirestoreService<IPerson> {
  constructor() {
    super('people');
  }
}
```

您可能还想知道为什么我们将地址信息存储在`IPerson`内部。如果您是从关系数据库的角度来看待 NoSQL 架构，那么很容易认为我们应该只开始引用地址，而不是重复数据，特别是在关系数据库中，记录是通过外键链接在一起创建`指针`来建立关系。 *老式* SQL 数据库使用外部表来最小化记录中的冗余，以便我们不会创建跨多个记录共享的重复数据。虽然这是一个有用的功能，但它确实使查询和检索记录变得更加复杂，因为我们感兴趣的信息可能分散在几个表中。通过将地址存储在人员旁边，我们减少了我们需要查询以构建人员信息的表的数量。这是基于我们想要查询记录的频率远远超过我们想要更改记录的想法，因此，如果我们需要更改地址，我们将更改主地址，然后单独的查询将运行通过所有人员记录，寻找需要更新的地址。我们将实现这一点，因为人员记录中地址部分的`ServerID`将与主地址中的`ServerID`匹配。

我们不会涵盖`Leads`数据库代码；您可以在源代码中阅读它，它几乎与此相同。我们的做法是，我们的微服务在功能上非常相似，因此我们可以简单地利用继承。

# 添加服务器端路由支持

除了有一个与数据库共同工作的常见方式之外，我们的传入 API 请求在端点方面都将非常相似。在写这本书的时候，我试图整理一些以后可以重复使用的代码片段。其中一个片段是我们处理 Express 路由的方式。我们在第四章中组合的服务器端代码，*MEAN Stack - 构建照片库*，就是这样一个区域，特别是路由的代码。我们可以几乎完全按照当时写的方式引入这段代码。

这是代码的快速提醒。首先，我们有我们的`IRouter`接口：

```ts
export interface IRouter {
  AddRoute(route: any): void;
}
```

然后，我们有我们的路由引擎 - 这段代码我们将直接插入到我们的服务器中：

```ts
export class RoutingEngine {
  constructor(private routing: IRouter[] = new Array<IRouter>()) {
  }
  public Add<T1 extends IRouter>(routing: (new () => T1), route: any) {
    const routed = new routing();
    routed.AddRoute(route);
    this.routing.push(routed);
  }
}
```

那么，在实践中，这是什么样子呢？好吧，这是保存从客户端发送过来的地址的代码。当我们从客户端收到一个`/add/`请求时，我们从请求体中提取详细信息，并将其转换为`IAddress`，然后用于保存到地址服务中：

```ts
export class SaveAddressRouting implements IRouter {
  AddRoute(route: any): void {
    route.post('/add/', (request: Request, response: Response) => {
      const person: IAddress = <IAddress>{...request.body};
      new AddressesService().Save(person);
      response.json(person);
    });
  }
}
```

获取地址的代码非常相似。我们不打算解剖这个方法，因为现在它应该看起来非常熟悉：

```ts
export class GetAddressRouting implements IRouter {
  AddRoute(route: any): void {
    route.get('/get/', async (request: Request, response: Response) => {
      const result = await new AddressesService().GetAll();
      if (result) {
        response.json(result);
      }
      response.send('');
    });
  }
}
```

`Leads`和`People`服务的代码几乎是相同的。请阅读我们的 GitHub 存储库中的代码，以熟悉它。

# 服务器类

再次，为了尽可能地重用代码，我们将使用我们在第四章中编写的 Express `Server`类的略微修改版本，*The MEAN Stack – Building a Photo Gallery*。我们将快速浏览代码以重新熟悉它。首先，让我们放置类定义和构造函数。我们的构造函数是第四章中构造函数的简化版本，*The MEAN Stack – Building a Photo Gallery*：

```ts
export abstract class Server {
  constructor(private port: number = 3000, private app: any = express(), protected routingEngine: RoutingEngine = new RoutingEngine()) {}
  }
}
```

我们还想要添加 CORS 支持。虽然我们可以将其设为强制性，但我仍然喜欢将是否要这样做的控制权交给服务开发人员，因此我们将保持这个方法为`public`：

```ts
public WithCorsSupport(): Server {
  this.app.use(cors());
  return this;
}
```

为了使我们的实际服务器实现工作，我们需要赋予它们添加路由的能力。我们通过`AddRouting`方法来实现这一点：

```ts
protected AddRouting(router: Router): void {
}
```

现在我们有了`AddRouting`方法，我们需要编写代码来启动我们的服务器：

```ts
public Start(): void {
  this.app.use(bodyParser.json()); 
  this.app.use(bodyParser.urlencoded({extended:true}));
  const router: Router = express.Router();
  this.AddRouting(router);
  this.app.use(router);
  this.app.listen(this.port, ()=> console.log(`logged onto server at ${this.port}`));
}
```

您可能已经注意到，我们缺少一个重要的部分。我们的服务器中没有数据库支持，但我们的服务需要初始化 Firebase。在我们的服务器中，我们添加了以下内容：

```ts
public WithDatabase(): Server {
  firebase.initializeApp(Environment.fireBase);
  return this;
}
```

请注意，我没有在存储库中包含`Environment.fireBase`，因为它包含我使用的服务器和密钥的详细信息。这是一个包含 Firebase 连接信息的常量。您可以将其替换为您在云中创建 Firebase 数据库时设置的连接信息。要添加这个，您需要在`Common`文件夹中创建一个名为`Environment.ts`的文件，其中包含如下代码：

```ts
export const Environment = {
  fireBase: {
    apiKey: <<add your api key here>>,
    authDomain: "advancedtypescript3-containers.firebaseapp.com",
    databaseURL: "https://advancedtypescript3-containers.firebaseio.com",
    projectId: "advancedtypescript3-containers",
    storageBucket: "advancedtypescript3-containers.appspot.com",
    messagingSenderId: <<add your sender id here>>
  }
}
```

# 创建我们的 Addresses 服务

现在我们已经有了创建实际服务所需的一切。在这里，我们将看一下`Addresses`服务，理解其他服务将遵循相同的模式。由于我们已经有了数据模型、数据访问代码和路由，我们所要做的就是创建我们的实际`AddressesServer`类。`AddressesServer`类就是这么简单：

```ts
export class AddressesServer extends Server {
  protected AddRouting(router: Router): void {
    this.routingEngine.Add(GetAddressRouting, router);
    this.routingEngine.Add(SaveAddressRouting, router);
  }
}
```

我们这样启动服务器：

```ts
new AddressesServer()
  .WithCorsSupport()
  .WithDatabase().Start();
```

代码就是这么简单。我们尽可能地遵循一个叫做**不要重复自己**（**DRY**）的原则。这简单地表示您应该尽量少地重复输入代码。换句话说，您应该尽量避免在代码库中散布着完全相同的代码。有时候，您无法避免这种情况，有时候，为了一个或两行代码而费力地创建大量代码框架是没有意义的，但是当您有大型功能区域时，您绝对应该尽量避免将其复制粘贴到代码的多个部分中。部分原因是，如果您复制并粘贴了代码，随后发现了一个 bug，您将不得不在多个地方修复这个 bug。

# 使用 Docker 来运行我们的服务

当我们看我们的服务时，我们可以看到一个有趣的问题；即它们都使用相同的端口启动。显然，我们不能真的为每个服务使用相同的端口，那么我们是不是给自己造成了问题？这是否意味着我们不能启动多个服务，如果是这样，这是否会破坏我们的微服务架构，意味着我们应该回到单体服务？

鉴于我们刚刚讨论的潜在问题以及本章介绍了 Docker，毫不奇怪地得知 Docker 就是解决这个问题的答案。通过 Docker，我们可以启动一个容器，部署我们的代码，并使用不同的端点暴露服务。那么，我们该如何做到这一点呢？

在每个服务中，我们将添加一些常见的文件：

```ts
node_modules
npm-debug.log
```

第一个文件叫做`.dockerignore`，它选择在复制或添加文件到容器时要忽略的文件。

我们要添加的下一个文件叫做 `Dockerfile`。这个文件描述了 Docker 容器以及如何构建它。`Dockerfile` 通过构建一系列指令的层来构建容器。第一层在容器中下载并安装 Node，具体来说是 Node 版本 8：

```ts
FROM node:8
```

下一层用于设置默认工作目录。该目录用于后续命令，比如 `RUN`、`COPY`、`ENTRYPOINT`、`CMD` 和 `ADD`：

```ts
WORKDIR /usr/src/app
```

在一些在线资源中，你会看到人们创建自己的目录作为工作目录。最好使用预定义的、众所周知的位置，比如 `/usr/src/app` 作为 `WORKDIR`。

由于我们现在已经有了一个工作目录，我们可以开始设置代码了。我们想要复制必要的文件来下载和安装我们的 `npm` 包：

```ts
COPY package*.json ./
RUN npm install
```

作为一个良好的实践，我们在复制代码之前复制 `package.json` 和 `package-lock.json` 文件，因为安装会缓存安装的内容。只要我们不改变 `package.json` 文件，如果代码再次构建，我们就不需要重新下载包。

所以，我们的包已经安装好了，但是我们还没有任何代码。让我们将本地文件夹的内容复制到工作目录中：

```ts
COPY . .
```

我们想要将服务器端口暴露给外部世界，所以现在让我们添加这一层：

```ts
EXPOSE 3000
```

最后，我们想要启动服务器。为了做到这一点，我们想要触发 `npm start`：

```ts
CMD [ "npm", "start" ]
```

作为运行 `CMD["npm", "start"]` 的替代方案，我们可以完全绕过 `npm`，使用 `CMD ["node", "dist/server.js"]`（或者服务器代码叫什么）。我们考虑这样做的原因是，运行 `npm` 会启动 `npm` 进程，然后启动我们的服务器进程，所以直接使用 Node 减少了运行的服务数量。此外，`npm` 有一个擅自消耗进程退出信号的习惯，所以除非 `npm` 告诉它，Node 不知道进程已经退出。

现在，如果我们想要启动地址服务，例如，我们可以从命令行运行以下命令：

```ts
docker build -t ohanlon/addresses .
docker run -p 17171:3000 -d ohanlon/addresses
```

第一行使用 `Dockerfile` 构建容器镜像，并给它一个标签，这样我们就可以在 Docker 容器中识别它。

一旦镜像构建完成，下一个命令运行安装并将容器端口发布到主机。这个技巧是使我们的服务器代码工作的 *魔法*，它将内部端口 `3000` 暴露给外部世界作为 `17171`。请注意，我们在这两种情况下都使用 `ohanlon/addresses` 来将容器镜像与我们要运行的镜像绑定（你可以用任何你想要的名称替换这个名称）。

`-d` 标志代表分离，这意味着我们的容器在后台静默运行。这允许我们启动服务并避免占用命令行。

如果你想找到可用的镜像，可以运行 `docker ps` 命令。

# 使用 docker-compose 来组合和启动服务

我们不再使用 `docker build` 和 `docker run` 来运行我们的镜像，而是有一个叫做 `docker-compose` 的东西来组合和运行多个容器。使用 Docker 组合，我们可以从多个 docker 文件或者完全通过一个名为 `docker-compose.yml` 的文件创建我们的容器。

我们将使用 `docker-compose.yml` 和我们在上一节中创建的 Docker 文件的组合来创建一个可以轻松运行的组合。在服务器代码的根目录中，创建一个名为 `docker-compose.yml` 的空文件。我们将首先指定文件符合的组合格式。在我们的情况下，我们将把它设置为 `2.1`：

```ts
version: '2.1'
```

我们将在容器内创建三个服务，所以让我们首先定义这些服务本身：

```ts
services:
  chapter08_addresses:
  chapter08_people:
  chapter08_leads:
```

现在，每个服务由离散信息组成，其中的第一部分详细说明了我们要使用的构建信息。这些信息在一个构建节点下，并包括上下文，它映射到我们的服务所在的目录，以及 Docker 文件，它定义了我们如何构建容器。可选地，我们可以设置`NODE_ENV`参数来标识节点环境，我们将设置为`production`。我们的谜题的最后一部分映射回`docker run`命令，我们在其中设置端口映射；每个服务都可以设置自己的`ports`映射。这是放在`chapter08_addresses`下的节点的样子：

```ts
build: 
  context: ./Addresses
  dockerfile: ./Dockerfile
environment:
  NODE_ENV: production
ports: 
  - 17171:3000
```

当我们把所有这些放在一起时，我们的`docker-compose.yml`文件看起来像这样：

```ts
version: '2.1'

services:
  chapter08_addresses:
    build: 
      context: ./Addresses
      dockerfile: ./Dockerfile
    environment:
      NODE_ENV: production
    ports: 
      - 17171:3000
  chapter08_people:
    build: 
      context: ./People
      dockerfile: ./Dockerfile
    environment:
      NODE_ENV: production
    ports: 
      - 31313:3000
  chapter08_leads:
    build: 
      context: ./Leads
      dockerfile: ./Dockerfile
    environment:
      NODE_ENV: production
    ports: 
      - 65432:3000
```

在我们开始这些过程之前，我们必须编译我们的微服务。Docker 不负责构建应用程序，因此在尝试组合我们的服务之前，我们有责任先这样做。

现在，我们有多个容器可以使用一个组合文件一起启动。为了运行我们的组合文件，我们使用`docker-compose up`命令。当所有容器都启动后，我们可以使用`docker ps`命令验证它们的状态，这给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/6f71c67e-1999-4a26-8426-59829276ce7f.png)

我们现在已经完成了服务器端的代码。我们已经准备好了需要创建我们的微服务的一切。现在我们要做的是继续创建将与我们的服务交互的用户界面。

# 创建我们的 React 用户界面

我们花了很多时间构建 Angular 应用程序，所以回到构建 React 应用程序是公平的。就像 Angular 可以与 Express 和 Node 一起工作一样，React 也可以与它们一起工作，既然我们已经有了 Express/Node 端，现在我们要创建我们的 React 客户端。我们将从创建具有 TypeScript 支持的 React 应用程序的命令开始：

```ts
npx create-react-app crmclient --scripts-version=react-scripts-ts
```

这将创建一个标准的 React 应用程序，我们将修改以满足我们的需求。我们需要做的第一件事是引入对 Bootstrap 的支持，这次使用`react-bootstrap`包。在此期间，我们也可以安装以下依赖项——`react-table`、`@types/react-table`、`react-router-dom`、`@types/react-router-dom`和`axios`。我们将在本章中使用它们，因此现在安装它们将节省一些时间。

在本书中，我们一直在使用`npm`来安装依赖项，但这并不是我们唯一的选择。`npm`有一个优点，它是 Node 的默认包管理器（毕竟它叫 Node Package Manager），但 Facebook 在 2015 年推出了自己的包管理器，叫做 Yarn。Yarn 是为了解决当时`npm`版本存在的问题而创建的。Yarn 使用自己的一组锁文件，而不是`npm`使用的默认`package*.lock`。你使用哪一个取决于你的个人偏好和评估它们提供的功能是否是你需要的。对于我们的目的，`npm`是一个合适的包管理器，所以我们将继续使用它。

# 使用 Bootstrap 作为我们的容器

我们希望使用 Bootstrap 来渲染我们整个显示。幸运的是，这是一个微不足道的任务，围绕着对我们的`App`组件进行一些小修改。为了渲染我们的显示，我们将把内容包裹在一个容器内，就像这样：

```ts
export class App extends React.Component {
  public render() {
    return (
      <Container fluid={true}>
        <div />
      </Container>
    );
  }
}
```

现在，当我们渲染我们的内容时，它将自动渲染在一个容器内，该容器延伸到页面的整个宽度。

# 创建一个分页用户界面

在添加导航元素之前，我们将创建用户单击链接时将链接到的组件。我们将从`AddAddress.tsx`开始，我们将在其中添加代码以添加地址。我们首先添加类定义：

```ts
export class AddAddress extends React.Component<any, IAddress> {
}
```

我们组件的默认状态是一个空的`IAddress`，所以我们添加了它的定义，并将组件状态设置为我们的默认值：

```ts
private defaultState: Readonly<IAddress>;
constructor(props:any) {
  super(props);
  this.defaultState = {
    Line1: '',
    Line2: '',
    Line3: '',
    Line4: '',
    PostalCode: '',
    ServerID: '',
  };
  const address: IAddress = this.defaultState;
  this.state = address;
}
```

在我们添加代码来渲染表单之前，我们需要添加一些方法。正如您可能还记得我们上次学习 React 时，我们学到如果用户在显示中更改任何内容，我们必须显式更新状态。就像上次一样，我们将编写一个`UpdateBinding`事件处理程序，当用户更改显示中的任何值时我们将调用它。我们将在所有的`Add*xxx*`组件中看到这种模式重复出现。作为一个复习，ID 告诉我们用户正在更新哪个字段，然后我们使用它来设置状态中的适当字段与更新值。根据这些信息，我们的`event`处理程序看起来像这样：

```ts
private UpdateBinding = (event: any) => {
  switch (event.target.id) {
    case `address1`:
      this.setState({ Line1: event.target.value});
      break;
    case `address2`:
      this.setState({ Line2: event.target.value});
      break;
    case `address3`:
      this.setState({ Line3: event.target.value});
      break;
    case `address4`:
      this.setState({ Line4: event.target.value});
      break;
    case `zipcode`:
      this.setState({ PostalCode: event.target.value});
      break;
  }
}
```

我们需要添加的另一个支持方法是触发 REST 调用到我们的地址服务。我们将使用 Axios 包来传输一个`POST`请求到添加地址的端点。Axios 给我们提供了基于 promise 的 REST 调用，这样我们就可以，例如，发出调用并等待它返回再继续处理。我们将选择一个简单的代码模型，并以一种忘记即可的方式发送我们的请求，这样我们就不必等待任何结果返回。为了简单起见，我们将立即重置 UI 的状态，准备让用户添加另一个地址。

既然我们已经添加了这些方法，我们将编写我们的`render`方法。定义如下：

```ts
public render() {
  return (
    <Container>
  </Container>
  );
}
```

`Container`元素映射回我们从 Bootstrap 中习惯的好老容器类。这里缺少的是实际的输入元素。每个输入都被分组在`Form.Group`中，这样我们就可以添加`Label`和`Control`，就像这样：

```ts
<Form.Group controlId="formGridAddress1">
  <Form.Label>Address</Form.Label>
  <Form.Control placeholder="First line of address" id="address1" value={this.state.Line1} onChange={this.UpdateBinding} />
</Form.Group>
```

作为另一个提醒，绑定的当前值通过单向绑定呈现在我们的显示中，表示为`value={this.state.Line1}`，用户的任何输入都会通过`UpdateBinding`事件处理程序触发对状态的更新。

我们添加的用于保存状态的`Button`代码如下：

```ts
<Button variant="primary" type="submit" onClick={this.Save}>
  Submit
</Button>
```

把所有这些放在一起，这就是我们的`render`方法的样子：

```ts
public render() {
  return (
    <Container>
      <Form.Group controlId="formGridAddress1">
        <Form.Label>Address</Form.Label>
        <Form.Control placeholder="First line of address" id="address1" value={this.state.Line1} onChange={this.UpdateBinding} />
      </Form.Group>
      <Form.Group controlId="formGridAddress2">
        <Form.Label>Address 2</Form.Label>
        <Form.Control id="address2" value={this.state.Line2} onChange={this.UpdateBinding} />
      </Form.Group>
      <Form.Group controlId="formGridAddress2">
        <Form.Label>Address 3</Form.Label>
        <Form.Control id="address3" value={this.state.Line3} onChange={this.UpdateBinding} />
      </Form.Group>
      <Form.Group controlId="formGridAddress2">
        <Form.Label>Address 4</Form.Label>
        <Form.Control id="address4" value={this.state.Line4} onChange={this.UpdateBinding} />
      </Form.Group>
      <Form.Group controlId="formGridAddress2">
        <Form.Label>Zip Code</Form.Label>
        <Form.Control id="zipcode" value={this.state.PostalCode} onChange={this.UpdateBinding}/>
      </Form.Group>
      <Button variant="primary" type="submit" onClick={this.Save}>
        Submit
      </Button>
    </Container>
  )
}
```

那么，这段代码一切都好吗？嗯，不，`Save`代码有一个小问题。如果用户点击按钮，因为状态在`Save`方法中不可见，所以不会保存到数据库。当我们执行`onClick={this.Save}`时，我们正在为`Save`方法分配一个回调。内部发生的是`this`上下文丢失，所以我们无法使用它来获取状态。现在，我们有两种修复方法；一种是我们已经经常见到的，就是使用箭头函数`=>`来捕获上下文，以便我们的方法可以处理它。

解决这个问题的另一种方法（也是我们故意编写`Save`方法不使用箭头函数的原因，这样我们就可以看到这个方法的操作）是在构造函数中添加以下代码来绑定上下文：

```ts
this.Save = this.Save.bind(this);
```

好了，这就是我们添加地址的代码。我希望您会同意这是一个足够简单的代码；一次又一次，人们创造了不必要复杂的代码，而一般来说，简单是一个更有吸引力的选择。我非常喜欢使代码尽可能简单。行业中有一种习惯，就是试图使代码变得比必要复杂，只是为了给其他开发人员留下印象。我敦促人们避免这种诱惑，因为清晰的代码更加令人印象深刻。

我们用于管理地址的用户界面是分页的，所以我们有一个标签页负责添加地址，而另一个标签页显示一个包含我们当前添加的所有地址的网格。现在是时候添加标签页和网格代码了。我们将创建一个名为`addresses.tsx`的新组件，它为我们完成这些工作。

同样，我们首先创建我们的类。这次，我们将`state`设置为空数组。我们这样做是因为我们将稍后从我们的地址微服务中填充它：

```ts
export default class Addresses extends React.Component<any, any> {
  constructor(props:any) {
    super(props);
    this.state = {
      data: []
    }
  }
}
```

为了从我们的微服务加载数据，我们需要一个处理这个任务的方法。我们将再次使用 Axios，但这次我们将使用 promise 功能在从服务器返回时设置状态：

```ts
private Load(): void {
  axios.get("http://localhost:17171/get/").then(x =>
  {
    this.setState({data: x.data});
  });
}
```

现在的问题是，我们何时想要调用`Load`方法？我们不想在构造函数中尝试获取状态，因为那会减慢组件的构建速度，所以我们需要另一个点来检索这些数据。答案在于 React 组件的生命周期。组件在创建时经历几种方法。它们的顺序如下：

1.  `constructor();`

1.  `getDerivedStateFromProps();`

1.  `render();`

1.  `componentDidMount();`

我们要实现的效果是使用`render`显示组件，然后使用绑定更新要在表格中显示的值。这告诉我们我们想要在`componentDidMount`中加载我们的状态：

```ts
public componentWillMount(): void {
  this.Load(); 
};
```

我们确实有另一个潜在的触发更新的点。如果用户添加了一个地址，然后切换标签回到显示表格的标签，我们将希望自动检索更新后的地址列表。让我们添加一个方法来处理这个问题：

```ts
private TabSelected(): void {
  this.Load();
}
```

现在是时候添加我们的`render`方法了。为了保持简单，我们将分两个阶段添加；第一阶段是添加`Tab`和`AddAddress`组件。在第二阶段，我们将添加`Table`。

添加标签需要我们引入*Reactified* Bootstrap 标签组件。在我们的`render`方法中，添加以下代码：

```ts
return (
  <Tabs id="tabController" defaultActiveKey="show" onSelect={this.TabSelected}>
    <Tab eventKey="add" title="Add address">
      <AddAddress />
    </Tab>
    <Tab eventKey="show" title="Addresses">
      <Row>
      </Row>
    </Tab>
  </Tabs>
)
```

我们有一个`Tabs`组件，其中包含两个单独的`Tab`项。每个标签都被赋予一个`eventKey`，我们可以使用它来设置默认的活动键（在这种情况下，我们将其设置为`show`）。当选择一个标签时，我们触发数据的加载。我们将看到我们的`AddAddress`组件已经添加到`Add Address`标签中。

我们在这里要做的所有事情就是添加我们将用来显示地址列表的表格。我们将创建一个我们想要在表格中显示的列的列表。我们使用以下语法创建列列表，其中`Header`是将显示在列顶部的标题，`accessor`告诉 React 从数据行中选择哪个属性：

```ts
const columns = [{
  Header: 'Address line 1',
  accessor: 'Line1'
}, {
  Header: 'Address line 2',
  accessor: 'Line2'
}, {
  Header: 'Address line 3',
  accessor: 'Line4'
}, {
  Header: 'Address line 4',
  accessor: 'Line4'
}, {
  Header: 'Postal code',
  accessor: 'PostalCode'
}]
```

最后，我们需要在我们的`Addresses`标签中添加表格。我们将使用流行的`ReactTable`组件来显示表格。将以下代码放入`<Row></Row>`部分以添加它：

```ts
<Col>
  <ReactTable data={this.state.data} columns={columns} 
    defaultPageSize={15} pageSizeOptions = {[10, 30]} className="-striped -highlight" /></Col>
```

这里有一些有趣的参数。我们将`data`绑定到`this.state.data`，以便在状态改变时自动更新它。我们创建的列与`columns`属性绑定。我喜欢我们可以使用`defaultPageSize`控制每页显示多少行，以及让用户使用`pageSizeOptions`选择覆盖行数的功能。我们将`className`设置为`-striped -highlight`，这样显示就会在灰色和白色之间有条纹，当鼠标移动到表格上时，行高亮会显示鼠标停留在哪一行。

# 在添加一个人时使用选择控件选择地址

当用户想要添加一个人时，他们只需要输入他们的名字和姓氏。我们向用户显示一个选择框，其中填充了先前输入的地址列表。让我们看看如何使用 React 处理这样一个更复杂的场景。

我们需要做的第一件事是创建两个单独的组件。我们有一个`AddPerson`组件用于输入名字和姓氏，还有一个`AddressChoice`组件，用于检索和显示用户可以选择的完整地址列表。我们将从`AddressChoice`组件开始。

这个组件使用了一个自定义的`IAddressProperty`，它为我们提供了访问父组件的能力，这样我们就可以在这个组件改变值时触发当前选择的地址的更新：

```ts
interface IAddressProperty {
  CurrentSelection : (currentSelection:IAddress | null) => void;
}
export class AddressesChoice extends React.Component<IAddressProperty, Map<string, string>> {
}
```

我们告诉 React，我们的组件接受`IAddressProperty`作为组件的 props，并且`Map<string, string>`作为状态。当我们从服务器检索地址列表时，我们用这个地图填充地址；键用于保存`ServerID`，值保存地址的格式化版本。由于这背后的逻辑看起来有点复杂，我们将从加载地址的方法开始，然后再回到构造函数：

```ts
private LoadAddreses(): void {
  axios.get("http://localhost:17171/get/").then((result:AxiosResponse<any>) =>
  {
    result.data.forEach((person: any) => {
      this.options.set(person.ServerID, `${person.Line1} ${person.Line2} ${person.Line3} ${person.Line4} ${person.PostalCode}`);
    });
    this.addresses = { ...result.data };
    this.setState(this.options);
  });
}
```

我们首先向服务器发出请求，获取完整的地址列表。当我们收到列表后，我们将遍历地址，构建我们刚刚讨论过的格式化地图。我们用格式化地图填充状态，并将未格式化的地址复制到一个单独的地址字段中；我们这样做的原因是，虽然我们希望将格式化版本显示到显示器上，但当选择改变时，我们希望将未格式化的版本发送回给调用者。我们还可以通过其他方式实现这一点，但这是一个简单的有用的小技巧。

有了加载功能，我们现在可以添加我们的构造函数和字段：

```ts
private options: Map<string, string>;
private addresses: IAddress[] = [];
constructor(prop: IAddressProperty) {
  super(prop);
  this.options = new Map<string, string>();
  this.Changed = this.Changed.bind(this);
  this.state = this.options;
}
```

请注意，我们在这里有一个`changed`绑定，与我们在前一节讨论的`bind`代码保持一致。数据加载再次发生在`componentDidMount`中：

```ts
public componentDidMount() {
 this.LoadAddreses();
}
```

现在我们准备构建我们的渲染方法。为了简化构建选择项的条目的可视化，我们将这段代码分离成一个单独的方法。这个方法简单地遍历`this.options`列表，创建要添加到`select`控件的选项：

```ts
private RenderList(): any[] {
  const optionsTemplate: any[] = [];
  this.options.forEach((value, key) => (
    optionsTemplate.push(<option key={key} value={key}>{value}</option>)
  ));
  return optionsTemplate;
}
```

我们的渲染方法使用了一个选择`Form.Control`，它将`Select...`显示为第一个选项，然后从`RenderList`中渲染出列表：

```ts
public render() {
  return (<Form.Control as="select" onChange={this.Changed}>
    <option>Select...</option>
    {this.RenderList()}
  </Form.Control>)
}
```

细心的读者会注意到，我们已经两次引用了`Changed`方法，但实际上并没有添加它。这个方法接受选择值并使用它来查找未格式化的地址，如果找到了，就使用`props`来触发`CurrentSelection`方法：

```ts
private Changed(optionSelected: any) {
  const address = Object.values(this.addresses).find(x => x.ServerID === optionSelected.target.value);
  if (address) {
    this.props.CurrentSelection(address);
  } else {
    this.props.CurrentSelection(null);
  }
}
```

在我们的`AddPerson`代码中，`AddressesChoice`在渲染中被引用如下：

```ts
<AddressesChoice CurrentSelection={this.CurrentSelection} />
```

我们不打算覆盖`AddPerson`内部的其余内容。我建议跟随下载的代码来查看这个位置。我们也不打算覆盖其他组件；如果我们继续剖析其他组件，特别是因为它们大部分都遵循我们刚刚讨论过的控件的相同格式，这一章可能会变成一个长达一百页的怪物。

# 添加我们的导航

我们想要添加到我们客户端代码库的最后一部分代码是处理客户端导航的能力。我们在讨论 Angular 时已经看到了如何做到这一点，现在是时候看看如何根据用户选择的链接显示不同的页面。我们将使用 Bootstrap 导航和 React 路由操作的组合。我们首先创建一个包含我们导航的路由器：

```ts
const routing = (
  <Router>
    <Navbar bg="light">
      <Navbar.Collapse id="basic-navbar-nav">
        <Nav.Link href="/">Home</Nav.Link>
        <Nav.Link href="/contacts">Contacts</Nav.Link>
        <Nav.Link href="/leads">Leads</Nav.Link>
        <Nav.Link href="/addresses">Addresses</Nav.Link>
      </Navbar.Collapse>
    </Navbar>
  </Router>
)
```

我们留下了一个主页，这样我们就可以添加适当的文档和图片，如果我们想要*装饰*它，使它看起来像一个商业 CRM 系统。其他`href`元素将与路由器绑定，以显示适当的 React 组件。在`Router`内部，我们添加了将`path`映射到`component`的`Route`条目，因此，如果用户选择`Addresses`，例如，将显示`Addresses`组件：

```ts
<Route path="/" component={App} />
<Route path="/addresses" component={Addresses} />
<Route path="/contacts" component={People} />
<Route path="/leads" component={Leads} />
```

我们的`routing`代码现在看起来像这样：

```ts
const routing = (
  <Router>
    <Navbar bg="light">
      <Navbar.Collapse id="basic-navbar-nav">
        <Nav.Link href="/">Home</Nav.Link>
        <Nav.Link href="/contacts">Contacts</Nav.Link>
        <Nav.Link href="/leads">Leads</Nav.Link>
        <Nav.Link href="/addresses">Addresses</Nav.Link>
      </Navbar.Collapse>
    </Navbar>
    <Route path="/" component={App} />
    <Route path="/addresses" component={Addresses} />
    <Route path="/contacts" component={People} />
    <Route path="/leads" component={Leads} />
  </Router>
)
```

为了添加我们的导航，包括路由，我们进行了以下操作：

```ts
ReactDOM.render(
  routing,
  document.getElementById('root') as HTMLElement
);
```

就是这样。我们现在有一个客户端应用程序，可以与我们的微服务进行通信，并协调它们的结果，使它们一起工作，即使它们的实现是相互独立的。

# 总结

在这一点上，我们已经创建了一系列微服务。我们首先定义了一系列共享功能，然后以此为基础创建专业服务。这些服务都在 Node.js 中使用了相同的端口，这本应该给我们带来问题，但我们通过创建一系列 Docker 容器来解决了这个问题，启动我们的服务并将内部端口重定向到不同的外部端口。我们看到了如何创建相关的 Docker 文件和 Docker 组合文件来启动服务。

然后，我们创建了一个基于 React 的客户端应用程序，通过引入选项卡来使用更高级的布局，以将微服务的查看结果与向服务添加记录的能力分开。在这个过程中，我们还使用了 Axios 来管理我们的 REST 调用。

在进行 REST 调用时，我们看到了如何使用 Swagger 来定义我们的 REST API，并讨论了是否在我们的服务中使用 Swagger 提供的 API 代码。

在下一章中，我们将远离 React，看看如何创建一个与 TensorFlow 一起工作的 Vue 客户端，以自动执行图像分类。

# 问题

1.  什么是 Docker 容器？

1.  我们用什么来将 Docker 容器分组在一起启动它们，我们可以使用什么命令来启动它们？

1.  我们如何使用 Docker 将内部端口映射到不同的外部端口？

1.  Swagger 为我们提供了哪些功能？

1.  如果一个方法在 React 中看不到状态，我们需要做什么？

# 进一步阅读

+   如果您想了解有关 Docker 的更多信息，Earl Waud 的《Docker 快速入门指南》（[`www.packtpub.com/in/networking-and-servers/docker-quick-start-guide`](https://www.packtpub.com/in/networking-and-servers/docker-quick-start-guide)）是一个很好的起点。

+   如果您在 Windows 上运行 Docker，Elton Stoneman 的《Windows 上的 Docker-第二版》（[`www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition`](https://www.packtpub.com/virtualization-and-cloud/docker-windows-second-edition)）将是一个很大的帮助。

+   在这个阶段，我希望您对微服务的兴趣已经被激起。如果是这样，Paul Osman 的《微服务开发食谱》（[`www.packtpub.com/in/application-development/microservices-development-cookbook`](https://www.packtpub.com/in/application-development/microservices-development-cookbook)）应该是您继续前进所需要的。


# 第九章：使用 Vue.js 和 TensorFlow.js 进行图像识别

当前计算机领域最热门的话题之一是机器学习。在本章中，我们将进入机器学习的世界，使用流行的`TensorFlow.js`包进行图像分类，以及姿势检测。作为对 Angular 和 React 的改变，我们将转向 Vue.js 来提供我们的客户端实现。

本章将涵盖以下主题：

+   机器学习是什么，以及它与人工智能的关系

+   如何安装 Vue

+   使用 Vue 创建应用程序

+   使用 Vue 模板显示主页

+   在 Vue 中使用路由

+   **卷积神经网络**（**CNNs**）是什么

+   TensorFlow 中模型的训练方式

+   使用预训练的 TensorFlow 模型构建图像分类类

+   TensorFlow 支持的图像类型，用于图像分类和姿势检测

+   使用姿势检测显示身体关节

# 技术要求

完成的项目可以从[`github.com/PacktPublishing/Advanced-TypeScript-3-Programming-Projects/tree/master/chapter09`](https://github.com/PacktPublishing/Advanced-TypeScript-3-Programming-Projects/tree/master/chapter09)下载。本项目使用 TensorFlow，因此本章将使用以下额外组件：

+   `@tensorflow-models/mobilenet`

+   `@tensorflow-models/posenet`

+   `@tensorflow/tfjs`

我们还将在 Vue 中使用 Bootstrap，因此我们需要安装以下 Bootstrap 组件：

+   `bootstrap`

+   `bootstrap-vue`

下载项目后，您将需要使用`npm install`命令安装包要求。

# 什么是机器学习，TensorFlow 如何适用？

现在很难摆脱人工智能机器的概念。人们已经习惯于使用 Siri、Alexa 和 Cortana 等工具，这些工具给人一种科技能理解我们并与我们互动的假象。这些语音激活系统使用自然语言处理来识别句子，比如“今天 Kos 的天气如何？”

这些系统背后的魔力就是机器学习。为了选择其中一个系统，我们将快速查看 Alexa 在展示之前的工作，然后再看机器学习与人工智能的关系。

当我们问 Alexa 一个问题时，*她*会认出*她*的名字，这样她就知道应该开始倾听后面的内容以开始处理。这相当于在某人的肩膀上轻拍以引起他们的注意。然后 Alexa 会记录以下句子，直到达到一个点，Alexa 可以通过互联网将录音传输到 Alexa 语音服务。这项极其复杂的服务尽其所能地解析录音（有时，重口音可能会让服务混淆）。然后服务根据解析的录音进行操作，并将结果发送回您的 Alexa 设备。

除了回答关于天气的问题，Alexa 还有大量的技能供用户使用，亚马逊鼓励开发者创建超出他们有时间想出的技能。这意味着轻松订购披萨和查看最新的赛车结果一样容易。

这个序言引导我们开始接触机器学习与 Alexa 有什么关系。Alexa 背后的软件使用机器学习不断更新自己，所以每次出错时，都会反馈回去，这样系统在下一次变得*更聪明*，并且不会在未来犯同样的错误。

正如你可以想象的那样，解释语音是一项非常复杂的任务。这是我们作为人类从小就学会的东西，与机器学习的类比令人叹为观止，因为我们也是通过重复和强化来学习语音的。因此，当一个婴儿随机说出“爸爸”时，婴儿已经学会发出这些声音，但还不知道这个声音的正确语境。通常由父母指向自己来提供的强化用于将声音与人物联系起来。当我们使用图片书时，类似的强化也会发生；当我们教婴儿“牛”的时候，我们会指向一张牛的图片。这样，婴儿就学会将这个词与图片联系起来。

由于语音解释非常复杂，它需要大量的处理能力，也需要一个庞大的预先训练的数据集。想象一下，如果我们不得不教 Alexa 一切会有多么令人沮丧。这在一定程度上解释了为什么机器学习系统现在才真正开始发挥作用。我们现在有足够的基础设施，可以将计算卸载到可靠、强大和专用的机器上。此外，我们现在有足够强大和快速的互联网来处理传输到这些机器学习系统的大量数据。如果我们仍然使用 56K 调制解调器，我们肯定无法做到现在能做到的一半。

# 什么是机器学习？

我们知道计算机擅长是或否答案，或者说 1 和 0。这意味着计算机基本上无法回答“-ish”，因此它无法对问题回答“有点是”。请稍等片刻，这很快就会变得清楚。

在其最基本的层面上，我们可以说，机器学习归结为教计算机以我们相同的方式学习。它们学会解释来自各种来源的数据，并利用这种学习对数据进行分类。机器将从成功和失败中学习，从而使其更准确和能够进行更复杂的推断。

回到计算机处理是或否答案的想法，当我们得出一个答案，相当于“嗯，这取决于”的时候，我们基本上是基于相同的输入得出多个答案——相当于通过多种途径得出是或否的答案。机器学习系统在学习方面变得越来越好，因此它们背后的算法能够利用越来越多的数据，以及越来越多的强化来建立更深层次的联系。

在幕后，机器学习应用了一系列令人难以置信的算法和统计模型，以便系统可以执行一些任务，而无需详细说明如何完成这些任务。这种推断水平远远超出了我们传统构建应用程序的方式，这是因为，鉴于正确的数学模型，计算机非常擅长发现模式。除此之外，它们同时执行大量相关任务，这意味着支持学习的数学模型可以将其计算结果作为反馈输入，以便更好地理解世界。

在这一点上，我们必须提到 AI 和机器学习并不相同。机器学习是基于自动学习的 AI 应用，而无需为处理特定任务而进行编程。机器学习的成功基于系统学习所需的足够数量的数据。可以应用一些算法类型。有些被称为无监督学习算法，而其他一些被称为监督学习算法。

无监督算法接收以前未分类或标记的数据。这些算法在这些数据集上运行，以寻找潜在或隐藏的模式，这些模式可以用来创建推断。

监督学习算法利用其先前的学习，并使用标记的示例将其应用于新数据。这些标记的示例帮助它学习正确的答案。在幕后，有一个训练数据集，学习算法用它来完善他们的知识并学习。训练数据的级别越高，算法产生正确答案的可能性就越大。

还有其他类型的算法，包括强化学习算法和半监督学习算法，但这些超出了本书的范围。

# 什么是 TensorFlow，它与机器学习有什么关系？

我们已经讨论了机器学习是什么，如果我们试图自己实现它，可能会显得非常令人生畏。幸运的是，有一些库可以帮助我们创建自己的机器学习实现。最初由 Google Brain 团队创建，TensorFlow 是这样一个旨在支持大规模机器学习和数值计算的库。最初，TensorFlow 是作为混合 Python/C++库编写的，其中 Python 提供了用于构建学习应用程序的前端 API，而 C++端执行它们。TensorFlow 汇集了许多机器学习和神经网络（有时称为**深度学习**）算法。

鉴于原始 Python 实现的成功，我们现在有了一个用 TypeScript 编写的 TensorFlow 实现（称为`TensorFlow.js`），我们可以在我们的应用程序中使用。这是我们将在本章中使用的版本。

# 项目概述

我们将在本章中编写的项目是我在为这本书写提案时最激动人心的项目。我对所有 AI 相关的事物都有长期的热爱；这个主题让我着迷。随着`TensorFlow.js`等框架的兴起（我将简称为 TensorFlow），在学术界之外进行复杂的机器学习的能力从未如此容易获得。正如我所说，这一章真的让我兴奋，所以我们不仅仅使用一个机器学习操作——我们将使用图像分类来确定图片中的内容，并使用姿势检测来绘制关键点，如人体的主要关节和主要面部标志。

与 GitHub 代码一起工作，这个主题应该需要大约一个小时才能完成，完成后应该是这样的：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/55d8a477-ed6c-4ab5-bcd7-752183ee41b7.png)

现在我们知道我们要构建的项目是什么，我们准备开始实施。在下一节中，我们将开始安装 Vue。

# 在 Vue 中开始使用 TensorFlow

如果您尚未安装 Vue，则第一步是安装 Vue **命令行界面**（**CLI**）。使用以下命令使用`npm`安装：

```ts
npm install -g @vue/cli
```

# 创建基于 Vue 的应用程序

我们的 TensorFlow 应用程序将完全在客户端浏览器中运行。这意味着我们需要编写一个应用程序来托管 TensorFlow 功能。我们将使用 Vue 来提供我们的客户端，因此需要以下步骤来自动构建我们的 Vue 应用程序。

创建我们的客户端就像运行`vue create`命令一样简单，如下所示：

```ts
vue create chapter09
```

这开始了创建应用程序的过程。在进行客户端创建过程时，需要进行一些决策点，首先是选择是否接受默认设置或手动选择要添加的功能。由于我们想要添加 TypeScript 支持，我们需要选择手动选择功能预设。以下截图显示了我们将要进行的步骤，以选择我们 Vue 应用程序的功能：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/56bc69f3-88ed-4234-a191-fd175d22128c.png)

我们的项目可以添加许多功能，但我们只对其中一些感兴趣，所以取消选择 Babel，选择添加 TypeScript、Router、VueX 和 Linter / Formatter。通过使用空格键来进行选择/取消选择：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/f775f672-aba1-4246-bd40-b253649f4616.png)

当我们按下*Enter*时，将呈现出许多其他选项。按下*Enter*将为前三个选项设置默认值。当我们到达选择**linter**（缩写为**Lexical INTERpreter**）的选项时，请从列表中选择 TSLint，然后继续按*Enter*处理其他选项。linter 是一个自动解析代码的工具，寻找潜在问题。它通过查看我们的代码来检查是否违反了一组预定义的规则，这可能表明存在错误或代码样式问题。

当我们完成了整个过程，我们的客户端将被创建；这将需要一些时间来完成，因为有大量的代码需要下载和安装。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/b4cb17e8-85fa-472a-afd6-a6971ed16521.png)

现在我们的应用程序已经创建，我们可以在客户端文件夹的根目录中运行`npm run serve`来运行它。与 Angular 和 React 不同，浏览器不会默认显示页面，所以我们需要自己打开页面，使用`http://localhost:8080`。这样做时，页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/82e894fd-191f-4704-a6b0-d7c39d47429c.png)

当我们编写图像分类器时，我们将使生活更加轻松，因为我们将通过修改主页来展示我们的图像分类器的运行情况，从而重用 Vue CLI 为我们创建的一些现有基础设施。

# 显示带有 Vue 模板的主页

与 React 以`.jsx`/`.tsx`扩展名为我们提供将代码和网页放在一起的特殊扩展名类似，Vue 为我们提供了单文件组件，创建为`.vue`文件。这些文件允许我们将代码和网页模板混合在一起构建我们的页面。在继续创建我们的第一个 TensorFlow 组件之前，让我们打开我们的`Home.vue`页面并对其进行分析。

我们可以看到我们的`.vue`组件分为两个部分。有一个模板部分定义了将显示在屏幕上的 HTML 的布局，还有一个单独的脚本部分，我们在其中包含我们的代码。由于我们使用 TypeScript，我们的`script`部分的语言是`ts`。

脚本部分首先通过定义`import`部分开始，这与标准的`.ts`文件中看到的方式非常相似。在导入中看到`@`时，这告诉我们导入路径是相对于`src`目录的，因此`HelloWorld.vue`组件位于`src/components`文件夹中：

```ts
<script lang="ts">
import { Component, Vue } from 'vue-property-decorator';
import HelloWorld from '@/components/HelloWorld.vue';
</script>
```

接下来我们需要做的是创建一个从`Vue`类继承的类。我们使用`@Component`创建一个名为`Home`的组件注册，可以在其他地方使用：

```ts
@Component
export default class Home extends Vue {}
```

还有一件事情我们需要做。我们的模板将引用一个外部的`HelloWorld`组件。我们必须用模板将要使用的组件装饰我们的类，就像这样：

```ts
@Component({
  components: {
    HelloWorld,
  },
})
export default class Home extends Vue {}
```

模板非常简单。它由一个单一的`div`类组成，我们将在其中渲染`HelloWorld`组件：

```ts
<template>
  <div class="home">
    <HelloWorld />
  </div>
</template>
```

从前面的代码模板中，我们可以看到，与 React 不同，Vue 没有为我们提供一个明确的`render`函数来处理 HTML 和状态的渲染。相反，渲染的构建更接近于 Angular 模型，其中模板被解析为可以提供的内容。

我们提到 Angular 的原因是因为 Vue.js 最初是由 Evan You 开发的，他当时正在谷歌的 AngularJS 项目上工作；他想要创建一个性能更好的库。虽然 AngularJS 是一个很棒的框架，但它需要完全接受 Angular 生态系统才能使用（Angular 团队正在努力解决这个问题）。因此，虽然 Vue 利用了 Angular 的特性，比如模板，但它的影响力很小，你只需在现有代码中添加一个脚本标签，然后慢慢将现有代码迁移到 Angular。

Vue 从 React 中借鉴了一些概念，比如使用虚拟 DOM（我们在介绍 React 时讨论过）。Vue 也使用虚拟 DOM，但以稍微不同的方式实现，主要是 Vue 只重新渲染有变化的组件，而 React 默认情况下也会重新渲染子组件。

现在我们要修改`HelloWorld`组件，以便与 TensorFlow 一起使用。但在这之前，我们需要编写一些支持类来处理 TensorFlow 的重要工作。这些类在代码量上并不大，但非常重要。我们的`ImageClassifier`类以标准的类定义开始，如下所示：

```ts
export class ImageClassifier {
}
```

下一步是可选的，但如果应用程序在 Windows 客户端上运行，它对应用程序的稳定性有重大影响。在底层，TensorFlow 使用 WebGLTextures，但在 Windows 平台上创建 WebGLTextures 存在问题。为了解决这个问题，我们的构造函数需要修改如下：

```ts
constructor() {
  tf.ENV.set('WEBGL_PACK', false);
}
```

由于我们可以运行图像分类任意次数，我们将添加一个表示标准`MobileNet` TensorFlow 的私有变量：

```ts
private model: MobileNet | null = null;
```

# MobileNet 介绍

此时，我们需要稍微了解一下 CNN 的世界。`MobileNet`是一个 CNN 模型，因此稍微了解 CNN 是如何帮助我们理解它与我们解决的问题有关。不用担心，我们不会深入研究 CNN 背后的数学，但了解一点它们的工作原理将有助于我们欣赏它们为我们带来了什么。

CNN 分类器通过接收输入图像（可能来自视频流），处理图像，并将其分类到预定义的类别中。为了理解它们的工作原理，我们需要退后一步，从计算机的角度思考问题。假设我们有一张马的照片。对于计算机来说，那张照片只是一系列像素，所以如果我们展示一张稍微不同的马的照片，计算机无法仅通过比较像素来判断它们是否匹配。

CNN 将图像分解成片段（比如 3x3 像素的网格），并比较这些片段。简单地说，它寻找的是这些片段能够匹配的数量。匹配的数量越多，我们就越有信心有一个匹配。这是对 CNN 的一个非常简化的描述，它涉及多个步骤和滤波器，但它应该有助于理解为什么我们想要在 TensorFlow 中使用`MobileNet`这样的 CNN。

`MobileNet`是一个专门的 CNN，除其他功能外，它为我们提供了针对 ImageNet 数据库中的图像进行训练的图像分类（[`www.image-net.org/`](http://www.image-net.org/)）。当我们加载模型时，我们加载的是一个为我们创建的预训练模型。我们使用预训练网络的原因是它已经在服务器上的大型数据集上进行了训练。我们不希望在浏览器中运行图像分类训练，因为这将需要从服务器到浏览器传输太多负载以执行训练。因此，无论您的客户端 PC 有多强大，复制训练数据集都会太多。

我们提到了`MobileNetV1`和`MobileNetV2`，但没有详细介绍它们是什么以及它们是在什么数据集上训练的。基本上，`MobileNet`模型是由谷歌开发的，并在 ImageNet 数据集上进行了训练，该数据集包含了 140 万张图像，分为 1000 类图像。之所以称这些模型为`MobileNet`模型，是因为它们是针对移动设备进行训练的，因此它们被设计为在低功耗和/或低存储设备上运行。

使用预训练模型，我们可以直接使用它，或者我们可以自定义它以用于迁移学习。

# 分类方法

现在我们对 CNN 有了一点了解，我们准备将这些知识付诸实践。我们将创建一个异步分类方法。当 TensorFlow 需要检测图像时，它可以使用多种格式，因此我们将概括我们的方法，只接受适当的类型：

```ts
public async Classify(image: tf.Tensor3D | ImageData | HTMLImageElement | 
HTMLCanvasElement | HTMLVideoElement):   Promise<TensorInformation[] | null> {
}
```

这些类型中只有一个是特定于 TensorFlow 的——`Tensor3D`类型。所有其他类型都是标准的 DOM 类型，因此可以在网页中轻松消耗，而无需跳过许多环节将图像转换为适当的格式。

我们还没有介绍我们的`TensorInformation`接口。当我们从`MobileNet`接收分类时，我们会收到一个分类名称和一个分类的置信水平。这作为`Promise<Array<[string, number]>>`从分类操作返回，因此我们将其转换为对我们的消费代码更有意义的东西：

```ts
export interface TensorInformation {
  className: string;
  probability: number; }
```

现在我们知道我们将返回一个分类数组和一个概率（置信水平）。回到我们的`Classify`方法，如果以前没有加载`MobileNet`，我们需要加载它。这个操作可能需要一段时间，这就是为什么我们对它进行缓存，这样我们下次调用这个方法时就不必重新加载它了：

```ts
if (!this.model) {   this.model = await mobilenet.load();  }
```

我们已经接受了`load`操作的默认设置。如果需要，我们可以提供一些选项：

+   `version`：这设置了`MobileNet`的版本号，默认为 1。现在，可以设置两个值：`1`表示我们使用`MobileNetV1`，`2`表示我们使用`MobileNetV2`。对我们来说，版本之间的区别实际上与模型的准确性和性能有关。

+   `alpha`：这可以设置为`0.25`、`0.5`、`0.75`或`1`。令人惊讶的是，这与图像上的`alpha`通道无关。相反，它指的是将要使用的网络宽度，有效地以性能换取准确性。数字越高，准确性越高。相反，数字越高，性能越慢。`alpha`的默认值为`1`。

+   `modelUrl`：如果我们想要使用自定义模型，我们可以在这里提供。

如果模型成功加载，那么我们现在可以执行图像分类。这是对`classify`方法的直接调用，传入我们方法中传递的`image`。完成此操作后，我们返回分类结果的数组：

```ts
if (this.model) {   const result = await this.model.classify(image);   return {   ...result,  };  }
```

`model.classify`方法默认返回三个分类，但如果需要，我们可以传递参数返回不同数量的分类。如果我们想要检索前五个结果，我们将更改`model.classify`行如下：

```ts
const result = await this.model.classify(image, 5);
```

最后，如果模型加载失败，我们将返回`null`。有了这个设置，我们完成的`Classify`方法如下所示：

```ts
public async Classify(image: tf.Tensor3D | ImageData | HTMLImageElement | 
HTMLCanvasElement | HTMLVideoElement):   Promise<TensorInformation[] | null> {   if (!this.model) {   this.model = await mobilenet.load();  }   if (this.model) {   const result = await this.model.classify(image);   return {   ...result,  };  }   return null;  }
```

TensorFlow 确实可以如此简单。显然，在幕后，隐藏了大量的复杂性，但这就是设计良好的库的美妙之处。它们应该保护我们免受复杂性的影响，同时为我们留出空间，以便在需要时进行更复杂的操作和定制。

这样，我们的图像分类组件就写好了。但是我们如何在 Vue 应用程序中使用它呢？在下一节中，我们将看到如何修改`HelloWorld`组件以使用这个类。

# 修改 HelloWorld 组件以支持图像分类

当我们创建 Vue 应用程序时，CLI 会为我们创建一个`HelloWorld.vue`文件，其中包含`HelloWorld`组件。我们将利用我们已经有这个组件的事实，并将其用于对预加载图像进行分类。如果我们愿意，我们可以使用它来使用文件上传组件加载图像，并在更改时驱动分类。

现在，让我们看看我们的`HelloWorld` TypeScript 代码是什么样子的。显然，我们将从类定义开始。就像我们之前看到的那样，我们已经用`@Component`装饰器标记了这个组件：

```ts
@Component export default class HelloWorld extends Vue {
}
```

我们有两个成员变量要在我们的类中声明。我们知道我们想要使用刚刚编写的`ImageClassifier`类，所以我们会引入它。我们还想创建一个`TensorInformation`结果数组，原因是我们将不得不在操作完成时绑定到它：

```ts
private readonly classifier: ImageClassifier = new ImageClassifier();  private tensors : TensorInformation[] | null = null;
```

在我们完成编写我们的类之前，我们需要看一下我们的模板会是什么样子。我们从`template`定义开始：

```ts
<template>
 <div class="container">
 </div> </template>
```

正如我们所看到的，我们正在使用 Bootstrap，所以我们将使用一个`div`容器来布置我们的内容。我们要添加到容器中的第一件事是一个图像。我选择在这里使用一组边境牧羊犬的图像，主要是因为我是狗的粉丝。为了我们能够在 TensorFlow 中读取这个图像，我们需要将`crossorigin`设置为`anonymous`。在这一部分中特别注意`ref="dogId"`，因为我们很快会再次需要它：

```ts
<img crossorigin="anonymous" id="img" src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQ0ucPLLnB4Pu1kMEs2uRZISegG5W7Icsb7tq27blyry0gnYhVOfg" alt="Dog" ref="dogId" >
```

在图像之后，我们将进一步添加 Bootstrap 支持，使用`row`和`col`类：

```ts
<div class="row">  <div class="col">  </div>  </div>
```

在这一行内，我们将创建一个 Bootstrap 列表。我们看到 Vue 有自己的 Bootstrap 支持，所以我们将使用它的版本来支持列表，即`b-list-group`：

```ts
<b-list-group>  </b-list-group>
```

现在，我们终于到了模板的实质部分。我们在类中公开张量数组的原因是为了在数组被填充时能够迭代每个结果。在下面的代码中，我们使用`v-for`动态创建了`b-list-group-item`的数量，以自动迭代每个张量项。这创建了`b-list-group-item`条目，但我们仍然需要显示单独的`className`和`probability`项。使用 Vue，我们使用`{{ <<item>> }}`来绑定文本项，比如这样：

```ts
<b-list-group-item v-for="tensor in tensors" v-bind:key="tensor.className">   {{ tensor.className }} - {{ tensor.probability }}
</b-list-group-item>
```

我们之所以在`v-for`旁边添加了`v-bind:key`，是因为 Vue 默认提供了所谓的**原地修补**。这意味着 Vue 使用这个键作为提示，以唯一地跟踪该项，以便在更改时保持值的最新状态。

就是这样；我们的模板完成了。正如我们所看到的，以下是一个简单的模板，但其中有很多内容。我们有一个 Bootstrap 容器显示一个图像，然后让 Vue 动态绑定`tensor`的细节：

```ts
<template>
 <div class="container">
 <img crossorigin="anonymous" id="img" src="https://encrypted-  
      tbn0.gstatic.com/imagesq=tbn:ANd9GcQ0ucPLLnB4Pu1kMEs2uRZ
      ISegG5W7Icsb7tq27blyry0gnYhVOfg" alt="Dog" ref="dogId" >
 <div class="row">
 <div class="col">
 <b-list-group>
 <b-list-group-item v-for="tensor in tensors" 
              v-bind:key="tensor.className">
  {{ tensor.className }} - {{ tensor.probability }}
          </b-list-group-item>
 </b-list-group>
 </div>
 </div>
 </div> </template>
```

回到我们的 TypeScript 代码，我们将编写一个方法，该方法获取图像，然后使用它调用我们的`ImageClassifier.Classify`方法：

```ts
public Classify(): void {
}
```

由于我们正在将图像加载到客户端上，我们必须等待页面呈现图像，以便我们可以检索它。我们将从构造函数中调用我们的`Classify`方法，因此在页面创建时运行，我们需要使用一个小技巧来等待图像加载。具体来说，我们将使用一个名为`nextTick`的 Vue 函数。重要的是要理解 DOM 的更新是异步发生的。当值发生变化时，更改不会立即呈现。相反，Vue 请求 DOM 更新，然后由计时器触发。因此，通过使用`nextTick`，我们等待下一个 DOM 更新时刻并执行相关操作：

```ts
public Classify(): void {   this.$nextTick().then(async () => {  });  }
```

我们在`then`块内标记`async`函数的原因是，我们将在此部分执行等待，这意味着我们也必须将其作为`async`范围。

在模板中，我们使用`ref`语句定义了我们的图像，因为我们希望从类内部访问它。为此，我们在这里查询 Vue 为我们维护的`ref`语句映射，由于我们已经设置了自己的引用为`dogId`，我们现在可以访问图像。这个技巧使我们不必使用`getElementById`来检索我们的 HTML 元素。

```ts
/* tslint:disable:no-string-literal */  const dog = this.$refs['dogId'];  /* tslint:enable:no-string-literal */
```

在构建 Vue 应用程序时，CLI 会自动为我们设置 TSLint 规则。其中一个规则涉及通过字符串字面量访问元素。我们可以使用`tslint:disable:no-string-literal`临时禁用该规则。要重新启用该规则，我们使用`tslint:enable:no-string-literal`。还有一种禁用此规则的替代方法是在单行上使用`/* tslint:disable-next-line:no-string-literal */`。您采取的方法并不重要；重要的是最终结果。

一旦我们有了对狗图片的引用，我们现在可以将图像转换为`HTMLImageElement`，并在`ImageClassifier`类中的`Classify`方法调用中使用它：

```ts
if (dog !== null && !this.tensors) {   const image = dog as HTMLImageElement;   this.tensors = await this.classifier.Classify(image);  }
```

当`Classify`调用返回时，只要模型已加载并成功找到分类，它将通过绑定的力量填充我们的屏幕列表。

在我们的示例中，我尽量保持我们的代码库尽可能干净和简单。代码已分离为单独的类，以便我们可以创建小而强大的功能块。要了解为什么我喜欢这样做，这是我们的`HelloWorld`代码的样子：

```ts
@Component export default class HelloWorld extends Vue {
  private readonly classifier: ImageClassifier = new ImageClassifier();
  private tensors: TensorInformation[] | null = null;    constructor() {
  super();
  this.Classify();
 }  public Classify(): void {
  this.$nextTick().then(async () => {
  /* tslint:disable:no-string-literal */
  const dog = this.$refs['dogId'];
  /* tslint:enable:no-string-literal */
  if (dog !== null && !this.tensors) {
  const image = dog as HTMLImageElement;
  this.tensors = await this.classifier.Classify(image);
 } }); } }
```

总共，包括`tslint`格式化程序和空格，这段代码只有 20 行。我们的`ImageClassifier`类只有 22 行，这是一个可以在其他地方使用而无需修改的`ImageClassifier`类。通过保持类简单，我们减少了它们可能出错的方式，并增加了重用它们的机会。更重要的是，我们遵循了名为**保持简单，愚蠢**（**KISS**）原则，该原则指出系统在本质上尽可能简单时效果最好。

现在我们已经看到图像分类的实际操作，我们可以考虑将姿势检测添加到我们的应用程序中。在这样做之前，我们需要看一下其他一些对我们重要的 Vue 领域。

# Vue 应用程序入口点

我们还没有涉及的是 Vue 应用程序的入口点是什么。我们已经看到了`Home.vue`页面，但那只是一个在其他地方呈现的组件。我们需要退一步，看看我们的 Vue 应用程序实际上是如何处理加载自身并显示相关组件的。在这个过程中，我们还将涉及 Vue 中的路由，以便我们可以看到所有这些是如何联系在一起的。

我们的起点位于`public`文件夹内。在那里，我们有一个`index.html`文件，我们可以将其视为应用程序的主模板。这是一个相当标准的 HTML 文件-我们可能希望给它一个更合适的`title`（在这里，我们选择`Advanced TypeScript - Machine Learning`）：

```ts
<!DOCTYPE html> <html lang="en">
 <head>
 <meta charset="utf-8">
 <meta http-equiv="X-UA-Compatible" content="IE=edge">
 <meta name="viewport" content="width=device-width,
      initial-scale=1.0">
 <link rel="icon" href="<%= BASE_URL %>favicon.ico">
 <title>Advanced TypeScript - Machine Learning</title>
 </head>
 <body>
 <noscript>
 <strong>We're sorry but chapter09 doesn't work properly without 
        JavaScript enabled. Please enable it to continue.</strong>
 </noscript>
 <div id="app"></div>
  <!-- built files will be auto injected -->
  </body> </html>
```

这里的重要元素是`div`，其`id`属性设置为`app`。这是我们将要呈现组件的元素。我们控制这个的方式是从`main.ts`文件中进行的。让我们首先通过添加 Bootstrap 支持来添加 Bootstrap 支持，既通过添加 Bootstrap CSS 文件，又通过使用`Vue.use`注册`BootstrapVue`插件：

```ts
import 'bootstrap/dist/css/bootstrap.css'; import 'bootstrap-vue/dist/bootstrap-vue.css';  Vue.use(BootstrapVue); 
```

尽管我们已经有了 Bootstrap 支持，但我们没有任何东西将我们的组件连接到`app div`。我们添加此支持的原因是创建一个新的 Vue 应用程序。这接受一个路由器，一个用于包含 Vue 状态和突变等内容的 Vue 存储库，以及一个`render`函数，在呈现组件时调用。传递给我们的`render`方法的`App`组件是我们将用于呈现所有其他组件的顶级`App`组件。当 Vue 应用程序创建完成时，它被挂载到`index.html`中的`app` div 中：

```ts
new Vue({
  router,
  store,
  render: (h) => h(App), }).$mount('#app'); 
```

我们的`App.vue`模板由两个独立的区域组成。在添加这些区域之前，让我们定义`template`元素和包含的`div`标签：

```ts
<template>
 <div id="app">
  </div>
</template>
```

在这个`div`标签中，我们将添加我们的第一个逻辑部分——我们的老朋友，导航栏。由于这些来自 Vue Bootstrap 实现，它们都以`b-`为前缀，但现在不需要解剖它们，因为到这一点它们应该非常熟悉：

```ts
<b-navbar toggleable="lg" type="dark" variant="info">  <b-collapse id="nav-collapse" is-nav>  <b-navbar-nav>  <b-nav-item to="/">Classifier</b-nav-item>  <b-nav-item to="/pose">Pose</b-nav-item>  </b-navbar-nav>  </b-collapse>  </b-navbar>
```

用户导航到页面时，我们需要显示适当的组件。在幕后，显示的组件由 Vue 路由器控制，但我们需要一个地方来显示它。这是通过在我们的导航栏下方使用以下标签来实现的：

```ts
<router-view/>
```

这是我们的`App`模板完成后的样子。正如我们所看到的，如果我们想要路由到其他页面，我们需要将单独的`b-nav-item`条目添加到此列表中。如果我们愿意，我们可以使用`v-for`以类似的方式动态创建这个导航列表，就像我们在构建图像分类器视图时看到的那样：

```ts
<template>
 <div id="app">
 <b-navbar toggleable="lg" type="dark" variant="info">
 <b-collapse id="nav-collapse" is-nav>
 <b-navbar-nav>
 <b-nav-item to="/">Classifier</b-nav-item>
 <b-nav-item to="/pose">Pose</b-nav-item>
 </b-navbar-nav>
 </b-collapse>
 </b-navbar>
 <router-view/>
 </div> </template>
```

当我们开始研究路由时，可能会认为将路由添加到我们的应用程序是一件非常复杂的事情。到现在为止，你应该对路由更加熟悉了，而且不会感到惊讶，因为在 Vue 中添加路由支持是直接而简单的。我们首先通过以下命令在 Vue 中注册`Router`插件：

```ts
Vue.use(Router);
```

有了这个，我们现在准备构建路由支持。我们导出一个`Router`的实例，可以在我们的`new Vue`调用中使用：

```ts
export default new Router({ });
```

现在我们需要添加我们的路由选项。我们要设置的第一个选项是路由模式。我们将使用 HTML5 `history` API 来管理我们的链接：

```ts
mode: 'history',
```

我们可以使用 URL 哈希进行路由。这在 Vue 支持的所有浏览器中都可以工作，并且如果 HTML5 `history` API 不可用，则是一个不错的选择。或者，还有一种抽象的路由模式，可以在包括 Node 在内的所有 JavaScript 环境中工作。如果浏览器 API 不存在，无论我们将模式设置为什么，路由器都将自动强制使用这个模式。

我们想要使用`history` API 的原因是它允许我们修改 URL 而不触发整个页面的刷新。由于我们知道我们只想替换组件，而不是替换整个`index.html`页面，我们最终利用这个 API 只重新加载页面的组件部分，而不进行整个页面的重新加载。

我们还想设置应用程序的基本 URL。如果我们想要覆盖此位置以从`deploy`文件夹中提供所有内容，那么我们将其设置为`/deploy/`：

```ts
base: process.env.BASE_URL,
```

虽然设置路由模式和基本 URL 都很好，但我们错过了重要的部分——设置路由本身。每个路由至少包含一个路径和一个组件。路径与 URL 中的路径相关联，组件标识将作为该路径结果显示的组件。我们的路由看起来像这样：

```ts
routes: [  {   path: '/',   name: 'home',   component: Home,  },  {   path: '/pose',   name: 'Pose',   component: Pose,  }, {
    path: '*',
    component: Home,
  } ],
```

我们的路由中有一个特殊的路径匹配。如果用户输入一个不存在的 URL，那么我们使用`*`来捕获它，并将其重定向到特定的组件。我们必须将其放在最后一个条目，否则它将优先于精确匹配。敏锐的读者会注意到，严格来说，我们不需要第一个路径，因为我们的路由仍然会显示`Home`组件，因为我们的`*`回退。

我们在路由中添加了一个指向尚不存在的组件的引用。现在我们将通过添加`Pose`组件来解决这个问题。

# 添加姿势检测功能

在开始处理姿势检测之前，我们将添加一个组件，该组件将承载相关功能。由于这是我们第一个*从头开始*的组件，我们也将从头开始介绍它。在我们的`views`文件夹中，创建一个名为`Pose.vue`的文件。这个文件将包含三个逻辑元素，所以我们将首先添加这些元素，并设置我们的模板以使用 Bootstrap：

```ts
<template>
  <div class="container">
  </div>
</template>
<script lang="ts">
</script>
<style scoped>
</style>
```

到目前为止，我们还没有看过的是`style`部分。作用域样式允许我们应用仅适用于当前组件的样式。我们很快将应用本地样式，但首先，我们需要设置要显示的图像。

对于我们的示例代码，我选择了一张宽 1200 像素，高 675 像素的图片。这些信息很重要，因为当我们进行姿势检测时，我们将在图像上绘制这些点，这意味着我们需要进行一些样式安排，以便在图像上放置一个画布，我们可以在上面绘制与图像上的位置匹配的点。我们首先使用两个容器来容纳我们的图像：

```ts
<div class="outsideWrapper">  <div class="insideWrapper">  </div>
</div>
```

我们现在要在我们的样式作用域部分添加一些 CSS 来固定尺寸。我们首先设置外部包装器的尺寸，然后相对于外部包装器定位我们的内部包装器，并将宽度和高度设置为 100%，以便它们完全填充边界：

```ts
.outsideWrapper{   width:1200px; height:675px;  }  .insideWrapper{   width:100%; height:100%;   position:relative;  }
```

回到`insideWrapper`，我们需要在其中添加我们的图像。我选择的示例图像是一个中性姿势，显示了关键身体点。我们的图像标签的格式应该看起来很熟悉，因为我们已经用图像分类代码做过这个：

```ts
<img crossorigin="anonymous" class="coveredImage" id="img" src="https://www.yogajournal.com/.image/t_share/MTQ3MTUyNzM1MjQ1MzEzNDg2/mountainhp2_292_37362_cmyk.jpg" alt="Pose" ref="poseId" >
```

在相同的`insideWrapper` `div`标签中，就在我们的图像下面，我们需要添加一个画布。当我们想要绘制关键身体点时，我们将使用这个画布。关键是画布的宽度和高度与容器的尺寸完全匹配：

```ts
<canvas ref="posecanvas" id="canvas" class="coveringCanvas" width=1200 height=675></canvas>
```

在这一点上，我们的`template`看起来像这样：

```ts
<template>
 <div class="container">
 <div class="outsideWrapper">
 <div class="insideWrapper">
 <img crossorigin="anonymous" class="coveredImage" 
          id="img" src="https://www.yogajournal.com/.image/t_share/
          MTQ3MTUyNzM1MjQ1MzEzNDg2/mountainhp2_292_37362_cmyk.jpg" 
          alt="Pose" ref="poseId" >
 <canvas ref="posecanvas" id="canvas" 
          class="coveringCanvas" width="1200" height="675"></canvas>
 </div>
 </div>
 </div> </template> 
```

我们已经为图像和画布添加了类，但我们还没有添加它们的定义。我们可以使用一个类来覆盖两者，但我对我们分别设置宽度和高度为 100%的类感到满意，并将它们绝对定位在容器内部：

```ts
.coveredImage{   width:100%; height:100%;   position:absolute; 
  top:0px; 
  left:0px;  }  .coveringCanvas{   width:100%; height:100%;   position:absolute; 
  top:0px; left:0px;  }
```

我们完成后，样式部分将如下所示：

```ts
<style scoped>
 .outsideWrapper{
  width:1200px; height:675px;
 } .insideWrapper{
  width:100%; height:100%;
  position:relative;
 } .coveredImage{
  width:100%; height:100%;
  position:absolute; 
 top:0px; 
 left:0px;
 } .coveringCanvas{
  width:100%; height:100%;
  position:absolute; 
 top:0px; 
 left:0px;
 } </style> 
```

在这一点上，我们需要编写一些辅助类——一个用于进行姿势检测，另一个用于在图像上绘制点。

# 在画布上绘制关键点

每当我们检测到一个姿势，我们都会得到一些关键点。每个关键点由位置（*x*和*y*坐标）、分数（或置信度）和关键点表示的实际部分组成。我们希望循环遍历这些点并在画布上绘制它们。

一如既往，让我们从我们的课程定义开始：

```ts
export class DrawPose { }
```

我们只需要获取一次画布元素，因为它不会改变。这表明我们可以将这个作为我们的画布，因为我们对画布的二维元素感兴趣，我们可以直接从画布中提取绘图上下文。有了这个上下文，我们清除画布上以前绘制的任何元素，并将`fillStyle`颜色设置为`#ff0300`，我们将用它来填充我们的姿势点：

```ts
constructor(private canvas: HTMLCanvasElement, private context = canvas.getContext('2d')) {   this.context!.clearRect(0, 0, this.canvas.offsetWidth, this.canvas.offsetHeight);   this.context!.fillStyle = '#ff0300';  }
```

为了绘制我们的关键点，我们编写一个方法，循环遍历每个`Keypoint`实例，并调用`fillRect`来绘制点。矩形从*x*和*y*坐标偏移 2.5 像素，以便绘制一个 5 像素的矩形实际上是在点的大致中心绘制一个矩形：

```ts
public Draw(keys: Keypoint[]): void {   keys.forEach((kp: Keypoint) => {   this.context!.fillRect(kp.position.x - 2.5, 
                           kp.position.y - 2.5, 5, 5);  });  }
```

完成后，我们的`DrawPose`类如下所示：

```ts
export class DrawPose {
  constructor(private canvas: HTMLCanvasElement, private context = 
    canvas.getContext('2d')) {
  this.context!.clearRect(0, 0, this.canvas.offsetWidth, 
        this.canvas.offsetHeight);
  this.context!.fillStyle = '#ff0300';
 }    public Draw(keys: Keypoint[]): void {
  keys.forEach((kp: Keypoint) => {
  this.context!.fillRect(kp.position.x - 2.5, 
                             kp.position.y - 2.5, 5, 5);
 }); } }
```

# 在图像上使用姿势检测

之前，我们创建了一个`ImageClassifier`类来执行图像分类。为了保持这个类的精神，我们现在要编写一个`PoseClassifier`类来管理物理姿势检测：

```ts
export class PoseClassifier {
}
```

我们将为我们的类设置两个私有成员。模型是一个`PoseNet`模型，在调用相关的加载方法时将被填充。`DrawPose`是我们刚刚定义的类：

```ts
private model: PoseNet | null = null;  private drawPose: DrawPose | null = null;
```

在我们进一步进行姿势检测代码之前，我们应该开始了解姿势检测是什么，它适用于什么，以及一些约束是什么。

# 关于姿势检测的简要说明

我们在这里使用术语**姿势检测**，但这也被称为**姿势估计**。如果你还没有接触过姿势估计，这简单地指的是计算机视觉操作，其中检测到人物形象，无论是从图像还是视频中。一旦人物被检测到，模型就能大致确定关键关节和身体部位（如左耳）的位置。

姿势检测的增长速度很快，它有一些明显的用途。例如，我们可以使用姿势检测来进行动作捕捉以制作动画；工作室越来越多地转向动作捕捉，以捕捉现场表演并将其转换为 3D 图像。另一个用途在体育领域；事实上，体育运动有许多潜在的动作捕捉用途。假设你是一支大联盟棒球队的投手。姿势检测可以用来确定在释放球时你的站姿是否正确；也许你倾斜得太远，或者你的肘部位置不正确。有了姿势检测，教练们更容易与球员合作纠正潜在问题。

在这一点上，值得注意的是，姿势检测并不等同于人物识别。我知道这似乎很明显，但有些人被这项技术所困惑，以为这种技术可以识别一个人是谁。那是完全不同的机器学习形式。

# PoseNet 是如何工作的？

即使使用基于摄像头的输入，执行姿势检测的过程也不会改变。我们从输入图像开始（视频的一个静止画面就足够了）。图像通过 CNN 进行第一部分处理，识别场景中人物的位置。下一步是将 CNN 的输出传递给姿势解码算法（我们稍后会回到这一点），并使用它来解码姿势。

我们之所以说*姿势解码算法*是为了掩盖我们实际上有两个解码算法的事实。我们可以检测单个姿势，或者如果有多个人，我们可以检测多个姿势。

我们选择了单姿势算法，因为它是更简单和更快的算法。如果图片中有多个人，算法有可能将不同人的关键点合并在一起；因此，遮挡等因素可能导致算法将人 2 的右肩检测为人 1 的左肘。在下面的图片中，我们可以看到右侧女孩的肘部遮挡了中间人的左肘：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/2d6da8aa-084f-4de7-aa17-509e2f214ad3.png)

遮挡是指图像的一部分遮挡了另一部分。

`PoseNet`检测到的关键点如下：

+   鼻子

+   左眼

+   右眼

+   左耳

+   右耳

+   左肩

+   右肩

+   左肘

+   右肘

+   左腕

+   右腕

+   左臀

+   右臀

+   左膝

+   右膝

+   左踝

+   右踝

我们可以看到它们在我们的应用程序中的位置。当它完成检测点时，我们会得到一组图像叠加，如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/8bbfe2de-3b60-43e1-98b1-2075ccf2e1ba.png)

# 回到我们的姿势检测代码

回到我们的`PoseClassifier`类，我们的构造函数处理了与我们的`ImageClassifier`实现讨论过的完全相同的 WebGLTexture 问题：

```ts
constructor() {   // If running on Windows, there can be issues 
  // loading WebGL textures properly.  // Running the following command solves this.   tf.ENV.set('WEBGL_PACK', false);  }
```

我们现在要编写一个异步的`Pose`方法，它会返回一个`Keypoint`项的数组，或者如果`PoseNet`模型加载失败或找不到任何姿势，则返回`null`。除了接受图像，这个方法还将接受提供上下文的画布，我们将在上面绘制我们的点：

```ts
public async Pose(image: HTMLImageElement, canvas: HTMLCanvasElement): Promise<Keypoint[] | null> {   return null;  }
```

就像`ImageClassifier`检索`MobileNet`模型一样，我们将检索`PoseNet`模型并对其进行缓存。我们将利用这个机会来实例化`DrawPose`实例。执行这样的逻辑是为了确保这是我们只做一次的事情，无论我们调用这个方法多少次。一旦模型不为空，代码就会阻止我们尝试再次加载`PoseNet`：

```ts
if (!this.model) {   this.model = await posenet.load();   this.drawPose = new DrawPose(canvas);  }
```

当我们加载模型时，我们可以提供以下选项：

+   **Multiplier**：这是所有卷积操作的通道数（深度）的浮点乘数。可以选择 1.01、1.0、0.75 或 0.50。这里有速度和准确性的权衡，较大的值更准确。

最后，如果模型成功加载，我们将使用我们的图像调用`estimateSinglePose`来检索`Pose`预测，其中还包含我们将绘制的`keypoints`：

```ts
if (this.model) {   const result: Pose = await this.model.estimateSinglePose(image);   if (result) {   this.drawPose!.Draw(result.keypoints);   return result.keypoints;  }  }
```

再次将所有这些放在一起，以展示我们不必写大量代码来完成所有这些工作，以及将代码分离成小的、自包含的逻辑块，使我们的代码更容易理解，也更容易编写。这是完整的`PoseClassifier`类：

```ts
export class PoseClassifier {
  private model: PoseNet | null = null;
  private drawPose: DrawPose | null = null;
  constructor() {
  // If running on Windows, there can be 
    // issues loading WebGL textures properly.
 // Running the following command solves this.  tf.ENV.set('WEBGL_PACK', false);
 }    public async Pose(image: HTMLImageElement, canvas: 
    HTMLCanvasElement): Promise<Keypoint[] | null> {
  if (!this.model) {
  this.model = await posenet.load();
  this.drawPose = new DrawPose(canvas);
 }    if (this.model) {
  const result: Pose = await 
             this.model.estimateSinglePose(image);
  if (result) {
  this.drawPose!.Draw(result.keypoints);
  return result.keypoints;
 } }  return null;
 } }
```

# 完成我们的姿势检测组件

回到我们的`Pose.vue`组件，现在我们需要填写`script`部分。我们需要以下`import`语句和组件的类定义（记住我承诺过我们会从头开始构建这个类）。同样，我们可以看到使用`@Component`来给我们一个组件注册。我们在 Vue 组件中一次又一次地看到这一点：

```ts
import { Component, Vue } from 'vue-property-decorator';  import {PoseClassifier} from '@/Models/PoseClassifier';  import {Keypoint} from '@tensorflow-models/posenet';  @Component  export default class Pose extends Vue {
}
```

我们已经到了可以编写我们的`Classify`方法的地步，当图像和画布被创建时，它将检索图像和画布，并将其传递给`PoseClassifier`类。我们需要一些私有字段来保存`PoseClassifier`实例和返回的`Keypoint`数组：

```ts
private readonly classifier: PoseClassifier = new PoseClassifier();  private keypoints: Keypoint[] | null;
```

在我们的`Classify`代码中，我们将使用相同的生命周期技巧，在检索名为`poseId`的图像引用和名为`posecanvas`的画布之前等待`nextTick`：

```ts
public Classify(): void {   this.$nextTick().then(async () => {   /* tslint:disable:no-string-literal */   const pose = this.$refs['poseId'];   const poseCanvas = this.$refs['posecanvas'];   /* tslint:enable:no-string-literal */  });  }
```

一旦我们有了图像引用，我们将它们转换为适当的`HTMLImageElement`和`HTMLCanvasElement`类型，然后调用`Pose`方法，并用结果值填充我们的`keypoints`成员：

```ts
if (pose !== null) {   const image: HTMLImageElement = pose as HTMLImageElement;   const canvas: HTMLCanvasElement = poseCanvas as HTMLCanvasElement   this.keypoints = await this.classifier.Pose(image, canvas);  }
```

在这一点上，我们可以运行应用程序。看到`keypoints`结果叠加在图像上非常令人满意，但我们可以做得更多。只需稍加努力，我们就可以在 Bootstrap 表格中显示`keypoints`结果。返回到我们的模板，并添加以下`div`语句以在图像下方添加 Bootstrap 行和列：

```ts
<div class="row">  <div class="col">  </div>  </div>
```

由于我们已经暴露了`keypoints`结果，我们可以简单地使用`b-table`创建一个 Vue Bootstrap 表格。我们使用`:items`将绑定设置为我们在类中定义的`keypoints`结果。这意味着每当`keypoints`条目获得新值时，表格将更新以显示这些值。

```ts
<b-table striped hover :items="keypoints"></b-table>
```

刷新我们的应用程序会在图像下方添加表格，表格如下所示：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/0e3e8bd3-753d-4108-bd61-fa17d61ffe87.png)

虽然这是一个合理的开始，但如果我们能更多地控制表格就更好了。目前，`b-table`自动捕捉并格式化字段。通过小小的改变，我们可以将`Position`实例分离为两个单独的条目，并使`Score`和`Part`字段可排序。

在我们的`Pose`类中，我们将创建一个`fields`条目。`fields`条目将分数条目映射到`Confidence`标签，并将其设置为`sortable`。`part`字段映射到`Part`的`label`值，并且也设置为`sortable`。我们将`position`分为两个单独的映射条目，分别标记为`X`和`Y`：

```ts
private fields =  {'score':  { label: 'Confidence', sortable: true},   'part':  { label: 'Part', sortable: true},   'position.x':  {label:'X'},   'position.y': {label: 'Y'}};
```

我们需要做的最后一件事是将`fields`输入连接到`b-table`。我们可以使用`:fields`属性来实现这一点，就像这样：

```ts
<b-table striped hover :items="keypoints" :fields="fields"></b-table>
```

刷新我们的应用程序会显示这些微小更改的效果。这是一个更具吸引力的屏幕，用户可以轻松地对`Confidence`（原名`score`）和`Part`字段进行排序，这显示了 Vue 的强大之处：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/adv-ts-prog-pj/img/afc205c4-af29-4c59-b390-b0afb12d4398.png)

就是这样——我们已经介绍了 TensorFlow 和 Vue。我们避开了 CNN 背后的数学方面，因为尽管乍一看可能令人生畏，但实际上并没有那么糟糕，但典型的 CNN 有很多部分。Vue 还有很多功能可以使用；对于一个如此小的库来说，它非常强大，这种小巧和强大的组合是它变得越来越受欢迎的原因之一。

# 总结

在本章中，我们迈出了使用流行的`TensorFlow.js`库编写机器学习应用程序的第一步。除了了解机器学习是什么，我们还看到了它如何适用于人工智能领域。虽然我们编写了类来连接到`MobileNet`和姿势检测库，但我们也介绍了 CNN 是什么。

除了研究`TensorFlow.js`，我们还开始了使用 Vue.js 的旅程，这是一个正在迅速赢得人气的客户端库，与 Angular 和 React 并驾齐驱。我们看到了如何使用`.vue`文件，以及如何将 TypeScript 与 Web 模板结合使用，包括使用 Vue 的绑定语法。

在下一章中，我们将迈出一大步，看看如何将 TypeScript 与 ASP.NET Core 结合起来，构建一个将 C#与 TypeScript 结合的音乐库。

# 问题

1.  TensorFlow 最初是用哪些语言发布的？

1.  什么是监督式机器学习？

1.  什么是`MobileNet`？

1.  默认情况下，我们会返回多少个分类？

1.  我们用什么命令来创建 Vue 应用程序？

1.  我们如何在 Vue 中表示一个组件？

# 进一步阅读

Packt 有大量关于 TensorFlow 的书籍和视频，如果您想提高对 TensorFlow 的了解。这些书籍不仅限于`TensorFlow.js`，因此涵盖了与 TensorFlow 最初实现相关的各种主题。以下是我推荐的一些书籍：

+   《TensorFlow 强化学习快速入门指南》（https://www.packtpub.com/in/big-data-and-business-intelligence/tensorflow-reinforcement-learning-quick-start-guide）：使用 Python 培训和部署智能和自学习代理，作者是 Kaushik Balakrishnan：ISBN 978-1789533583。

+   《TensorFlow 机器学习项目》（https://www.packtpub.com/big-data-and-business-intelligence/tensorflow-machine-learning-projects）：使用 Python 生态系统进行高级数值计算，构建 13 个真实世界项目，作者是 Ankit Jain 和 Amita Kapoor：ISBN 978-1789132212。

+   《使用 TensorFlow 2 进行计算机视觉实践》（https://www.packtpub.com/in/application-development/hands-computer-vision-tensorflow-2）：利用深度学习和 Keras 创建强大的图像处理应用，作者是 Benjamin Planche 和 Eliot Andres：ISBN 978-1788830645。

除了 TensorFlow，我们还研究了使用 Vue，因此以下内容也将有助于进一步提高您的知识：

+   《Vue CLI 3 快速入门指南》（https://www.packtpub.com/in/web-development/vue-cli-3-quick-start-guide）作者是 Ajdin Imsirovic：ISBN 978-1789950342。
