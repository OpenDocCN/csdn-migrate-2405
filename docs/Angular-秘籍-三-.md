# Angular 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7`](https://zh.annas-archive.org/md5/B1FA96EFE213EFF9E25A2BF507BCADB7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：*第五章*：Angular 和 RxJS - 令人敬畏的组合

Angular 和 RxJS 结合起来，创造了一种令人敬畏的组合。通过结合它们，您可以以响应式的方式处理数据，处理流，并在 Angular 应用程序中执行非常复杂的操作。这正是您将在本章中学到的内容。

以下是本章将要涵盖的示例：

+   使用实例方法处理 RxJS 操作符

+   使用静态方法处理 RxJS 操作符

+   取消订阅流以避免内存泄漏

+   使用`async`管道与 Observable 同步绑定数据到您的 Angular 模板

+   使用`combineLatest`同时订阅多个流

+   使用`flatMap`操作符创建顺序的**超文本传输协议**（**HTTP**）调用

+   使用`switchMap`操作符将最后一个订阅切换为新的订阅

+   使用 RxJS 进行去抖动 HTTP 请求

# 技术要求

对于本章的示例，请确保您的计算机上已安装了**Git**和**Node.js**。您还需要安装`@angular/cli`包，可以在终端中使用`npm install -g @angular/cli`来安装。本章的代码可以在以下链接找到：[`github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter05`](https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter05)。

# 使用实例方法处理 RxJS 操作符

在这个示例中，您将学习如何使用 RxJS 操作符的实例方法来处理流。我们将从一个基本应用程序开始，在该应用程序中，您可以使用`interval`方法开始监听流。然后，我们将在订阅中引入一些实例方法来修改输出。

## 准备工作

我们将要处理的项目位于`chapter05/start_here/rxjs-operators-instance-methods`，在克隆的存储库中。

1.  在**Visual Studio Code**（**VS Code**）中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序。点击**开始流**按钮，您应该会看到类似这样的东西：

![图 5.1 - rxjs-operators-instance-methods 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.1_B15150.jpg)

图 5.1 - rxjs-operators-instance-methods 应用程序在 http://localhost:4200 上运行

现在应用程序正在运行，我们将继续进行示例的步骤。

## 操作步骤…

我们有一个 Angular 应用程序，已经设置了一些东西。通过点击**开始流**按钮，我们可以开始查看使用 RxJS 的`interval`方法创建输出从`0`开始的数字序列的 Observable 的流输出。我们将使用一些操作符来显示来自我们的`inputStreamData`数组的元素，这是本教程的目标。让我们开始吧。

1.  首先，我们将使用`map`操作符确保我们将从`interval` Observable 生成的数字映射到我们数组的有效索引。为此，我们将更新`app.component.ts`文件。

我们必须确保映射的数字不大于或等于`inputStreamData`的长度。我们将使用`map`操作符每次对数字取模来做到这一点，如下所示：

```ts
import { Component } from '@angular/core';
import { interval, Subscription } from 'rxjs';
import { map } from 'rxjs/operators';
@Component({...})
export class AppComponent {
...
  startStream() {
    this.subscription = streamSource
    .pipe(
      map(output => output % this.inputStreamData.      length),
    )
    .subscribe(input => {
      this.outputStreamData.push(input);
    });
...
}
```

如果现在点击**开始流**按钮，您会看到我们得到的输出是`0, 1, 2, 0, 1, 2`...等等。这确保我们始终可以使用数字作为索引从`inputStreamData`数组中获取项目：

![图 5.2 - 流使用 inputStreamData.length 上的模数输出 0,1,2..序列](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.2_B15150.jpg)

图 5.2 - 流使用 inputStreamData.length 上的模数输出 0,1,2..序列

1.  现在，我们将使用另一个`map`方法来获取数组中每个流输出的元素，如下所示：

```ts
  startStream() {
    const streamSource = interval(1500);
    this.subscription = streamSource
    .pipe(
      map(output => output % this.inputStreamData.      length),
      map(index => this.inputStreamData[index])
    )
    .subscribe(element => {
      this.outputStreamData.push(element);
    });
  }
```

请注意，我们已将`subscribe`方法的参数重命名为`element`而不是`input`。这是因为最终我们得到了一个元素。请参阅以下屏幕截图，演示了流如何使用索引输出来自`inputStreamData`的元素：

![图 5.3 - 流使用索引从 inputStreamData 输出元素](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.3_B15150.jpg)

图 5.3 - 流使用索引从 inputStreamData 输出元素

1.  现在，为了使事情更有趣，我们将创建另一个流，使用相同的`interval`方法来发出卡通标题，但间隔为`1000ms`。将以下代码添加到您的`startStream`方法中：

```ts
  startStream() {
    const streamSource = interval(1500);
    const cartoonStreamSource = interval(1000)
      .pipe(
        map(output => output % this.cartoonsStreamData.        length),
        map(index => this.cartoonsStreamData[index]),
      )
    this.subscription = streamSource
    .pipe(...)
    .subscribe(...);
  }
```

1.  我们还将在`AppComponent`类中创建名为`cartoonStreamData`的流数据（在先前的代码中使用）。代码应该是这样的：

```ts
export class AppComponent {
  subscription: Subscription = null;
  inputStreamData = ['john wick', 'inception',   'interstellar'];
  cartoonsStreamData = ['thunder cats', 'Dragon Ball Z',   'Ninja Turtles'];
  outputStreamData = [];
  ...
}
```

1.  现在我们已经将`cartoonsStreamData`流数据放在了适当的位置，我们还可以将其添加到模板中，以便我们也可以在视图上显示它。在`app.component.html`中`<div class="input-stream">`元素的子元素应该是这样的：

```ts
    <div class="input-stream">
      <div class="input-stream__item" *ngFor="let item       of inputStreamData">
        {{item}}
      </div>
      <hr/>
      <div class="input-stream__item" *ngFor="let item       of cartoonsStreamData">
        {{item}}
      </div>
    </div>
```

1.  现在，我们将使用 `merge`（实例）方法来合并这两个流，并在流发出值时从各自的流数据数组中添加一个元素。有趣，对吧？

我们将使用以下代码来实现这一点：

```ts
...
import { map, merge } from 'rxjs/operators';
export class AppComponent {
  ...
  startStream() {
    ...
    this.subscription = streamSource
    .pipe(
      map(output => output % this.inputStreamData.      length),
      map(index => this.inputStreamData[index]),
      merge(cartoonStreamSource)
    )
    .subscribe(element => {
      this.outputStreamData.push(element);
    });
  }
}
```

重要提示

使用 `merge` 方法作为实例方法的用法已被弃用，推荐使用静态的 `merge` 方法。

太棒了！您现在已经实现了整个食谱，实现了两个流的有趣合并。以下截图显示了最终输出：

![图 5.4 – 食谱的最终输出](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.4_B15150.jpg)

图 5.4 – 食谱的最终输出

让我们继续下一节，了解它是如何工作的。

## 工作原理…

`map` 操作符为您提供了流的输出值，您应该返回要将其映射到的值。我们确保通过取数组长度的模数将自动生成的顺序数字转换为数组的索引。然后，我们在这些索引之上使用另一个 `map` 操作符来获取数组中的实际元素。最后，我们创建了另一个流，并使用 `merge` 方法来合并这两个流的输出，并将其添加到 `outputStreamData` 数组中。

## 另请参阅

+   *抓住小点游戏*—RxJS 文档（[`www.learnrxjs.io/learn-rxjs/recipes/catch-the-dot-game`](https://www.learnrxjs.io/learn-rxjs/recipes/catch-the-dot-game)）

+   RxJS `map` 操作符文档（[`www.learnrxjs.io/learn-rxjs/operators/transformation/map`](https://www.learnrxjs.io/learn-rxjs/operators/transformation/map)）

+   RxJS `merge` 操作符文档（[`www.learnrxjs.io/learn-rxjs/operators/combination/merge`](https://www.learnrxjs.io/learn-rxjs/operators/combination/merge)）

# 使用静态方法处理 RxJS 操作符

在这个食谱中，您将学习使用 RxJS 操作符的静态方法来处理流。我们将从一个基本应用程序开始，在该应用程序中，您可以使用 `interval` 方法开始监听流。然后，我们将在订阅中引入一些静态方法来修改输出，以在**用户界面**（**UI**）上看到它。之后，我们将使用 `partition` 静态操作符来拆分流。最后，我们将使用 `merge` 静态操作符来合并分区流，以查看它们的输出。

## 准备工作

此食谱的项目位于 `chapter05/start_here/rxjs-operators-static-methods`。

1.  在 VS Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这将在新的浏览器标签中打开应用程序，你应该能够看到类似这样的东西：

![图 5.5 – rxjs-operators-static-methods 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.5_B15150.jpg)

图 5.5 – rxjs-operators-static-methods 应用程序在 http://localhost:4200 上运行

我们还有以下数据，其中包括电影和卡通，这将是流的输出结果：

```ts
combinedStreamData = [{
    type: 'movie',
    title: 'john wick'
  }, {
    type: 'cartoon',
    title: 'Thunder Cats'
  }, {
    type: 'movie',
    title: 'inception'
  }, {
    type: 'cartoon',
    title: 'Dragon Ball Z'
  }, {
    type: 'cartoon',
    title: 'Ninja Turtles'
  }, {
    type: 'movie',
    title: 'interstellar'
  }];
```

现在应用程序在本地运行，让我们在下一节中看一下配方的步骤。

## 如何做…

我们手头有一个 Angular 应用程序，其中有一个名为`combinedStreamData`的数组中有一些数据。通过点击**开始流**按钮，我们可以开始查看流在**电影**输出部分和**卡通**输出部分的输出。我们将使用`partition`和`merge`操作符来获得期望的输出，并且还会显示当前输出的电影和卡通数量。让我们开始吧。

1.  首先，我们将从 RxJS 中导入`partition`和`merge`操作符（与之前的配方不同，我们不是从`rxjs/operators`中导入）。在`app.component.ts`文件中，导入应该如下所示：

```ts
import { Component } from '@angular/core';
import { interval, partition, merge, Subscription } from 'rxjs';
```

1.  现在，我们将在`AppComponent`类中创建两个属性，`movies`和`cartoons`，一个用于保存电影，一个用于保存卡通：

```ts
import { Component } from '@angular/core';
import { interval, partition, merge, Subscription } from 'rxjs';
import { map, tap } from 'rxjs/operators';
export class AppComponent {
  …
  outputStreamData = [];
  movies= []
  cartoons= [];
  startStream() {
  }
  ...
}
```

1.  现在，我们将在模板中使用适当的变量来表示电影和卡通，步骤如下：

```ts
<div class="cards-container">
    <div class="input-stream">
      ...
    <div class="output-stream">
      <h6>Movies</h6>
      <div class="input-stream__item" *ngFor="let movie       of movies">
        {{movie}}
      </div>
    </div>
    <div class="output-stream">
      <h6>Cartoons</h6>
      <div class="input-stream__item" *ngFor="let cartoon       of cartoons">
        {{cartoon}}
      </div>
    </div>
  </div>
```

1.  现在我们将使用`partition`操作符从`streamSource`属性创建两个流。你的`startStream`方法应该如下所示：

```ts
startStream() {
    const streamSource = interval(1500).pipe(
      map(input => {
        const index = input % this.combinedStreamData.        length;
        return this.combinedStreamData[index];
      })
    );
    const [moviesStream, cartoonsStream] = partition(
      streamSource, item => item.type === 'movie'
    );
    this.subscription = streamSource
      .subscribe(input => {
        this.outputStreamData.push(input);
      });
  }
```

现在我们已经将流拆分，我们可以合并它们以订阅单个流，推送到适当的输出数组，并将值记录到控制台输出。

1.  现在让我们合并这些流，然后使用`tap`操作符将它们添加到适当的输出数组中，步骤如下：

```ts
startStream() {
   ...
    this.subscription = merge(
      moviesStream.pipe(
        tap(movie => {
          this.movies.push(movie.title);
        })
      ),
      cartoonsStream.pipe(
        tap(cartoon => {
          this.cartoons.push(cartoon.title);
        })
      ),
    )
      .subscribe(input => {
        this.outputStreamData.push(input);
      });
  }
```

通过这个改变，你应该能够在适当的容器中看到正确的数值——也就是说，无论是电影还是卡通。请参考以下截图，显示了分区流如何向适当的 Observables 发出数值：

![图 5.6 – 分区流将数据输出到适当的视图](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.6_B15150.jpg)

图 5.6 – 分区流将数据输出到适当的视图

1.  最后，由于我们已经合并了流，我们可以使用`console.log`来查看每个输出的值。我们将从`AppComponent`中删除`outputStreamData`属性，并在`subscribe`块中使用`console.log`语句而不是推送到`outputStreamData`，如下所示：

```ts
...
@Component({...})
export class AppComponent {
  ...
  outputStreamData = []; ← Remove
  movies = [];
  cartoons = [];
  ngOnInit() {}
  startStream() {
    const streamSource = interval(1500).pipe(
      map(...)
    );
    const [moviesStream, cartoonsStream] =     partition(...);
    this.subscription = merge(
      moviesStream.pipe(...),
      cartoonsStream.pipe(...)
    ).subscribe((output) => {
      console.log(output);
    });
  }
  ...
}
```

一旦刷新应用程序，您应该在控制台上看到如下日志：

![图 5.7 - 合并流中订阅块中每个输出的控制台日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.7_B15150.jpg)

图 5.7 - 合并流中订阅块中每个输出的控制台日志

太棒了！现在你知道如何使用 RxJS 的静态操作符（特别是`partition`和`merge`）来处理实际用例中的流。请参阅下一节，了解其工作原理。

## 工作原理…

RxJS 有一堆静态操作符/方法，我们可以根据特定的用例来使用。在这个示例中，我们使用`partition`操作符根据作为第二个参数提供的`predicate`函数创建了两个不同的流，它返回一个包含两个 Observables 的数组。第一个将包含满足谓词的所有值，第二个将包含不满足谓词的所有值。*为什么要分割流？*很高兴你问。因为我们需要在不同的输出容器中显示适当的输出。而且很棒的是，我们后来合并了这些流，这样我们只需要订阅一个流，然后也可以取消订阅这个流。

## 另请参阅

+   RxJS `map`操作符文档（[`www.learnrxjs.io/learn-rxjs/operators/transformation/map`](https://www.learnrxjs.io/learn-rxjs/operators/transformation/map)）

+   RxJS `merge`操作符文档（[`www.learnrxjs.io/learn-rxjs/operators/combination/merge`](https://www.learnrxjs.io/learn-rxjs/operators/combination/merge)）

+   RxJS `partition`操作符文档（[`www.learnrxjs.io/learn-rxjs/operators/transformation/partition`](https://www.learnrxjs.io/learn-rxjs/operators/transformation/partition)）

# 取消订阅流以避免内存泄漏

流很有趣，而且很棒，当你完成这一章时，你会对 RxJS 有更多了解，尽管在不小心使用流时会出现问题。在处理流时最大的错误之一是在不再需要时不取消订阅它们，而在这个示例中，您将学习如何取消订阅流以避免在 Angular 应用程序中出现内存泄漏。

## 准备工作

此配方的项目位于`chapter05/start_here/rxjs-unsubscribing-streams`中。

1.  在 VS Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序，您应该会看到类似于这样的东西：

![图 5.8 – rxjs-unsubscribing-streams 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.8_B15150.jpg)

图 5.8 – rxjs-unsubscribing-streams 应用程序在 http://localhost:4200 上运行

现在我们的应用程序在本地运行，让我们在下一节中看一下配方的步骤。

## 如何做…

我们目前有一个具有两个路由的应用程序，即**主页**和**关于**。这是为了向您展示未处理的订阅可能会导致应用程序内存泄漏。默认路由是**主页**，在`HomeComponent`类中，我们处理一个使用`interval`方法输出数据的单个流。

1.  点击**开始流**按钮，您应该看到流发出值。

1.  然后，通过点击页眉（右上角）的**关于**按钮导航到**关于**页面，然后返回到**主页**。

你看到了什么？什么都没有？一切看起来都很好，对吧？嗯，并不完全是这样。

1.  为了查看我们是否有未处理的订阅（这是一个问题），让我们在`home.component.ts`文件中的`startStream`方法内放置一个`console.log`，具体来说，在`.subscribe`方法的块内，如下所示：

```ts
...
export class HomeComponent implements OnInit {
  ...
  startStream() {
    const streamSource = interval(1500);
    this.subscription = streamSource.subscribe(input => {
      this.outputStreamData.push(input);
      console.log('stream output', input)
    });
  }
  stopStream() {...}
}
```

如果您现在执行与*步骤 1*中提到的相同步骤，您将在控制台上看到以下输出：

![图 5.9 – rxjs-unsubscribing-streams 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.9_B15150.jpg)

图 5.9 – rxjs-unsubscribing-streams 应用程序在 http://localhost:4200 上运行

想要再玩一些吗？尝试执行*步骤 1*几次，甚至不刷新页面一次。你将看到**混乱**！

1.  因此，为了解决这个问题，我们将使用最简单的方法，即在用户从路由中导航离开时取消订阅流。让我们实现`ngOnDestroy`生命周期方法，如下所示：

```ts
import { Component, OnInit, OnDestroy } from '@angular/core';
...
@Component({
  selector: 'app-home',
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.scss']
})
export class HomeComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
  }
  ngOnDestroy() {
    this.stopStream();
  }
  startStream() {
    const streamSource = interval(1500);
    this.subscription = streamSource.subscribe(input => {
      this.outputStreamData.push(input);
      console.log('stream output', input)
    });
  }
  stopStream() {
    this.subscription.unsubscribe();
    this.subscription = null;
  }
}
```

太好了！如果您再次按照*步骤 1*的说明操作，您会发现一旦从**主页**导航离开，控制台上就不会再有进一步的日志输出，我们的应用程序现在没有未处理的流导致内存泄漏。阅读下一节以了解其工作原理。

## 工作原理…

当我们创建一个 Observable/流并订阅它时，RxJS 会自动将我们提供的`.subscribe`方法块添加为 Observable 的处理程序。因此，每当 Observable 发出值时，我们的方法应该被调用。有趣的是，当组件卸载或从路由导航离开时，Angular 不会自动销毁该订阅/处理程序。这是因为 Observable 的核心是 RxJS，而不是 Angular，因此处理它不是 Angular 的责任。

Angular 提供了某些生命周期方法，我们使用了`OnDestroy`（`ngOnDestroy`）方法。这是因为当我们从一个路由导航离开时，Angular 会销毁该路由，这时我们希望取消订阅所有已订阅的流。

## 还有更多...

在一个复杂的 Angular 应用程序中，会有一些情况下，您可能会在一个组件中有多个订阅，并且当组件被销毁时，您希望一次清理所有这些订阅。同样，您可能希望根据某些事件/条件取消订阅，而不是`OnDestroy`生命周期。这是一个例子，您手头有多个订阅，并且希望在组件销毁时一起清理所有这些订阅：

```ts
startStream() {
    const streamSource = interval(1500);
    const secondStreamSource = interval(3000);
    const fastestStreamSource = interval(500);
    streamSource.subscribe(input => {...});
    secondStreamSource.subscribe(input => {
      this.outputStreamData.push(input);
      console.log('second stream output', input)
    });
    fastestStreamSource.subscribe(input => {
      this.outputStreamData.push(input);
      console.log('fastest stream output', input)
    });
  }
  stopStream() {
  }
```

请注意，我们不再将`streamSource`的**Subscription**保存到`this.subscription`中，我们还从`stopStream`方法中删除了代码。原因是因为我们没有为每个 Subscription 拥有单独的属性/变量。相反，我们将有一个单一的变量来处理。让我们看一下以下的步骤来开始工作。

1.  首先，我们将在`HomeComponent`类中创建一个名为`isComponentAlive`的属性：

```ts
...
export class HomeComponent implements OnInit, OnDestroy {
  isComponentAlive: boolean;
  ...
}
```

1.  现在，我们将从`rxjs/operators`中导入`takeWhile`操作符，如下所示：

```ts
import { Component, OnInit, OnDestroy } from '@angular/core';
import { interval } from 'rxjs/internal/observable/interval';
import { Subscription } from 'rxjs/internal/Subscription';
import { takeWhile } from 'rxjs/operators';
```

1.  现在，我们将使用`takeWhile`操作符与我们的每个流，使它们只在`isComponentAlive`属性设置为`true`时工作。由于`takeWhile`需要一个`predicate`方法，它应该是这样的：

```ts
startStream() {
    ...
    streamSource
      .pipe(
        takeWhile(() => !!this.isComponentAlive)
      ).subscribe(input => {...});
    secondStreamSource
      .pipe(
        takeWhile(() => !!this.isComponentAlive)
      ).subscribe(input => {...});
    fastestStreamSource
      .pipe(
        takeWhile(() => !!this.isComponentAlive)
      ).subscribe(input => {...});
  }
```

如果您现在在**主页**上按下**开始流**按钮，您仍然看不到任何输出或日志，因为`isComponentAlive`属性仍然是`undefined`。

1.  为了使流工作，我们将在`ngOnInit`方法以及`startStream`方法中将`isComponentAlive`属性设置为`true`。代码应该是这样的：

```ts
  ngOnInit() {
    this.isComponentAlive = true;
  }
  ngOnDestroy() {
    this.stopStream();
  }
  startStream() {
    this.isComponentAlive = true;
    const streamSource = interval(1500);
    const secondStreamSource = interval(3000);
    const fastestStreamSource = interval(500);
    ...
  }
```

在此步骤之后，如果您现在尝试启动流并从页面导航离开，您仍将看到与流相同的问题-即它们尚未取消订阅。

1.  要一次取消订阅所有流，我们将在`stopStream`方法中将`isComponentAlive`的值设置为`false`，如下所示：

```ts
  stopStream() {
    this.isComponentAlive = false;
  }
```

然后！ 现在，如果您在流发出值时导航离开路由，流将立即停止，就在您离开**主页**路由时。 瞧！

## 另请参阅

+   阅读 RxJS 订阅（https://www.learnrxjs.io/learn-rxjs/concepts/rxjs-primer#subscription）

+   `takeWhile`文档（https://www.learnrxjs.io/learn-rxjs/operators/filtering/takewhile）

# 使用 Observable 和 async 管道将数据同步绑定到您的 Angular 模板

正如您在上一个配方中所学到的，取消订阅您订阅的流至关重要。 如果我们有一种更简单的方法在组件被销毁时取消订阅它们-也就是说，让 Angular 以某种方式来处理它，那该多好？ 在这个配方中，您将学习如何使用 Angular 的`async`管道与 Observable 直接将流中的数据绑定到 Angular 模板，而无需在`*.component.ts`文件中订阅。

## 做好准备

此配方的项目位于`chapter05/start_here/using-async-pipe`。

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器选项卡中打开应用程序。 一旦页面打开，您应该看到类似于这样的东西：

！[图 5.10-使用异步管道应用程序在 http://localhost:4200 上运行

]（image/Figure_5.10_B15150.jpg）

图 5.10-使用异步管道应用程序在 http://localhost:4200 上运行

现在我们的应用程序在本地运行，让我们在下一节中看到该配方的步骤。

## 如何做…

我们现在的应用程序有三个流/可观察对象在不同的时间间隔观察值。 我们依赖于`isComponentAlive`属性来保持订阅活动或在属性设置为`false`时停止它。 我们将删除对`takeWhile`的使用，并以某种方式使一切都与我们现在拥有的类似地工作。

1.  首先，从`home.component.ts`文件中删除`subscription`属性，并添加一个名为`streamOutput$`的`Observable`类型属性。 代码应如下所示：

```ts
...
import { Observable } from 'rxjs';
...
export class HomeComponent implements OnInit, OnDestroy {
  isComponentAlive: boolean;
  subscription: Subscription = null ← Remove this;
  inputStreamData = ['john wick', 'inception',   'interstellar']; 
  streamsOutput$: Observable<number[]> ← Add this
  outputStreamData = []
  constructor() { }
  ...
}
```

通过这种改变，应用程序会因为一些缺少的变量而崩溃。 不要害怕！ 我在这里帮助您。

1.  现在我们将组合所有的流以输出单个输出，即`outputStreamData`数组。我们将从`startStream()`方法中删除所有现有的`.pipe`和`.subscribe`方法，所以代码现在应该是这样的：

```ts
import { Component, OnInit, OnDestroy } from '@angular/core';
import { merge, Observable } from 'rxjs';
import { map, takeWhile } from 'rxjs/operators';
...
export class HomeComponent implements OnInit, OnDestroy {
  ...
  startStream() {
    const streamSource = interval(1500);
    const secondStreamSource = interval(3000);
    const fastestStreamSource = interval(500);
    this.streamsOutput$ = merge(
      streamSource,
      secondStreamSource,
      fastestStreamSource
    )
  }
  ...
}
```

有了这个改变，linters 仍然会抱怨。为什么？因为`merge`操作符会合并所有流并输出最新的值。这是一个`Observable<number>`数据类型，而不是`Observable<string[]>`，这是`streamsOutput$`的类型。

1.  由于我们想要分配包含从流中发出的每个输出的整个数组，我们将使用`map`操作符，并将每个输出添加到`outputStreamData`数组中，并返回`outputStreamData`数组的最新状态，如下所示：

```ts
startStream() {
    const streamSource = interval(1500);
    const secondStreamSource = interval(3000);
    const fastestStreamSource = interval(500);
    this.streamsOutput$ = merge(
      streamSource,
      secondStreamSource,
      fastestStreamSource
    ).pipe(
      takeWhile(() => !!this.isComponentAlive),
      map(output => {
        this.outputStreamData = [...this.        outputStreamData, output]
        return this.outputStreamData;
      })
    )
  }
```

1.  从`HomeComponent`类中删除`stopStream`方法，因为我们不再需要它。同时，从`ngOnDestroy`方法中删除它的使用。

1.  最后，修改`home.component.html`模板，使用`streamOutput$` Observable 和`async`管道来循环输出数组：

```ts
    <div class="output-stream">
      <div class="input-stream__item" *ngFor="let item       of streamsOutput$ | async">
        {{item}}
      </div>
    </div>
```

1.  为了验证订阅在组件销毁时确实被销毁，让我们在`startStream`方法中的`map`操作符中放置一个`console.log`，如下所示：

```ts
startStream() {
    const streamSource = interval(1500);
    const secondStreamSource = interval(3000);
    const fastestStreamSource = interval(500);
    this.streamsOutput$ = merge(
      streamSource,
      secondStreamSource,
      fastestStreamSource
    ).pipe(
      takeWhile(() => !!this.isComponentAlive),
      map(output => {
        console.log(output)
        this.outputStreamData = [...this.        outputStreamData, output]
        return this.outputStreamData;
      })
    )
  }
```

万岁！有了这个改变，你可以尝试刷新应用程序，离开**Home**路由，你会发现控制台日志会在你这样做时立即停止。你感受到我们通过删除所有那些额外代码所获得的成就了吗？我当然感受到了。好吧，接下来看看它是如何工作的。

## 它是如何工作的…

Angular 的`async`管道在组件销毁时会自动销毁/取消订阅。这给了我们一个很好的机会在可能的情况下使用它。在这个示例中，我们基本上使用`merge`操作符组合了所有的流。有趣的是，对于`streamsOutput$`属性，我们希望得到一个输出数组的 Observable，我们可以对其进行循环。然而，合并流只是将它们组合在一起并发出任何一个流发出的最新值。因此，我们添加了一个`.pipe()`方法和`.map()`操作符，以从组合的流中取出最新的输出，将其添加到`outputStreamData`数组中以进行持久化，并从`.map()`方法中返回它，这样我们在模板中使用`async`管道时就可以得到数组。

有趣的事实-流不会发出任何值，除非它们被订阅。"*但是，阿赫桑，我们没有订阅流，我们只是合并和映射数据。订阅在哪里？*"很高兴你问。Angular 的`async`管道订阅了流本身，这也触发了我们在*步骤 6*中添加的`console.log`。

重要提示

`async` 管道有一个限制，即在组件销毁之前无法停止订阅。在这种情况下，您可能希望使用类似`takeWhile`/`takeUntil`操作符的组件内订阅，或者在组件销毁时自己执行常规的`.unsubscribe`方法。

## 另请参阅

+   Angular `async` 管道文档（[`angular.io/api/common/AsyncPipe`](https://angular.io/api/common/AsyncPipe)）

# 使用 combineLatest 订阅多个流

在上一个示例中，我们不得不合并所有流，这导致最后由任何一个流发出的单个输出。在这个示例中，我们将使用`combineLatest`，它的输出是一个数组，结合了所有的流。这种方法适用于当您想要来自所有流的最新输出，组合在一个单独的订阅中。

## 准备工作

我们要使用的项目位于克隆存储库内的`chapter05/start_here/using-combinelatest-operator`中。

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该在新的浏览器标签中打开应用程序，你应该看到类似这样的东西：

![图 5.11 - 使用 combinelatest-operator 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.11_B15150.jpg)

图 5.11 - 使用 combinelatest-operator 应用程序在 http://localhost:4200 上运行

现在我们的应用程序在本地运行，让我们在下一节中看看这个示例的步骤。

## 如何做…

对于这个示例，我们有一个显示框的应用程序。框有一个大小（宽度和高度），一个边框半径，一个背景颜色，以及文本的颜色。它还有四个输入来修改所有提到的因素。现在，我们必须手动点击按钮来应用更改。如果我们可以订阅输入的更改并立即更新框呢？这就是我们要做的。

1.  我们将首先创建一个名为`listenToInputChanges`的方法，在其中我们将订阅每个输入的更改，并使用`combineLatest`操作符组合这些流。更新`home/home.component.ts`文件如下：

```ts
...
import { combineLatest, Observable } from 'rxjs';
...
export class HomeComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    ...
    this.applyChanges();
    this.listenToInputChanges(); ← Add this
  }
  listenToInputChanges() {
    combineLatest([
      this.boxForm.get('size').valueChanges,
      this.boxForm.get('borderRadius').valueChanges,
      this.boxForm.get(      'backgroundColor').valueChanges,
      this.boxForm.get('textColor').valueChanges
    ]).subscribe(() => {
      this.applyChanges();
    });
  }
  ...
}
```

1.  记住不取消订阅流是一个坏主意吗？这就是我们在这里的情况：一个已订阅的流。我们将使用`async`管道代替`home.component.ts`文件中当前使用的订阅。为此，让我们创建一个名为`boxStyles$`的 Observable 属性，并删除`boxStyles`属性。然后，将`combineLatest`的流分配给它，如下所示：

```ts
...
import { map} from 'rxjs/operators';
...
export class HomeComponent implements OnInit, OnDestroy {
  ...
  boxStyles: {...}; ← Remove this
  boxForm = new FormGroup({...});
  boxStyles$: Observable<{
    width: string,
    height: string,
    backgroundColor: string,
    color: string
    borderRadius: string
  }>;
   ...
  listenToInputChanges() {
    this.boxStyles$ = combineLatest([...]).    pipe(map(([size, borderRadius, backgroundColor,     textColor]) => {
      return {
        width: `${size}px`,
        height: `${size}px`,
        backgroundColor,
        color: textColor,
        borderRadius: `${borderRadius}px`
      }
    }));
  }
  ...
}
```

1.  我们需要从`home.component.ts`文件中删除`setBoxStyles()`和`applyChanges()`方法以及`applyChanges()`方法的使用。更新文件如下：

```ts
export class HomeComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    ...
    this.applyChanges(); ← Remove this
    this.listenToInputChanges(); ← Add this
  }
  ...
  setBoxStyles(size, backgroundColor, color,   borderRadius) {...}  ← Remove this
  applyChanges() {...} ← Remove this
  ...
}
```

1.  我们还需要从模板中删除`applyChanges()`方法的使用。从`home.component.html`文件中的`<form>`元素中删除`(ngSubmit)`处理程序，使其如下所示：

```ts
<div class="home" [formGroup]="boxForm" (ngSubmit)="applyChanges()" ← Remove this>
  ...
</div>
```

1.  我们还需要从`home.component.html`模板中删除`submit-btn-container`元素，因为我们不再需要它。从文件中删除以下内容：

```ts
<div class="row submit-btn-container" ← Remove this element>
  <button class="btn btn-primary" type="submit"   (click)="applyChanges()">Change Styles</button>
</div>
```

如果刷新应用程序，你会注意到框根本不显示。我们将在下一步中修复这个问题。

1.  由于我们在应用程序启动时使用了`combineLatest`操作符，但我们没有触发它，因为没有一个输入发生了变化，我们需要使用`startWith`操作符和初始值来初始化框。为此，我们将使用`startWith`操作符和初始值，如下所示：

```ts
...
import { map, startWith } from 'rxjs/operators';
@Component({...})
export class HomeComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    this.listenToInputChanges();
  }
  listenToInputChanges() {
    this.boxStyles$ = combineLatest([
      this.boxForm
        .get('size')
        .valueChanges.pipe(startWith(this.        sizeOptions[0])),
      this.boxForm
        .get('borderRadius')
        .valueChanges.pipe(startWith(        this.borderRadiusOptions[0])),
      this.boxForm
        .get('backgroundColor')
        .valueChanges.pipe(startWith(        this.colorOptions[1])),
      this.boxForm
        .get('textColor')
        .valueChanges.pipe(startWith(        this.colorOptions[0])),
    ]).pipe(
      map(...);
  }
  ngOnDestroy() {}
}
```

1.  现在我们已经有了`boxStyles$` Observable，让我们在模板中使用它，而不是`boxStyles`属性：

```ts
  ...
  <div class="row" *ngIf="boxStyles$ | async as bStyles">
    <div class="box" [ngStyle]="bStyles">
      <div class="box__text">
        Hello World!
      </div>
    </div>
  </div>
  ...
```

大功告成！现在一切都运行得很完美。

恭喜完成了食谱。现在你是流和`combineLatest`操作符的大师了。查看下一节以了解它是如何工作的。

## 它是如何工作的…

**响应式表单**的美妙之处在于它们提供比常规的`ngModel`绑定或者甚至模板驱动表单更灵活的功能。对于每个表单控件，我们可以订阅它的`valueChanges` Observable，每当输入发生变化时就会接收到一个新的值。因此，我们不再依赖于**提交**按钮的点击，而是直接订阅了每个**表单控件**的`valueChanges`属性。在常规情况下，这将导致四个不同的流用于四个输入，这意味着我们需要处理四个订阅并确保取消订阅。这就是`combineLatest`操作符发挥作用的地方。我们使用`combineLatest`操作符将这四个流合并为一个，这意味着我们只需要在组件销毁时取消订阅一个流。但是！记住如果我们使用`async`管道就不需要这样做了？这正是我们所做的。我们从`home.component.ts`文件中移除了订阅，并使用了`.pipe()`方法和`.map()`操作符。`.map()`操作符将数据转换为我们需要的格式，然后将转换后的数据返回给`boxStyles$` Observable。最后，我们在模板中使用 async 管道订阅`boxStyles$` Observable，并将其值分配为我们盒子元素的`[ngStyle]`。

重要提示

`combineLatest`方法在每个 Observable 至少发出一个值之前不会发出初始值。因此，我们使用`startWith`操作符与每个单独的表单控件的`valueChanges`流来提供一个初始发出的值。

## 另请参阅

+   `combineLatest`操作符文档（[`www.learnrxjs.io/learn-rxjs/operators/combination/combinelatest`](https://www.learnrxjs.io/learn-rxjs/operators/combination/combinelatest)）

+   `combineLatest`操作符的可视化表示（[`rxjs-dev.firebaseapp.com/api/index/function/combineLatest`](https://rxjs-dev.firebaseapp.com/api/index/function/combineLatest)）

# 使用 flatMap 操作符创建顺序的 HTTP 调用

使用**Promises**的日子很棒。并不是说那些日子已经过去了，但我们作为开发者肯定更喜欢**Observables**而不是**Promises**，有很多原因。我真的很喜欢 Promises 的一件事是你可以链接 Promises 来做一些事情，比如顺序的 HTTP 调用。在这个教程中，你将学习如何使用`flatMap`操作符来使用**Observables**做同样的事情。

## 准备就绪

我们要处理的项目位于克隆存储库中的`chapter05/start_here/using-flatmap-operator`中。

1.  在 VS Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这应该在新的浏览器标签中打开应用程序，你应该会看到类似这样的东西：

![图 5.12 – 使用-flatmap-operator 应用程序正在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.12_B15150.jpg)

图 5.12 – 使用-flatmap-operator 应用程序正在 http://localhost:4200 上运行

现在应用程序看起来完美，实际上。没有什么可疑的，对吧？嗯，不完全是。按照以下步骤找出问题所在。

1.  打开 Chrome DevTools。

1.  转到**网络**选项卡，并模拟**慢 3G**网络，如下所示：![图 5.13 – 在 Chrome DevTools 中模拟慢 3G 网络](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.13_B15150.jpg)

图 5.13 – 在 Chrome DevTools 中模拟慢 3G 网络

如果你点击主页上的任何卡片，你应该能够到达特定用户的详细信息页面。

1.  现在刷新应用程序，查看**网络**选项卡，你会看到 HTTP 调用并行执行，如下所示：

![图 5.14 – 并行调用异步加载数据](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.14_B15150.jpg)

图 5.14 – 并行调用异步加载数据

问题在于我们不确定由于两个 HTTP 调用并行执行，哪个数据会先到来。因此，用户可能会在主用户加载之前看到类似的用户。让我们看看如何避免这种情况。

## 如何做…

为了解决类似用户可能在主用户之前加载的问题，我们将不得不顺序加载数据，并分别显示相应的内容，而在内容加载时，我们将显示一个加载器。让我们开始吧。

1.  首先，让我们修改我们的`user-detail/user-detail.component.html`文件，以便在加载时显示加载器，以及在加载类似的用户时也显示加载器。代码应该如下所示：

```ts
<div class="user-detail">
  <div class="main-content user-card">
    <app-user-card *ngIf="user$ | async as user; else     loader" [user]="user"></app-user-card>
  </div>
  <div class="secondary-container">
    <h4>Similar Users</h4>
    <div class="similar-users">
      <ng-container *ngIf="similarUsers$ | async as       users; else loader">
        <app-user-card class="user-card" *ngFor="let user         of users" [user]="user"></app-user-card>
      </ng-container>
    </div>
  </div>
</div>
<ng-template #loader>
  <app-loader></app-loader>
</ng-template>
```

如果刷新应用程序，你应该会看到在进行调用之前两个加载器都出现。

我们希望进行顺序调用，为此，我们不能直接将流绑定到`UserDetailComponent`类中的 Observables。也就是说，我们甚至不能使用`async`管道。

1.  让我们将`UserDetailComponent`类中的 Observable 属性转换为常规属性，如下所示：

```ts
...
export class UserDetailComponent implements OnInit, OnDestroy {
  user: IUser;
  similarUsers: IUser[];
  isComponentAlive: boolean;
  ...
}
```

只要保存上述更改，应用程序就会立即崩溃。

1.  让我们在模板中使用我们在上一步中修改的新变量。修改`user-detail.component.html`文件，如下所示：

```ts
<div class="user-detail">
  <div class="main-content user-card">
    <app-user-card *ngIf="user; else loader"     [user]="user"></app-user-card>
  </div>
  <div class="secondary-container">
    <h4>Similar Users</h4>
    <div class="similar-users">
      <ng-container *ngIf="similarUsers; else loader">
        <app-user-card class="user-card" *ngFor="let user         of similarUsers" [user]="user"></app-user-card>
      </ng-container>
    </div>
  </div>
</div>
...
```

1.  最后，让我们现在使用`flatMap`运算符按顺序执行调用，并将接收到的值分配给相应的变量，如下所示：

```ts
...
import { takeWhile, flatMap } from 'rxjs/operators';
export class UserDetailComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    this.isComponentAlive = true;
    this.route.paramMap.pipe(
      takeWhile(() => !!this.isComponentAlive),
      flatMap(params => {
        this.user = null;
        this.similarUsers = null;
        const userId = params.get('uuid');
        return this.userService.getUser(userId)
          .pipe(
            flatMap((user: IUser) => {
              this.user = user;
              return this.userService.              getSimilarUsers(userId);
            })
          );
      })
    ).subscribe((similarUsers: IUser[]) => {
      this.similarUsers = similarUsers;
    })
  }
  ...
}
```

是的！如果您现在刷新应用程序，您会注意到调用是顺序的，因为我们首先获取主用户，然后获取相似用户。要确认，您可以打开 Chrome DevTools 并查看**应用程序编程接口**（**API**）调用的网络日志。您应该会看到类似以下内容：

![图 5.15 – API 调用同步执行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.15_B15150.jpg)

图 5.15 – API 调用同步执行

现在您已经完成了这个步骤，请查看下一节，了解其工作原理。

## 工作原理…

`flatMap`运算符获取前一个 Observable 的输出，并应返回一个新的 Observable。这有助于我们按顺序执行 HTTP 调用，以确保数据根据其优先级或我们的业务逻辑加载。

由于我们希望在选择新用户时执行调用，这可以从`UserDetailComponent`类本身发生，我们直接在`route.paramsMap`上放置了`flatMap`运算符。每当发生这种情况时，我们首先将`user`和`similarUsers`属性设置为`null`。"*但为什么？*"嗯，因为如果我们在`UserDetailsComponent`页面上并单击任何相似用户，页面不会更改，因为我们已经在上面。这意味着用户和`similarUsers`变量仍将包含其先前的值。而且由于它们已经有值（即它们不是`null`），在点击任何相似用户时，加载程序将不会显示在这种情况下。聪明，对吧？

无论如何，在将变量分配为`null`之后，我们将 Observable 从`this.userService.getUser(userId)`块返回，这将导致执行第一个 HTTP 调用以获取主用户。然后，我们在第一个调用的 Observable 上使用管道和`flatMap`来获取主用户，将其分配给`this.user`块，然后返回第二个调用的 Observable——即`this.userService.getSimilarUsers(userId)`代码。最后，我们使用`.subscribe`方法从`getSimilarUsers(userId)`接收值，一旦接收到值，我们将其分配给`this.similarUsers`。

## 另请参见

+   `flatMap`/`mergeMap`文档（[`www.learnrxjs.io/learn-rxjs/operators/transformation/mergemap`](https://www.learnrxjs.io/learn-rxjs/operators/transformation/mergemap)）

# 使用 switchMap 操作符来切换最后一个订阅与新的订阅

对于许多应用程序，我们有诸如用户输入时搜索内容的功能。这是一个非常好的**用户体验**（**UX**），因为用户不必按按钮进行搜索。然而，如果我们在每次按键时向服务器发送调用，那将导致大量的 HTTP 调用被发送，我们无法知道哪个 HTTP 调用会首先完成；因此，我们无法确定我们是否会在视图上看到正确的数据。在这个示例中，您将学习如何使用`switchMap`操作符来取消上一个订阅并创建一个新的订阅。这将导致取消以前的调用并保留一个调用 - 最后一个调用。

## 准备工作

我们要处理的项目位于克隆存储库中的`chapter05/start_here/using-switchmap-operator`中。

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序，你应该会看到类似于这样的东西：

![图 5.16 - 使用 switchmap-operator 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.16_B15150.jpg)

图 5.16 - 使用 switchmap-operator 应用程序在 http://localhost:4200 上运行

现在我们的应用程序在本地运行，打开 Chrome DevTools 并转到**Network**选项卡。在搜索输入框中输入`'huds'`，你会看到有四个调用被发送到 API 服务器，如下所示：

![图 5.17 - 每次输入更改都发送一个单独的调用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.17_B15150.jpg)

图 5.17 - 每次输入更改都发送一个单独的调用

## 如何做…

您可以在主页的搜索框中开始输入以查看筛选后的用户，如果您查看**Network**选项卡，您会注意到每次输入更改时，我们都会发送一个新的 HTTP 调用。让我们通过使用`switchMap`操作符来避免在每次按键时发送调用。

1.  首先，在`home/home.component.ts`文件中从`rxjs/operators`中导入`switchMap`操作符，如下所示：

```ts
...
import { switchMap, takeWhile } from 'rxjs/operators';
```

1.  我们现在将修改对`username`表单控件的订阅，具体来说是使用`switchMap`操作符来调用`this.userService.searchUsers(query)`方法的`valueChanges` Observable。这将返回一个包含 HTTP 调用结果的`Observable`。代码应该如下所示：

```ts
...
  ngOnInit() {
    this.componentAlive = true;
    this.searchForm = new FormGroup({
      username: new FormControl('', [])
    })
    this.searchUsers();
    this.searchForm.get('username').valueChanges
      .pipe(
        takeWhile(() => !!this.componentAlive),
        switchMap((query) => this.userService.        searchUsers(query))
      )
      .subscribe((users) => {
        this.users = users;
      })
  }
```

如果现在刷新应用程序，打开 Chrome DevTools，并在输入`'huds'`时检查网络类型，您会看到所有先前的调用都被取消，我们只有最新的 HTTP 调用成功：

![图 5.18 – switchMap 取消先前的 HTTP 调用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.18_B15150.jpg)

图 5.18 – switchMap 取消先前的 HTTP 调用

哇！现在我们只有一个调用会成功，处理数据，并最终显示在视图中。请参阅下一节了解其工作原理。

## 它是如何工作的…

`switchMap`操作符会取消先前（内部）的订阅，并订阅一个新的 Observable。这就是为什么它会取消我们示例中之前发送的所有 HTTP 调用，只订阅最后一个的原因。这是我们应用程序的预期行为。

## 另请参阅

+   `switchMap`操作符文档（https://www.learnrxjs.io/learn-rxjs/operators/transformation/switchmap）

# 使用 RxJS 进行 HTTP 请求去抖

在上一个示例中，我们学习了如何使用`switchMap`操作符来取消先前的 HTTP 调用，如果有新的 HTTP 调用。这很好，但是为什么在我们可以使用一种技术在发送 HTTP 调用之前等待一段时间呢？理想情况下，我们将继续监听一段时间的重复请求，然后继续进行最新的请求。在这个示例中，我们将使用`debounceTime`操作符来确保我们只在用户停止输入一段时间后才发送 HTTP 调用。

## 准备工作

我们将要处理的项目位于克隆存储库中的`chapter05/start_here/using-debouncetime-operator`中。

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器选项卡中打开应用程序，并且您应该会看到类似于这样的内容：

![图 5.19 – 使用 debouncetime 操作符的应用程序运行在 http://localhost.4200 上](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.19_B15150.jpg)

图 5.19 – 使用 debouncetime 操作符的应用程序运行在 http://localhost.4200 上

现在应用程序正在运行，打开 Chrome DevTools，转到**网络**选项卡，然后在用户搜索栏中输入`'Irin'`。您应该会看到类似于这样的内容：

![图 5.20 - 每次键盘输入都会发送到服务器的新调用](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.20_B15150.jpg)

图 5.20 - 每次键盘输入都会发送到服务器的新调用

注意第三次调用的响应是在第四次调用之后吗？这就是我们试图通过使用某种防抖来解决的问题。

让我们在下一节中跳转到食谱步骤。

## 如何做…

当我们在主页的搜索框中输入时（也就是说，每当输入发生变化时），我们会发送一个新的 HTTP 调用。

为了确保在输入搜索后处于空闲状态时只发送一次调用，我们将在`this.searchForm.get('username').valueChanges` Observable 上放置一个`debounceTime`操作符。更新`home/home.component.ts`文件，如下所示：

```ts
...
import { debounceTime, takeWhile } from 'rxjs/operators';
...
export class HomeComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    ...
    this.searchForm.get('username').valueChanges
      .pipe(
        takeWhile(() => !!this.componentAlive),
        debounceTime(300),
      )
      .subscribe(() => {
        this.searchUsers();
      })
  }
  searchUsers() {...}
  ngOnDestroy() {}
}
```

就是这样！如果您在检查**网络**选项卡时在搜索输入框中输入`'irin'`，您应该只看到一次调用被发送到服务器，如下所示：

![图 5.21 - debounceTime 只导致一次调用发送到服务器](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_5.21_B15150.jpg)

图 5.21 - debounceTime 只导致一次调用发送到服务器

请查看下一节以了解它是如何工作的。

## 它是如何工作的…

`debounceTime`操作符在从源 Observable 发出值之前等待一段时间，而且只有在没有更多的源发射时才会发出值。这使我们能够在输入的`valueChanges` Observable 上使用该操作符。当您在输入框中输入内容时，`debounceTime`操作符会等待 300 毫秒，以查看您是否仍在输入。如果您在这 300 毫秒内没有输入，它将继续发出值，导致最终进行 HTTP 调用。

## 另请参阅

+   `debounceTime`操作符文档（[`rxjs-dev.firebaseapp.com/api/operators/debounceTime`](https://rxjs-dev.firebaseapp.com/api/operators/debounceTime))

+   `debounce`操作符文档（[`rxjs-dev.firebaseapp.com/api/operators/debounce`](https://rxjs-dev.firebaseapp.com/api/operators/debounce))

+   `delay`操作符文档（[`rxjs-dev.firebaseapp.com/api/operators/delay`](https://rxjs-dev.firebaseapp.com/api/operators/delay))


# 第六章：*第六章*：使用 NgRx 进行响应式状态管理

Angular 和响应式编程是最好的朋友，以响应式方式处理应用程序的状态是您可以为应用程序做的最好的事情之一。NgRx 是一个为 Angular 提供一组库作为响应式扩展的框架。在本章中，您将学习如何使用 NgRx 生态系统以响应式地管理应用程序的状态，并且您还将学习 NgRx 生态系统将帮助您完成的一些很酷的事情。

以下是本章我们将要涵盖的食谱：

+   使用动作和减速器创建你的第一个 NgRx 存储

+   使用`@ngrx/store-devtools`来调试状态变化

+   创建一个效果来获取第三方**应用程序编程接口**（**API**）数据

+   使用选择器从多个组件中的存储中获取数据

+   使用`@ngrx/component-store`来在组件内进行本地状态管理

+   使用`@ngrx/router-store`以响应式方式处理路由更改

# 技术要求

对于本章的食谱，请确保您的计算机上已安装**Git**和**Node.js**。您还需要安装`@angular/cli`包，可以在终端中使用`npm install -g @angular/cli`来安装。本章的代码可以在 https://github.com/PacktPublishing/Angular-Cookbook/tree/master/chapter06 找到。

# 使用动作和减速器创建你的第一个 NgRx 存储

在这个食谱中，您将通过设置您的第一个 NgRx 存储来逐步了解 NgRx 的基础知识。您还将创建一些动作以及一个减速器，并且为了查看减速器中的变化，我们将放入适当的控制台日志。

## 准备工作

我们将要使用的项目位于`chapter06/start_here/ngrx-actions-reducer`中，位于克隆存储库内：

1.  在**Visual Studio Code** (**VS Code**)中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序。点击**以管理员身份登录**按钮，您应该会看到以下屏幕：

![图 6.1 – ngrx-actions-reducers 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.1_B15150.jpg)

图 6.1 – ngrx-actions-reducers 应用程序在 http://localhost:4200 上运行

现在我们的应用程序正在运行，我们将继续进行食谱的步骤。

## 如何做…

我们有一个现有的 Angular 应用程序，我们在之前的示例中也使用过。如果您以管理员用户身份登录，您可以向购物篮中添加和移除物品。但是，如果您以员工身份登录，您只能添加物品而不能移除物品。现在我们将开始将 NgRx 集成到应用程序中，并创建一个 reducer 和一些动作：

1.  首先通过**Node Package Manager** (**npm**)在您的项目中安装`@ngrx/store package`。打开终端（Mac/Linux）或命令提示符（Windows），导航到项目根目录，并运行以下命令：

```ts
npm install @ngrx/store@12.0.0 --save
```

如果您已经在运行，请确保重新运行`ng-serve`命令。

1.  更新`app.module.ts`文件以包括`StoreModule`，如下所示：

```ts
...
import { StoreModule } from '@ngrx/store';
@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    FormsModule,
    BrowserAnimationsModule,
    StoreModule.forRoot({})
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

注意，我们已经向`forRoot`方法传递了一个空对象`{}`；我们将在以后进行更改。

1.  现在，我们将创建一些动作。在`app`文件夹内创建一个名为`store`的文件夹。然后，在`store`文件夹内创建一个名为`app.actions.ts`的文件，并最后向新创建的文件中添加以下代码：

```ts
import { createAction, props } from '@ngrx/store';
import { IFruit } from '../interfaces/fruit.interface';
export const addItemToBucket = createAction(
  '[Bucket] Add Item',
  props<IFruit>()
);
export const removeItemFromBucket = createAction(
  '[Bucket] Remove Item',
  props<IFruit>()
);
```

由于我们现在已经有了动作，我们必须创建一个 reducer。

1.  在`store`文件夹内创建一个新文件，命名为`app.reducer.ts`，并向其中添加以下代码以定义必要的导入：

```ts
import { Action, createReducer, on } from '@ngrx/store';
import { IFruit } from '../interfaces/fruit.interface';
import * as AppActions from './app.actions';
```

1.  现在，定义一个`AppState`接口以反映应用程序的状态，并定义一个`initialState`变量以反映应用程序启动时应用程序状态的外观。在`app.reducer.ts`文件中添加以下代码：

```ts
import { Action, createReducer, on } from '@ngrx/store';
import { IFruit } from '../interfaces/fruit.interface';
import * as AppActions from './app.actions';

export interface AppState {
  bucket: IFruit[];
}

const initialState: AppState = {
  bucket: []
}
```

1.  现在是时候实际创建一个 reducer 了。在`app.reducer.ts`文件中添加以下代码以创建一个 reducer：

```ts
...
const initialState: AppState = {
  bucket: []
}
const appReducer = createReducer(
  initialState,
  on(AppActions.addItemToBucket, (state, fruit) =>   ({ ...state, bucket: [fruit, ...state.bucket] })),
  on(AppActions.removeItemFromBucket, (state, fruit) => {
    return {
      ...state,
      bucket: state.bucket.filter(bucketItem => {
        return bucketItem.id !== fruit.id;
      }) }
  }),
);

export function reducer(state: AppState = initialState, action: Action) {
  return appReducer(state, action);
}
```

1.  我们还将在`reducer`方法中添加一些`console.logs`调用，以查看控制台上所有动作的触发情况。在`app.reducer.ts`文件中添加如下日志：

```ts
export function reducer(state: AppState = initialState, action: Action) {
  console.log('state', state);
  console.log('action', action);
  return appReducer(state, action);
}
```

1.  最后，在`app.module.ts`文件中使用`StoreModule.forRoot()`方法注册此 reducer，以便我们可以看到事情的运行情况：

```ts
...
import { StoreModule } from '@ngrx/store';
import * as appStore from './store/app.reducer';
@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    ...
    StoreModule.forRoot({app: appStore.reducer})
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

如果现在刷新应用程序，您应该在应用程序启动时立即在控制台上看到以下日志：

![图 6.2 - 显示应用启动时的初始状态和@ngrx/store/init 动作的日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.2_B15150.jpg)

图 6.2 - 显示应用启动时的初始状态和@ngrx/store/init 动作的日志

1.  现在我们可以看到 reducer 起作用了，让我们在添加和移除购物篮中的物品时分派我们的动作。为此，在`shared/components/bucket`/`bucket.component.ts`文件中按以下方式分派动作：

```ts
...
import { Store } from '@ngrx/store';
import { AppState } from 'src/app/store/app.reducer';
import { addItemToBucket, removeItemFromBucket } from 'src/app/store/app.actions';
export class BucketComponent implements OnInit {
  ...
  constructor(
    private bucketService: BucketService,
    private store: Store<AppState>
  ) { }
  ngOnInit(): void {...}
  addSelectedFruitToBucket() {
const newItem: IFruit = {
      id: Date.now(),
      name: this.selectedFruit
    }
    this.bucketService.addItem(newItem);
    this.store.dispatch(addItemToBucket(newItem));
  }
  deleteFromBucket(fruit: IFruit) {
    this.bucketService.removeItem(fruit);
    this.store.dispatch(removeItemFromBucket(fruit));
  }
}
```

1.  以管理员身份登录应用程序，向桶中添加一些项目，然后删除一些项目。您会在控制台上看到类似这样的内容：

![图 6.3 - 显示从桶中添加和删除项目的操作日志](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.3_B15150.jpg)

图 6.3 - 显示从桶中添加和删除项目的操作日志

至此，这个教程就结束了！您现在知道如何将 NgRx 存储集成到 Angular 应用程序中，以及如何创建 NgRx 操作并分发它们。您还知道如何创建一个 reducer，定义它的状态，并监听操作以对分发的操作进行操作。

## 另请参阅

+   NgRx reducer 文档（[`ngrx.io/guide/store/reducers`](https://ngrx.io/guide/store/reducers)）

+   NgRx 操作文档（[`ngrx.io/guide/store/actions`](https://ngrx.io/guide/store/actions)）

+   RxJS 合并操作符文档（[`www.learnrxjs.io/learn-rxjs/operators/combination/merge`](https://www.learnrxjs.io/learn-rxjs/operators/combination/merge)）

# 使用@ngrx/store-devtools 调试状态更改

在这个教程中，您将学习如何设置和使用`@ngrx/store-devtools`来调试应用程序的状态、操作分发以及操作分发时状态的差异。我们将使用一个我们熟悉的现有应用程序来了解这个过程。

## 准备工作

这个教程的项目位于`chapter06/start_here/using-ngrx-store-devtool`：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器选项卡中打开应用程序。

1.  以管理员用户身份登录，并且您应该看到这样的屏幕：

![图 6.4 - 在 http://localhost:4200 上运行的使用 ngrx-store-devtools 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.4_B15150.jpg)

图 6.4 - 在 http://localhost:4200 上运行的使用 ngrx-store-devtools 应用程序

现在我们已经设置好了应用程序，让我们在下一节中看看这个教程的步骤。

## 如何做…

我们有一个 Angular 应用程序，已经集成了`@ngrx/store`包。我们还设置了一个 reducer，并且有一些操作，当您添加或删除项目时，这些操作会立即在控制台上记录。让我们开始配置应用程序的存储开发工具：

1.  首先在项目中安装`@ngrx/store-devtools`包，如下所示：

```ts
npm install @ngrx/store-devtools@12.0.0 --save
```

1.  现在，更新您的`app.module.ts`文件，包括`StoreDevtoolsModule.instrument`条目，如下所示：

```ts
...
import * as appStore from './store/app.reducer';
import { StoreDevtoolsModule } from '@ngrx/store-devtools';
@NgModule({
  declarations: [
    AppComponent
  ],
  imports: [
    ...
    StoreModule.forRoot({app: appStore.reducer}),
    StoreDevtoolsModule.instrument({
      maxAge: 25, // Retains last 25 states
    }),
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

1.  现在，从[`github.com/zalmoxisus/redux-devtools-extension/`](https://github.com/zalmoxisus/redux-devtools-extension/)下载 Redux DevTools 扩展，安装到您特定的浏览器上。在本书中，我将一直使用 Chrome 浏览器。

1.  打开 Chrome DevTools。应该会有一个名为**Redux**的新标签。点击它并刷新页面。您会看到类似于这样的内容：![图 6.5 - Redux DevTools 显示初始的 Redux 动作已经分发](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.5_B15150.jpg)

图 6.5 - Redux DevTools 显示初始的 Redux 动作已经分发

1.  要查看当前应用程序状态，请点击**State**按钮，如下截图所示，您应该会看到我们当前的状态是`app > bucket: []`：![图 6.6 - 在 Redux DevTools 扩展中查看当前状态](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.6_B15150.jpg)

图 6.6 - 在 Redux DevTools 扩展中查看当前状态

1.  现在，向桶里加入一个樱桃🍒和一个香蕉🍌，然后从桶里移除香蕉🍌。您应该看到所有相关的动作被分发，如下所示：

![图 6.7 - Redux DevTools 显示 addItemToBucket 和 removeItemFromBucket 动作](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.7_B15150.jpg)

图 6.7 - Redux DevTools 显示 addItemToBucket 和 removeItemFromBucket 动作

如果您展开状态中的桶数组，您会看到它反映了桶的当前状态，就像我们在以下截图中看到的那样：

![图 6.8 - Redux DevTools 显示桶的当前状态](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.8_B15150.jpg)

图 6.8 - Redux DevTools 显示桶的当前状态

太棒了！您刚刚学会了如何使用 Redux DevTools 扩展来查看您的 NgRx 状态和已分发的动作。

## 它是如何工作的...

重要的是要理解 NgRx 是 Angular 和 Redux（使用 RxJS）的组合。通过使用 Store Devtools 包和 Redux DevTools 扩展，我们能够轻松调试应用程序，这有助于我们发现潜在的错误，预测状态变化，并且更透明地了解`@ngrx/store`包后台发生的情况。

## 还有更多...

您还可以看到动作在应用程序状态中引起的差异。也就是说，当我们使用水果分发`addItemToBucket`动作时，桶中会增加一个项目，当我们分发`removeItemFromBucket`动作时，桶中会移除一个项目。请参见以下截图和*图 6.10*：

![图 6.9 - addItemToBucket 操作导致向桶中添加项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.9_B15150.jpg)

图 6.9 - addItemToBucket 操作导致向桶中添加项目

请注意*图 6.9*中数据`{id:1605205728586,name:'Banana` `🍌``'}`周围的绿色背景。这代表对状态的添加。您可以在这里看到`removeItemFromBucket`操作：

![图 6.10 - removeItemFromBucket 操作导致从桶中移除项目](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.10_B15150.jpg)

图 6.10 - removeItemFromBucket 操作导致从桶中移除项目

同样，注意*图 6.10*中数据`{id:16052057285…` `🍌``'}`周围的红色背景和删除线。这代表从状态中移除。

## 另请参阅

+   NgRx Store Devtools 文档 ([`ngrx.io/guide/store-devtools`](https://ngrx.io/guide/store-devtools))

# 创建一个用于获取第三方 API 数据的效果

在这个食谱中，您将学习如何使用`@ngrx/effects`包来使用 NgRx 效果。您将创建并注册一个效果，该效果将监听一个事件。然后，我们将对该操作做出反应，以获取第三方 API 数据，并作出成功或失败的响应。这将会很有趣。

## 准备工作

这个食谱的项目位于`chapter06/start_here/using-ngrx-effect`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`以安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序，并且您应该会看到应用程序，如下所示：

![图 6.11 - 使用 ngrx-effects 应用程序在 http://localhost:4200 上运行](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.11_B15150.jpg)

图 6.11 - 使用 ngrx-effects 应用程序在 http://localhost:4200 上运行

现在我们的应用程序在本地运行，让我们在下一节中看看食谱的步骤。

## 如何做…

我们有一个名为**Home**页面的单一路由的应用程序。在`HomeComponent`类中，我们使用`UserService`发送**超文本传输协议**（**HTTP**）调用以获取用户，然后在浏览器上显示出来。正如您在*图 6.1*中所看到的，我们已经集成了`@ngrx/store`和`@ngrx/store-devtools`包。

1.  在项目中安装`@ngrx/effects`包，如下所示：

```ts
npm install --save @ngrx/effects@12.0.0
```

1.  现在我们将创建用于从 HTTP 调用获取用户的动作。我们将有一个动作用于获取用户，一个用于成功获取用户时分派，以及一个用于在出现错误时分派的动作。将以下代码添加到`store/app.actions.ts`文件中：

```ts
import { createAction, props } from '@ngrx/store';
import { IUser } from '../core/interfaces/user.interface';
export const APP_ACTIONS = {
  GET_USERS: '[Users] Get Users',
  GET_USERS_SUCCESS: '[Users] Get Users Success',
  GET_USERS_FAILURE: '[Users] Get Users Failure',
}
export const getUsers = createAction(
  APP_ACTIONS.GET_USERS,
);
export const getUsersSuccess = createAction(
  APP_ACTIONS.GET_USERS_SUCCESS,
  props<{users: IUser[]}>()
);
export const getUsersFailure = createAction(
  APP_ACTIONS.GET_USERS_FAILURE,
  props<{error: string}>()
);
```

现在让我们创建一个效果，以便我们可以监听`GET_USERS`动作，执行 API 调用，并在成功获取数据时分派成功动作。

1.  在`store`文件夹中创建一个名为`app.effects.ts`的文件，并将以下代码添加到其中：

```ts
import { Injectable } from '@angular/core';
import { Actions, createEffect, ofType } from '@ngrx/effects';
import { of } from 'rxjs';
import { map, mergeMap, catchError } from 'rxjs/operators';
import { UserService } from '../core/services/user.service';
import { APP_ACTIONS, getUsersFailure, getUsersSuccess } from './app.actions';
@Injectable()
export class AppEffects {
  constructor(
    private actions$: Actions,
    private userService: UserService
  ) {}
}
```

1.  现在我们将在`app.effects.ts`文件中创建一个新的效果，以注册`GET_USERS`动作的监听器，如下所示：

```ts
...
@Injectable()
export class AppEffects {
  getUsers$ = createEffect(() =>
    this.actions$.pipe(
      ofType(APP_ACTIONS.GET_USERS),
      mergeMap(() => this.userService.getUsers()
        .pipe(
          map(users => {
            return getUsersSuccess({
              users
            })
          }),
          catchError((error) => of(getUsersFailure({
            error
          })))
        )
      )
    )
  );
  ...
}
```

1.  现在我们将在`app.module.ts`文件中将我们的效果注册为应用程序的根效果，如下所示：

```ts
...
import { EffectsModule } from '@ngrx/effects';
import { AppEffects } from './store/app.effects';
@NgModule({
  declarations: [...],
  imports: [
    ...
    StoreDevtoolsModule.instrument({
      maxAge: 25, // Retains last 25 states
    }),
    EffectsModule.forRoot([AppEffects])
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

一旦我们注册了效果，您应该在 Redux DevTools 扩展中看到一个名为`@ngrx/effects/init`的额外动作触发，如下所示：

![图 6.12 - @ngrx/effects/init 动作在应用启动时触发](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.12_B15150.jpg)

图 6.12 - @ngrx/effects/init 动作在应用启动时触发

1.  现在我们已经让效果监听动作，让我们从`HomeComponent`类中分派`GET_USERS`动作，我们应该看到成功调用后返回`GET_USERS_SUCCESS`动作。添加以下代码以从`home/home.component.ts`中分派动作：

```ts
...
import { AppState } from '../store/app.reducer';
import { Store } from '@ngrx/store';
import { getUsers } from '../store/app.actions';
@Component({...})
export class HomeComponent implements OnInit, OnDestroy {
  users$: Observable<IUser[]>;
  constructor(
    private userService: UserService,
    private store: Store<AppState>
  ) {}
  ngOnInit() {
    this.store.dispatch(getUsers())
    this.users$ = this.userService.getUsers();
  }
  ngOnDestroy() {}
}
```

如果现在刷新应用程序，您应该看到`[Users] Get Users`动作被分派，并且作为成功 HTTP 调用的返回，`[Users] Get Users Success`动作也被分派：

![图 6.13 - 分派 GET_USERS 和 GET_USERS_SUCCESS 动作](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.13_B15150.jpg)

图 6.13 - 分派 GET_USERS 和 GET_USERS_SUCCESS 动作

请注意*图 6.13*中，在分派`GET_USERS_SUCCESS`动作后，`Diff`为空。这是因为到目前为止我们还没有使用 reducer 更新状态。

1.  让我们在`app.reducer.ts`文件中更新状态，以监听`GET_USERS_SUCCESS`动作并相应地将用户分配到状态中。代码应该如下所示：

```ts
import { Action, createReducer, on } from '@ngrx/store';
import { IUser } from '../core/interfaces/user.interface';
import { getUsersSuccess } from './app.actions';
export interface AppState {
  users: IUser[];
}
const initialState: AppState = {
  users: []
}
const appReducer = createReducer(
  initialState,
  on(getUsersSuccess, (state, action) => ({
    ...state,
    users: action.users
  }))
);
export function reducer(state: AppState = initialState, action: Action) {
  return appReducer(state, action);
}
```

如果现在刷新应用程序，您应该看到用户被分配到状态中，如下所示：

![图 6.14 - GET_USERS_SUCCESS 动作将用户添加到状态](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.14_B15150.jpg)

图 6.14 - GET_USERS_SUCCESS 动作将用户添加到状态

如果您现在查看应用程序的状态，您应该看到类似于这样的内容：

![图 6.15 - 在 GET_USERS_SUCCESS 动作后包含用户的应用程序状态](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.15_B15150.jpg)

图 6.15 - 在 GET_USERS_SUCCESS 操作后包含用户的应用程序状态

现在，我们向服务器发送了两个调用 - 一个通过 effect，另一个通过`HomeComponent`类的`ngOnInit`方法，直接使用`UserService`实例。让我们从`HomeComponent`类中删除`UserService`。现在我们看不到任何数据，但这是我们将在下一个示例中要做的事情。

1.  从`HomeComponent`类中删除`UserService`，你的`home.component.ts`文件现在应该是这样的：

```ts
...
@Component({...})
export class HomeComponent implements OnInit, OnDestroy {
  users$: Observable<IUser[]>;
  constructor(
  private userService: UserService, ← Remove this
    private store: Store<AppState>
  ) {}
  ngOnInit() {
    this.store.dispatch(getUsers());
    this.users$ = this.userService.getUsers();  ← Remove     this
  }
  ngOnDestroy() {}
}
```

太棒了！现在你知道如何在你的 Angular 应用程序中使用 NgRx 效果。请查看下一节，了解 NgRx 效果的工作原理。

重要说明

现在我们有一个输出，如*图 6.15*所示 - 也就是说，即使用户数据已经设置在存储中，我们仍然保持显示加载程序。这个示例的主要目的是使用`@ngrx/effects`，这已经完成了。我们将在下一个示例中显示适当的数据，*使用选择器从多个组件中的存储中获取数据*。

## 它是如何工作的...

为了使 NgRx 效果起作用，我们需要安装`@ngrx/effects`包，创建一个效果，并在`AppModule`类中将其注册为一组效果（根效果）。当你创建一个效果时，它必须监听一个动作。当从任何组件甚至另一个效果向存储分派一个动作时，注册的效果会触发，执行你希望它执行的工作，并应该返回另一个动作。对于 API 调用，通常有三个动作 - 即主要动作，以及以下成功和失败动作。理想情况下，在成功动作（也许在失败动作上），你会想要更新一些状态变量。

## 另请参阅

+   NgRx 效果文档([`ngrx.io/guide/effects`](https://ngrx.io/guide/effects))

# 在多个组件中使用选择器从存储中获取数据

在上一个示例中，我们创建了一个 NgRx 效果来获取第三方 API 数据作为用户，并将其保存在 Redux 存储中。这是我们在这个示例中的起点。我们有一个效果，从`api.randomuser.me`获取用户并将其存储在状态中，目前在**用户界面**（**UI**）上没有显示任何内容。在这个示例中，你将创建一些 NgRx 选择器，以在**主页**和**用户详细信息**页面上显示相似的用户。

## 做好准备

此示例的项目位于`chapter06/start_here/using-ngrx-selector`中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签中打开应用程序。一旦页面打开，你应该能够看到应用程序，如下所示：

![图 6.16 - 在 http://localhost:4200 上运行的 ngrx-selectors 应用程序](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.16_B15150.jpg)

图 6.16 - 在 http://localhost:4200 上运行的 ngrx-selectors 应用程序

现在我们的应用程序在本地运行，让我们在下一节中看看食谱的步骤。

## 如何做…

在这个食谱中，我们所要做的就是使用 NgRx 选择器、我们已经有的 reducer 和 Redux 状态。非常简单。让我们开始吧！

我们将首先在**主页**上显示用户，并为此创建我们的第一个 NgRx 选择器：

1.  在`store`文件夹中创建一个新文件。命名为`app.selectors.ts`并添加以下代码：

```ts
import { createSelector, createFeatureSelector } from '@ngrx/store';
import { AppState } from './app.reducer';
export const selectApp = createFeatureSelector<AppState>('app');
export const selectUsers = createSelector(
  selectApp,
  (state: AppState) => state.users
);
```

现在我们已经有了选择器，让我们在`HomeComponent`类中使用它。

1.  修改`home.component.ts`文件中的`ngOnInit`方法。它应该是这样的：

```ts
...
import { getUsers } from '../store/app.actions';
import { selectUsers } from '../store/app.selectors';
@Component({...})
export class HomeComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    this.users$ = this.store.select(selectUsers);
    this.store.dispatch(getUsers())
  }
  ngOnDestroy() {}
}
```

现在刷新应用程序，你应该能够看到用户。如果你点击任何一个用户，你将导航到用户详情，但看不到任何有价值的数据。页面应该是这样的：

![图 6.17 - 无法显示当前用户和相似用户](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.17_B15150.jpg)

图 6.17 - 无法显示当前用户和相似用户

1.  为了查看当前用户和相似用户，我们首先在`UserDetailComponent`类中创建两个 Observables，以便稍后订阅它们各自的 store 选择器。在`user-detail.component.ts`文件中添加 Observables，如下所示：

```ts
...
import { ActivatedRoute } from '@angular/router';
import { Observable } from 'rxjs/internal/Observable';
@Component({...})
export class UserDetailComponent implements OnInit, OnDestroy {
  user: IUser = null; ← Remove this
  similarUsers: IUser[] = []; ← Remove this
  user$: Observable<IUser> = null; ← Add this
  similarUsers$: Observable<IUser[]> = null; ← Add this
  isComponentAlive: boolean;
  constructor( ) {}
  ngOnInit() {
    this.isComponentAlive = true;
  }
  ngOnDestroy() {
    this.isComponentAlive = false;
  }
}
```

1.  更新`user-detail.component.html`模板以使用新的 Observable 属性，如下所示：

```ts
<div class="user-detail">
  <div class="main-content user-card">
    <app-user-card *ngIf="user$ | async as user;     else loader" [user]="user"></app-user-card>
  </div>
  <div class="secondary-container">
    <h4>Similar Users</h4>
    <div class="similar-users">
      <ng-container *ngIf="similarUsers$ | async       as similarUsers; else loader">
        <app-user-card class="user-card" *ngFor="let user         of similarUsers" [user]="user"></app-user-card>
      </ng-container>
    </div>
  </div>
</div>
...
```

1.  更新`app.selectors.ts`文件以添加两个选择器，如下所示：

```ts
...
import { IUser } from '../core/interfaces/user.interface';
export const selectUsers = createSelector(...);
export const selectCurrentUser = (uuid) => createSelector(
  selectUsers,
  (users: IUser[]) => users ? users.find(user => {
    return user.login.uuid === uuid;
  }) : null
);
export const selectSimilarUsers = (uuid) => createSelector(
  selectUsers,
  (users: IUser[]) => users ? users.filter(user => {
    return user.login.uuid !== uuid;
  }): null
);
```

由于我们使用用户的**通用唯一标识符**（**UUID**）导航到**用户详情**页面，我们将监听活动路由的`paramsMap`并分配适当的选择器。

1.  首先，在`user-detail.component.ts`文件中添加正确的导入，如下所示：

```ts
...
import { takeWhile } from 'rxjs/operators';
import { Store } from '@ngrx/store';
import { AppState } from '../store/app.reducer';
import { selectCurrentUser, selectSimilarUsers } from '../store/app.selectors';
import { ActivatedRoute } from '@angular/router';
```

1.  现在，在相同的`user-detail.component.ts`文件中，使用`Store`服务并更新`ngOnInit`方法，如下所示：

```ts
@Component({...})
export class UserDetailComponent implements OnInit, OnDestroy {
  ...
  constructor(
    private route: ActivatedRoute,
    private store: Store<AppState>
  ) {}
  ngOnInit() {
    this.isComponentAlive = true;
    this.route.paramMap.pipe(
      takeWhile(() => !!this.isComponentAlive)
    )
    .subscribe(params => {
      const uuid = params.get('uuid');
      this.user$ = this.store.      select(selectCurrentUser(uuid))
      this.similarUsers$ = this.store.      select(selectSimilarUsers(uuid))
    });
  }
  ...
}
```

我们将在`UserDetailComponent`类中添加另一个方法，如果应用程序中还没有获取用户，它将获取用户。

1.  按照以下方式向 `user-detail.component.ts` 文件添加 `getUsersIfNecessary` 方法：

```ts
...
import { first, takeWhile } from 'rxjs/operators';
import { Store } from '@ngrx/store';
import { AppState } from '../store/app.reducer';
import { selectCurrentUser, selectSimilarUsers, selectUsers } from '../store/app.selectors';
import { getUsers } from '../store/app.actions';
@Component({...})
export class UserDetailComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    …
    this.getUsersIfNecessary();
  }
  getUsersIfNecessary() {
    this.store.select(selectUsers)
    .pipe(
      first ()
    )
    .subscribe((users) => {
      if (users === null) {
        this.store.dispatch(getUsers())
      }
    })
  }
}
```

刷新应用程序… 突然！您现在可以看到当前用户和相似用户。请查看下一节以了解它是如何工作的。

## 工作原理…

在这个教程中，我们已经有了一个 reducer 和一个从第三方 API 获取用户数据的 effect。我们首先创建了一个用于主屏幕用户的选择器。这很容易——我们只需要创建一个简单的选择器。请注意，reducer 的状态如下所示：

```ts
  app: {
    users: []
  }
```

这就是为什么我们首先使用 `createFeatureSelector` 来获取 `app` 状态，然后使用 `createSelector` 来获取 `users` 状态。

困难的部分是获取当前用户和相似用户。为此，我们创建了可以以 `uuid` 作为输入的选择器。然后，我们在 `UserDetailComponent` 类中监听 `paramMap` 的 `uuid`，一旦它发生变化，我们就会获取它。然后，我们通过将 `uuid` 传递给选择器来使用它们，以便选择器可以过滤当前用户和相似用户。

最后，我们遇到了一个问题，即如果有人直接着陆到**用户详情**页面并带有 `uuid`，他们将看不到任何东西，因为我们没有获取用户。这是因为我们只在主页上获取用户，所以任何直接着陆到用户详情页面的人都不会触发 effect。这就是为什么我们创建了一个名为 `getUsersIfNecessary` 的方法，以便它可以检查状态并在没有获取用户时获取用户。

## 另请参阅

+   NgRx 选择器文档 ([`ngrx.io/guide/store/selectors`](https://ngrx.io/guide/store/selectors))

# 使用 @ngrx/component-store 在组件内进行本地状态管理

在这个教程中，您将学习如何使用 NgRx Component Store，以及如何使用它来代替基于推送的 Subject/BehaviorSubject 模式与服务一起维护组件的本地状态。

请记住，`@ngrx/component-store` 是一个独立的库，与 `Redux` 或 `@ngrx/store` 等没有关联。

## 准备工作

我们要处理的项目位于克隆存储库中的 `chapter06/start_here/ngrx-component-store` 目录中：

1.  在 VS Code 中打开项目。

1.  打开终端并运行 `npm install` 来安装项目的依赖项。

1.  完成后，运行 `ng serve -o`。

这应该在新的浏览器标签页中打开应用程序。以管理员身份登录，您应该能看到它，如下所示：

![图 6.18 - ngrx-component-store 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.18_B15150.jpg)

图 6.18 - ngrx-component-store 应用程序运行在 http://localhost:4200

现在我们的应用程序在本地运行，让我们在下一节中看一下这个配方的步骤。

## 如何做…

到目前为止，我们已经在许多配方中使用了我们喜爱的桶应用程序。目前桶的状态存储在`BucketService`中，它使用了`BehaviorSubject`模式。我们将用 NgRx Component Store 替换它。让我们开始吧：

1.  通过在项目根目录中运行以下命令，将`@ngrx/component-store`包添加到项目的依赖项中：

```ts
npm install @ngrx/component-store@12.0.0 --save
```

1.  我们首先要使我们的`BucketService`与`ComponentStore`兼容。为了做到这一点，我们将为桶状态创建一个接口，将`BucketService`从`ComponentStore`扩展，并通过调用`super`方法来初始化服务。更新`file services/bucket.service.ts`文件，如下所示：

```ts
...
import { IBucketService } from '../interfaces/bucket-service';
import { ComponentStore } from '@ngrx/component-store';
export interface BucketState {
  bucket: IFruit[]
}
@Injectable({
  providedIn: 'root'
})
export class BucketService extends ComponentStore<BucketState>  implements IBucketService {
  bucketSource = new BehaviorSubject([]);
  bucket$: Observable<IFruit[]> =   this.bucketSource.asObservable();
  constructor() {
    super({
      bucket: []
    })
  }
  ...
}
```

在我们实际显示`ComponentStore`中的数据之前，这一切都没有意义。现在让我们来做这件事。

1.  修改`bucket$` Observable，使用`ComponentStore`状态，而不是依赖于`BehaviorSubject`模式，如下所示：

```ts
...
export class BucketService extends ComponentStore<BucketState>  implements IBucketService {
  bucketSource = new BehaviorSubject([]);
  readonly bucket$: Observable<IFruit[]> =   this.select(state => state.bucket);
  constructor() {
    super({
      bucket: []
    })
  }
  ...
}
```

你应该能够看到没有桶项目显示了，或者即使你添加了一个项目，它也不会显示。这是因为它仍然需要一些工作。

1.  首先，让我们确保不是用空数组从组件存储中初始化`bucket`，而是用`localStorage`中的值来初始化它。即使它们还没有显示出来，也试着添加一些项目。然后，修改`loadItems()`方法，使用`BucketService`上的`setState`方法。代码应该如下所示：

```ts
  loadItems() {
    const bucket = JSON.parse(window.localStorage.    getItem('bucket') || '[]');
    this.bucketSource.next(bucket); ← Remove this
    this.setState({ ← Add this
      bucket
    })
  }
```

请注意，我们已经从代码中删除了`this.bucketSource.next(bucket);`行。这是因为我们不再使用`bucketSource`属性，它是一种`BehaviorSubject`模式。我们将对下一组函数执行相同的操作。

此外，你现在应该能够看到之前添加的项目，但没有显示出来。

1.  现在让我们替换`BucketService`中的`addItem`方法，以便它可以正确更新状态并显示新的项目在视图中，如我们所期望的那样。为此，我们将使用`ComponentStore`的`updater`方法，并修改我们的`addItem`方法为一个更新器，如下所示：

```ts
  readonly addItem = this.updater((state, fruit: IFruit)   => {
    const bucket = [fruit, ...state.bucket]
    window.localStorage.setItem('bucket',     JSON.stringify(bucket));
    return ({
      bucket
    })
  });
```

如果你现在添加一个项目，你应该能够在视图中看到它。

1.  我们现在也可以将`BucketService`中的`removeItem`方法替换为`updater`方法。代码应该如下所示：

```ts
  readonly removeItem = this.updater((state, fruit:   IFruit) => {
    const bucket = state.bucket.filter(item =>     item.id !== fruit.id);
    window.localStorage.setItem('bucket',     JSON.stringify(bucket));
    return ({
      bucket
    })
  });
```

通过这个改变，您应该看到应用程序正在工作。但是我们确实有一个需要解决的问题，那就是`EmployeeService`也需要更新，使`removeItem`方法成为`updater`方法。

1.  让我们将`EmployeeBucketService`中的`removeItem`方法替换为`updater`方法。修改`employee/services/employee-bucket.service.ts`文件如下：

```ts
import { Injectable } from '@angular/core';
import { IFruit } from 'src/app/interfaces/fruit.interface';
import { BucketService } from 'src/app/services/bucket.service';
...
export class EmployeeBucketService extends BucketService {
  constructor() {
    super();
  }
  readonly removeItem = this.updater((state, _: IFruit)   => {
    alert('Employees can not delete items');
    return state;
  });
}
```

而且！现在一切应该都很好，您不应该看到任何错误。

1.  由于我们已经摆脱了`BucketService`属性`bucketSource`中`BehaviorSubject`模式的所有用法，我们可以从`BucketService`中删除该属性本身。最终代码应该如下所示：

```ts
import { Injectable } from '@angular/core';
import { BehaviorSubject ← Remove this, Observable } from 'rxjs';
...
export class BucketService extends ComponentStore<BucketState>  implements IBucketService {
  bucketSource = new BehaviorSubject([]); ← Remove
  readonly bucket$: Observable<IFruit[]> =   this.select((state) => state.bucket);
  constructor() {
    super({
      bucket: []
    })
  }
...
}
```

恭喜！您已完成该教程。请查看下一节以了解其工作原理。

## 它是如何工作的...

如前所述，`@ngrx/component-store`是一个独立的包，可以轻松安装在您的 Angular 应用程序中，而无需使用`@ngrx/store`、`@ngrx/effects`等。它应该替换 Angular 服务中`BehaviorSubject`的使用方式，这就是我们在本教程中所做的。我们介绍了如何初始化`ComponentStore`以及如何使用`setState`方法设置初始状态，当我们已经有值而无需访问状态时，我们学会了如何创建`updater`方法，它们可以用于更新状态，因为它们可以访问状态并允许我们甚至为我们自己的用例传递参数。

## 另请参阅

+   `@ngrx/component-store`文档（[`ngrx.io/guide/component-store`](https://ngrx.io/guide/component-store)）

+   `@ngrx/component-store`文档中的 Effects（[`ngrx.io/guide/component-store/effect`](https://ngrx.io/guide/component-store/effect)）

# 使用@ngrx/router-store 来以响应式方式处理路由更改

NgRx 很棒，因为它允许您将数据存储在一个集中的位置。然而，监听路由更改仍然是我们目前所涵盖的 NgRx 范围之外的事情。我们确实依赖于`ActivatedRoute`服务来监听路由更改，当我们想要测试这样的组件时，`ActivatedRoute`服务就成了一个依赖项。在本教程中，您将安装`@ngrx/router-store`包，并学习如何使用该包中内置的一些操作来监听路由更改。

## 准备工作

我们将要处理的项目位于`chapter06/start_here/ngrx-router-store`中，位于克隆存储库内：

1.  在 VS Code 中打开项目。

1.  打开终端并运行`npm install`来安装项目的依赖项。

1.  完成后，运行`ng serve -o`。

这应该会在新的浏览器标签页中打开应用程序，你应该会看到类似这样的东西：

![图 6.19 - ngrx-router-store 应用程序运行在 http://localhost:4200](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.19_B15150.jpg)

图 6.19 - ngrx-router-store 应用程序运行在 http://localhost:4200

现在应用程序正在运行，请查看下一节的步骤。

## 如何做…

为了利用 NgRx 甚至对路由更改的强大功能，我们将利用`@ngrx/router-store`包来监听路由更改。让我们开始吧！

1.  首先，在项目根目录中运行以下命令安装`@ngrx/router-store`包：

```ts
npm install @ngrx/router-store@12.0.0 --save
```

1.  现在，在你的`app.module.ts`文件中导入`StoreRouterConnectingModule`和`routerReducer`，并设置`imports`，如下所示：

```ts
...
import { StoreRouterConnectingModule, routerReducer } from '@ngrx/router-store';
@NgModule({
  declarations: [...],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    StoreModule.forRoot({
      app: appStore.reducer,
  router: routerReducer
    }),
 StoreRouterConnectingModule.forRoot(),
    StoreDevtoolsModule.instrument({
      maxAge: 25, // Retains last 25 states
    }),
    EffectsModule.forRoot([AppEffects])
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

现在刷新应用程序并通过 Redux DevTools 扩展进行检查，你应该还会看到一些额外的名为`@ngrx/router-store/*`的操作被分发。你还应该看到状态中的`router`属性具有当前路由的信息，如下截图所示：

![图 6.20 - @ngrx/router-store 操作和路由器状态在 NgRx 存储中的反映](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-cb/img/Figure_6.20_B15150.jpg)

图 6.20 - @ngrx/router-store 操作和路由器状态在 NgRx 存储中的反映

1.  我们现在必须修改我们的 reducer，或者更准确地说，修改`AppState`接口，以反映我们还有来自`@ngrx/router-store`包的`router`属性。为此，请修改`store/app.reducer.ts`文件，如下所示：

```ts
...
import { getUsersSuccess } from './app.actions';
import { RouterReducerState } from '@ngrx/router-store'
export interface AppState {
  users: IUser[];
  router: RouterReducerState<any>;
}
const initialState: AppState = {
  users: null,
  router: null
}
...
```

1.  基本上，我们必须摆脱`UserDetailComponent`类中对`ActivatedRoute`服务的使用。为了做到这一点，我们首先修改我们的选择器，直接从路由器状态中获取参数。修改`app.selectors.ts`文件，如下所示：

```ts
...
import { getSelectors, RouterReducerState } from '@ngrx/router-store';
export const selectApp = createFeatureSelector<AppState>('app');
export const selectUsers = createSelector(
  selectApp,
  (state: AppState) => state.users
);
...
export const selectRouter = createFeatureSelector<
  AppState,
  RouterReducerState<any>
>('router');
const { selectRouteParam } = getSelectors(selectRouter);
export const selectUserUUID = selectRouteParam('uuid');
export const selectCurrentUser = createSelector(
  selectUserUUID,
  selectUsers,
  (uuid, users: IUser[]) => users ? users.find(user => {
    return user.login.uuid === uuid;
  }) : null
);
export const selectSimilarUsers = createSelector(
  selectUserUUID,
  selectUsers,
  (uuid, users: IUser[]) => users ? users.filter(user =>   {
    return user.login.uuid !== uuid;
  }): null
);
```

你现在应该在控制台上看到一些错误。那是因为我们改变了`selectSimilarUsers`和`selectCurrentUser`选择器的签名，但它将在下一步中被修复。

1.  修改`user-detail/user-detail.component.ts`文件以正确使用更新后的选择器，如下所示：

```ts
...
export class UserDetailComponent implements OnInit, OnDestroy {
  ...
  ngOnInit() {
    ...
    this.route.paramMap.pipe(
      takeWhile(() => !!this.isComponentAlive)
    )
    .subscribe(params => {
      const uuid = params.get('uuid');
      this.user$ = this.store.select(selectCurrentUser)
      this.similarUsers$ = this.store.      select(selectSimilarUsers)
    })
  }
  ...
}
```

这个更改应该已经解决了控制台上的错误，你应该能够看到应用程序完美地运行，即使我们不再从`UserDetailComponent`类中传递任何`uuid`。

1.  通过上一步的更改，我们现在可以安全地从`UserDetailComponent`类中删除`ActivatedRoute`服务的使用，代码现在应该是这样的：

```ts
...
import { Observable } from 'rxjs/internal/Observable';
import { first } from 'rxjs/operators';
import { Store } from '@ngrx/store';
...
export class UserDetailComponent implements OnInit, OnDestroy {
  ...
  constructor(
    private store: Store<AppState>
) {}
  ngOnInit() {
    this.isComponentAlive = true;
    this.getUsersIfNecessary();
    this.user$ = this.store.select(selectCurrentUser)
    this.similarUsers$ = this.store.    select(selectSimilarUsers)
  }
  ...
}
```

哇哦！你现在已经完成了这个食谱。查看下一节，了解这是如何运作的。

## 它是如何工作的...

`@ngrx/router-store`是一个了不起的包，它通过许多魔法使我们在 NgRx 中的开发变得更加容易。你看到了我们如何通过使用该包中的选择器，完全删除了`UserDetailComponent`类中的`ActivatedRoute`服务。基本上，这帮助我们在选择器中正确获取**路由参数**，并且我们可以在选择器中使用它来获取和过滤出适当的数据。在幕后，该包监听整个 Angular 应用程序中的路由更改，并从路由本身获取数据。然后将相应的信息存储在 NgRx Store 中，以便它保留在 Redux 状态中，并且可以通过该包提供的选择器轻松选择。在我看来，这太棒了！我这么说是因为该包正在做我们否则必须做的所有繁重工作。因此，我们的`UserDetailComponent`类现在只依赖于`Store`服务，这使得测试变得更加容易，因为依赖更少。

## 另请参阅

+   `@ngrx/router-store`文档（[`ngrx.io/guide/router-store/`](https://ngrx.io/guide/router-store/)）
